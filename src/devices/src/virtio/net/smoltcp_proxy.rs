use crate::legacy::IrqChip;
use crate::virtio::net::{MAX_BUFFER_SIZE, QUEUE_SIZE, RX_INDEX, TX_INDEX};
use crate::virtio::{Queue, VIRTIO_MMIO_INT_VRING};
use crate::Error as DeviceError;
use mio::event::{Event, Source};
use mio::net::UnixListener;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Registry, Token};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use smoltcp::iface::{Config, Context, Interface, PollResult, Routes, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant as SmoltcpInstant;
use smoltcp::wire::{
    EthernetAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, IpVersion, Ipv4Address,
    Ipv4Cidr,
};
use socket2::{Domain, SockAddr, Socket};
use std::cmp;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;
use tracing::{debug, error, info, trace, warn};
use utils::eventfd::{EventFd, EFD_NONBLOCK};
use virtio_bindings::virtio_net::virtio_net_hdr_v1;
use vm_memory::{Bytes as MemBytes, GuestAddress, GuestMemoryMmap};

// --- Constants and Configuration ---
const VIRTQ_TX_TOKEN: Token = Token(0);
const VIRTQ_RX_TOKEN: Token = Token(1);
const HOST_SOCKET_START_TOKEN: usize = 2;

const VM_MAC: EthernetAddress = EthernetAddress([0xde, 0xad, 0xbe, 0xef, 0x00, 0x00]);
const PROXY_MAC: EthernetAddress = EthernetAddress([0x02, 0x00, 0x00, 0x01, 0x02, 0x03]);
const VM_IP: Ipv4Address = Ipv4Address::new(192, 168, 100, 2);
const PROXY_IP: Ipv4Address = Ipv4Address::new(192, 168, 100, 1);
const SUBNET_MASK: Ipv4Address = Ipv4Address::new(255, 255, 255, 0);

/// Represents the virtio-net device as a `smoltcp` PHY device.
/// This acts as the bridge between the VM's virtio queues and the smoltcp stack.
struct VirtualDevice {
    rx_buffer: VecDeque<Vec<u8>>,
    tx_buffer: VecDeque<Vec<u8>>,
    mem: GuestMemoryMmap,
    queues: Vec<Queue>,
    rx_frame_buf: [u8; MAX_BUFFER_SIZE],
    tx_frame_buf: [u8; MAX_BUFFER_SIZE],
}

impl VirtualDevice {
    pub fn receive_raw(&mut self) -> Option<Vec<u8>> {
        if let Some(head) = self.queues[TX_INDEX].pop(&self.mem) {
            let head_index = head.index;
            // Use the pre-allocated buffer instead of a new Vec
            let buffer = &mut self.rx_frame_buf;
            let mut read_count = 0;
            let mut next_desc = Some(head);

            while let Some(desc) = next_desc {
                if !desc.is_write_only() {
                    let len = cmp::min(buffer.len() - read_count, desc.len as usize);
                    if self
                        .mem
                        // Read into a mutable slice of the pre-allocated array
                        .read_slice(&mut buffer[read_count..read_count + len], desc.addr)
                        .is_ok()
                    {
                        read_count += len;
                    }
                }
                next_desc = desc.next_descriptor();
            }

            self.queues[TX_INDEX]
                .add_used(&self.mem, head_index, 0)
                .unwrap();

            if read_count > 0 {
                let eth_start = std::mem::size_of::<virtio_net_hdr_v1>();
                if read_count > eth_start {
                    // This second, smaller allocation is still necessary with the
                    // current design, but avoiding the first large allocation
                    // is the big performance win.
                    let packet_data = buffer[eth_start..read_count].to_vec();
                    trace!("{}", packet_dumper::log_vm_packet_in(&packet_data));
                    return Some(packet_data);
                }
            }
        }
        None
    }
}

impl Device for VirtualDevice {
    type RxToken<'a>
        = RxToken
    where
        Self: 'a;
    type TxToken<'a>
        = TxToken<'a>
    where
        Self: 'a;

    /// Receives a packet from the virtio TX queue (i.e., from the guest).
    fn receive(
        &mut self,
        timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // This function will now consume packets that have been buffered
        // by the work loop (if they weren't handled as new connections).
        if let Some(buffer) = self.rx_buffer.pop_front() {
            let rx_token = RxToken { buffer };
            let tx_token = TxToken {
                mem: &self.mem,
                rx_queue: &mut self.queues[RX_INDEX],
                buf: &mut self.tx_frame_buf,
            };
            return Some((rx_token, tx_token));
        }
        None
    }

    /// Transmits a packet to the virtio RX queue (i.e., to the guest).
    fn transmit(&mut self, timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        // Check if there are any available descriptors in the RX queue.
        // The guest puts empty buffers here for us to fill.
        if !self.queues[RX_INDEX].is_empty(&self.mem) {
            // If a buffer is available, return a TxToken.
            // smoltcp will then call the token's `consume` method to fill the buffer.
            Some(TxToken {
                mem: &self.mem,
                rx_queue: &mut self.queues[RX_INDEX],
                buf: &mut self.tx_frame_buf,
            })
        } else {
            // If the guest has not provided any empty buffers, we can't transmit.
            // Tell smoltcp the device is exhausted.
            None
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1500;
        caps.medium = Medium::Ethernet;
        caps
    }
}

// A token that holds a received packet.
struct RxToken {
    buffer: Vec<u8>,
}

impl<'a> phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

// A token that can transmit a packet.
struct TxToken<'a> {
    mem: &'a GuestMemoryMmap,
    rx_queue: &'a mut Queue,
    buf: &'a mut [u8],
}

impl<'a> phy::TxToken for TxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let result = f(&mut self.buf[..len]);

        trace!("{}", packet_dumper::log_vm_packet_out(&self.buf[..len]));

        // Prepend virtio-net header
        let mut frame = vec![0u8; std::mem::size_of::<virtio_net_hdr_v1>() + len];
        frame[std::mem::size_of::<virtio_net_hdr_v1>()..].copy_from_slice(&self.buf[..len]);

        // Write the frame to the guest's RX queue.
        if let Some(head) = self.rx_queue.pop(self.mem) {
            let head_index = head.index;
            let mut written = 0;
            let mut next_desc = Some(head);

            while let Some(desc) = next_desc {
                if desc.is_write_only() {
                    let write_len = cmp::min(frame.len() - written, desc.len as usize);
                    if self
                        .mem
                        .write_slice(&frame[written..written + write_len], desc.addr)
                        .is_ok()
                    {
                        written += write_len;
                    }
                }
                next_desc = desc.next_descriptor();
            }
            self.rx_queue
                .add_used(self.mem, head_index, written as u32)
                .unwrap();
        }

        result
    }
}

enum HostSocket {
    Tcp(mio::net::TcpStream),
    Udp(mio::net::UdpSocket),
    Unix(mio::net::UnixStream),
}

/// The main proxy structure, now using smoltcp.
pub struct SmoltcpProxy {
    // Virtio-related fields
    queue_evts: Vec<EventFd>,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
    intc: Option<IrqChip>,
    irq_line: Option<u32>,

    // smoltcp-related fields
    device: VirtualDevice,
    iface: Interface,
    sockets: SocketSet<'static>,

    // mio and networking fields
    poll: Poll,
    registry: Registry,
    next_token: usize,
    host_connections: HashMap<Token, (HostSocket, SocketHandle)>,
    nat_table: HashMap<IpEndpoint, Token>, // (External IP, External Port) -> Token
    reverse_nat_table: HashMap<Token, (IpEndpoint, IpEndpoint)>,
    udp_listeners: HashMap<IpEndpoint, SocketHandle>,
    unix_listeners: HashMap<Token, (UnixListener, u16)>,

    next_ephemeral_port: u16,
}

impl SmoltcpProxy {
    pub fn new(
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
        interrupt_status: Arc<AtomicUsize>,
        interrupt_evt: EventFd,
        intc: Option<IrqChip>,
        irq_line: Option<u32>,
        mem: GuestMemoryMmap,
        listeners: Vec<(u16, String)>,
    ) -> io::Result<Self> {
        let poll = Poll::new()?;
        let registry = poll.registry().try_clone()?;

        // Create the virtual device for smoltcp
        let mut virtual_device = VirtualDevice {
            rx_buffer: VecDeque::new(),
            tx_buffer: VecDeque::new(),
            mem,
            queues,
            rx_frame_buf: [0; MAX_BUFFER_SIZE],
            tx_frame_buf: [0; MAX_BUFFER_SIZE],
        };

        // Configure smoltcp interface
        // let neighbor_cache = NeighborCache::new(BTreeMap::new());
        // let mut routes = Routes::new(BTreeMap::new());
        // let default_gateway_ipv4 = PROXY_IP;
        // routes.add_default_ipv4_route(default_gateway_ipv4).unwrap();

        // let ip_addrs = [IpCidr::new(IpAddress::from(VM_IP), 24)];

        let mut iface = Interface::new(
            Config::new(smoltcp::wire::HardwareAddress::Ethernet((PROXY_MAC))),
            &mut virtual_device,
            smoltcp::time::Instant::now(),
        );

        iface.set_any_ip(true);

        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::from(PROXY_IP), 24))
                .expect("maximum number of IPs in TCP interface reached");
        });

        iface
            .routes_mut()
            .add_default_ipv4_route(PROXY_IP)
            .expect("could not add default ipv4 route");

        let sockets = SocketSet::new(vec![]);

        let mut next_token = HOST_SOCKET_START_TOKEN;
        let mut unix_listeners = HashMap::new();

        fn configure_socket(domain: Domain, sock_type: socket2::Type) -> io::Result<Socket> {
            let socket = Socket::new(domain, sock_type, None)?;
            const BUF_SIZE: usize = 8 * 1024 * 1024;
            if let Err(e) = socket.set_recv_buffer_size(BUF_SIZE) {
                warn!(error = %e, "Failed to set receive buffer size.");
            }
            if let Err(e) = socket.set_send_buffer_size(BUF_SIZE) {
                warn!(error = %e, "Failed to set send buffer size.");
            }
            socket.set_nonblocking(true)?;
            Ok(socket)
        }

        for (vm_port, path) in listeners {
            if std::fs::exists(path.as_str())? {
                std::fs::remove_file(path.as_str())?;
            }
            let listener_socket = configure_socket(Domain::UNIX, socket2::Type::STREAM)?;
            listener_socket.bind(&SockAddr::unix(path.as_str())?)?;
            listener_socket.listen(1024)?;
            info!(socket_path = %path, %vm_port, "Listening for Unix socket ingress connections");

            let mut listener = UnixListener::from_std(listener_socket.into());

            let token = Token(next_token);
            registry.register(&mut listener, token, Interest::READABLE)?;
            next_token += 1;

            unix_listeners.insert(token, (listener, vm_port));
        }

        Ok(SmoltcpProxy {
            queue_evts,
            interrupt_status,
            interrupt_evt,
            intc,
            irq_line,
            device: virtual_device,
            iface,
            sockets: unsafe { std::mem::transmute(sockets) },
            poll,
            registry,
            next_token,
            host_connections: HashMap::new(),
            nat_table: HashMap::new(),
            reverse_nat_table: HashMap::new(),
            next_ephemeral_port: 49152,
            udp_listeners: HashMap::new(),
            unix_listeners,
        })
    }

    pub fn run(mut self) {
        thread::Builder::new()
            .name("smoltcp-proxy".into())
            .spawn(move || self.work())
            .unwrap();
    }

    fn work(&mut self) {
        let mut events = Events::with_capacity(1024);

        // Register virtio queue events with mio
        self.poll
            .registry()
            .register(
                &mut SourceFd(&self.queue_evts[TX_INDEX].as_raw_fd()),
                VIRTQ_TX_TOKEN,
                Interest::READABLE,
            )
            .unwrap();
        self.poll
            .registry()
            .register(
                &mut SourceFd(&self.queue_evts[RX_INDEX].as_raw_fd()),
                VIRTQ_RX_TOKEN,
                Interest::READABLE,
            )
            .unwrap();

        let start_time = Instant::now();

        loop {
            // Poll for events from virtio queues and host sockets
            let timeout = self
                .iface
                .poll_delay(
                    SmoltcpInstant::from_millis(start_time.elapsed().as_millis() as i64),
                    &self.sockets,
                )
                .map(|d| std::time::Duration::from_millis(d.total_millis() as u64));

            self.poll.poll(&mut events, timeout).unwrap();

            // Process virtio queue events
            for event in events.iter() {
                match event.token() {
                    VIRTQ_TX_TOKEN => {
                        trace!("handling TX queue event");
                        self.queue_evts[TX_INDEX].read().unwrap();
                        self.device.queues[TX_INDEX]
                            .disable_notification(&self.device.mem)
                            .unwrap();
                    }
                    VIRTQ_RX_TOKEN => {
                        trace!("handling RX queue event");
                        self.queue_evts[RX_INDEX].read().unwrap();
                        self.device.queues[RX_INDEX]
                            .disable_notification(&self.device.mem)
                            .unwrap();
                    }
                    token => {
                        if self.unix_listeners.contains_key(&token) {
                            self.handle_unix_listener_event(token);
                        } else {
                            self.handle_host_socket_event(token, event);
                        }
                    }
                }
            }

            while let Some(data) = self.device.receive_raw() {
                // A TX buffer was just consumed. Signal the guest.
                self.signal_used_queue(TX_INDEX).unwrap();

                // Check if the packet was the start of a new session and was handled.
                let packet_was_intercepted = self.intercept_new_session(&data);

                // ONLY if the packet was not intercepted (e.g., it's an ACK or data for an
                // existing connection), do we queue it for smoltcp.
                if !packet_was_intercepted {
                    self.device.rx_buffer.push_back(data);
                }
            }

            let timestamp = SmoltcpInstant::from_millis(start_time.elapsed().as_millis() as i64);

            match self
                .iface
                .poll(timestamp, &mut self.device, &mut self.sockets)
            {
                PollResult::None => {} // This is expected if we only queued a packet
                PollResult::SocketStateChanged => {
                    debug!("socket state changed!");
                }
            }

            // Signal the guest if packets were sent to the RX queue
            if self.device.queues[RX_INDEX]
                .needs_notification(&self.device.mem)
                .unwrap()
            {
                trace!("signaling rx queue that it was used");
                self.signal_used_queue(RX_INDEX).unwrap();
            }
            if self.device.queues[TX_INDEX]
                .needs_notification(&self.device.mem)
                .unwrap()
            {
                trace!("signaling tx queue that it was used");
                self.signal_used_queue(TX_INDEX).unwrap();
            }

            // Re-enable notifications
            self.device.queues[RX_INDEX]
                .enable_notification(&self.device.mem)
                .unwrap();
            self.device.queues[TX_INDEX]
                .enable_notification(&self.device.mem)
                .unwrap();

            for (token, (stream, handle)) in self.host_connections.iter_mut() {
                let socket = match stream {
                    HostSocket::Tcp(_stream) => {
                        self.sockets.get::<smoltcp::socket::tcp::Socket>(*handle)
                    }
                    HostSocket::Unix(_stream) => {
                        self.sockets.get::<smoltcp::socket::tcp::Socket>(*handle)
                    }
                    _ => {
                        continue;
                    }
                };

                // Use `can_recv()` to check if there is ACTUALLY data waiting to be sent.
                // `may_recv()` is too broad and causes the busy-loop.
                if socket.can_recv() {
                    // Re-register for writable events since we now have data to send.
                    // This needs to handle both TCP and Unix streams.
                    match stream {
                        HostSocket::Tcp(s) => {
                            self.registry
                                .reregister(s, *token, Interest::READABLE | Interest::WRITABLE)
                                .unwrap();
                        }
                        HostSocket::Unix(s) => {
                            self.registry
                                .reregister(s, *token, Interest::READABLE | Interest::WRITABLE)
                                .unwrap();
                        }
                        // No action needed for UDP here.
                        _ => {}
                    }
                }
            }
        }
    }

    fn forward_stream<T: Read + Write + Source>(
        &mut self,
        token: Token,
        event: &Event,
        stream: &mut T,
        handle: SocketHandle,
    ) -> bool {
        let socket = self.sockets.get_mut::<smoltcp::socket::tcp::Socket>(handle);

        // If the smoltcp socket is dead, we can't do anything.
        if !socket.is_active() || socket.state() == smoltcp::socket::tcp::State::Closed {
            return false; // Tells the caller to remove this connection.
        }

        // --- 1. Read from Host, Write to Guest ---
        if event.is_readable() {
            let mut buffer = [0u8; 2048];
            loop {
                // Loop to drain the readable data from the host socket.
                if !socket.can_send() {
                    break; // Guest-side buffer is full.
                }

                let send_capacity = socket.send_capacity() - socket.send_queue();
                let read_limit = std::cmp::min(send_capacity, buffer.len());

                match stream.read(&mut buffer[..read_limit]) {
                    Ok(0) => {
                        // Host closed the connection.
                        trace!(?token, "Host stream EOF, closing smoltcp socket");
                        socket.close();
                        break;
                    }
                    Ok(n) => {
                        trace!(?token, bytes = n, "Read from host, wrote to smoltcp");
                        if let Err(e) = socket.send_slice(&buffer[..n]) {
                            error!(?token, "could not send slice to smoltcp socket: {e}");
                            socket.abort();
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        trace!(?token, "would block, breaking stream write loop");
                        break; // No more data to read for now.
                    }
                    Err(e) => {
                        error!(?token, error = %e, "Read error on host stream, aborting");
                        socket.abort();
                        break;
                    }
                }
            }
        }

        // --- 2. Read from Guest, Write to Host ---
        if event.is_writable() && socket.can_recv() {
            loop {
                // Loop to drain the guest-side buffer.
                let result = socket.recv(|data| {
                    match stream.write(data) {
                        Ok(n) => (n, (n == 0, false)), // Continue writing
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            (0, (true, false)) // Host buffer is full, break inner loop.
                        }
                        Err(e) => {
                            error!(?token, error = %e, "Write error on host stream, aborting");
                            (data.len(), (true, true)) // Mark all data as "consumed" to abort.
                        }
                    }
                });

                match result {
                    Ok((should_break, should_abort)) => {
                        trace!(
                            ?token,
                            should_break,
                            should_abort,
                            "read a packet from socket"
                        );
                        if should_abort {
                            socket.abort();
                        }
                        // Broke due to WouldBlock or an error.
                        if should_break {
                            break;
                        }
                    }
                    Err(e) => {
                        error!(?token, "could not recv from smoltcp socket: {e}");
                        socket.abort();
                        break;
                    }
                }
            }
        }

        // --- 3. Manage Mio Interest ---
        // After all I/O, decide if we still need to be notified about writability.
        if socket.can_recv() {
            // We still have data to send to the host, so we need WRITABLE interest.
            // This handles the case where a write was blocked by WouldBlock.
            self.registry
                .reregister(stream, token, Interest::READABLE | Interest::WRITABLE)
                .unwrap_or_else(|e| {
                    error!(?token, error=%e, "Reregister R|W failed");
                    socket.abort();
                });
        } else {
            // The guest-side buffer is empty, we only need to know when the host sends us data.
            self.registry
                .reregister(stream, token, Interest::READABLE)
                .unwrap_or_else(|e| {
                    error!(?token, error=%e, "Reregister R-only failed");
                    socket.abort();
                });
        }

        // Return true to keep the connection, false to close it.
        socket.is_active() && socket.state() != smoltcp::socket::tcp::State::Closed
    }

    fn handle_unix_listener_event(&mut self, token: Token) {
        // Retrieve the listener and the target guest port.
        if let Some((listener, guest_port)) = self.unix_listeners.remove(&token) {
            loop {
                let (mut stream, _addr) = match listener.accept() {
                    Ok(res) => res,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        // No more pending connections to accept.
                        break;
                    }
                    Err(e) => {
                        error!(?token, error = %e, "Failed to accept unix socket connection");
                        // FIXME: probably need to cleanup something
                        break;
                    }
                };

                info!(
                    ?token,
                    port = guest_port,
                    "Accepted new unix socket connection"
                );

                // Create the smoltcp TCP socket that will connect TO the guest.
                let rx_buffer = smoltcp::socket::tcp::SocketBuffer::new(vec![0; 65535]);
                let tx_buffer = smoltcp::socket::tcp::SocketBuffer::new(vec![0; 65535]);
                let mut smoltcp_socket = smoltcp::socket::tcp::Socket::new(rx_buffer, tx_buffer);

                smoltcp_socket.set_ack_delay(None);
                smoltcp_socket.set_nagle_enabled(false);

                // Set up the connection parameters. The remote endpoint is the guest.
                let remote_endpoint = IpEndpoint::new(IpAddress::from(VM_IP), guest_port);
                let ephemeral_port = self.get_ephemeral_port();

                trace!(?token, "connecting to {remote_endpoint}");

                // Tell the smoltcp socket to initiate a connection.
                smoltcp_socket
                    .connect(
                        self.iface.context(),
                        remote_endpoint,
                        IpListenEndpoint {
                            port: ephemeral_port,
                            addr: Some(IpAddress::Ipv4(PROXY_IP)),
                        },
                    )
                    .unwrap();
                let smoltcp_handle = self.sockets.add(smoltcp_socket);

                // Register the new stream with mio for read/write events.
                let new_token = Token(self.next_token);
                self.next_token += 1;
                self.registry
                    .register(
                        &mut stream,
                        new_token,
                        Interest::READABLE | Interest::WRITABLE,
                    )
                    .unwrap();

                // Add the new active connection to our tracking map.
                self.host_connections
                    .insert(new_token, (HostSocket::Unix(stream), smoltcp_handle));

                trace!(token = ?new_token, "assigned token to proxy connection");
            }
            self.unix_listeners.insert(token, (listener, guest_port));
        }
    }

    /// Parses a raw packet from the guest. If it's a new TCP connection attempt,
    /// it sets up the host-side connection and the smoltcp "twin" socket.
    /// Returns true if the packet was handled, meaning it should not be given to smoltcp.
    fn intercept_new_session(&mut self, data: &[u8]) -> bool {
        if let Some(eth) = EthernetPacket::new(data) {
            if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                match ipv4.get_next_level_protocol() {
                    // --- Keep your existing TCP logic ---
                    IpNextHeaderProtocols::Tcp => {
                        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                            // We only care about the initial SYN packet to start a connection
                            if tcp.get_flags() == TcpFlags::SYN {
                                let guest_addr = IpAddress::from(ipv4.get_source());
                                let dest_addr = IpAddress::from(ipv4.get_destination());
                                let guest_port = tcp.get_source();
                                let dest_port = tcp.get_destination();

                                let dest_socket_addr =
                                    std::net::SocketAddr::new(dest_addr.into(), dest_port);

                                info!(from = %guest_addr, to = %dest_socket_addr, "New connection attempt from guest");

                                let real_dest = SocketAddr::new(dest_addr.into(), dest_port);
                                let stream = match dest_addr.into() {
                                    IpAddr::V4(_) => {
                                        Socket::new(Domain::IPV4, socket2::Type::STREAM, None)
                                    }
                                    IpAddr::V6(_) => {
                                        Socket::new(Domain::IPV6, socket2::Type::STREAM, None)
                                    }
                                };

                                let Ok(sock) = stream else {
                                    error!(error = %stream.unwrap_err(), "Failed to create egress socket");
                                    return true;
                                };

                                sock.set_nonblocking(true).unwrap();

                                match sock.connect(&real_dest.into()) {
                                    Ok(()) => (),
                                    Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => (),
                                    Err(e) => {
                                        error!(error = %e, "Failed to connect egress socket");
                                        return true;
                                    }
                                }

                                let mut stream = mio::net::TcpStream::from_std(sock.into());

                                // 2. Create the smoltcp "twin" socket to represent the guest's side
                                let rx_buffer =
                                    smoltcp::socket::tcp::SocketBuffer::new(vec![0; 65535]);
                                let tx_buffer =
                                    smoltcp::socket::tcp::SocketBuffer::new(vec![0; 65535]);
                                let mut smoltcp_socket =
                                    smoltcp::socket::tcp::Socket::new(rx_buffer, tx_buffer);

                                smoltcp_socket.set_ack_delay(None);
                                smoltcp_socket.set_nagle_enabled(false);

                                smoltcp_socket
                                    .listen(IpEndpoint::new(dest_addr, dest_port))
                                    .unwrap();

                                let smoltcp_handle = self.sockets.add(smoltcp_socket);

                                // 3. Register the real socket with mio and map it to the twin
                                let token = Token(self.next_token);
                                self.next_token += 1;
                                self.registry
                                    .register(
                                        &mut stream,
                                        token,
                                        Interest::READABLE | Interest::WRITABLE,
                                    )
                                    .unwrap();
                                self.host_connections
                                    .insert(token, (HostSocket::Tcp(stream), smoltcp_handle));
                            }
                        }
                    }

                    IpNextHeaderProtocols::Udp => {
                        let src = ipv4.get_source();
                        let dst = ipv4.get_destination();
                        if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                            let guest_addr = IpAddress::from(src);
                            let guest_port = udp.get_source();

                            // Check if this is the first packet for this session.
                            if !self
                                .nat_table
                                .contains_key(&(guest_addr, guest_port).into())
                            {
                                self.handle_udp_datagram(src, dst, udp);
                                return true;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        false
    }

    /// Handles events on host-side TCP sockets.
    fn handle_host_socket_event(&mut self, token: Token, event: &Event) {
        trace!(
            ?token,
            readable = event.is_readable(),
            writable = event.is_writable(),
            "handling socket event"
        );
        if let Some((mut stream, handle)) = self.host_connections.remove(&token) {
            match &mut stream {
                HostSocket::Tcp(stream) => {
                    trace!(?token, "fowarding tcp stream");
                    if !self.forward_stream(token, event, stream, handle) {
                        trace!(?token, "tcp stream should not be kept, shutting down");
                        _ = stream.shutdown(std::net::Shutdown::Both);
                        return;
                    }
                }
                HostSocket::Unix(stream) => {
                    trace!(?token, "fowarding unix stream");
                    if !self.forward_stream(token, event, stream, handle) {
                        trace!(?token, "unix stream should not be kept, shutting down");
                        _ = stream.shutdown(std::net::Shutdown::Both);
                        return;
                    }
                }
                // HostSocket::Tcp(stream) => {
                //     let socket = self
                //         .sockets
                //         .get_mut::<smoltcp::socket::tcp::Socket>(*handle);

                //     if event.is_writable() {
                //         trace!(?token, "socket is writable");
                //         while socket.can_recv() {
                //             let result = socket.recv(|data| {
                //                 // Write the data from smoltcp's send buffer to the host socket.
                //                 match stream.write(data) {
                //                     Ok(n) => {
                //                         trace!(
                //                             "Wrote {} bytes to host socket token={:?}",
                //                             n,
                //                             token
                //                         );
                //                         (n, (n, false))
                //                     }
                //                     Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                //                         // Host socket is full, stop for now.
                //                         (0, (0, false))
                //                     }
                //                     Err(e) => {
                //                         error!("Write error on host socket: {}", e);

                //                         (0, (0, true))
                //                     }
                //                 }
                //             });

                //             match result {
                //                 Ok((_, true)) => {
                //                     trace!(
                //                         ?token,
                //                         "write error on socket, aborting smoltcp socket!"
                //                     );
                //                     socket.abort();
                //                     // The mio socket is blocked, so break the loop.
                //                     break;
                //                 }
                //                 Ok((0, false)) => {
                //                     trace!(?token, "no more data to write");
                //                     break;
                //                 }
                //                 Ok(_) => {
                //                     // keep going
                //                     trace!(?token, "looping to write more data");
                //                 }
                //                 Err(e) => {
                //                     // An error occurred in smoltcp, close everything.
                //                     trace!(?token, "error receiving from smoltcp socket: {e}");
                //                     stream.shutdown(std::net::Shutdown::Both).ok();
                //                     socket.abort();
                //                     break;
                //                 }
                //             }
                //         }
                //         if !socket.can_recv() {
                //             self.registry
                //                 .reregister(stream, token, Interest::READABLE)
                //                 .unwrap();
                //         }
                //     }

                //     if event.is_readable() {
                //         // Create a temporary buffer limited by the smaller of our buffer
                //         // size or the available capacity in the smoltcp socket.
                //         let mut read_buf = [0u8; 2048];
                //         // Loop to drain all data available on the mio socket.
                //         while socket.can_send() {
                //             let max_sendable = socket.send_capacity() - socket.send_queue();
                //             if max_sendable == 0 {
                //                 // No more space in smoltcp's buffer, stop reading from host
                //                 break;
                //             }

                //             // Limit our read to the smaller of our buffer size or what smoltcp can accept
                //             let read_limit = std::cmp::min(max_sendable, read_buf.len());

                //             match stream.read(&mut read_buf[..read_limit]) {
                //                 Ok(0) => {
                //                     // The host closed the connection.
                //                     trace!(?token, "EOF from a host socket");
                //                     socket.close();
                //                     break;
                //                 }
                //                 Ok(n) => {
                //                     // Give the exact data we read to smoltcp. This should not fail
                //                     // since we sized our read to fit.
                //                     if let Err(e) = socket.send_slice(&read_buf[..n]) {
                //                         error!(
                //                             ?token,
                //                             "smoltcp send_slice error after sized read: {}", e
                //                         );
                //                         socket.abort();
                //                         break;
                //                     }
                //                     trace!(?token, bytes = n, "read from host and sent to smoltcp");
                //                 }
                //                 Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                //                     // The mio socket has no more data to read for now.
                //                     break;
                //                 }
                //                 Err(e) => {
                //                     error!(?token, "Error reading from host socket: {}", e);
                //                     socket.abort();
                //                     break;
                //                 }
                //             }
                //         }
                //     }
                // }
                HostSocket::Udp(stream) => {
                    if event.is_readable() {
                        let mut buffer = [0u8; 2048];
                        // Use recv_from to get the data AND the address of the internet server
                        match stream.recv_from(&mut buffer) {
                            Ok((size, source_addr)) => {
                                trace!(?token, bytes = size, from = %source_addr, "read from a host UDP socket");

                                // Look up the target guest for this connection
                                if let Some((guest_endpoint, original_dest_endpoint)) =
                                    self.reverse_nat_table.get(&token)
                                {
                                    if let Some(smoltcp_handle) =
                                        self.udp_listeners.get(original_dest_endpoint)
                                    {
                                        let smoltcp_udp_socket =
                                            self.sockets.get_mut::<smoltcp::socket::udp::Socket>(
                                                *smoltcp_handle,
                                            );

                                        // Construct the metadata to fake the source address
                                        let metadata = smoltcp::socket::udp::UdpMetadata {
                                            endpoint: *guest_endpoint,
                                            local_address: Some(source_addr.ip().into()),
                                            meta: Default::default(),
                                        };

                                        if let Err(e) =
                                            smoltcp_udp_socket.send_slice(&buffer[..size], metadata)
                                        {
                                            error!("smoltcp UDP send_slice error: {}", e);
                                        }
                                    }
                                }
                            }
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => (),
                            Err(e) => error!("Error reading from host UDP socket: {}", e),
                        }
                    }

                    if event.is_writable() {
                        // do nothing
                    }
                }
            }
            self.host_connections.insert(token, (stream, handle));
        }
    }

    fn get_ephemeral_port(&mut self) -> u16 {
        const EPHEMERAL_PORT_MIN: u16 = 49152;

        loop {
            // Get the next port number from our counter.
            let candidate_port = self.next_ephemeral_port;

            // Increment the counter for the next time, wrapping around if needed.
            self.next_ephemeral_port = self.next_ephemeral_port.wrapping_add(1);
            if self.next_ephemeral_port < EPHEMERAL_PORT_MIN {
                self.next_ephemeral_port = EPHEMERAL_PORT_MIN;
            }

            // Check if the candidate port is already in use by any existing socket.
            let is_in_use = self.sockets.iter().any(|(_, socket)| {
                let local_port = match socket {
                    smoltcp::socket::Socket::Tcp(s) => s.local_endpoint().map(|ep| ep.port),
                    smoltcp::socket::Socket::Udp(s) => Some(s.endpoint().port),
                    // Add other socket types here if you use them
                    _ => None,
                };
                local_port == Some(candidate_port)
            });

            // If the port is not in use, we've found one. Return it.
            if !is_in_use {
                return candidate_port;
            }

            // Otherwise, the loop continues and we'll try the next port.
        }
    }

    fn handle_udp_datagram(
        &mut self,
        guest_addr: std::net::Ipv4Addr,
        dest_addr: std::net::Ipv4Addr,
        udp_packet: UdpPacket,
    ) {
        let guest_addr = IpAddress::Ipv4(guest_addr);
        let dest_addr = IpAddress::Ipv4(dest_addr);
        let guest_port = udp_packet.get_source();
        let dest_port = udp_packet.get_destination();

        let guest_endpoint = IpEndpoint::new(guest_addr, guest_port);
        let dest_endpoint = IpEndpoint::new(dest_addr, dest_port);

        // For UDP, we use the NAT table to track "sessions" based on the guest's endpoint
        if self.nat_table.contains_key(&guest_endpoint) {
            // This is part of an existing session, we just need to forward the data.
            // The mio event loop will handle reading/writing subsequent packets.
            // We let smoltcp handle this packet to get it into the socket buffer.
            return;
        }

        info!(
            "New UDP session from guest {}:{} to {}:{}",
            guest_addr, guest_port, dest_addr, dest_port
        );

        let is_ipv4 = dest_addr.version() == IpVersion::Ipv4;

        // Determine IP domain
        let domain = if is_ipv4 { Domain::IPV4 } else { Domain::IPV6 };

        // Create and configure the socket using socket2
        let socket = Socket::new(domain, socket2::Type::DGRAM, None).unwrap();
        const BUF_SIZE: usize = 8 * 1024 * 1024; // 8MB buffer
        if let Err(e) = socket.set_recv_buffer_size(BUF_SIZE) {
            warn!(error = %e, "Failed to set UDP receive buffer size.");
        }
        if let Err(e) = socket.set_send_buffer_size(BUF_SIZE) {
            warn!(error = %e, "Failed to set UDP send buffer size.");
        }
        socket.set_nonblocking(true).unwrap();

        // Bind to a wildcard address
        let bind_addr: SocketAddr = if is_ipv4 { "0.0.0.0:0" } else { "[::]:0" }
            .parse()
            .unwrap();
        socket.bind(&bind_addr.into()).unwrap();

        // This is a new UDP session. Set up the host socket and smoltcp twin.
        // match socket.connect(&real_dest.into()) {
        //     Ok(()) => {
        // 2. Send the initial datagram using the standard socket directly.
        let real_dest = SocketAddr::new(dest_addr.into(), dest_port);
        if let Err(e) = socket.send_to(udp_packet.payload(), &real_dest.into()) {
            error!("Failed to send initial UDP datagram: {}", e);
            return;
        }

        let mut mio_socket = mio::net::UdpSocket::from_std(socket.into());

        let smoltcp_handle = *self.udp_listeners.entry(dest_endpoint).or_insert_with(|| {
            info!("Creating new smoltcp listener for {}", dest_endpoint);
            let rx_buffer = smoltcp::socket::udp::PacketBuffer::new(
                vec![smoltcp::socket::udp::PacketMetadata::EMPTY],
                vec![0; 1280],
            );
            let tx_buffer = smoltcp::socket::udp::PacketBuffer::new(
                vec![smoltcp::socket::udp::PacketMetadata::EMPTY],
                vec![0; 1280],
            );
            let mut socket = smoltcp::socket::udp::Socket::new(rx_buffer, tx_buffer);

            // Bind the socket to the specific destination endpoint.
            socket.bind(dest_endpoint).unwrap();

            self.sockets.add(socket)
        });

        // Register with mio and map the sockets
        let token = Token(self.next_token);
        self.next_token += 1;
        self.registry
            .register(&mut mio_socket, token, Interest::READABLE)
            .unwrap();
        self.host_connections
            .insert(token, (HostSocket::Udp(mio_socket), smoltcp_handle));

        // Add to NAT table to track the session
        self.nat_table.insert(guest_endpoint, token);
        self.reverse_nat_table
            .insert(token, (guest_endpoint, dest_endpoint));

        // let dest_socket_addr =
        //     std::net::SocketAddr::new(dest_addr.into(), udp_packet.get_destination());

        // if let Some((HostSocket::Udp(mio_socket), _)) = self.host_connections.get(&token) {
        //     if let Err(e) = mio_socket.send_to(udp_packet.payload(), dest_socket_addr) {
        //         error!("Failed to send initial UDP datagram: {}", e);
        //     }
        // }
        // }
        // Err(e) => {
        //     error!("Failed to bind host UDP socket: {}", e);
        // }
        // }
    }

    /// Checks if a smoltcp socket is already being tracked.
    fn is_socket_tracked(&self, handle: SocketHandle) -> bool {
        self.host_connections.values().any(|(_, h)| *h == handle)
    }

    /// Signals the guest that there are used descriptors in a queue.
    fn signal_used_queue(&mut self, queue_index: usize) -> Result<(), DeviceError> {
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);
        if let Some(intc) = &self.intc {
            intc.lock()
                .unwrap()
                .set_irq(self.irq_line, Some(&self.interrupt_evt))?;
        }
        Ok(())
    }
}

mod packet_dumper {
    use super::*;
    use pnet::packet::{
        arp::{ArpOperations, ArpPacket},
        ethernet::{EtherTypes, EthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::Ipv4Packet,
        ipv6::Ipv6Packet,
        tcp::{TcpFlags, TcpPacket},
        Packet,
    };
    fn format_tcp_flags(flags: u8) -> String {
        let mut s = String::new();
        if (flags & TcpFlags::SYN) != 0 {
            s.push('S');
        }
        if (flags & TcpFlags::ACK) != 0 {
            s.push('.');
        }
        if (flags & TcpFlags::FIN) != 0 {
            s.push('F');
        }
        if (flags & TcpFlags::RST) != 0 {
            s.push('R');
        }
        if (flags & TcpFlags::PSH) != 0 {
            s.push('P');
        }
        if (flags & TcpFlags::URG) != 0 {
            s.push('U');
        }
        s
    }
    pub fn log_vm_packet_in(data: &[u8]) -> PacketDumper {
        PacketDumper {
            data,
            direction: "VM|IN",
        }
    }
    pub fn log_vm_packet_out(data: &[u8]) -> PacketDumper {
        PacketDumper {
            data,
            direction: "VM|OUT",
        }
    }

    pub struct PacketDumper<'a> {
        data: &'a [u8],
        direction: &'static str,
    }

    impl<'a> std::fmt::Display for PacketDumper<'a> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            if let Some(eth) = EthernetPacket::new(self.data) {
                match eth.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                            let src = ipv4.get_source();
                            let dst = ipv4.get_destination();
                            match ipv4.get_next_level_protocol() {
                                IpNextHeaderProtocols::Tcp => {
                                    if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                        write!(f, "[{}] IP {}.{} > {}.{}: Flags [{}], seq {}, ack {}, win {}, len {}",
                                                self.direction, src, tcp.get_source(), dst, tcp.get_destination(),
                                                format_tcp_flags(tcp.get_flags()), tcp.get_sequence(),
                                                tcp.get_acknowledgement(), tcp.get_window(), tcp.payload().len())
                                    } else {
                                        write!(
                                            f,
                                            "[{}] IP {} > {}: TCP (parse failed)",
                                            self.direction, src, dst
                                        )
                                    }
                                }
                                IpNextHeaderProtocols::Udp => {
                                    if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                        write!(
                                            f,
                                            "[{}] IP {}.{} > {}.{}: len {}",
                                            self.direction,
                                            src,
                                            udp.get_source(),
                                            dst,
                                            udp.get_destination(),
                                            udp.get_length()
                                        )
                                    } else {
                                        write!(
                                            f,
                                            "[{}] IP {} > {}: UDP (parse failed)",
                                            self.direction, src, dst
                                        )
                                    }
                                }
                                _ => write!(
                                    f,
                                    "[{}] IPv4 {} > {}: proto {} ({} > {})",
                                    self.direction,
                                    src,
                                    dst,
                                    ipv4.get_next_level_protocol(),
                                    eth.get_source(),
                                    eth.get_destination(),
                                ),
                            }
                        } else {
                            write!(f, "[{}] IPv4 packet (parse failed)", self.direction)
                        }
                    }
                    EtherTypes::Ipv6 => {
                        if let Some(ipv6) = Ipv6Packet::new(eth.payload()) {
                            let src = ipv6.get_source();
                            let dst = ipv6.get_destination();
                            match ipv6.get_next_header() {
                                IpNextHeaderProtocols::Tcp => {
                                    if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                                        write!(f, "[{}] IP6 [{}]:{} > [{}]:{}: Flags [{}], seq {}, ack {}, win {}, len {}",
                                                self.direction, src, tcp.get_source(), dst, tcp.get_destination(),
                                                format_tcp_flags(tcp.get_flags()), tcp.get_sequence(),
                                                tcp.get_acknowledgement(), tcp.get_window(), tcp.payload().len())
                                    } else {
                                        write!(
                                            f,
                                            "[{}] IP6 {} > {}: TCP (parse failed)",
                                            self.direction, src, dst
                                        )
                                    }
                                }
                                _ => write!(
                                    f,
                                    "[{}] IPv6 {} > {}: proto {}",
                                    self.direction,
                                    src,
                                    dst,
                                    ipv6.get_next_header()
                                ),
                            }
                        } else {
                            write!(f, "[{}] IPv6 packet (parse failed)", self.direction)
                        }
                    }
                    EtherTypes::Arp => {
                        if let Some(arp) = ArpPacket::new(eth.payload()) {
                            write!(
                                f,
                                "[{}] ARP, {}, who has {}? Tell {}",
                                self.direction,
                                if arp.get_operation() == ArpOperations::Request {
                                    "request"
                                } else {
                                    "reply"
                                },
                                arp.get_target_proto_addr(),
                                arp.get_sender_proto_addr()
                            )
                        } else {
                            write!(f, "[{}] ARP packet (parse failed)", self.direction)
                        }
                    }
                    _ => write!(
                        f,
                        "[{}] Unknown L3 protocol: {}",
                        self.direction,
                        eth.get_ethertype()
                    ),
                }
            } else {
                write!(f, "[{}] Ethernet packet (parse failed)", self.direction)
            }
        }
    }
}
