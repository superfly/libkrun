use crate::legacy::IrqChip;
use crate::virtio::net::{MAX_BUFFER_SIZE, QUEUE_SIZE, RX_INDEX, TX_INDEX};
use crate::virtio::{Queue, VIRTIO_MMIO_INT_VRING};
use crate::Error as DeviceError;
use mio::event::Event;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Registry, Token};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::{cmp, mem, result};
use utils::eventfd::{EventFd, EFD_NONBLOCK};
use virtio_bindings::virtio_net::virtio_net_hdr_v1;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use super::device::{FrontendError, RxError, TxError};

// Re-export types from net-proxy for internal use
use bytes::{Buf, Bytes as NetBytes, BytesMut};
use mio::net::{UnixListener, UnixStream};
use net_proxy::backend::{ReadError, WriteError};
use pnet::packet::arp::{ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{self, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::udp::{self, MutableUdpPacket, UdpPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use rand;
use socket2::{Domain, SockAddr, Socket};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn};

const fn vnet_hdr_len() -> usize {
    mem::size_of::<virtio_net_hdr_v1>()
}

fn write_virtio_net_hdr(buf: &mut [u8]) -> usize {
    let len = vnet_hdr_len();
    buf[0..len].fill(0);
    len
}

// Network Configuration
const PROXY_MAC: MacAddr = MacAddr(0x02, 0x00, 0x00, 0x01, 0x02, 0x03);
const VM_MAC: MacAddr = MacAddr(0xde, 0xad, 0xbe, 0xef, 0x00, 0x00);
const PROXY_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 100, 1);
const VM_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 100, 2);
const MAX_SEGMENT_SIZE: usize = 1460;
const UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(30);

// Token definitions
const VIRTQ_TX_TOKEN: Token = Token(0);
const VIRTQ_RX_TOKEN: Token = Token(1);
const PROXY_START_TOKEN: usize = 2;
const VM_READ_BUDGET: u8 = 32;
const HOST_READ_BUDGET: usize = 16;
const MAX_PROXY_QUEUE_SIZE: usize = 32;

// Connection types from net-proxy
type NatKey = (IpAddr, u16, IpAddr, u16);

// TCP Connection states
#[derive(Debug, Clone)]
pub struct EgressConnecting;
#[derive(Debug, Clone)]
pub struct IngressConnecting;
#[derive(Debug, Clone)]
pub struct Established;
#[derive(Debug, Clone)]
pub struct Closing;

// TCP Connection with typestate pattern
pub struct TcpConnection<State> {
    stream: Box<dyn HostStream>,
    tx_seq: u32,
    tx_ack: u32,
    write_buffer: VecDeque<NetBytes>,
    to_vm_buffer: VecDeque<NetBytes>,
    state: State,
}

// Host stream trait
trait HostStream: Read + Write + mio::event::Source + Send {
    fn shutdown(&mut self, how: Shutdown) -> io::Result<()>;
    fn as_any(&self) -> &dyn std::any::Any;
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
}

impl HostStream for mio::net::TcpStream {
    fn shutdown(&mut self, how: Shutdown) -> io::Result<()> {
        self.shutdown(how)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

impl HostStream for UnixStream {
    fn shutdown(&mut self, how: Shutdown) -> io::Result<()> {
        self.shutdown(how)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

// Connection wrapper
enum AnyConnection {
    EgressConnecting(TcpConnection<EgressConnecting>),
    IngressConnecting(TcpConnection<IngressConnecting>),
    Established(TcpConnection<Established>),
    Closing(TcpConnection<Closing>),
}

impl AnyConnection {
    fn stream_mut(&mut self) -> &mut Box<dyn HostStream> {
        match self {
            AnyConnection::EgressConnecting(conn) => &mut conn.stream,
            AnyConnection::IngressConnecting(conn) => &mut conn.stream,
            AnyConnection::Established(conn) => &mut conn.stream,
            AnyConnection::Closing(conn) => &mut conn.stream,
        }
    }

    fn write_buffer(&self) -> &VecDeque<NetBytes> {
        match self {
            AnyConnection::EgressConnecting(conn) => &conn.write_buffer,
            AnyConnection::IngressConnecting(conn) => &conn.write_buffer,
            AnyConnection::Established(conn) => &conn.write_buffer,
            AnyConnection::Closing(conn) => &conn.write_buffer,
        }
    }

    fn to_vm_buffer_mut(&mut self) -> &mut VecDeque<NetBytes> {
        match self {
            AnyConnection::EgressConnecting(conn) => &mut conn.to_vm_buffer,
            AnyConnection::IngressConnecting(conn) => &mut conn.to_vm_buffer,
            AnyConnection::Established(conn) => &mut conn.to_vm_buffer,
            AnyConnection::Closing(conn) => &mut conn.to_vm_buffer,
        }
    }

    fn to_vm_buffer(&self) -> &VecDeque<NetBytes> {
        match self {
            AnyConnection::EgressConnecting(conn) => &conn.to_vm_buffer,
            AnyConnection::IngressConnecting(conn) => &conn.to_vm_buffer,
            AnyConnection::Established(conn) => &conn.to_vm_buffer,
            AnyConnection::Closing(conn) => &conn.to_vm_buffer,
        }
    }

    fn write_buffer_mut(&mut self) -> &mut VecDeque<NetBytes> {
        match self {
            AnyConnection::EgressConnecting(conn) => &mut conn.write_buffer,
            AnyConnection::IngressConnecting(conn) => &mut conn.write_buffer,
            AnyConnection::Established(conn) => &mut conn.write_buffer,
            AnyConnection::Closing(conn) => &mut conn.write_buffer,
        }
    }

    fn tx_seq(&self) -> u32 {
        match self {
            AnyConnection::EgressConnecting(conn) => conn.tx_seq,
            AnyConnection::IngressConnecting(conn) => conn.tx_seq,
            AnyConnection::Established(conn) => conn.tx_seq,
            AnyConnection::Closing(conn) => conn.tx_seq,
        }
    }

    fn tx_ack(&self) -> u32 {
        match self {
            AnyConnection::EgressConnecting(conn) => conn.tx_ack,
            AnyConnection::IngressConnecting(conn) => conn.tx_ack,
            AnyConnection::Established(conn) => conn.tx_ack,
            AnyConnection::Closing(conn) => conn.tx_ack,
        }
    }

    fn inc_tx_seq(&mut self, amount: u32) {
        match self {
            AnyConnection::EgressConnecting(conn) => conn.tx_seq = conn.tx_seq.wrapping_add(amount),
            AnyConnection::IngressConnecting(conn) => {
                conn.tx_seq = conn.tx_seq.wrapping_add(amount)
            }
            AnyConnection::Established(conn) => conn.tx_seq = conn.tx_seq.wrapping_add(amount),
            AnyConnection::Closing(conn) => conn.tx_seq = conn.tx_seq.wrapping_add(amount),
        }
    }
}

impl<State> TcpConnection<State> {
    fn new(
        stream: Box<dyn HostStream>,
        tx_seq: u32,
        tx_ack: u32,
        state: State,
    ) -> TcpConnection<State> {
        TcpConnection {
            stream,
            tx_seq,
            tx_ack,
            write_buffer: VecDeque::new(),
            to_vm_buffer: VecDeque::new(),
            state,
        }
    }
}

impl TcpConnection<EgressConnecting> {
    fn establish(self) -> TcpConnection<Established> {
        TcpConnection {
            stream: self.stream,
            tx_seq: self.tx_seq,
            tx_ack: self.tx_ack,
            write_buffer: self.write_buffer,
            to_vm_buffer: self.to_vm_buffer,
            state: Established,
        }
    }
}

impl TcpConnection<IngressConnecting> {
    fn establish(self) -> TcpConnection<Established> {
        TcpConnection {
            stream: self.stream,
            tx_seq: self.tx_seq,
            tx_ack: self.tx_ack,
            write_buffer: self.write_buffer,
            to_vm_buffer: self.to_vm_buffer,
            state: Established,
        }
    }
}

impl TcpConnection<Established> {
    fn close(self) -> TcpConnection<Closing> {
        TcpConnection {
            stream: self.stream,
            tx_seq: self.tx_seq,
            tx_ack: self.tx_ack,
            write_buffer: self.write_buffer,
            to_vm_buffer: self.to_vm_buffer,
            state: Closing,
        }
    }
}

// Unified NetProxy that handles both virtio queues and network proxying
pub struct UnifiedNetProxy {
    // Virtio queue handling
    queues: Vec<Queue>,
    queue_evts: Vec<EventFd>,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
    intc: Option<IrqChip>,
    irq_line: Option<u32>,
    mem: GuestMemoryMmap,

    // Network proxy functionality
    registry: Registry,
    next_token: usize,
    unix_listeners: HashMap<Token, (UnixListener, u16)>,
    tcp_nat_table: HashMap<NatKey, Token>,
    reverse_tcp_nat: HashMap<Token, NatKey>,
    host_connections: HashMap<Token, AnyConnection>,
    udp_nat_table: HashMap<NatKey, Token>,
    host_udp_sockets: HashMap<Token, (mio::net::UdpSocket, Instant)>,
    reverse_udp_nat: HashMap<Token, NatKey>,
    paused_reads: HashSet<Token>,
    connections_to_remove: Vec<Token>,
    last_udp_cleanup: Instant,

    // Unified polling and buffers
    poll: Poll,
    rx_frame_buf: [u8; MAX_BUFFER_SIZE],
    rx_frame_buf_len: usize,
    rx_has_deferred_frame: bool,
    tx_iovec: Vec<(GuestAddress, usize)>,
    tx_frame_buf: BytesMut,
    tx_frame_len: usize,

    // Network proxy buffers
    packet_buf: BytesMut,
    read_buf: [u8; 16384],
    to_vm_control_queue: VecDeque<NetBytes>,
    data_run_queue: VecDeque<Token>,

    guest_rx_stalled: bool,
}

impl UnifiedNetProxy {
    #[allow(clippy::too_many_arguments)]
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
        let mut next_token = PROXY_START_TOKEN;
        let mut unix_listeners = HashMap::new();

        // Configure socket helper function
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

        // Set up Unix listeners
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

        Ok(Self {
            queues,
            queue_evts,
            interrupt_status,
            interrupt_evt,
            intc,
            irq_line,
            mem,

            registry,
            next_token,
            unix_listeners,
            tcp_nat_table: Default::default(),
            reverse_tcp_nat: Default::default(),
            host_connections: Default::default(),
            udp_nat_table: Default::default(),
            host_udp_sockets: Default::default(),
            reverse_udp_nat: Default::default(),
            paused_reads: Default::default(),
            connections_to_remove: Default::default(),
            last_udp_cleanup: Instant::now(),

            poll,
            rx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            rx_frame_buf_len: 0,
            rx_has_deferred_frame: false,
            tx_frame_buf: BytesMut::zeroed(MAX_BUFFER_SIZE),
            tx_frame_len: 0,
            tx_iovec: Vec::with_capacity(QUEUE_SIZE as usize),

            packet_buf: BytesMut::with_capacity(2048),
            read_buf: [0u8; 16384],
            to_vm_control_queue: Default::default(),
            data_run_queue: Default::default(),

            guest_rx_stalled: false,
        })
    }

    pub fn run(mut self) {
        thread::Builder::new()
            .name("unified-net-proxy".into())
            .spawn(move || self.work())
            .unwrap();
    }

    fn work(&mut self) {
        let mut events = Events::with_capacity(1024);

        // Register virtio queue events
        self.poll
            .registry()
            .register(
                &mut SourceFd(&self.queue_evts[TX_INDEX].as_raw_fd()),
                VIRTQ_TX_TOKEN,
                Interest::READABLE,
            )
            .expect("could not register VIRTQ_TX_TOKEN");

        self.poll
            .registry()
            .register(
                &mut SourceFd(&self.queue_evts[RX_INDEX].as_raw_fd()),
                VIRTQ_RX_TOKEN,
                Interest::READABLE,
            )
            .expect("could not register VIRTQ_RX_TOKEN");

        loop {
            self.poll
                .poll(&mut events, None)
                .expect("could not poll mio events");

            for event in events.iter() {
                match event.token() {
                    VIRTQ_RX_TOKEN => {
                        self.guest_rx_stalled = false;
                        self.process_rx_queue_event();
                    }
                    VIRTQ_TX_TOKEN => {
                        self.process_tx_queue_event();
                    }
                    token => {
                        // Handle network proxy events
                        self.handle_network_event(token, event);
                    }
                }
            }

            // Process any pending frames to VM
            self.process_to_vm_queue();

            // Clean up removed connections
            self.cleanup_connections();
        }
    }

    fn process_rx_queue_event(&mut self) {
        if let Err(e) = self.queue_evts[RX_INDEX].read() {
            log::error!("Failed to get rx event from queue: {:?}", e);
        }
        if let Err(e) = self.queues[RX_INDEX].disable_notification(&self.mem) {
            error!("error disabling queue notifications: {:?}", e);
        }
        if let Err(e) = self.process_rx() {
            log::error!("Failed to process rx: {e:?} (triggered by queue event)")
        };
        if let Err(e) = self.queues[RX_INDEX].enable_notification(&self.mem) {
            error!("error enabling queue notifications: {:?}", e);
        }
    }

    fn process_tx_queue_event(&mut self) {
        match self.queue_evts[TX_INDEX].read() {
            Ok(_) => self.process_tx_loop(),
            Err(e) => {
                log::error!("Failed to get tx queue event from queue: {e:?}");
            }
        }
    }

    fn handle_network_event(&mut self, token: Token, event: &Event) {
        // Handle Unix listener connections
        if let Some((listener, vm_port)) = self.unix_listeners.get_mut(&token) {
            if event.is_readable() {
                // Accept new connections - implementation would go here
                // This is a simplified version
                info!("New connection on Unix listener for port {}", vm_port);
            }
            return;
        }

        // Handle host connections
        if let Some(mut connection) = self.host_connections.remove(&token) {
            let mut reregister_interest: Option<Interest> = None;

            connection = match connection {
                AnyConnection::EgressConnecting(conn) => {
                    if event.is_writable() {
                        info!(
                            ?token,
                            "Egress connection established to host. Sending SYN-ACK to VM."
                        );
                        let nat_key = *self.reverse_tcp_nat.get(&token).unwrap();
                        let syn_ack_packet = build_tcp_packet(
                            nat_key,
                            conn.tx_seq,
                            conn.tx_ack,
                            None,
                            Some(TcpFlags::SYN | TcpFlags::ACK),
                        );
                        self.to_vm_control_queue.push_back(syn_ack_packet);

                        let mut established_conn = conn.establish();
                        established_conn.tx_seq = established_conn.tx_seq.wrapping_add(1);

                        let mut write_error = false;
                        while let Some(data) = established_conn.write_buffer.front_mut() {
                            trace!(
                                ?token,
                                bytes = data.len(),
                                "immediately writing some data that was queued"
                            );
                            match established_conn.stream.write(data) {
                                Ok(0) => {
                                    trace!(?token, "connection EOF'd");
                                    write_error = true;
                                    break;
                                }
                                Ok(n) if n == data.len() => {
                                    trace!(?token, bytes = n, "fully wrote data");
                                    _ = established_conn.write_buffer.pop_front();
                                }
                                Ok(n) => {
                                    trace!(?token, bytes = n, "partially wrote data");
                                    data.advance(n);
                                    break;
                                }
                                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                    trace!(
                                        ?token,
                                        "would block, setting re-register as readable + writable"
                                    );
                                    reregister_interest =
                                        Some(Interest::READABLE | Interest::WRITABLE);
                                    break;
                                }
                                Err(e) => {
                                    trace!(?token, "error writing to conn: {e}");
                                    write_error = true;
                                    break;
                                }
                            }
                        }

                        if write_error {
                            info!(?token, "Closing connection immediately after establishment due to write error.");
                            let _ = established_conn.stream.shutdown(Shutdown::Write);
                            AnyConnection::Closing(TcpConnection {
                                stream: established_conn.stream,
                                tx_seq: established_conn.tx_seq,
                                tx_ack: established_conn.tx_ack,
                                write_buffer: established_conn.write_buffer,
                                to_vm_buffer: established_conn.to_vm_buffer,
                                state: Closing,
                            })
                        } else {
                            if reregister_interest.is_none() {
                                reregister_interest = Some(Interest::READABLE);
                            }
                            AnyConnection::Established(established_conn)
                        }
                    } else {
                        AnyConnection::EgressConnecting(conn)
                    }
                }
                AnyConnection::Established(mut conn) => {
                    let mut keep_connection = true;

                    if event.is_writable() {
                        // Write buffered data to host
                        while let Some(data) = conn.write_buffer.front_mut() {
                            match conn.stream.write(data) {
                                Ok(0) => {
                                    trace!(?token, "Host detected closed connection during write");
                                    keep_connection = false;
                                    break;
                                }
                                Ok(n) if n == data.len() => {
                                    trace!(?token, bytes = n, "Host fully wrote to connection");
                                    conn.write_buffer.pop_front();
                                }
                                Ok(n) => {
                                    trace!(?token, bytes = n, "Host partially wrote to connection");
                                    data.advance(n);
                                    break;
                                }
                                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                    break;
                                }
                                Err(e) => {
                                    error!(?token, error = %e, "Error writing to host socket");
                                    keep_connection = false;
                                    break;
                                }
                            }
                        }
                    }

                    if keep_connection && event.is_readable() {
                        // if self.to_vm_control_queue.len() > MAX_PROXY_QUEUE_SIZE {
                        //     trace!(?token, "VM queue is full, pausing reads from host.");
                        //     self.paused_reads.insert(token);

                        //     // Reregister interest, but WITHOUT READABLE
                        //     if let Err(e) = self.registry.reregister(
                        //         &mut conn.stream,
                        //         token,
                        //         Interest::WRITABLE, // Assuming we still want to know when we can write
                        //     ) {
                        //         error!(?token, error = %e, "Failed to reregister to pause reads");
                        //     }

                        //     // Put the connection back and stop processing this event for now.
                        //     self.host_connections
                        //         .insert(token, AnyConnection::Established(conn));
                        //     return;
                        // }

                        // Read from host and forward to VM
                        let mut read_buf = [0u8; 8192];
                        let mut data_was_read = false;

                        for _ in 0..HOST_READ_BUDGET {
                            if conn.to_vm_buffer.len() > MAX_PROXY_QUEUE_SIZE {
                                trace!(?token, "Per-connection VM queue is full, pausing reads.");
                                self.paused_reads.insert(token);
                                if let Err(e) = self.registry.reregister(
                                    &mut conn.stream,
                                    token,
                                    Interest::WRITABLE,
                                ) {
                                    error!(?token, "could not re-register interest: {e}");
                                    keep_connection = false;
                                }
                                break; // Stop reading from the host socket
                            }
                            match conn.stream.read(&mut read_buf) {
                                Ok(0) => {
                                    // Connection closed by host
                                    info!(?token, "Host detected closed connection during read");
                                    if let Some(&nat_key) = self.reverse_tcp_nat.get(&token) {
                                        let fin_packet = build_tcp_packet(
                                            nat_key,
                                            conn.tx_seq,
                                            conn.tx_ack,
                                            None,
                                            Some(TcpFlags::FIN | TcpFlags::ACK),
                                        );
                                        self.to_vm_control_queue.push_back(fin_packet);
                                        conn.tx_seq = conn.tx_seq.wrapping_add(1);
                                    }
                                    keep_connection = false;
                                    break;
                                }
                                Ok(n) => {
                                    trace!(?token, bytes = n, "Host read from connection");
                                    // Forward data to VM
                                    if let Some(&nat_key) = self.reverse_tcp_nat.get(&token) {
                                        let mut offset = 0;
                                        while offset < n {
                                            let chunk_size =
                                                std::cmp::min(n - offset, MAX_SEGMENT_SIZE);
                                            let chunk = &read_buf[offset..offset + chunk_size];

                                            // trace!(
                                            //     ?token,
                                            //     buffer_len = conn.to_vm_buffer.len(),
                                            //     chunk_len = chunk.len(),
                                            //     current_seq = conn.tx_seq,
                                            //     offset,
                                            //     total_read = n,
                                            //     "Queueing data packet to VM"
                                            // );
                                            // let packet = build_tcp_packet(
                                            //     nat_key,
                                            //     conn.tx_seq,
                                            //     conn.tx_ack,
                                            //     Some(chunk),
                                            //     Some(TcpFlags::ACK | TcpFlags::PSH),
                                            // );
                                            conn.to_vm_buffer
                                                .push_back(NetBytes::copy_from_slice(chunk));

                                            data_was_read = true;
                                            // Update sequence for this chunk
                                            // let old_seq = conn.tx_seq;
                                            // conn.tx_seq =
                                            //     conn.tx_seq.wrapping_add(chunk_size as u32);
                                            // trace!(
                                            //     ?token,
                                            //     old_seq,
                                            //     new_seq = conn.tx_seq,
                                            //     bytes_buffered = chunk_size,
                                            //     "Updated tx_seq after buffering chunk"
                                            // );

                                            offset += chunk_size;
                                        }

                                        // let data_packet = self.build_tcp_packet(
                                        //     nat_key,
                                        //     conn.tx_seq,
                                        //     conn.tx_ack,
                                        //     Some(&read_buf[..n]),
                                        //     Some(TcpFlags::PSH | TcpFlags::ACK),
                                        // );
                                        // self.to_vm_control_queue.push_back(data_packet);
                                        // conn.tx_seq = conn.tx_seq.wrapping_add(n as u32);
                                    }
                                }
                                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                    // No more data available
                                    break;
                                }
                                Err(e) => {
                                    error!(?token, error = %e, "Error reading from host socket");
                                    keep_connection = false;
                                }
                            }
                        }
                        if data_was_read && !self.data_run_queue.contains(&token) {
                            self.data_run_queue.push_back(token);
                        }
                    }

                    if keep_connection {
                        // Update interest based on buffer state
                        if !self.paused_reads.contains(&token) {
                            // Update interest based on buffer state
                            if conn.write_buffer.is_empty() {
                                reregister_interest = Some(Interest::READABLE);
                            } else {
                                reregister_interest = Some(Interest::READABLE | Interest::WRITABLE);
                            }
                        }

                        AnyConnection::Established(conn)
                    } else {
                        self.connections_to_remove.push(token);
                        return; // Don't reinsert the connection
                    }
                }
                other => other, // Handle other states
            };

            // Reregister with new interest if needed
            if let Some(interest) = reregister_interest {
                trace!(?token, ?interest, "re-registering interest");
                if let Err(e) = self
                    .registry
                    .reregister(connection.stream_mut(), token, interest)
                {
                    error!(?token, error = %e, "Failed to reregister connection");
                }
            }

            self.host_connections.insert(token, connection);
        }

        // Handle UDP sockets
        if let Some((socket, _)) = self.host_udp_sockets.get_mut(&token) {
            if event.is_readable() {
                let mut buf = [0u8; 8192];
                match socket.recv(&mut buf) {
                    Ok(n) => {
                        if let Some(&nat_key) = self.reverse_udp_nat.get(&token) {
                            let udp_packet = build_udp_packet(nat_key, &buf[..n]);
                            self.to_vm_control_queue.push_back(udp_packet);
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        // No data available
                    }
                    Err(e) => {
                        error!(?token, error = %e, "Error reading from UDP socket");
                    }
                }
            }
        }
    }

    fn process_to_vm_queue(&mut self) {
        if !self.to_vm_control_queue.is_empty()
            || !self.data_run_queue.is_empty() && !self.guest_rx_stalled
        {
            if let Err(e) = self.queues[RX_INDEX].enable_notification(&self.mem) {
                error!("error disabling queue notifications: {e:?}");
            }
            if let Err(e) = self.process_rx() {
                log::error!("Failed to process rx: {e:?} (triggered by backend socket readable)");
            };
            if let Err(e) = self.queues[RX_INDEX].disable_notification(&self.mem) {
                error!("error disabling queue notifications: {e:?}");
            }
        }
        // if self.to_vm_control_queue.len() < (MAX_PROXY_QUEUE_SIZE / 2) {
        //     // Un-pause at a lower threshold
        //     for token in self.paused_reads.drain() {
        //         if let Some(conn) = self.host_connections.get_mut(&token) {
        //             info!(?token, "Un-pausing reads from host.");
        //             if let Err(e) = self.registry.reregister(
        //                 conn.stream_mut(),
        //                 token,
        //                 Interest::READABLE | Interest::WRITABLE, // Re-enable reading
        //             ) {
        //                 error!(?token, error = %e, "Failed to reregister to unpause reads");
        //             }
        //         }
        //     }
        // }
    }

    fn process_rx(&mut self) -> result::Result<(), RxError> {
        let mut signal_queue = false;

        // 1. --- HIGH PRIORITY: Process the control queue first ---
        while let Some(packet) = self.to_vm_control_queue.pop_front() {
            // This logic remains the same: build a frame and try to write it.
            let header_len = write_virtio_net_hdr(&mut self.rx_frame_buf);
            let len = header_len + packet.len();
            self.rx_frame_buf[header_len..len].copy_from_slice(&packet);
            self.rx_frame_buf_len = len;

            if self.write_frame_to_guest() {
                signal_queue = true;
            } else {
                // If guest is full, put the control packet back at the FRONT and stop.
                // This is critical to prevent losing ACKs.
                warn!("Guest RX queue full, deferring high-priority packet.");
                self.to_vm_control_queue.push_front(packet);
                self.rx_has_deferred_frame = true; // Use the existing deferral mechanism
                break;
            }
        }

        // 2. --- FAIR SCHEDULING: Process the data run queue ---
        let mut budget = VM_READ_BUDGET;
        let num_connections_to_service = self.data_run_queue.len();

        // Loop through the connections that have data to send
        for _ in 0..num_connections_to_service {
            if budget == 0 {
                break;
            }

            // Get the next connection token without removing it yet
            let Some(token) = self.data_run_queue.front().copied() else {
                continue;
            };

            let Some(mut conn) = self.host_connections.remove(&token) else {
                // Connection was removed, clean up from queue
                self.data_run_queue.pop_front();
                continue;
            };

            // Get the next chunk of data from this connection's private buffer
            if let Some(data_chunk) = conn.to_vm_buffer_mut().pop_front() {
                // Now, build the TCP packet from this chunk
                if let Some(&nat_key) = self.reverse_tcp_nat.get(&token) {
                    let tx_seq = conn.tx_seq();
                    let tx_ack = conn.tx_ack();

                    let packet = build_tcp_packet(
                        nat_key,
                        tx_seq,
                        tx_ack,
                        Some(&data_chunk),
                        Some(TcpFlags::ACK | TcpFlags::PSH),
                    );

                    // --- This is the existing logic from the old way ---
                    let header_len = write_virtio_net_hdr(&mut self.rx_frame_buf);
                    let len = header_len + packet.len();
                    self.rx_frame_buf[header_len..len].copy_from_slice(&packet);
                    self.rx_frame_buf_len = len;

                    let wrote = self.write_frame_to_guest();

                    if wrote {
                        signal_queue = true;
                        budget -= 1;

                        conn.inc_tx_seq(data_chunk.len() as u32);
                        if conn.to_vm_buffer().len() < (MAX_PROXY_QUEUE_SIZE / 2)
                            && self.paused_reads.contains(&token)
                        {
                            trace!(?token, "Un-pausing reads from host.");
                            if let Err(e) = self.registry.reregister(
                                conn.stream_mut(),
                                token,
                                Interest::READABLE | Interest::WRITABLE, // Re-enable reading
                            ) {
                                error!(?token, error = %e, "Failed to reregister to unpause reads");
                                // TODO: cleanup!!!
                                continue;
                            }
                            self.paused_reads.remove(&token);
                        }
                    } else {
                        // Guest queue is full. Put data back at the FRONT of the private buffer.
                        warn!("Guest RX queue full, deferring data packet.");
                        conn.to_vm_buffer_mut().push_front(data_chunk);
                        self.rx_has_deferred_frame = true;
                        // Cycle the token that failed to the back of the run queue.
                        if let Some(failed_token) = self.data_run_queue.pop_front() {
                            self.data_run_queue.push_back(failed_token);
                        }
                        self.host_connections.insert(token, conn);
                        self.guest_rx_stalled = true;
                        break;
                    }
                }
            }

            self.host_connections.insert(token, conn);

            // Cycle the token to the back of the queue for fairness
            if let Some(token) = self.data_run_queue.pop_front() {
                // Only re-add it if its buffer is not empty
                if let Some(conn) = self.host_connections.get(&token) {
                    if !conn.to_vm_buffer().is_empty() {
                        self.data_run_queue.push_back(token);
                    }
                }
            }
        }

        if signal_queue {
            self.signal_used_queue().map_err(RxError::DeviceError)?;
        }

        Ok(())
    }

    fn process_tx_loop(&mut self) {
        loop {
            self.queues[TX_INDEX]
                .disable_notification(&self.mem)
                .unwrap();

            if let Err(e) = self.process_tx() {
                log::error!("Failed to process tx: {e:?}");
            };

            if !self.queues[TX_INDEX]
                .enable_notification(&self.mem)
                .unwrap()
            {
                break;
            }
        }
    }

    fn process_tx(&mut self) -> result::Result<(), TxError> {
        let mut raise_irq = false;

        while let Some(head) = self.queues[TX_INDEX].pop(&self.mem) {
            let head_index = head.index;
            let mut read_count = 0;
            let mut next_desc = Some(head);

            self.tx_iovec.clear();
            while let Some(desc) = next_desc {
                if desc.is_write_only() {
                    self.tx_iovec.clear();
                    break;
                }
                self.tx_iovec.push((desc.addr, desc.len as usize));
                read_count += desc.len as usize;
                next_desc = desc.next_descriptor();
            }

            // Copy buffer from across multiple descriptors.
            read_count = 0;
            for (desc_addr, desc_len) in self.tx_iovec.drain(..) {
                let limit = cmp::min(read_count + desc_len, self.tx_frame_buf.len());

                let read_result = self
                    .mem
                    .read_slice(&mut self.tx_frame_buf[read_count..limit], desc_addr);
                match read_result {
                    Ok(()) => {
                        read_count += limit - read_count;
                    }
                    Err(e) => {
                        log::error!("Failed to read slice: {:?}", e);
                        read_count = 0;
                        break;
                    }
                }
            }

            self.tx_frame_len = read_count;
            let buf = self.tx_frame_buf.split_to(read_count);
            let res = self.handle_packet_from_vm(&buf);
            self.tx_frame_buf.unsplit(buf); // re-gain capacity
            match res {
                Ok(()) => {
                    self.tx_frame_len = 0;
                    self.queues[TX_INDEX]
                        .add_used(&self.mem, head_index, 0)
                        .map_err(TxError::QueueError)?;
                    raise_irq = true;
                }
                Err(WriteError::NothingWritten) => {
                    self.queues[TX_INDEX].undo_pop();
                    break;
                }
                Err(WriteError::PartialWrite) => {
                    log::trace!("process_tx: partial write");
                    /*
                    This situation should be pretty rare, assuming reasonably sized socket buffers.
                    We have written only a part of a frame to the backend socket (the socket is full).

                    The frame we have read from the guest remains in tx_frame_buf, and will be sent
                    later.

                    Note that we cannot wait for the backend to process our sending frames, because
                    the backend could be blocked on sending a remainder of a frame to us - us waiting
                    for backend would cause a deadlock.
                     */
                    self.queues[TX_INDEX]
                        .add_used(&self.mem, head_index, 0)
                        .map_err(TxError::QueueError)?;
                    raise_irq = true;
                    break;
                }
                Err(e @ WriteError::Internal(_) | e @ WriteError::ProcessNotRunning) => {
                    return Err(TxError::Backend(e))
                }
            }
        }

        if raise_irq && self.queues[TX_INDEX].needs_notification(&self.mem).unwrap() {
            self.signal_used_queue().map_err(TxError::DeviceError)?;
        }

        Ok(())
    }

    fn handle_packet_from_vm<B: AsRef<[u8]>>(&mut self, buf: B) -> Result<(), WriteError> {
        let raw_packet = buf.as_ref();

        // Skip virtio header
        let eth_start = vnet_hdr_len();
        if raw_packet.len() <= eth_start {
            return Err(WriteError::NothingWritten);
        }

        let eth_packet = &raw_packet[eth_start..];
        trace!("{}", packet_dumper::log_vm_packet_in(eth_packet));
        if let Some(eth_frame) = EthernetPacket::new(eth_packet) {
            match eth_frame.get_ethertype() {
                EtherTypes::Ipv4 | EtherTypes::Ipv6 => {
                    return self.handle_ip_packet(eth_frame.payload())
                }
                EtherTypes::Arp => {
                    let buf = handle_arp_packet(eth_frame.payload())?;
                    self.to_vm_control_queue.push_back(buf);
                    return Ok(());
                }
                _ => return Ok(()),
            }
        }
        Err(WriteError::NothingWritten)
    }

    fn signal_used_queue(&mut self) -> result::Result<(), DeviceError> {
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);
        if let Some(intc) = &self.intc {
            intc.lock()
                .unwrap()
                .set_irq(self.irq_line, Some(&self.interrupt_evt))?;
        }
        Ok(())
    }

    fn write_frame_to_guest_impl(&mut self) -> result::Result<(), FrontendError> {
        let mut result = Ok(());
        let queue = &mut self.queues[RX_INDEX];
        let head_descriptor = queue.pop(&self.mem).ok_or(FrontendError::EmptyQueue)?;
        let head_index = head_descriptor.index;

        let mut frame_slice = &self.rx_frame_buf[..self.rx_frame_buf_len];
        trace!(
            "{}",
            packet_dumper::log_vm_packet_out(&frame_slice[vnet_hdr_len()..])
        );
        let frame_len = frame_slice.len();
        let mut maybe_next_descriptor = Some(head_descriptor);

        while let Some(descriptor) = &maybe_next_descriptor {
            if frame_slice.is_empty() {
                break;
            }

            if !descriptor.is_write_only() {
                result = Err(FrontendError::ReadOnlyDescriptor);
                break;
            }

            let len = std::cmp::min(frame_slice.len(), descriptor.len as usize);
            // trace!(len = descriptor.len, "memory descriptor");
            match self.mem.write_slice(&frame_slice[..len], descriptor.addr) {
                Ok(()) => {
                    frame_slice = &frame_slice[len..];
                }
                Err(e) => {
                    log::error!("Failed to write slice: {:?}", e);
                    result = Err(FrontendError::GuestMemory(e));
                    break;
                }
            }

            maybe_next_descriptor = descriptor.next_descriptor();
            // trace!("got descriptor? {}", maybe_next_descriptor.is_some());
        }

        if result.is_ok() && !frame_slice.is_empty() {
            warn!(
                frame_len,
                "Receiving buffer is too small to hold frame of current size"
            );
            result = Err(FrontendError::DescriptorChainTooSmall);
        }

        // Mark the descriptor chain as used. If an error occurred, skip the descriptor chain.
        let used_len = if result.is_err() { 0 } else { frame_len as u32 };
        queue
            .add_used(&self.mem, head_index, used_len)
            .map_err(FrontendError::QueueError)?;
        result
    }

    fn write_frame_to_guest(&mut self) -> bool {
        let max_iterations = self.queues[RX_INDEX].actual_size();
        for _ in 0..max_iterations {
            match self.write_frame_to_guest_impl() {
                Ok(()) => return true,
                Err(FrontendError::EmptyQueue) => continue,
                Err(_) => continue,
            }
        }
        false
    }

    fn handle_tcp_packet(
        &mut self,
        src_addr: IpAddr,
        dst_addr: IpAddr,
        tcp_packet: &TcpPacket,
    ) -> Result<(), WriteError> {
        let src_port = tcp_packet.get_source();
        let dst_port = tcp_packet.get_destination();
        let nat_key = (src_addr, src_port, dst_addr, dst_port);
        let reverse_nat_key = (dst_addr, dst_port, src_addr, src_port);

        trace!(
            %src_addr,
            %dst_addr,
            %src_port,
            %dst_port,
            "handle tcp packet from VM"
        );

        let token = self
            .tcp_nat_table
            .get(&nat_key)
            .or_else(|| self.tcp_nat_table.get(&reverse_nat_key))
            .copied();

        if let Some(token) = token {
            // Handle existing connection
            if let Some(connection) = self.host_connections.remove(&token) {
                let new_connection_state = match connection {
                    AnyConnection::EgressConnecting(conn) => {
                        trace!(?token, "egress is connecting");
                        AnyConnection::EgressConnecting(conn)
                    }
                    AnyConnection::IngressConnecting(mut conn) => {
                        let flags = tcp_packet.get_flags();
                        if (flags & (TcpFlags::SYN | TcpFlags::ACK))
                            == (TcpFlags::SYN | TcpFlags::ACK)
                        {
                            info!(
                                ?token,
                                "Received SYN-ACK from VM, completing ingress handshake."
                            );
                            conn.tx_ack = tcp_packet.get_sequence().wrapping_add(1);

                            let established_conn = conn.establish();
                            let ack_packet = build_tcp_packet(
                                *self.reverse_tcp_nat.get(&token).unwrap(),
                                established_conn.tx_seq,
                                established_conn.tx_ack,
                                None,
                                Some(TcpFlags::ACK),
                            );
                            self.to_vm_control_queue.push_back(ack_packet);
                            AnyConnection::Established(established_conn)
                        } else {
                            AnyConnection::IngressConnecting(conn)
                        }
                    }
                    AnyConnection::Established(mut conn) => {
                        let incoming_seq = tcp_packet.get_sequence();
                        let payload = tcp_packet.payload();
                        let is_ack_only =
                            payload.is_empty() && (tcp_packet.get_flags() & TcpFlags::ACK) != 0;
                        trace!(
                            ?token,
                            incoming_seq,
                            expected_ack = conn.tx_ack,
                            is_ack_only,
                            "handling established host conn"
                        );

                        let is_valid_packet = incoming_seq == conn.tx_ack
                            || (is_ack_only && incoming_seq == conn.tx_ack.wrapping_sub(1));

                        if is_valid_packet {
                            trace!(?token, "existing established connection");
                            let flags = tcp_packet.get_flags();

                            // Handle RST
                            if (flags & TcpFlags::RST) != 0 {
                                info!(?token, "RST received from VM. Tearing down connection.");
                                self.connections_to_remove.push(token);
                                return Ok(());
                            }

                            let mut should_ack = false;

                            // Handle data (simplified)
                            if !payload.is_empty() {
                                conn.tx_ack = conn.tx_ack.wrapping_add(payload.len() as u32);
                                should_ack = true;

                                if !conn.write_buffer.is_empty() {
                                    // Tthe host-side write buffer is already backlogged, queue new data.
                                    trace!(
                                        ?token,
                                        "Host write buffer has backlog; queueing new data from VM."
                                    );
                                    conn.write_buffer
                                        .push_back(NetBytes::copy_from_slice(payload));
                                } else {
                                    match conn.stream.write(payload) {
                                        Ok(n) => {
                                            if n < payload.len() {
                                                let remainder = &payload[n..];
                                                trace!(?token, "Partial write to host. Buffering {} remaining bytes.", remainder.len());
                                                conn.write_buffer.push_back(
                                                    NetBytes::copy_from_slice(remainder),
                                                );
                                                self.registry.reregister(
                                                    &mut conn.stream,
                                                    token,
                                                    Interest::READABLE | Interest::WRITABLE,
                                                )?;
                                            }
                                        }
                                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                            trace!(
                                            ?token,
                                            "Host socket would block. Buffering entire payload."
                                        );
                                            conn.write_buffer
                                                .push_back(NetBytes::copy_from_slice(payload));
                                            self.registry.reregister(
                                                &mut conn.stream,
                                                token,
                                                Interest::READABLE | Interest::WRITABLE,
                                            )?;
                                        }
                                        Err(e) => {
                                            error!(?token, error = %e, "Error writing to host socket. Closing connection.");
                                            self.connections_to_remove.push(token);
                                        }
                                    }
                                }
                            }

                            // For large payloads that we successfully buffer, ACK immediately to prevent
                            // host flow control stalls, even if VM hasn't read the data yet
                            if !payload.is_empty() && !should_ack {
                                trace!(
                                    ?token,
                                    payload_len = payload.len(),
                                    "Immediate ACK to prevent flow control stall"
                                );
                                should_ack = true;
                            }

                            // Handle FIN
                            if (flags & TcpFlags::FIN) != 0 {
                                conn.tx_ack = conn.tx_ack.wrapping_add(1);
                                should_ack = true;
                            }

                            if should_ack {
                                if let Some(&nat_key) = self.reverse_tcp_nat.get(&token) {
                                    let ack_packet = build_tcp_packet(
                                        nat_key,
                                        conn.tx_seq,
                                        conn.tx_ack,
                                        None,
                                        Some(TcpFlags::ACK),
                                    );
                                    self.to_vm_control_queue.push_back(ack_packet);
                                    trace!(?token, "should ack! pushed packet into queue");
                                }
                            }

                            if (flags & TcpFlags::FIN) != 0 {
                                trace!(?token, "received FIN. closing connection");
                                self.host_connections
                                    .insert(token, AnyConnection::Closing(conn.close()));
                            } else if !self.connections_to_remove.contains(&token) {
                                trace!(?token, "keeping connection");
                                self.host_connections
                                    .insert(token, AnyConnection::Established(conn));
                            }
                        } else {
                            trace!(?token, "ignoring out of order packet");
                            self.host_connections
                                .insert(token, AnyConnection::Established(conn));
                        }
                        return Ok(());
                    }
                    AnyConnection::Closing(conn) => {
                        // Handle closing state
                        AnyConnection::Closing(conn)
                    }
                };
                if !self.connections_to_remove.contains(&token) {
                    self.host_connections.insert(token, new_connection_state);
                }
            }
        } else if (tcp_packet.get_flags() & TcpFlags::SYN) != 0 {
            // New egress connection
            info!(?nat_key, "New egress flow detected");
            let real_dest = SocketAddr::new(dst_addr, dst_port);
            let stream = match dst_addr {
                IpAddr::V4(_) => Socket::new(Domain::IPV4, socket2::Type::STREAM, None),
                IpAddr::V6(_) => Socket::new(Domain::IPV6, socket2::Type::STREAM, None),
            };

            let Ok(sock) = stream else {
                error!(error = %stream.unwrap_err(), "Failed to create egress socket");
                return Ok(());
            };

            sock.set_nonblocking(true).unwrap();

            match sock.connect(&real_dest.into()) {
                Ok(()) => (),
                Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => (),
                Err(e) => {
                    error!(error = %e, "Failed to connect egress socket");
                    return Ok(());
                }
            }

            let stream = mio::net::TcpStream::from_std(sock.into());
            let token = Token(self.next_token);
            self.next_token += 1;
            let mut stream = Box::new(stream);
            self.registry
                .register(&mut stream, token, Interest::READABLE | Interest::WRITABLE)
                .unwrap();

            let conn = TcpConnection::new(
                stream as Box<dyn HostStream>,
                rand::random::<u32>(),
                tcp_packet.get_sequence().wrapping_add(1),
                EgressConnecting,
            );

            self.tcp_nat_table.insert(nat_key, token);
            self.reverse_tcp_nat.insert(token, nat_key);
            self.host_connections
                .insert(token, AnyConnection::EgressConnecting(conn));
        }
        Ok(())
    }

    fn handle_udp_packet(
        &mut self,
        src_addr: IpAddr,
        dst_addr: IpAddr,
        udp_packet: &UdpPacket,
    ) -> Result<(), WriteError> {
        let src_port = udp_packet.get_source();
        let dst_port = udp_packet.get_destination();
        let nat_key = (src_addr, src_port, dst_addr, dst_port);

        let token = *self.udp_nat_table.entry(nat_key).or_insert_with(|| {
            info!(?nat_key, "New egress UDP flow detected");
            let new_token = Token(self.next_token);
            self.next_token += 1;

            let domain = if dst_addr.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            };

            let socket = Socket::new(domain, socket2::Type::DGRAM, None).unwrap();
            socket.set_nonblocking(true).unwrap();

            let bind_addr: SocketAddr = if dst_addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            }
            .parse()
            .unwrap();
            socket.bind(&bind_addr.into()).unwrap();

            let real_dest = SocketAddr::new(dst_addr, dst_port);
            if socket.connect(&real_dest.into()).is_ok() {
                let mut mio_socket = mio::net::UdpSocket::from_std(socket.into());
                self.registry
                    .register(&mut mio_socket, new_token, Interest::READABLE)
                    .unwrap();
                self.reverse_udp_nat.insert(new_token, nat_key);
                self.host_udp_sockets
                    .insert(new_token, (mio_socket, Instant::now()));
            }
            new_token
        });

        if let Some((socket, last_seen)) = self.host_udp_sockets.get_mut(&token) {
            if socket.send(udp_packet.payload()).is_ok() {
                *last_seen = Instant::now();
            }
        }

        Ok(())
    }

    fn cleanup_connections(&mut self) {
        for token in self.connections_to_remove.drain(..) {
            if let Some(_connection) = self.host_connections.remove(&token) {
                info!(?token, "Cleaned up connection");
            }
            self.tcp_nat_table.retain(|_, &mut v| v != token);
            self.reverse_tcp_nat.remove(&token);
            self.udp_nat_table.retain(|_, &mut v| v != token);
            self.reverse_udp_nat.remove(&token);
            self.host_udp_sockets.remove(&token);
            self.paused_reads.remove(&token);
        }

        // Cleanup expired UDP connections
        let now = Instant::now();
        if now.duration_since(self.last_udp_cleanup) > UDP_SESSION_TIMEOUT {
            let expired_tokens: Vec<Token> = self
                .host_udp_sockets
                .iter()
                .filter(|(_, (_, last_seen))| now.duration_since(*last_seen) > UDP_SESSION_TIMEOUT)
                .map(|(&token, _)| token)
                .collect();

            for token in expired_tokens {
                info!(?token, "Cleaning up expired UDP connection");
                self.host_udp_sockets.remove(&token);
                self.reverse_udp_nat.remove(&token);
                self.udp_nat_table.retain(|_, &mut v| v != token);
            }

            self.last_udp_cleanup = now;
        }
    }
    fn handle_ip_packet(&mut self, ip_payload: &[u8]) -> Result<(), WriteError> {
        // Parse IP packet for both IPv4 and IPv6
        let Some(ip_packet) = IpPacket::new(ip_payload) else {
            return Err(WriteError::NothingWritten);
        };

        let (src_addr, dst_addr, protocol, payload) = (
            ip_packet.get_source(),
            ip_packet.get_destination(),
            ip_packet.get_next_header(),
            ip_packet.payload(),
        );
        match protocol {
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp) = TcpPacket::new(payload) {
                    return self.handle_tcp_packet(src_addr, dst_addr, &tcp);
                }
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(udp) = UdpPacket::new(payload) {
                    return self.handle_udp_packet(src_addr, dst_addr, &udp);
                }
            }
            _ => return Ok(()), // Ignore other protocols
        }

        Err(WriteError::NothingWritten)
    }
}

enum IpPacket<'p> {
    V4(Ipv4Packet<'p>),
    V6(Ipv6Packet<'p>),
}

impl<'p> IpPacket<'p> {
    fn new(ip_payload: &'p [u8]) -> Option<Self> {
        if let Some(ipv4) = Ipv4Packet::new(ip_payload) {
            Some(Self::V4(ipv4))
        } else if let Some(ipv6) = Ipv6Packet::new(ip_payload) {
            Some(Self::V6(ipv6))
        } else {
            None
        }
    }

    fn get_source(&self) -> IpAddr {
        match self {
            IpPacket::V4(ipp) => IpAddr::V4(ipp.get_source()),
            IpPacket::V6(ipp) => IpAddr::V6(ipp.get_source()),
        }
    }
    fn get_destination(&self) -> IpAddr {
        match self {
            IpPacket::V4(ipp) => IpAddr::V4(ipp.get_destination()),
            IpPacket::V6(ipp) => IpAddr::V6(ipp.get_destination()),
        }
    }

    fn get_next_header(&self) -> IpNextHeaderProtocol {
        match self {
            IpPacket::V4(ipp) => ipp.get_next_level_protocol(),
            IpPacket::V6(ipp) => ipp.get_next_header(),
        }
    }

    fn payload(&self) -> &[u8] {
        match self {
            IpPacket::V4(ipp) => ipp.payload(),
            IpPacket::V6(ipp) => ipp.payload(),
        }
    }
}

fn handle_arp_packet(arp_payload: &[u8]) -> Result<NetBytes, WriteError> {
    if let Some(arp) = ArpPacket::new(arp_payload) {
        if arp.get_operation() == ArpOperations::Request && arp.get_target_proto_addr() == PROXY_IP
        {
            debug!("Responding to ARP request for {}", PROXY_IP);
            let reply = build_arp_reply(&arp);
            return Ok(reply);
        }
    }
    Err(WriteError::NothingWritten)
}

fn build_arp_reply(request: &ArpPacket) -> NetBytes {
    let mut buf = vec![0u8; 42]; // Ethernet header (14) + ARP packet (28)

    // Build Ethernet header
    let mut eth_packet = MutableEthernetPacket::new(&mut buf).unwrap();
    eth_packet.set_destination(VM_MAC);
    eth_packet.set_source(PROXY_MAC);
    eth_packet.set_ethertype(EtherTypes::Arp);

    // Build ARP reply
    let mut arp_reply = MutableArpPacket::new(eth_packet.payload_mut()).unwrap();
    arp_reply.set_hardware_type(pnet::packet::arp::ArpHardwareTypes::Ethernet);
    arp_reply.set_protocol_type(EtherTypes::Ipv4);
    arp_reply.set_hw_addr_len(6);
    arp_reply.set_proto_addr_len(4);
    arp_reply.set_operation(ArpOperations::Reply);
    arp_reply.set_sender_hw_addr(PROXY_MAC);
    arp_reply.set_sender_proto_addr(PROXY_IP);
    arp_reply.set_target_hw_addr(request.get_sender_hw_addr());
    arp_reply.set_target_proto_addr(request.get_sender_proto_addr());

    NetBytes::from(buf)
}

fn build_tcp_packet(
    nat_key: NatKey,
    tx_seq: u32,
    tx_ack: u32,
    payload: Option<&[u8]>,
    flags: Option<u8>,
    // window_size: u16,
) -> NetBytes {
    let (key_src_ip, key_src_port, key_dst_ip, key_dst_port) = nat_key;
    let (packet_src_ip, packet_src_port, packet_dst_ip, packet_dst_port) =
        if key_src_ip == IpAddr::V4(PROXY_IP) {
            (key_src_ip, key_src_port, key_dst_ip, key_dst_port) // Ingress
        } else {
            (key_dst_ip, key_dst_port, key_src_ip, key_src_port) // Egress Reply
        };

    let packet = match (packet_src_ip, packet_dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => build_ipv4_tcp_packet(
            src,
            dst,
            packet_src_port,
            packet_dst_port,
            tx_seq,
            tx_ack,
            payload,
            flags,
            // window_size,
        ),
        (IpAddr::V6(src), IpAddr::V6(dst)) => build_ipv6_tcp_packet(
            src,
            dst,
            packet_src_port,
            packet_dst_port,
            tx_seq,
            tx_ack,
            payload,
            flags,
            // window_size,
        ),
        _ => {
            return NetBytes::new();
        }
    };
    packet
}

fn build_ipv4_tcp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    tx_seq: u32,
    tx_ack: u32,
    payload: Option<&[u8]>,
    flags: Option<u8>,
    // window_size: u16,
) -> NetBytes {
    let payload_data = payload.unwrap_or(&[]);
    let total_len = 14 + 20 + 20 + payload_data.len();
    let mut packet_buf = vec![0u8; total_len];

    let (eth_slice, ip_slice) = packet_buf.split_at_mut(14);
    let mut eth = MutableEthernetPacket::new(eth_slice).unwrap();
    eth.set_destination(VM_MAC);
    eth.set_source(PROXY_MAC);
    eth.set_ethertype(EtherTypes::Ipv4);

    let mut ip = MutableIpv4Packet::new(ip_slice).unwrap();
    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_total_length((20 + 20 + payload_data.len()) as u16);
    ip.set_ttl(64);
    ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip.set_source(src_ip);
    ip.set_destination(dst_ip);

    let mut tcp = MutableTcpPacket::new(ip.payload_mut()).unwrap();
    tcp.set_source(src_port);
    tcp.set_destination(dst_port);
    tcp.set_sequence(tx_seq);
    tcp.set_acknowledgement(tx_ack);
    tcp.set_data_offset(5);
    tcp.set_window(u16::MAX);
    if let Some(f) = flags {
        tcp.set_flags(f);
    }
    tcp.set_payload(payload_data);
    tcp.set_checksum(tcp::ipv4_checksum(&tcp.to_immutable(), &src_ip, &dst_ip));

    ip.set_checksum(ipv4::checksum(&ip.to_immutable()));

    packet_buf.into()
}

fn build_ipv6_tcp_packet(
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    tx_seq: u32,
    tx_ack: u32,
    payload: Option<&[u8]>,
    flags: Option<u8>,
    // window_size: u16,
) -> NetBytes {
    let payload_data = payload.unwrap_or(&[]);
    let total_len = 14 + 40 + 20 + payload_data.len();
    let mut packet_buf = vec![0u8; total_len];

    let (eth_slice, ip_slice) = packet_buf.split_at_mut(14);
    let mut eth = MutableEthernetPacket::new(eth_slice).unwrap();
    eth.set_destination(VM_MAC);
    eth.set_source(PROXY_MAC);
    eth.set_ethertype(EtherTypes::Ipv6);

    let mut ip = MutableIpv6Packet::new(ip_slice).unwrap();
    ip.set_version(6);
    ip.set_payload_length((20 + payload_data.len()) as u16);
    ip.set_next_header(IpNextHeaderProtocols::Tcp);
    ip.set_hop_limit(64);
    ip.set_source(src_ip);
    ip.set_destination(dst_ip);

    let mut tcp = MutableTcpPacket::new(ip.payload_mut()).unwrap();
    tcp.set_source(src_port);
    tcp.set_destination(dst_port);
    tcp.set_sequence(tx_seq);
    tcp.set_acknowledgement(tx_ack);
    tcp.set_data_offset(5);
    tcp.set_window(u16::MAX);
    if let Some(f) = flags {
        tcp.set_flags(f);
    }
    tcp.set_payload(payload_data);
    tcp.set_checksum(tcp::ipv6_checksum(&tcp.to_immutable(), &src_ip, &dst_ip));

    packet_buf.into()
}

fn build_udp_packet(nat_key: NatKey, payload: &[u8]) -> NetBytes {
    let (key_src_ip, key_src_port, key_dst_ip, key_dst_port) = nat_key;
    let (packet_src_ip, packet_src_port, packet_dst_ip, packet_dst_port) =
        (key_dst_ip, key_dst_port, key_src_ip, key_src_port); // Always a reply

    match (packet_src_ip, packet_dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            build_ipv4_udp_packet(src, dst, packet_src_port, packet_dst_port, payload)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            build_ipv6_udp_packet(src, dst, packet_src_port, packet_dst_port, payload)
        }
        _ => NetBytes::new(),
    }
}

fn build_ipv4_udp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> NetBytes {
    let total_len = 14 + 20 + 8 + payload.len();
    let mut packet_buf = vec![0u8; total_len];

    let (eth_slice, ip_slice) = packet_buf.split_at_mut(14);
    let mut eth = MutableEthernetPacket::new(eth_slice).unwrap();
    eth.set_destination(VM_MAC);
    eth.set_source(PROXY_MAC);
    eth.set_ethertype(EtherTypes::Ipv4);

    let mut ip = MutableIpv4Packet::new(ip_slice).unwrap();
    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_total_length((20 + 8 + payload.len()) as u16);
    ip.set_ttl(64);
    ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ip.set_source(src_ip);
    ip.set_destination(dst_ip);

    let mut udp = MutableUdpPacket::new(ip.payload_mut()).unwrap();
    udp.set_source(src_port);
    udp.set_destination(dst_port);
    udp.set_length((8 + payload.len()) as u16);
    udp.set_payload(payload);
    udp.set_checksum(udp::ipv4_checksum(&udp.to_immutable(), &src_ip, &dst_ip));

    ip.set_checksum(ipv4::checksum(&ip.to_immutable()));

    packet_buf.into()
}

fn build_ipv6_udp_packet(
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> NetBytes {
    let total_len = 14 + 40 + 8 + payload.len();
    let mut packet_buf = vec![0u8; total_len];

    let (eth_slice, ip_slice) = packet_buf.split_at_mut(14);
    let mut eth = MutableEthernetPacket::new(eth_slice).unwrap();
    eth.set_destination(VM_MAC);
    eth.set_source(PROXY_MAC);
    eth.set_ethertype(EtherTypes::Ipv6);

    let mut ip = MutableIpv6Packet::new(ip_slice).unwrap();
    ip.set_version(6);
    ip.set_payload_length((8 + payload.len()) as u16);
    ip.set_next_header(IpNextHeaderProtocols::Udp);
    ip.set_hop_limit(64);
    ip.set_source(src_ip);
    ip.set_destination(dst_ip);

    let mut udp = MutableUdpPacket::new(ip.payload_mut()).unwrap();
    udp.set_source(src_port);
    udp.set_destination(dst_port);
    udp.set_length((8 + payload.len()) as u16);
    udp.set_payload(payload);
    udp.set_checksum(udp::ipv6_checksum(&udp.to_immutable(), &src_ip, &dst_ip));

    packet_buf.into()
}

mod packet_dumper {
    use super::*;
    use pnet::packet::Packet;
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

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::arp::{ArpOperations, ArpPacket};
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::tcp::{TcpFlags, TcpPacket};
    use pnet::packet::udp::UdpPacket;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_tcp_packet_building() {
        let nat_key = (IpAddr::V4(PROXY_IP), 12345, IpAddr::V4(VM_IP), 8080);

        let mut packet_buf = BytesMut::with_capacity(2048);
        let tcp_packet = build_tcp_packet_simple(&mut packet_buf, nat_key, 1000, 2000, b"Hello");

        assert!(!tcp_packet.is_empty());

        // Parse and verify
        let eth_packet = EthernetPacket::new(&tcp_packet).unwrap();
        assert_eq!(eth_packet.get_destination(), VM_MAC);
        assert_eq!(eth_packet.get_source(), PROXY_MAC);

        let ipv4_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();
        assert_eq!(ipv4_packet.get_source(), PROXY_IP);
        assert_eq!(ipv4_packet.get_destination(), VM_IP);

        let tcp_parsed = TcpPacket::new(ipv4_packet.payload()).unwrap();
        assert_eq!(tcp_parsed.get_source(), 12345);
        assert_eq!(tcp_parsed.get_destination(), 8080);
        assert_eq!(tcp_parsed.get_sequence(), 1000);
        assert_eq!(tcp_parsed.get_acknowledgement(), 2000);
    }

    #[test]
    fn test_arp_reply_building() {
        let mut packet_buf = BytesMut::with_capacity(64);
        let arp_packet = build_arp_reply_simple(&mut packet_buf);

        assert_eq!(arp_packet.len(), 42); // Ethernet + ARP

        let eth_packet = EthernetPacket::new(&arp_packet).unwrap();
        assert_eq!(eth_packet.get_ethertype(), EtherTypes::Arp);

        let arp_parsed = ArpPacket::new(eth_packet.payload()).unwrap();
        assert_eq!(arp_parsed.get_operation(), ArpOperations::Reply);
        assert_eq!(arp_parsed.get_sender_hw_addr(), PROXY_MAC);
        assert_eq!(arp_parsed.get_sender_proto_addr(), PROXY_IP);
    }

    #[test]
    fn test_nat_table_operations() {
        use std::collections::HashMap;

        let mut nat_table: HashMap<NatKey, Token> = HashMap::new();
        let mut reverse_nat: HashMap<Token, NatKey> = HashMap::new();

        let nat_key = (
            IpAddr::V4(VM_IP),
            12345,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
        );
        let token = Token(100);

        // Test insertion
        nat_table.insert(nat_key, token);
        reverse_nat.insert(token, nat_key);

        // Test lookup
        assert_eq!(nat_table.get(&nat_key), Some(&token));
        assert_eq!(reverse_nat.get(&token), Some(&nat_key));

        // Test cleanup
        nat_table.remove(&nat_key);
        reverse_nat.remove(&token);

        assert!(!nat_table.contains_key(&nat_key));
        assert!(!reverse_nat.contains_key(&token));
    }

    // Helper functions for testing
    fn build_tcp_packet_simple(
        packet_buf: &mut BytesMut,
        nat_key: NatKey,
        seq: u32,
        ack: u32,
        payload: &[u8],
    ) -> bytes::Bytes {
        let (src_addr, src_port, dst_addr, dst_port) = nat_key;
        let total_len = 14 + 20 + 20 + payload.len();

        packet_buf.resize(total_len, 0);

        // Build Ethernet header
        let mut eth = MutableEthernetPacket::new(packet_buf).unwrap();
        eth.set_destination(VM_MAC);
        eth.set_source(PROXY_MAC);
        eth.set_ethertype(EtherTypes::Ipv4);

        // Build IPv4 header
        let mut ipv4 = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length((20 + 20 + payload.len()) as u16);
        ipv4.set_next_level_protocol(IpNextHeaderProtocols::Tcp);

        if let (IpAddr::V4(src), IpAddr::V4(dst)) = (src_addr, dst_addr) {
            ipv4.set_source(src);
            ipv4.set_destination(dst);
        }

        // Build TCP header
        let mut tcp = MutableTcpPacket::new(ipv4.payload_mut()).unwrap();
        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(ack);
        tcp.set_data_offset(5);
        tcp.set_flags(TcpFlags::ACK);
        tcp.set_payload(payload);

        packet_buf.split().freeze()
    }

    fn build_arp_reply_simple(packet_buf: &mut BytesMut) -> &[u8] {
        packet_buf.resize(42, 0);

        let mut eth = MutableEthernetPacket::new(packet_buf).unwrap();
        eth.set_destination(VM_MAC);
        eth.set_source(PROXY_MAC);
        eth.set_ethertype(EtherTypes::Arp);

        let mut arp = MutableArpPacket::new(eth.payload_mut()).unwrap();
        arp.set_operation(ArpOperations::Reply);
        arp.set_sender_hw_addr(PROXY_MAC);
        arp.set_sender_proto_addr(PROXY_IP);
        arp.set_target_hw_addr(VM_MAC);
        arp.set_target_proto_addr(VM_IP);

        packet_buf
    }
}
