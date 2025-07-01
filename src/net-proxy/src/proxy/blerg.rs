use bytes::{Buf, Bytes, BytesMut};
use mio::event::Source;
use mio::net::{TcpStream, UdpSocket, UnixListener, UnixStream};
use mio::{Interest, Registry, Token};
use pnet::packet::arp::{ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{self, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::udp::{self, MutableUdpPacket, UdpPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use socket2::{Domain, SockAddr, Socket};
use std::any::Any;
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr};
use std::os::fd::AsRawFd;
use std::os::unix::prelude::RawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn};
use utils::eventfd::EventFd;

use crate::backend::{NetBackend, ReadError, WriteError};

// --- Network Configuration ---
const PROXY_MAC: MacAddr = MacAddr(0x02, 0x00, 0x00, 0x01, 0x02, 0x03);
const VM_MAC: MacAddr = MacAddr(0xde, 0xad, 0xbe, 0xef, 0x00, 0x00);
const PROXY_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 100, 1);
const VM_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 100, 2);
const MAX_SEGMENT_SIZE: usize = 1460;
const UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(30);

// --- Simplified Flow Control ---
const BACKPRESSURE_THRESHOLD: usize = 64;
const HOST_READ_BUDGET: usize = 16;
const MAX_CONN_BUFFER_SIZE: usize = 256;

const MAX_PROXY_QUEUE_SIZE: usize = 32;

// --- Typestate Pattern for Connections ---
#[derive(Debug, Clone)]
pub struct EgressConnecting;
#[derive(Debug, Clone)]
pub struct IngressConnecting;
#[derive(Debug, Clone)]
pub struct Established;
#[derive(Debug, Clone)]
pub struct Closing;

pub struct TcpConnection<State> {
    stream: BoxedHostStream,
    tx_seq: u32,
    tx_ack: u32,
    write_buffer: VecDeque<Bytes>,
    to_vm_buffer: VecDeque<Bytes>,
    is_in_run_queue: bool,
    #[allow(dead_code)]
    state: State,
}

enum AnyConnection {
    EgressConnecting(TcpConnection<EgressConnecting>),
    IngressConnecting(TcpConnection<IngressConnecting>),
    Established(TcpConnection<Established>),
    Closing(TcpConnection<Closing>),
}

// --- Trait and Impls for Connection Management ---
trait HostStream: Read + Write + Source + Send + Any {
    fn shutdown(&mut self, how: Shutdown) -> io::Result<()>;
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}
impl HostStream for TcpStream {
    fn shutdown(&mut self, how: Shutdown) -> io::Result<()> {
        TcpStream::shutdown(self, how)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
impl HostStream for UnixStream {
    fn shutdown(&mut self, how: Shutdown) -> io::Result<()> {
        UnixStream::shutdown(self, how)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
type BoxedHostStream = Box<dyn HostStream>;
type NatKey = (IpAddr, u16, IpAddr, u16);

impl<State> TcpConnection<State> {
    fn stream_mut(&mut self) -> &mut BoxedHostStream {
        &mut self.stream
    }
}

pub trait ConnectingState {}
impl ConnectingState for EgressConnecting {}
impl ConnectingState for IngressConnecting {}

impl<S: ConnectingState> TcpConnection<S> {
    fn establish(self) -> TcpConnection<Established> {
        info!("Connection established");
        TcpConnection {
            stream: self.stream,
            tx_seq: self.tx_seq,
            tx_ack: self.tx_ack,
            write_buffer: self.write_buffer,
            to_vm_buffer: self.to_vm_buffer,
            is_in_run_queue: self.is_in_run_queue,
            state: Established,
        }
    }
}

impl TcpConnection<Established> {
    fn close(mut self) -> TcpConnection<Closing> {
        info!(?self.tx_seq, ?self.tx_ack, "Closing connection");
        let _ = self.stream.shutdown(Shutdown::Write);
        TcpConnection {
            stream: self.stream,
            tx_seq: self.tx_seq,
            tx_ack: self.tx_ack,
            write_buffer: self.write_buffer,
            to_vm_buffer: self.to_vm_buffer,
            is_in_run_queue: self.is_in_run_queue,
            state: Closing,
        }
    }
}

impl AnyConnection {
    fn to_vm_buffer_mut(&mut self) -> &mut VecDeque<Bytes> {
        match self {
            AnyConnection::EgressConnecting(c) => &mut c.to_vm_buffer,
            AnyConnection::IngressConnecting(c) => &mut c.to_vm_buffer,
            AnyConnection::Established(c) => &mut c.to_vm_buffer,
            AnyConnection::Closing(c) => &mut c.to_vm_buffer,
        }
    }
    fn to_vm_buffer(&self) -> &VecDeque<Bytes> {
        match self {
            AnyConnection::EgressConnecting(c) => &c.to_vm_buffer,
            AnyConnection::IngressConnecting(c) => &c.to_vm_buffer,
            AnyConnection::Established(c) => &c.to_vm_buffer,
            AnyConnection::Closing(c) => &c.to_vm_buffer,
        }
    }
    fn stream_mut(&mut self) -> &mut BoxedHostStream {
        match self {
            AnyConnection::EgressConnecting(c) => &mut c.stream,
            AnyConnection::IngressConnecting(c) => &mut c.stream,
            AnyConnection::Established(c) => &mut c.stream,
            AnyConnection::Closing(c) => &mut c.stream,
        }
    }
    fn is_in_run_queue_mut(&mut self) -> &mut bool {
        match self {
            AnyConnection::EgressConnecting(c) => &mut c.is_in_run_queue,
            AnyConnection::IngressConnecting(c) => &mut c.is_in_run_queue,
            AnyConnection::Established(c) => &mut c.is_in_run_queue,
            AnyConnection::Closing(c) => &mut c.is_in_run_queue,
        }
    }
}

pub struct NetProxy {
    waker: Arc<EventFd>,
    registry: mio::Registry,
    next_token: usize,

    unix_listeners: HashMap<Token, (UnixListener, u16)>,
    tcp_nat_table: HashMap<NatKey, Token>,
    reverse_tcp_nat: HashMap<Token, NatKey>,
    host_connections: HashMap<Token, AnyConnection>,
    udp_nat_table: HashMap<NatKey, Token>,
    host_udp_sockets: HashMap<Token, (UdpSocket, Instant)>,
    reverse_udp_nat: HashMap<Token, NatKey>,

    connections_to_remove: Vec<Token>,
    last_udp_cleanup: Instant,

    packet_buf: BytesMut,
    read_buf: [u8; 8192],

    to_vm_control_queue: VecDeque<Bytes>,
    to_vm_data_queue: VecDeque<Bytes>,
    data_run_queue: VecDeque<Token>,
}

impl NetProxy {
    pub fn new(
        waker: Arc<EventFd>,
        registry: Registry,
        start_token: usize,
        listeners: Vec<(u16, String)>,
    ) -> io::Result<Self> {
        let mut next_token = start_token;
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

        Ok(Self {
            waker,
            registry,
            next_token,
            unix_listeners,
            tcp_nat_table: Default::default(),
            reverse_tcp_nat: Default::default(),
            host_connections: Default::default(),
            udp_nat_table: Default::default(),
            host_udp_sockets: Default::default(),
            reverse_udp_nat: Default::default(),
            connections_to_remove: Default::default(),
            last_udp_cleanup: Instant::now(),
            packet_buf: BytesMut::with_capacity(2048),
            read_buf: [0u8; 8192],
            to_vm_control_queue: VecDeque::with_capacity(64),
            to_vm_data_queue: VecDeque::with_capacity(256),
            data_run_queue: VecDeque::with_capacity(128),
        })
    }

    fn add_to_run_queue(&mut self, token: Token) {
        if let Some(conn) = self.host_connections.get_mut(&token) {
            let is_in_queue = conn.is_in_run_queue_mut();
            if !*is_in_queue {
                self.data_run_queue.push_back(token);
                *is_in_queue = true;
                trace!(?token, "Added connection to data run queue.");
            }
        }
    }

    fn process_run_queue(&mut self) {
        let num_to_process = self.data_run_queue.len();
        if num_to_process == 0 {
            return;
        }
        trace!("Processing data run queue of length {}", num_to_process);

        for _ in 0..num_to_process {
            if let Some(token) = self.data_run_queue.pop_front() {
                let mut re_add = false;
                if let Some(conn) = self.host_connections.get_mut(&token) {
                    *conn.is_in_run_queue_mut() = false;
                    if let Some(packet) = conn.to_vm_buffer_mut().pop_front() {
                        trace!(?token, "Moved one data packet to main data queue.");
                        self.to_vm_data_queue.push_back(packet);
                    }

                    // Check if draining this packet has brought the buffer below the pause threshold.
                    // If the connection was paused, this is our chance to un-pause it.
                    if conn.to_vm_buffer().len() < MAX_PROXY_QUEUE_SIZE {
                        if self.paused_reads.remove(&token) {
                            info!(?token, "Queue draining. Unpausing reads for connection.");
                            // We must re-register interest in READABLE events now.
                            let interest = if conn.write_buffer().is_empty() {
                                Interest::READABLE
                            } else {
                                Interest::READABLE.add(Interest::WRITABLE)
                            };
                            if let Err(e) =
                                self.registry.reregister(conn.stream_mut(), token, interest)
                            {
                                error!(?token, "Failed to reregister to unpause: {}", e);
                            }
                        }
                    }

                    if !conn.to_vm_buffer_mut().is_empty() {
                        re_add = true;
                    }
                }
                if re_add {
                    self.add_to_run_queue(token);
                }
            }
        }
    }

    fn read_from_host_socket(
        &mut self,
        conn: &mut TcpConnection<Established>,
        token: Token,
    ) -> io::Result<()> {
        if conn.to_vm_buffer.len() >= BACKPRESSURE_THRESHOLD {
            trace!(
                ?token,
                buffer_len = conn.to_vm_buffer.len(),
                "Backpressure applied, not reading from host."
            );
            return Ok(());
        }

        trace!(?token, "Reading from host socket.");
        for i in 0..HOST_READ_BUDGET {
            match conn.stream.read(&mut self.read_buf) {
                Ok(0) => {
                    info!(?token, "Host closed connection gracefully.");
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Host closed connection",
                    ));
                }
                Ok(n) => {
                    trace!(
                        ?token,
                        "Read {} bytes from host (budget item {}/{})",
                        n,
                        i + 1,
                        HOST_READ_BUDGET
                    );
                    let mut offset = 0;
                    while offset < n {
                        if conn.to_vm_buffer.len() >= MAX_CONN_BUFFER_SIZE {
                            warn!(
                                ?token,
                                "Connection buffer full, dropping excess data from host."
                            );
                            break;
                        }
                        let chunk_size = std::cmp::min(n - offset, MAX_SEGMENT_SIZE);
                        let chunk = &self.read_buf[offset..offset + chunk_size];

                        if let Some(&nat_key) = self.reverse_tcp_nat.get(&token) {
                            let packet = build_tcp_packet(
                                &mut self.packet_buf,
                                nat_key,
                                conn.tx_seq,
                                conn.tx_ack,
                                Some(chunk),
                                Some(TcpFlags::ACK | TcpFlags::PSH),
                                u16::MAX,
                            );
                            conn.tx_seq = conn.tx_seq.wrapping_add(chunk_size as u32);
                            conn.to_vm_buffer.push_back(packet);
                        }
                        offset += chunk_size;
                    }
                    if !conn.to_vm_buffer.is_empty() {
                        self.add_to_run_queue(token);
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    error!(?token, "Error reading from host socket: {}", e);
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    pub fn handle_packet_from_vm(&mut self, raw_packet: &[u8]) -> Result<(), WriteError> {
        trace!(
            "Handling packet from VM ({} bytes): {}",
            raw_packet.len(),
            packet_dumper::log_packet_in(raw_packet)
        );
        if let Some(eth_frame) = EthernetPacket::new(raw_packet) {
            match eth_frame.get_ethertype() {
                EtherTypes::Ipv4 | EtherTypes::Ipv6 => self.handle_ip_packet(eth_frame.payload()),
                EtherTypes::Arp => self.handle_arp_packet(eth_frame.payload()),
                _ => {
                    trace!(
                        "Ignoring unknown L3 protocol: {}",
                        eth_frame.get_ethertype()
                    );
                    Ok(())
                }
            }
        } else {
            Err(WriteError::NothingWritten)
        }
    }

    pub fn handle_arp_packet(&mut self, arp_payload: &[u8]) -> Result<(), WriteError> {
        if let Some(arp) = ArpPacket::new(arp_payload) {
            if arp.get_operation() == ArpOperations::Request
                && arp.get_target_proto_addr() == PROXY_IP
            {
                debug!("Responding to ARP request for {}", PROXY_IP);
                let reply = build_arp_reply(&mut self.packet_buf, &arp);
                self.to_vm_control_queue.push_back(reply);
                return Ok(());
            }
        }
        Err(WriteError::NothingWritten)
    }

    pub fn handle_ip_packet(&mut self, ip_payload: &[u8]) -> Result<(), WriteError> {
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
                    self.handle_tcp_packet(src_addr, dst_addr, &tcp)
                } else {
                    Err(WriteError::NothingWritten)
                }
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(udp) = UdpPacket::new(payload) {
                    self.handle_udp_packet(src_addr, dst_addr, &udp)
                } else {
                    Err(WriteError::NothingWritten)
                }
            }
            _ => {
                trace!("Ignoring unknown L4 protocol: {}", protocol);
                Ok(())
            }
        }
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
        let token = self
            .tcp_nat_table
            .get(&nat_key)
            .or_else(|| {
                let reverse_nat_key = (dst_addr, dst_port, src_addr, src_port);
                self.tcp_nat_table.get(&reverse_nat_key)
            })
            .copied();

        trace!(?nat_key, ?token, "Handling TCP packet from VM.");

        if let Some(token) = token {
            if let Some(connection) = self.host_connections.remove(&token) {
                let new_connection_state = match connection {
                    AnyConnection::EgressConnecting(conn) => AnyConnection::EgressConnecting(conn),
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
                            let mut established_conn = conn.establish();
                            self.registry.reregister(
                                established_conn.stream_mut(),
                                token,
                                Interest::READABLE,
                            )?;
                            let ack_packet = build_tcp_packet(
                                &mut self.packet_buf,
                                *self.reverse_tcp_nat.get(&token).unwrap(),
                                established_conn.tx_seq,
                                established_conn.tx_ack,
                                None,
                                Some(TcpFlags::ACK),
                                u16::MAX,
                            );
                            self.to_vm_control_queue.push_back(ack_packet);
                            AnyConnection::Established(established_conn)
                        } else {
                            AnyConnection::IngressConnecting(conn)
                        }
                    }
                    AnyConnection::Established(mut conn) => {
                        let payload = tcp_packet.payload();
                        let flags = tcp_packet.get_flags();

                        if (flags & TcpFlags::RST) != 0 {
                            info!(?token, "RST received from VM. Closing connection.");
                            self.connections_to_remove.push(token);
                            return Ok(());
                        }

                        // ** CRITICAL FIX **: Process ACKs from the VM to clear our send buffer.
                        let ack_num = tcp_packet.get_acknowledgement();
                        let before_len = conn.to_vm_buffer.len();
                        conn.to_vm_buffer.retain(|pkt_bytes| {
                            if let Some(eth) = EthernetPacket::new(pkt_bytes) {
                                if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                                    if let Some(tcp) = TcpPacket::new(ip.payload()) {
                                        let seq = tcp.get_sequence();
                                        let end_seq = seq.wrapping_add(tcp.payload().len() as u32);
                                        // Keep packet if its end sequence is after what VM has ACK'd.
                                        // This handles sequence number wrapping correctly.
                                        return end_seq.wrapping_sub(ack_num) > 0;
                                    }
                                }
                            }
                            true // Keep if parsing fails
                        });
                        let after_len = conn.to_vm_buffer.len();
                        if before_len != after_len {
                            trace!(
                                ?token,
                                ack_num,
                                "Processed ACK from VM. Cleared {} packets from send buffer.",
                                before_len - after_len
                            );
                        }

                        let mut should_ack = false;
                        if !payload.is_empty() {
                            trace!(?token, "Writing {} bytes from VM to host.", payload.len());
                            match conn.stream_mut().write_all(payload) {
                                Ok(()) => {
                                    conn.tx_ack = conn.tx_ack.wrapping_add(payload.len() as u32);
                                    should_ack = true;
                                }
                                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                    warn!(?token, "Host socket would block. Buffering data.");
                                    conn.write_buffer.push_back(Bytes::copy_from_slice(payload));
                                    self.registry.reregister(
                                        conn.stream_mut(),
                                        token,
                                        Interest::READABLE | Interest::WRITABLE,
                                    )?;
                                }
                                Err(e) => {
                                    error!(?token, "Error writing to host: {}. Closing.", e);
                                    self.connections_to_remove.push(token);
                                }
                            }
                        }

                        if (flags & TcpFlags::FIN) != 0 {
                            info!(?token, "Received FIN from VM.");
                            conn.tx_ack = conn.tx_ack.wrapping_add(1);
                            should_ack = true;
                        }

                        if should_ack {
                            if let Some(&nat_key) = self.reverse_tcp_nat.get(&token) {
                                trace!(?token, "Sending ACK to VM for received data/FIN.");
                                let ack_packet = build_tcp_packet(
                                    &mut self.packet_buf,
                                    nat_key,
                                    conn.tx_seq,
                                    conn.tx_ack,
                                    None,
                                    Some(TcpFlags::ACK),
                                    u16::MAX,
                                );
                                self.to_vm_control_queue.push_back(ack_packet);
                            }
                        }

                        if (flags & TcpFlags::FIN) != 0 {
                            AnyConnection::Closing(conn.close())
                        } else {
                            AnyConnection::Established(conn)
                        }
                    }
                    AnyConnection::Closing(mut conn) => {
                        if (tcp_packet.get_flags() & TcpFlags::ACK) != 0
                            && tcp_packet.get_acknowledgement() == conn.tx_seq
                        {
                            info!(
                                ?token,
                                "Received final ACK for our FIN. Marking for removal."
                            );
                            self.connections_to_remove.push(token);
                        }
                        AnyConnection::Closing(conn)
                    }
                };
                if !self.connections_to_remove.contains(&token) {
                    self.host_connections.insert(token, new_connection_state);
                }
            }
        } else if (tcp_packet.get_flags() & TcpFlags::SYN) != 0 {
            info!(?nat_key, "New egress flow detected");
            let real_dest = SocketAddr::new(dst_addr, dst_port);
            let domain = if dst_addr.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            };
            let sock = Socket::new(domain, socket2::Type::STREAM, None)?;
            sock.set_nonblocking(true)?;
            match sock.connect(&real_dest.into()) {
                Ok(()) => (),
                Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => (),
                Err(e) => {
                    error!(error = %e, "Failed to connect egress socket");
                    return Ok(());
                }
            }
            let mut stream = mio::net::TcpStream::from_std(sock.into());
            let token = Token(self.next_token);
            self.next_token += 1;
            self.registry
                .register(&mut stream, token, Interest::READABLE | Interest::WRITABLE)?;
            let conn = TcpConnection {
                stream: Box::new(stream),
                tx_seq: rand::random::<u32>(),
                tx_ack: tcp_packet.get_sequence().wrapping_add(1),
                state: EgressConnecting,
                write_buffer: VecDeque::new(),
                to_vm_buffer: VecDeque::new(),
                is_in_run_queue: false,
            };
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

            // Determine IP domain
            let domain = if dst_addr.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            };

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
            let bind_addr: SocketAddr = if dst_addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            }
            .parse()
            .unwrap();
            socket.bind(&bind_addr.into()).unwrap();

            // Connect to the real destination
            let real_dest = SocketAddr::new(dst_addr, dst_port);
            if socket.connect(&real_dest.into()).is_ok() {
                let mut mio_socket = UdpSocket::from_std(socket.into());
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
            } else {
                warn!(?token, "Failed to send UDP packet to host.");
            }
        }
        Ok(())
    }

    fn notify_waker_if_necessary(&self) {
        if !self.to_vm_control_queue.is_empty()
            || !self.to_vm_data_queue.is_empty()
            || !self.data_run_queue.is_empty()
        {
            if let Err(e) = self.waker.write(1) {
                error!("Failed to signal waker: {}", e);
            }
        }
    }
}

impl NetBackend for NetProxy {
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        if let Some(popped) = self.to_vm_control_queue.pop_front() {
            let packet_len = popped.len();
            buf[..packet_len].copy_from_slice(&popped);
            trace!(
                len = packet_len,
                queue = "control",
                "Read packet from queue."
            );
            return Ok(packet_len);
        }

        self.process_run_queue();
        if let Some(popped) = self.to_vm_data_queue.pop_front() {
            let packet_len = popped.len();
            buf[..packet_len].copy_from_slice(&popped);
            trace!(len = packet_len, queue = "data", "Read packet from queue.");
            return Ok(packet_len);
        }

        Err(ReadError::NothingRead)
    }

    fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError> {
        self.handle_packet_from_vm(&buf[hdr_len..])?;
        self.notify_waker_if_necessary();
        Ok(())
    }

    fn handle_event(&mut self, token: Token, is_readable: bool, is_writable: bool) {
        trace!(?token, is_readable, is_writable, "Handling mio event.");
        if let Some((listener, vm_port)) = self.unix_listeners.get(&token) {
            if let Ok((mut stream, _)) = listener.accept() {
                let new_token = Token(self.next_token);
                info!(?new_token, "Accepted Unix socket ingress connection");
                if let Err(e) = self
                    .registry
                    .register(&mut stream, new_token, Interest::READABLE)
                {
                    warn!("could not register initial interest in new stream");
                    return;
                }

                self.next_token += 1;

                let nat_key = (
                    PROXY_IP.into(),
                    (rand::random::<u16>() % 32768) + 32768,
                    VM_IP.into(),
                    *vm_port,
                );
                let conn = TcpConnection {
                    stream: Box::new(stream),
                    tx_seq: rand::random::<u32>(),
                    tx_ack: 0,
                    state: IngressConnecting,
                    write_buffer: VecDeque::new(),
                    to_vm_buffer: VecDeque::new(),
                    is_in_run_queue: false,
                };

                let syn_packet = build_tcp_packet(
                    &mut self.packet_buf,
                    nat_key,
                    conn.tx_seq,
                    conn.tx_ack,
                    None,
                    Some(TcpFlags::SYN),
                    u16::MAX,
                );
                self.to_vm_control_queue.push_back(syn_packet);
                self.tcp_nat_table.insert(nat_key, new_token);
                self.reverse_tcp_nat.insert(new_token, nat_key);
                self.host_connections
                    .insert(new_token, AnyConnection::IngressConnecting(conn));
            }
        } else if let Some(connection) = self.host_connections.remove(&token) {
            let mut conn_closed = false;
            let new_connection_state = match connection {
                AnyConnection::EgressConnecting(mut conn) => {
                    if is_writable {
                        // // Calling peer_addr() will return an error if the socket is not connected.
                        // if conn.stream_mut().peer_addr().is_err() {
                        //     info!(?token, "Egress connection failed to establish.");
                        //     // You should probably send a TCP RST back to the VM here.
                        //     self.connections_to_remove.push(token);
                        //     // Return or create a new "Failed" state instead of proceeding.
                        //     return;
                        // }

                        info!(?token, "Egress connection established. Sending SYN-ACK.");
                        let nat_key = *self.reverse_tcp_nat.get(&token).unwrap();
                        let syn_ack = build_tcp_packet(
                            &mut self.packet_buf,
                            nat_key,
                            conn.tx_seq,
                            conn.tx_ack,
                            None,
                            Some(TcpFlags::SYN | TcpFlags::ACK),
                            u16::MAX,
                        );
                        conn.tx_seq = conn.tx_seq.wrapping_add(1);
                        self.to_vm_control_queue.push_back(syn_ack);
                        let mut established_conn = conn.establish();
                        if let Err(e) = self.registry.reregister(
                            established_conn.stream_mut(),
                            token,
                            Interest::READABLE,
                        ) {
                            debug!("could not re-register readable interest after sending syn-ack: {e}");
                            _ = self.registry.deregister(established_conn.stream_mut());
                            return;
                        }
                        AnyConnection::Established(established_conn)
                    } else {
                        AnyConnection::EgressConnecting(conn)
                    }
                }
                AnyConnection::IngressConnecting(conn) => AnyConnection::IngressConnecting(conn),
                AnyConnection::Established(mut conn) => {
                    if is_writable {
                        while let Some(data) = conn.write_buffer.front_mut() {
                            match conn.stream.write(data) {
                                Ok(0) => {
                                    conn_closed = true;
                                    break;
                                }
                                Ok(n) if n == data.len() => {
                                    _ = conn.write_buffer.pop_front();
                                }
                                Ok(n) => {
                                    data.advance(n);
                                    break;
                                }
                                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                                Err(_) => {
                                    conn_closed = true;
                                    break;
                                }
                            }
                        }
                    }
                    if is_readable {
                        if self.read_from_host_socket(&mut conn, token).is_err() {
                            conn_closed = true;
                        }
                    }
                    if conn_closed {
                        let mut closing_conn = conn.close();
                        if let Some(&key) = self.reverse_tcp_nat.get(&token) {
                            let fin_ack = build_tcp_packet(
                                &mut self.packet_buf,
                                key,
                                closing_conn.tx_seq,
                                closing_conn.tx_ack,
                                None,
                                Some(TcpFlags::FIN | TcpFlags::ACK),
                                u16::MAX,
                            );
                            closing_conn.tx_seq = closing_conn.tx_seq.wrapping_add(1);
                            self.to_vm_control_queue.push_back(fin_ack);
                        }
                        AnyConnection::Closing(closing_conn)
                    } else {
                        let interest = if conn.write_buffer.is_empty() {
                            Interest::READABLE
                        } else {
                            Interest::READABLE | Interest::WRITABLE
                        };
                        self.registry
                            .reregister(conn.stream_mut(), token, interest)
                            .unwrap_or_else(|e| error!(?token, "Failed to reregister: {}", e));
                        AnyConnection::Established(conn)
                    }
                }
                AnyConnection::Closing(mut conn) => {
                    if is_readable {
                        // Drain any final data from the closing socket.
                        loop {
                            match conn.stream.read(&mut self.read_buf) {
                                Ok(0) => break,    // EOF
                                Ok(_) => continue, // More data to drain
                                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                                Err(_) => break,
                            }
                        }
                    }
                    AnyConnection::Closing(conn)
                }
            };
            self.host_connections.insert(token, new_connection_state);
        } else if let Some((socket, last_seen)) = self.host_udp_sockets.get_mut(&token) {
            loop {
                match socket.recv(&mut self.read_buf) {
                    Ok(n) => {
                        if let Some(nat_key) = self.reverse_udp_nat.get(&token).copied() {
                            let response_packet = build_udp_packet(
                                &mut self.packet_buf,
                                nat_key,
                                &self.read_buf[..n],
                            );
                            self.to_vm_control_queue.push_back(response_packet);
                            *last_seen = Instant::now();
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        error!(?token, "Error receiving from UDP socket: {}", e);
                        break;
                    }
                }
            }
        }

        if !self.connections_to_remove.is_empty() {
            for token in self.connections_to_remove.drain(..) {
                info!(?token, "Cleaning up fully closed TCP connection.");
                if let Some(mut conn) = self.host_connections.remove(&token) {
                    let _ = self.registry.deregister(conn.stream_mut());
                }
                if let Some(key) = self.reverse_tcp_nat.remove(&token) {
                    self.tcp_nat_table.remove(&key);
                }
            }
        }
        if self.last_udp_cleanup.elapsed() > UDP_SESSION_TIMEOUT {
            let expired_tokens: Vec<Token> = self
                .host_udp_sockets
                .iter()
                .filter(|(_, (_, last_seen))| last_seen.elapsed() > UDP_SESSION_TIMEOUT)
                .map(|(token, _)| *token)
                .collect();
            for token in expired_tokens {
                info!(?token, "Cleaning up timed out UDP session.");
                if let Some((mut socket, _)) = self.host_udp_sockets.remove(&token) {
                    let _ = self.registry.deregister(&mut socket);
                    if let Some(key) = self.reverse_udp_nat.remove(&token) {
                        self.udp_nat_table.remove(&key);
                    }
                }
            }
            self.last_udp_cleanup = Instant::now();
        }

        self.notify_waker_if_necessary();
    }

    fn has_unfinished_write(&self) -> bool {
        false
    }
    fn try_finish_write(&mut self, _hdr_len: usize, _buf: &[u8]) -> Result<(), WriteError> {
        trace!("TRY FINISH WRITE WAS CALLED");
        Ok(())
    }
    fn raw_socket_fd(&self) -> RawFd {
        self.waker.as_raw_fd()
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
            IpPacket::V4(i) => i.get_source().into(),
            IpPacket::V6(i) => i.get_source().into(),
        }
    }
    fn get_destination(&self) -> IpAddr {
        match self {
            IpPacket::V4(i) => i.get_destination().into(),
            IpPacket::V6(i) => i.get_destination().into(),
        }
    }
    fn get_next_header(&self) -> IpNextHeaderProtocol {
        match self {
            IpPacket::V4(i) => i.get_next_level_protocol(),
            IpPacket::V6(i) => i.get_next_header(),
        }
    }
    fn payload(&self) -> &[u8] {
        match self {
            IpPacket::V4(i) => i.payload(),
            IpPacket::V6(i) => i.payload(),
        }
    }
}

fn build_arp_reply(packet_buf: &mut BytesMut, request: &ArpPacket) -> Bytes {
    let total_len = 14 + 28;
    packet_buf.clear();
    packet_buf.resize(total_len, 0);
    let (eth_slice, arp_slice) = packet_buf.split_at_mut(14);
    let mut eth_frame = MutableEthernetPacket::new(eth_slice).unwrap();
    eth_frame.set_destination(request.get_sender_hw_addr());
    eth_frame.set_source(PROXY_MAC);
    eth_frame.set_ethertype(EtherTypes::Arp);
    let mut arp_reply = MutableArpPacket::new(arp_slice).unwrap();
    arp_reply.clone_from(request);
    arp_reply.set_operation(ArpOperations::Reply);
    arp_reply.set_sender_hw_addr(PROXY_MAC);
    arp_reply.set_sender_proto_addr(PROXY_IP);
    arp_reply.set_target_hw_addr(request.get_sender_hw_addr());
    arp_reply.set_target_proto_addr(request.get_sender_proto_addr());
    packet_buf.split_to(total_len).freeze()
}

pub fn build_tcp_packet(
    packet_buf: &mut BytesMut,
    nat_key: NatKey,
    tx_seq: u32,
    tx_ack: u32,
    payload: Option<&[u8]>,
    flags: Option<u8>,
    window_size: u16,
) -> Bytes {
    let (key_src_ip, key_src_port, key_dst_ip, key_dst_port) = nat_key;
    let (packet_src_ip, packet_src_port, packet_dst_ip, packet_dst_port) =
        if key_src_ip == IpAddr::V4(PROXY_IP) {
            (key_src_ip, key_src_port, key_dst_ip, key_dst_port)
        } else {
            (key_dst_ip, key_dst_port, key_src_ip, key_src_port)
        };
    let packet = match (packet_src_ip, packet_dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => build_ipv4_tcp_packet(
            packet_buf,
            src,
            dst,
            packet_src_port,
            packet_dst_port,
            tx_seq,
            tx_ack,
            payload,
            flags,
            window_size,
        ),
        (IpAddr::V6(src), IpAddr::V6(dst)) => build_ipv6_tcp_packet(
            packet_buf,
            src,
            dst,
            packet_src_port,
            packet_dst_port,
            tx_seq,
            tx_ack,
            payload,
            flags,
            window_size,
        ),
        _ => return Bytes::new(),
    };
    trace!("{}", packet_dumper::log_packet_out(&packet));
    packet
}

fn build_ipv4_tcp_packet(
    packet_buf: &mut BytesMut,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    tx_seq: u32,
    tx_ack: u32,
    payload: Option<&[u8]>,
    flags: Option<u8>,
    window_size: u16,
) -> Bytes {
    let payload_data = payload.unwrap_or(&[]);
    let total_len = 14 + 20 + 20 + payload_data.len();
    packet_buf.clear();
    packet_buf.resize(total_len, 0);
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
    tcp.set_window(window_size);
    if let Some(f) = flags {
        tcp.set_flags(f);
    }
    tcp.set_payload(payload_data);
    tcp.set_checksum(tcp::ipv4_checksum(&tcp.to_immutable(), &src_ip, &dst_ip));
    ip.set_checksum(ipv4::checksum(&ip.to_immutable()));
    packet_buf.split_to(total_len).freeze()
}

fn build_ipv6_tcp_packet(
    packet_buf: &mut BytesMut,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    tx_seq: u32,
    tx_ack: u32,
    payload: Option<&[u8]>,
    flags: Option<u8>,
    window_size: u16,
) -> Bytes {
    let payload_data = payload.unwrap_or(&[]);
    let total_len = 14 + 40 + 20 + payload_data.len();
    packet_buf.clear();
    packet_buf.resize(total_len, 0);
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
    tcp.set_window(window_size);
    if let Some(f) = flags {
        tcp.set_flags(f);
    }
    tcp.set_payload(payload_data);
    tcp.set_checksum(tcp::ipv6_checksum(&tcp.to_immutable(), &src_ip, &dst_ip));
    packet_buf.split_to(total_len).freeze()
}

pub fn build_udp_packet(packet_buf: &mut BytesMut, nat_key: NatKey, payload: &[u8]) -> Bytes {
    let (key_src_ip, key_src_port, key_dst_ip, key_dst_port) = nat_key;
    let (packet_src_ip, packet_src_port, packet_dst_ip, packet_dst_port) =
        (key_dst_ip, key_dst_port, key_src_ip, key_src_port);
    match (packet_src_ip, packet_dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => build_ipv4_udp_packet(
            packet_buf,
            src,
            dst,
            packet_src_port,
            packet_dst_port,
            payload,
        ),
        (IpAddr::V6(src), IpAddr::V6(dst)) => build_ipv6_udp_packet(
            packet_buf,
            src,
            dst,
            packet_src_port,
            packet_dst_port,
            payload,
        ),
        _ => Bytes::new(),
    }
}

fn build_ipv4_udp_packet(
    packet_buf: &mut BytesMut,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Bytes {
    let total_len = 14 + 20 + 8 + payload.len();
    packet_buf.clear();
    packet_buf.resize(total_len, 0);
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
    packet_buf.split_to(total_len).freeze()
}

fn build_ipv6_udp_packet(
    packet_buf: &mut BytesMut,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Bytes {
    let total_len = 14 + 40 + 8 + payload.len();
    packet_buf.clear();
    packet_buf.resize(total_len, 0);
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
    packet_buf.split_to(total_len).freeze()
}

mod packet_dumper {
    use super::*;
    use pnet::packet::Packet;
    use tracing::trace;
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
    pub fn log_packet_in(data: &[u8]) -> PacketDumper {
        PacketDumper {
            data,
            direction: "IN",
        }
    }
    pub fn log_packet_out(data: &[u8]) -> PacketDumper {
        PacketDumper {
            data,
            direction: "OUT",
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
                                        write!(f, "[{}] IP {}.{} > {}.{}: Flags [{}], seq {}, ack {}, win {}, len {}", self.direction, src, tcp.get_source(), dst, tcp.get_destination(), format_tcp_flags(tcp.get_flags()), tcp.get_sequence(), tcp.get_acknowledgement(), tcp.get_window(), tcp.payload().len())
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
                                    "[{}] IPv4 {} > {}: proto {}",
                                    self.direction,
                                    src,
                                    dst,
                                    ipv4.get_next_level_protocol()
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
                                        write!(f, "[{}] IP6 [{}]:{} > [{}]:{}: Flags [{}], seq {}, ack {}, win {}, len {}", self.direction, src, tcp.get_source(), dst, tcp.get_destination(), format_tcp_flags(tcp.get_flags()), tcp.get_sequence(), tcp.get_acknowledgement(), tcp.get_window(), tcp.payload().len())
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
