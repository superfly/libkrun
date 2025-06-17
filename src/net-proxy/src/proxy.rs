use bytes::{Buf, Bytes, BytesMut};
use mio::event::{Event, Source};
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
use std::cmp;
use std::collections::{HashMap, HashSet, VecDeque};
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
    #[allow(dead_code)]
    state: State,
}

enum AnyConnection {
    EgressConnecting(TcpConnection<EgressConnecting>),
    IngressConnecting(TcpConnection<IngressConnecting>),
    Established(TcpConnection<Established>),
    Closing(TcpConnection<Closing>),
}

impl AnyConnection {
    fn stream_mut(&mut self) -> &mut BoxedHostStream {
        match self {
            AnyConnection::EgressConnecting(conn) => conn.stream_mut(),
            AnyConnection::IngressConnecting(conn) => conn.stream_mut(),
            AnyConnection::Established(conn) => conn.stream_mut(),
            AnyConnection::Closing(conn) => conn.stream_mut(),
        }
    }
    fn write_buffer(&self) -> &VecDeque<Bytes> {
        match self {
            AnyConnection::EgressConnecting(conn) => &conn.write_buffer,
            AnyConnection::IngressConnecting(conn) => &conn.write_buffer,
            AnyConnection::Established(conn) => &conn.write_buffer,
            AnyConnection::Closing(conn) => &conn.write_buffer,
        }
    }

    fn to_vm_buffer(&self) -> &VecDeque<Bytes> {
        match self {
            AnyConnection::EgressConnecting(conn) => &conn.to_vm_buffer,
            AnyConnection::IngressConnecting(conn) => &conn.to_vm_buffer,
            AnyConnection::Established(conn) => &conn.to_vm_buffer,
            AnyConnection::Closing(conn) => &conn.to_vm_buffer,
        }
    }

    fn to_vm_buffer_mut(&mut self) -> &mut VecDeque<Bytes> {
        match self {
            AnyConnection::EgressConnecting(conn) => &mut conn.to_vm_buffer,
            AnyConnection::IngressConnecting(conn) => &mut conn.to_vm_buffer,
            AnyConnection::Established(conn) => &mut conn.to_vm_buffer,
            AnyConnection::Closing(conn) => &mut conn.to_vm_buffer,
        }
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
            state: Established,
        }
    }
}

impl TcpConnection<Established> {
    fn close(mut self) -> TcpConnection<Closing> {
        info!("Closing connection");
        let _ = self.stream.shutdown(Shutdown::Write);
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

impl<State> TcpConnection<State> {
    fn stream_mut(&mut self) -> &mut BoxedHostStream {
        &mut self.stream
    }
}

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

const HOST_READ_BUDGET: usize = 1;
const MAX_PROXY_QUEUE_SIZE: usize = 32;

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
    paused_reads: HashSet<Token>,

    connections_to_remove: Vec<Token>,
    last_udp_cleanup: Instant,

    packet_buf: BytesMut,
    read_buf: [u8; 16384],

    to_vm_control_queue: VecDeque<Bytes>,
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
            paused_reads: Default::default(),
            connections_to_remove: Default::default(),
            last_udp_cleanup: Instant::now(),
            packet_buf: BytesMut::with_capacity(2048),
            read_buf: [0u8; 16384],
            to_vm_control_queue: Default::default(),
            data_run_queue: Default::default(),
        })
    }

    pub fn handle_packet_from_vm(&mut self, raw_packet: &[u8]) -> Result<(), WriteError> {
        if let Some(eth_frame) = EthernetPacket::new(raw_packet) {
            match eth_frame.get_ethertype() {
                EtherTypes::Ipv4 | EtherTypes::Ipv6 => {
                    return self.handle_ip_packet(eth_frame.payload())
                }
                EtherTypes::Arp => return self.handle_arp_packet(eth_frame.payload()),
                _ => return Ok(()),
            }
        }
        return Err(WriteError::NothingWritten);
    }

    pub fn handle_arp_packet(&mut self, arp_payload: &[u8]) -> Result<(), WriteError> {
        if let Some(arp) = ArpPacket::new(arp_payload) {
            if arp.get_operation() == ArpOperations::Request
                && arp.get_target_proto_addr() == PROXY_IP
            {
                debug!("Responding to ARP request for {}", PROXY_IP);
                let reply = build_arp_reply(&mut self.packet_buf, &arp);
                // queue the packet
                self.to_vm_control_queue.push_back(reply);
                return Ok(());
            }
        }
        return Err(WriteError::NothingWritten);
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
                    return self.handle_tcp_packet(src_addr, dst_addr, &tcp);
                }
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(udp) = UdpPacket::new(payload) {
                    return self.handle_udp_packet(src_addr, dst_addr, &udp);
                }
            }
            _ => return Ok(()),
        }
        Err(WriteError::NothingWritten)
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
        let token = self
            .tcp_nat_table
            .get(&nat_key)
            .or_else(|| self.tcp_nat_table.get(&reverse_nat_key))
            .copied();

        if let Some(token) = token {
            if self.paused_reads.remove(&token) {
                if let Some(conn) = self.host_connections.get_mut(&token) {
                    info!(
                        ?token,
                        "Packet received for paused connection. Unpausing reads."
                    );
                    let interest = if conn.write_buffer().is_empty() {
                        Interest::READABLE
                    } else {
                        Interest::READABLE.add(Interest::WRITABLE)
                    };

                    // Try to reregister the stream's interest.
                    if let Err(e) = self.registry.reregister(conn.stream_mut(), token, interest) {
                        // A deregistered stream might cause either NotFound or InvalidInput.
                        // We must handle both cases by re-registering the stream from scratch.
                        if e.kind() == io::ErrorKind::NotFound
                            || e.kind() == io::ErrorKind::InvalidInput
                        {
                            info!(?token, "Stream was deregistered, re-registering.");
                            if let Err(e_reg) =
                                self.registry.register(conn.stream_mut(), token, interest)
                            {
                                error!(
                                    ?token,
                                    "Failed to re-register stream after unpause: {}", e_reg
                                );
                            }
                        } else {
                            error!(
                                ?token,
                                "Failed to reregister to unpause reads on ACK: {}", e
                            );
                        }
                    }
                }
            }
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
                            self.registry
                                .reregister(
                                    established_conn.stream_mut(),
                                    token,
                                    Interest::READABLE,
                                )
                                .unwrap();

                            let ack_packet = build_tcp_packet(
                                &mut self.packet_buf,
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
                        trace!(token = ?token, incoming_seq, expected_ack = conn.tx_ack, "Handling packet for established connection.");

                        // A new data segment is only valid if its sequence number EXACTLY matches
                        // the end of the last segment we acknowledged.
                        if incoming_seq == conn.tx_ack {
                            let flags = tcp_packet.get_flags();

                            // *** FIX START: Handle RST packets first ***
                            // An RST packet immediately terminates the connection.
                            if (flags & TcpFlags::RST) != 0 {
                                info!(?token, "RST received from VM. Tearing down connection.");
                                self.connections_to_remove.push(token);
                                // By returning here, we ensure the connection is not put back into the map.
                                // It will be cleaned up at the end of the event loop.
                                return Ok(());
                            }
                            // *** FIX END ***

                            let payload = tcp_packet.payload();
                            let mut should_ack = false;

                            // If the host-side write buffer is already backlogged, queue new data.
                            if !conn.write_buffer.is_empty() {
                                if !payload.is_empty() {
                                    trace!(
                                        ?token,
                                        "Host write buffer has backlog; queueing new data from VM."
                                    );
                                    conn.write_buffer.push_back(Bytes::copy_from_slice(payload));
                                    conn.tx_ack = conn.tx_ack.wrapping_add(payload.len() as u32);
                                    should_ack = true;
                                }
                            } else if !payload.is_empty() {
                                // Attempt a direct write if the buffer is empty.
                                match conn.stream_mut().write(payload) {
                                    Ok(n) => {
                                        conn.tx_ack =
                                            conn.tx_ack.wrapping_add(payload.len() as u32);
                                        should_ack = true;

                                        if n < payload.len() {
                                            let remainder = &payload[n..];
                                            trace!(?token, "Partial write to host. Buffering {} remaining bytes.", remainder.len());
                                            conn.write_buffer
                                                .push_back(Bytes::copy_from_slice(remainder));
                                            self.registry.reregister(
                                                conn.stream_mut(),
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
                                            .push_back(Bytes::copy_from_slice(payload));
                                        conn.tx_ack =
                                            conn.tx_ack.wrapping_add(payload.len() as u32);
                                        should_ack = true;
                                        self.registry.reregister(
                                            conn.stream_mut(),
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

                            if payload.is_empty()
                                && (flags & (TcpFlags::FIN | TcpFlags::RST | TcpFlags::SYN)) == 0
                            {
                                should_ack = true;
                            }

                            if (flags & TcpFlags::FIN) != 0 {
                                conn.tx_ack = conn.tx_ack.wrapping_add(1);
                                should_ack = true;
                            }

                            if should_ack {
                                if let Some(&nat_key) = self.reverse_tcp_nat.get(&token) {
                                    let ack_packet = build_tcp_packet(
                                        &mut self.packet_buf,
                                        nat_key,
                                        conn.tx_seq,
                                        conn.tx_ack,
                                        None,
                                        Some(TcpFlags::ACK),
                                    );
                                    self.to_vm_control_queue.push_back(ack_packet);
                                }
                            }

                            if (flags & TcpFlags::FIN) != 0 {
                                self.host_connections
                                    .insert(token, AnyConnection::Closing(conn.close()));
                            } else if !self.connections_to_remove.contains(&token) {
                                self.host_connections
                                    .insert(token, AnyConnection::Established(conn));
                            }
                        } else {
                            trace!(token = ?token, incoming_seq, expected_ack = conn.tx_ack, "Ignoring out-of-order packet from VM.");
                            self.host_connections
                                .insert(token, AnyConnection::Established(conn));
                        }
                        return Ok(());
                    }
                    AnyConnection::Closing(mut conn) => {
                        let flags = tcp_packet.get_flags();
                        let ack_num = tcp_packet.get_acknowledgement();

                        // Check if this is the final ACK for the FIN we already sent.
                        // The FIN we sent consumed a sequence number, so tx_seq should be one higher.
                        if (flags & TcpFlags::ACK) != 0 && ack_num == conn.tx_seq {
                            info!(
                                ?token,
                                "Received final ACK from VM. Tearing down connection."
                            );
                            self.connections_to_remove.push(token);
                        }
                        // Handle a simultaneous close, where we get a FIN while already closing.
                        else if (flags & TcpFlags::FIN) != 0 {
                            info!(
                                ?token,
                                "Received FIN from VM during a simultaneous close. Acknowledging."
                            );
                            // Acknowledge the FIN from the VM. A FIN consumes one sequence number.
                            conn.tx_ack = tcp_packet.get_sequence().wrapping_add(1);
                            let ack_packet = build_tcp_packet(
                                &mut self.packet_buf,
                                *self.reverse_tcp_nat.get(&token).unwrap(),
                                conn.tx_seq,
                                conn.tx_ack,
                                None,
                                Some(TcpFlags::ACK),
                            );
                            self.to_vm_control_queue.push_back(ack_packet);
                        }

                        // Keep the connection in the closing state until it's marked for full removal.
                        if !self.connections_to_remove.contains(&token) {
                            self.host_connections
                                .insert(token, AnyConnection::Closing(conn));
                        }
                        return Ok(());
                    }
                };
                if !self.connections_to_remove.contains(&token) {
                    self.host_connections.insert(token, new_connection_state);
                }
            }
        } else if (tcp_packet.get_flags() & TcpFlags::SYN) != 0 {
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

            if let Err(e) = sock.set_nodelay(true) {
                warn!(error = %e, "Failed to set TCP_NODELAY on egress socket");
            }
            if let Err(e) = sock.set_nonblocking(true) {
                error!(error = %e, "Failed to set non-blocking on egress socket");
                return Ok(());
            }

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

            let conn = TcpConnection {
                stream,
                tx_seq: rand::random::<u32>(),
                tx_ack: tcp_packet.get_sequence().wrapping_add(1),
                state: EgressConnecting,
                write_buffer: VecDeque::new(),
                to_vm_buffer: VecDeque::new(),
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
            let bind_addr: SocketAddr = if dst_addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            }
            .parse()
            .unwrap();

            if let Ok(socket) = std::net::UdpSocket::bind(bind_addr) {
                let real_dest = SocketAddr::new(dst_addr, dst_port);
                if socket.connect(real_dest).is_ok() {
                    let mut mio_socket = UdpSocket::from_std(socket);
                    self.registry
                        .register(&mut mio_socket, new_token, Interest::READABLE)
                        .unwrap();
                    self.reverse_udp_nat.insert(new_token, nat_key);
                    self.host_udp_sockets
                        .insert(new_token, (mio_socket, Instant::now()));
                }
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
}

impl NetBackend for NetProxy {
    fn get_rx_queue_len(&self) -> usize {
        self.to_vm_control_queue.len() + self.data_run_queue.len()
    }
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, crate::backend::ReadError> {
        if let Some(popped) = self.to_vm_control_queue.pop_front() {
            let packet_len = popped.len();
            buf[..packet_len].copy_from_slice(&popped);
            return Ok(packet_len);
        }

        if let Some(token) = self.data_run_queue.pop_front() {
            if let Some(conn) = self.host_connections.get_mut(&token) {
                if let Some(packet) = conn.to_vm_buffer_mut().pop_front() {
                    if !conn.to_vm_buffer_mut().is_empty() {
                        self.data_run_queue.push_back(token);
                    }

                    let packet_len = packet.len();
                    buf[..packet_len].copy_from_slice(&packet);
                    return Ok(packet_len);
                }
            }
        }

        Err(ReadError::NothingRead)
    }

    fn write_frame(
        &mut self,
        hdr_len: usize,
        buf: &mut [u8],
    ) -> Result<(), crate::backend::WriteError> {
        self.handle_packet_from_vm(&buf[hdr_len..])?;
        if !self.to_vm_control_queue.is_empty() || !self.data_run_queue.is_empty() {
            if let Err(e) = self.waker.write(1) {
                error!("Failed to write to backend waker: {}", e);
            }
        }
        Ok(())
    }

    fn handle_event(&mut self, token: Token, is_readable: bool, is_writable: bool) {
        match token {
            token if self.unix_listeners.contains_key(&token) => {
                if let Some((listener, vm_port)) = self.unix_listeners.get(&token) {
                    if let Ok((mut stream, _)) = listener.accept() {
                        let token = Token(self.next_token);
                        self.next_token += 1;
                        info!(?token, "Accepted Unix socket ingress connection");
                        if let Err(e) = self.registry.register(
                            &mut stream,
                            token,
                            Interest::READABLE | Interest::WRITABLE,
                        ) {
                            error!("could not register unix ingress conn: {e}");
                            return;
                        }

                        let nat_key = (
                            PROXY_IP.into(),
                            (rand::random::<u16>() % 32768) + 32768,
                            VM_IP.into(),
                            *vm_port,
                        );

                        let mut conn = TcpConnection {
                            stream: Box::new(stream),
                            tx_seq: rand::random::<u32>(),
                            tx_ack: 0,
                            state: IngressConnecting,
                            write_buffer: VecDeque::new(),
                            to_vm_buffer: VecDeque::new(),
                        };

                        let syn_packet = build_tcp_packet(
                            &mut self.packet_buf,
                            nat_key,
                            conn.tx_seq,
                            conn.tx_ack,
                            None,
                            Some(TcpFlags::SYN),
                        );
                        self.to_vm_control_queue.push_back(syn_packet);
                        conn.tx_seq = conn.tx_seq.wrapping_add(1);
                        self.tcp_nat_table.insert(nat_key, token);
                        self.reverse_tcp_nat.insert(token, nat_key);
                        self.host_connections
                            .insert(token, AnyConnection::IngressConnecting(conn));
                        debug!(?nat_key, "Sending SYN packet for new ingress flow");
                    }
                }
            }
            token => {
                if let Some(mut connection) = self.host_connections.remove(&token) {
                    let mut reregister_interest: Option<Interest> = None;

                    connection = match connection {
                        AnyConnection::EgressConnecting(mut conn) => {
                            if is_writable {
                                info!(
                                    "Egress connection established to host. Sending SYN-ACK to VM."
                                );
                                let nat_key = *self.reverse_tcp_nat.get(&token).unwrap();
                                let syn_ack_packet = build_tcp_packet(
                                    &mut self.packet_buf,
                                    nat_key,
                                    conn.tx_seq,
                                    conn.tx_ack,
                                    None,
                                    Some(TcpFlags::SYN | TcpFlags::ACK),
                                );
                                self.to_vm_control_queue.push_back(syn_ack_packet);

                                conn.tx_seq = conn.tx_seq.wrapping_add(1);
                                let mut established_conn = TcpConnection {
                                    stream: conn.stream,
                                    tx_seq: conn.tx_seq,
                                    tx_ack: conn.tx_ack,
                                    write_buffer: conn.write_buffer,
                                    to_vm_buffer: VecDeque::new(),
                                    state: Established,
                                };
                                let mut write_error = false;
                                while let Some(data) = established_conn.write_buffer.front_mut() {
                                    match established_conn.stream.write(data) {
                                        Ok(0) => {
                                            write_error = true;
                                            break;
                                        }
                                        Ok(n) if n == data.len() => {
                                            _ = established_conn.write_buffer.pop_front();
                                        }
                                        Ok(n) => {
                                            data.advance(n);
                                            break;
                                        }
                                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                            reregister_interest =
                                                Some(Interest::READABLE | Interest::WRITABLE);
                                            break;
                                        }
                                        Err(_) => {
                                            write_error = true;
                                            break;
                                        }
                                    }
                                }

                                if write_error {
                                    info!("Closing connection immediately after establishment due to write error.");
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
                        AnyConnection::IngressConnecting(conn) => {
                            AnyConnection::IngressConnecting(conn)
                        }
                        AnyConnection::Established(mut conn) => {
                            let mut conn_closed = false;
                            let mut conn_aborted = false;

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
                                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                            break
                                        }
                                        Err(_) => {
                                            conn_closed = true;
                                            break;
                                        }
                                    }
                                }
                            }

                            if is_readable {
                                // If the connection is paused, we must NOT read from the socket,
                                // even though mio reported it as readable. This breaks the busy-loop.
                                if self.paused_reads.contains(&token) {
                                    trace!(
                                        ?token,
                                        "Ignoring readable event because connection is paused."
                                    );
                                } else {
                                    // Connection is not paused, so we can read from the host.
                                    'read_loop: for _ in 0..HOST_READ_BUDGET {
                                        match conn.stream.read(&mut self.read_buf) {
                                            Ok(0) => {
                                                conn_closed = true;
                                                break 'read_loop;
                                            }
                                            Ok(n) => {
                                                if let Some(&nat_key) =
                                                    self.reverse_tcp_nat.get(&token)
                                                {
                                                    let was_empty = conn.to_vm_buffer.is_empty();
                                                    for chunk in
                                                        self.read_buf[..n].chunks(MAX_SEGMENT_SIZE)
                                                    {
                                                        let packet = build_tcp_packet(
                                                            &mut self.packet_buf,
                                                            nat_key,
                                                            conn.tx_seq,
                                                            conn.tx_ack,
                                                            Some(chunk),
                                                            Some(TcpFlags::ACK | TcpFlags::PSH),
                                                        );
                                                        conn.to_vm_buffer.push_back(packet);
                                                        conn.tx_seq = conn
                                                            .tx_seq
                                                            .wrapping_add(chunk.len() as u32);
                                                    }
                                                    if was_empty && !conn.to_vm_buffer.is_empty() {
                                                        self.data_run_queue.push_back(token);
                                                    }
                                                }
                                            }
                                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                                break 'read_loop
                                            }
                                            Err(ref e)
                                                if e.kind() == io::ErrorKind::ConnectionReset =>
                                            {
                                                info!(?token, "Host connection reset.");
                                                conn_aborted = true;
                                                break 'read_loop;
                                            }
                                            Err(_) => {
                                                conn_closed = true;
                                                break 'read_loop;
                                            }
                                        }
                                    }
                                }
                            }

                            if conn_aborted {
                                // Send a RST to the VM and mark for immediate removal.
                                if let Some(&key) = self.reverse_tcp_nat.get(&token) {
                                    let rst_packet = build_tcp_packet(
                                        &mut self.packet_buf,
                                        key,
                                        conn.tx_seq,
                                        conn.tx_ack,
                                        None,
                                        Some(TcpFlags::RST | TcpFlags::ACK),
                                    );
                                    self.to_vm_control_queue.push_back(rst_packet);
                                }
                                self.connections_to_remove.push(token);
                                // Return the connection so it can be re-inserted and then immediately cleaned up.
                                AnyConnection::Established(conn)
                            } else if conn_closed {
                                let mut closing_conn = conn.close();
                                if let Some(&key) = self.reverse_tcp_nat.get(&token) {
                                    let fin_packet = build_tcp_packet(
                                        &mut self.packet_buf,
                                        key,
                                        closing_conn.tx_seq,
                                        closing_conn.tx_ack,
                                        None,
                                        Some(TcpFlags::FIN | TcpFlags::ACK),
                                    );
                                    closing_conn.tx_seq = closing_conn.tx_seq.wrapping_add(1);
                                    self.to_vm_control_queue.push_back(fin_packet);
                                }
                                AnyConnection::Closing(closing_conn)
                            } else {
                                if conn.to_vm_buffer.len() >= MAX_PROXY_QUEUE_SIZE {
                                    if !self.paused_reads.contains(&token) {
                                        info!(?token, "Connection buffer full. Pausing reads.");
                                        self.paused_reads.insert(token);
                                    }
                                }

                                let needs_read = !self.paused_reads.contains(&token);
                                let needs_write = !conn.write_buffer.is_empty();

                                match (needs_read, needs_write) {
                                    (true, true) => {
                                        let interest = Interest::READABLE.add(Interest::WRITABLE);
                                        self.registry
                                            .reregister(conn.stream_mut(), token, interest)
                                            .unwrap_or_else(|e| {
                                                error!(?token, "reregister R+W failed: {}", e)
                                            });
                                    }
                                    (true, false) => {
                                        self.registry
                                            .reregister(
                                                conn.stream_mut(),
                                                token,
                                                Interest::READABLE,
                                            )
                                            .unwrap_or_else(|e| {
                                                error!(?token, "reregister R failed: {}", e)
                                            });
                                    }
                                    (false, true) => {
                                        self.registry
                                            .reregister(
                                                conn.stream_mut(),
                                                token,
                                                Interest::WRITABLE,
                                            )
                                            .unwrap_or_else(|e| {
                                                error!(?token, "reregister W failed: {}", e)
                                            });
                                    }
                                    (false, false) => {
                                        // No interests; deregister the stream from the poller completely.
                                        if let Err(e) = self.registry.deregister(conn.stream_mut())
                                        {
                                            error!(?token, "Deregister failed: {}", e);
                                        }
                                    }
                                }
                                AnyConnection::Established(conn)
                            }
                        }
                        AnyConnection::Closing(mut conn) => {
                            if is_readable {
                                while conn.stream.read(&mut self.read_buf).unwrap_or(0) > 0 {}
                            }
                            AnyConnection::Closing(conn)
                        }
                    };
                    if let Some(interest) = reregister_interest {
                        self.registry
                            .reregister(connection.stream_mut(), token, interest)
                            .expect("could not re-register connection");
                    }
                    self.host_connections.insert(token, connection);
                } else if let Some((socket, last_seen)) = self.host_udp_sockets.get_mut(&token) {
                    if let Ok(n) = socket.recv(&mut self.read_buf) {
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
                }
            }
        }

        if !self.connections_to_remove.is_empty() {
            for token in self.connections_to_remove.drain(..) {
                info!(?token, "Cleaning up fully closed connection.");
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
                info!(?token, "UDP session timed out");
                if let Some((mut socket, _)) = self.host_udp_sockets.remove(&token) {
                    _ = self.registry.deregister(&mut socket);
                    if let Some(key) = self.reverse_udp_nat.remove(&token) {
                        self.udp_nat_table.remove(&key);
                    }
                }
            }
            self.last_udp_cleanup = Instant::now();
        }

        if !self.to_vm_control_queue.is_empty() || !self.data_run_queue.is_empty() {
            if let Err(e) = self.waker.write(1) {
                error!("Failed to write to backend waker: {}", e);
            }
        }
    }

    fn has_unfinished_write(&self) -> bool {
        false
    }

    fn try_finish_write(
        &mut self,
        _hdr_len: usize,
        _buf: &[u8],
    ) -> Result<(), crate::backend::WriteError> {
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

    packet_buf.clone().freeze()
}

fn build_tcp_packet(
    packet_buf: &mut BytesMut,
    nat_key: NatKey,
    tx_seq: u32,
    tx_ack: u32,
    payload: Option<&[u8]>,
    flags: Option<u8>,
) -> Bytes {
    let (key_src_ip, key_src_port, key_dst_ip, key_dst_port) = nat_key;
    let (packet_src_ip, packet_src_port, packet_dst_ip, packet_dst_port) =
        if key_src_ip == IpAddr::V4(PROXY_IP) {
            (key_src_ip, key_src_port, key_dst_ip, key_dst_port) // Ingress
        } else {
            (key_dst_ip, key_dst_port, key_src_ip, key_src_port) // Egress Reply
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
        ),
        _ => {
            return Bytes::new();
        }
    };
    packet_dumper::log_packet_out(&packet);
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
    tcp.set_window(u16::MAX);
    if let Some(f) = flags {
        tcp.set_flags(f);
    }
    tcp.set_payload(payload_data);
    tcp.set_checksum(tcp::ipv4_checksum(&tcp.to_immutable(), &src_ip, &dst_ip));

    ip.set_checksum(ipv4::checksum(&ip.to_immutable()));

    packet_buf.clone().freeze()
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
    tcp.set_window(u16::MAX);
    if let Some(f) = flags {
        tcp.set_flags(f);
    }
    tcp.set_payload(payload_data);
    tcp.set_checksum(tcp::ipv6_checksum(&tcp.to_immutable(), &src_ip, &dst_ip));

    packet_buf.clone().freeze()
}

fn build_udp_packet(packet_buf: &mut BytesMut, nat_key: NatKey, payload: &[u8]) -> Bytes {
    let (key_src_ip, key_src_port, key_dst_ip, key_dst_port) = nat_key;
    let (packet_src_ip, packet_src_port, packet_dst_ip, packet_dst_port) =
        (key_dst_ip, key_dst_port, key_src_ip, key_src_port); // Always a reply

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

    packet_buf.clone().freeze()
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

    packet_buf.clone().freeze()
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
    pub fn log_packet_in(data: &[u8]) {
        log_packet(data, "IN");
    }
    pub fn log_packet_out(data: &[u8]) {
        log_packet(data, "OUT");
    }
    fn log_packet(data: &[u8], direction: &str) {
        if let Some(eth) = EthernetPacket::new(data) {
            match eth.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                        let src = ipv4.get_source();
                        let dst = ipv4.get_destination();
                        match ipv4.get_next_level_protocol() {
                            IpNextHeaderProtocols::Tcp => {
                                if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                    trace!("[{}] IP {}.{} > {}.{}: Flags [{}], seq {}, ack {}, win {}, len {}",
                                            direction, src, tcp.get_source(), dst, tcp.get_destination(),
                                            format_tcp_flags(tcp.get_flags()), tcp.get_sequence(),
                                            tcp.get_acknowledgement(), tcp.get_window(), tcp.payload().len());
                                }
                            }
                            _ => trace!(
                                "[{}] IPv4 {} > {}: proto {}",
                                direction,
                                src,
                                dst,
                                ipv4.get_next_level_protocol()
                            ),
                        }
                    }
                }
                EtherTypes::Ipv6 => {
                    if let Some(ipv6) = Ipv6Packet::new(eth.payload()) {
                        let src = ipv6.get_source();
                        let dst = ipv6.get_destination();
                        match ipv6.get_next_header() {
                            IpNextHeaderProtocols::Tcp => {
                                if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                                    trace!(
                                            "[{}] IP6 [{}]:{} > [{}]:{}: Flags [{}], seq {}, ack {}, win {}, len {}",
                                            direction, src, tcp.get_source(), dst, tcp.get_destination(),
                                            format_tcp_flags(tcp.get_flags()), tcp.get_sequence(),
                                            tcp.get_acknowledgement(), tcp.get_window(), tcp.payload().len()
                                        );
                                }
                            }
                            _ => trace!(
                                "[{}] IPv6 {} > {}: proto {}",
                                direction,
                                src,
                                dst,
                                ipv6.get_next_header()
                            ),
                        }
                    }
                }
                EtherTypes::Arp => {
                    if let Some(arp) = ArpPacket::new(eth.payload()) {
                        trace!(
                            "[{}] ARP, {}, who has {}? Tell {}",
                            direction,
                            if arp.get_operation() == ArpOperations::Request {
                                "request"
                            } else {
                                "reply"
                            },
                            arp.get_target_proto_addr(),
                            arp.get_sender_proto_addr()
                        );
                    }
                }
                _ => trace!(
                    "[{}] Unknown L3 protocol: {}",
                    direction,
                    eth.get_ethertype()
                ),
            }
        }
    }
}

mod tests {
    use super::*;
    use mio::Poll;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Mutex;

    /// An enhanced mock HostStream for precise control over test scenarios.
    #[derive(Default, Debug)]
    struct MockHostStream {
        read_buffer: Arc<Mutex<VecDeque<Bytes>>>,
        write_buffer: Arc<Mutex<Vec<u8>>>,
        shutdown_state: Arc<Mutex<Option<Shutdown>>>,
        simulate_read_close: Arc<Mutex<bool>>,
        write_capacity: Arc<Mutex<Option<usize>>>,
        // NEW: If Some, the read() method will return the specified error.
        read_error: Arc<Mutex<Option<io::ErrorKind>>>,
    }

    impl Read for MockHostStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            // Check if we need to simulate a specific read error.
            if let Some(kind) = *self.read_error.lock().unwrap() {
                return Err(io::Error::new(kind, "Simulated read error"));
            }
            if *self.simulate_read_close.lock().unwrap() {
                return Ok(0); // Simulate connection closed by host.
            }
            // ... (rest of the read method is unchanged)
            let mut read_buf = self.read_buffer.lock().unwrap();
            if let Some(mut front) = read_buf.pop_front() {
                let bytes_to_copy = std::cmp::min(buf.len(), front.len());
                buf[..bytes_to_copy].copy_from_slice(&front[..bytes_to_copy]);
                if bytes_to_copy < front.len() {
                    front.advance(bytes_to_copy);
                    read_buf.push_front(front);
                }
                Ok(bytes_to_copy)
            } else {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "would block"))
            }
        }
    }

    impl Write for MockHostStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            // Lock the capacity to decide which behavior to use
            let mut capacity_opt = self.write_capacity.lock().unwrap();

            if let Some(capacity) = capacity_opt.as_mut() {
                // --- Capacity-Limited Logic for the new partial write test ---
                if *capacity == 0 {
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, "would block"));
                }
                let bytes_to_write = std::cmp::min(buf.len(), *capacity);
                self.write_buffer
                    .lock()
                    .unwrap()
                    .extend_from_slice(&buf[..bytes_to_write]);
                *capacity -= bytes_to_write; // Reduce available capacity
                Ok(bytes_to_write)
            } else {
                // --- Original "unlimited write" logic for other tests ---
                self.write_buffer.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Source for MockHostStream {
        // These are just stubs to satisfy the trait bounds.
        fn register(
            &mut self,
            _registry: &Registry,
            _token: Token,
            _interests: Interest,
        ) -> io::Result<()> {
            Ok(())
        }
        fn reregister(
            &mut self,
            _registry: &Registry,
            _token: Token,
            _interests: Interest,
        ) -> io::Result<()> {
            Ok(())
        }
        fn deregister(&mut self, _registry: &Registry) -> io::Result<()> {
            Ok(())
        }
    }

    impl HostStream for MockHostStream {
        fn shutdown(&mut self, how: Shutdown) -> io::Result<()> {
            *self.shutdown_state.lock().unwrap() = Some(how);
            Ok(())
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
    }

    // Helper to setup a basic proxy and an established connection for tests
    fn setup_proxy_with_established_conn(
        registry: Registry,
    ) -> (
        NetProxy,
        Token,
        NatKey,
        Arc<Mutex<Vec<u8>>>,
        Arc<Mutex<Option<Shutdown>>>,
    ) {
        let mut proxy =
            NetProxy::new(Arc::new(EventFd::new(0).unwrap()), registry, 10, vec![]).unwrap();

        let token = Token(10);
        let nat_key = (VM_IP.into(), 50000, "8.8.8.8".parse().unwrap(), 443);
        let write_buffer = Arc::new(Mutex::new(Vec::new()));
        let shutdown_state = Arc::new(Mutex::new(None));

        let mock_stream = Box::new(MockHostStream {
            write_buffer: write_buffer.clone(),
            shutdown_state: shutdown_state.clone(),
            ..Default::default()
        });

        let conn = TcpConnection {
            stream: mock_stream,
            tx_seq: 100,
            tx_ack: 200,
            state: Established,
            write_buffer: VecDeque::new(),
            to_vm_buffer: VecDeque::new(),
        };

        proxy
            .host_connections
            .insert(token, AnyConnection::Established(conn));
        proxy.tcp_nat_table.insert(nat_key, token);
        proxy.reverse_tcp_nat.insert(token, nat_key);

        (proxy, token, nat_key, write_buffer, shutdown_state)
    }

    /// A helper function to provide detailed assertions on a captured packet.
    fn assert_packet(
        packet_bytes: &Bytes,
        expected_src_ip: IpAddr,
        expected_dst_ip: IpAddr,
        expected_src_port: u16,
        expected_dst_port: u16,
        expected_flags: u8,
        expected_seq: u32,
        expected_ack: u32,
    ) {
        let eth_packet =
            EthernetPacket::new(packet_bytes).expect("Failed to parse Ethernet packet");
        assert_eq!(eth_packet.get_ethertype(), EtherTypes::Ipv4);

        let ipv4_packet =
            Ipv4Packet::new(eth_packet.payload()).expect("Failed to parse IPv4 packet");
        assert_eq!(ipv4_packet.get_source(), expected_src_ip);
        assert_eq!(ipv4_packet.get_destination(), expected_dst_ip);
        assert_eq!(
            ipv4_packet.get_next_level_protocol(),
            IpNextHeaderProtocols::Tcp
        );

        let tcp_packet = TcpPacket::new(ipv4_packet.payload()).expect("Failed to parse TCP packet");
        assert_eq!(tcp_packet.get_source(), expected_src_port);
        assert_eq!(tcp_packet.get_destination(), expected_dst_port);
        assert_eq!(
            tcp_packet.get_flags(),
            expected_flags,
            "TCP flags did not match"
        );
        assert_eq!(
            tcp_packet.get_sequence(),
            expected_seq,
            "Sequence number did not match"
        );
        assert_eq!(
            tcp_packet.get_acknowledgement(),
            expected_ack,
            "Acknowledgment number did not match"
        );
    }

    #[test]
    fn test_partial_write_maintains_order() {
        // 1. SETUP
        _ = tracing_subscriber::fmt::try_init();
        let poll = Poll::new().unwrap();
        let registry = poll.registry().try_clone().unwrap();
        let mut proxy =
            NetProxy::new(Arc::new(EventFd::new(0).unwrap()), registry, 10, vec![]).unwrap();
        let token = Token(10);

        let packet_a_payload = Bytes::from_static(b"THIS_IS_THE_FIRST_PACKET_PAYLOAD"); // 32 bytes
        let packet_b_payload = Bytes::from_static(b"THIS_IS_THE_SECOND_ONE");
        let host_ip: Ipv4Addr = "1.2.3.4".parse().unwrap();

        let host_written_data = Arc::new(Mutex::new(Vec::new()));
        let mock_write_capacity = Arc::new(Mutex::new(None));

        let mock_stream = Box::new(MockHostStream {
            write_buffer: host_written_data.clone(),
            write_capacity: mock_write_capacity.clone(),
            ..Default::default()
        });

        let nat_key = (VM_IP.into(), 12345, host_ip.into(), 80);
        let conn = TcpConnection {
            stream: mock_stream,
            tx_seq: 1000,
            tx_ack: 2000,
            state: Established,
            write_buffer: VecDeque::new(),
            to_vm_buffer: VecDeque::new(),
        };
        proxy
            .host_connections
            .insert(token, AnyConnection::Established(conn));
        proxy.tcp_nat_table.insert(nat_key, token);
        proxy.reverse_tcp_nat.insert(token, nat_key);

        let build_packet_from_vm = |payload: &[u8], seq: u32| {
            let frame_len = 54 + payload.len();
            let mut raw_packet = vec![0u8; frame_len];
            let mut eth_frame = MutableEthernetPacket::new(&mut raw_packet).unwrap();
            eth_frame.set_destination(PROXY_MAC);
            eth_frame.set_source(VM_MAC);
            eth_frame.set_ethertype(EtherTypes::Ipv4);

            let mut ipv4 = MutableIpv4Packet::new(eth_frame.payload_mut()).unwrap();
            ipv4.set_version(4);
            ipv4.set_header_length(5);
            ipv4.set_total_length((20 + 20 + payload.len()) as u16);
            ipv4.set_ttl(64);
            ipv4.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ipv4.set_source(VM_IP);
            ipv4.set_destination(host_ip);
            ipv4.set_checksum(ipv4::checksum(&ipv4.to_immutable()));

            let mut tcp = MutableTcpPacket::new(ipv4.payload_mut()).unwrap();
            tcp.set_source(12345);
            tcp.set_destination(80);
            tcp.set_sequence(seq);
            tcp.set_acknowledgement(1000);
            tcp.set_data_offset(5);
            tcp.set_flags(TcpFlags::ACK | TcpFlags::PSH);
            tcp.set_window(u16::MAX);
            tcp.set_payload(payload);
            tcp.set_checksum(tcp::ipv4_checksum(&tcp.to_immutable(), &VM_IP, &host_ip));

            Bytes::copy_from_slice(eth_frame.packet())
        };

        // 2. EXECUTION - PART 1: Force a partial write of Packet A
        info!("Step 1: Forcing a partial write for Packet A");
        *mock_write_capacity.lock().unwrap() = Some(20);
        let packet_a = build_packet_from_vm(&packet_a_payload, 2000);
        proxy.handle_packet_from_vm(&packet_a).unwrap();

        // *** FIX IS HERE ***
        // Assert that exactly 20 bytes were written.
        assert_eq!(*host_written_data.lock().unwrap(), b"THIS_IS_THE_FIRST_PA");

        // Assert that the remaining 12 bytes were correctly buffered by the proxy.
        if let Some(AnyConnection::Established(c)) = proxy.host_connections.get(&token) {
            assert_eq!(c.write_buffer.front().unwrap().as_ref(), b"CKET_PAYLOAD");
        } else {
            panic!("Connection not in established state");
        }

        // 3. EXECUTION - PART 2: Send Packet B
        info!("Step 2: Sending Packet B, which should be queued");
        let packet_b = build_packet_from_vm(&packet_b_payload, 2000 + 32);
        proxy.handle_packet_from_vm(&packet_b).unwrap();

        // 4. EXECUTION - PART 3: Drain the proxy's buffer
        info!("Step 3: Simulating a writable event to drain the proxy buffer");
        *mock_write_capacity.lock().unwrap() = Some(1000);
        proxy.handle_event(token, false, true);

        // 5. FINAL ASSERTION
        info!("Step 4: Verifying the final written data is correctly ordered");
        let expected_final_data = [packet_a_payload.as_ref(), packet_b_payload.as_ref()].concat();
        assert_eq!(*host_written_data.lock().unwrap(), expected_final_data);
        info!("Partial write test passed: Data was written to host in the correct order.");
    }

    #[test]
    fn test_egress_handshake_sends_correct_syn_ack() {
        _ = tracing_subscriber::fmt::try_init();
        let poll = Poll::new().unwrap();
        let registry = poll.registry().try_clone().unwrap();
        let mut proxy =
            NetProxy::new(Arc::new(EventFd::new(0).unwrap()), registry, 10, vec![]).unwrap();

        let vm_ip: Ipv4Addr = VM_IP;
        let vm_port = 49152;
        let server_ip: Ipv4Addr = "1.1.1.1".parse().unwrap();
        let server_port = 80;
        let nat_key = (vm_ip.into(), vm_port, server_ip.into(), server_port);
        let vm_initial_seq = 1000;

        let mut raw_packet_buf = [0u8; 60];
        let mut eth_frame = MutableEthernetPacket::new(&mut raw_packet_buf).unwrap();
        eth_frame.set_destination(PROXY_MAC);
        eth_frame.set_source(VM_MAC);
        eth_frame.set_ethertype(EtherTypes::Ipv4);

        let mut ipv4_packet = MutableIpv4Packet::new(eth_frame.payload_mut()).unwrap();
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet.set_total_length(40);
        ipv4_packet.set_ttl(64);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ipv4_packet.set_source(vm_ip);
        ipv4_packet.set_destination(server_ip);

        let mut tcp_packet = MutableTcpPacket::new(ipv4_packet.payload_mut()).unwrap();
        tcp_packet.set_source(vm_port);
        tcp_packet.set_destination(server_port);
        tcp_packet.set_sequence(vm_initial_seq);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_window(u16::MAX);
        tcp_packet.set_checksum(tcp::ipv4_checksum(
            &tcp_packet.to_immutable(),
            &vm_ip,
            &server_ip,
        ));

        ipv4_packet.set_checksum(ipv4::checksum(&ipv4_packet.to_immutable()));
        let syn_from_vm = eth_frame.packet();
        proxy.handle_packet_from_vm(syn_from_vm).unwrap();
        let token = *proxy.tcp_nat_table.get(&nat_key).unwrap();
        proxy.handle_event(token, false, true);

        assert_eq!(proxy.to_vm_control_queue.len(), 1);
        let packet_to_vm = proxy.to_vm_control_queue.pop_front().unwrap();

        let proxy_initial_seq =
            if let AnyConnection::Established(conn) = proxy.host_connections.get(&token).unwrap() {
                conn.tx_seq.wrapping_sub(1)
            } else {
                panic!("Connection not established");
            };

        assert_packet(
            &packet_to_vm,
            IpAddr::V4(server_ip),
            IpAddr::V4(vm_ip),
            server_port,
            vm_port,
            TcpFlags::SYN | TcpFlags::ACK,
            proxy_initial_seq,
            vm_initial_seq.wrapping_add(1),
        );
    }

    #[test]
    fn test_proxy_acks_data_from_vm() {
        let poll = Poll::new().unwrap();
        let registry = poll.registry().try_clone().unwrap();
        let (mut proxy, token, nat_key, host_write_buffer, _) =
            setup_proxy_with_established_conn(registry);

        let (vm_ip, vm_port, host_ip, host_port) = nat_key;

        let conn_state = proxy.host_connections.get_mut(&token).unwrap();
        let tx_seq_before = if let AnyConnection::Established(c) = conn_state {
            c.tx_seq
        } else {
            0
        };

        let data_from_vm = build_tcp_packet(
            &mut BytesMut::new(),
            nat_key,
            200,
            101,
            Some(b"0123456789"),
            Some(TcpFlags::ACK | TcpFlags::PSH),
        );
        proxy.handle_packet_from_vm(&data_from_vm).unwrap();

        assert_eq!(*host_write_buffer.lock().unwrap(), b"0123456789");

        assert_eq!(proxy.to_vm_control_queue.len(), 1);
        let packet_to_vm = proxy.to_vm_control_queue.pop_front().unwrap();

        assert_packet(
            &packet_to_vm,
            host_ip,
            vm_ip,
            host_port,
            vm_port,
            TcpFlags::ACK,
            tx_seq_before,
            210,
        );
    }

    #[test]
    fn test_fin_from_host_sends_fin_to_vm() {
        let poll = Poll::new().unwrap();
        let registry = poll.registry().try_clone().unwrap();
        let (mut proxy, token, nat_key, _, _) = setup_proxy_with_established_conn(registry);
        let (vm_ip, vm_port, host_ip, host_port) = nat_key;

        let conn_state_before = proxy.host_connections.get(&token).unwrap();
        let (tx_seq_before, tx_ack_before) =
            if let AnyConnection::Established(c) = conn_state_before {
                (c.tx_seq, c.tx_ack)
            } else {
                panic!()
            };

        if let Some(AnyConnection::Established(conn)) = proxy.host_connections.get_mut(&token) {
            let mock_stream = conn
                .stream
                .as_any_mut()
                .downcast_mut::<MockHostStream>()
                .unwrap();
            *mock_stream.simulate_read_close.lock().unwrap() = true;
        }
        proxy.handle_event(token, true, false);

        assert_eq!(proxy.to_vm_control_queue.len(), 1);
        let packet_to_vm = proxy.to_vm_control_queue.pop_front().unwrap();

        assert_packet(
            &packet_to_vm,
            host_ip,
            vm_ip,
            host_port,
            vm_port,
            TcpFlags::FIN | TcpFlags::ACK,
            tx_seq_before,
            tx_ack_before,
        );

        let conn_state_after = proxy.host_connections.get(&token).unwrap();
        assert!(matches!(conn_state_after, AnyConnection::Closing(_)));
        if let AnyConnection::Closing(c) = conn_state_after {
            assert_eq!(c.tx_seq, tx_seq_before.wrapping_add(1));
        }
    }

    #[test]
    fn test_egress_handshake_and_data_transfer() {
        _ = tracing_subscriber::fmt::try_init();
        let poll = Poll::new().unwrap();
        let registry = poll.registry().try_clone().unwrap();
        let mut proxy =
            NetProxy::new(Arc::new(EventFd::new(0).unwrap()), registry, 10, vec![]).unwrap();

        let vm_ip: Ipv4Addr = VM_IP;
        let vm_port = 49152;
        let server_ip: Ipv4Addr = "1.1.1.1".parse().unwrap();
        let server_port = 80;

        let nat_key = (vm_ip.into(), vm_port, server_ip.into(), server_port);
        let token = Token(10);

        let mut raw_packet_buf = [0u8; 60];
        let mut eth_frame = MutableEthernetPacket::new(&mut raw_packet_buf).unwrap();
        eth_frame.set_destination(PROXY_MAC);
        eth_frame.set_source(VM_MAC);
        eth_frame.set_ethertype(EtherTypes::Ipv4);

        let mut ipv4_packet = MutableIpv4Packet::new(eth_frame.payload_mut()).unwrap();
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet.set_total_length(40);
        ipv4_packet.set_ttl(64);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ipv4_packet.set_source(vm_ip);
        ipv4_packet.set_destination(server_ip);

        let mut tcp_packet = MutableTcpPacket::new(ipv4_packet.payload_mut()).unwrap();
        tcp_packet.set_source(vm_port);
        tcp_packet.set_destination(server_port);
        tcp_packet.set_sequence(1000);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_window(u16::MAX);
        tcp_packet.set_checksum(tcp::ipv4_checksum(
            &tcp_packet.to_immutable(),
            &vm_ip,
            &server_ip,
        ));

        ipv4_packet.set_checksum(ipv4::checksum(&ipv4_packet.to_immutable()));
        let syn_from_vm = eth_frame.packet();

        proxy.handle_packet_from_vm(syn_from_vm).unwrap();

        assert_eq!(*proxy.tcp_nat_table.get(&nat_key).unwrap(), token);
        assert_eq!(proxy.host_connections.len(), 1);

        proxy.handle_event(token, false, true);

        assert!(matches!(
            proxy.host_connections.get(&token).unwrap(),
            AnyConnection::Established(_)
        ));
        assert_eq!(proxy.to_vm_control_queue.len(), 1);
    }

    #[test]
    fn test_graceful_close_from_vm_fin() {
        let poll = Poll::new().unwrap();
        let registry = poll.registry().try_clone().unwrap();
        let (mut proxy, token, nat_key, _, host_shutdown_state) =
            setup_proxy_with_established_conn(registry);

        let fin_from_vm = build_tcp_packet(
            &mut BytesMut::new(),
            nat_key,
            200,
            101,
            None,
            Some(TcpFlags::FIN | TcpFlags::ACK),
        );
        proxy.handle_packet_from_vm(&fin_from_vm).unwrap();

        assert!(matches!(
            proxy.host_connections.get(&token).unwrap(),
            AnyConnection::Closing(_)
        ));
        assert_eq!(*host_shutdown_state.lock().unwrap(), Some(Shutdown::Write));
    }

    #[test]
    fn test_graceful_close_from_host() {
        let poll = Poll::new().unwrap();
        let registry = poll.registry().try_clone().unwrap();
        let (mut proxy, token, _, _, _) = setup_proxy_with_established_conn(registry);

        if let Some(AnyConnection::Established(conn)) = proxy.host_connections.get_mut(&token) {
            let mock_stream = conn
                .stream
                .as_any_mut()
                .downcast_mut::<MockHostStream>()
                .unwrap();
            *mock_stream.simulate_read_close.lock().unwrap() = true;
        } else {
            panic!("Test setup failed");
        }

        proxy.handle_event(token, true, false);

        assert!(matches!(
            proxy.host_connections.get(&token).unwrap(),
            AnyConnection::Closing(_)
        ));
        assert_eq!(proxy.to_vm_control_queue.len(), 1);
        let packet_bytes = proxy.to_vm_control_queue.front().unwrap();
        let eth_packet = EthernetPacket::new(packet_bytes).unwrap();
        let ipv4_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();
        let tcp_packet = TcpPacket::new(ipv4_packet.payload()).unwrap();
        assert_eq!(tcp_packet.get_flags() & TcpFlags::FIN, TcpFlags::FIN);
    }

    // The test that started it all!
    #[test]
    fn test_reverse_mode_flow_control() {
        _ = tracing_subscriber::fmt::try_init();
        let poll = Poll::new().unwrap();
        let registry = poll.registry().try_clone().unwrap();
        // GIVEN: a proxy with a mocked connection
        let mut proxy =
            NetProxy::new(Arc::new(EventFd::new(0).unwrap()), registry, 10, vec![]).unwrap();

        let vm_ip: IpAddr = VM_IP.into();
        let vm_port = 50000;
        let server_ip: IpAddr = "93.184.216.34".parse::<Ipv4Addr>().unwrap().into();
        let server_port = 5201;
        let nat_key = (vm_ip, vm_port, server_ip, server_port);
        let token = Token(10);

        let server_read_buffer = Arc::new(Mutex::new(VecDeque::<Bytes>::new()));
        let mock_server_stream = Box::new(MockHostStream {
            read_buffer: server_read_buffer.clone(),
            ..Default::default()
        });

        // Manually insert an established connection
        let conn = TcpConnection {
            stream: mock_server_stream,
            tx_seq: 100,
            tx_ack: 1001,
            state: Established,
            write_buffer: VecDeque::new(),
            to_vm_buffer: VecDeque::new(),
        };
        proxy.tcp_nat_table.insert(nat_key, token);
        proxy.reverse_tcp_nat.insert(token, nat_key);
        proxy
            .host_connections
            .insert(token, AnyConnection::Established(conn));

        // WHEN: a flood of data arrives from the host (more than the proxy's queue size)
        for i in 0..100 {
            server_read_buffer
                .lock()
                .unwrap()
                .push_back(Bytes::from(format!("chunk_{}", i)));
        }

        // AND: the proxy processes readable events until it decides to pause
        let mut safety_break = 0;
        while !proxy.paused_reads.contains(&token) {
            proxy.handle_event(token, true, false);
            safety_break += 1;
            if safety_break > (MAX_PROXY_QUEUE_SIZE + 5) {
                panic!("Test loop ran too many times, backpressure did not engage.");
            }
        }

        // THEN: The connection should be paused and its buffer should be full
        assert!(
            proxy.paused_reads.contains(&token),
            "Connection should be in the paused_reads set"
        );

        let get_buffer_len = |proxy: &NetProxy| {
            proxy
                .host_connections
                .get(&token)
                .unwrap()
                .to_vm_buffer()
                .len()
        };

        assert_eq!(
            get_buffer_len(&proxy),
            MAX_PROXY_QUEUE_SIZE,
            "Connection's to_vm_buffer should be full"
        );

        // *** NEW/ADJUSTED PART OF THE TEST ***
        // AND: a subsequent 'readable' event for the paused connection should be IGNORED
        info!("Confirming that a readable event on a paused connection does not read more data.");
        proxy.handle_event(token, true, false);

        // Assert that the buffer size has NOT increased, proving the read was skipped.
        assert_eq!(
            get_buffer_len(&proxy),
            MAX_PROXY_QUEUE_SIZE,
            "Buffer size should not increase when a read is paused"
        );

        // WHEN: an ACK is received from the VM, the connection should un-pause
        let ack_from_vm = build_tcp_packet(
            &mut BytesMut::new(),
            nat_key,
            1001, // VM sequence number
            500,  // Doesn't matter for this test
            None,
            Some(TcpFlags::ACK),
        );
        proxy.handle_packet_from_vm(&ack_from_vm).unwrap();

        // THEN: The connection should no longer be paused
        assert!(
            !proxy.paused_reads.contains(&token),
            "The ACK from the VM should have unpaused reads."
        );

        // AND: The proxy should now be able to read more data again
        let buffer_len_before_resume = get_buffer_len(&proxy);
        proxy.handle_event(token, true, false);
        let buffer_len_after_resume = get_buffer_len(&proxy);
        assert!(
            buffer_len_after_resume > buffer_len_before_resume,
            "Proxy should have read more data after being unpaused"
        );

        info!("Flow control test, including pause enforcement, passed!");
    }

    #[test]
    fn test_rst_from_vm_tears_down_connection() {
        // 1. SETUP
        _ = tracing_subscriber::fmt::try_init();
        let poll = Poll::new().unwrap();
        let registry = poll.registry().try_clone().unwrap();
        let mut proxy =
            NetProxy::new(Arc::new(EventFd::new(0).unwrap()), registry, 10, vec![]).unwrap();
        let token = Token(10);
        let host_ip: Ipv4Addr = "8.8.8.8".parse().unwrap();

        // Manually insert an established connection into the proxy's state
        let nat_key = (VM_IP.into(), 54321, host_ip.into(), 443);
        let conn = TcpConnection {
            stream: Box::new(MockHostStream::default()), // The mock stream isn't used here
            tx_seq: 1000,
            tx_ack: 2000,
            state: Established,
            write_buffer: VecDeque::new(),
            to_vm_buffer: VecDeque::new(),
        };
        proxy
            .host_connections
            .insert(token, AnyConnection::Established(conn));
        proxy.tcp_nat_table.insert(nat_key, token);
        proxy.reverse_tcp_nat.insert(token, nat_key);

        // 2. ACTION: Simulate a RST packet arriving from the VM
        info!("Simulating RST packet from VM for token {:?}", token);

        // Craft a valid TCP header with the RST flag set
        let rst_packet = {
            let mut raw_packet = [0u8; 100];
            let mut eth = MutableEthernetPacket::new(&mut raw_packet).unwrap();
            eth.set_destination(PROXY_MAC);
            eth.set_source(VM_MAC);
            eth.set_ethertype(EtherTypes::Ipv4);
            let mut ip = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length(40);
            ip.set_ttl(64);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip.set_source(VM_IP);
            ip.set_destination(host_ip);
            let mut tcp = MutableTcpPacket::new(ip.payload_mut()).unwrap();
            tcp.set_source(54321);
            tcp.set_destination(443);
            tcp.set_sequence(2000); // In-sequence
            tcp.set_flags(TcpFlags::RST | TcpFlags::ACK);
            Bytes::copy_from_slice(eth.packet())
        };

        // Process the RST packet
        proxy.handle_packet_from_vm(&rst_packet).unwrap();

        // 3. ASSERTION: The connection should be marked for immediate removal
        assert!(
            proxy.connections_to_remove.contains(&token),
            "Connection token should be in the removal queue after a RST"
        );

        // We can also run the cleanup code to be thorough
        proxy.handle_event(Token(999), false, false); // A dummy event to trigger cleanup
        assert!(
            !proxy.host_connections.contains_key(&token),
            "Connection should be gone from the map after cleanup"
        );
        info!("RST test passed.");
    }
    #[test]
    fn test_ingress_connection_handshake() {
        // 1. SETUP
        _ = tracing_subscriber::fmt::try_init();
        let poll = Poll::new().unwrap();
        let registry = poll.registry().try_clone().unwrap();
        let start_token = 10;
        let listener_token = Token(start_token); // The first token allocated will be for the listener.
        let vm_port = 8080;

        let socket_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let socket_path = socket_dir.path().join("ingress.sock");
        let socket_path_str = socket_path.to_str().unwrap().to_string();

        let mut proxy = NetProxy::new(
            Arc::new(EventFd::new(0).unwrap()),
            registry,
            start_token,
            vec![(vm_port, socket_path_str)],
        )
        .unwrap();

        // 2. ACTION - PART 1: Simulate a client connecting to the Unix socket.
        info!("Simulating client connection to Unix socket listener");
        let _client_stream = std::os::unix::net::UnixStream::connect(&socket_path)
            .expect("Test client failed to connect to Unix socket");

        proxy.handle_event(listener_token, true, false);

        // 3. ASSERTIONS - PART 1: Verify the proxy sends a SYN packet to the VM.
        assert_eq!(
            proxy.host_connections.len(),
            1,
            "A new host connection should be created"
        );
        let new_conn_token = Token(start_token + 1);
        assert!(
            proxy.host_connections.contains_key(&new_conn_token),
            "Connection should exist for the new token"
        );
        assert!(
            matches!(
                proxy.host_connections.get(&new_conn_token).unwrap(),
                AnyConnection::IngressConnecting(_)
            ),
            "Connection should be in the IngressConnecting state"
        );

        assert_eq!(
            proxy.to_vm_control_queue.len(),
            1,
            "Proxy should have one packet to send to the VM"
        );
        let syn_to_vm = proxy.to_vm_control_queue.pop_front().unwrap();

        // *** FIX START: Un-chain the method calls to extend lifetimes ***
        let eth_syn = EthernetPacket::new(&syn_to_vm).expect("Failed to parse SYN Ethernet frame");
        let ipv4_syn = Ipv4Packet::new(eth_syn.payload()).expect("Failed to parse SYN IPv4 packet");
        let syn_tcp = TcpPacket::new(ipv4_syn.payload()).expect("Failed to parse SYN TCP packet");
        // *** FIX END ***

        info!("Verifying proxy sent correct SYN packet to VM");
        assert_eq!(
            syn_tcp.get_destination(),
            vm_port,
            "SYN packet destination port should be the forwarded port"
        );
        assert_eq!(
            syn_tcp.get_flags() & TcpFlags::SYN,
            TcpFlags::SYN,
            "Packet should have SYN flag"
        );
        let proxy_initial_seq = syn_tcp.get_sequence();

        // 4. ACTION - PART 2: Simulate the VM replying with a SYN-ACK.
        info!("Simulating SYN-ACK packet from VM");
        let nat_key = *proxy.reverse_tcp_nat.get(&new_conn_token).unwrap();
        let vm_initial_seq = 5000;
        let syn_ack_from_vm = build_tcp_packet(
            &mut BytesMut::new(),
            nat_key,
            vm_initial_seq,                    // VM's sequence number
            proxy_initial_seq.wrapping_add(1), // Acknowledging the proxy's SYN
            None,
            Some(TcpFlags::SYN | TcpFlags::ACK),
        );
        proxy.handle_packet_from_vm(&syn_ack_from_vm).unwrap();

        // 5. ASSERTIONS - PART 2: Verify the connection is now established.
        assert!(
            matches!(
                proxy.host_connections.get(&new_conn_token).unwrap(),
                AnyConnection::Established(_)
            ),
            "Connection should now be in the Established state"
        );

        info!("Verifying proxy sent final ACK of 3-way handshake");
        assert_eq!(
            proxy.to_vm_control_queue.len(),
            1,
            "Proxy should have sent the final ACK packet to the VM"
        );

        let final_ack_to_vm = proxy.to_vm_control_queue.pop_front().unwrap();

        // *** FIX START: Un-chain the method calls to extend lifetimes ***
        let eth_ack = EthernetPacket::new(&final_ack_to_vm)
            .expect("Failed to parse final ACK Ethernet frame");
        let ipv4_ack =
            Ipv4Packet::new(eth_ack.payload()).expect("Failed to parse final ACK IPv4 packet");
        let final_ack_tcp =
            TcpPacket::new(ipv4_ack.payload()).expect("Failed to parse final ACK TCP packet");
        // *** FIX END ***

        assert_eq!(
            final_ack_tcp.get_flags() & TcpFlags::ACK,
            TcpFlags::ACK,
            "Packet should have ACK flag"
        );
        assert_eq!(
            final_ack_tcp.get_flags() & TcpFlags::SYN,
            0,
            "Packet should NOT have SYN flag"
        );

        assert_eq!(
            final_ack_tcp.get_sequence(),
            proxy_initial_seq.wrapping_add(1)
        );
        assert_eq!(
            final_ack_tcp.get_acknowledgement(),
            vm_initial_seq.wrapping_add(1)
        );
        info!("Ingress handshake test passed.");
    }

    #[test]
    fn test_host_connection_reset_sends_rst_to_vm() {
        // 1. SETUP
        _ = tracing_subscriber::fmt::try_init();
        let poll = Poll::new().unwrap();
        let registry = poll.registry().try_clone().unwrap();
        let mut proxy =
            NetProxy::new(Arc::new(EventFd::new(0).unwrap()), registry, 10, vec![]).unwrap();
        let token = Token(10);
        let host_ip: Ipv4Addr = "8.8.8.8".parse().unwrap();

        // Create a mock stream that will return a ConnectionReset error on read.
        let mock_stream = Box::new(MockHostStream {
            read_error: Arc::new(Mutex::new(Some(io::ErrorKind::ConnectionReset))),
            ..Default::default()
        });

        // Manually insert an established connection into the proxy's state.
        let nat_key = (VM_IP.into(), 54321, host_ip.into(), 443);
        let conn = TcpConnection {
            stream: mock_stream,
            tx_seq: 1000,
            tx_ack: 2000,
            state: Established,
            write_buffer: VecDeque::new(),
            to_vm_buffer: VecDeque::new(),
        };
        proxy
            .host_connections
            .insert(token, AnyConnection::Established(conn));
        proxy.tcp_nat_table.insert(nat_key, token);
        proxy.reverse_tcp_nat.insert(token, nat_key);

        // 2. ACTION: Simulate a readable event, which will trigger the error.
        info!("Simulating readable event on a socket that will reset");
        proxy.handle_event(token, true, false);

        // 3. ASSERTIONS
        info!("Verifying proxy sent RST to VM and is cleaning up");
        // Assert that a RST packet was sent to the VM.
        assert_eq!(
            proxy.to_vm_control_queue.len(),
            1,
            "Proxy should send one packet to VM"
        );
        let rst_packet = proxy.to_vm_control_queue.front().unwrap();
        let eth = EthernetPacket::new(rst_packet).unwrap();
        let ip = Ipv4Packet::new(eth.payload()).unwrap();
        let tcp = TcpPacket::new(ip.payload()).unwrap();
        assert_eq!(
            tcp.get_flags() & TcpFlags::RST,
            TcpFlags::RST,
            "Packet should have RST flag set"
        );

        // Assert that the connection has been fully removed from the proxy's state,
        // which is the end result of the cleanup process.
        assert!(
            !proxy.host_connections.contains_key(&token),
            "Connection should be removed from the active connections map after reset"
        );
        info!("Host connection reset test passed.");
    }

    #[test]
    fn test_final_ack_completes_graceful_close() {
        // 1. SETUP
        _ = tracing_subscriber::fmt::try_init();
        let poll = Poll::new().unwrap();
        let registry = poll.registry().try_clone().unwrap();
        let mut proxy =
            NetProxy::new(Arc::new(EventFd::new(0).unwrap()), registry, 10, vec![]).unwrap();
        let token = Token(10);
        let host_ip: Ipv4Addr = "8.8.8.8".parse().unwrap();

        // Create a connection and put it directly into the `Closing` state.
        // This simulates the state after the proxy has sent a FIN to the VM.
        let closing_conn = {
            let est_conn = TcpConnection {
                stream: Box::new(MockHostStream::default()),
                tx_seq: 1000,
                tx_ack: 2000,
                state: Established,
                write_buffer: VecDeque::new(),
                to_vm_buffer: VecDeque::new(),
            };
            // When the proxy sends a FIN, its sequence number is incremented.
            let mut conn_after_fin = est_conn.close();
            conn_after_fin.tx_seq = conn_after_fin.tx_seq.wrapping_add(1);
            conn_after_fin
        };
        let nat_key = (VM_IP.into(), 54321, host_ip.into(), 443);
        proxy
            .host_connections
            .insert(token, AnyConnection::Closing(closing_conn));
        proxy.tcp_nat_table.insert(nat_key, token);
        proxy.reverse_tcp_nat.insert(token, nat_key);

        // 2. ACTION: Simulate the final ACK from the VM.
        // This ACK acknowledges the FIN that the proxy already sent.
        info!("Simulating final ACK from VM for a closing connection");
        let final_ack_from_vm = build_tcp_packet(
            &mut BytesMut::new(),
            nat_key,
            2000, // VM's sequence number
            1001, // Acknowledging the proxy's FIN (initial seq 1000 + 1)
            None,
            Some(TcpFlags::ACK),
        );
        proxy.handle_packet_from_vm(&final_ack_from_vm).unwrap();

        // 3. ASSERTION
        info!("Verifying connection is marked for full removal");
        assert!(
            proxy.connections_to_remove.contains(&token),
            "Connection should be marked for removal after final ACK"
        );
        info!("Graceful close test passed.");
    }

    #[test]
    fn test_out_of_order_packet_from_vm_is_ignored() {
        // 1. SETUP
        _ = tracing_subscriber::fmt::try_init();
        let poll = Poll::new().unwrap();
        let registry = poll.registry().try_clone().unwrap();
        let mut proxy =
            NetProxy::new(Arc::new(EventFd::new(0).unwrap()), registry, 10, vec![]).unwrap();
        let token = Token(10);
        let host_ip: Ipv4Addr = "8.8.8.8".parse().unwrap();

        // The proxy expects the next sequence number from the VM to be 2000.
        let expected_ack_from_vm = 2000;

        let host_write_buffer = Arc::new(Mutex::new(Vec::new()));
        let mock_stream = Box::new(MockHostStream {
            write_buffer: host_write_buffer.clone(),
            ..Default::default()
        });

        // Manually insert an established connection into the proxy's state.
        let nat_key = (VM_IP.into(), 54321, host_ip.into(), 443);
        let conn = TcpConnection {
            stream: mock_stream,
            tx_seq: 1000,                 // Proxy's sequence number to the VM
            tx_ack: expected_ack_from_vm, // What the proxy expects from the VM
            state: Established,
            write_buffer: VecDeque::new(),
            to_vm_buffer: VecDeque::new(),
        };
        proxy
            .host_connections
            .insert(token, AnyConnection::Established(conn));
        proxy.tcp_nat_table.insert(nat_key, token);
        proxy.reverse_tcp_nat.insert(token, nat_key);

        // 2. ACTION: Simulate an out-of-order packet from the VM.
        info!(
            "Sending packet with seq=3000, but proxy expects seq={}",
            expected_ack_from_vm
        );
        let out_of_order_packet = {
            let payload = b"This data should be ignored";
            let frame_len = 54 + payload.len();
            let mut raw_packet = vec![0u8; frame_len];
            let mut eth = MutableEthernetPacket::new(&mut raw_packet).unwrap();
            eth.set_destination(PROXY_MAC);
            eth.set_source(VM_MAC);
            eth.set_ethertype(EtherTypes::Ipv4);
            let mut ip = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length((20 + 20 + payload.len()) as u16);
            ip.set_ttl(64);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip.set_source(VM_IP);
            ip.set_destination(host_ip);
            let mut tcp = MutableTcpPacket::new(ip.payload_mut()).unwrap();
            tcp.set_source(54321);
            tcp.set_destination(443);
            tcp.set_sequence(3000); // This sequence number is intentionally incorrect.
            tcp.set_acknowledgement(1000);
            tcp.set_flags(TcpFlags::ACK | TcpFlags::PSH);
            tcp.set_payload(payload);
            Bytes::copy_from_slice(eth.packet())
        };

        // Process the bad packet.
        proxy.handle_packet_from_vm(&out_of_order_packet).unwrap();

        // 3. ASSERTIONS
        info!("Verifying that the out-of-order packet was ignored");
        let conn_state = proxy.host_connections.get(&token).unwrap();
        let established_conn = match conn_state {
            AnyConnection::Established(c) => c,
            _ => panic!("Connection is no longer in the established state"),
        };

        // Assert that the proxy's internal state did NOT change.
        assert_eq!(
            established_conn.tx_ack, expected_ack_from_vm,
            "Proxy's expected ack number should not change"
        );

        // Assert that no side effects occurred.
        assert!(
            host_write_buffer.lock().unwrap().is_empty(),
            "No data should have been written to the host"
        );
        assert!(
            proxy.to_vm_control_queue.is_empty(),
            "Proxy should not have sent an ACK for an ignored packet"
        );

        info!("Out-of-order packet test passed.");
    }
    #[test]
    fn test_simultaneous_close() {
        // 1. SETUP
        _ = tracing_subscriber::fmt::try_init();
        let poll = Poll::new().unwrap();
        let registry = poll.registry().try_clone().unwrap();
        let mut proxy =
            NetProxy::new(Arc::new(EventFd::new(0).unwrap()), registry, 10, vec![]).unwrap();
        let token = Token(10);
        let host_ip: Ipv4Addr = "8.8.8.8".parse().unwrap();

        let mock_stream = Box::new(MockHostStream {
            simulate_read_close: Arc::new(Mutex::new(true)),
            ..Default::default()
        });

        let nat_key = (VM_IP.into(), 54321, host_ip.into(), 443);
        let initial_proxy_seq = 1000;
        let conn = TcpConnection {
            stream: mock_stream,
            tx_seq: initial_proxy_seq,
            tx_ack: 2000,
            state: Established,
            write_buffer: VecDeque::new(),
            to_vm_buffer: VecDeque::new(),
        };
        proxy
            .host_connections
            .insert(token, AnyConnection::Established(conn));
        proxy.tcp_nat_table.insert(nat_key, token);
        proxy.reverse_tcp_nat.insert(token, nat_key);

        // 2. ACTION: Simulate a simultaneous close
        info!("Step 1: Simulating FIN from host via read returning Ok(0)");
        proxy.handle_event(token, true, false);

        info!("Step 2: Simulating simultaneous FIN from VM");
        let fin_from_vm = build_tcp_packet(
            &mut BytesMut::new(),
            nat_key,
            2000,              // VM's sequence number
            initial_proxy_seq, // Acknowledging data up to this point
            None,
            Some(TcpFlags::FIN | TcpFlags::ACK),
        );
        proxy.handle_packet_from_vm(&fin_from_vm).unwrap();

        // 3. ASSERTIONS
        info!("Step 3: Verifying proxy's responses");
        assert_eq!(
            proxy.to_vm_control_queue.len(),
            2,
            "Proxy should have sent two packets to the VM"
        );

        // Check Packet 1: The proxy's FIN
        let proxy_fin_packet = proxy.to_vm_control_queue.pop_front().unwrap();
        // *** FIX START: Un-chain method calls to extend lifetimes ***
        let eth_fin =
            EthernetPacket::new(&proxy_fin_packet).expect("Failed to parse FIN Ethernet frame");
        let ipv4_fin = Ipv4Packet::new(eth_fin.payload()).expect("Failed to parse FIN IPv4 packet");
        let tcp_fin = TcpPacket::new(ipv4_fin.payload()).expect("Failed to parse FIN TCP packet");
        // *** FIX END ***
        assert_eq!(
            tcp_fin.get_flags() & TcpFlags::FIN,
            TcpFlags::FIN,
            "First packet should be a FIN"
        );
        assert_eq!(
            tcp_fin.get_sequence(),
            initial_proxy_seq,
            "FIN sequence should be correct"
        );

        // Check Packet 2: The proxy's ACK of the VM's FIN
        let proxy_ack_packet = proxy.to_vm_control_queue.pop_front().unwrap();
        // *** FIX START: Un-chain method calls to extend lifetimes ***
        let eth_ack =
            EthernetPacket::new(&proxy_ack_packet).expect("Failed to parse ACK Ethernet frame");
        let ipv4_ack = Ipv4Packet::new(eth_ack.payload()).expect("Failed to parse ACK IPv4 packet");
        let tcp_ack = TcpPacket::new(ipv4_ack.payload()).expect("Failed to parse ACK TCP packet");
        // *** FIX END ***
        assert_eq!(
            tcp_ack.get_flags(),
            TcpFlags::ACK,
            "Second packet should be a pure ACK"
        );
        assert_eq!(
            tcp_ack.get_acknowledgement(),
            2001,
            "Should acknowledge the VM's FIN by advancing seq by 1"
        );

        assert!(
            matches!(
                proxy.host_connections.get(&token).unwrap(),
                AnyConnection::Closing(_)
            ),
            "Connection should be in the Closing state"
        );
        assert!(
            proxy.connections_to_remove.is_empty(),
            "Connection should not be fully removed yet"
        );

        info!("Simultaneous close test passed.");
    }
}
