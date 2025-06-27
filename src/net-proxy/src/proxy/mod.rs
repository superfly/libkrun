use bytes::{Bytes, BytesMut};
use crc::{Crc, CRC_32_ISO_HDLC};
use mio::event::Source;
use mio::net::{TcpStream, UdpSocket, UnixListener, UnixStream};
use mio::{Interest, Registry, Token};
use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpFlags, TcpOptionNumbers, TcpPacket};
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use socket2::{Domain, SockAddr, Socket};
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr};
use std::os::fd::AsRawFd;
use std::os::unix::prelude::RawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn};
use utils::eventfd::EventFd;

use crate::backend::{NetBackend, ReadError, WriteError};
use crate::proxy::tcp_fsm::TcpNegotiatedOptions;

pub mod packet_utils;
pub mod tcp_fsm;
pub mod simple_tcp;

use packet_utils::{build_arp_reply, build_tcp_packet, build_udp_packet, IpPacket};
use tcp_fsm::{AnyConnection, NatKey, ProxyAction, CONNECTION_STALL_TIMEOUT};

pub const CHECKSUM: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

// --- Network Configuration ---
const PROXY_MAC: MacAddr = MacAddr(0x02, 0x00, 0x00, 0x01, 0x02, 0x03);
const VM_MAC: MacAddr = MacAddr(0xde, 0xad, 0xbe, 0xef, 0x00, 0x00);
const PROXY_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 100, 1);
const VM_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 100, 2);
const UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for connections in TIME_WAIT state, as per RFC recommendation.
const TIME_WAIT_DURATION: Duration = Duration::from_secs(60);
/// The timeout before we retransmit a TCP packet.
const RTO_DURATION: Duration = Duration::from_millis(500);

// --- Main Proxy Struct ---
pub struct NetProxy {
    waker: Arc<EventFd>,
    registry: mio::Registry,
    next_token: usize,
    pub current_token: Token, // Track current token being processed

    unix_listeners: HashMap<Token, (UnixListener, u16)>,
    tcp_nat_table: HashMap<NatKey, Token>,
    reverse_tcp_nat: HashMap<Token, NatKey>,
    host_connections: HashMap<Token, AnyConnection>,

    udp_nat_table: HashMap<NatKey, Token>,
    host_udp_sockets: HashMap<Token, (UdpSocket, Instant)>,
    reverse_udp_nat: HashMap<Token, NatKey>,

    connections_to_remove: Vec<Token>,
    time_wait_queue: VecDeque<(Instant, Token)>,
    last_udp_cleanup: Instant,

    // --- Queues for sending data back to the VM ---
    // High-priority packets like SYN/FIN/RST ACKs
    to_vm_control_queue: VecDeque<Bytes>,
    // Tokens for connections that have data packets ready to send
    // pub data_run_queue: VecDeque<Token>,
    pub packet_buf: BytesMut,
    pub read_buf: [u8; 16384],

    last_data_token_idx: usize,
    
    // Debug stats
    stats_last_report: Instant,
    stats_packets_in: u64,
    stats_packets_out: u64,
    stats_bytes_in: u64,
    stats_bytes_out: u64,
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

        for (vm_port, path) in listeners {
            if std::fs::metadata(path.as_str()).is_ok() {
                if let Err(e) = std::fs::remove_file(path.as_str()) {
                    warn!("Failed to remove existing socket file {}: {}", path, e);
                }
            }
            let listener_socket = Socket::new(Domain::UNIX, socket2::Type::STREAM, None)?;
            listener_socket.bind(&SockAddr::unix(path.as_str())?)?;
            listener_socket.listen(1024)?;
            listener_socket.set_nonblocking(true)?;

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
            current_token: Token(0),
            unix_listeners,
            tcp_nat_table: Default::default(),
            reverse_tcp_nat: Default::default(),
            host_connections: Default::default(),
            udp_nat_table: Default::default(),
            host_udp_sockets: Default::default(),
            reverse_udp_nat: Default::default(),
            connections_to_remove: Default::default(),
            time_wait_queue: Default::default(),
            last_udp_cleanup: Instant::now(),
            to_vm_control_queue: Default::default(),
            // data_run_queue: Default::default(),
            packet_buf: BytesMut::with_capacity(2048),
            read_buf: [0u8; 16384],
            last_data_token_idx: 0,
            stats_last_report: Instant::now(),
            stats_packets_in: 0,
            stats_packets_out: 0,
            stats_bytes_in: 0,
            stats_bytes_out: 0,
        })
    }

    /// Schedules a connection for immediate removal.
    fn schedule_removal(&mut self, token: Token) {
        if !self.connections_to_remove.contains(&token) {
            self.connections_to_remove.push(token);
        }
    }

    /// Fully removes a connection's state from the proxy.
    fn remove_connection(&mut self, token: Token) {
        info!(?token, "Cleaning up fully closed connection.");
        if let Some(mut conn) = self.host_connections.remove(&token) {
            // It's possible the stream was already deregistered (e.g., in TIME_WAIT)
            let _ = self.registry.deregister(conn.get_host_stream_mut());
        }
        if let Some(key) = self.reverse_tcp_nat.remove(&token) {
            self.tcp_nat_table.remove(&key);
        }
    }

    /// Executes the actions dictated by the state machine.
    fn execute_action(&mut self, token: Token, action: ProxyAction) {
        match action {
            ProxyAction::SendControlPacket(p) => {
                trace!(?token, "queueing control packet");
                self.to_vm_control_queue.push_back(p)
            }
            ProxyAction::Reregister(interest) => {
                trace!(?token, ?interest, "reregistering connection");
                if let Some(conn) = self.host_connections.get_mut(&token) {
                    if let Err(e) = self.registry.reregister(conn.get_host_stream_mut(), token, interest) {
                        error!(?token, "Failed to reregister stream: {}", e);
                        self.schedule_removal(token);
                    }
                } else {
                    trace!(?token, ?interest, "count not find connection to reregister");
                }
            }
            ProxyAction::Deregister => {
                trace!(?token, "deregistering connection from mio");
                if let Some(conn) = self.host_connections.get_mut(&token) {
                    if let Err(e) = self.registry.deregister(conn.get_host_stream_mut()) {
                        error!(?token, "Failed to deregister stream: {}", e);
                    }
                } else {
                    trace!(?token, "could not find connection to deregister");
                }
            }
            ProxyAction::ShutdownHostWrite => {
                trace!(?token, "shutting down host write end");
                if let Some(conn) = self.host_connections.get_mut(&token) {
                    // Need to get a mutable reference to the stream for shutdown
                    if let AnyConnection::Established(c) = conn {
                        if c.stream.shutdown(Shutdown::Write).is_err() {
                            // This can fail if the connection is already closed, which is fine.
                            trace!(?token, "Host write shutdown failed, likely already closed.");
                        }
                    } else if let AnyConnection::Simple(c) = conn {
                        // Simple connections don't implement HostStream trait, need to cast
                        if let Some(tcp_stream) = c.stream.as_any_mut().downcast_mut::<mio::net::TcpStream>() {
                            if tcp_stream.shutdown(Shutdown::Write).is_err() {
                                trace!(?token, "Host write shutdown failed, likely already closed.");
                            }
                        } else if let Some(unix_stream) = c.stream.as_any_mut().downcast_mut::<mio::net::UnixStream>() {
                            if unix_stream.shutdown(Shutdown::Write).is_err() {
                                trace!(?token, "Host write shutdown failed, likely already closed.");
                            }
                        }
                    }
                    // For other connection types, we don't need to handle shutdown
                } else {
                    trace!(?token, "could not find connection to shutdown write");
                }
            }
            ProxyAction::EnterTimeWait => {
                info!(?token, "Connection entering TIME_WAIT state.");
                // Deregister from mio, but keep connection state for TIME_WAIT_DURATION
                if let Some(conn) = self.host_connections.get_mut(&token) {
                    let _ = self.registry.deregister(conn.get_host_stream_mut());
                } else {
                    debug!(?token, "could not find connection to enter TIME_WAIT");
                }
                self.time_wait_queue
                    .push_back((Instant::now() + TIME_WAIT_DURATION, token));
            }
            ProxyAction::ScheduleRemoval => {
                trace!(?token, "schedule removal");
                self.schedule_removal(token);
            }
            // ProxyAction::QueueDataForVm => {
            //     trace!(?token, "queueing data for vm");
            //     if !self.data_run_queue.contains(&token) {
            //         self.data_run_queue.push_back(token);
            //     } else {
            //         trace!(?token, "data_run_queue did not contain token!");
            //     }
            // }
            ProxyAction::DoNothing => {
                trace!(?token, "doing nothing...");
            }
            ProxyAction::Multi(actions) => {
                trace!(?token, "multiple actions! count: {}", actions.len());
                for act in actions {
                    self.execute_action(token, act);
                }
            }
        }
    }

    /// Main entrypoint for a raw Ethernet frame from the VM.
    pub fn handle_packet_from_vm(&mut self, raw_packet: &[u8]) -> Result<(), WriteError> {
        // Update stats
        self.stats_packets_in += 1;
        self.stats_bytes_in += raw_packet.len() as u64;
        self.report_stats_if_needed();
        
        packet_utils::log_packet(raw_packet, "IN");
        if let Some(eth_frame) = EthernetPacket::new(raw_packet) {
            match eth_frame.get_ethertype() {
                EtherTypes::Ipv4 | EtherTypes::Ipv6 => self.handle_ip_packet(eth_frame.payload()),
                EtherTypes::Arp => self.handle_arp_packet(eth_frame.payload()),
                _ => Ok(()),
            }
        } else {
            Err(WriteError::NothingWritten)
        }
    }

    fn handle_arp_packet(&mut self, arp_payload: &[u8]) -> Result<(), WriteError> {
        if let Some(arp) = ArpPacket::new(arp_payload) {
            if arp.get_operation() == ArpOperations::Request
                && arp.get_target_proto_addr() == PROXY_IP
            {
                debug!("Responding to ARP request for {}", PROXY_IP);
                let reply =
                    build_arp_reply(&mut self.packet_buf, &arp, PROXY_MAC, VM_MAC, PROXY_IP);
                self.to_vm_control_queue.push_back(reply);
                return Ok(());
            }
        }
        Err(WriteError::NothingWritten)
    }

    fn handle_ip_packet(&mut self, ip_payload: &[u8]) -> Result<(), WriteError> {
        let Some(ip_packet) = IpPacket::new(ip_payload) else {
            return Err(WriteError::NothingWritten);
        };

        let (src_addr, dst_addr, protocol, payload) = (
            ip_packet.source(),
            ip_packet.destination(),
            ip_packet.next_header(),
            ip_packet.payload(),
        );

        match protocol {
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp) = TcpPacket::new(payload) {
                    self.handle_tcp_packet(src_addr, dst_addr, &tcp)
                } else {
                    Ok(())
                }
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(udp) = UdpPacket::new(payload) {
                    self.handle_udp_packet(src_addr, dst_addr, &udp)
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
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
        let nat_key: NatKey = (src_addr, src_port, dst_addr, dst_port);

        if let Some(&token) = self.tcp_nat_table.get(&nat_key) {
            // Existing connection
            if let Some(connection) = self.host_connections.remove(&token) {
                let (new_connection, action) =
                    connection.handle_packet(tcp_packet, PROXY_MAC, VM_MAC);
                self.host_connections.insert(token, new_connection);
                self.execute_action(token, action);
            }
        } else if (tcp_packet.get_flags() & TcpFlags::SYN) != 0 {
            // New Egress connection (from VM to outside)

            let mut vm_options = TcpNegotiatedOptions::default();
            for option in tcp_packet.get_options_iter() {
                match option.get_number() {
                    TcpOptionNumbers::WSCALE => {
                        vm_options.window_scale = Some(option.payload()[0]);
                    }
                    TcpOptionNumbers::SACK_PERMITTED => {
                        vm_options.sack_permitted = true;
                    }
                    TcpOptionNumbers::TIMESTAMPS => {
                        let payload = option.payload();
                        // Extract TSval and TSecr
                        let tsval =
                            u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                        let tsecr =
                            u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
                        vm_options.timestamp = Some((tsval, tsecr));
                    }
                    _ => {}
                }
            }
            trace!(?vm_options, "Parsed TCP options from VM SYN");

            info!(?nat_key, "New egress TCP flow detected (SYN)");
            
            // Debug: Log when we have many connections (Docker-like behavior)  
            if self.host_connections.len() > 5 {
                warn!(
                    active_connections = self.host_connections.len(),
                    ?dst_addr,
                    dst_port,
                    "Many active egress connections detected - possible Docker pull"
                );
            }
            
            let real_dest = SocketAddr::new(dst_addr, dst_port);
            let domain = if dst_addr.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            };

            let sock = match Socket::new(domain, socket2::Type::STREAM, None) {
                Ok(s) => s,
                Err(e) => {
                    error!(error = %e, "Failed to create egress socket");
                    return Ok(());
                }
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

            let token = Token(self.next_token);
            self.next_token += 1;

            let mut stream = TcpStream::from_std(sock.into());

            self.registry
                .register(&mut stream, token, Interest::WRITABLE) // Wait for connection to establish
                .unwrap();

            let conn = AnyConnection::new_egress(
                Box::new(stream),
                nat_key,
                tcp_packet.get_sequence(),
                vm_options,
            );

            self.tcp_nat_table.insert(nat_key, token);
            self.reverse_tcp_nat.insert(token, nat_key);
            self.host_connections.insert(token, conn);
        } else {
            // Packet for a non-existent connection, send RST
            trace!(?nat_key, "Packet for unknown TCP connection, sending RST.");
            let rst_packet = build_tcp_packet(
                &mut self.packet_buf,
                (dst_addr, dst_port, src_addr, src_port),
                tcp_packet.get_acknowledgement(),
                tcp_packet
                    .get_sequence()
                    .wrapping_add(tcp_packet.payload().len() as u32),
                None,
                Some(TcpFlags::RST | TcpFlags::ACK),
                PROXY_MAC,
                VM_MAC,
            );
            self.to_vm_control_queue.push_back(rst_packet);
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

            let mut mio_socket = UdpSocket::from_std(socket.into());
            self.registry
                .register(&mut mio_socket, new_token, Interest::READABLE)
                .unwrap();
            self.reverse_udp_nat.insert(new_token, nat_key);
            self.host_udp_sockets
                .insert(new_token, (mio_socket, Instant::now()));
            new_token
        });

        if let Some((socket, last_seen)) = self.host_udp_sockets.get_mut(&token) {
            trace!(?nat_key, "Sending UDP packet to host");
            let real_dest = SocketAddr::new(dst_addr, dst_port);
            if socket.send_to(udp_packet.payload(), real_dest).is_ok() {
                *last_seen = Instant::now();
            } else {
                warn!("Failed to send UDP packet to host");
            }
        }
        Ok(())
    }

    /// Checks for and handles any timed-out events like TIME_WAIT or UDP session cleanup.
    fn check_timeouts(&mut self) {
        let now = Instant::now();

        // 1. TCP TIME_WAIT cleanup (This part is fine)
        while let Some((expiry, token)) = self.time_wait_queue.front() {
            if now >= *expiry {
                let (_, token_to_remove) = self.time_wait_queue.pop_front().unwrap();
                info!(?token_to_remove, "TIME_WAIT expired. Removing connection.");
                self.remove_connection(token_to_remove);
            } else {
                break;
            }
        }

        // 2. TCP Retransmission Timeout (RTO)
        // The check_for_retransmit method now handles re-queueing internally.
        // The polling read_frame will pick it up. No separate action is needed here.
        for (_token, conn) in self.host_connections.iter_mut() {
            conn.check_for_retransmit(RTO_DURATION);
        }

        // 3. UDP Session cleanup (This part is fine)
        if self.last_udp_cleanup.elapsed() > UDP_SESSION_TIMEOUT {
            let expired: Vec<Token> = self
                .host_udp_sockets
                .iter()
                .filter(|(_, (_, ls))| ls.elapsed() > UDP_SESSION_TIMEOUT)
                .map(|(t, _)| *t)
                .collect();
            for token in expired {
                info!(?token, "UDP session timed out. Removing.");
                if let Some((mut socket, _)) = self.host_udp_sockets.remove(&token) {
                    let _ = self.registry.deregister(&mut socket);
                    if let Some(key) = self.reverse_udp_nat.remove(&token) {
                        self.udp_nat_table.remove(&key);
                    }
                }
            }
            self.last_udp_cleanup = now;
        }
    }

    /// Notifies the virtio backend if there are packets ready to be read by the VM.
    fn wake_backend_if_needed(&self) {
        if !self.to_vm_control_queue.is_empty()
            || self.host_connections.values().any(|c| c.has_data_for_vm())
        {
            if let Err(e) = self.waker.write(1) {
                // Don't error on EWOULDBLOCK, it just means the waker was already set.
                if e.kind() != io::ErrorKind::WouldBlock {
                    error!("Failed to write to backend waker: {}", e);
                }
            }
        }
    }

    /// Check for connections that have stalled (no activity for CONNECTION_STALL_TIMEOUT)
    /// and force re-registration to recover from mio event loop dropouts.
    /// Only triggers for connections that show signs of actual deadlock, not normal inactivity.
    fn check_stalled_connections(&mut self) {
        let now = Instant::now();
        let mut stalled_tokens = Vec::new();
        
        // Identify stalled connections - be more selective to avoid false positives
        for (token, connection) in &self.host_connections {
            if let Some(last_activity) = connection.get_last_activity() {
                let stall_duration = now.duration_since(last_activity);
                if stall_duration > CONNECTION_STALL_TIMEOUT {
                    // Only consider it a stall if the connection should be active but isn't
                    // Check if this is an established connection with pending work
                    let should_be_active = connection.has_data_for_vm() 
                        || connection.has_data_for_host()
                        || connection.can_read_from_host();
                        
                    if should_be_active {
                        stalled_tokens.push(*token);
                        warn!(
                            ?token,
                            stall_duration = ?stall_duration,
                            has_data_for_vm = connection.has_data_for_vm(),
                            has_data_for_host = connection.has_data_for_host(),
                            can_read_from_host = connection.can_read_from_host(),
                            "Detected truly stalled connection with pending work - forcing recovery"
                        );
                    } else {
                        // Connection is just idle, which is normal
                        trace!(?token, stall_duration = ?stall_duration, "Connection idle but no pending work");
                    }
                }
            }
        }
        
        // Force re-registration of truly stalled connections
        for token in stalled_tokens {
            if let Some(connection) = self.host_connections.get_mut(&token) {
                let current_interest = connection.get_current_interest();
                info!(?token, ?current_interest, "Re-registering truly stalled connection");
                
                // Force re-registration with current interest to kick the connection
                // back into the mio event loop
                if let Err(e) = self.registry.reregister(
                    connection.get_host_stream_mut(),
                    token,
                    current_interest,
                ) {
                    error!(?token, error = %e, "Failed to re-register stalled connection");
                } else {
                    // Update activity timestamp after successful re-registration
                    connection.update_last_activity();
                }
            }
        }
    }

    /// Report network stats periodically for debugging
    fn report_stats_if_needed(&mut self) {
        if self.stats_last_report.elapsed() >= Duration::from_secs(5) {
            info!(
                packets_in = self.stats_packets_in,
                packets_out = self.stats_packets_out,
                bytes_in = self.stats_bytes_in,
                bytes_out = self.stats_bytes_out,
                active_connections = self.host_connections.len(),
                control_queue_len = self.to_vm_control_queue.len(),
                "Network stats"
            );
            self.stats_last_report = Instant::now();
        }
    }

    fn read_frame_internal(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        // 1. Control packets still have absolute priority.
        if let Some(popped) = self.to_vm_control_queue.pop_front() {
            let packet_len = popped.len();
            buf[..packet_len].copy_from_slice(&popped);
            packet_utils::log_packet(&popped, "OUT");
            return Ok(packet_len);
        }

        // 2. If no control packets, search for a data packet.
        if self.host_connections.is_empty() {
            return Err(ReadError::NothingRead);
        }

        // Ensure the starting index is valid.
        if self.last_data_token_idx >= self.host_connections.len() {
            self.last_data_token_idx = 0;
        }

        // Iterate through all connections, starting from where we left off.
        let tokens: Vec<Token> = self.host_connections.keys().copied().collect();
        for i in 0..tokens.len() {
            let current_idx = (self.last_data_token_idx + i) % tokens.len();
            let token = tokens[current_idx];

            if let Some(conn) = self.host_connections.get_mut(&token) {
                if conn.has_data_for_vm() {
                    // Found a connection with data. Send one packet.
                    if let Some(packet) = conn.get_packet_to_send_to_vm() {
                        let packet_len = packet.len();
                        buf[..packet_len].copy_from_slice(&packet);
                        packet_utils::log_packet(&packet, "OUT");

                        // Update the index for the next call.
                        self.last_data_token_idx = (current_idx + 1) % tokens.len();

                        return Ok(packet_len);
                    }
                }
            }
        }

        Err(ReadError::NothingRead)
    }
}

impl NetBackend for NetProxy {
    fn get_rx_queue_len(&self) -> usize {
        self.to_vm_control_queue.len()
    }

    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        // This logic now strictly prioritizes the control queue. It must be
        // completely empty before we even consider sending a data packet. This
        // prevents control packet starvation and ensures timely TCP ACKs.

        // 1. DRAIN the high-priority control queue first.
        if let Some(popped) = self.to_vm_control_queue.pop_front() {
            let packet_len = popped.len();
            buf[..packet_len].copy_from_slice(&popped);
            packet_utils::log_packet(&popped, "OUT");
            
            // Update outbound stats
            self.stats_packets_out += 1;
            self.stats_bytes_out += packet_len as u64;
            
            // After sending a packet, immediately wake the backend because
            // this queue OR the data queues might have more to send.
            self.wake_backend_if_needed();
            return Ok(packet_len);
        }

        // 2. ONLY if the control queue is empty, service the data queues.
        // The previous round-robin implementation was stateful and buggy because
        // the HashMap's key order is not stable. This is a simpler, stateless
        // iteration. It's not perfectly "fair" in the short-term, but it's
        // robust and guarantees every connection will be serviced, preventing
        // starvation.
        for (_token, conn) in self.host_connections.iter_mut() {
            if conn.has_data_for_vm() {
                if let Some(packet) = conn.get_packet_to_send_to_vm() {
                    let packet_len = packet.len();
                    buf[..packet_len].copy_from_slice(&packet);
                    packet_utils::log_packet(&packet, "OUT");

                    // Update outbound stats
                    self.stats_packets_out += 1;
                    self.stats_bytes_out += packet_len as u64;

                    // Wake the backend, as this connection or others may still have data.
                    self.wake_backend_if_needed();
                    return Ok(packet_len);
                }
            }
        }

        // No packets were available from any queue.
        Err(ReadError::NothingRead)
    }

    fn write_frame(
        &mut self,
        hdr_len: usize,
        buf: &mut [u8],
    ) -> Result<(), crate::backend::WriteError> {
        self.handle_packet_from_vm(&buf[hdr_len..])?;
        self.wake_backend_if_needed();
        Ok(())
    }

    fn handle_event(&mut self, token: Token, is_readable: bool, is_writable: bool) {
        self.current_token = token;
        
        // Debug logging for all events
        trace!(?token, is_readable, is_writable, 
               active_connections = self.host_connections.len(),
               "handle_event called");

        if self.unix_listeners.contains_key(&token) {
            // New Ingress connection (from local Unix socket)
            if let Some((listener, vm_port)) = self.unix_listeners.get(&token) {
                if let Ok((mut mio_stream, _)) = listener.accept() {
                    let new_token = Token(self.next_token);
                    self.next_token += 1;
                    info!(?new_token, "Accepted Unix socket ingress connection");
                    
                    // Debug: Log when we have many connections (Docker-like behavior)
                    if self.host_connections.len() > 5 {
                        warn!(
                            active_connections = self.host_connections.len(),
                            "Many active connections detected - possible Docker pull"
                        );
                    }

                    self.registry
                        .register(&mut mio_stream, new_token, Interest::READABLE)
                        .unwrap();

                    // Create a synthetic NAT key for this ingress connection
                    let nat_key = (
                        PROXY_IP.into(),
                        (rand::random::<u16>() % 32768) + 32768,
                        VM_IP.into(),
                        *vm_port,
                    );

                    let (conn, syn_ack_packet) = AnyConnection::new_ingress(
                        Box::new(mio_stream),
                        nat_key,
                        &mut self.packet_buf,
                        PROXY_MAC,
                        VM_MAC,
                    );

                    // For ingress connections, send SYN-ACK to establish the connection
                    self.to_vm_control_queue.push_back(syn_ack_packet);

                    self.tcp_nat_table.insert(nat_key, new_token);
                    self.reverse_tcp_nat.insert(new_token, nat_key);
                    self.host_connections.insert(new_token, conn);
                }
            }
        } else if let Some(connection) = self.host_connections.remove(&token) {
            // Event on an existing TCP connection
            let (new_connection, action) =
                connection.handle_event(is_readable, is_writable, PROXY_MAC, VM_MAC);
            self.host_connections.insert(token, new_connection);
            self.execute_action(token, action);
        } else if let Some((socket, last_seen)) = self.host_udp_sockets.get_mut(&token) {
            // Event on a UDP socket
            for _ in 0..16 {
                // read budget
                match socket.recv_from(&mut self.read_buf) {
                    Ok((n, _addr)) => {
                        trace!(?token, "Read {} bytes from UDP socket", n);
                        if let Some(nat_key) = self.reverse_udp_nat.get(&token).copied() {
                            let response = build_udp_packet(
                                &mut self.packet_buf,
                                nat_key,
                                &self.read_buf[..n],
                                PROXY_MAC,
                                VM_MAC,
                            );
                            self.to_vm_control_queue.push_back(response);
                            *last_seen = Instant::now();
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        error!(?token, "UDP recv error: {}", e);
                        break;
                    }
                }
            }
        }

        // --- Cleanup and Timeouts ---
        if !self.connections_to_remove.is_empty() {
            let tokens_to_remove: Vec<Token> = self.connections_to_remove.drain(..).collect();
            for token_to_remove in tokens_to_remove {
                self.remove_connection(token_to_remove);
            }
        }

        self.check_timeouts();
        
        // Check for stalled connections and force recovery
        self.check_stalled_connections();

        self.wake_backend_if_needed();
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

#[cfg(test)]
pub mod tests {
    use super::*;
    use bytes::Buf;
    use mio::Poll;
    use pnet::packet::ipv4::Ipv4Packet;
    use std::any::Any;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use tcp_fsm::states;
    use tcp_fsm::{BoxedHostStream, HostStream};
    use tempfile::tempdir;

    #[derive(Default, Debug, Clone)]
    pub struct MockHostStream {
        pub read_buffer: Arc<Mutex<VecDeque<Bytes>>>,
        pub write_buffer: Arc<Mutex<Vec<u8>>>,
        pub shutdown_state: Arc<Mutex<Option<Shutdown>>>,
    }

    impl Read for MockHostStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
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
            self.write_buffer.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Source for MockHostStream {
        fn register(&mut self, _: &Registry, _: Token, _: Interest) -> io::Result<()> {
            Ok(())
        }
        fn reregister(&mut self, _: &Registry, _: Token, _: Interest) -> io::Result<()> {
            Ok(())
        }
        fn deregister(&mut self, _: &Registry) -> io::Result<()> {
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

    /// Test setup helper
    fn setup_proxy(registry: Registry, listeners: Vec<(u16, String)>) -> NetProxy {
        NetProxy::new(Arc::new(EventFd::new(0).unwrap()), registry, 10, listeners).unwrap()
    }

    /// Build a TCP packet from the VM perspective
    fn build_vm_tcp_packet(
        packet_buf: &mut BytesMut,
        vm_port: u16,
        host_ip: IpAddr,
        host_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Bytes {
        let key = (VM_IP.into(), vm_port, host_ip, host_port);
        build_tcp_packet(
            packet_buf,
            key,
            seq,
            ack,
            Some(payload),
            Some(flags),
            VM_MAC,
            PROXY_MAC,
        )
    }

    #[test]
    fn test_egress_handshake() {
        let _ = tracing_subscriber::fmt::try_init();
        let poll = Poll::new().unwrap();
        let registry = poll.registry().try_clone().unwrap();
        let mut proxy = setup_proxy(registry, vec![]);

        let vm_port = 49152;
        let host_ip: IpAddr = "8.8.8.8".parse().unwrap();
        let host_port = 443;
        let vm_initial_seq = 1000;

        // 1. VM sends SYN
        let syn_from_vm = build_vm_tcp_packet(
            &mut BytesMut::new(),
            vm_port,
            host_ip,
            host_port,
            vm_initial_seq,
            0,
            TcpFlags::SYN,
            &[],
        );
        proxy.handle_packet_from_vm(&syn_from_vm).unwrap();

        // Assert: A new simple connection was created
        assert_eq!(proxy.host_connections.len(), 1);
        let token = *proxy.tcp_nat_table.values().next().unwrap();
        let conn = proxy.host_connections.get(&token).unwrap();
        assert!(matches!(conn, AnyConnection::Simple(_)));

        // 2. Simulate mio writable event for the host socket
        proxy.handle_event(token, false, true);

        // Assert: Connection is still Simple (no state change needed)
        let conn_after = proxy.host_connections.get(&token).unwrap();
        assert!(matches!(conn_after, AnyConnection::Simple(_)));

        // For simple connections, a SYN-ACK is sent when host connection establishes
        assert_eq!(proxy.to_vm_control_queue.len(), 1);
        let syn_ack_to_vm = proxy.to_vm_control_queue.pop_front().unwrap();
        let eth = EthernetPacket::new(&syn_ack_to_vm).unwrap();
        let ip = Ipv4Packet::new(eth.payload()).unwrap();
        let tcp = TcpPacket::new(ip.payload()).unwrap();
        assert_eq!(tcp.get_flags(), TcpFlags::SYN | TcpFlags::ACK);
        assert_eq!(tcp.get_acknowledgement(), vm_initial_seq.wrapping_add(1));
    }

    #[test]
    fn test_active_close_and_time_wait() {
        let _ = tracing_subscriber::fmt::try_init();
        let poll = Poll::new().unwrap();
        let registry = poll.registry().try_clone().unwrap();
        let mut proxy = setup_proxy(registry, vec![]);

        // 1. Setup an established connection with a mock stream
        let token = Token(21);
        let nat_key = (VM_IP.into(), 50002, "8.8.8.8".parse().unwrap(), 443);
        let mut mock_stream = MockHostStream::default();
        mock_stream
            .read_buffer
            .lock()
            .unwrap()
            .push_back(Bytes::from_static(&[])); // Simulate read returning 0 (EOF)

        let conn = tcp_fsm::AnyConnection::Established(tcp_fsm::TcpConnection {
            stream: Box::new(mock_stream),
            nat_key,
            state: states::Established {
                tx_seq: 100,
                rx_seq: 200,
                rx_buf: Default::default(),
                write_buffer: Default::default(),
                write_buffer_size: 0,
                to_vm_buffer: Default::default(),
                in_flight_packets: Default::default(),
                highest_ack_from_vm: 200,
                dup_ack_count: 0,
                host_reads_paused: false,
                vm_reads_paused: false,
                last_fast_retransmit_seq: None,
                current_interest: Interest::READABLE,
                vm_window_size: 65535,
                vm_window_scale: 0,
                last_zero_window_probe: None,
                last_activity: Instant::now(),
            },
            packet_buf: BytesMut::with_capacity(2048),
            read_buf: [0u8; 16384],
        });
        proxy.host_connections.insert(token, conn);
        proxy.tcp_nat_table.insert(nat_key, token);

        // 2. Trigger event where host closes (read returns 0). Proxy should send FIN.
        proxy.handle_event(token, true, false);

        // Assert: State is now FinWait1 and a FIN was sent.
        let conn = proxy.host_connections.get(&token).unwrap();
        assert!(matches!(conn, AnyConnection::FinWait1(_)));
        let proxy_fin_seq = if let AnyConnection::FinWait1(c) = conn {
            c.state.fin_seq
        } else {
            panic!()
        };
        assert_eq!(proxy.to_vm_control_queue.len(), 1, "Proxy should send FIN");

        // 3. Simulate VM ACKing the proxy's FIN.
        proxy.to_vm_control_queue.clear();
        let ack_of_fin = build_vm_tcp_packet(
            &mut BytesMut::new(),
            nat_key.1,
            nat_key.2,
            nat_key.3,
            200,
            proxy_fin_seq,
            TcpFlags::ACK,
            &[],
        );
        proxy.handle_packet_from_vm(&ack_of_fin).unwrap();

        // Assert: State is now FinWait2
        assert!(matches!(
            proxy.host_connections.get(&token).unwrap(),
            AnyConnection::FinWait2(_)
        ));

        // 4. Simulate VM sending its own FIN.
        let fin_from_vm = build_vm_tcp_packet(
            &mut BytesMut::new(),
            nat_key.1,
            nat_key.2,
            nat_key.3,
            200,
            proxy_fin_seq,
            TcpFlags::FIN | TcpFlags::ACK,
            &[],
        );
        proxy.handle_packet_from_vm(&fin_from_vm).unwrap();

        // Assert: State is now TimeWait, and an ACK was sent.
        assert!(matches!(
            proxy.host_connections.get(&token).unwrap(),
            AnyConnection::TimeWait(_)
        ));
        assert_eq!(
            proxy.to_vm_control_queue.len(),
            1,
            "Proxy should send final ACK"
        );
        assert!(
            proxy.time_wait_queue.iter().any(|&(_, t)| t == token),
            "Connection should be in TIME_WAIT queue"
        );
    }

    #[test]
    fn test_rst_in_established_state() {
        let _ = tracing_subscriber::fmt::try_init();
        let poll = Poll::new().unwrap();
        let registry = poll.registry().try_clone().unwrap();
        let mut proxy = setup_proxy(registry, vec![]);

        // 1. Setup an established connection
        let token = Token(30);
        let nat_key = (VM_IP.into(), 50010, "8.8.8.8".parse().unwrap(), 443);
        let conn = AnyConnection::Established(tcp_fsm::TcpConnection {
            stream: Box::new(MockHostStream::default()),
            nat_key,
            // Using a real state is better than Default::default()
            state: states::Established {
                tx_seq: 100,
                rx_seq: 200,
                rx_buf: Default::default(),
                write_buffer: Default::default(),
                write_buffer_size: 0,
                to_vm_buffer: Default::default(),
                in_flight_packets: Default::default(),
                highest_ack_from_vm: 100,
                dup_ack_count: 0,
                host_reads_paused: false,
                vm_reads_paused: false,
                last_fast_retransmit_seq: None,
                current_interest: Interest::READABLE,
                vm_window_size: 65535,
                vm_window_scale: 0,
                last_zero_window_probe: None,
                last_activity: Instant::now(),
            },
            packet_buf: BytesMut::with_capacity(2048),
            read_buf: [0u8; 16384],
        });
        proxy.host_connections.insert(token, conn);
        proxy.tcp_nat_table.insert(nat_key, token);
        proxy.reverse_tcp_nat.insert(token, nat_key);

        // 2. Simulate VM sending a RST packet
        let rst_from_vm = build_vm_tcp_packet(
            &mut BytesMut::new(),
            nat_key.1,
            nat_key.2,
            nat_key.3,
            200, // sequence number
            0,
            TcpFlags::RST,
            &[],
        );
        proxy.handle_packet_from_vm(&rst_from_vm).unwrap();

        // 3. Assert that the connection is now SCHEDULED for removal.
        // This happens immediately after the packet is processed.
        assert!(
            proxy.connections_to_remove.contains(&token),
            "Connection should be queued for removal after RST"
        );

        // 4. Trigger the cleanup logic by processing a dummy event
        proxy.handle_event(Token(101), false, false); // Use a token not associated with the connection

        // 5. Assert that the connection has been COMPLETELY removed.
        assert!(
            proxy.connections_to_remove.is_empty(),
            "Cleanup queue should be empty after handle_event"
        );
        assert!(
            proxy.host_connections.get(&token).is_none(),
            "Connection should have been removed"
        );
        assert!(
            proxy.tcp_nat_table.get(&nat_key).is_none(),
            "NAT table entry should be gone"
        );
        assert!(
            proxy.reverse_tcp_nat.get(&token).is_none(),
            "Reverse NAT table entry should be gone"
        );
    }

    // #[test]
    // fn test_host_to_vm_data_integrity() {
    //     let _ = tracing_subscriber::fmt::try_init();
    //     let poll = Poll::new().unwrap();
    //     let registry = poll.registry().try_clone().unwrap();
    //     let mut proxy = setup_proxy(registry, vec![]);

    //     // 1. Create a known, large block of data that will require multiple TCP segments.
    //     let original_data: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();

    //     // 2. Setup an established connection with a mock stream containing our data.
    //     let token = Token(40);
    //     let nat_key = (VM_IP.into(), 50020, "8.8.8.8".parse().unwrap(), 443);
    //     let mut mock_stream = MockHostStream::default();
    //     mock_stream
    //         .read_buffer
    //         .lock()
    //         .unwrap()
    //         .push_back(Bytes::from(original_data.clone()));

    //     let initial_tx_seq = 5000;
    //     let initial_rx_seq = 6000;
    //     let mut conn = AnyConnection::Established(tcp_fsm::TcpConnection {
    //         stream: Box::new(mock_stream),
    //         nat_key,
    //         read_buf: [0; 16384],
    //         packet_buf: BytesMut::new(),
    //         state: states::Established {
    //             tx_seq: initial_tx_seq,
    //             rx_seq: initial_rx_seq,
    //             // ... other fields can be default for this test
    //             ..Default::default()
    //         },
    //     });
    //     proxy.host_connections.insert(token, conn);
    //     proxy.reverse_tcp_nat.insert(token, nat_key);
    //     proxy.tcp_nat_table.insert(nat_key, token);

    //     // 3. Trigger the readable event. This will cause the proxy to read from the mock
    //     //    stream, chunk the data, and queue packets for the VM.
    //     proxy.handle_event(token, true, false);

    //     // 4. Extract all the generated packets and reassemble the payload.
    //     let mut reassembled_data = Vec::new();
    //     let mut next_expected_seq = initial_tx_seq;

    //     // The packets are queued on the connection, which is put on the run queue.
    //     if let Some(run_token) = proxy.data_run_queue.pop_front() {
    //         assert_eq!(run_token, token);
    //         let mut conn = proxy.host_connections.remove(&run_token).unwrap();

    //         while let Some(packet_bytes) = conn.get_packet_to_send_to_vm() {
    //             let eth =
    //                 EthernetPacket::new(&packet_bytes).expect("Should be valid ethernet packet");
    //             let ip = Ipv4Packet::new(eth.payload()).expect("Should be valid ipv4 packet");
    //             let tcp = TcpPacket::new(ip.payload()).expect("Should be valid tcp packet");

    //             // Assert that sequence numbers are contiguous.
    //             assert_eq!(
    //                 tcp.get_sequence(),
    //                 next_expected_seq,
    //                 "TCP sequence number is not contiguous"
    //             );

    //             let payload = tcp.payload();
    //             reassembled_data.extend_from_slice(payload);

    //             // Update the next expected sequence number for the next iteration.
    //             next_expected_seq = next_expected_seq.wrapping_add(payload.len() as u32);
    //         }
    //     } else {
    //         panic!("Connection was not added to the data run queue");
    //     }

    //     // 5. Assert that the reassembled data is identical to the original data.
    //     assert_eq!(
    //         reassembled_data.len(),
    //         original_data.len(),
    //         "Reassembled data length does not match original"
    //     );
    //     assert_eq!(
    //         reassembled_data, original_data,
    //         "Reassembled data content does not match original"
    //     );
    // }

    // #[test]
    // fn test_concurrent_connection_integrity() {
    //     let _ = tracing_subscriber::fmt::try_init();
    //     let poll = Poll::new().unwrap();
    //     let registry = poll.registry().try_clone().unwrap();
    //     let mut proxy = setup_proxy(registry, vec![]);

    //     // 1. Define two distinct sets of original data and connection details.
    //     let original_data_a: Vec<u8> = (0..3000).map(|i| (i % 250) as u8).collect();
    //     let token_a = Token(100);
    //     let nat_key_a = (VM_IP.into(), 51001, "1.1.1.1".parse().unwrap(), 443);

    //     let original_data_b: Vec<u8> = (3000..6000).map(|i| (i % 250) as u8).collect();
    //     let token_b = Token(200);
    //     let nat_key_b = (VM_IP.into(), 51002, "2.2.2.2".parse().unwrap(), 443);

    //     // 2. Setup Connection A
    //     let mut stream_a = MockHostStream::default();
    //     stream_a
    //         .read_buffer
    //         .lock()
    //         .unwrap()
    //         .push_back(Bytes::from(original_data_a.clone()));
    //     let conn_a = AnyConnection::Established(tcp_fsm::TcpConnection {
    //         stream: Box::new(stream_a),
    //         nat_key: nat_key_a,
    //         read_buf: [0; 16384],
    //         packet_buf: BytesMut::new(),
    //         state: states::Established {
    //             tx_seq: 1000,
    //             ..Default::default()
    //         },
    //     });
    //     proxy.host_connections.insert(token_a, conn_a);

    //     // 3. Setup Connection B
    //     let mut stream_b = MockHostStream::default();
    //     stream_b
    //         .read_buffer
    //         .lock()
    //         .unwrap()
    //         .push_back(Bytes::from(original_data_b.clone()));
    //     let conn_b = AnyConnection::Established(tcp_fsm::TcpConnection {
    //         stream: Box::new(stream_b),
    //         nat_key: nat_key_b,
    //         read_buf: [0; 16384],
    //         packet_buf: BytesMut::new(),
    //         state: states::Established {
    //             tx_seq: 2000,
    //             ..Default::default()
    //         },
    //     });
    //     proxy.host_connections.insert(token_b, conn_b);

    //     // 4. Simulate mio firing readable events for both connections in the same tick.
    //     proxy.handle_event(token_a, true, false);
    //     proxy.handle_event(token_b, true, false);

    //     // 5. Reassemble the data for both streams from the proxy's output queues.
    //     let mut reassembled_streams: BTreeMap<u16, Vec<u8>> = BTreeMap::new();

    //     while let Some(run_token) = proxy.data_run_queue.pop_front() {
    //         let mut conn = proxy.host_connections.remove(&run_token).unwrap();

    //         while let Some(packet_bytes) = conn.get_packet_to_send_to_vm() {
    //             let eth = EthernetPacket::new(&packet_bytes).unwrap();
    //             let ip = Ipv4Packet::new(eth.payload()).unwrap();
    //             let tcp = TcpPacket::new(ip.payload()).unwrap();

    //             // Demultiplex streams based on the destination port inside the VM.
    //             let vm_port = tcp.get_destination();
    //             let stream_payload = reassembled_streams.entry(vm_port).or_default();
    //             stream_payload.extend_from_slice(tcp.payload());
    //         }
    //         proxy.host_connections.insert(run_token, conn);
    //     }

    //     // 6. Assert that both reassembled streams are identical to their originals.
    //     let reassembled_a = reassembled_streams
    //         .get(&nat_key_a.1)
    //         .expect("Stream A produced no data");
    //     assert_eq!(reassembled_a.len(), original_data_a.len());
    //     assert_eq!(
    //         *reassembled_a, original_data_a,
    //         "Data for connection A is corrupted"
    //     );

    //     let reassembled_b = reassembled_streams
    //         .get(&nat_key_b.1)
    //         .expect("Stream B produced no data");
    //     assert_eq!(reassembled_b.len(), original_data_b.len());
    //     assert_eq!(
    //         *reassembled_b, original_data_b,
    //         "Data for connection B is corrupted"
    //     );
    // }
}
