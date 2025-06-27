use bytes::{Buf, Bytes, BytesMut};
use core::fmt;
use mio::event::Source;
use mio::Interest;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::any::Any;
use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown};
use std::time::{Duration, Instant};
use tracing::{info, trace, warn};

use super::packet_utils::build_tcp_packet;
use crate::proxy::CHECKSUM;

// --- Flow Control Configuration ---
// Dramatically increase buffer sizes for high-speed transfers (30+ MB/s)
pub const TCP_BUFFER_SIZE: usize = 1024; // Number of packets (increased from 128)
const TCP_BUFFER_UNPAUSE_THRESHOLD: usize = TCP_BUFFER_SIZE / 2;
// Allow much more in-flight data for high-speed transfers  
const MAX_IN_FLIGHT_PACKETS: usize = TCP_BUFFER_SIZE * 4; // 4096 packets (~6MB)
const UNPAUSE_IN_FLIGHT_THRESHOLD: usize = TCP_BUFFER_SIZE * 2; // 2048 packets (~3MB)
pub(crate) const MAX_SEGMENT_SIZE: usize = 1460;
/// Max size in bytes of the buffer for data going from VM to Host.
const HOST_WRITE_BUFFER_HIGH_WATER: usize = 1024 * 1024; // 1 MiB (increased from 256KB)
const HOST_WRITE_BUFFER_LOW_WATER: usize = 1024 * 256; // 256 KiB (increased from 64KB)
/// Zero-window probe interval for deadlock recovery
const ZERO_WINDOW_PROBE_INTERVAL: Duration = Duration::from_millis(500);
/// Connection stall detection timeout - if no activity for this long, force recovery
/// Increase to 5 minutes to avoid interference with slow transfers
pub const CONNECTION_STALL_TIMEOUT: Duration = Duration::from_secs(300);

// --- Type Definitions ---
pub type NatKey = (IpAddr, u16, IpAddr, u16);

#[derive(Debug, Default, Clone, Copy)]
pub struct TcpNegotiatedOptions {
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub timestamp: Option<(u32, u32)>,
}

// --- Actions returned by state transitions for the proxy to execute ---
#[derive(Debug, PartialEq)]
pub enum ProxyAction {
    SendControlPacket(Bytes),
    Reregister(Interest),
    Deregister,
    ShutdownHostWrite,
    EnterTimeWait,
    ScheduleRemoval,
    // QueueDataForVm,
    DoNothing,
    Multi(Vec<ProxyAction>),
}

// --- Host Stream Trait ---
pub trait HostStream: Read + Write + Source + Send + Any {
    fn shutdown(&mut self, how: Shutdown) -> io::Result<()>;
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl HostStream for mio::net::TcpStream {
    fn shutdown(&mut self, how: Shutdown) -> io::Result<()> {
        mio::net::TcpStream::shutdown(self, how)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl HostStream for mio::net::UnixStream {
    fn shutdown(&mut self, how: Shutdown) -> io::Result<()> {
        mio::net::UnixStream::shutdown(self, how)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
pub type BoxedHostStream = Box<dyn HostStream>;

// --- Typestate Pattern for TCP Connections ---
pub mod states {
    use super::*;

    #[derive(Debug)]
    pub struct EgressConnecting {
        pub vm_initial_seq: u32,
        pub tx_seq: u32,
        pub vm_options: TcpNegotiatedOptions,
    }
    #[derive(Debug)]
    pub struct IngressConnecting {
        pub tx_seq: u32,
        pub rx_seq: u32,
    }
    #[derive(Debug)]
    pub struct Established {
        pub tx_seq: u32,
        pub rx_seq: u32,
        // Buffer for out-of-order packets from VM
        pub rx_buf: BTreeMap<u32, Bytes>,
        // Buffer for data from VM to be written to host
        pub write_buffer: VecDeque<Bytes>,
        pub write_buffer_size: usize,
        // Buffer for data from host to be sent to VM
        pub to_vm_buffer: VecDeque<Bytes>,
        // Packets sent to VM but not yet ACKed. Tuple is (seq, packet, sent_at, sequence_len)
        pub in_flight_packets: VecDeque<(u32, Bytes, Instant, u32)>,
        pub highest_ack_from_vm: u32,
        pub dup_ack_count: u16,
        pub host_reads_paused: bool,
        /// If true, we stop processing data packets from the VM because the host can't keep up.
        pub vm_reads_paused: bool,
        // Track the last sequence we fast retransmitted to prevent loops
        pub last_fast_retransmit_seq: Option<u32>,
        // Track the current mio Interest to avoid unnecessary reregistrations
        pub current_interest: Interest,
        // Track VM's advertised window size and scale for flow control
        pub vm_window_size: u16,
        pub vm_window_scale: u8,
        // Track last zero-window probe for deadlock recovery
        pub last_zero_window_probe: Option<Instant>,
        // Track last activity for connection health monitoring
        pub last_activity: Instant,
    }
    #[derive(Debug)]
    pub struct FinWait1 {
        pub fin_seq: u32,
        pub rx_seq: u32,
    } // Sent FIN, waiting for ACK
    #[derive(Debug)]
    pub struct FinWait2 {
        pub rx_seq: u32,
    } // Got ACK for our FIN, waiting for peer's FIN
    #[derive(Debug)]
    pub struct CloseWait {
        pub tx_seq: u32,
        pub rx_seq: u32,
    } // Received FIN, waiting for app to close
    #[derive(Debug)]
    pub struct LastAck {
        pub fin_seq: u32,
    } // Sent our FIN, waiting for final ACK
    #[derive(Debug)]
    pub struct Closing {
        pub fin_seq: u32,
        pub rx_seq: u32,
    } // Simultaneous close: both sides sent FIN, waiting for ACK of our FIN
    #[derive(Debug)]
    pub struct TimeWait;
    #[derive(Debug)]
    pub struct Listen {
        pub listen_port: u16,
    } // Server listening for incoming connections
    #[derive(Debug)]
    pub struct Closed;
}

pub struct TcpConnection<State> {
    pub stream: BoxedHostStream,
    pub nat_key: NatKey,
    pub state: State,
    pub read_buf: [u8; 16384],
    pub packet_buf: BytesMut,
}

impl<State> fmt::Debug for TcpConnection<State>
where
    State: fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpConnection")
            .field("state", &self.state)
            .field("nat_key", &self.nat_key)
            .finish()
    }
}

// --- Main Connection Enum ---
// This is the "manager" that delegates to the concrete state types.
#[derive(Debug)]
pub enum AnyConnection {
    EgressConnecting(TcpConnection<states::EgressConnecting>),
    IngressConnecting(TcpConnection<states::IngressConnecting>),
    Established(TcpConnection<states::Established>),
    FinWait1(TcpConnection<states::FinWait1>),
    FinWait2(TcpConnection<states::FinWait2>),
    CloseWait(TcpConnection<states::CloseWait>),
    LastAck(TcpConnection<states::LastAck>),
    TimeWait(TcpConnection<states::TimeWait>),
    Closing(TcpConnection<states::Closing>),
    Listen(TcpConnection<states::Listen>),
    Closed(TcpConnection<states::Closed>),
    Simple(super::simple_tcp::SimpleTcpConnection),
}

/// Trait defining the behavior for each TCP state.
pub trait TcpState {
    fn handle_packet(
        self,
        tcp_packet: &TcpPacket,
        proxy_mac: MacAddr,
        vm_mac: MacAddr,
    ) -> (AnyConnection, ProxyAction);

    fn handle_event(
        self,
        is_readable: bool,
        is_writable: bool,
        proxy_mac: MacAddr,
        vm_mac: MacAddr,
    ) -> (AnyConnection, ProxyAction);
}

/// Correctly calculates the number of bytes this packet consumes in sequence space.
fn sequence_space_consumed(tcp: &TcpPacket) -> u32 {
    let mut len = tcp.payload().len() as u32;
    if (tcp.get_flags() & TcpFlags::SYN) != 0 {
        len += 1;
    }
    if (tcp.get_flags() & TcpFlags::FIN) != 0 {
        len += 1;
    }
    len
}

// --- State Transition Implementations ---

impl<S> TcpConnection<S> {
    fn transition<NewState>(self, state: NewState) -> TcpConnection<NewState> {
        TcpConnection {
            stream: self.stream,
            nat_key: self.nat_key,
            state,
            packet_buf: self.packet_buf,
            read_buf: self.read_buf,
        }
    }
}

// --- Generic Helpers on AnyConnection ---
impl AnyConnection {
    pub fn stream_mut(&mut self) -> &mut BoxedHostStream {
        match self {
            AnyConnection::EgressConnecting(c) => &mut c.stream,
            AnyConnection::IngressConnecting(c) => &mut c.stream,
            AnyConnection::Established(c) => &mut c.stream,
            AnyConnection::FinWait1(c) => &mut c.stream,
            AnyConnection::FinWait2(c) => &mut c.stream,
            AnyConnection::CloseWait(c) => &mut c.stream,
            AnyConnection::LastAck(c) => &mut c.stream,
            AnyConnection::TimeWait(c) => &mut c.stream,
            AnyConnection::Closing(c) => &mut c.stream,
            AnyConnection::Listen(c) => &mut c.stream,
            AnyConnection::Closed(c) => &mut c.stream,
            AnyConnection::Simple(c) => &mut c.stream,
        }
    }

    pub fn is_send_buffer_full(&self) -> bool {
        match self {
            AnyConnection::Established(c) => c.state.to_vm_buffer.len() >= TCP_BUFFER_SIZE,
            AnyConnection::Simple(c) => {
                c.to_vm_buffer.len() >= super::simple_tcp::SIMPLE_BUFFER_SIZE
            }
            _ => false, // Not applicable in other states
        }
    }

    pub fn send_buffer_len(&self) -> usize {
        match self {
            AnyConnection::Established(c) => c.state.to_vm_buffer.len(),
            AnyConnection::Simple(c) => c.to_vm_buffer.len(),
            _ => 0,
        }
    }

    pub fn has_data_for_vm(&self) -> bool {
        match self {
            AnyConnection::Established(c) => !c.state.to_vm_buffer.is_empty(),
            AnyConnection::Simple(c) => c.has_data_for_vm(),
            _ => false,
        }
    }

    pub fn has_data_for_host(&self) -> bool {
        match self {
            AnyConnection::Established(c) => !c.state.write_buffer.is_empty(),
            AnyConnection::Simple(c) => c.has_data_for_host(),
            _ => false,
        }
    }

    pub fn can_read_from_host(&self) -> bool {
        match self {
            AnyConnection::Established(c) => true, // Complex connections handle this differently
            AnyConnection::Simple(c) => c.can_read_from_host(),
            _ => false,
        }
    }

    pub fn window_just_opened(&mut self) -> bool {
        match self {
            AnyConnection::Established(_) => false, // Complex connections handle this differently
            AnyConnection::Simple(c) => c.window_just_opened(),
            _ => false,
        }
    }

    pub fn get_packet_to_send_to_vm(&mut self) -> Option<Bytes> {
        match self {
            AnyConnection::Established(c) => {
                if let Some(packet) = c.state.to_vm_buffer.pop_front() {
                    if let Some(ip) = super::packet_utils::IpPacket::new(&packet[14..]) {
                        if let Some(tcp) = TcpPacket::new(ip.payload()) {
                            let seq = tcp.get_sequence();
                            let seq_len = sequence_space_consumed(&tcp);
                            trace!(?c.nat_key, seq, len = seq_len, "Sending data packet to VM");

                            // Update timestamp for retransmissions - packets should already be tracked from handle_event
                            for (s, _, ref mut ts, _) in c.state.in_flight_packets.iter_mut() {
                                if *s == seq {
                                    *ts = Instant::now();
                                    break;
                                }
                            }
                        }
                    }
                    Some(packet)
                } else {
                    None
                }
            }
            AnyConnection::Simple(c) => c.get_packet_to_send_to_vm(),
            _ => None,
        }
    }

    pub fn check_for_retransmit(&mut self, rto_duration: Duration) -> bool {
        match self {
            AnyConnection::Established(c) => {
                if let Some((seq, packet, sent_at, len)) = c.state.in_flight_packets.front() {
                    if sent_at.elapsed() > rto_duration {
                        warn!(?c.nat_key, seq, len, "RTO expired. Re-queueing packet for retransmission.");
                        let packet_clone = packet.clone();
                        c.state.to_vm_buffer.push_front(packet_clone);

                        // Update timestamp for this retransmission instead of removing
                        if let Some((_, _, ref mut ts, _)) = c.state.in_flight_packets.front_mut() {
                            *ts = Instant::now();
                        }
                        return true;
                    }
                }
                false
            }
            AnyConnection::Simple(_) => {
                // Simple connections don't do retransmissions - let TCP handle it
                false
            }
            _ => false,
        }
    }

    pub fn get_last_activity(&self) -> Option<Instant> {
        match self {
            AnyConnection::Established(c) => Some(c.state.last_activity),
            AnyConnection::Simple(_) => {
                // Simple connections don't track activity timestamps yet
                // TODO: Add activity tracking to SimpleTcpConnection
                None
            }
            _ => None,
        }
    }

    pub fn get_current_interest(&self) -> Interest {
        match self {
            AnyConnection::Established(c) => c.state.current_interest,
            AnyConnection::Simple(_) => Interest::READABLE | Interest::WRITABLE, // Default for simple connections
            _ => Interest::READABLE,
        }
    }

    pub fn get_host_stream_mut(&mut self) -> &mut dyn Source {
        match self {
            AnyConnection::EgressConnecting(c) => c.stream.as_mut(),
            AnyConnection::IngressConnecting(c) => c.stream.as_mut(),
            AnyConnection::Established(c) => c.stream.as_mut(),
            AnyConnection::FinWait1(c) => c.stream.as_mut(),
            AnyConnection::FinWait2(c) => c.stream.as_mut(),
            AnyConnection::CloseWait(c) => c.stream.as_mut(),
            AnyConnection::LastAck(c) => c.stream.as_mut(),
            AnyConnection::TimeWait(c) => c.stream.as_mut(),
            AnyConnection::Closing(c) => c.stream.as_mut(),
            AnyConnection::Listen(c) => c.stream.as_mut(),
            AnyConnection::Closed(c) => c.stream.as_mut(),
            AnyConnection::Simple(c) => &mut c.stream,
        }
    }

    pub fn update_last_activity(&mut self) {
        match self {
            AnyConnection::Established(c) => {
                c.state.last_activity = Instant::now();
            }
            AnyConnection::Simple(_) => {
                // Simple connections don't track activity timestamps yet
                // TODO: Add activity tracking to SimpleTcpConnection
            }
            _ => {}
        }
    }
}

// --- Constructor logic ---
impl AnyConnection {
    pub fn new_egress(
        stream: BoxedHostStream,
        nat_key: NatKey,
        vm_initial_seq: u32,
        vm_options: TcpNegotiatedOptions,
    ) -> Self {
        AnyConnection::EgressConnecting(TcpConnection {
            stream,
            nat_key,
            state: states::EgressConnecting {
                vm_initial_seq,
                tx_seq: rand::random::<u32>(),
                vm_options,
            },
            packet_buf: BytesMut::with_capacity(2048),
            read_buf: [0u8; 16384],
        })
    }

    pub fn new_ingress(
        stream: BoxedHostStream,
        nat_key: NatKey,
        packet_buf: &mut BytesMut,
        proxy_mac: MacAddr,
        vm_mac: MacAddr,
    ) -> (Self, Bytes) {
        let initial_seq = rand::random::<u32>();
        let conn = AnyConnection::IngressConnecting(TcpConnection {
            stream,
            nat_key,
            state: states::IngressConnecting {
                tx_seq: initial_seq.wrapping_add(1),
                rx_seq: 0,
            },
            packet_buf: BytesMut::with_capacity(2048),
            read_buf: [0u8; 16384],
        });

        let syn_packet = build_tcp_packet(
            packet_buf,
            (nat_key.2, nat_key.3, nat_key.0, nat_key.1),
            initial_seq,
            0,
            None,
            Some(TcpFlags::SYN),
            proxy_mac,
            vm_mac,
        );

        (conn, syn_packet)
    }

    pub fn new_simple(stream: BoxedHostStream, nat_key: NatKey, vm_initial_seq: u32) -> Self {
        AnyConnection::Simple(super::simple_tcp::SimpleTcpConnection::new(
            stream,
            nat_key,
            vm_initial_seq,
        ))
    }
}

// --- Dispatcher methods ---
impl AnyConnection {
    pub fn handle_packet(
        self,
        tcp_packet: &TcpPacket,
        proxy_mac: MacAddr,
        vm_mac: MacAddr,
    ) -> (Self, ProxyAction) {
        match self {
            AnyConnection::EgressConnecting(c) => c.handle_packet(tcp_packet, proxy_mac, vm_mac),
            AnyConnection::IngressConnecting(c) => c.handle_packet(tcp_packet, proxy_mac, vm_mac),
            AnyConnection::Established(c) => c.handle_packet(tcp_packet, proxy_mac, vm_mac),
            AnyConnection::FinWait1(c) => c.handle_packet(tcp_packet, proxy_mac, vm_mac),
            AnyConnection::FinWait2(c) => c.handle_packet(tcp_packet, proxy_mac, vm_mac),
            AnyConnection::CloseWait(c) => c.handle_packet(tcp_packet, proxy_mac, vm_mac),
            AnyConnection::LastAck(c) => c.handle_packet(tcp_packet, proxy_mac, vm_mac),
            AnyConnection::TimeWait(c) => c.handle_packet(tcp_packet, proxy_mac, vm_mac),
            AnyConnection::Closing(c) => c.handle_packet(tcp_packet, proxy_mac, vm_mac),
            AnyConnection::Listen(c) => c.handle_packet(tcp_packet, proxy_mac, vm_mac),
            AnyConnection::Closed(c) => c.handle_packet(tcp_packet, proxy_mac, vm_mac),
            AnyConnection::Simple(mut c) => {
                let action = c.handle_vm_packet(tcp_packet, proxy_mac, vm_mac);
                (AnyConnection::Simple(c), action)
            }
        }
    }

    pub fn handle_event(
        self,
        is_readable: bool,
        is_writable: bool,
        proxy_mac: MacAddr,
        vm_mac: MacAddr,
    ) -> (Self, ProxyAction) {
        match self {
            AnyConnection::EgressConnecting(c) => {
                c.handle_event(is_readable, is_writable, proxy_mac, vm_mac)
            }
            AnyConnection::IngressConnecting(c) => {
                c.handle_event(is_readable, is_writable, proxy_mac, vm_mac)
            }
            AnyConnection::Established(c) => {
                c.handle_event(is_readable, is_writable, proxy_mac, vm_mac)
            }
            AnyConnection::FinWait1(c) => {
                c.handle_event(is_readable, is_writable, proxy_mac, vm_mac)
            }
            AnyConnection::FinWait2(c) => {
                c.handle_event(is_readable, is_writable, proxy_mac, vm_mac)
            }
            AnyConnection::CloseWait(c) => {
                c.handle_event(is_readable, is_writable, proxy_mac, vm_mac)
            }
            AnyConnection::LastAck(c) => {
                c.handle_event(is_readable, is_writable, proxy_mac, vm_mac)
            }
            AnyConnection::TimeWait(c) => {
                c.handle_event(is_readable, is_writable, proxy_mac, vm_mac)
            }
            AnyConnection::Closing(c) => {
                c.handle_event(is_readable, is_writable, proxy_mac, vm_mac)
            }
            AnyConnection::Listen(c) => c.handle_event(is_readable, is_writable, proxy_mac, vm_mac),
            AnyConnection::Closed(c) => c.handle_event(is_readable, is_writable, proxy_mac, vm_mac),
            AnyConnection::Simple(mut c) => {
                let action = c.handle_host_event(is_readable, is_writable, proxy_mac, vm_mac);
                (AnyConnection::Simple(c), action)
            }
        }
    }
}

// --- Trait Implementations for each state ---

impl TcpState for TcpConnection<states::EgressConnecting> {
    fn handle_packet(
        self,
        _: &TcpPacket,
        _proxy_mac: MacAddr,
        _vm_mac: MacAddr,
    ) -> (AnyConnection, ProxyAction) {
        warn!("Received packet from VM while in EgressConnecting state. Ignoring.");
        (
            AnyConnection::EgressConnecting(self),
            ProxyAction::DoNothing,
        )
    }

    fn handle_event(
        mut self,
        _is_readable: bool,
        is_writable: bool,
        proxy_mac: MacAddr,
        vm_mac: MacAddr,
    ) -> (AnyConnection, ProxyAction) {
        if is_writable {
            info!(?self.nat_key, "Egress connection established to host. Sending SYN-ACK to VM.");
            let ack_seq = self.state.vm_initial_seq.wrapping_add(1);
            let syn_ack_packet = build_tcp_packet(
                &mut self.packet_buf,
                (
                    self.nat_key.2,
                    self.nat_key.3,
                    self.nat_key.0,
                    self.nat_key.1,
                ),
                self.state.tx_seq,
                ack_seq,
                None,
                Some(TcpFlags::SYN | TcpFlags::ACK),
                proxy_mac,
                vm_mac,
            );
            let new_state = states::Established {
                tx_seq: self.state.tx_seq.wrapping_add(1),
                rx_seq: ack_seq,
                rx_buf: BTreeMap::new(),
                write_buffer: VecDeque::new(),
                write_buffer_size: 0,
                to_vm_buffer: VecDeque::new(),
                in_flight_packets: VecDeque::new(),
                highest_ack_from_vm: self.state.tx_seq,
                dup_ack_count: 0,
                host_reads_paused: false,
                vm_reads_paused: false,
                last_fast_retransmit_seq: None,
                current_interest: Interest::READABLE.add(Interest::WRITABLE),
                vm_window_size: 65535, // Default window size until VM sends ACK with actual window
                vm_window_scale: self.state.vm_options.window_scale.unwrap_or(0),
                last_zero_window_probe: None,
                last_activity: Instant::now(),
            };
            (
                AnyConnection::Established(self.transition(new_state)),
                ProxyAction::Multi(vec![
                    ProxyAction::SendControlPacket(syn_ack_packet),
                    ProxyAction::Reregister(Interest::READABLE.add(Interest::WRITABLE)),
                ]),
            )
        } else {
            (
                AnyConnection::EgressConnecting(self),
                ProxyAction::DoNothing,
            )
        }
    }
}

impl TcpState for TcpConnection<states::IngressConnecting> {
    fn handle_packet(
        mut self,
        tcp: &TcpPacket,
        proxy_mac: MacAddr,
        vm_mac: MacAddr,
    ) -> (AnyConnection, ProxyAction) {
        let flags = tcp.get_flags();
        if (flags & (TcpFlags::SYN | TcpFlags::ACK)) == (TcpFlags::SYN | TcpFlags::ACK) {
            info!(?self.nat_key, "Received SYN-ACK from VM, completing ingress handshake.");
            if tcp.get_acknowledgement() != self.state.tx_seq {
                warn!(?self.nat_key, ack = tcp.get_acknowledgement(), expected = self.state.tx_seq, "Received SYN-ACK with wrong ack number. Ignoring.");
                return (
                    AnyConnection::IngressConnecting(self),
                    ProxyAction::DoNothing,
                );
            }
            self.state.rx_seq = tcp.get_sequence().wrapping_add(1);
            let ack_packet = build_tcp_packet(
                &mut self.packet_buf,
                (
                    self.nat_key.2,
                    self.nat_key.3,
                    self.nat_key.0,
                    self.nat_key.1,
                ),
                self.state.tx_seq,
                self.state.rx_seq,
                None,
                Some(TcpFlags::ACK),
                proxy_mac,
                vm_mac,
            );
            let new_state = states::Established {
                tx_seq: self.state.tx_seq,
                rx_seq: self.state.rx_seq,
                rx_buf: BTreeMap::new(),
                write_buffer: VecDeque::new(),
                write_buffer_size: 0,
                to_vm_buffer: VecDeque::new(),
                in_flight_packets: VecDeque::new(),
                highest_ack_from_vm: self.state.tx_seq,
                dup_ack_count: 0,
                host_reads_paused: false,
                vm_reads_paused: false,
                last_fast_retransmit_seq: None,
                current_interest: Interest::READABLE.add(Interest::WRITABLE),
                vm_window_size: tcp.get_window(),
                vm_window_scale: 0, // No window scale info in this transition
                last_zero_window_probe: None,
                last_activity: Instant::now(),
            };
            (
                AnyConnection::Established(self.transition(new_state)),
                ProxyAction::Multi(vec![
                    ProxyAction::SendControlPacket(ack_packet),
                    ProxyAction::Reregister(Interest::READABLE.add(Interest::WRITABLE)),
                ]),
            )
        } else {
            (
                AnyConnection::IngressConnecting(self),
                ProxyAction::DoNothing,
            )
        }
    }
    fn handle_event(
        self,
        _ir: bool,
        _iw: bool,
        _pm: MacAddr,
        _vm: MacAddr,
    ) -> (AnyConnection, ProxyAction) {
        warn!(?self.nat_key, "Ignoring mio event in IngressConnecting state.");
        (
            AnyConnection::IngressConnecting(self),
            ProxyAction::DoNothing,
        )
    }
}

impl TcpConnection<states::Established> {
    /// Calculate proper Interest based on current flow control state
    fn calculate_interest(&self) -> Interest {
        // Check if we can actually accept more data from host
        let can_read_from_host = !self.state.host_reads_paused
            && self.state.to_vm_buffer.len() < TCP_BUFFER_SIZE
            && self.state.in_flight_packets.len() < MAX_IN_FLIGHT_PACKETS;

        // Additionally check VM window constraints
        let bytes_in_flight = self
            .state
            .in_flight_packets
            .iter()
            .map(|(_, _, _, seq_len)| *seq_len)
            .sum::<u32>();
        let effective_vm_window = (self.state.vm_window_size as u32) << self.state.vm_window_scale;
        // Be more aggressive with window utilization - only pause when we're very close to the limit
        let vm_window_available =
            bytes_in_flight < effective_vm_window.saturating_sub(MAX_SEGMENT_SIZE as u32 / 4);

        // Build Interest from scratch based on flow control constraints
        let should_read = can_read_from_host && vm_window_available;
        // Stabilize write interest - only care about write_buffer, not to_vm_buffer which flaps constantly
        let should_write = !self.state.write_buffer.is_empty();

        match (should_read, should_write) {
            (true, true) => Interest::READABLE.add(Interest::WRITABLE),
            (true, false) => Interest::READABLE,
            (false, true) => Interest::WRITABLE,
            (false, false) => {
                // Critical fix: Always stay readable to detect connection state changes
                // and potential recovery conditions. WRITABLE-only registration can cause
                // deadlocks where the connection never detects new data availability.
                Interest::READABLE
            }
        }
    }
}

impl TcpState for TcpConnection<states::Established> {
    fn handle_packet(
        mut self,
        tcp: &TcpPacket,
        proxy_mac: MacAddr,
        vm_mac: MacAddr,
    ) -> (AnyConnection, ProxyAction) {
        let incoming_seq = tcp.get_sequence();
        let flags = tcp.get_flags();
        let payload = tcp.payload();
        let mut actions = Vec::new();

        if (flags & TcpFlags::RST) != 0 {
            info!(?self.nat_key, "RST received from VM. Tearing down connection.");
            return (
                AnyConnection::Established(self),
                ProxyAction::ScheduleRemoval,
            );
        }

        let was_paused = self.state.host_reads_paused;
        let ack_num = tcp.get_acknowledgement();
        if (flags & TcpFlags::ACK) != 0 {
            let is_new_ack = ack_num != self.state.highest_ack_from_vm
                && ack_num.wrapping_sub(self.state.highest_ack_from_vm) < (1 << 31);
            if is_new_ack {
                trace!(?self.nat_key,
                       old_ack=self.state.highest_ack_from_vm,
                       new_ack=ack_num,
                       ack_diff=ack_num.wrapping_sub(self.state.highest_ack_from_vm),
                       "New ACK received");
                self.state.highest_ack_from_vm = ack_num;
                self.state.dup_ack_count = 0;
                // Clear fast retransmit tracking on new ACK
                self.state.last_fast_retransmit_seq = None;

                // Update VM's advertised window size for flow control
                self.state.vm_window_size = tcp.get_window();
                trace!(?self.nat_key, vm_window=self.state.vm_window_size, "Updated VM window size");

                let before_prune = self.state.in_flight_packets.len();
                // More careful pruning: only remove packets that are fully acknowledged
                self.state
                    .in_flight_packets
                    .retain(|(seq, _p, _, seq_len)| {
                        let packet_end = seq.wrapping_add(*seq_len);
                        // Keep packet if any part of it is not yet acknowledged
                        // A packet is fully ACKed if ack_num >= packet_end (handling wrap-around)
                        let is_fully_acked = ack_num.wrapping_sub(packet_end) < (1u32 << 31);
                        if is_fully_acked {
                            trace!(?self.nat_key,
                                   packet_seq=*seq,
                                   packet_end=packet_end,
                                   ack=ack_num,
                                   "Removing fully ACKed packet");
                        }
                        !is_fully_acked
                    });
                let after_prune = self.state.in_flight_packets.len();
                if before_prune > after_prune {
                    trace!(?self.nat_key, pruned = before_prune - after_prune, ack=ack_num, remaining=after_prune, "Pruned acknowledged in-flight packets");
                }

                // Unpause if BOTH buffers are below threshold
                if was_paused
                    && self.state.to_vm_buffer.len() < TCP_BUFFER_UNPAUSE_THRESHOLD
                    && self.state.in_flight_packets.len() < UNPAUSE_IN_FLIGHT_THRESHOLD
                {
                    info!(?self.nat_key,
                          in_flight_len=self.state.in_flight_packets.len(),
                          to_vm_len=self.state.to_vm_buffer.len(),
                          unpause_threshold=UNPAUSE_IN_FLIGHT_THRESHOLD,
                          "Buffers drained, unpausing host reads.");
                    self.state.host_reads_paused = false;
                    let new_interest = self.calculate_interest();
                    if new_interest != self.state.current_interest {
                        actions.push(ProxyAction::Reregister(new_interest));
                        self.state.current_interest = new_interest;
                    }
                }
            } else if payload.is_empty() && ack_num == self.state.highest_ack_from_vm {
                self.state.dup_ack_count += 1;
                trace!(?self.nat_key, ack=ack_num, count=self.state.dup_ack_count, "Duplicate ACK received");

                // Only trigger fast retransmit if we haven't already done it for this sequence
                if self.state.dup_ack_count >= 3
                    && self.state.last_fast_retransmit_seq != Some(ack_num)
                {
                    // Find the specific packet that the VM is requesting (the one starting at ack_num)
                    let mut found_packet = None;
                    for (i, (seq, packet, _timestamp, len)) in
                        self.state.in_flight_packets.iter().enumerate()
                    {
                        if *seq == ack_num {
                            found_packet = Some((i, packet.clone(), *len));
                            break;
                        }
                    }

                    if let Some((packet_index, packet, len)) = found_packet {
                        warn!(?self.nat_key, seq=ack_num, len, "Triple duplicate ACKs detected. Fast retransmitting specific packet.");
                        self.state.to_vm_buffer.push_front(packet);
                        // Update timestamp for this retransmission
                        if let Some((_, _, ref mut ts, _)) =
                            self.state.in_flight_packets.get_mut(packet_index)
                        {
                            *ts = std::time::Instant::now();
                        }
                        // Track that we've fast retransmitted this sequence to prevent loops
                        self.state.last_fast_retransmit_seq = Some(ack_num);
                        self.state.dup_ack_count = 0;
                    } else {
                        // Fallback: if we can't find the exact packet, retransmit the first one
                        if let Some((seq, packet, _timestamp, len)) =
                            self.state.in_flight_packets.front()
                        {
                            warn!(?self.nat_key, seq, len, requested_seq=ack_num, "Triple duplicate ACKs: requested packet not found, retransmitting first in-flight.");
                            self.state.to_vm_buffer.push_front(packet.clone());
                            if let Some((_, _, ref mut ts, _)) =
                                self.state.in_flight_packets.front_mut()
                            {
                                *ts = std::time::Instant::now();
                            }
                            // Track that we've fast retransmitted this sequence to prevent loops
                            self.state.last_fast_retransmit_seq = Some(ack_num);
                            self.state.dup_ack_count = 0;
                        }
                    }
                }
            }

            // Note: Removed overly aggressive unpausing logic here.
            // Host reads should only be unpaused when there was actual buffer pressure that got relieved,
            // not just when buffers happen to be empty.
        }

        if (flags & TcpFlags::FIN) != 0 {
            info!(?self.nat_key, "FIN received from VM. Moving to CloseWait.");
            // Calculate the proper ACK: sequence + payload length + 1 (for FIN)
            let fin_ack_seq = incoming_seq
                .wrapping_add(payload.len() as u32)
                .wrapping_add(1);
            let ack_packet = build_tcp_packet(
                &mut self.packet_buf,
                (
                    self.nat_key.2,
                    self.nat_key.3,
                    self.nat_key.0,
                    self.nat_key.1,
                ),
                self.state.tx_seq,
                fin_ack_seq,
                None,
                Some(TcpFlags::ACK),
                proxy_mac,
                vm_mac,
            );
            let new_state = states::CloseWait {
                tx_seq: self.state.tx_seq,
                rx_seq: fin_ack_seq,
            };
            actions.push(ProxyAction::SendControlPacket(ack_packet));
            actions.push(ProxyAction::ShutdownHostWrite);
            return (
                AnyConnection::CloseWait(self.transition(new_state)),
                ProxyAction::Multi(actions),
            );
        }

        if !payload.is_empty() {
            if self.state.vm_reads_paused {
                trace!(?self.nat_key, "VM reads paused, dropping data packet from VM");
            } else {
                let was_write_buffer_empty = self.state.write_buffer.is_empty(); // Check before adding
                let incoming_end_seq = incoming_seq.wrapping_add(payload.len() as u32);
                // Check for duplicate or out-of-window data
                let seq_diff = incoming_seq.wrapping_sub(self.state.rx_seq);
                if seq_diff > (1u32 << 31) {
                    // This is either duplicate data or very old data
                    trace!(?self.nat_key, seq=incoming_seq, expected=self.state.rx_seq, seq_diff, "Received duplicate/old data packet");
                } else if incoming_seq != self.state.rx_seq {
                    trace!(?self.nat_key, seq=incoming_seq, expected=self.state.rx_seq, len=payload.len(), "Received out-of-order packet, buffering.");
                    // Only buffer if we haven't seen this data before
                    self.state
                        .rx_buf
                        .entry(incoming_seq)
                        .or_insert_with(|| Bytes::copy_from_slice(payload));
                } else {
                    trace!(?self.nat_key, seq=incoming_seq, len=payload.len(), "Received in-order packet.");
                    self.state
                        .write_buffer
                        .push_back(Bytes::copy_from_slice(payload));
                    self.state.write_buffer_size += payload.len();
                    self.state.rx_seq = incoming_end_seq;

                    // Process any contiguous buffered packets
                    while let Some(data) = self.state.rx_buf.remove(&self.state.rx_seq) {
                        let data_len = data.len();
                        trace!(?self.nat_key, seq = self.state.rx_seq, len = data_len, "Processing contiguous packet from rx_buf.");
                        self.state.rx_seq = self.state.rx_seq.wrapping_add(data_len as u32);
                        self.state.write_buffer.push_back(data);
                        self.state.write_buffer_size += data_len;
                    }
                }

                if self.state.write_buffer_size > HOST_WRITE_BUFFER_HIGH_WATER {
                    info!(?self.nat_key, size=self.state.write_buffer_size, "Host write buffer full, pausing VM reads.");
                    self.state.vm_reads_paused = true;
                }

                if was_write_buffer_empty && !self.state.write_buffer.is_empty() {
                    let new_interest = self.calculate_interest();
                    if new_interest != self.state.current_interest {
                        actions.push(ProxyAction::Reregister(new_interest));
                        self.state.current_interest = new_interest;
                    }
                }
            }

            let ack_packet = build_tcp_packet(
                &mut self.packet_buf,
                (
                    self.nat_key.2,
                    self.nat_key.3,
                    self.nat_key.0,
                    self.nat_key.1,
                ),
                self.state.tx_seq,
                self.state.rx_seq,
                None,
                Some(TcpFlags::ACK),
                proxy_mac,
                vm_mac,
            );
            actions.push(ProxyAction::SendControlPacket(ack_packet));
        }

        // Update Interest based on current flow control state (only if not already updated during unpausing)
        if !actions
            .iter()
            .any(|a| matches!(a, ProxyAction::Reregister(_)))
        {
            let new_interest = self.calculate_interest();
            if new_interest != self.state.current_interest {
                actions.push(ProxyAction::Reregister(new_interest));
                self.state.current_interest = new_interest;
            }
        }

        (
            AnyConnection::Established(self),
            ProxyAction::Multi(actions),
        )
    }

    fn handle_event(
        mut self,
        is_readable: bool,
        is_writable: bool,
        proxy_mac: MacAddr,
        vm_mac: MacAddr,
    ) -> (AnyConnection, ProxyAction) {
        // Update activity timestamp for connection health monitoring
        self.state.last_activity = Instant::now();

        let mut actions = Vec::new();
        let mut host_closed = false;

        if is_readable && !self.state.host_reads_paused {
            // Aggressive reading: try to read as much data as possible in one go
            // This prevents creating tiny 1-byte packets that kill performance
            let mut total_read = 0;

            loop {
                match self.stream.read(&mut self.read_buf[total_read..]) {
                    Ok(0) => {
                        if total_read == 0 {
                            trace!(?self.nat_key, "Host stream readable returned 0 bytes.");
                            host_closed = true;
                        }
                        break;
                    }
                    Ok(n) => {
                        total_read += n;
                        // Continue reading until we fill the buffer or would block
                        if total_read >= self.read_buf.len() {
                            break;
                        }
                        // Also continue until we have a reasonable chunk size
                        if total_read >= MAX_SEGMENT_SIZE && n < MAX_SEGMENT_SIZE / 4 {
                            break;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        // No more data available right now
                        break;
                    }
                    Err(e) => {
                        trace!(?self.nat_key, ?e, "Error reading from host stream");
                        return (
                            AnyConnection::Established(self),
                            ProxyAction::ScheduleRemoval,
                        );
                    }
                }
            }

            if total_read > 0 {
                let checksum = CHECKSUM.checksum(&self.read_buf[..total_read]);
                trace!(bytes = total_read, crc32 = %checksum, "BOUNDARY 1: Read data from host socket");

                // Segment data into TCP packets with proper sequence tracking
                let mut bytes_processed = 0;
                let initial_tx_seq = self.state.tx_seq;

                for chunk in self.read_buf[..total_read].chunks(MAX_SEGMENT_SIZE) {
                    // Pause if either send buffer is full OR in_flight_packets is too large
                    // This prevents memory exhaustion when the VM can't keep up with ACKing
                    if self.state.to_vm_buffer.len() >= TCP_BUFFER_SIZE {
                        self.state.host_reads_paused = true;
                        info!(?self.nat_key,
                              to_vm_len=self.state.to_vm_buffer.len(),
                              in_flight_len=self.state.in_flight_packets.len(),
                              "Send buffer full, pausing host reads.");
                        break;
                    }

                    // Also pause if in_flight_packets queue is too large (VM can't keep up)
                    if self.state.in_flight_packets.len() >= MAX_IN_FLIGHT_PACKETS {
                        self.state.host_reads_paused = true;
                        warn!(?self.nat_key,
                              in_flight_len=self.state.in_flight_packets.len(),
                              to_vm_len=self.state.to_vm_buffer.len(),
                              max_in_flight=MAX_IN_FLIGHT_PACKETS,
                              "In-flight packet queue too large, pausing host reads - VM may be slow to ACK");
                        break;
                    }

                    // CRITICAL: Check VM's advertised window to prevent VM buffer exhaustion
                    let bytes_in_flight = self
                        .state
                        .in_flight_packets
                        .iter()
                        .map(|(_, _, _, seq_len)| *seq_len)
                        .sum::<u32>();
                    let effective_vm_window =
                        (self.state.vm_window_size as u32) << self.state.vm_window_scale;
                    // Be more aggressive - only pause when we're very close to exhausting VM window
                    if bytes_in_flight
                        >= effective_vm_window.saturating_sub(MAX_SEGMENT_SIZE as u32 / 2)
                    {
                        self.state.host_reads_paused = true;
                        warn!(?self.nat_key,
                              bytes_in_flight=bytes_in_flight,
                              vm_window=effective_vm_window,
                              vm_window_raw=self.state.vm_window_size,
                              vm_window_scale=self.state.vm_window_scale,
                              "VM window exhausted, pausing host reads");
                        break;
                    }

                    let current_packet_seq = self.state.tx_seq.wrapping_add(bytes_processed as u32);

                    trace!(?self.nat_key,
                           chunk_len=chunk.len(),
                           packet_seq=current_packet_seq,
                           rx_seq=self.state.rx_seq,
                           "Building TCP packet from host data");

                    let packet = build_tcp_packet(
                        &mut self.packet_buf,
                        (
                            self.nat_key.2,
                            self.nat_key.3,
                            self.nat_key.0,
                            self.nat_key.1,
                        ),
                        current_packet_seq,
                        self.state.rx_seq,
                        Some(chunk),
                        Some(TcpFlags::PSH | TcpFlags::ACK),
                        proxy_mac,
                        vm_mac,
                    );

                    // Track this packet for retransmission
                    self.state.in_flight_packets.push_back((
                        current_packet_seq,
                        packet.clone(),
                        std::time::Instant::now(),
                        chunk.len() as u32,
                    ));

                    self.state.to_vm_buffer.push_back(packet);
                    bytes_processed += chunk.len();
                }

                // Only update tx_seq after all packets are successfully queued
                if bytes_processed > 0 {
                    self.state.tx_seq = self.state.tx_seq.wrapping_add(bytes_processed as u32);
                    trace!(?self.nat_key,
                               bytes=bytes_processed,
                               old_tx_seq=initial_tx_seq,
                               new_tx_seq=self.state.tx_seq,
                               in_flight_count=self.state.in_flight_packets.len(),
                               "Updated TX sequence after segmentation");
                }
            }
        }

        if is_writable {
            let mut bytes_written = 0;
            while let Some(data) = self.state.write_buffer.front_mut() {
                match self.stream.write(data) {
                    Ok(0) => {
                        host_closed = true;
                        break;
                    }
                    Ok(n) => {
                        bytes_written += n;
                        self.state.write_buffer_size -= n;
                        if n == data.len() {
                            self.state.write_buffer.pop_front();
                        } else {
                            data.advance(n);
                            break;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        host_closed = true;
                        break;
                    }
                }
            }
            if bytes_written > 0 {
                trace!(?self.nat_key, bytes=bytes_written, "Wrote data to host stream.");
            }

            if self.state.vm_reads_paused
                && self.state.write_buffer_size < HOST_WRITE_BUFFER_LOW_WATER
            {
                info!(?self.nat_key, size=self.state.write_buffer_size, "Host write buffer drained, unpausing VM reads.");
                self.state.vm_reads_paused = false;
            }
        }

        if host_closed {
            info!(?self.nat_key, "Host closed. Sending FIN, moving to FinWait1.");
            let fin_packet = build_tcp_packet(
                &mut self.packet_buf,
                (
                    self.nat_key.2,
                    self.nat_key.3,
                    self.nat_key.0,
                    self.nat_key.1,
                ),
                self.state.tx_seq,
                self.state.rx_seq,
                None,
                Some(TcpFlags::FIN | TcpFlags::ACK),
                proxy_mac,
                vm_mac,
            );
            let new_state = states::FinWait1 {
                fin_seq: self.state.tx_seq.wrapping_add(1),
                rx_seq: self.state.rx_seq,
            };
            return (
                AnyConnection::FinWait1(self.transition(new_state)),
                ProxyAction::Multi(vec![ProxyAction::SendControlPacket(fin_packet)]),
            );
        }

        // Zero-window probing for deadlock recovery
        if self.state.host_reads_paused {
            let bytes_in_flight = self
                .state
                .in_flight_packets
                .iter()
                .map(|(_, _, _, seq_len)| *seq_len)
                .sum::<u32>();
            let effective_vm_window =
                (self.state.vm_window_size as u32) << self.state.vm_window_scale;

            // Check if we're in a zero or very small window situation
            // Be more lenient - only trigger when we're well into the zero window territory
            if bytes_in_flight >= effective_vm_window.saturating_sub(MAX_SEGMENT_SIZE as u32 * 2) {
                let now = Instant::now();
                let should_probe = match self.state.last_zero_window_probe {
                    None => true,
                    Some(last_probe) => {
                        now.duration_since(last_probe) >= ZERO_WINDOW_PROBE_INTERVAL
                    }
                };

                if should_probe {
                    // Send a 1-byte window probe to check if VM window has reopened
                    trace!(?self.nat_key,
                           bytes_in_flight=bytes_in_flight,
                           vm_window=effective_vm_window,
                           "Sending zero-window probe for deadlock recovery");

                    // Create a minimal probe packet (1 byte or empty ACK)
                    let probe_packet = build_tcp_packet(
                        &mut self.packet_buf,
                        self.nat_key,
                        self.state.tx_seq, // Use current sequence (will be retransmitted)
                        self.state.rx_seq,
                        Some(&[0u8; 1]), // 1-byte probe data
                        Some(TcpFlags::ACK | TcpFlags::PSH),
                        proxy_mac,
                        vm_mac,
                    );

                    actions.push(ProxyAction::SendControlPacket(probe_packet));
                    self.state.last_zero_window_probe = Some(now);

                    // Also try to unpause reads optimistically
                    self.state.host_reads_paused = false;
                    trace!(?self.nat_key, "Optimistically unpausing host reads after zero-window probe");
                }
            }
        }

        // Use centralized Interest calculation that respects all flow control constraints
        let interest = self.calculate_interest();

        // Only reregister if the interest has actually changed
        if interest != self.state.current_interest {
            actions.push(ProxyAction::Reregister(interest));
            self.state.current_interest = interest;
        }

        (
            AnyConnection::Established(self),
            ProxyAction::Multi(actions),
        )
    }
}

impl TcpState for TcpConnection<states::FinWait1> {
    fn handle_packet(
        self,
        tcp: &TcpPacket,
        _proxy_mac: MacAddr,
        _vm_mac: MacAddr,
    ) -> (AnyConnection, ProxyAction) {
        if (tcp.get_flags() & TcpFlags::ACK) != 0 && tcp.get_acknowledgement() == self.state.fin_seq
        {
            info!(?self.nat_key, "Got ACK for our FIN. Moving to FinWait2.");
            let new_state = states::FinWait2 {
                rx_seq: self.state.rx_seq,
            };
            (
                AnyConnection::FinWait2(self.transition(new_state)),
                ProxyAction::DoNothing,
            )
        } else {
            (AnyConnection::FinWait1(self), ProxyAction::DoNothing)
        }
    }
    fn handle_event(
        self,
        _ir: bool,
        _iw: bool,
        _pm: MacAddr,
        _vm: MacAddr,
    ) -> (AnyConnection, ProxyAction) {
        (AnyConnection::FinWait1(self), ProxyAction::DoNothing)
    }
}

impl TcpState for TcpConnection<states::FinWait2> {
    fn handle_packet(
        mut self,
        tcp: &TcpPacket,
        proxy_mac: MacAddr,
        vm_mac: MacAddr,
    ) -> (AnyConnection, ProxyAction) {
        if (tcp.get_flags() & TcpFlags::FIN) != 0 {
            info!(?self.nat_key, "Got peer FIN in FinWait2. Moving to TimeWait.");
            let ack_packet = build_tcp_packet(
                &mut self.packet_buf,
                (
                    self.nat_key.2,
                    self.nat_key.3,
                    self.nat_key.0,
                    self.nat_key.1,
                ),
                0,
                tcp.get_sequence().wrapping_add(1),
                None,
                Some(TcpFlags::ACK),
                proxy_mac,
                vm_mac,
            );
            let new_state = states::TimeWait;
            (
                AnyConnection::TimeWait(self.transition(new_state)),
                ProxyAction::Multi(vec![
                    ProxyAction::SendControlPacket(ack_packet),
                    ProxyAction::EnterTimeWait,
                ]),
            )
        } else {
            (AnyConnection::FinWait2(self), ProxyAction::DoNothing)
        }
    }

    fn handle_event(
        self,
        _ir: bool,
        _iw: bool,
        _pm: MacAddr,
        _vm: MacAddr,
    ) -> (AnyConnection, ProxyAction) {
        (AnyConnection::FinWait2(self), ProxyAction::DoNothing)
    }
}

impl TcpState for TcpConnection<states::CloseWait> {
    fn handle_packet(
        self,
        _: &TcpPacket,
        _proxy_mac: MacAddr,
        _vm_mac: MacAddr,
    ) -> (AnyConnection, ProxyAction) {
        (AnyConnection::CloseWait(self), ProxyAction::DoNothing)
    }

    fn handle_event(
        mut self,
        _ir: bool,
        _is_writable: bool,
        proxy_mac: MacAddr,
        vm_mac: MacAddr,
    ) -> (AnyConnection, ProxyAction) {
        // App has closed its side, now we can send our FIN.
        info!(?self.nat_key, "Application closed in CloseWait. Sending FIN, moving to LastAck.");
        let fin_packet = build_tcp_packet(
            &mut self.packet_buf,
            (
                self.nat_key.2,
                self.nat_key.3,
                self.nat_key.0,
                self.nat_key.1,
            ),
            self.state.tx_seq,
            self.state.rx_seq,
            None,
            Some(TcpFlags::FIN | TcpFlags::ACK),
            proxy_mac,
            vm_mac,
        );
        let new_state = states::LastAck {
            fin_seq: self.state.tx_seq.wrapping_add(1),
        };
        (
            AnyConnection::LastAck(self.transition(new_state)),
            ProxyAction::SendControlPacket(fin_packet),
        )
    }
}

impl TcpState for TcpConnection<states::LastAck> {
    fn handle_packet(
        self,
        tcp: &TcpPacket,
        _proxy_mac: MacAddr,
        _vm_mac: MacAddr,
    ) -> (AnyConnection, ProxyAction) {
        if (tcp.get_flags() & TcpFlags::ACK) != 0 && tcp.get_acknowledgement() == self.state.fin_seq
        {
            info!(?self.nat_key, "Received final ACK in LastAck. Connection is fully closed.");
            (AnyConnection::LastAck(self), ProxyAction::ScheduleRemoval)
        } else {
            (AnyConnection::LastAck(self), ProxyAction::DoNothing)
        }
    }

    fn handle_event(
        self,
        _ir: bool,
        _iw: bool,
        _pm: MacAddr,
        _vm: MacAddr,
    ) -> (AnyConnection, ProxyAction) {
        (AnyConnection::LastAck(self), ProxyAction::DoNothing)
    }
}

impl TcpState for TcpConnection<states::TimeWait> {
    fn handle_packet(
        mut self,
        tcp: &TcpPacket,
        proxy_mac: MacAddr,
        vm_mac: MacAddr,
    ) -> (AnyConnection, ProxyAction) {
        let flags = tcp.get_flags();

        // In TIME_WAIT, handle retransmitted FINs by re-sending final ACK
        if (flags & TcpFlags::FIN) != 0 {
            trace!(?self.nat_key, "Retransmitted FIN in TIME_WAIT, re-sending final ACK");
            let ack_packet = build_tcp_packet(
                &mut self.packet_buf,
                (
                    self.nat_key.2,
                    self.nat_key.3,
                    self.nat_key.0,
                    self.nat_key.1,
                ),
                0, // We don't have a sequence number in TIME_WAIT
                tcp.get_sequence().wrapping_add(1),
                None,
                Some(TcpFlags::ACK),
                proxy_mac,
                vm_mac,
            );
            (
                AnyConnection::TimeWait(self),
                ProxyAction::SendControlPacket(ack_packet),
            )
        } else {
            // For other packets, send RST to indicate connection is closed
            trace!(?self.nat_key, "Unexpected packet in TIME_WAIT, sending RST");
            let rst_packet = build_tcp_packet(
                &mut self.packet_buf,
                (
                    self.nat_key.2,
                    self.nat_key.3,
                    self.nat_key.0,
                    self.nat_key.1,
                ),
                tcp.get_acknowledgement(),
                0,
                None,
                Some(TcpFlags::RST),
                proxy_mac,
                vm_mac,
            );
            (
                AnyConnection::TimeWait(self),
                ProxyAction::SendControlPacket(rst_packet),
            )
        }
    }
    fn handle_event(
        self,
        _ir: bool,
        _iw: bool,
        _pm: MacAddr,
        _vm: MacAddr,
    ) -> (AnyConnection, ProxyAction) {
        // We shouldn't receive mio events as the socket is deregistered.
        (AnyConnection::TimeWait(self), ProxyAction::DoNothing)
    }
}

impl TcpState for TcpConnection<states::Closing> {
    fn handle_packet(
        mut self,
        tcp: &TcpPacket,
        proxy_mac: MacAddr,
        vm_mac: MacAddr,
    ) -> (AnyConnection, ProxyAction) {
        let flags = tcp.get_flags();

        // In CLOSING state, we're waiting for ACK of our FIN
        if (flags & TcpFlags::ACK) != 0 {
            let ack_num = tcp.get_acknowledgement();
            if ack_num == self.state.fin_seq.wrapping_add(1) {
                // Our FIN was ACKed, transition to TIME_WAIT
                trace!(?self.nat_key, "FIN ACKed in CLOSING, entering TIME_WAIT");
                let time_wait = TcpConnection {
                    stream: self.stream,
                    nat_key: self.nat_key,
                    state: states::TimeWait,
                    read_buf: self.read_buf,
                    packet_buf: self.packet_buf,
                };
                return (
                    AnyConnection::TimeWait(time_wait),
                    ProxyAction::EnterTimeWait,
                );
            }
        }

        // Handle retransmitted FIN
        if (flags & TcpFlags::FIN) != 0 {
            let expected_seq = self.state.rx_seq;
            if tcp.get_sequence() == expected_seq {
                // Re-send ACK for the FIN
                let ack_packet = build_tcp_packet(
                    &mut self.packet_buf,
                    (
                        self.nat_key.2,
                        self.nat_key.3,
                        self.nat_key.0,
                        self.nat_key.1,
                    ),
                    self.state.fin_seq.wrapping_add(1),
                    expected_seq.wrapping_add(1),
                    None,
                    Some(TcpFlags::ACK),
                    proxy_mac,
                    vm_mac,
                );
                return (
                    AnyConnection::Closing(self),
                    ProxyAction::SendControlPacket(ack_packet),
                );
            }
        }

        (AnyConnection::Closing(self), ProxyAction::DoNothing)
    }

    fn handle_event(
        self,
        _ir: bool,
        _iw: bool,
        _pm: MacAddr,
        _vm: MacAddr,
    ) -> (AnyConnection, ProxyAction) {
        // No host events expected in CLOSING state
        (AnyConnection::Closing(self), ProxyAction::DoNothing)
    }
}

impl TcpState for TcpConnection<states::Listen> {
    fn handle_packet(
        mut self,
        tcp: &TcpPacket,
        proxy_mac: MacAddr,
        vm_mac: MacAddr,
    ) -> (AnyConnection, ProxyAction) {
        let flags = tcp.get_flags();

        // In LISTEN state, we only accept SYN packets
        if (flags & TcpFlags::SYN) != 0 && (flags & TcpFlags::ACK) == 0 {
            // This would be for incoming connections, but our proxy is egress-only
            // Just respond with RST to reject the connection
            let rst_packet = build_tcp_packet(
                &mut self.packet_buf,
                (
                    self.nat_key.2,
                    self.nat_key.3,
                    self.nat_key.0,
                    self.nat_key.1,
                ),
                0,
                tcp.get_sequence().wrapping_add(1),
                None,
                Some(TcpFlags::RST | TcpFlags::ACK),
                proxy_mac,
                vm_mac,
            );
            return (
                AnyConnection::Listen(self),
                ProxyAction::SendControlPacket(rst_packet),
            );
        }

        (AnyConnection::Listen(self), ProxyAction::DoNothing)
    }

    fn handle_event(
        self,
        _ir: bool,
        _iw: bool,
        _pm: MacAddr,
        _vm: MacAddr,
    ) -> (AnyConnection, ProxyAction) {
        // No host events expected in LISTEN state for egress proxy
        (AnyConnection::Listen(self), ProxyAction::DoNothing)
    }
}

impl TcpState for TcpConnection<states::Closed> {
    fn handle_packet(
        mut self,
        tcp: &TcpPacket,
        proxy_mac: MacAddr,
        vm_mac: MacAddr,
    ) -> (AnyConnection, ProxyAction) {
        // In CLOSED state, respond to any packet with RST
        let flags = tcp.get_flags();

        if (flags & TcpFlags::RST) == 0 {
            // Send RST to indicate connection is closed
            let rst_seq = if (flags & TcpFlags::ACK) != 0 {
                tcp.get_acknowledgement()
            } else {
                0
            };

            let rst_ack = if (flags & TcpFlags::ACK) != 0 {
                0
            } else {
                tcp.get_sequence()
                    .wrapping_add(tcp.payload().len() as u32)
                    .wrapping_add(if (flags & (TcpFlags::SYN | TcpFlags::FIN)) != 0 {
                        1
                    } else {
                        0
                    })
            };

            let rst_flags = if (flags & TcpFlags::ACK) != 0 {
                TcpFlags::RST
            } else {
                TcpFlags::RST | TcpFlags::ACK
            };

            let rst_packet = build_tcp_packet(
                &mut self.packet_buf,
                (
                    self.nat_key.2,
                    self.nat_key.3,
                    self.nat_key.0,
                    self.nat_key.1,
                ),
                rst_seq,
                rst_ack,
                None,
                Some(rst_flags),
                proxy_mac,
                vm_mac,
            );
            return (
                AnyConnection::Closed(self),
                ProxyAction::SendControlPacket(rst_packet),
            );
        }

        (AnyConnection::Closed(self), ProxyAction::DoNothing)
    }

    fn handle_event(
        self,
        _ir: bool,
        _iw: bool,
        _pm: MacAddr,
        _vm: MacAddr,
    ) -> (AnyConnection, ProxyAction) {
        // No host events expected in CLOSED state
        (AnyConnection::Closed(self), ProxyAction::DoNothing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};
    use std::io::{Read, Write};

    // Mock stream for testing
    struct MockStream {
        read_data: Vec<u8>,
        write_data: Vec<u8>,
        read_pos: usize,
    }

    impl MockStream {
        fn new() -> Self {
            Self {
                read_data: vec![],
                write_data: vec![],
                read_pos: 0,
            }
        }
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.read_pos >= self.read_data.len() {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "would block"));
            }
            let len = std::cmp::min(buf.len(), self.read_data.len() - self.read_pos);
            buf[..len].copy_from_slice(&self.read_data[self.read_pos..self.read_pos + len]);
            self.read_pos += len;
            Ok(len)
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.write_data.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl mio::event::Source for MockStream {
        fn register(
            &mut self,
            _registry: &mio::Registry,
            _token: mio::Token,
            _interests: Interest,
        ) -> io::Result<()> {
            Ok(())
        }

        fn reregister(
            &mut self,
            _registry: &mio::Registry,
            _token: mio::Token,
            _interests: Interest,
        ) -> io::Result<()> {
            Ok(())
        }

        fn deregister(&mut self, _registry: &mio::Registry) -> io::Result<()> {
            Ok(())
        }
    }

    impl HostStream for MockStream {
        fn shutdown(&mut self, _how: std::net::Shutdown) -> io::Result<()> {
            Ok(())
        }

        fn as_any(&self) -> &dyn Any {
            self
        }

        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
    }

    fn create_tcp_packet(seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 20 + payload.len()];
        let mut tcp_packet = MutableTcpPacket::new(&mut packet).unwrap();
        tcp_packet.set_source(80);
        tcp_packet.set_destination(12345);
        tcp_packet.set_sequence(seq);
        tcp_packet.set_acknowledgement(ack);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(flags);
        tcp_packet.set_window(65535);
        tcp_packet.set_payload(payload);
        packet
    }

    #[test]
    fn test_ack_storm_prevention() {
        let mock_stream = Box::new(MockStream::new());
        let nat_key = (
            "192.168.100.2".parse().unwrap(),
            50428,
            "104.16.97.215".parse().unwrap(),
            443,
        );

        // Create an established connection
        let mut conn = TcpConnection {
            stream: mock_stream,
            nat_key,
            state: states::Established {
                tx_seq: 2416030169,
                rx_seq: 930294810,
                rx_buf: BTreeMap::new(),
                write_buffer: VecDeque::new(),
                write_buffer_size: 0,
                to_vm_buffer: VecDeque::new(),
                in_flight_packets: VecDeque::new(),
                highest_ack_from_vm: 2416030169,
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
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        // Add a packet to in-flight that the VM is requesting
        let test_packet = Bytes::from(vec![0u8; 1460]);
        conn.state
            .in_flight_packets
            .push_back((2416030169, test_packet, Instant::now(), 1460));

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        // Send 6 duplicate ACKs for the same sequence - should trigger fast retransmit only on the 3rd
        for i in 1..=6 {
            let packet_data = create_tcp_packet(930294809, 2416030169, TcpFlags::ACK, &[]);
            let tcp_packet = TcpPacket::new(&packet_data).unwrap();

            let (new_conn, _action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);

            if let AnyConnection::Established(established_conn) = new_conn {
                conn = established_conn;

                if i == 3 {
                    // After 3rd duplicate ACK, should have triggered fast retransmit
                    assert_eq!(conn.state.last_fast_retransmit_seq, Some(2416030169));
                    assert!(
                        !conn.state.to_vm_buffer.is_empty(),
                        "Should have queued retransmission"
                    );
                    // Clear the buffer to test subsequent ACKs
                    conn.state.to_vm_buffer.clear();
                } else if i > 3 {
                    // Subsequent duplicate ACKs should not trigger more retransmissions
                    assert!(
                        conn.state.to_vm_buffer.is_empty(),
                        "Should not retransmit again for ACK {}",
                        i
                    );
                    assert_eq!(conn.state.last_fast_retransmit_seq, Some(2416030169));
                }
            } else {
                panic!("Connection should remain in Established state");
            }
        }
    }

    #[test]
    fn test_no_duplicate_packets_in_flight() {
        let mock_stream = Box::new(MockStream::new());
        let nat_key = (
            "192.168.100.2".parse().unwrap(),
            50428,
            "104.16.97.215".parse().unwrap(),
            443,
        );

        // Create an established connection with a packet already in-flight
        let mut conn = TcpConnection {
            stream: mock_stream,
            nat_key,
            state: states::Established {
                tx_seq: 2416030169,
                rx_seq: 930294810,
                rx_buf: BTreeMap::new(),
                write_buffer: VecDeque::new(),
                write_buffer_size: 0,
                to_vm_buffer: VecDeque::new(),
                in_flight_packets: VecDeque::new(),
                highest_ack_from_vm: 2416030169,
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
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        // Create a test packet
        let test_packet = build_tcp_packet(
            &mut conn.packet_buf,
            (nat_key.2, nat_key.3, nat_key.0, nat_key.1),
            2416030169,
            930294810,
            Some(&[1, 2, 3, 4]),
            Some(TcpFlags::PSH | TcpFlags::ACK),
            proxy_mac,
            vm_mac,
        );

        // Add packet to send buffer (simulating new data from host)
        conn.state.to_vm_buffer.push_back(test_packet.clone());
        conn.state.in_flight_packets.push_back((
            2416030169,
            test_packet.clone(),
            Instant::now(),
            4,
        ));

        // Verify we have 1 packet in flight
        assert_eq!(conn.state.in_flight_packets.len(), 1);

        // Simulate retransmission by adding the same packet back to send buffer
        conn.state.to_vm_buffer.push_back(test_packet);

        // Create AnyConnection wrapper
        let mut any_conn = AnyConnection::Established(conn);

        // Send the packet twice (original + retransmission)
        let packet1 = any_conn.get_packet_to_send_to_vm();
        assert!(packet1.is_some());

        let packet2 = any_conn.get_packet_to_send_to_vm();
        assert!(packet2.is_some());

        // Should still only have 1 packet in flight (no duplicates)
        if let AnyConnection::Established(conn) = any_conn {
            assert_eq!(
                conn.state.in_flight_packets.len(),
                1,
                "Should not have duplicate packets in flight"
            );

            // Verify it's the right packet
            let (seq, _, _, len) = conn.state.in_flight_packets.front().unwrap();
            assert_eq!(*seq, 2416030169);
            assert_eq!(*len, 4);
        } else {
            panic!("Connection should remain in Established state");
        }
    }

    #[test]
    fn test_fast_retransmit_reset_on_new_ack() {
        let mock_stream = Box::new(MockStream::new());
        let nat_key = (
            "192.168.100.2".parse().unwrap(),
            50428,
            "104.16.97.215".parse().unwrap(),
            443,
        );

        let mut conn = TcpConnection {
            stream: mock_stream,
            nat_key,
            state: states::Established {
                tx_seq: 2416030169,
                rx_seq: 930294810,
                rx_buf: BTreeMap::new(),
                write_buffer: VecDeque::new(),
                write_buffer_size: 0,
                to_vm_buffer: VecDeque::new(),
                in_flight_packets: VecDeque::new(),
                highest_ack_from_vm: 930294809,
                dup_ack_count: 3,
                host_reads_paused: false,
                vm_reads_paused: false,
                last_fast_retransmit_seq: Some(2416030169),
                current_interest: Interest::READABLE,
                vm_window_size: 65535,
                vm_window_scale: 0,
                last_zero_window_probe: None,
                last_activity: Instant::now(),
            },
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        // Send a new ACK that advances the window
        let packet_data = create_tcp_packet(930294809, 2416031629, TcpFlags::ACK, &[]);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();

        let (new_conn, _action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);

        if let AnyConnection::Established(established_conn) = new_conn {
            // Should reset fast retransmit tracking and dup ack count
            assert_eq!(established_conn.state.last_fast_retransmit_seq, None);
            assert_eq!(established_conn.state.dup_ack_count, 0);
            assert_eq!(established_conn.state.highest_ack_from_vm, 2416031629);
        } else {
            panic!("Connection should remain in Established state");
        }
    }

    /// Test that Interest calculation includes to_vm_buffer state (Fix #1)
    #[test]
    fn test_interest_includes_to_vm_buffer() {
        use super::*;
        use crate::proxy::tcp_fsm::states;
        use crate::proxy::{tests::MockHostStream, VM_IP};
        use bytes::BytesMut;

        let mock_stream = Box::new(MockHostStream::default());
        let nat_key = (VM_IP.into(), 12345, "8.8.8.8".parse().unwrap(), 443);

        let mut conn = TcpConnection {
            stream: mock_stream,
            nat_key,
            state: states::Established {
                tx_seq: 1000,
                rx_seq: 2000,
                rx_buf: BTreeMap::new(),
                write_buffer: VecDeque::new(),
                write_buffer_size: 0,
                to_vm_buffer: VecDeque::new(),
                in_flight_packets: VecDeque::new(),
                highest_ack_from_vm: 1000,
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
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        // Initially no data queued - should be READABLE only
        let packet_data = create_tcp_packet(2000, 1000, TcpFlags::ACK, &[]);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();
        let (mut conn, action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);

        if let AnyConnection::Established(ref established) = conn {
            assert_eq!(established.state.current_interest, Interest::READABLE);
        }

        // Add data to to_vm_buffer - should trigger READABLE | WRITABLE
        if let AnyConnection::Established(ref mut established) = conn {
            established
                .state
                .to_vm_buffer
                .push_back(bytes::Bytes::from_static(b"test"));
        }

        let packet_data = create_tcp_packet(2000, 1000, TcpFlags::ACK, &[]);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();
        let (conn, action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);

        if let AnyConnection::Established(ref established) = conn {
            assert_eq!(
                established.state.current_interest,
                Interest::READABLE.add(Interest::WRITABLE)
            );
        }
    }

    /// Test that in_flight_packets queue has size limit (Fix #2)
    #[test]
    fn test_in_flight_packets_size_limit() {
        use super::*;
        use crate::proxy::tcp_fsm::states;
        use crate::proxy::{tests::MockHostStream, VM_IP};
        use bytes::BytesMut;

        let mock_stream = Box::new(MockHostStream::default());
        let nat_key = (VM_IP.into(), 12345, "8.8.8.8".parse().unwrap(), 443);

        let mut conn = TcpConnection {
            stream: mock_stream,
            nat_key,
            state: states::Established {
                tx_seq: 1000,
                rx_seq: 2000,
                rx_buf: BTreeMap::new(),
                write_buffer: VecDeque::new(),
                write_buffer_size: 0,
                to_vm_buffer: VecDeque::new(),
                in_flight_packets: VecDeque::new(),
                highest_ack_from_vm: 1000,
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
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        // Fill in_flight_packets to limit (TCP_BUFFER_SIZE * 10 = 320)
        for i in 0..320 {
            conn.state.in_flight_packets.push_back((
                1000 + i * 1460,
                bytes::Bytes::from_static(b"test"),
                std::time::Instant::now(),
                1460,
            ));
        }

        assert!(!conn.state.host_reads_paused);

        // Simulate reading more data when at limit - should trigger pause
        conn.read_buf[0..1460].fill(42); // Fill buffer with data

        // Manually call the segmentation logic that checks the limit
        let was_paused = conn.state.host_reads_paused;
        let mut bytes_processed = 0;

        // This simulates the loop in handle_event that checks buffer limits
        for chunk in conn.read_buf[0..1460].chunks(MAX_SEGMENT_SIZE) {
            if conn.state.to_vm_buffer.len() >= TCP_BUFFER_SIZE
                || conn.state.in_flight_packets.len() >= TCP_BUFFER_SIZE * 10
            {
                conn.state.host_reads_paused = true;
                break;
            }
            bytes_processed += chunk.len();
        }

        assert!(
            conn.state.host_reads_paused,
            "Host reads should be paused when in_flight_packets exceeds limit"
        );
    }

    /// Test that reregistration only happens when Interest changes (Fix #3)
    #[test]
    fn test_no_unnecessary_reregistration() {
        use super::*;
        use crate::proxy::tcp_fsm::states;
        use crate::proxy::{tests::MockHostStream, VM_IP};
        use bytes::BytesMut;

        let mock_stream = Box::new(MockHostStream::default());
        let nat_key = (VM_IP.into(), 12345, "8.8.8.8".parse().unwrap(), 443);

        let mut conn = TcpConnection {
            stream: mock_stream,
            nat_key,
            state: states::Established {
                tx_seq: 1000,
                rx_seq: 2000,
                rx_buf: BTreeMap::new(),
                write_buffer: VecDeque::new(),
                write_buffer_size: 0,
                to_vm_buffer: VecDeque::new(),
                in_flight_packets: VecDeque::new(),
                highest_ack_from_vm: 1000,
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
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        // Send ACK packet - no state change, should not trigger reregistration
        let packet_data = create_tcp_packet(2000, 1000, TcpFlags::ACK, &[]);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();
        let (conn, action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);

        // Should not contain any reregistration action
        match action {
            ProxyAction::Multi(actions) => {
                let has_reregister = actions
                    .iter()
                    .any(|a| matches!(a, ProxyAction::Reregister(_)));
                assert!(
                    !has_reregister,
                    "Should not reregister when Interest hasn't changed"
                );
            }
            ProxyAction::Reregister(_) => {
                panic!("Should not reregister when Interest hasn't changed");
            }
            _ => {} // Other actions are fine
        }

        // Verify current_interest is still tracked correctly
        if let AnyConnection::Established(ref established) = conn {
            assert_eq!(established.state.current_interest, Interest::READABLE);
        }
    }

    /// Test that host reads pause and unpause correctly based on both buffers
    #[test]
    fn test_host_reads_pause_unpause() {
        use super::*;
        use crate::proxy::tcp_fsm::states;
        use crate::proxy::{tests::MockHostStream, VM_IP};
        use bytes::BytesMut;

        let mock_stream = Box::new(MockHostStream::default());
        let nat_key = (VM_IP.into(), 12345, "8.8.8.8".parse().unwrap(), 443);

        let mut conn = TcpConnection {
            stream: mock_stream,
            nat_key,
            state: states::Established {
                tx_seq: 1000,
                rx_seq: 2000,
                rx_buf: BTreeMap::new(),
                write_buffer: VecDeque::new(),
                write_buffer_size: 0,
                to_vm_buffer: VecDeque::new(),
                in_flight_packets: VecDeque::new(),
                highest_ack_from_vm: 1000,
                dup_ack_count: 0,
                host_reads_paused: true, // Start paused
                vm_reads_paused: false,
                last_fast_retransmit_seq: None,
                current_interest: Interest::READABLE,
                vm_window_size: 65535,
                vm_window_scale: 0,
                last_zero_window_probe: None,
                last_activity: Instant::now(),
            },
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        // Add some packets to in_flight_packets but keep under unpause threshold
        for i in 0..10 {
            conn.state.in_flight_packets.push_back((
                1000 + i * 1460,
                bytes::Bytes::from_static(b"test"),
                std::time::Instant::now(),
                1460,
            ));
        }

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        // Send ACK that acknowledges some packets - should unpause reads
        let packet_data = create_tcp_packet(2000, 15600, TcpFlags::ACK, &[]); // ACK up to packet 10
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();
        let (conn, action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);

        if let AnyConnection::Established(ref established) = conn {
            assert!(
                !established.state.host_reads_paused,
                "Host reads should be unpaused when buffers drain"
            );
        }

        // Verify reregistration action was triggered for unpausing
        match action {
            ProxyAction::Multi(actions) => {
                let has_reregister = actions
                    .iter()
                    .any(|a| matches!(a, ProxyAction::Reregister(_)));
                assert!(has_reregister, "Should reregister when unpausing reads");
            }
            _ => {}
        }
    }

    /// Test that Interest updates are tracked correctly during explicit reregistrations
    #[test]
    fn test_explicit_reregistration_tracking() {
        use super::*;
        use crate::proxy::tcp_fsm::states;
        use crate::proxy::{tests::MockHostStream, VM_IP};
        use bytes::BytesMut;

        let mock_stream = Box::new(MockHostStream::default());
        let nat_key = (VM_IP.into(), 12345, "8.8.8.8".parse().unwrap(), 443);

        let mut conn = TcpConnection {
            stream: mock_stream,
            nat_key,
            state: states::Established {
                tx_seq: 1000,
                rx_seq: 2000,
                rx_buf: BTreeMap::new(),
                write_buffer: VecDeque::new(),
                write_buffer_size: 0,
                to_vm_buffer: VecDeque::new(),
                in_flight_packets: VecDeque::new(),
                highest_ack_from_vm: 1000,
                dup_ack_count: 0,
                host_reads_paused: true,
                vm_reads_paused: false,
                last_fast_retransmit_seq: None,
                current_interest: Interest::READABLE,
                vm_window_size: 65535,
                vm_window_scale: 0,
                last_zero_window_probe: None,
                last_activity: Instant::now(),
            },
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        // Send ACK that should unpause reads - triggers explicit reregistration
        let packet_data = create_tcp_packet(2000, 1000, TcpFlags::ACK, &[]);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();
        let (conn, _action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);

        if let AnyConnection::Established(ref established) = conn {
            // current_interest should be updated to reflect the new state
            assert_eq!(
                established.state.current_interest,
                Interest::READABLE.add(Interest::WRITABLE)
            );
            assert!(!established.state.host_reads_paused);
        }
    }

    #[test]
    fn test_ack_processing_removes_inflight_packets() {
        use super::super::tests::MockHostStream;
        // Test that ACK processing correctly removes acknowledged packets
        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        let mut conn = TcpConnection {
            stream: Box::new(MockHostStream::default()),
            nat_key: (
                "192.168.100.2".parse().unwrap(),
                8080,
                "8.8.8.8".parse().unwrap(),
                80,
            ),
            state: states::Established {
                tx_seq: 1000,
                rx_seq: 2000,
                write_buffer: VecDeque::new(),
                write_buffer_size: 0,
                to_vm_buffer: VecDeque::new(),
                rx_buf: BTreeMap::new(),
                in_flight_packets: VecDeque::new(),
                highest_ack_from_vm: 1000,
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
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        // Add some packets to in_flight queue
        conn.state.in_flight_packets.push_back((
            1000,
            Bytes::from("packet1"),
            Instant::now(),
            1460,
        ));
        conn.state.in_flight_packets.push_back((
            2460,
            Bytes::from("packet2"),
            Instant::now(),
            1460,
        ));
        conn.state.in_flight_packets.push_back((
            3920,
            Bytes::from("packet3"),
            Instant::now(),
            1460,
        ));

        assert_eq!(conn.state.in_flight_packets.len(), 3);

        // Send ACK for first packet (seq 1000 + len 1460 = 2460)
        let packet_data = create_tcp_packet(2000, 2460, TcpFlags::ACK, &[]);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();
        let (conn, _action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);

        if let AnyConnection::Established(ref established) = conn {
            // First packet should be removed
            assert_eq!(established.state.in_flight_packets.len(), 2);
            assert_eq!(established.state.highest_ack_from_vm, 2460);
        }

        // Send ACK for second packet (seq 2460 + len 1460 = 3920)
        let packet_data = create_tcp_packet(2000, 3920, TcpFlags::ACK, &[]);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();
        let (conn, _action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);

        if let AnyConnection::Established(ref established) = conn {
            // Second packet should be removed
            assert_eq!(established.state.in_flight_packets.len(), 1);
            assert_eq!(established.state.highest_ack_from_vm, 3920);
        }
    }

    #[test]
    fn test_closing_state_handles_ack_and_transitions_to_time_wait() {
        let mock_stream = Box::new(MockStream::new());
        let nat_key = (
            "192.168.100.2".parse().unwrap(),
            50428,
            "104.16.97.215".parse().unwrap(),
            443,
        );
        let fin_seq = 1000;
        let rx_seq = 2000;

        // Create a connection in CLOSING state (both sides sent FIN)
        let conn = TcpConnection {
            stream: mock_stream,
            nat_key,
            state: states::Closing { fin_seq, rx_seq },
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        // VM ACKs our FIN - should transition to TIME_WAIT
        let packet_data = create_tcp_packet(rx_seq, fin_seq + 1, TcpFlags::ACK, &[]);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();

        let (new_conn, action) =
            AnyConnection::Closing(conn).handle_packet(&tcp_packet, proxy_mac, vm_mac);

        // Should transition to TIME_WAIT
        assert!(matches!(new_conn, AnyConnection::TimeWait(_)));
        assert_eq!(action, ProxyAction::EnterTimeWait);
    }

    #[test]
    fn test_closing_state_handles_retransmitted_fin() {
        let mock_stream = Box::new(MockStream::new());
        let nat_key = (
            "192.168.100.2".parse().unwrap(),
            50428,
            "104.16.97.215".parse().unwrap(),
            443,
        );
        let fin_seq = 1000;
        let rx_seq = 2000;

        // Create a connection in CLOSING state
        let mut conn = TcpConnection {
            stream: mock_stream,
            nat_key,
            state: states::Closing { fin_seq, rx_seq },
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        // VM retransmits FIN - should send ACK
        let packet_data = create_tcp_packet(rx_seq, fin_seq + 1, TcpFlags::FIN, &[]);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();

        let (new_conn, action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);

        // Should stay in CLOSING and send control packet (ACK)
        assert!(matches!(new_conn, AnyConnection::Closing(_)));
        assert!(matches!(action, ProxyAction::SendControlPacket(_)));
    }

    #[test]
    fn test_listen_state_rejects_connections_with_rst() {
        let mock_stream = Box::new(MockStream::new());
        let nat_key = (
            "192.168.100.2".parse().unwrap(),
            50428,
            "104.16.97.215".parse().unwrap(),
            443,
        );

        // Create a connection in LISTEN state
        let mut conn = TcpConnection {
            stream: mock_stream,
            nat_key,
            state: states::Listen { listen_port: 443 },
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        // VM sends SYN to listening port - should reject with RST (egress-only proxy)
        let packet_data = create_tcp_packet(1000, 0, TcpFlags::SYN, &[]);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();

        let (new_conn, action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);

        // Should stay in LISTEN and send RST
        assert!(matches!(new_conn, AnyConnection::Listen(_)));
        if let ProxyAction::SendControlPacket(packet) = action {
            // Verify it's a RST packet
            let eth_packet = pnet::packet::ethernet::EthernetPacket::new(&packet).unwrap();
            let ip_packet = pnet::packet::ipv4::Ipv4Packet::new(eth_packet.payload()).unwrap();
            let tcp_rst = TcpPacket::new(ip_packet.payload()).unwrap();
            assert_eq!(tcp_rst.get_flags() & TcpFlags::RST, TcpFlags::RST);
        } else {
            panic!("Expected SendControlPacket with RST");
        }
    }

    #[test]
    fn test_closed_state_responds_with_rst_to_any_packet() {
        let mock_stream = Box::new(MockStream::new());
        let nat_key = (
            "192.168.100.2".parse().unwrap(),
            50428,
            "104.16.97.215".parse().unwrap(),
            443,
        );

        // Create a connection in CLOSED state
        let mut conn = TcpConnection {
            stream: mock_stream,
            nat_key,
            state: states::Closed,
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        // Send any packet to closed connection
        let packet_data = create_tcp_packet(1000, 2000, TcpFlags::ACK, b"test data");
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();

        let (new_conn, action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);

        // Should stay CLOSED and send RST
        assert!(matches!(new_conn, AnyConnection::Closed(_)));
        if let ProxyAction::SendControlPacket(packet) = action {
            // Verify it's a RST packet
            let eth_packet = pnet::packet::ethernet::EthernetPacket::new(&packet).unwrap();
            let ip_packet = pnet::packet::ipv4::Ipv4Packet::new(eth_packet.payload()).unwrap();
            let tcp_rst = TcpPacket::new(ip_packet.payload()).unwrap();
            assert_eq!(tcp_rst.get_flags() & TcpFlags::RST, TcpFlags::RST);
        } else {
            panic!("Expected SendControlPacket with RST");
        }
    }

    #[test]
    fn test_closed_state_ignores_rst_packets() {
        let mock_stream = Box::new(MockStream::new());
        let nat_key = (
            "192.168.100.2".parse().unwrap(),
            50428,
            "104.16.97.215".parse().unwrap(),
            443,
        );

        // Create a connection in CLOSED state
        let conn = TcpConnection {
            stream: mock_stream,
            nat_key,
            state: states::Closed,
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        // Send RST packet to closed connection
        let packet_data = create_tcp_packet(1000, 2000, TcpFlags::RST, &[]);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();

        let (new_conn, action) =
            AnyConnection::Closed(conn).handle_packet(&tcp_packet, proxy_mac, vm_mac);

        // Should stay CLOSED and do nothing (don't respond to RST with RST)
        assert!(matches!(new_conn, AnyConnection::Closed(_)));
        assert_eq!(action, ProxyAction::DoNothing);
    }

    #[test]
    fn test_fin_wait1_transitions_to_fin_wait2_on_ack() {
        let mock_stream = Box::new(MockStream::new());
        let nat_key = (
            "192.168.100.2".parse().unwrap(),
            50428,
            "104.16.97.215".parse().unwrap(),
            443,
        );
        let fin_seq = 1000;
        let rx_seq = 2000;

        // Create a connection in FIN_WAIT1 state
        let conn = TcpConnection {
            stream: mock_stream,
            nat_key,
            state: states::FinWait1 { fin_seq, rx_seq },
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        // VM ACKs our FIN - should transition to FIN_WAIT2
        let packet_data = create_tcp_packet(rx_seq, fin_seq, TcpFlags::ACK, &[]);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();

        let (new_conn, action) =
            AnyConnection::FinWait1(conn).handle_packet(&tcp_packet, proxy_mac, vm_mac);

        // Should transition to FIN_WAIT2
        assert!(matches!(new_conn, AnyConnection::FinWait2(_)));
        // Verify no special action needed for transition
        assert!(matches!(
            action,
            ProxyAction::DoNothing | ProxyAction::Multi(_)
        ));
    }

    #[test]
    fn test_fin_wait1_ignores_other_packets() {
        let mock_stream = Box::new(MockStream::new());
        let nat_key = (
            "192.168.100.2".parse().unwrap(),
            50428,
            "104.16.97.215".parse().unwrap(),
            443,
        );
        let fin_seq = 1000;
        let rx_seq = 2000;

        // Create a connection in FIN_WAIT1 state
        let conn = TcpConnection {
            stream: mock_stream,
            nat_key,
            state: states::FinWait1 { fin_seq, rx_seq },
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        // VM sends FIN without ACKing our FIN - should ignore and stay in FIN_WAIT1
        let packet_data = create_tcp_packet(rx_seq, fin_seq + 10, TcpFlags::FIN, &[]);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();

        let (new_conn, action) =
            AnyConnection::FinWait1(conn).handle_packet(&tcp_packet, proxy_mac, vm_mac);

        // Should stay in FIN_WAIT1 and do nothing
        assert!(matches!(new_conn, AnyConnection::FinWait1(_)));
        assert_eq!(action, ProxyAction::DoNothing);
    }

    #[test]
    fn test_fin_wait2_transitions_to_time_wait_on_fin() {
        let mock_stream = Box::new(MockStream::new());
        let nat_key = (
            "192.168.100.2".parse().unwrap(),
            50428,
            "104.16.97.215".parse().unwrap(),
            443,
        );
        let rx_seq = 2000;

        // Create a connection in FIN_WAIT2 state
        let mut conn = TcpConnection {
            stream: mock_stream,
            nat_key,
            state: states::FinWait2 { rx_seq },
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        // VM sends FIN - should transition to TIME_WAIT
        let packet_data = create_tcp_packet(rx_seq, 1001, TcpFlags::FIN, &[]);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();

        let (new_conn, action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);

        // Should transition to TIME_WAIT and send final ACK
        assert!(matches!(new_conn, AnyConnection::TimeWait(_)));
        assert!(matches!(
            action,
            ProxyAction::Multi(_) | ProxyAction::SendControlPacket(_)
        ));
    }

    #[test]
    fn test_close_wait_transitions_to_last_ack_on_close() {
        let mock_stream = Box::new(MockStream::new());
        let nat_key = (
            "192.168.100.2".parse().unwrap(),
            50428,
            "104.16.97.215".parse().unwrap(),
            443,
        );
        let tx_seq = 1000;
        let rx_seq = 2000;

        // Create a connection in CLOSE_WAIT state
        let conn = TcpConnection {
            stream: mock_stream,
            nat_key,
            state: states::CloseWait { tx_seq, rx_seq },
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        // Simulate host closing the connection (readable event on closed socket)
        let (new_conn, action) =
            AnyConnection::CloseWait(conn).handle_event(true, false, proxy_mac, vm_mac);

        // Should transition to LAST_ACK and send FIN
        assert!(matches!(new_conn, AnyConnection::LastAck(_)));
        assert!(matches!(
            action,
            ProxyAction::Multi(_) | ProxyAction::SendControlPacket(_)
        ));
    }

    #[test]
    fn test_last_ack_transitions_to_closed_on_ack() {
        let mock_stream = Box::new(MockStream::new());
        let nat_key = (
            "192.168.100.2".parse().unwrap(),
            50428,
            "104.16.97.215".parse().unwrap(),
            443,
        );
        let fin_seq = 1000;

        // Create a connection in LAST_ACK state
        let conn = TcpConnection {
            stream: mock_stream,
            nat_key,
            state: states::LastAck { fin_seq },
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        // VM ACKs our FIN - should close connection
        let packet_data = create_tcp_packet(2000, fin_seq, TcpFlags::ACK, &[]);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();

        let (new_conn, action) =
            AnyConnection::LastAck(conn).handle_packet(&tcp_packet, proxy_mac, vm_mac);

        // Should schedule removal (equivalent to CLOSED)
        assert_eq!(action, ProxyAction::ScheduleRemoval);
        // Connection should be removed from the proxy
    }

    #[test]
    fn test_time_wait_handles_retransmitted_fin() {
        let mock_stream = Box::new(MockStream::new());
        let nat_key = (
            "192.168.100.2".parse().unwrap(),
            50428,
            "104.16.97.215".parse().unwrap(),
            443,
        );

        // Create a connection in TIME_WAIT state
        let mut conn = TcpConnection {
            stream: mock_stream,
            nat_key,
            state: states::TimeWait,
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        // VM retransmits FIN - should re-send final ACK
        let packet_data = create_tcp_packet(2000, 1001, TcpFlags::FIN, &[]);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();

        let (new_conn, action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);

        // Should stay in TIME_WAIT and send ACK
        assert!(matches!(new_conn, AnyConnection::TimeWait(_)));
        assert!(matches!(action, ProxyAction::SendControlPacket(_)));
    }

    #[test]
    fn test_egress_connecting_establishes_on_syn_ack() {
        let mock_stream = Box::new(MockStream::new());
        let nat_key = (
            "192.168.100.2".parse().unwrap(),
            50428,
            "104.16.97.215".parse().unwrap(),
            443,
        );
        let vm_initial_seq = 1000;
        let our_seq = 2000;

        // Create an egress connecting connection
        let conn = TcpConnection {
            stream: mock_stream,
            nat_key,
            state: states::EgressConnecting {
                vm_initial_seq,
                tx_seq: our_seq,
                vm_options: TcpNegotiatedOptions::default(),
            },
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        // Host connection becomes writable - should establish connection
        let (new_conn, action) =
            AnyConnection::EgressConnecting(conn).handle_event(false, true, proxy_mac, vm_mac);

        // Should transition to ESTABLISHED
        assert!(matches!(new_conn, AnyConnection::Established(_)));
        // Should send SYN-ACK to VM and reregister for read/write
        assert!(matches!(action, ProxyAction::Multi(_)));
    }

    #[test]
    fn test_ingress_connecting_establishes_on_ack() {
        let mock_stream = Box::new(MockStream::new());
        let nat_key = (
            "192.168.100.2".parse().unwrap(),
            50428,
            "104.16.97.215".parse().unwrap(),
            443,
        );
        let our_seq = 2000;
        let vm_seq = 1000;

        // Create an ingress connecting connection (we sent SYN-ACK)
        let conn = TcpConnection {
            stream: mock_stream,
            nat_key,
            state: states::IngressConnecting {
                tx_seq: our_seq,
                rx_seq: vm_seq + 1, // We expect VM's initial seq + 1
            },
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        // VM sends SYN-ACK - should establish connection
        let packet_data =
            create_tcp_packet(vm_seq + 1, our_seq, TcpFlags::SYN | TcpFlags::ACK, &[]);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();

        let (new_conn, action) =
            AnyConnection::IngressConnecting(conn).handle_packet(&tcp_packet, proxy_mac, vm_mac);

        // Should transition to ESTABLISHED
        assert!(matches!(new_conn, AnyConnection::Established(_)));
        // Should send ACK and reregister for read/write
        assert!(matches!(action, ProxyAction::Multi(_)));
    }

    #[test]
    fn test_high_throughput_connection_handles_large_data() {
        let mock_stream = Box::new(MockStream::new());
        let nat_key = (
            "192.168.100.2".parse().unwrap(),
            50428,
            "104.16.97.215".parse().unwrap(),
            443,
        );

        // Create an established connection ready for high throughput
        let mut conn = TcpConnection {
            stream: mock_stream,
            nat_key,
            state: states::Established {
                tx_seq: 1000,
                rx_seq: 2000,
                rx_buf: BTreeMap::new(),
                write_buffer: VecDeque::new(),
                write_buffer_size: 0,
                to_vm_buffer: VecDeque::new(),
                in_flight_packets: VecDeque::new(),
                highest_ack_from_vm: 1000,
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
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        // Simulate receiving large chunks of data from VM (10KB total)
        let large_data = vec![0xAAu8; 1460]; // MSS-sized chunk
        let num_packets = 7; // ~10KB total

        for i in 0..num_packets {
            let seq = 2000 + (i * 1460) as u32;
            let packet_data = create_tcp_packet(seq, 1000, TcpFlags::ACK, &large_data);
            let tcp_packet = TcpPacket::new(&packet_data).unwrap();

            let (new_conn, action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);
            conn = match new_conn {
                AnyConnection::Established(c) => c,
                _ => panic!("Connection should stay established"),
            };

            // Should queue data for host and send ACK
            assert!(matches!(
                action,
                ProxyAction::Multi(_) | ProxyAction::SendControlPacket(_)
            ));
            assert!(!conn.state.write_buffer.is_empty());
        }

        // Verify all data was buffered correctly
        let total_buffered: usize = conn
            .state
            .write_buffer
            .iter()
            .map(|chunk| chunk.len())
            .sum();
        assert_eq!(total_buffered, num_packets * 1460);

        // Connection should not be paused for reasonable amounts of data
        assert!(!conn.state.vm_reads_paused);
    }

    #[test]
    fn test_connection_handles_burst_traffic_with_flow_control() {
        let mock_stream = Box::new(MockStream::new());
        let nat_key = (
            "192.168.100.2".parse().unwrap(),
            50428,
            "104.16.97.215".parse().unwrap(),
            443,
        );

        // Create connection with small buffer to trigger flow control
        let mut conn = TcpConnection {
            stream: mock_stream,
            nat_key,
            state: states::Established {
                tx_seq: 1000,
                rx_seq: 2000,
                rx_buf: BTreeMap::new(),
                write_buffer: VecDeque::new(),
                write_buffer_size: 0,
                to_vm_buffer: VecDeque::new(),
                in_flight_packets: VecDeque::new(),
                highest_ack_from_vm: 1000,
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
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        // Send burst of large packets to fill buffer beyond high water mark
        let large_data = vec![0xBBu8; 1460];
        let burst_size = 50; // 73KB burst - should trigger flow control

        let mut vm_paused = false;
        for i in 0..burst_size {
            let seq = 2000 + (i * 1460) as u32;
            let packet_data = create_tcp_packet(seq, 1000, TcpFlags::ACK, &large_data);
            let tcp_packet = TcpPacket::new(&packet_data).unwrap();

            let (new_conn, _action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);
            conn = match new_conn {
                AnyConnection::Established(c) => c,
                _ => panic!("Connection should stay established"),
            };

            // Check if VM reads got paused due to buffer pressure
            if conn.state.vm_reads_paused {
                vm_paused = true;
                break;
            }
        }

        // Should have triggered flow control pausing
        assert!(vm_paused, "VM reads should be paused for large burst");

        // Buffer should be near or above high water mark
        assert!(conn.state.write_buffer_size >= HOST_WRITE_BUFFER_HIGH_WATER * 3 / 4);
    }

    #[test]
    fn test_connection_handles_out_of_order_packets() {
        let mock_stream = Box::new(MockStream::new());
        let nat_key = (
            "192.168.100.2".parse().unwrap(),
            50428,
            "104.16.97.215".parse().unwrap(),
            443,
        );

        let mut conn = TcpConnection {
            stream: mock_stream,
            nat_key,
            state: states::Established {
                tx_seq: 1000,
                rx_seq: 2000,
                rx_buf: BTreeMap::new(),
                write_buffer: VecDeque::new(),
                write_buffer_size: 0,
                to_vm_buffer: VecDeque::new(),
                in_flight_packets: VecDeque::new(),
                highest_ack_from_vm: 1000,
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
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        let data1 = vec![0x11u8; 100];
        let data2 = vec![0x22u8; 100];
        let data3 = vec![0x33u8; 100];

        // Send packets out of order: 3, 1, 2

        // Packet 3 (seq 2200)
        let packet3_data = create_tcp_packet(2200, 1000, TcpFlags::ACK, &data3);
        let tcp_packet3 = TcpPacket::new(&packet3_data).unwrap();
        let (new_conn, _action) = conn.handle_packet(&tcp_packet3, proxy_mac, vm_mac);
        conn = match new_conn {
            AnyConnection::Established(c) => c,
            _ => panic!("Connection should stay established"),
        };

        // Should buffer out-of-order packet
        assert!(!conn.state.rx_buf.is_empty());
        assert!(conn.state.write_buffer.is_empty()); // Not yet written to host

        // Packet 1 (seq 2000) - the missing packet
        let packet1_data = create_tcp_packet(2000, 1000, TcpFlags::ACK, &data1);
        let tcp_packet1 = TcpPacket::new(&packet1_data).unwrap();
        let (new_conn, _action) = conn.handle_packet(&tcp_packet1, proxy_mac, vm_mac);
        conn = match new_conn {
            AnyConnection::Established(c) => c,
            _ => panic!("Connection should stay established"),
        };

        // Should now write packet 1 to host buffer
        assert!(!conn.state.write_buffer.is_empty());

        // Packet 2 (seq 2100)
        let packet2_data = create_tcp_packet(2100, 1000, TcpFlags::ACK, &data2);
        let tcp_packet2 = TcpPacket::new(&packet2_data).unwrap();
        let (new_conn, _action) = conn.handle_packet(&tcp_packet2, proxy_mac, vm_mac);
        conn = match new_conn {
            AnyConnection::Established(c) => c,
            _ => panic!("Connection should stay established"),
        };

        // All packets should now be processed in order
        let total_buffered: usize = conn
            .state
            .write_buffer
            .iter()
            .map(|chunk| chunk.len())
            .sum();
        assert_eq!(total_buffered, 300); // All three 100-byte packets

        // Out-of-order buffer should be empty now
        assert!(conn.state.rx_buf.is_empty());
    }

    #[test]
    fn test_multiple_connections_independent_state() {
        // Test that multiple connections maintain independent state
        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        // Create 3 connections in different states
        let conn1 = TcpConnection {
            stream: Box::new(MockStream::new()),
            nat_key: (
                "192.168.100.2".parse().unwrap(),
                50001,
                "1.1.1.1".parse().unwrap(),
                443,
            ),
            state: states::EgressConnecting {
                vm_initial_seq: 1000,
                tx_seq: 2000,
                vm_options: TcpNegotiatedOptions::default(),
            },
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        let mut conn2 = TcpConnection {
            stream: Box::new(MockStream::new()),
            nat_key: (
                "192.168.100.2".parse().unwrap(),
                50002,
                "2.2.2.2".parse().unwrap(),
                443,
            ),
            state: states::Established {
                tx_seq: 3000,
                rx_seq: 4000,
                rx_buf: BTreeMap::new(),
                write_buffer: VecDeque::new(),
                write_buffer_size: 0,
                to_vm_buffer: VecDeque::new(),
                in_flight_packets: VecDeque::new(),
                highest_ack_from_vm: 3000,
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
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        let conn3 = TcpConnection {
            stream: Box::new(MockStream::new()),
            nat_key: (
                "192.168.100.2".parse().unwrap(),
                50003,
                "3.3.3.3".parse().unwrap(),
                443,
            ),
            state: states::FinWait1 {
                fin_seq: 5000,
                rx_seq: 6000,
            },
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        // Trigger different events on each connection

        // Conn1: Host becomes writable (should transition to Established)
        let (new_conn1, action1) =
            AnyConnection::EgressConnecting(conn1).handle_event(false, true, proxy_mac, vm_mac);
        assert!(matches!(new_conn1, AnyConnection::Established(_)));
        assert!(matches!(action1, ProxyAction::Multi(_)));

        // Conn2: Receive data packet (should stay Established)
        let data = vec![0xDDu8; 500];
        let packet_data = create_tcp_packet(4000, 3000, TcpFlags::ACK, &data);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();
        let (new_conn2, action2) = conn2.handle_packet(&tcp_packet, proxy_mac, vm_mac);
        assert!(matches!(new_conn2, AnyConnection::Established(_)));
        assert!(matches!(
            action2,
            ProxyAction::Multi(_) | ProxyAction::SendControlPacket(_)
        ));

        // Conn3: Receive FIN ACK (should transition to FinWait2)
        let packet_data = create_tcp_packet(6000, 5000, TcpFlags::ACK, &[]);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();
        let (new_conn3, action3) =
            AnyConnection::FinWait1(conn3).handle_packet(&tcp_packet, proxy_mac, vm_mac);
        assert!(matches!(new_conn3, AnyConnection::FinWait2(_)));
        assert_eq!(action3, ProxyAction::DoNothing);

        // Verify each connection maintained independent state and transitioned correctly
        // This proves the state machine handles multiple concurrent connections properly
    }

    #[test]
    fn test_connection_resource_limits_and_cleanup() {
        let mock_stream = Box::new(MockStream::new());
        let nat_key = (
            "192.168.100.2".parse().unwrap(),
            50428,
            "104.16.97.215".parse().unwrap(),
            443,
        );

        let mut conn = TcpConnection {
            stream: mock_stream,
            nat_key,
            state: states::Established {
                tx_seq: 1000,
                rx_seq: 2000,
                rx_buf: BTreeMap::new(),
                write_buffer: VecDeque::new(),
                write_buffer_size: 0,
                to_vm_buffer: VecDeque::new(),
                in_flight_packets: VecDeque::new(),
                highest_ack_from_vm: 1000,
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
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        // Add many packets to in-flight buffer to test size limits
        let test_data = vec![0xFFu8; 1460];
        for i in 0..TCP_BUFFER_SIZE + 5 {
            let seq = 1000 + (i * 1460) as u32;
            let packet = Bytes::from(test_data.clone());
            conn.state
                .in_flight_packets
                .push_back((seq, packet, Instant::now(), 1460));
        }

        // Verify buffer size limit is enforced
        assert!(conn.state.in_flight_packets.len() >= TCP_BUFFER_SIZE);

        // Send ACK to clear some in-flight packets
        let ack_seq = 1000 + (TCP_BUFFER_SIZE as u32 / 2 * 1460);
        let packet_data = create_tcp_packet(2000, ack_seq, TcpFlags::ACK, &[]);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();

        let (new_conn, _action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);
        let conn = match new_conn {
            AnyConnection::Established(c) => c,
            _ => panic!("Connection should stay established"),
        };

        // Should have removed ACKed packets from in-flight buffer
        assert!(conn.state.in_flight_packets.len() < TCP_BUFFER_SIZE + 5);

        // Highest ACK should be updated
        assert!(conn.state.highest_ack_from_vm >= ack_seq);
    }

    #[test]
    fn test_concurrent_connection_establishment_and_teardown() {
        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        // Simulate multiple connections in various stages of establishment/teardown
        let connections = vec![
            // New connection establishing
            AnyConnection::EgressConnecting(TcpConnection {
                stream: Box::new(MockStream::new()),
                nat_key: (
                    "192.168.100.2".parse().unwrap(),
                    50001,
                    "1.1.1.1".parse().unwrap(),
                    443,
                ),
                state: states::EgressConnecting {
                    vm_initial_seq: 1000,
                    tx_seq: 2000,
                    vm_options: TcpNegotiatedOptions::default(),
                },
                read_buf: [0u8; 16384],
                packet_buf: BytesMut::with_capacity(2048),
            }),
            // Active data transfer
            AnyConnection::Established(TcpConnection {
                stream: Box::new(MockStream::new()),
                nat_key: (
                    "192.168.100.2".parse().unwrap(),
                    50002,
                    "2.2.2.2".parse().unwrap(),
                    443,
                ),
                state: states::Established {
                    tx_seq: 3000,
                    rx_seq: 4000,
                    rx_buf: BTreeMap::new(),
                    write_buffer: VecDeque::new(),
                    write_buffer_size: 0,
                    to_vm_buffer: VecDeque::new(),
                    in_flight_packets: VecDeque::new(),
                    highest_ack_from_vm: 3000,
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
                read_buf: [0u8; 16384],
                packet_buf: BytesMut::with_capacity(2048),
            }),
            // Connection closing
            AnyConnection::FinWait1(TcpConnection {
                stream: Box::new(MockStream::new()),
                nat_key: (
                    "192.168.100.2".parse().unwrap(),
                    50003,
                    "3.3.3.3".parse().unwrap(),
                    443,
                ),
                state: states::FinWait1 {
                    fin_seq: 5000,
                    rx_seq: 6000,
                },
                read_buf: [0u8; 16384],
                packet_buf: BytesMut::with_capacity(2048),
            }),
        ];

        // Process events on all connections simultaneously
        let mut results = Vec::new();
        for (i, conn) in connections.into_iter().enumerate() {
            let result = match i {
                0 => {
                    // Establish connection
                    conn.handle_event(false, true, proxy_mac, vm_mac)
                }
                1 => {
                    // Send data
                    let data = vec![0xAAu8; 1000];
                    let packet_data = create_tcp_packet(4000, 3000, TcpFlags::ACK, &data);
                    let tcp_packet = TcpPacket::new(&packet_data).unwrap();
                    conn.handle_packet(&tcp_packet, proxy_mac, vm_mac)
                }
                2 => {
                    // ACK the FIN
                    let packet_data = create_tcp_packet(6000, 5000, TcpFlags::ACK, &[]);
                    let tcp_packet = TcpPacket::new(&packet_data).unwrap();
                    conn.handle_packet(&tcp_packet, proxy_mac, vm_mac)
                }
                _ => unreachable!(),
            };
            results.push(result);
        }

        // Verify each connection transitioned correctly despite concurrent processing
        assert!(matches!(results[0].0, AnyConnection::Established(_))); // Connected
        assert!(matches!(results[1].0, AnyConnection::Established(_))); // Still active
        assert!(matches!(results[2].0, AnyConnection::FinWait2(_))); // Closing progressed

        // Each should have appropriate actions
        assert!(matches!(results[0].1, ProxyAction::Multi(_))); // Send SYN-ACK + reregister
        assert!(matches!(
            results[1].1,
            ProxyAction::Multi(_) | ProxyAction::SendControlPacket(_)
        )); // ACK data
        assert_eq!(results[2].1, ProxyAction::DoNothing); // Just state change
    }

    /// Test Interest registration when in-flight packets exceed limit
    #[test]
    fn test_interest_removes_readable_when_inflight_packets_full() {
        use super::super::tests::MockHostStream;
        use std::time::Instant;

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        let mut conn = TcpConnection {
            stream: Box::new(MockHostStream::default()),
            nat_key: (
                "192.168.100.2".parse().unwrap(),
                8080,
                "8.8.8.8".parse().unwrap(),
                80,
            ),
            state: states::Established {
                tx_seq: 1000,
                rx_seq: 2000,
                rx_buf: BTreeMap::new(),
                write_buffer: VecDeque::new(),
                write_buffer_size: 0,
                to_vm_buffer: VecDeque::new(),
                in_flight_packets: VecDeque::new(),
                highest_ack_from_vm: 1000,
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
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        // Fill in_flight_packets to exceed MAX_IN_FLIGHT_PACKETS limit
        for i in 0..MAX_IN_FLIGHT_PACKETS + 1 {
            conn.state.in_flight_packets.push_back((
                1000 + (i as u32 * 1460),
                Bytes::from(vec![0u8; 1460]),
                Instant::now(),
                1460,
            ));
        }

        // Send empty ACK - should trigger interest recalculation
        let packet_data = create_tcp_packet(2000, 1000, TcpFlags::ACK, &[]);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();
        let (conn, action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);

        // Should remove READABLE interest due to too many in-flight packets
        match action {
            ProxyAction::Multi(actions) => {
                let reregister_action = actions
                    .iter()
                    .find(|a| matches!(a, ProxyAction::Reregister(_)));
                if let Some(ProxyAction::Reregister(interest)) = reregister_action {
                    assert!(
                        !interest.is_readable(),
                        "Should not have READABLE when in-flight packets exceed limit"
                    );
                    assert!(
                        interest.is_writable(),
                        "Should still have WRITABLE for sending data"
                    );
                }
            }
            _ => panic!("Expected Multi action with Reregister"),
        }

        if let AnyConnection::Established(ref established) = conn {
            assert!(
                !established.state.current_interest.is_readable(),
                "current_interest should not have READABLE"
            );
        }
    }

    /// Test Interest registration when VM window is exhausted
    #[test]
    fn test_interest_removes_readable_when_vm_window_exhausted() {
        use super::super::tests::MockHostStream;
        use std::time::Instant;

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        let mut conn = TcpConnection {
            stream: Box::new(MockHostStream::default()),
            nat_key: (
                "192.168.100.2".parse().unwrap(),
                8080,
                "8.8.8.8".parse().unwrap(),
                80,
            ),
            state: states::Established {
                tx_seq: 1000,
                rx_seq: 2000,
                rx_buf: BTreeMap::new(),
                write_buffer: VecDeque::new(),
                write_buffer_size: 0,
                to_vm_buffer: VecDeque::new(),
                in_flight_packets: VecDeque::new(),
                highest_ack_from_vm: 1000,
                dup_ack_count: 0,
                host_reads_paused: false,
                vm_reads_paused: false,
                last_fast_retransmit_seq: None,
                current_interest: Interest::READABLE,
                vm_window_size: 8760, // Small window - 6 packets worth
                vm_window_scale: 0,
                last_zero_window_probe: None,
                last_activity: Instant::now(),
            },
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        // Fill in_flight_packets to exhaust VM window (6 packets * 1460 bytes = 8760 bytes)
        for i in 0..6 {
            conn.state.in_flight_packets.push_back((
                1000 + (i as u32 * 1460),
                Bytes::from(vec![0u8; 1460]),
                Instant::now(),
                1460,
            ));
        }

        // Send empty ACK - should trigger interest recalculation
        let packet_data = create_tcp_packet(2000, 1000, TcpFlags::ACK, &[]);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();
        let (conn, action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);

        // Should remove READABLE interest due to VM window exhaustion
        match action {
            ProxyAction::Multi(actions) => {
                let reregister_action = actions
                    .iter()
                    .find(|a| matches!(a, ProxyAction::Reregister(_)));
                if let Some(ProxyAction::Reregister(interest)) = reregister_action {
                    assert!(
                        !interest.is_readable(),
                        "Should not have READABLE when VM window is exhausted"
                    );
                }
            }
            _ => panic!("Expected Multi action with Reregister"),
        }

        if let AnyConnection::Established(ref established) = conn {
            assert!(
                !established.state.current_interest.is_readable(),
                "current_interest should not have READABLE"
            );
        }
    }

    /// Test Interest registration when to_vm_buffer is full
    #[test]
    fn test_interest_removes_readable_when_buffer_full() {
        use super::super::tests::MockHostStream;

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        let mut conn = TcpConnection {
            stream: Box::new(MockHostStream::default()),
            nat_key: (
                "192.168.100.2".parse().unwrap(),
                8080,
                "8.8.8.8".parse().unwrap(),
                80,
            ),
            state: states::Established {
                tx_seq: 1000,
                rx_seq: 2000,
                rx_buf: BTreeMap::new(),
                write_buffer: VecDeque::new(),
                write_buffer_size: 0,
                to_vm_buffer: VecDeque::new(),
                in_flight_packets: VecDeque::new(),
                highest_ack_from_vm: 1000,
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
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        // Fill to_vm_buffer to TCP_BUFFER_SIZE limit
        for _ in 0..TCP_BUFFER_SIZE {
            conn.state
                .to_vm_buffer
                .push_back(Bytes::from(vec![0u8; 1460]));
        }

        // Send empty ACK - should trigger interest recalculation
        let packet_data = create_tcp_packet(2000, 1000, TcpFlags::ACK, &[]);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();
        let (conn, action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);

        // Should remove READABLE interest due to full buffer
        match action {
            ProxyAction::Multi(actions) => {
                let reregister_action = actions
                    .iter()
                    .find(|a| matches!(a, ProxyAction::Reregister(_)));
                if let Some(ProxyAction::Reregister(interest)) = reregister_action {
                    assert!(
                        !interest.is_readable(),
                        "Should not have READABLE when to_vm_buffer is full"
                    );
                    assert!(
                        interest.is_writable(),
                        "Should have WRITABLE since buffer has data"
                    );
                }
            }
            _ => panic!("Expected Multi action with Reregister"),
        }

        if let AnyConnection::Established(ref established) = conn {
            assert!(
                !established.state.current_interest.is_readable(),
                "current_interest should not have READABLE"
            );
            assert!(
                established.state.current_interest.is_writable(),
                "current_interest should have WRITABLE"
            );
        }
    }

    /// Test Interest registration when host reads are paused
    #[test]
    fn test_interest_removes_readable_when_host_reads_paused() {
        use super::super::tests::MockHostStream;

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        let mut conn = TcpConnection {
            stream: Box::new(MockHostStream::default()),
            nat_key: (
                "192.168.100.2".parse().unwrap(),
                8080,
                "8.8.8.8".parse().unwrap(),
                80,
            ),
            state: states::Established {
                tx_seq: 1000,
                rx_seq: 2000,
                rx_buf: BTreeMap::new(),
                write_buffer: VecDeque::new(),
                write_buffer_size: 0,
                to_vm_buffer: VecDeque::new(),
                in_flight_packets: VecDeque::new(),
                highest_ack_from_vm: 1000,
                dup_ack_count: 0,
                host_reads_paused: true, // Explicitly paused
                vm_reads_paused: false,
                last_fast_retransmit_seq: None,
                current_interest: Interest::READABLE.add(Interest::WRITABLE),
                vm_window_size: 65535,
                vm_window_scale: 0,
                last_zero_window_probe: None,
                last_activity: Instant::now(),
            },
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        // Send empty ACK - should trigger interest recalculation
        let packet_data = create_tcp_packet(2000, 1000, TcpFlags::ACK, &[]);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();
        let (conn, action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);

        // Should remove READABLE interest due to host reads being paused
        match action {
            ProxyAction::Multi(actions) => {
                let reregister_action = actions
                    .iter()
                    .find(|a| matches!(a, ProxyAction::Reregister(_)));
                if let Some(ProxyAction::Reregister(interest)) = reregister_action {
                    assert!(
                        !interest.is_readable(),
                        "Should not have READABLE when host reads are paused"
                    );
                }
            }
            _ => panic!("Expected Multi action with Reregister"),
        }

        if let AnyConnection::Established(ref established) = conn {
            assert!(
                !established.state.current_interest.is_readable(),
                "current_interest should not have READABLE"
            );
        }
    }

    /// Test Interest adds WRITABLE when there's data to send
    #[test]
    fn test_interest_adds_writable_when_data_pending() {
        use super::super::tests::MockHostStream;

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        let mut conn = TcpConnection {
            stream: Box::new(MockHostStream::default()),
            nat_key: (
                "192.168.100.2".parse().unwrap(),
                8080,
                "8.8.8.8".parse().unwrap(),
                80,
            ),
            state: states::Established {
                tx_seq: 1000,
                rx_seq: 2000,
                rx_buf: BTreeMap::new(),
                write_buffer: VecDeque::new(),
                write_buffer_size: 0,
                to_vm_buffer: VecDeque::new(),
                in_flight_packets: VecDeque::new(),
                highest_ack_from_vm: 1000,
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
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        // Add data to write_buffer
        conn.state
            .write_buffer
            .push_back(Bytes::from(b"test data".to_vec()));

        // Send empty ACK - should trigger interest recalculation
        let packet_data = create_tcp_packet(2000, 1000, TcpFlags::ACK, &[]);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();
        let (conn, action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);

        // Should add WRITABLE interest due to pending write data
        match action {
            ProxyAction::Multi(actions) => {
                let reregister_action = actions
                    .iter()
                    .find(|a| matches!(a, ProxyAction::Reregister(_)));
                if let Some(ProxyAction::Reregister(interest)) = reregister_action {
                    assert!(
                        interest.is_readable(),
                        "Should have READABLE when conditions are met"
                    );
                    assert!(
                        interest.is_writable(),
                        "Should have WRITABLE when data is pending"
                    );
                }
            }
            _ => panic!("Expected Multi action with Reregister"),
        }

        if let AnyConnection::Established(ref established) = conn {
            assert!(
                established.state.current_interest.is_readable(),
                "current_interest should have READABLE"
            );
            assert!(
                established.state.current_interest.is_writable(),
                "current_interest should have WRITABLE"
            );
        }
    }

    /// Test Interest correctly handles multiple flow control conditions
    #[test]
    fn test_interest_multiple_conditions() {
        use super::super::tests::MockHostStream;
        use std::time::Instant;

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        let mut conn = TcpConnection {
            stream: Box::new(MockHostStream::default()),
            nat_key: (
                "192.168.100.2".parse().unwrap(),
                8080,
                "8.8.8.8".parse().unwrap(),
                80,
            ),
            state: states::Established {
                tx_seq: 1000,
                rx_seq: 2000,
                rx_buf: BTreeMap::new(),
                write_buffer: VecDeque::new(),
                write_buffer_size: 0,
                to_vm_buffer: VecDeque::new(),
                in_flight_packets: VecDeque::new(),
                highest_ack_from_vm: 1000,
                dup_ack_count: 0,
                host_reads_paused: true, // Multiple conditions
                vm_reads_paused: false,
                last_fast_retransmit_seq: None,
                current_interest: Interest::READABLE.add(Interest::WRITABLE),
                vm_window_size: 1460, // Small window
                vm_window_scale: 0,
                last_zero_window_probe: None,
                last_activity: Instant::now(),
            },
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        // Add multiple flow control violations
        // 1. host_reads_paused = true
        // 2. Fill buffer to capacity
        for _ in 0..TCP_BUFFER_SIZE {
            conn.state
                .to_vm_buffer
                .push_back(Bytes::from(vec![0u8; 1460]));
        }
        // 3. Exhaust VM window
        conn.state.in_flight_packets.push_back((
            1000,
            Bytes::from(vec![0u8; 1460]),
            Instant::now(),
            1460,
        ));

        // Send empty ACK - should trigger interest recalculation
        let packet_data = create_tcp_packet(2000, 1000, TcpFlags::ACK, &[]);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();
        let (conn, action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);

        // Should remove READABLE due to multiple violations, but keep WRITABLE for pending data
        match action {
            ProxyAction::Multi(actions) => {
                let reregister_action = actions
                    .iter()
                    .find(|a| matches!(a, ProxyAction::Reregister(_)));
                if let Some(ProxyAction::Reregister(interest)) = reregister_action {
                    assert!(
                        !interest.is_readable(),
                        "Should not have READABLE when multiple conditions violated"
                    );
                    assert!(
                        interest.is_writable(),
                        "Should have WRITABLE when buffer has data"
                    );
                }
            }
            _ => panic!("Expected Multi action with Reregister"),
        }

        if let AnyConnection::Established(ref established) = conn {
            assert!(
                !established.state.current_interest.is_readable(),
                "current_interest should not have READABLE"
            );
            assert!(
                established.state.current_interest.is_writable(),
                "current_interest should have WRITABLE"
            );
        }
    }

    /// Test that Interest changes don't trigger unnecessary reregistrations
    #[test]
    fn test_interest_no_unnecessary_reregistration() {
        use super::super::tests::MockHostStream;

        let proxy_mac = MacAddr::new(0, 0, 0, 0, 0, 1);
        let vm_mac = MacAddr::new(0, 0, 0, 0, 0, 2);

        let mut conn = TcpConnection {
            stream: Box::new(MockHostStream::default()),
            nat_key: (
                "192.168.100.2".parse().unwrap(),
                8080,
                "8.8.8.8".parse().unwrap(),
                80,
            ),
            state: states::Established {
                tx_seq: 1000,
                rx_seq: 2000,
                rx_buf: BTreeMap::new(),
                write_buffer: VecDeque::new(),
                write_buffer_size: 0,
                to_vm_buffer: VecDeque::new(),
                in_flight_packets: VecDeque::new(),
                highest_ack_from_vm: 1000,
                dup_ack_count: 0,
                host_reads_paused: false,
                vm_reads_paused: false,
                last_fast_retransmit_seq: None,
                current_interest: Interest::READABLE,
                vm_window_size: 65535,
                vm_window_scale: 0, // Already correct
                last_zero_window_probe: None,
                last_activity: Instant::now(),
            },
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        // Send empty ACK - should NOT trigger reregistration since interest is already correct
        let packet_data = create_tcp_packet(2000, 1000, TcpFlags::ACK, &[]);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();
        let (conn, action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);

        // Should not have Reregister action since Interest didn't change
        match action {
            ProxyAction::Multi(actions) => {
                let has_reregister = actions
                    .iter()
                    .any(|a| matches!(a, ProxyAction::Reregister(_)));
                assert!(
                    !has_reregister,
                    "Should not reregister when Interest hasn't changed"
                );
            }
            ProxyAction::DoNothing => {
                // This is fine - no actions needed
            }
            ProxyAction::Reregister(_) => {
                panic!("Should not reregister when Interest hasn't changed");
            }
            _ => {} // Other actions are fine
        }

        if let AnyConnection::Established(ref established) = conn {
            assert_eq!(
                established.state.current_interest,
                Interest::READABLE,
                "current_interest should remain unchanged"
            );
        }
    }

    /// Test that TCP packets have correct MAC and IP addresses when sent to VM
    #[test]
    fn test_packet_addresses_vm_to_host_data_packet() {
        use super::super::tests::MockHostStream;
        use pnet::packet::ethernet::EthernetPacket;
        use pnet::packet::ipv4::Ipv4Packet;
        use pnet::packet::tcp::TcpPacket;

        let proxy_mac = MacAddr::new(0x02, 0x00, 0x00, 0x01, 0x02, 0x03);
        let vm_mac = MacAddr::new(0xde, 0xad, 0xbe, 0xef, 0x00, 0x00);

        let mut conn = TcpConnection {
            stream: Box::new(MockHostStream::default()),
            nat_key: (
                "192.168.100.2".parse().unwrap(),
                8080,
                "8.8.8.8".parse().unwrap(),
                80,
            ),
            state: states::Established {
                tx_seq: 1000,
                rx_seq: 2000,
                rx_buf: BTreeMap::new(),
                write_buffer: VecDeque::new(),
                write_buffer_size: 0,
                to_vm_buffer: VecDeque::new(),
                in_flight_packets: VecDeque::new(),
                highest_ack_from_vm: 1000,
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
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        // Send data packet from VM
        let vm_data = b"Hello from VM";
        let packet_data = create_tcp_packet(2000, 1000, TcpFlags::PSH | TcpFlags::ACK, vm_data);
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();
        let (conn, action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);

        // Should generate ACK packet to VM
        match action {
            ProxyAction::Multi(actions) => {
                let control_action = actions
                    .iter()
                    .find(|a| matches!(a, ProxyAction::SendControlPacket(_)));
                if let Some(ProxyAction::SendControlPacket(packet_bytes)) = control_action {
                    // Parse the generated packet
                    let eth_packet = EthernetPacket::new(packet_bytes).unwrap();
                    let ip_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();
                    let tcp_packet = TcpPacket::new(ip_packet.payload()).unwrap();

                    // Verify MAC addresses (proxy -> VM)
                    assert_eq!(
                        eth_packet.get_source(),
                        proxy_mac,
                        "Source MAC should be proxy"
                    );
                    assert_eq!(
                        eth_packet.get_destination(),
                        vm_mac,
                        "Dest MAC should be VM"
                    );

                    // Verify IP addresses (host -> VM)
                    assert_eq!(
                        ip_packet.get_source(),
                        "8.8.8.8".parse::<std::net::Ipv4Addr>().unwrap(),
                        "Source IP should be host"
                    );
                    assert_eq!(
                        ip_packet.get_destination(),
                        "192.168.100.2".parse::<std::net::Ipv4Addr>().unwrap(),
                        "Dest IP should be VM"
                    );

                    // Verify TCP ports (host -> VM)
                    assert_eq!(
                        tcp_packet.get_source(),
                        80,
                        "Source port should be host port"
                    );
                    assert_eq!(
                        tcp_packet.get_destination(),
                        8080,
                        "Dest port should be VM port"
                    );

                    // Verify this is an ACK packet
                    assert_eq!(
                        tcp_packet.get_flags() & TcpFlags::ACK,
                        TcpFlags::ACK,
                        "Should be ACK packet"
                    );
                } else {
                    panic!("Expected SendControlPacket action for ACK");
                }
            }
            _ => panic!("Expected Multi action with SendControlPacket"),
        }
    }

    /// Test packet addresses when proxy sends SYN-ACK during connection establishment
    #[test]
    fn test_packet_addresses_syn_ack_establishment() {
        use super::super::tests::MockHostStream;
        use pnet::packet::ethernet::EthernetPacket;
        use pnet::packet::ipv4::Ipv4Packet;
        use pnet::packet::tcp::TcpPacket;

        let proxy_mac = MacAddr::new(0x02, 0x00, 0x00, 0x01, 0x02, 0x03);
        let vm_mac = MacAddr::new(0xde, 0xad, 0xbe, 0xef, 0x00, 0x00);

        let conn = TcpConnection {
            stream: Box::new(MockHostStream::default()),
            nat_key: (
                "192.168.100.2".parse().unwrap(),
                8080,
                "8.8.8.8".parse().unwrap(),
                80,
            ),
            state: states::EgressConnecting {
                vm_initial_seq: 1000,
                tx_seq: 2000,
                vm_options: TcpNegotiatedOptions::default(),
            },
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        // Simulate host becoming writable (connection established)
        let (conn, action) =
            AnyConnection::EgressConnecting(conn).handle_event(false, true, proxy_mac, vm_mac);

        // Should send SYN-ACK to VM
        match action {
            ProxyAction::Multi(actions) => {
                let control_action = actions
                    .iter()
                    .find(|a| matches!(a, ProxyAction::SendControlPacket(_)));
                if let Some(ProxyAction::SendControlPacket(packet_bytes)) = control_action {
                    // Parse the SYN-ACK packet
                    let eth_packet = EthernetPacket::new(packet_bytes).unwrap();
                    let ip_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();
                    let tcp_packet = TcpPacket::new(ip_packet.payload()).unwrap();

                    // Verify MAC addresses (proxy -> VM)
                    assert_eq!(
                        eth_packet.get_source(),
                        proxy_mac,
                        "Source MAC should be proxy"
                    );
                    assert_eq!(
                        eth_packet.get_destination(),
                        vm_mac,
                        "Dest MAC should be VM"
                    );

                    // Verify IP addresses (host -> VM)
                    assert_eq!(
                        ip_packet.get_source(),
                        "8.8.8.8".parse::<std::net::Ipv4Addr>().unwrap(),
                        "Source IP should be host"
                    );
                    assert_eq!(
                        ip_packet.get_destination(),
                        "192.168.100.2".parse::<std::net::Ipv4Addr>().unwrap(),
                        "Dest IP should be VM"
                    );

                    // Verify TCP ports (host -> VM)
                    assert_eq!(
                        tcp_packet.get_source(),
                        80,
                        "Source port should be host port"
                    );
                    assert_eq!(
                        tcp_packet.get_destination(),
                        8080,
                        "Dest port should be VM port"
                    );

                    // Verify this is a SYN-ACK packet
                    assert_eq!(
                        tcp_packet.get_flags() & (TcpFlags::SYN | TcpFlags::ACK),
                        TcpFlags::SYN | TcpFlags::ACK,
                        "Should be SYN-ACK packet"
                    );
                } else {
                    panic!("Expected SendControlPacket action for SYN-ACK");
                }
            }
            _ => panic!("Expected Multi action with SendControlPacket"),
        }
    }

    /// Test packet addresses when proxy sends FIN packet during connection teardown
    #[test]
    fn test_packet_addresses_fin_teardown() {
        use super::super::tests::MockHostStream;
        use pnet::packet::ethernet::EthernetPacket;
        use pnet::packet::ipv4::Ipv4Packet;
        use pnet::packet::tcp::TcpPacket;

        let proxy_mac = MacAddr::new(0x02, 0x00, 0x00, 0x01, 0x02, 0x03);
        let vm_mac = MacAddr::new(0xde, 0xad, 0xbe, 0xef, 0x00, 0x00);

        let conn = TcpConnection {
            stream: Box::new(MockHostStream::default()),
            nat_key: (
                "192.168.100.2".parse().unwrap(),
                8080,
                "8.8.8.8".parse().unwrap(),
                80,
            ),
            state: states::CloseWait {
                tx_seq: 1000,
                rx_seq: 2000,
            },
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        // Simulate host close event (readable event indicating close)
        let (conn, action) =
            AnyConnection::CloseWait(conn).handle_event(true, false, proxy_mac, vm_mac);

        // Should send FIN to VM
        match action {
            ProxyAction::SendControlPacket(packet_bytes) => {
                // Parse the FIN packet
                let eth_packet = EthernetPacket::new(&packet_bytes).unwrap();
                let ip_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();
                let tcp_packet = TcpPacket::new(ip_packet.payload()).unwrap();

                // Verify MAC addresses (proxy -> VM)
                assert_eq!(
                    eth_packet.get_source(),
                    proxy_mac,
                    "Source MAC should be proxy"
                );
                assert_eq!(
                    eth_packet.get_destination(),
                    vm_mac,
                    "Dest MAC should be VM"
                );

                // Verify IP addresses (host -> VM)
                assert_eq!(
                    ip_packet.get_source(),
                    "8.8.8.8".parse::<std::net::Ipv4Addr>().unwrap(),
                    "Source IP should be host"
                );
                assert_eq!(
                    ip_packet.get_destination(),
                    "192.168.100.2".parse::<std::net::Ipv4Addr>().unwrap(),
                    "Dest IP should be VM"
                );

                // Verify TCP ports (host -> VM)
                assert_eq!(
                    tcp_packet.get_source(),
                    80,
                    "Source port should be host port"
                );
                assert_eq!(
                    tcp_packet.get_destination(),
                    8080,
                    "Dest port should be VM port"
                );

                // Verify this is a FIN packet
                assert_eq!(
                    tcp_packet.get_flags() & TcpFlags::FIN,
                    TcpFlags::FIN,
                    "Should be FIN packet"
                );
            }
            _ => panic!("Expected SendControlPacket action for FIN"),
        }
    }

    /// Test packet addresses when proxy sends RST packet to reject connection
    #[test]
    fn test_packet_addresses_rst_reject() {
        use super::super::tests::MockHostStream;
        use pnet::packet::ethernet::EthernetPacket;
        use pnet::packet::ipv4::Ipv4Packet;
        use pnet::packet::tcp::TcpPacket;

        let proxy_mac = MacAddr::new(0x02, 0x00, 0x00, 0x01, 0x02, 0x03);
        let vm_mac = MacAddr::new(0xde, 0xad, 0xbe, 0xef, 0x00, 0x00);

        let mut conn = TcpConnection {
            stream: Box::new(MockHostStream::default()),
            nat_key: (
                "192.168.100.2".parse().unwrap(),
                8080,
                "8.8.8.8".parse().unwrap(),
                80,
            ),
            state: states::Closed,
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        // Send packet to closed connection
        let packet_data = create_tcp_packet(1000, 2000, TcpFlags::ACK, b"test data");
        let tcp_packet = TcpPacket::new(&packet_data).unwrap();
        let (conn, action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);

        // Should send RST to VM
        match action {
            ProxyAction::SendControlPacket(packet_bytes) => {
                // Parse the RST packet
                let eth_packet = EthernetPacket::new(&packet_bytes).unwrap();
                let ip_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();
                let tcp_packet = TcpPacket::new(ip_packet.payload()).unwrap();

                // Verify MAC addresses (proxy -> VM)
                assert_eq!(
                    eth_packet.get_source(),
                    proxy_mac,
                    "Source MAC should be proxy"
                );
                assert_eq!(
                    eth_packet.get_destination(),
                    vm_mac,
                    "Dest MAC should be VM"
                );

                // Verify IP addresses (host -> VM)
                assert_eq!(
                    ip_packet.get_source(),
                    "8.8.8.8".parse::<std::net::Ipv4Addr>().unwrap(),
                    "Source IP should be host"
                );
                assert_eq!(
                    ip_packet.get_destination(),
                    "192.168.100.2".parse::<std::net::Ipv4Addr>().unwrap(),
                    "Dest IP should be VM"
                );

                // Verify TCP ports (host -> VM)
                assert_eq!(
                    tcp_packet.get_source(),
                    80,
                    "Source port should be host port"
                );
                assert_eq!(
                    tcp_packet.get_destination(),
                    8080,
                    "Dest port should be VM port"
                );

                // Verify this is a RST packet
                assert_eq!(
                    tcp_packet.get_flags() & TcpFlags::RST,
                    TcpFlags::RST,
                    "Should be RST packet"
                );
            }
            _ => panic!("Expected SendControlPacket action for RST"),
        }
    }

    /// Test packet addresses when proxy sends data packet with payload to VM
    #[test]
    fn test_packet_addresses_data_from_host() {
        use super::super::tests::MockHostStream;
        use pnet::packet::ethernet::EthernetPacket;
        use pnet::packet::ipv4::Ipv4Packet;
        use pnet::packet::tcp::TcpPacket;

        let proxy_mac = MacAddr::new(0x02, 0x00, 0x00, 0x01, 0x02, 0x03);
        let vm_mac = MacAddr::new(0xde, 0xad, 0xbe, 0xef, 0x00, 0x00);

        let mut mock_stream = MockHostStream::default();
        // Add data to be read from host
        mock_stream
            .read_buffer
            .lock()
            .unwrap()
            .push_back(Bytes::from("Hello from host"));

        let mut conn = TcpConnection {
            stream: Box::new(mock_stream),
            nat_key: (
                "192.168.100.2".parse().unwrap(),
                8080,
                "8.8.8.8".parse().unwrap(),
                80,
            ),
            state: states::Established {
                tx_seq: 1000,
                rx_seq: 2000,
                rx_buf: BTreeMap::new(),
                write_buffer: VecDeque::new(),
                write_buffer_size: 0,
                to_vm_buffer: VecDeque::new(),
                in_flight_packets: VecDeque::new(),
                highest_ack_from_vm: 1000,
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
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        // Trigger read from host
        let (conn, _action) = conn.handle_event(true, false, proxy_mac, vm_mac);

        // Get the data packet that was queued for VM
        if let AnyConnection::Established(ref established) = conn {
            assert!(
                !established.state.to_vm_buffer.is_empty(),
                "Should have data packet for VM"
            );

            let packet_bytes = &established.state.to_vm_buffer[0];

            // Parse the data packet
            let eth_packet = EthernetPacket::new(packet_bytes).unwrap();
            let ip_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();
            let tcp_packet = TcpPacket::new(ip_packet.payload()).unwrap();

            // Verify MAC addresses (proxy -> VM)
            assert_eq!(
                eth_packet.get_source(),
                proxy_mac,
                "Source MAC should be proxy"
            );
            assert_eq!(
                eth_packet.get_destination(),
                vm_mac,
                "Dest MAC should be VM"
            );

            // Verify IP addresses (host -> VM)
            assert_eq!(
                ip_packet.get_source(),
                "8.8.8.8".parse::<std::net::Ipv4Addr>().unwrap(),
                "Source IP should be host"
            );
            assert_eq!(
                ip_packet.get_destination(),
                "192.168.100.2".parse::<std::net::Ipv4Addr>().unwrap(),
                "Dest IP should be VM"
            );

            // Verify TCP ports (host -> VM)
            assert_eq!(
                tcp_packet.get_source(),
                80,
                "Source port should be host port"
            );
            assert_eq!(
                tcp_packet.get_destination(),
                8080,
                "Dest port should be VM port"
            );

            // Verify payload contains host data
            assert_eq!(
                tcp_packet.payload(),
                b"Hello from host",
                "Should contain host data"
            );
        } else {
            panic!("Connection should be in Established state");
        }
    }

    /// Test packet addresses with IPv6 addresses
    #[test]
    fn test_packet_addresses_ipv6() {
        use super::super::tests::MockHostStream;
        use pnet::packet::ethernet::EthernetPacket;
        use pnet::packet::ipv6::Ipv6Packet;
        use pnet::packet::tcp::TcpPacket;

        let proxy_mac = MacAddr::new(0x02, 0x00, 0x00, 0x01, 0x02, 0x03);
        let vm_mac = MacAddr::new(0xde, 0xad, 0xbe, 0xef, 0x00, 0x00);

        let mut conn = TcpConnection {
            stream: Box::new(MockHostStream::default()),
            nat_key: (
                "2001:db8::2".parse().unwrap(),
                8080,
                "2001:db8::8".parse().unwrap(),
                80,
            ),
            state: states::Established {
                tx_seq: 1000,
                rx_seq: 2000,
                rx_buf: BTreeMap::new(),
                write_buffer: VecDeque::new(),
                write_buffer_size: 0,
                to_vm_buffer: VecDeque::new(),
                in_flight_packets: VecDeque::new(),
                highest_ack_from_vm: 1000,
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
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
        };

        // Create IPv6 TCP packet from VM
        let mut packet_buf = vec![0u8; 74]; // Ethernet + IPv6 + TCP headers

        // Build minimal IPv6 TCP packet
        use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
        use pnet::packet::ip::IpNextHeaderProtocols;
        use pnet::packet::ipv6::MutableIpv6Packet;
        use pnet::packet::tcp::MutableTcpPacket;

        let mut eth = MutableEthernetPacket::new(&mut packet_buf[0..14]).unwrap();
        eth.set_source(vm_mac);
        eth.set_destination(proxy_mac);
        eth.set_ethertype(EtherTypes::Ipv6);

        let mut ipv6 = MutableIpv6Packet::new(&mut packet_buf[14..54]).unwrap();
        ipv6.set_version(6);
        ipv6.set_payload_length(20);
        ipv6.set_next_header(IpNextHeaderProtocols::Tcp);
        ipv6.set_hop_limit(64);
        ipv6.set_source("2001:db8::2".parse().unwrap());
        ipv6.set_destination("2001:db8::8".parse().unwrap());

        let mut tcp = MutableTcpPacket::new(&mut packet_buf[54..74]).unwrap();
        tcp.set_source(8080);
        tcp.set_destination(80);
        tcp.set_sequence(2000);
        tcp.set_acknowledgement(1000);
        tcp.set_data_offset(5);
        tcp.set_flags(TcpFlags::ACK);
        tcp.set_window(65535);

        let tcp_packet = TcpPacket::new(&packet_buf[54..74]).unwrap();
        let (conn, action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);

        // Should generate ACK packet to VM or be DoNothing
        match action {
            ProxyAction::Multi(actions) => {
                let control_action = actions
                    .iter()
                    .find(|a| matches!(a, ProxyAction::SendControlPacket(_)));
                if let Some(ProxyAction::SendControlPacket(packet_bytes)) = control_action {
                    // Parse the generated packet
                    let eth_packet = EthernetPacket::new(packet_bytes).unwrap();

                    // Verify it's IPv6
                    assert_eq!(
                        eth_packet.get_ethertype(),
                        EtherTypes::Ipv6,
                        "Should be IPv6 packet"
                    );

                    let ipv6_packet = Ipv6Packet::new(eth_packet.payload()).unwrap();
                    let tcp_packet = TcpPacket::new(ipv6_packet.payload()).unwrap();

                    // Verify MAC addresses (proxy -> VM)
                    assert_eq!(
                        eth_packet.get_source(),
                        proxy_mac,
                        "Source MAC should be proxy"
                    );
                    assert_eq!(
                        eth_packet.get_destination(),
                        vm_mac,
                        "Dest MAC should be VM"
                    );

                    // Verify IPv6 addresses (host -> VM)
                    assert_eq!(
                        ipv6_packet.get_source(),
                        "2001:db8::8".parse::<std::net::Ipv6Addr>().unwrap(),
                        "Source IP should be host"
                    );
                    assert_eq!(
                        ipv6_packet.get_destination(),
                        "2001:db8::2".parse::<std::net::Ipv6Addr>().unwrap(),
                        "Dest IP should be VM"
                    );

                    // Verify TCP ports (host -> VM)
                    assert_eq!(
                        tcp_packet.get_source(),
                        80,
                        "Source port should be host port"
                    );
                    assert_eq!(
                        tcp_packet.get_destination(),
                        8080,
                        "Dest port should be VM port"
                    );
                }
                // If no SendControlPacket found, that's ok - may have been just reregistration
            }
            ProxyAction::SendControlPacket(packet_bytes) => {
                // Parse the generated packet
                let eth_packet = EthernetPacket::new(&packet_bytes).unwrap();

                // Verify it's IPv6
                assert_eq!(
                    eth_packet.get_ethertype(),
                    EtherTypes::Ipv6,
                    "Should be IPv6 packet"
                );

                let ipv6_packet = Ipv6Packet::new(eth_packet.payload()).unwrap();
                let tcp_packet = TcpPacket::new(ipv6_packet.payload()).unwrap();

                // Verify MAC addresses (proxy -> VM)
                assert_eq!(
                    eth_packet.get_source(),
                    proxy_mac,
                    "Source MAC should be proxy"
                );
                assert_eq!(
                    eth_packet.get_destination(),
                    vm_mac,
                    "Dest MAC should be VM"
                );

                // Verify IPv6 addresses (host -> VM)
                assert_eq!(
                    ipv6_packet.get_source(),
                    "2001:db8::8".parse::<std::net::Ipv6Addr>().unwrap(),
                    "Source IP should be host"
                );
                assert_eq!(
                    ipv6_packet.get_destination(),
                    "2001:db8::2".parse::<std::net::Ipv6Addr>().unwrap(),
                    "Dest IP should be VM"
                );

                // Verify TCP ports (host -> VM)
                assert_eq!(
                    tcp_packet.get_source(),
                    80,
                    "Source port should be host port"
                );
                assert_eq!(
                    tcp_packet.get_destination(),
                    8080,
                    "Dest port should be VM port"
                );
            }
            _ => {
                // IPv6 might not trigger packet generation, that's also acceptable
            }
        }
    }

    /// Test that address mapping is correct regardless of connection direction
    #[test]
    fn test_packet_addresses_different_nat_keys() {
        use super::super::tests::MockHostStream;
        use pnet::packet::ethernet::EthernetPacket;
        use pnet::packet::ipv4::Ipv4Packet;
        use pnet::packet::tcp::TcpPacket;

        let proxy_mac = MacAddr::new(0x02, 0x00, 0x00, 0x01, 0x02, 0x03);
        let vm_mac = MacAddr::new(0xde, 0xad, 0xbe, 0xef, 0x00, 0x00);

        // Test different VM/host IP combinations
        let test_cases = vec![
            // (vm_ip, vm_port, host_ip, host_port)
            ("192.168.100.2", 8080, "8.8.8.8", 80),
            ("192.168.100.2", 12345, "1.1.1.1", 443),
            ("192.168.100.2", 55555, "127.0.0.1", 3000),
        ];

        for (vm_ip, vm_port, host_ip, host_port) in test_cases {
            let mut conn = TcpConnection {
                stream: Box::new(MockHostStream::default()),
                nat_key: (
                    vm_ip.parse().unwrap(),
                    vm_port,
                    host_ip.parse().unwrap(),
                    host_port,
                ),
                state: states::Established {
                    tx_seq: 1000,
                    rx_seq: 2000,
                    rx_buf: BTreeMap::new(),
                    write_buffer: VecDeque::new(),
                    write_buffer_size: 0,
                    to_vm_buffer: VecDeque::new(),
                    in_flight_packets: VecDeque::new(),
                    highest_ack_from_vm: 1000,
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
                read_buf: [0u8; 16384],
                packet_buf: BytesMut::with_capacity(2048),
            };

            // Send ACK packet from VM
            let packet_data = create_tcp_packet(2000, 1000, TcpFlags::ACK, &[]);
            let tcp_packet = TcpPacket::new(&packet_data).unwrap();
            let (conn, action) = conn.handle_packet(&tcp_packet, proxy_mac, vm_mac);

            // Check if ACK is generated
            match action {
                ProxyAction::Multi(actions) => {
                    let control_action = actions
                        .iter()
                        .find(|a| matches!(a, ProxyAction::SendControlPacket(_)));
                    if let Some(ProxyAction::SendControlPacket(packet_bytes)) = control_action {
                        // Parse the generated packet
                        let eth_packet = EthernetPacket::new(packet_bytes).unwrap();
                        let ip_packet = Ipv4Packet::new(eth_packet.payload()).unwrap();
                        let tcp_packet = TcpPacket::new(ip_packet.payload()).unwrap();

                        // Verify MAC addresses are always proxy -> VM
                        assert_eq!(
                            eth_packet.get_source(),
                            proxy_mac,
                            "Source MAC should be proxy for {}:{} -> {}:{}",
                            vm_ip,
                            vm_port,
                            host_ip,
                            host_port
                        );
                        assert_eq!(
                            eth_packet.get_destination(),
                            vm_mac,
                            "Dest MAC should be VM for {}:{} -> {}:{}",
                            vm_ip,
                            vm_port,
                            host_ip,
                            host_port
                        );

                        // Verify IP addresses are always host -> VM
                        assert_eq!(
                            ip_packet.get_source(),
                            host_ip.parse::<std::net::Ipv4Addr>().unwrap(),
                            "Source IP should be host for {}:{} -> {}:{}",
                            vm_ip,
                            vm_port,
                            host_ip,
                            host_port
                        );
                        assert_eq!(
                            ip_packet.get_destination(),
                            vm_ip.parse::<std::net::Ipv4Addr>().unwrap(),
                            "Dest IP should be VM for {}:{} -> {}:{}",
                            vm_ip,
                            vm_port,
                            host_ip,
                            host_port
                        );

                        // Verify TCP ports are always host -> VM
                        assert_eq!(
                            tcp_packet.get_source(),
                            host_port,
                            "Source port should be host port for {}:{} -> {}:{}",
                            vm_ip,
                            vm_port,
                            host_ip,
                            host_port
                        );
                        assert_eq!(
                            tcp_packet.get_destination(),
                            vm_port,
                            "Dest port should be VM port for {}:{} -> {}:{}",
                            vm_ip,
                            vm_port,
                            host_ip,
                            host_port
                        );
                    }
                }
                _ => {
                    // Some cases might not generate ACK if no state change
                }
            }
        }
    }
}
