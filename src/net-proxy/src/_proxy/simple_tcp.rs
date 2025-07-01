use bytes::{Buf, Bytes, BytesMut};
use mio::Interest;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::time::Instant;
use tracing::{info, trace, warn};
use rand;

use super::packet_utils::build_tcp_packet;
use super::tcp_fsm::{BoxedHostStream, NatKey, ProxyAction};
use crate::proxy::CHECKSUM;

// Simple flow control - increase buffer size for large downloads to prevent stalls
pub const SIMPLE_BUFFER_SIZE: usize = 128;  // Increased to ~187KB (128 * 1460 bytes) for large downloads
const MAX_SEGMENT_SIZE: usize = 1460;

/// Dramatically simplified TCP connection that lets the host TCP stack handle:
/// - Sequence number management
/// - Retransmissions  
/// - Flow control
/// - Congestion control
/// - Reliability
///
/// We only handle:
/// - Simple buffering between host and VM
/// - Basic TCP packet construction for VM
/// - Connection state (open/closed)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SimpleConnectionState {
    Connecting,    // Waiting for host connection to establish
    Established,   // Ready for data transfer
    Closed,        // Connection closed
}

pub struct SimpleTcpConnection {
    pub stream: BoxedHostStream,
    pub nat_key: NatKey,
    pub state: SimpleConnectionState,
    
    // Simple buffers - no sequence tracking needed
    pub to_vm_buffer: VecDeque<Bytes>,     // Data from host to send to VM
    pub to_host_buffer: VecDeque<Bytes>,   // Data from VM to send to host
    
    // Minimal state tracking
    pub host_can_read: bool,  // Can we read from host?
    pub vm_can_read: bool,    // Can VM handle more data?
    pub is_closed: bool,      // Connection closed?
    
    // Simple sliding window management
    pub vm_acked_seq: u32,    // Last sequence number ACKed by VM
    pub max_inflight_bytes: usize, // Maximum bytes to send without ACK
    pub vm_window_size: u32,  // VM's advertised window size
    
    // Buffers for I/O
    pub read_buf: [u8; 16384],
    pub packet_buf: BytesMut,
    
    // Sequence numbers for handshake
    pub vm_initial_seq: u32,   // VM's initial sequence number  
    pub host_initial_seq: u32, // Our initial sequence number
    pub last_vm_seq: u32,
    pub last_host_seq: u32,
    
    // Track if sliding window just opened up
    pub window_just_opened: bool,
}

impl SimpleTcpConnection {
    pub fn new(stream: BoxedHostStream, nat_key: NatKey, vm_initial_seq: u32) -> Self {
        let host_initial_seq = rand::random::<u32>();
        Self {
            stream,
            nat_key,
            state: SimpleConnectionState::Connecting,
            to_vm_buffer: VecDeque::new(),
            to_host_buffer: VecDeque::new(),
            host_can_read: false,  // Don't read until established
            vm_can_read: true,
            is_closed: false,
            read_buf: [0u8; 16384],
            packet_buf: BytesMut::with_capacity(2048),
            vm_initial_seq,
            host_initial_seq,
            last_vm_seq: vm_initial_seq,
            last_host_seq: 0,
            vm_acked_seq: host_initial_seq,  // VM will ACK our initial seq + 1 in handshake
            max_inflight_bytes: 64 * 1024,  // 64KB window - conservative
            vm_window_size: 65535,  // Start with reasonable window assumption
            window_just_opened: false,
        }
    }
    
    /// Handle events from the host socket (readable/writable)
    pub fn handle_host_event(&mut self, is_readable: bool, is_writable: bool, proxy_mac: MacAddr, vm_mac: MacAddr) -> ProxyAction {
        trace!(?self.nat_key, is_readable, is_writable, state=?self.state, to_host_buffer_len=self.to_host_buffer.len(), "handle_host_event called");
        let mut actions = Vec::new();
        
        // Handle connection establishment
        if self.state == SimpleConnectionState::Connecting {
            if is_writable {
                // Host connection established! Send SYN-ACK to VM
                info!(?self.nat_key, "Host connection established, sending SYN-ACK to VM");
                self.state = SimpleConnectionState::Established;
                self.host_can_read = true;
                self.last_host_seq = self.host_initial_seq.wrapping_add(1);
                // VM will ACK our SYN-ACK, so set our expectation
                self.vm_acked_seq = self.host_initial_seq;
                
                let syn_ack = build_tcp_packet(
                    &mut self.packet_buf,
                    (self.nat_key.2, self.nat_key.3, self.nat_key.0, self.nat_key.1),
                    self.host_initial_seq,
                    self.vm_initial_seq.wrapping_add(1),
                    None,
                    Some(TcpFlags::SYN | TcpFlags::ACK),
                    proxy_mac,
                    vm_mac,
                );
                return ProxyAction::SendControlPacket(syn_ack);
            }
            // Still connecting, just wait
            return ProxyAction::DoNothing;
        }
        
        // Handle established connection data transfer
        if self.state == SimpleConnectionState::Established {
            trace!(?self.nat_key, is_readable, is_writable, host_can_read=self.host_can_read, vm_can_read=self.vm_can_read, to_host_buf_len=self.to_host_buffer.len(), "Processing established connection event");
            
            // Read data from host if possible and VM can handle it
            if is_readable && self.host_can_read && self.vm_can_read {
                info!(?self.nat_key, "Attempting to read from host");
                match self.read_from_host(proxy_mac, vm_mac) {
                    Ok(true) => {
                        // Successfully read data - interest will be determined at the end
                        trace!(?self.nat_key, "Successfully read data from host");
                    }
                    Ok(false) => {
                        // No data read (would block)
                        trace!(?self.nat_key, "Host read would block");
                    }
                    Err(_) => {
                        // Host closed or error
                        self.is_closed = true;
                        self.state = SimpleConnectionState::Closed;
                        actions.push(ProxyAction::ScheduleRemoval);
                    }
                }
            }
            
            // Write buffered data to host if possible
            if is_writable && !self.to_host_buffer.is_empty() {
                info!(?self.nat_key, buffer_len=self.to_host_buffer.len(), "Host is writable, attempting to write buffered data");
                self.write_to_host();
            } else if is_writable && self.to_host_buffer.is_empty() {
                trace!(?self.nat_key, "Host is writable but no data to write");
            } else if !is_writable && !self.to_host_buffer.is_empty() {
                warn!(?self.nat_key, buffer_len=self.to_host_buffer.len(), "Have data for host but socket not writable");
            }
        }
        
        // Handle writable events even when closed if we have buffered data
        if self.state == SimpleConnectionState::Closed && is_writable && !self.to_host_buffer.is_empty() {
            info!(?self.nat_key, buffer_len=self.to_host_buffer.len(), "Connection closed but still have data to write to host");
            self.write_to_host();
        }
        
        // Determine what Interest we need and always reregister
        let mut interest: Option<Interest> = None;
        
        // Only register for READABLE if we can actually read (haven't hit sliding window AND VM window is open)
        if self.host_can_read && self.vm_can_read && self.vm_window_size > 0 {
            interest = Some(interest.map_or(Interest::READABLE, |i| i.add(Interest::READABLE)));
        }
        
        // Register for WRITABLE if we have data to write to host
        if !self.to_host_buffer.is_empty() {
            interest = Some(interest.map_or(Interest::WRITABLE, |i| i.add(Interest::WRITABLE)));
        }
        
        // If we have valid interests, reregister. Otherwise, deregister properly
        if let Some(final_interest) = interest {
            info!(?self.nat_key, ?final_interest, host_can_read=self.host_can_read, vm_can_read=self.vm_can_read, vm_window=self.vm_window_size, host_buffer_len=self.to_host_buffer.len(), "Requesting host socket interest");
            actions.push(ProxyAction::Reregister(final_interest));
        } else {
            warn!(?self.nat_key, host_can_read=self.host_can_read, vm_can_read=self.vm_can_read, vm_window=self.vm_window_size, host_buffer_len=self.to_host_buffer.len(), "No valid interests, deregistering from mio");
            actions.push(ProxyAction::Deregister);
        }
        
        match actions.len() {
            0 => ProxyAction::DoNothing,
            1 => actions.into_iter().next().unwrap(),
            _ => ProxyAction::Multi(actions),
        }
    }
    
    /// Handle a packet from the VM
    pub fn handle_vm_packet(&mut self, tcp_packet: &TcpPacket, proxy_mac: MacAddr, vm_mac: MacAddr) -> ProxyAction {
        let flags = tcp_packet.get_flags();
        let payload = tcp_packet.payload();
        
        // Handle connection teardown
        if (flags & TcpFlags::FIN) != 0 {
            info!(?self.nat_key, "FIN received from VM");
            self.is_closed = true;
            self.state = SimpleConnectionState::Closed;
            return ProxyAction::ScheduleRemoval;
        }
        
        if (flags & TcpFlags::RST) != 0 {
            info!(?self.nat_key, "RST received from VM");  
            self.is_closed = true;
            self.state = SimpleConnectionState::Closed;
            return ProxyAction::ScheduleRemoval;
        }
        
        // Handle handshake completion
        if self.state == SimpleConnectionState::Established && (flags & TcpFlags::ACK) != 0 && payload.is_empty() {
            // This might be the final ACK of the 3-way handshake
            let expected_ack = self.host_initial_seq.wrapping_add(1);
            if tcp_packet.get_acknowledgement() == expected_ack {
                trace!(?self.nat_key, "Handshake completed by VM");
                self.last_vm_seq = tcp_packet.get_sequence();
                // Update VM ACK tracking with the handshake ACK
                self.vm_acked_seq = tcp_packet.get_acknowledgement();
                return ProxyAction::DoNothing;
            }
        }
        
        // Only process data packets if we're established
        if self.state != SimpleConnectionState::Established {
            // Ignore packets until connection is established
            return ProxyAction::DoNothing;
        }
        
        // Handle data packets - buffer them for the host
        if !payload.is_empty() {
            info!(?self.nat_key, len=payload.len(), seq=tcp_packet.get_sequence(), "Received data from VM, buffering for host");
            self.to_host_buffer.push_back(Bytes::copy_from_slice(payload));
            
            // Update sequence for ACK
            self.last_vm_seq = tcp_packet.get_sequence().wrapping_add(payload.len() as u32);
        }
        
        // Handle ACKs - they control flow to VM and advance our sending window
        if (flags & TcpFlags::ACK) != 0 {
            let vm_ack = tcp_packet.get_acknowledgement();
            let vm_window = tcp_packet.get_window();
            
            // Update VM's advertised window size
            self.vm_window_size = vm_window as u32;
            
            // Update what the VM has acknowledged (advance our sending window)
            if vm_ack > self.vm_acked_seq {
                let acked_bytes = vm_ack.wrapping_sub(self.vm_acked_seq);
                self.vm_acked_seq = vm_ack;
                info!(?self.nat_key, vm_ack, acked_bytes, vm_window, "VM advanced ACK window");
                
                // Check if advancing the ACK opened up space within VM's advertised window
                let current_inflight = self.last_host_seq.wrapping_sub(self.vm_acked_seq);
                let was_blocked = !self.vm_can_read;
                
                // VM window can accommodate our current inflight data
                if vm_window > 0 && current_inflight < vm_window as u32 {
                    self.vm_can_read = true;
                    if was_blocked {
                        self.window_just_opened = true;
                        trace!(?self.nat_key, vm_window, current_inflight, "VM ACK advanced and opened window, was blocked");
                    } else {
                        trace!(?self.nat_key, vm_window, current_inflight, "VM ACK advanced, window still good");
                    }
                } else {
                    self.vm_can_read = false;
                    trace!(?self.nat_key, vm_window, current_inflight, "VM ACK advanced but window still insufficient");
                }
                
                // Check if we can resume reading from host (sliding window opened up)
                if current_inflight < self.max_inflight_bytes as u32 && !self.host_can_read {
                    self.host_can_read = true;
                    self.window_just_opened = true;  // Mark that window just opened
                    trace!(?self.nat_key, current_inflight, max_window=self.max_inflight_bytes, "Sliding window opened, can read from host again");
                }
            } else if vm_ack == self.vm_acked_seq {
                // Duplicate ACK - VM is still waiting for the same data
                // Still update window size even for duplicate ACKs
                trace!(?self.nat_key, vm_ack, vm_window, "Duplicate ACK from VM");
                
                // Check if VM window significantly opened up - allow sending more data
                let current_inflight = self.last_host_seq.wrapping_sub(self.vm_acked_seq);
                trace!(?self.nat_key, vm_window, current_inflight, vm_can_read=self.vm_can_read, "Checking VM window opening");
                
                // If VM window can accommodate our current inflight data, we can send more
                if vm_window > 0 && current_inflight < vm_window as u32 {
                    let was_blocked = !self.vm_can_read;
                    self.vm_can_read = true;
                    
                    // If we were previously blocked by window, mark as opened
                    if was_blocked {
                        self.window_just_opened = true;
                        trace!(?self.nat_key, vm_window, current_inflight, "VM window opened, was blocked before");
                    } else {
                        trace!(?self.nat_key, vm_window, current_inflight, "VM window good, was not blocked");
                    }
                } else {
                    trace!(?self.nat_key, vm_window, current_inflight, "VM window condition not met, blocking");
                    self.vm_can_read = false;
                }
            } else {
                // VM ACKing older data - ignore
                trace!(?self.nat_key, vm_ack, current_ack=self.vm_acked_seq, "VM ACKing old data");
            }
        }
        
        // Send ACK back to VM if there was data
        if !payload.is_empty() {
            info!(?self.nat_key, buffer_len=self.to_host_buffer.len(), "VM packet processed, interest will be determined by caller");
            self.send_ack_to_vm(tcp_packet, proxy_mac, vm_mac)
        } else {
            ProxyAction::DoNothing
        }
    }
    
    /// Read data from host and create packets for VM
    fn read_from_host(&mut self, proxy_mac: MacAddr, vm_mac: MacAddr) -> io::Result<bool> {
        // Check if we can send more data (sliding window check)
        let inflight_bytes = self.last_host_seq.wrapping_sub(self.vm_acked_seq);
        if inflight_bytes >= self.max_inflight_bytes as u32 {
            warn!(?self.nat_key, inflight_bytes, max_window=self.max_inflight_bytes, vm_acked=self.vm_acked_seq, our_seq=self.last_host_seq, "Hit sliding window limit, pausing reads");
            self.host_can_read = false;
            return Ok(false);
        }
        
        // Check VM's advertised window - respect the VM's flow control
        if self.vm_window_size == 0 {
            warn!(?self.nat_key, vm_window=self.vm_window_size, vm_acked=self.vm_acked_seq, our_seq=self.last_host_seq, "VM advertised zero window, pausing reads");
            self.vm_can_read = false;
            return Ok(false);
        }
        
        match self.stream.read(&mut self.read_buf) {
            Ok(0) => {
                // Host closed
                info!(?self.nat_key, "Host closed connection");
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Host closed"))
            }
            Ok(n) => {
                let checksum = CHECKSUM.checksum(&self.read_buf[..n]);
                info!(?self.nat_key, bytes=n, crc32=%checksum, vm_acked=self.vm_acked_seq, our_seq=self.last_host_seq, "Read data from host, creating packets for VM");
                
                // Simple chunking into TCP packets for VM
                for chunk in self.read_buf[..n].chunks(MAX_SEGMENT_SIZE) {
                    // Stop if VM buffer is full
                    if self.to_vm_buffer.len() >= SIMPLE_BUFFER_SIZE {
                        self.vm_can_read = false;
                        warn!(?self.nat_key, "VM buffer full, will pause");
                        break;
                    }
                    
                    // Stop if adding this chunk would exceed our sliding window
                    let future_inflight = self.last_host_seq.wrapping_add(chunk.len() as u32).wrapping_sub(self.vm_acked_seq);
                    if future_inflight > self.max_inflight_bytes as u32 {
                        warn!(?self.nat_key, chunk_len=chunk.len(), future_inflight, max_window=self.max_inflight_bytes, "Would exceed sliding window, stopping");
                        self.host_can_read = false;
                        break;
                    }
                    
                    // Stop if adding this chunk would exceed VM's advertised window
                    if future_inflight > self.vm_window_size {
                        warn!(?self.nat_key, chunk_len=chunk.len(), future_inflight, vm_window=self.vm_window_size, "Would exceed VM window, stopping");
                        self.vm_can_read = false;
                        break;
                    }
                    
                    let packet = build_tcp_packet(
                        &mut self.packet_buf,
                        (self.nat_key.2, self.nat_key.3, self.nat_key.0, self.nat_key.1),
                        self.last_host_seq,
                        self.last_vm_seq,
                        Some(chunk),
                        Some(TcpFlags::PSH | TcpFlags::ACK),
                        proxy_mac,
                        vm_mac,
                    );
                    
                    self.to_vm_buffer.push_back(packet);
                    self.last_host_seq = self.last_host_seq.wrapping_add(chunk.len() as u32);
                    info!(?self.nat_key, chunk_len=chunk.len(), new_seq=self.last_host_seq, vm_acked=self.vm_acked_seq, inflight=self.last_host_seq.wrapping_sub(self.vm_acked_seq), "Created packet for VM");
                }
                
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                trace!(?self.nat_key, "Host read would block");
                Ok(false)
            }
            Err(e) => {
                warn!(?self.nat_key, error=%e, "Host read error");
                Err(e)
            }
        }
    }
    
    /// Write buffered data to host
    fn write_to_host(&mut self) {
        while let Some(data) = self.to_host_buffer.front() {
            trace!(?self.nat_key, len=data.len(), "Attempting to write data to host");
            match self.stream.write(data) {
                Ok(n) if n == data.len() => {
                    // Wrote entire chunk
                    info!(?self.nat_key, bytes_written=n, "Successfully wrote entire chunk to host");
                    self.to_host_buffer.pop_front();
                }
                Ok(n) => {
                    // Partial write - advance the buffer
                    info!(?self.nat_key, bytes_written=n, total_len=data.len(), "Partial write to host");
                    let mut remaining = self.to_host_buffer.pop_front().unwrap();
                    remaining.advance(n);
                    self.to_host_buffer.push_front(remaining);
                    break; // Socket would block
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    trace!(?self.nat_key, "Host write would block");
                    break;
                }
                Err(e) => {
                    warn!(?self.nat_key, error=%e, "Host write error");
                    break;
                }
            }
        }
        
        // If we drained the buffer, we can read from host again
        if self.to_host_buffer.is_empty() {
            info!(?self.nat_key, "Drained to_host_buffer, enabling host reads");
            self.host_can_read = true;
        }
    }
    
    /// Send an ACK packet to the VM
    fn send_ack_to_vm(&mut self, original_packet: &TcpPacket, proxy_mac: MacAddr, vm_mac: MacAddr) -> ProxyAction {
        // Simple ACK - just acknowledge what we received
        let ack_seq = original_packet.get_sequence().wrapping_add(original_packet.payload().len() as u32);
        
        let ack_packet = build_tcp_packet(
            &mut self.packet_buf,
            (self.nat_key.2, self.nat_key.3, self.nat_key.0, self.nat_key.1),
            self.last_host_seq,
            ack_seq,
            None,
            Some(TcpFlags::ACK),
            proxy_mac,
            vm_mac,
        );
        
        ProxyAction::SendControlPacket(ack_packet)
    }
    
    /// Check if we have data to send to VM
    pub fn has_data_for_vm(&self) -> bool {
        !self.to_vm_buffer.is_empty()
    }
    
    pub fn has_data_for_host(&self) -> bool {
        !self.to_host_buffer.is_empty()
    }
    
    pub fn can_read_from_host(&self) -> bool {
        self.host_can_read && self.state == SimpleConnectionState::Established
    }
    
    pub fn window_just_opened(&mut self) -> bool {
        let result = self.window_just_opened;
        self.window_just_opened = false; // Reset flag after checking
        result
    }
    
    /// Get next packet to send to VM
    pub fn get_packet_to_send_to_vm(&mut self) -> Option<Bytes> {
        let packet = self.to_vm_buffer.pop_front()?;
        
        // If buffer has space now, VM can read more
        if self.to_vm_buffer.len() < SIMPLE_BUFFER_SIZE / 2 {
            self.vm_can_read = true;
        }
        
        Some(packet)
    }
}

impl std::fmt::Debug for SimpleTcpConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimpleTcpConnection")
            .field("nat_key", &self.nat_key)
            .field("state", &self.state)
            .field("to_vm_buffer_len", &self.to_vm_buffer.len())
            .field("to_host_buffer_len", &self.to_host_buffer.len())
            .field("host_can_read", &self.host_can_read)
            .field("vm_can_read", &self.vm_can_read)
            .field("is_closed", &self.is_closed)
            .field("vm_initial_seq", &self.vm_initial_seq)
            .field("host_initial_seq", &self.host_initial_seq)
            .field("last_vm_seq", &self.last_vm_seq)
            .field("last_host_seq", &self.last_host_seq)
            .field("vm_acked_seq", &self.vm_acked_seq)
            .field("max_inflight_bytes", &self.max_inflight_bytes)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::tcp_fsm::HostStream;
    use std::sync::{Arc, Mutex};
    use std::collections::VecDeque;
    use std::net::{IpAddr, Shutdown};
    use std::any::Any;
    use mio::{Registry, Token};
    use pnet::packet::ethernet::EthernetPacket;
    use pnet::packet::ipv4::Ipv4Packet;

    /// Mock stream for testing
    #[derive(Debug, Clone)]
    struct MockHostStream {
        read_buffer: Arc<Mutex<VecDeque<Bytes>>>,
        write_buffer: Arc<Mutex<Vec<u8>>>,
        shutdown_state: Arc<Mutex<Option<Shutdown>>>,
    }

    impl MockHostStream {
        fn new() -> Self {
            Self {
                read_buffer: Arc::new(Mutex::new(VecDeque::new())),
                write_buffer: Arc::new(Mutex::new(Vec::new())),
                shutdown_state: Arc::new(Mutex::new(None)),
            }
        }

        fn add_read_data(&self, data: &[u8]) {
            self.read_buffer.lock().unwrap().push_back(Bytes::copy_from_slice(data));
        }

        fn get_written_data(&self) -> Vec<u8> {
            self.write_buffer.lock().unwrap().clone()
        }
    }

    impl std::io::Read for MockHostStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
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
                Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "would block"))
            }
        }
    }

    impl std::io::Write for MockHostStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.write_buffer.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl mio::event::Source for MockHostStream {
        fn register(&mut self, _: &Registry, _: Token, _: Interest) -> std::io::Result<()> {
            Ok(())
        }

        fn reregister(&mut self, _: &Registry, _: Token, _: Interest) -> std::io::Result<()> {
            Ok(())
        }

        fn deregister(&mut self, _: &Registry) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl HostStream for MockHostStream {
        fn shutdown(&mut self, how: Shutdown) -> std::io::Result<()> {
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

    /// Helper to create a test TCP packet
    fn create_test_tcp_packet(
        src_ip: IpAddr,
        src_port: u16, 
        dst_ip: IpAddr,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut packet_buf = BytesMut::new();
        let nat_key = (src_ip, src_port, dst_ip, dst_port);
        let packet = build_tcp_packet(
            &mut packet_buf,
            nat_key,
            seq,
            ack,
            Some(payload),
            Some(flags),
            MacAddr::new(0xde, 0xad, 0xbe, 0xef, 0x00, 0x00), // VM MAC
            MacAddr::new(0x02, 0x00, 0x00, 0x01, 0x02, 0x03), // Proxy MAC
        );
        packet.to_vec()
    }

    #[test]
    fn test_syn_ack_packet_structure() {
        let mock_stream = MockHostStream::new();
        let nat_key = (
            "192.168.100.2".parse::<IpAddr>().unwrap(),
            12345,
            "8.8.8.8".parse::<IpAddr>().unwrap(),
            443,
        );
        let vm_initial_seq = 1000;
        let mut connection = SimpleTcpConnection::new(Box::new(mock_stream), nat_key, vm_initial_seq);
        
        let proxy_mac = MacAddr::new(0x02, 0x00, 0x00, 0x01, 0x02, 0x03);
        let vm_mac = MacAddr::new(0xde, 0xad, 0xbe, 0xef, 0x00, 0x00);

        // Simulate host connection becoming writable (establishes connection)
        let action = connection.handle_host_event(false, true, proxy_mac, vm_mac);

        // Verify we get a SYN-ACK control packet
        match action {
            ProxyAction::SendControlPacket(packet) => {
                // Parse Ethernet header
                let eth = EthernetPacket::new(&packet).unwrap();
                assert_eq!(eth.get_source(), proxy_mac);
                assert_eq!(eth.get_destination(), vm_mac);
                assert_eq!(eth.get_ethertype(), pnet::packet::ethernet::EtherTypes::Ipv4);

                // Parse IP header  
                let ip = Ipv4Packet::new(eth.payload()).unwrap();
                assert_eq!(ip.get_source(), "8.8.8.8".parse::<std::net::Ipv4Addr>().unwrap());
                assert_eq!(ip.get_destination(), "192.168.100.2".parse::<std::net::Ipv4Addr>().unwrap());

                // Parse TCP header
                let tcp = TcpPacket::new(ip.payload()).unwrap();
                assert_eq!(tcp.get_source(), 443);
                assert_eq!(tcp.get_destination(), 12345);
                assert_eq!(tcp.get_flags(), TcpFlags::SYN | TcpFlags::ACK);
                assert_eq!(tcp.get_sequence(), connection.host_initial_seq);
                assert_eq!(tcp.get_acknowledgement(), vm_initial_seq + 1);
                assert_eq!(tcp.payload().len(), 0); // SYN-ACK has no payload
                
                // Verify connection state changed to Established
                assert_eq!(connection.state, SimpleConnectionState::Established);
            }
            _ => panic!("Expected SendControlPacket action, got {:?}", action),
        }
    }

    #[test]
    fn test_data_packet_sequence_numbers() {
        let mock_stream = MockHostStream::new();
        let nat_key = (
            "192.168.100.2".parse::<IpAddr>().unwrap(),
            12345,
            "8.8.8.8".parse::<IpAddr>().unwrap(),
            443,
        );
        let vm_initial_seq = 2000;
        let mut connection = SimpleTcpConnection::new(Box::new(mock_stream), nat_key, vm_initial_seq);
        
        // Establish connection first
        let proxy_mac = MacAddr::new(0x02, 0x00, 0x00, 0x01, 0x02, 0x03);
        let vm_mac = MacAddr::new(0xde, 0xad, 0xbe, 0xef, 0x00, 0x00);
        connection.handle_host_event(false, true, proxy_mac, vm_mac);
        assert_eq!(connection.state, SimpleConnectionState::Established);

        // Create a data packet from VM
        let payload = b"Hello, World!";
        let vm_packet_data = create_test_tcp_packet(
            "192.168.100.2".parse().unwrap(),
            12345,
            "8.8.8.8".parse().unwrap(), 
            443,
            vm_initial_seq + 1, // After handshake
            connection.host_initial_seq + 1,
            TcpFlags::PSH | TcpFlags::ACK,
            payload,
        );

        // Parse the packet and handle it
        let eth = EthernetPacket::new(&vm_packet_data).unwrap();
        let ip = Ipv4Packet::new(eth.payload()).unwrap();
        let tcp = TcpPacket::new(ip.payload()).unwrap();
        
        let action = connection.handle_vm_packet(&tcp, proxy_mac, vm_mac);

        // Verify we get an ACK back
        match action {
            ProxyAction::Multi(actions) => {
                let control_action = &actions[0];
                match control_action {
                    ProxyAction::SendControlPacket(ack_packet) => {
                        // Parse the ACK packet
                        let ack_eth = EthernetPacket::new(ack_packet).unwrap();
                        let ack_ip = Ipv4Packet::new(ack_eth.payload()).unwrap();
                        let ack_tcp = TcpPacket::new(ack_ip.payload()).unwrap();

                        // Verify ACK packet structure
                        assert_eq!(ack_eth.get_source(), proxy_mac);
                        assert_eq!(ack_eth.get_destination(), vm_mac);
                        assert_eq!(ack_ip.get_source(), "8.8.8.8".parse::<std::net::Ipv4Addr>().unwrap());
                        assert_eq!(ack_ip.get_destination(), "192.168.100.2".parse::<std::net::Ipv4Addr>().unwrap());
                        assert_eq!(ack_tcp.get_source(), 443);
                        assert_eq!(ack_tcp.get_destination(), 12345);
                        assert_eq!(ack_tcp.get_flags(), TcpFlags::ACK);
                        
                        // Verify sequence numbers
                        assert_eq!(ack_tcp.get_sequence(), connection.last_host_seq);
                        assert_eq!(ack_tcp.get_acknowledgement(), vm_initial_seq + 1 + payload.len() as u32);
                        assert_eq!(ack_tcp.payload().len(), 0); // ACK has no payload
                    }
                    _ => panic!("Expected SendControlPacket in multi-action"),
                }
            }
            ProxyAction::SendControlPacket(ack_packet) => {
                // Same verification as above
                let ack_eth = EthernetPacket::new(&ack_packet).unwrap();
                let ack_ip = Ipv4Packet::new(ack_eth.payload()).unwrap();
                let ack_tcp = TcpPacket::new(ack_ip.payload()).unwrap();
                
                assert_eq!(ack_tcp.get_acknowledgement(), vm_initial_seq + 1 + payload.len() as u32);
            }
            _ => panic!("Expected control packet action, got {:?}", action),
        }

        // Verify data was buffered for host
        assert_eq!(connection.to_host_buffer.len(), 1);
        let buffered_data = connection.to_host_buffer.front().unwrap();
        assert_eq!(buffered_data.as_ref(), payload);
    }

    #[test]
    fn test_host_to_vm_data_packets() {
        let mock_stream = MockHostStream::new();
        let nat_key = (
            "192.168.100.2".parse::<IpAddr>().unwrap(),
            12345,
            "8.8.8.8".parse::<IpAddr>().unwrap(),
            443,
        );
        let vm_initial_seq = 3000;
        let mut connection = SimpleTcpConnection::new(Box::new(mock_stream.clone()), nat_key, vm_initial_seq);
        
        // Establish connection
        let proxy_mac = MacAddr::new(0x02, 0x00, 0x00, 0x01, 0x02, 0x03);
        let vm_mac = MacAddr::new(0xde, 0xad, 0xbe, 0xef, 0x00, 0x00);
        connection.handle_host_event(false, true, proxy_mac, vm_mac);
        
        // Add data to mock stream
        let test_data = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest";
        mock_stream.add_read_data(test_data);
        
        // Trigger read from host
        let action = connection.handle_host_event(true, false, proxy_mac, vm_mac);
        
        // Should reregister for READABLE + WRITABLE (may be multiple actions)
        match action {
            ProxyAction::Reregister(interest) => {
                assert!(interest.is_readable());
                assert!(interest.is_writable());
            }
            ProxyAction::Multi(actions) => {
                // Should have at least one Reregister with READABLE + WRITABLE
                let has_readable_writable = actions.iter().any(|a| {
                    if let ProxyAction::Reregister(interest) = a {
                        interest.is_readable() && interest.is_writable()
                    } else {
                        false
                    }
                });
                assert!(has_readable_writable, "Expected at least one Reregister with READABLE + WRITABLE");
            }
            _ => panic!("Expected Reregister action, got {:?}", action),
        }
        
        // Check that packets were created for VM
        assert!(connection.has_data_for_vm());
        
        // Get the packet and verify its structure
        let vm_packet = connection.get_packet_to_send_to_vm().unwrap();
        let eth = EthernetPacket::new(&vm_packet).unwrap();
        let ip = Ipv4Packet::new(eth.payload()).unwrap();
        let tcp = TcpPacket::new(ip.payload()).unwrap();
        
        // Verify packet headers
        assert_eq!(eth.get_source(), proxy_mac);
        assert_eq!(eth.get_destination(), vm_mac);
        assert_eq!(ip.get_source(), "8.8.8.8".parse::<std::net::Ipv4Addr>().unwrap());
        assert_eq!(ip.get_destination(), "192.168.100.2".parse::<std::net::Ipv4Addr>().unwrap());
        assert_eq!(tcp.get_source(), 443);
        assert_eq!(tcp.get_destination(), 12345);
        assert_eq!(tcp.get_flags(), TcpFlags::PSH | TcpFlags::ACK);
        
        // Verify sequence numbers
        assert_eq!(tcp.get_sequence(), connection.host_initial_seq + 1); // After SYN-ACK
        assert_eq!(tcp.get_acknowledgement(), connection.last_vm_seq);
        
        // Verify payload
        let expected_chunk_size = std::cmp::min(test_data.len(), MAX_SEGMENT_SIZE);
        assert_eq!(tcp.payload().len(), expected_chunk_size);
        assert_eq!(tcp.payload(), &test_data[..expected_chunk_size]);
    }

    #[test] 
    fn test_vm_to_host_data_flow() {
        let mock_stream = MockHostStream::new();
        let nat_key = (
            "192.168.100.2".parse::<IpAddr>().unwrap(),
            12345,
            "8.8.8.8".parse::<IpAddr>().unwrap(),
            443,
        );
        let vm_initial_seq = 4000;
        let mut connection = SimpleTcpConnection::new(Box::new(mock_stream.clone()), nat_key, vm_initial_seq);
        
        // Establish connection
        let proxy_mac = MacAddr::new(0x02, 0x00, 0x00, 0x01, 0x02, 0x03);
        let vm_mac = MacAddr::new(0xde, 0xad, 0xbe, 0xef, 0x00, 0x00);
        connection.handle_host_event(false, true, proxy_mac, vm_mac);
        
        // Create HTTP request from VM
        let http_request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let vm_packet_data = create_test_tcp_packet(
            "192.168.100.2".parse().unwrap(),
            12345,
            "8.8.8.8".parse().unwrap(),
            443,
            vm_initial_seq + 1,
            connection.host_initial_seq + 1,
            TcpFlags::PSH | TcpFlags::ACK,
            http_request,
        );
        
        // Handle the packet
        let eth = EthernetPacket::new(&vm_packet_data).unwrap();
        let ip = Ipv4Packet::new(eth.payload()).unwrap();
        let tcp = TcpPacket::new(ip.payload()).unwrap();
        connection.handle_vm_packet(&tcp, proxy_mac, vm_mac);
        
        // Simulate host socket becoming writable
        connection.handle_host_event(false, true, proxy_mac, vm_mac);
        
        // Verify data was written to mock stream
        let written_data = mock_stream.get_written_data();
        assert_eq!(written_data, http_request);
        
        // Verify buffer was drained
        assert_eq!(connection.to_host_buffer.len(), 0);
    }

    #[test]
    fn test_mac_address_consistency() {
        let mock_stream = MockHostStream::new();
        let nat_key = (
            "192.168.100.2".parse::<IpAddr>().unwrap(),
            12345,
            "10.0.0.1".parse::<IpAddr>().unwrap(),
            80,
        );
        let vm_initial_seq = 5000;
        let mut connection = SimpleTcpConnection::new(Box::new(mock_stream), nat_key, vm_initial_seq);
        
        // Use specific MAC addresses
        let proxy_mac = MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);
        let vm_mac = MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
        
        // Test SYN-ACK packet MAC addresses
        let action = connection.handle_host_event(false, true, proxy_mac, vm_mac);
        match action {
            ProxyAction::SendControlPacket(packet) => {
                let eth = EthernetPacket::new(&packet).unwrap();
                assert_eq!(eth.get_source(), proxy_mac);
                assert_eq!(eth.get_destination(), vm_mac);
            }
            _ => panic!("Expected SendControlPacket"),
        }
        
        // Test ACK packet MAC addresses
        let payload = b"test";
        let vm_packet_data = create_test_tcp_packet(
            "192.168.100.2".parse().unwrap(),
            12345,
            "10.0.0.1".parse().unwrap(),
            80,
            vm_initial_seq + 1,
            connection.host_initial_seq + 1,
            TcpFlags::PSH | TcpFlags::ACK,
            payload,
        );
        
        let eth = EthernetPacket::new(&vm_packet_data).unwrap();
        let ip = Ipv4Packet::new(eth.payload()).unwrap();
        let tcp = TcpPacket::new(ip.payload()).unwrap();
        
        let action = connection.handle_vm_packet(&tcp, proxy_mac, vm_mac);
        match action {
            ProxyAction::Multi(actions) => {
                match &actions[0] {
                    ProxyAction::SendControlPacket(ack_packet) => {
                        let ack_eth = EthernetPacket::new(ack_packet).unwrap();
                        assert_eq!(ack_eth.get_source(), proxy_mac);
                        assert_eq!(ack_eth.get_destination(), vm_mac);
                    }
                    _ => panic!("Expected SendControlPacket in multi-action"),
                }
            }
            ProxyAction::SendControlPacket(ack_packet) => {
                let ack_eth = EthernetPacket::new(&ack_packet).unwrap();
                assert_eq!(ack_eth.get_source(), proxy_mac);
                assert_eq!(ack_eth.get_destination(), vm_mac);
            }
            _ => panic!("Expected control packet action"),
        }
    }
}