//! Protocol-specific info structs passed to handler methods.

use pnet::packet::tcp::TcpFlags;

/// TCP packet info passed to `handle_tcp`.
#[derive(Debug, Clone, Copy)]
pub struct TcpInfo<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u8,
    pub seq: u32,
    pub ack: u32,
    pub payload: &'a [u8],
}

impl TcpInfo<'_> {
    /// Check if this is a SYN packet (new connection).
    #[inline]
    pub fn is_syn(&self) -> bool {
        (self.flags & TcpFlags::SYN) != 0 && (self.flags & TcpFlags::ACK) == 0
    }
}

/// UDP packet info passed to `handle_udp`.
#[derive(Debug, Clone, Copy)]
pub struct UdpInfo<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

/// ICMP packet info passed to `handle_icmp`.
#[derive(Debug, Clone, Copy)]
pub struct IcmpInfo<'a> {
    pub icmp_type: u8,
    pub code: u8,
    pub payload: &'a [u8],
}

impl IcmpInfo<'_> {
    /// Check if this is an echo request (ping).
    #[inline]
    pub fn is_echo_request(&self) -> bool {
        self.icmp_type == 8
    }
}
