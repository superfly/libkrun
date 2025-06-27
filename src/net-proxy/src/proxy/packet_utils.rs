use bytes::{Bytes, BytesMut};
use pnet::packet::arp::{ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{self, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::udp::{self, MutableUdpPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::trace;

use crate::proxy::CHECKSUM;

use super::tcp_fsm::NatKey;

// --- Generic IP Packet Abstraction ---
pub enum IpPacket<'p> {
    V4(Ipv4Packet<'p>),
    V6(Ipv6Packet<'p>),
}

impl<'p> IpPacket<'p> {
    pub fn new(ip_payload: &'p [u8]) -> Option<Self> {
        if ip_payload.is_empty() {
            return None;
        }
        match ip_payload[0] >> 4 {
            4 => Ipv4Packet::new(ip_payload).map(IpPacket::V4),
            6 => Ipv6Packet::new(ip_payload).map(IpPacket::V6),
            _ => None,
        }
    }
    pub fn source(&self) -> IpAddr {
        match self {
            IpPacket::V4(p) => p.get_source().into(),
            IpPacket::V6(p) => p.get_source().into(),
        }
    }
    pub fn destination(&self) -> IpAddr {
        match self {
            IpPacket::V4(p) => p.get_destination().into(),
            IpPacket::V6(p) => p.get_destination().into(),
        }
    }
    pub fn next_header(&self) -> IpNextHeaderProtocol {
        match self {
            IpPacket::V4(p) => p.get_next_level_protocol(),
            IpPacket::V6(p) => p.get_next_header(),
        }
    }
    pub fn payload(&self) -> &[u8] {
        match self {
            IpPacket::V4(p) => p.payload(),
            IpPacket::V6(p) => p.payload(),
        }
    }
}

// --- Packet Building Logic ---

pub fn build_arp_reply(
    packet_buf: &mut BytesMut,
    request: &ArpPacket,
    proxy_mac: MacAddr,
    _vm_mac: MacAddr,
    proxy_ip: Ipv4Addr,
) -> Bytes {
    let total_len = 14 + 28;
    packet_buf.clear();
    packet_buf.resize(total_len, 0);

    let (eth_slice, arp_slice) = packet_buf.split_at_mut(14);

    let mut eth_frame = MutableEthernetPacket::new(eth_slice).unwrap();
    eth_frame.set_destination(request.get_sender_hw_addr());
    eth_frame.set_source(proxy_mac);
    eth_frame.set_ethertype(EtherTypes::Arp);

    let mut arp_reply = MutableArpPacket::new(arp_slice).unwrap();
    arp_reply.clone_from(request);
    arp_reply.set_operation(ArpOperations::Reply);
    arp_reply.set_sender_hw_addr(proxy_mac);
    arp_reply.set_sender_proto_addr(proxy_ip);
    arp_reply.set_target_hw_addr(request.get_sender_hw_addr());
    arp_reply.set_target_proto_addr(request.get_sender_proto_addr());

    packet_buf.split_to(total_len).freeze()
}

pub fn build_tcp_packet(
    packet_buf: &mut BytesMut,
    nat_key: NatKey,
    tx_seq: u32,
    rx_seq: u32,
    payload: Option<&[u8]>,
    flags: Option<u8>,
    src_mac: MacAddr,
    dst_mac: MacAddr,
) -> Bytes {
    let (key_src_ip, key_src_port, key_dst_ip, key_dst_port) = nat_key;

    let packet = match (key_src_ip, key_dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => build_ipv4_tcp_packet(
            packet_buf,
            src,
            dst,
            key_src_port,
            key_dst_port,
            tx_seq,
            rx_seq,
            payload,
            flags,
            src_mac,
            dst_mac,
        ),
        (IpAddr::V6(src), IpAddr::V6(dst)) => build_ipv6_tcp_packet(
            packet_buf,
            src,
            dst,
            key_src_port,
            key_dst_port,
            tx_seq,
            rx_seq,
            payload,
            flags,
            src_mac,
            dst_mac,
        ),
        _ => return Bytes::new(),
    };
    packet
}

fn build_ipv4_tcp_packet(
    packet_buf: &mut BytesMut,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    tx_seq: u32,
    rx_seq: u32,
    payload: Option<&[u8]>,
    flags: Option<u8>,
    src_mac: MacAddr,
    dst_mac: MacAddr,
) -> Bytes {
    let payload_data = payload.unwrap_or(&[]);
    let tcp_header_len = 20;
    let ip_header_len = 20;
    let eth_header_len = 14;

    let total_len = eth_header_len + ip_header_len + tcp_header_len + payload_data.len();
    packet_buf.clear();
    packet_buf.resize(total_len, 0);

    let (eth_slice, remaining) = packet_buf.split_at_mut(eth_header_len);
    let (ip_slice, tcp_slice) = remaining.split_at_mut(ip_header_len);

    let mut eth = MutableEthernetPacket::new(eth_slice).unwrap();
    eth.set_destination(dst_mac);
    eth.set_source(src_mac);
    eth.set_ethertype(EtherTypes::Ipv4);

    let mut ip = MutableIpv4Packet::new(ip_slice).unwrap();
    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_total_length((ip_header_len + tcp_header_len + payload_data.len()) as u16);
    ip.set_ttl(64);
    ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip.set_source(src_ip);
    ip.set_destination(dst_ip);

    let mut tcp = MutableTcpPacket::new(tcp_slice).unwrap();
    tcp.set_source(src_port);
    tcp.set_destination(dst_port);
    tcp.set_sequence(tx_seq);
    tcp.set_acknowledgement(rx_seq);
    tcp.set_data_offset(5);
    tcp.set_window(u16::MAX);
    if let Some(f) = flags {
        tcp.set_flags(f);
    }
    tcp.set_payload(payload_data);
    let checksum = tcp::ipv4_checksum(&tcp.to_immutable(), &src_ip, &dst_ip);
    tcp.set_checksum(checksum);

    // Calculate and set IP checksum
    let ip_checksum = ipv4::checksum(&ip.to_immutable());
    ip.set_checksum(ip_checksum);

    packet_buf.split_to(total_len).freeze()
}

fn build_ipv6_tcp_packet(
    packet_buf: &mut BytesMut,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    tx_seq: u32,
    rx_seq: u32,
    payload: Option<&[u8]>,
    flags: Option<u8>,
    src_mac: MacAddr,
    dst_mac: MacAddr,
) -> Bytes {
    let payload_data = payload.unwrap_or(&[]);
    let tcp_header_len = 20;
    let ip_header_len = 40; // IPv6 header is 40 bytes
    let eth_header_len = 14;

    let total_len = eth_header_len + ip_header_len + tcp_header_len + payload_data.len();
    packet_buf.clear();
    packet_buf.resize(total_len, 0);

    let (eth_slice, remaining) = packet_buf.split_at_mut(eth_header_len);
    let (ip_slice, tcp_slice) = remaining.split_at_mut(ip_header_len);

    let mut eth = MutableEthernetPacket::new(eth_slice).unwrap();
    eth.set_destination(dst_mac);
    eth.set_source(src_mac);
    eth.set_ethertype(EtherTypes::Ipv6);

    let mut ip = MutableIpv6Packet::new(ip_slice).unwrap();
    ip.set_version(6);
    ip.set_traffic_class(0);
    ip.set_flow_label(0);
    ip.set_payload_length((tcp_header_len + payload_data.len()) as u16);
    ip.set_next_header(IpNextHeaderProtocols::Tcp);
    ip.set_hop_limit(64);
    ip.set_source(src_ip);
    ip.set_destination(dst_ip);

    let mut tcp = MutableTcpPacket::new(tcp_slice).unwrap();
    tcp.set_source(src_port);
    tcp.set_destination(dst_port);
    tcp.set_sequence(tx_seq);
    tcp.set_acknowledgement(rx_seq);
    tcp.set_data_offset(5);
    tcp.set_window(u16::MAX);
    if let Some(f) = flags {
        tcp.set_flags(f);
    }
    tcp.set_payload(payload_data);

    // Use the ipv6_checksum function for TCP
    let checksum = tcp::ipv6_checksum(&tcp.to_immutable(), &src_ip, &dst_ip);
    tcp.set_checksum(checksum);

    packet_buf.split_to(total_len).freeze()
}

pub fn build_udp_packet(
    packet_buf: &mut BytesMut,
    nat_key: NatKey,
    payload: &[u8],
    src_mac: MacAddr,
    dst_mac: MacAddr,
) -> Bytes {
    let (key_src_ip, key_src_port, key_dst_ip, key_dst_port) = nat_key;
    // For UDP, we are always building a reply packet from the host to the VM
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
            src_mac,
            dst_mac,
        ),
        (IpAddr::V6(src), IpAddr::V6(dst)) => build_ipv6_udp_packet(
            packet_buf,
            src,
            dst,
            packet_src_port,
            packet_dst_port,
            payload,
            src_mac,
            dst_mac,
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
    src_mac: MacAddr,
    dst_mac: MacAddr,
) -> Bytes {
    let udp_header_len = 8;
    let ip_header_len = 20;
    let eth_header_len = 14;

    let total_len = eth_header_len + ip_header_len + udp_header_len + payload.len();
    packet_buf.clear();
    packet_buf.resize(total_len, 0);

    let (eth_slice, remaining) = packet_buf.split_at_mut(eth_header_len);
    let (ip_slice, udp_slice) = remaining.split_at_mut(ip_header_len);

    let mut eth = MutableEthernetPacket::new(eth_slice).unwrap();
    eth.set_destination(dst_mac);
    eth.set_source(src_mac);
    eth.set_ethertype(EtherTypes::Ipv4);

    let mut ip = MutableIpv4Packet::new(ip_slice).unwrap();
    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_total_length((ip_header_len + udp_header_len + payload.len()) as u16);
    ip.set_ttl(64);
    ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ip.set_source(src_ip);
    ip.set_destination(dst_ip);

    let mut udp = MutableUdpPacket::new(udp_slice).unwrap();
    udp.set_source(src_port);
    udp.set_destination(dst_port);
    udp.set_length((udp_header_len + payload.len()) as u16);
    udp.set_payload(payload);
    udp.set_checksum(udp::ipv4_checksum(&udp.to_immutable(), &src_ip, &dst_ip));

    let ip_checksum = ipv4::checksum(&ip.to_immutable());
    ip.set_checksum(ip_checksum);
    packet_buf.split_to(total_len).freeze()
}

fn build_ipv6_udp_packet(
    packet_buf: &mut BytesMut,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    src_mac: MacAddr,
    dst_mac: MacAddr,
) -> Bytes {
    let udp_header_len = 8;
    let ip_header_len = 40; // IPv6 header is 40 bytes
    let eth_header_len = 14;

    let total_len = eth_header_len + ip_header_len + udp_header_len + payload.len();
    packet_buf.clear();
    packet_buf.resize(total_len, 0);

    let (eth_slice, remaining) = packet_buf.split_at_mut(eth_header_len);
    let (ip_slice, udp_slice) = remaining.split_at_mut(ip_header_len);

    let mut eth = MutableEthernetPacket::new(eth_slice).unwrap();
    eth.set_destination(dst_mac);
    eth.set_source(src_mac);
    eth.set_ethertype(EtherTypes::Ipv6);

    let mut ip = MutableIpv6Packet::new(ip_slice).unwrap();
    ip.set_version(6);
    ip.set_traffic_class(0);
    ip.set_flow_label(0);
    ip.set_payload_length((udp_header_len + payload.len()) as u16);
    ip.set_next_header(IpNextHeaderProtocols::Udp);
    ip.set_hop_limit(64);
    ip.set_source(src_ip);
    ip.set_destination(dst_ip);

    let mut udp = MutableUdpPacket::new(udp_slice).unwrap();
    udp.set_source(src_port);
    udp.set_destination(dst_port);
    udp.set_length((udp_header_len + payload.len()) as u16);
    udp.set_payload(payload);

    // Use the ipv6_checksum function for UDP
    let checksum = udp::ipv6_checksum(&udp.to_immutable(), &src_ip, &dst_ip);
    udp.set_checksum(checksum);

    packet_buf.split_to(total_len).freeze()
}

// --- Packet Logging ---
pub fn log_packet(data: &[u8], direction: &str) {
    // Only do expensive packet parsing when trace logging is enabled
    if !log::log_enabled!(log::Level::Trace) {
        return;
    }
    if let Some(eth) = EthernetPacket::new(data) {
        if let Some(ip) = IpPacket::new(eth.payload()) {
            match ip.next_header() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp) = TcpPacket::new(ip.payload()) {
                        // Calculate checksum only if there is a payload
                        let payload_checksum = if !tcp.payload().is_empty() {
                            let crc = CHECKSUM.checksum(tcp.payload());
                            format!("{:08x}", crc)
                        } else {
                            "----------".to_string()
                        };

                        trace!(
                            "[{}] {} > {}: Flags [{}], seq {}, ack {}, win {}, len {}, crc32 {}",
                            direction,
                            format!("{}:{}", ip.source(), tcp.get_source()),
                            format!("{}:{}", ip.destination(), tcp.get_destination()),
                            format_tcp_flags(tcp.get_flags()),
                            tcp.get_sequence(),
                            tcp.get_acknowledgement(),
                            tcp.get_window(),
                            tcp.payload().len(),
                            payload_checksum
                        );
                    }
                }
                IpNextHeaderProtocols::Udp => {
                    use pnet::packet::udp::UdpPacket;
                    if let Some(udp) = UdpPacket::new(ip.payload()) {
                        // Calculate checksum for UDP payload
                        let payload_checksum = if !udp.payload().is_empty() {
                            let crc = CHECKSUM.checksum(udp.payload());
                            format!("{:08x}", crc)
                        } else {
                            "----------".to_string()
                        };

                        trace!(
                            "[{}] {} > {}: UDP len {}, crc32 {}",
                            direction,
                            format!("{}:{}", ip.source(), udp.get_source()),
                            format!("{}:{}", ip.destination(), udp.get_destination()),
                            udp.payload().len(),
                            payload_checksum
                        );
                    }
                }
                _ => {
                    trace!(
                        "[{}] {} > {}: Protocol {:?}",
                        direction,
                        ip.source(),
                        ip.destination(),
                        ip.next_header()
                    );
                }
            }
        }
    }
}

fn format_tcp_flags(flags: u8) -> String {
    // ... implementation unchanged ...
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
    s
}
