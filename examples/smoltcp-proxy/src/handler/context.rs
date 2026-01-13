//! Packet context for handler processing.

use bytes::Bytes;
use pnet::packet::tcp::TcpFlags;
use std::net::Ipv4Addr;
use tokio::sync::mpsc;

use crate::util::internet_checksum;

/// Transport protocol info parsed from the packet.
#[derive(Debug, Clone)]
pub enum TransportProtocol<'a> {
    Tcp {
        src_port: u16,
        dst_port: u16,
        flags: u8,
        seq: u32,
        ack: u32,
        payload: &'a [u8],
    },
    Udp {
        src_port: u16,
        dst_port: u16,
        payload: &'a [u8],
    },
    Icmp {
        icmp_type: u8,
        code: u8,
        payload: &'a [u8],
    },
    Other {
        protocol: u8,
    },
}

/// Parsed packet context passed to handlers.
/// Provides both parsed fields and response-building helpers.
pub struct PacketContext<'a> {
    /// Raw packet bytes
    pub raw: &'a [u8],
    /// Source MAC address
    pub src_mac: [u8; 6],
    /// Destination MAC address
    pub dst_mac: [u8; 6],
    /// Source IP address
    pub src_ip: Ipv4Addr,
    /// Destination IP address
    pub dst_ip: Ipv4Addr,
    /// Transport layer protocol and data
    pub transport: TransportProtocol<'a>,

    // Config for building responses (from proxy config)
    vm_mac: [u8; 6],
    gateway_mac: [u8; 6],

    /// Channel to send packets to guest. Clone this for async tasks.
    pub to_guest: &'a mpsc::Sender<Bytes>,
}

impl<'a> PacketContext<'a> {
    /// Parse a raw Ethernet frame into a PacketContext.
    ///
    /// All payload slices are derived from `raw` to ensure proper lifetimes.
    pub fn parse(
        raw: &'a [u8],
        vm_mac: [u8; 6],
        gateway_mac: [u8; 6],
        to_guest: &'a mpsc::Sender<Bytes>,
    ) -> Option<Self> {
        // Ethernet header is 14 bytes
        const ETH_HEADER_LEN: usize = 14;
        if raw.len() < ETH_HEADER_LEN {
            return None;
        }

        // Parse MAC addresses directly from raw bytes
        let src_mac = [raw[6], raw[7], raw[8], raw[9], raw[10], raw[11]];
        let dst_mac = [raw[0], raw[1], raw[2], raw[3], raw[4], raw[5]];

        // Check EtherType for IPv4 (0x0800)
        if raw[12] != 0x08 || raw[13] != 0x00 {
            return None;
        }

        let ip_start = ETH_HEADER_LEN;
        if raw.len() < ip_start + 20 {
            return None;
        }

        // Parse IPv4 header
        let ihl = (raw[ip_start] & 0x0F) as usize;
        let ip_header_len = ihl * 4;
        if ip_header_len < 20 || raw.len() < ip_start + ip_header_len {
            return None;
        }

        let src_ip = Ipv4Addr::new(
            raw[ip_start + 12],
            raw[ip_start + 13],
            raw[ip_start + 14],
            raw[ip_start + 15],
        );
        let dst_ip = Ipv4Addr::new(
            raw[ip_start + 16],
            raw[ip_start + 17],
            raw[ip_start + 18],
            raw[ip_start + 19],
        );
        let protocol = raw[ip_start + 9];

        let transport_start = ip_start + ip_header_len;

        let transport = match protocol {
            // TCP (protocol 6)
            6 => {
                if raw.len() < transport_start + 20 {
                    return None;
                }
                let src_port = u16::from_be_bytes([raw[transport_start], raw[transport_start + 1]]);
                let dst_port =
                    u16::from_be_bytes([raw[transport_start + 2], raw[transport_start + 3]]);
                let seq = u32::from_be_bytes([
                    raw[transport_start + 4],
                    raw[transport_start + 5],
                    raw[transport_start + 6],
                    raw[transport_start + 7],
                ]);
                let ack = u32::from_be_bytes([
                    raw[transport_start + 8],
                    raw[transport_start + 9],
                    raw[transport_start + 10],
                    raw[transport_start + 11],
                ]);
                let data_offset = ((raw[transport_start + 12] >> 4) as usize) * 4;
                let flags = raw[transport_start + 13];

                let payload_start = transport_start + data_offset;
                let payload = if payload_start <= raw.len() {
                    &raw[payload_start..]
                } else {
                    &raw[raw.len()..]
                };

                TransportProtocol::Tcp {
                    src_port,
                    dst_port,
                    flags,
                    seq,
                    ack,
                    payload,
                }
            }
            // UDP (protocol 17)
            17 => {
                if raw.len() < transport_start + 8 {
                    return None;
                }
                let src_port = u16::from_be_bytes([raw[transport_start], raw[transport_start + 1]]);
                let dst_port =
                    u16::from_be_bytes([raw[transport_start + 2], raw[transport_start + 3]]);
                let payload_start = transport_start + 8;
                let payload = &raw[payload_start..];

                TransportProtocol::Udp {
                    src_port,
                    dst_port,
                    payload,
                }
            }
            // ICMP (protocol 1)
            1 => {
                if raw.len() < transport_start + 8 {
                    return None;
                }
                let icmp_type = raw[transport_start];
                let code = raw[transport_start + 1];
                let payload_start = transport_start + 8;
                let payload = &raw[payload_start..];

                TransportProtocol::Icmp {
                    icmp_type,
                    code,
                    payload,
                }
            }
            other => TransportProtocol::Other { protocol: other },
        };

        Some(Self {
            raw,
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            transport,
            vm_mac,
            gateway_mac,
            to_guest,
        })
    }

    /// Build a UDP response packet to send back to the guest.
    /// Swaps src/dst and wraps payload in UDP/IP/Ethernet headers.
    pub fn build_udp_response(&self, payload: &[u8]) -> Bytes {
        let (src_port, dst_port) = match &self.transport {
            TransportProtocol::Udp {
                src_port, dst_port, ..
            } => (*dst_port, *src_port),
            _ => (0, 0),
        };

        // UDP header (8 bytes)
        let udp_len = 8 + payload.len();
        let mut udp_header = Vec::with_capacity(udp_len);
        udp_header.extend_from_slice(&src_port.to_be_bytes());
        udp_header.extend_from_slice(&dst_port.to_be_bytes());
        udp_header.extend_from_slice(&(udp_len as u16).to_be_bytes());
        udp_header.extend_from_slice(&[0, 0]); // Checksum (optional for IPv4)
        udp_header.extend_from_slice(payload);

        self.build_ip_response(17, &udp_header) // 17 = UDP
    }

    /// Build an ICMP echo reply packet.
    pub fn build_icmp_echo_reply(&self, id: u16, sequence: u16, data: &[u8]) -> Bytes {
        let mut icmp = Vec::with_capacity(8 + data.len());
        icmp.push(0); // Type: Echo Reply
        icmp.push(0); // Code
        icmp.extend_from_slice(&[0, 0]); // Checksum placeholder
        icmp.extend_from_slice(&id.to_be_bytes());
        icmp.extend_from_slice(&sequence.to_be_bytes());
        icmp.extend_from_slice(data);

        // Calculate checksum
        let checksum = internet_checksum(&icmp);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

        self.build_ip_response(1, &icmp) // 1 = ICMP
    }

    /// Build a TCP RST packet to reject a connection.
    pub fn build_tcp_rst(&self) -> Bytes {
        let (src_port, dst_port, their_seq, their_ack) = match &self.transport {
            TransportProtocol::Tcp {
                src_port,
                dst_port,
                seq,
                ack,
                ..
            } => (*dst_port, *src_port, *seq, *ack),
            _ => return Bytes::new(),
        };

        // TCP header (20 bytes, no options)
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        // Seq = their ack (or 0 if no ack)
        let seq = if their_ack != 0 { their_ack } else { 0 };
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        // Ack = their seq + 1
        let ack = their_seq.wrapping_add(1);
        tcp[8..12].copy_from_slice(&ack.to_be_bytes());
        tcp[12] = 5 << 4; // Data offset: 5 (20 bytes)
        tcp[13] = 0x14; // Flags: RST + ACK
        tcp[14..16].copy_from_slice(&0u16.to_be_bytes()); // Window
                                                          // Checksum calculated below
        tcp[18..20].copy_from_slice(&0u16.to_be_bytes()); // Urgent pointer

        // TCP checksum requires pseudo-header
        let checksum = self.tcp_checksum(&tcp);
        tcp[16..18].copy_from_slice(&checksum.to_be_bytes());

        self.build_ip_response(6, &tcp) // 6 = TCP
    }

    /// Build an IP response packet (helper for other builders).
    fn build_ip_response(&self, protocol: u8, payload: &[u8]) -> Bytes {
        let ip_total_len = 20 + payload.len();
        let mut ip = Vec::with_capacity(ip_total_len);

        // IPv4 header
        ip.push(0x45); // Version + IHL
        ip.push(0x00); // DSCP + ECN
        ip.extend_from_slice(&(ip_total_len as u16).to_be_bytes());
        ip.extend_from_slice(&[0x00, 0x00]); // Identification
        ip.extend_from_slice(&[0x40, 0x00]); // Flags + Fragment offset
        ip.push(64); // TTL
        ip.push(protocol);
        ip.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder
        ip.extend_from_slice(&self.dst_ip.octets()); // Src = original dst
        ip.extend_from_slice(&self.src_ip.octets()); // Dst = original src

        // Calculate IP checksum
        let checksum = internet_checksum(&ip[..20]);
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());

        // Append payload
        ip.extend_from_slice(payload);

        // Build Ethernet frame
        let mut eth = Vec::with_capacity(14 + ip.len());
        eth.extend_from_slice(&self.vm_mac); // Dst = VM
        eth.extend_from_slice(&self.gateway_mac); // Src = Gateway
        eth.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4
        eth.extend_from_slice(&ip);

        Bytes::from(eth)
    }

    /// Calculate TCP checksum with pseudo-header.
    fn tcp_checksum(&self, tcp_segment: &[u8]) -> u16 {
        let mut pseudo = Vec::with_capacity(12 + tcp_segment.len());
        pseudo.extend_from_slice(&self.dst_ip.octets()); // Src in response
        pseudo.extend_from_slice(&self.src_ip.octets()); // Dst in response
        pseudo.push(0);
        pseudo.push(6); // TCP protocol
        pseudo.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(tcp_segment);
        internet_checksum(&pseudo)
    }

    // Convenience accessors

    /// Get destination port if TCP or UDP.
    pub fn dst_port(&self) -> Option<u16> {
        match &self.transport {
            TransportProtocol::Tcp { dst_port, .. } => Some(*dst_port),
            TransportProtocol::Udp { dst_port, .. } => Some(*dst_port),
            _ => None,
        }
    }

    /// Get source port if TCP or UDP.
    pub fn src_port(&self) -> Option<u16> {
        match &self.transport {
            TransportProtocol::Tcp { src_port, .. } => Some(*src_port),
            TransportProtocol::Udp { src_port, .. } => Some(*src_port),
            _ => None,
        }
    }

    /// Check if this is a TCP SYN packet (new connection).
    pub fn is_tcp_syn(&self) -> bool {
        matches!(&self.transport, TransportProtocol::Tcp { flags, .. } if *flags == TcpFlags::SYN)
    }

    /// Check if this is an ICMP echo request.
    pub fn is_icmp_echo_request(&self) -> bool {
        matches!(
            &self.transport,
            TransportProtocol::Icmp { icmp_type: 8, .. }
        )
    }

    /// Check if this is a DNS query (UDP port 53).
    pub fn is_dns_query(&self) -> bool {
        matches!(&self.transport, TransportProtocol::Udp { dst_port: 53, .. })
    }

    /// Get UDP payload if this is a UDP packet.
    pub fn udp_payload(&self) -> Option<&[u8]> {
        match &self.transport {
            TransportProtocol::Udp { payload, .. } => Some(payload),
            _ => None,
        }
    }
}
