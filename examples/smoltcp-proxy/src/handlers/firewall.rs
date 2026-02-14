//! Firewall handler and configuration.
//!
//! Provides O(1) port-based filtering with CIDR destination rules.
//! Supports both IPv4 and IPv6 addresses.

use log::debug;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::handler::{
    HandlerResult, IcmpInfo, PacketContext, PacketHandler, PacketVerdict, TcpInfo, UdpInfo,
};

/// A CIDR block for IP filtering. Supports both IPv4 and IPv6.
///
/// An IPv4 CIDR only matches IPv4 addresses, and an IPv6 CIDR only matches IPv6 addresses.
#[derive(Clone, Copy, Debug)]
pub enum Cidr {
    /// IPv4 CIDR (e.g., 10.0.0.0/8)
    V4 {
        network: u32,
        mask: u32,
        #[allow(dead_code)]
        prefix_len: u8,
    },
    /// IPv6 CIDR (e.g., 2001:db8::/32)
    V6 {
        network: u128,
        mask: u128,
        #[allow(dead_code)]
        prefix_len: u8,
    },
}

impl Cidr {
    /// Create an IPv4 CIDR from octets and prefix length.
    /// Example: `Cidr::v4([10, 0, 0, 0], 8)` for 10.0.0.0/8
    pub fn v4(ip: [u8; 4], prefix_len: u8) -> Self {
        let prefix_len = prefix_len.min(32);
        let mask = if prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - prefix_len)
        };
        let network = u32::from_be_bytes(ip) & mask;
        Self::V4 {
            network,
            mask,
            prefix_len,
        }
    }

    /// Create an IPv6 CIDR from octets and prefix length.
    /// Example: `Cidr::v6([0x20, 0x01, 0x0d, 0xb8, ...], 32)` for 2001:db8::/32
    pub fn v6(ip: [u8; 16], prefix_len: u8) -> Self {
        let prefix_len = prefix_len.min(128);
        let mask = if prefix_len == 0 {
            0
        } else {
            u128::MAX << (128 - prefix_len)
        };
        let network = u128::from_be_bytes(ip) & mask;
        Self::V6 {
            network,
            mask,
            prefix_len,
        }
    }

    /// Create from an IpAddr and prefix length.
    pub fn from_addr(ip: IpAddr, prefix_len: u8) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::v4(v4.octets(), prefix_len),
            IpAddr::V6(v6) => Self::v6(v6.octets(), prefix_len),
        }
    }

    /// Create from Ipv4Addr and prefix length.
    pub fn from_ipv4(ip: Ipv4Addr, prefix_len: u8) -> Self {
        Self::v4(ip.octets(), prefix_len)
    }

    /// Create from Ipv6Addr and prefix length.
    pub fn from_ipv6(ip: Ipv6Addr, prefix_len: u8) -> Self {
        Self::v6(ip.octets(), prefix_len)
    }

    /// Parse from string like "10.0.0.0/8", "192.168.1.1", "2001:db8::/32", or "::1".
    pub fn parse(s: &str) -> Option<Self> {
        let (ip_str, prefix_len) = if let Some((ip, prefix)) = s.split_once('/') {
            // Prefix must be a valid number
            let len: u8 = prefix.parse().ok()?;
            (ip, Some(len))
        } else {
            (s, None)
        };

        // Try parsing as IPv6 first (contains ':')
        if ip_str.contains(':') {
            let ip: Ipv6Addr = ip_str.parse().ok()?;
            return Some(Self::v6(ip.octets(), prefix_len.unwrap_or(128)));
        }

        // Try parsing as IPv4
        let ip: Ipv4Addr = ip_str.parse().ok()?;
        Some(Self::v4(ip.octets(), prefix_len.unwrap_or(32)))
    }

    /// Check if an IP address matches this CIDR.
    /// Returns false if address families don't match (IPv4 CIDR vs IPv6 address).
    #[inline(always)]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Cidr::V4 { network, mask, .. }, IpAddr::V4(v4)) => {
                let ip_bits = u32::from_be_bytes(v4.octets());
                (ip_bits & mask) == *network
            }
            (Cidr::V6 { network, mask, .. }, IpAddr::V6(v6)) => {
                let ip_bits = u128::from_be_bytes(v6.octets());
                (ip_bits & mask) == *network
            }
            // IPv4 CIDR doesn't match IPv6 address and vice versa
            _ => false,
        }
    }

    /// Check if an IPv4 address matches this CIDR.
    /// Returns false if this is an IPv6 CIDR.
    #[inline(always)]
    pub fn contains_v4(&self, ip: Ipv4Addr) -> bool {
        match self {
            Cidr::V4 { network, mask, .. } => {
                let ip_bits = u32::from_be_bytes(ip.octets());
                (ip_bits & mask) == *network
            }
            Cidr::V6 { .. } => false,
        }
    }

    /// Check if an IPv6 address matches this CIDR.
    /// Returns false if this is an IPv4 CIDR.
    #[inline(always)]
    pub fn contains_v6(&self, ip: Ipv6Addr) -> bool {
        match self {
            Cidr::V6 { network, mask, .. } => {
                let ip_bits = u128::from_be_bytes(ip.octets());
                (ip_bits & mask) == *network
            }
            Cidr::V4 { .. } => false,
        }
    }

    /// Returns true if this is an IPv4 CIDR.
    pub fn is_v4(&self) -> bool {
        matches!(self, Cidr::V4 { .. })
    }

    /// Returns true if this is an IPv6 CIDR.
    pub fn is_v6(&self) -> bool {
        matches!(self, Cidr::V6 { .. })
    }
}

/// Bitmap for fast port lookup. 65536 ports = 1024 u64s = 8KB.
/// Fits in L1 cache for extremely fast checks.
#[derive(Clone)]
pub struct PortBitmap {
    bits: Box<[u64; 1024]>,
}

impl Default for PortBitmap {
    fn default() -> Self {
        Self::new()
    }
}

impl PortBitmap {
    pub fn new() -> Self {
        Self {
            bits: Box::new([0u64; 1024]),
        }
    }

    /// Create a bitmap with all ports set.
    pub fn all() -> Self {
        Self {
            bits: Box::new([u64::MAX; 1024]),
        }
    }

    #[inline(always)]
    pub fn set(&mut self, port: u16) {
        let idx = port as usize / 64;
        let bit = port as usize % 64;
        self.bits[idx] |= 1 << bit;
    }

    #[inline(always)]
    pub fn clear(&mut self, port: u16) {
        let idx = port as usize / 64;
        let bit = port as usize % 64;
        self.bits[idx] &= !(1 << bit);
    }

    #[inline(always)]
    pub fn contains(&self, port: u16) -> bool {
        let idx = port as usize / 64;
        let bit = port as usize % 64;
        (self.bits[idx] >> bit) & 1 != 0
    }

    /// Set a range of ports (inclusive).
    pub fn set_range(&mut self, start: u16, end: u16) {
        for port in start..=end {
            self.set(port);
        }
    }
}

/// Firewall configuration with O(1) port lookups and CIDR-based destination filtering.
///
/// Uses bitmaps for port matching - each check is a single array lookup + bit test.
/// The entire bitmap (8KB per protocol) fits in L1 cache.
///
/// Destination filtering uses a deny list (blocked destinations) and an optional
/// allow list (if set, only those destinations are permitted).
///
/// # Example
/// ```ignore
/// let mut fw = FirewallConfig::deny_all();
/// fw.allow_tcp(80).allow_tcp(443).allow_tcp_range(8080, 8090);
/// fw.allow_udp(53);
/// fw.allow_icmp();
///
/// // Block private networks
/// fw.deny_destination_str("10.0.0.0/8");
/// fw.deny_destination_str("172.16.0.0/12");
/// fw.deny_destination_str("192.168.0.0/16");
///
/// assert!(fw.check_tcp(80, [8, 8, 8, 8].into()));
/// assert!(!fw.check_tcp(80, [10, 0, 0, 1].into())); // Blocked by destination
/// ```
#[derive(Clone)]
pub struct FirewallConfig {
    tcp_allowed: PortBitmap,
    udp_allowed: PortBitmap,
    icmp_allowed: bool,
    /// Destinations that are always blocked (deny list).
    denied_destinations: Vec<Cidr>,
    /// If Some, only these destinations are allowed (allowlist mode).
    /// Takes precedence over denied_destinations.
    allowed_destinations: Option<Vec<Cidr>>,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self::allow_all()
    }
}

impl FirewallConfig {
    /// Allow all traffic (no filtering).
    pub fn allow_all() -> Self {
        Self {
            tcp_allowed: PortBitmap::all(),
            udp_allowed: PortBitmap::all(),
            icmp_allowed: true,
            denied_destinations: Vec::new(),
            allowed_destinations: None,
        }
    }

    /// Deny all traffic by default. Use allow_* methods to open ports.
    pub fn deny_all() -> Self {
        Self {
            tcp_allowed: PortBitmap::new(),
            udp_allowed: PortBitmap::new(),
            icmp_allowed: false,
            denied_destinations: Vec::new(),
            allowed_destinations: None,
        }
    }

    /// Allow a TCP port.
    pub fn allow_tcp(&mut self, port: u16) -> &mut Self {
        self.tcp_allowed.set(port);
        self
    }

    /// Allow a range of TCP ports (inclusive).
    pub fn allow_tcp_range(&mut self, start: u16, end: u16) -> &mut Self {
        self.tcp_allowed.set_range(start, end);
        self
    }

    /// Deny a TCP port.
    pub fn deny_tcp(&mut self, port: u16) -> &mut Self {
        self.tcp_allowed.clear(port);
        self
    }

    /// Allow a UDP port.
    pub fn allow_udp(&mut self, port: u16) -> &mut Self {
        self.udp_allowed.set(port);
        self
    }

    /// Allow a range of UDP ports (inclusive).
    pub fn allow_udp_range(&mut self, start: u16, end: u16) -> &mut Self {
        self.udp_allowed.set_range(start, end);
        self
    }

    /// Deny a UDP port.
    pub fn deny_udp(&mut self, port: u16) -> &mut Self {
        self.udp_allowed.clear(port);
        self
    }

    /// Allow ICMP (ping).
    pub fn allow_icmp(&mut self) -> &mut Self {
        self.icmp_allowed = true;
        self
    }

    /// Deny ICMP (ping).
    pub fn deny_icmp(&mut self) -> &mut Self {
        self.icmp_allowed = false;
        self
    }

    /// Add a destination to the deny list.
    pub fn deny_destination(&mut self, cidr: Cidr) -> &mut Self {
        self.denied_destinations.push(cidr);
        self
    }

    /// Add a destination to the deny list (from string like "10.0.0.0/8").
    pub fn deny_destination_str(&mut self, cidr: &str) -> &mut Self {
        if let Some(c) = Cidr::parse(cidr) {
            self.denied_destinations.push(c);
        }
        self
    }

    /// Enable allowlist mode - only specified destinations are permitted.
    /// Call this, then use `allow_destination` to add permitted destinations.
    pub fn destination_allowlist_mode(&mut self) -> &mut Self {
        if self.allowed_destinations.is_none() {
            self.allowed_destinations = Some(Vec::new());
        }
        self
    }

    /// Add a destination to the allow list (only used in allowlist mode).
    pub fn allow_destination(&mut self, cidr: Cidr) -> &mut Self {
        if let Some(ref mut allowed) = self.allowed_destinations {
            allowed.push(cidr);
        }
        self
    }

    /// Add a destination to the allow list (from string like "8.8.8.0/24").
    pub fn allow_destination_str(&mut self, cidr: &str) -> &mut Self {
        if let Some(c) = Cidr::parse(cidr) {
            if let Some(ref mut allowed) = self.allowed_destinations {
                allowed.push(c);
            }
        }
        self
    }

    /// Check if destination IP is allowed.
    #[inline]
    fn check_destination(&self, dst_ip: IpAddr) -> bool {
        // Allowlist mode: must match at least one allowed destination
        if let Some(ref allowed) = self.allowed_destinations {
            return allowed.iter().any(|cidr| cidr.contains(dst_ip));
        }

        // Denylist mode: must not match any denied destination
        !self
            .denied_destinations
            .iter()
            .any(|cidr| cidr.contains(dst_ip))
    }

    /// Check if a TCP connection to the given destination is allowed.
    #[inline(always)]
    pub fn check_tcp(&self, dst_port: u16, dst_ip: IpAddr) -> bool {
        self.tcp_allowed.contains(dst_port) && self.check_destination(dst_ip)
    }

    /// Check if a UDP packet to the given destination is allowed.
    #[inline(always)]
    pub fn check_udp(&self, dst_port: u16, dst_ip: IpAddr) -> bool {
        self.udp_allowed.contains(dst_port) && self.check_destination(dst_ip)
    }

    /// Check if ICMP/ICMPv6 to the given destination is allowed.
    #[inline(always)]
    pub fn check_icmp(&self, dst_ip: IpAddr) -> bool {
        self.icmp_allowed && self.check_destination(dst_ip)
    }
}

/// A packet handler that implements firewall rules using FirewallConfig.
///
/// This handler drops packets that don't pass the firewall checks.
/// For TCP, only SYN packets are checked (connection initiation).
///
/// # Example
/// ```ignore
/// let mut firewall = FirewallConfig::default();
/// firewall.deny_tcp(22);  // Block SSH
/// firewall.deny_destination_str("10.0.0.0/8");  // Block private network
///
/// let handler = FirewallHandler::new(firewall);
/// config.handlers.push(Arc::new(handler));
/// ```
pub struct FirewallHandler {
    config: FirewallConfig,
}

impl FirewallHandler {
    /// Create a new firewall handler with the given configuration.
    pub fn new(config: FirewallConfig) -> Self {
        Self { config }
    }
}

impl PacketHandler for FirewallHandler {
    fn handle_tcp(&self, ctx: &PacketContext, tcp: TcpInfo) -> HandlerResult {
        // Only check SYN packets (connection initiation)
        if tcp.is_syn() && !self.config.check_tcp(tcp.dst_port, ctx.dst_ip) {
            debug!(
                "FirewallHandler: blocked TCP {} -> {}:{}",
                ctx.src_ip, ctx.dst_ip, tcp.dst_port
            );
            return Ok(PacketVerdict::Drop);
        }
        Ok(PacketVerdict::Continue)
    }

    fn handle_udp(&self, ctx: &PacketContext, udp: UdpInfo) -> HandlerResult {
        if !self.config.check_udp(udp.dst_port, ctx.dst_ip) {
            debug!(
                "FirewallHandler: blocked UDP {} -> {}:{}",
                ctx.src_ip, ctx.dst_ip, udp.dst_port
            );
            return Ok(PacketVerdict::Drop);
        }
        Ok(PacketVerdict::Continue)
    }

    fn handle_icmp(&self, ctx: &PacketContext, icmp: IcmpInfo) -> HandlerResult {
        // Only check echo requests (pings)
        if icmp.is_echo_request() && !self.config.check_icmp(ctx.dst_ip) {
            debug!(
                "FirewallHandler: blocked ICMP {} -> {}",
                ctx.src_ip, ctx.dst_ip
            );
            return Ok(PacketVerdict::Drop);
        }
        Ok(PacketVerdict::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Cidr Tests ====================

    mod cidr {
        use super::*;

        // Helper to create IpAddr::V4 from octets
        fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
            IpAddr::V4(Ipv4Addr::new(a, b, c, d))
        }

        // Helper to create IpAddr::V6 from segments
        fn v6(segments: [u16; 8]) -> IpAddr {
            IpAddr::V6(Ipv6Addr::new(
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                segments[4],
                segments[5],
                segments[6],
                segments[7],
            ))
        }

        #[test]
        fn test_cidr_v4_slash_8() {
            let cidr = Cidr::v4([10, 0, 0, 0], 8);
            assert!(cidr.contains(v4(10, 0, 0, 1)));
            assert!(cidr.contains(v4(10, 255, 255, 255)));
            assert!(!cidr.contains(v4(11, 0, 0, 1)));
            assert!(!cidr.contains(v4(9, 255, 255, 255)));
        }

        #[test]
        fn test_cidr_v4_slash_24() {
            let cidr = Cidr::v4([192, 168, 1, 0], 24);
            assert!(cidr.contains(v4(192, 168, 1, 1)));
            assert!(cidr.contains(v4(192, 168, 1, 255)));
            assert!(!cidr.contains(v4(192, 168, 2, 1)));
            assert!(!cidr.contains(v4(192, 168, 0, 255)));
        }

        #[test]
        fn test_cidr_v4_slash_32() {
            let cidr = Cidr::v4([8, 8, 8, 8], 32);
            assert!(cidr.contains(v4(8, 8, 8, 8)));
            assert!(!cidr.contains(v4(8, 8, 8, 9)));
            assert!(!cidr.contains(v4(8, 8, 8, 7)));
        }

        #[test]
        fn test_cidr_v4_slash_0() {
            let cidr = Cidr::v4([0, 0, 0, 0], 0);
            // /0 matches all IPv4
            assert!(cidr.contains(v4(0, 0, 0, 0)));
            assert!(cidr.contains(v4(255, 255, 255, 255)));
            assert!(cidr.contains(v4(10, 20, 30, 40)));
            // But not IPv6
            assert!(!cidr.contains(v6([0, 0, 0, 0, 0, 0, 0, 1])));
        }

        #[test]
        fn test_cidr_v4_slash_16() {
            let cidr = Cidr::v4([172, 16, 0, 0], 16);
            assert!(cidr.contains(v4(172, 16, 0, 1)));
            assert!(cidr.contains(v4(172, 16, 255, 255)));
            assert!(!cidr.contains(v4(172, 17, 0, 0)));
            assert!(!cidr.contains(v4(172, 15, 255, 255)));
        }

        #[test]
        fn test_cidr_v6_slash_64() {
            let cidr = Cidr::parse("2001:db8::/32").unwrap();
            assert!(cidr.contains(v6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1])));
            assert!(cidr.contains(v6([
                0x2001, 0x0db8, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
            ])));
            assert!(!cidr.contains(v6([0x2001, 0x0db9, 0, 0, 0, 0, 0, 1])));
            // IPv4 doesn't match IPv6 CIDR
            assert!(!cidr.contains(v4(10, 0, 0, 1)));
        }

        #[test]
        fn test_cidr_v6_slash_128() {
            let cidr = Cidr::parse("::1/128").unwrap();
            assert!(cidr.contains(v6([0, 0, 0, 0, 0, 0, 0, 1])));
            assert!(!cidr.contains(v6([0, 0, 0, 0, 0, 0, 0, 2])));
        }

        #[test]
        fn test_cidr_v6_link_local() {
            let cidr = Cidr::parse("fe80::/10").unwrap();
            assert!(cidr.contains(v6([0xfe80, 0, 0, 0, 0, 0, 0, 1])));
            assert!(cidr.contains(v6([
                0xfebf, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
            ])));
            assert!(!cidr.contains(v6([0xfec0, 0, 0, 0, 0, 0, 0, 1])));
        }

        #[test]
        fn test_cidr_from_addr_v4() {
            let cidr = Cidr::from_addr(v4(192, 168, 100, 0), 24);
            assert!(cidr.contains(v4(192, 168, 100, 50)));
            assert!(!cidr.contains(v4(192, 168, 101, 50)));
        }

        #[test]
        fn test_cidr_from_addr_v6() {
            let cidr = Cidr::from_addr(v6([0x2001, 0x0db8, 0xabcd, 0, 0, 0, 0, 0]), 48);
            assert!(cidr.contains(v6([0x2001, 0x0db8, 0xabcd, 0, 0, 0, 0, 1])));
            assert!(!cidr.contains(v6([0x2001, 0x0db8, 0xabce, 0, 0, 0, 0, 1])));
        }

        #[test]
        fn test_cidr_parse_ipv4_with_prefix() {
            let cidr = Cidr::parse("10.0.0.0/8").unwrap();
            assert!(cidr.is_v4());
            assert!(cidr.contains(v4(10, 1, 2, 3)));
            assert!(!cidr.contains(v4(11, 0, 0, 0)));
        }

        #[test]
        fn test_cidr_parse_ipv4_single_host() {
            let cidr = Cidr::parse("1.2.3.4").unwrap();
            assert!(cidr.is_v4());
            assert!(cidr.contains(v4(1, 2, 3, 4)));
            assert!(!cidr.contains(v4(1, 2, 3, 5)));
        }

        #[test]
        fn test_cidr_parse_ipv6_with_prefix() {
            let cidr = Cidr::parse("2001:db8::/32").unwrap();
            assert!(cidr.is_v6());
            assert!(cidr.contains(v6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1])));
        }

        #[test]
        fn test_cidr_parse_ipv6_single_host() {
            let cidr = Cidr::parse("::1").unwrap();
            assert!(cidr.is_v6());
            assert!(cidr.contains(v6([0, 0, 0, 0, 0, 0, 0, 1])));
            assert!(!cidr.contains(v6([0, 0, 0, 0, 0, 0, 0, 2])));
        }

        #[test]
        fn test_cidr_parse_invalid() {
            assert!(Cidr::parse("not an ip").is_none());
            assert!(Cidr::parse("10.0.0").is_none());
            assert!(Cidr::parse("10.0.0.0.0").is_none());
            assert!(Cidr::parse("10.0.0.0/abc").is_none());
        }

        #[test]
        fn test_cidr_parse_private_networks() {
            // RFC 1918 private networks
            let class_a = Cidr::parse("10.0.0.0/8").unwrap();
            let class_b = Cidr::parse("172.16.0.0/12").unwrap();
            let class_c = Cidr::parse("192.168.0.0/16").unwrap();

            // Class A: 10.0.0.0 - 10.255.255.255
            assert!(class_a.contains(v4(10, 0, 0, 1)));
            assert!(class_a.contains(v4(10, 255, 255, 255)));

            // Class B: 172.16.0.0 - 172.31.255.255
            assert!(class_b.contains(v4(172, 16, 0, 1)));
            assert!(class_b.contains(v4(172, 31, 255, 255)));
            assert!(!class_b.contains(v4(172, 32, 0, 0)));

            // Class C: 192.168.0.0 - 192.168.255.255
            assert!(class_c.contains(v4(192, 168, 0, 1)));
            assert!(class_c.contains(v4(192, 168, 255, 255)));
            assert!(!class_c.contains(v4(192, 169, 0, 0)));
        }

        #[test]
        fn test_cidr_contains_v4_method() {
            let cidr = Cidr::v4([192, 168, 1, 0], 24);
            assert!(cidr.contains_v4(Ipv4Addr::new(192, 168, 1, 100)));
            assert!(!cidr.contains_v4(Ipv4Addr::new(192, 168, 2, 100)));
        }

        #[test]
        fn test_cidr_v4_does_not_match_v6() {
            let cidr_v4 = Cidr::v4([0, 0, 0, 0], 0);
            let cidr_v6 = Cidr::parse("::/0").unwrap();

            // IPv4 CIDR doesn't match IPv6 addresses
            assert!(!cidr_v4.contains(v6([0, 0, 0, 0, 0, 0, 0, 1])));

            // IPv6 CIDR doesn't match IPv4 addresses
            assert!(!cidr_v6.contains(v4(10, 0, 0, 1)));
        }
    }

    // ==================== PortBitmap Tests ====================

    mod port_bitmap {
        use super::*;

        #[test]
        fn test_new_bitmap_is_empty() {
            let bitmap = PortBitmap::new();
            assert!(!bitmap.contains(0));
            assert!(!bitmap.contains(80));
            assert!(!bitmap.contains(65535));
        }

        #[test]
        fn test_all_bitmap_is_full() {
            let bitmap = PortBitmap::all();
            assert!(bitmap.contains(0));
            assert!(bitmap.contains(80));
            assert!(bitmap.contains(443));
            assert!(bitmap.contains(65535));
        }

        #[test]
        fn test_set_and_contains() {
            let mut bitmap = PortBitmap::new();
            bitmap.set(80);
            bitmap.set(443);
            bitmap.set(8080);

            assert!(bitmap.contains(80));
            assert!(bitmap.contains(443));
            assert!(bitmap.contains(8080));
            assert!(!bitmap.contains(81));
            assert!(!bitmap.contains(22));
        }

        #[test]
        fn test_clear() {
            let mut bitmap = PortBitmap::all();
            bitmap.clear(22);
            bitmap.clear(23);

            assert!(!bitmap.contains(22));
            assert!(!bitmap.contains(23));
            assert!(bitmap.contains(80));
            assert!(bitmap.contains(443));
        }

        #[test]
        fn test_set_range() {
            let mut bitmap = PortBitmap::new();
            bitmap.set_range(8080, 8090);

            assert!(!bitmap.contains(8079));
            assert!(bitmap.contains(8080));
            assert!(bitmap.contains(8085));
            assert!(bitmap.contains(8090));
            assert!(!bitmap.contains(8091));
        }

        #[test]
        fn test_boundary_ports() {
            let mut bitmap = PortBitmap::new();
            bitmap.set(0);
            bitmap.set(65535);

            assert!(bitmap.contains(0));
            assert!(bitmap.contains(65535));
            assert!(!bitmap.contains(1));
            assert!(!bitmap.contains(65534));
        }

        #[test]
        fn test_bit_boundaries() {
            // Test around 64-bit boundaries
            let mut bitmap = PortBitmap::new();
            bitmap.set(63);
            bitmap.set(64);
            bitmap.set(65);

            assert!(!bitmap.contains(62));
            assert!(bitmap.contains(63));
            assert!(bitmap.contains(64));
            assert!(bitmap.contains(65));
            assert!(!bitmap.contains(66));
        }
    }

    // ==================== FirewallConfig Tests ====================

    mod firewall_config {
        use super::*;

        // Helper to create IpAddr::V4 from octets
        fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
            IpAddr::V4(Ipv4Addr::new(a, b, c, d))
        }

        #[test]
        fn test_allow_all() {
            let fw = FirewallConfig::allow_all();
            assert!(fw.check_tcp(80, ip(8, 8, 8, 8)));
            assert!(fw.check_tcp(22, ip(10, 0, 0, 1)));
            assert!(fw.check_udp(53, ip(1, 1, 1, 1)));
            assert!(fw.check_icmp(ip(8, 8, 8, 8)));
        }

        #[test]
        fn test_deny_all() {
            let fw = FirewallConfig::deny_all();
            assert!(!fw.check_tcp(80, ip(8, 8, 8, 8)));
            assert!(!fw.check_tcp(22, ip(10, 0, 0, 1)));
            assert!(!fw.check_udp(53, ip(1, 1, 1, 1)));
            assert!(!fw.check_icmp(ip(8, 8, 8, 8)));
        }

        #[test]
        fn test_allow_specific_tcp_ports() {
            let mut fw = FirewallConfig::deny_all();
            fw.allow_tcp(80).allow_tcp(443);

            assert!(fw.check_tcp(80, ip(8, 8, 8, 8)));
            assert!(fw.check_tcp(443, ip(8, 8, 8, 8)));
            assert!(!fw.check_tcp(22, ip(8, 8, 8, 8)));
            assert!(!fw.check_tcp(8080, ip(8, 8, 8, 8)));
        }

        #[test]
        fn test_allow_tcp_range() {
            let mut fw = FirewallConfig::deny_all();
            fw.allow_tcp_range(8080, 8090);

            assert!(!fw.check_tcp(8079, ip(8, 8, 8, 8)));
            assert!(fw.check_tcp(8080, ip(8, 8, 8, 8)));
            assert!(fw.check_tcp(8085, ip(8, 8, 8, 8)));
            assert!(fw.check_tcp(8090, ip(8, 8, 8, 8)));
            assert!(!fw.check_tcp(8091, ip(8, 8, 8, 8)));
        }

        #[test]
        fn test_deny_specific_tcp_port() {
            let mut fw = FirewallConfig::allow_all();
            fw.deny_tcp(22);

            assert!(fw.check_tcp(80, ip(8, 8, 8, 8)));
            assert!(!fw.check_tcp(22, ip(8, 8, 8, 8)));
        }

        #[test]
        fn test_allow_specific_udp_ports() {
            let mut fw = FirewallConfig::deny_all();
            fw.allow_udp(53).allow_udp(123);

            assert!(fw.check_udp(53, ip(8, 8, 8, 8)));
            assert!(fw.check_udp(123, ip(8, 8, 8, 8)));
            assert!(!fw.check_udp(80, ip(8, 8, 8, 8)));
        }

        #[test]
        fn test_allow_udp_range() {
            let mut fw = FirewallConfig::deny_all();
            fw.allow_udp_range(10000, 10010);

            assert!(fw.check_udp(10005, ip(8, 8, 8, 8)));
            assert!(!fw.check_udp(9999, ip(8, 8, 8, 8)));
        }

        #[test]
        fn test_deny_specific_udp_port() {
            let mut fw = FirewallConfig::allow_all();
            fw.deny_udp(53);

            assert!(fw.check_udp(80, ip(8, 8, 8, 8)));
            assert!(!fw.check_udp(53, ip(8, 8, 8, 8)));
        }

        #[test]
        fn test_allow_icmp() {
            let mut fw = FirewallConfig::deny_all();
            fw.allow_icmp();

            assert!(fw.check_icmp(ip(8, 8, 8, 8)));
        }

        #[test]
        fn test_deny_icmp() {
            let mut fw = FirewallConfig::allow_all();
            fw.deny_icmp();

            assert!(!fw.check_icmp(ip(8, 8, 8, 8)));
        }

        #[test]
        fn test_deny_destination() {
            let mut fw = FirewallConfig::allow_all();
            fw.deny_destination(Cidr::v4([10, 0, 0, 0], 8));

            // Port allowed, but destination blocked
            assert!(!fw.check_tcp(80, ip(10, 0, 0, 1)));
            assert!(!fw.check_udp(53, ip(10, 255, 255, 255)));
            assert!(!fw.check_icmp(ip(10, 1, 2, 3)));

            // Other destinations still allowed
            assert!(fw.check_tcp(80, ip(8, 8, 8, 8)));
            assert!(fw.check_udp(53, ip(1, 1, 1, 1)));
        }

        #[test]
        fn test_deny_destination_str() {
            let mut fw = FirewallConfig::allow_all();
            fw.deny_destination_str("192.168.0.0/16");

            assert!(!fw.check_tcp(80, ip(192, 168, 1, 1)));
            assert!(fw.check_tcp(80, ip(192, 169, 1, 1)));
        }

        #[test]
        fn test_deny_multiple_destinations() {
            let mut fw = FirewallConfig::allow_all();
            fw.deny_destination_str("10.0.0.0/8")
                .deny_destination_str("172.16.0.0/12")
                .deny_destination_str("192.168.0.0/16");

            // All private networks blocked
            assert!(!fw.check_tcp(80, ip(10, 0, 0, 1)));
            assert!(!fw.check_tcp(80, ip(172, 16, 0, 1)));
            assert!(!fw.check_tcp(80, ip(192, 168, 0, 1)));

            // Public IPs allowed
            assert!(fw.check_tcp(80, ip(8, 8, 8, 8)));
            assert!(fw.check_tcp(80, ip(1, 1, 1, 1)));
        }

        #[test]
        fn test_allowlist_mode() {
            let mut fw = FirewallConfig::allow_all();
            fw.destination_allowlist_mode()
                .allow_destination_str("8.8.8.0/24")
                .allow_destination_str("1.1.1.0/24");

            // Only allowed destinations work
            assert!(fw.check_tcp(80, ip(8, 8, 8, 8)));
            assert!(fw.check_tcp(80, ip(1, 1, 1, 1)));

            // Everything else blocked
            assert!(!fw.check_tcp(80, ip(9, 9, 9, 9)));
            assert!(!fw.check_tcp(80, ip(10, 0, 0, 1)));
        }

        #[test]
        fn test_allowlist_mode_empty() {
            let mut fw = FirewallConfig::allow_all();
            fw.destination_allowlist_mode();

            // Empty allowlist means nothing is allowed
            assert!(!fw.check_tcp(80, ip(8, 8, 8, 8)));
            assert!(!fw.check_tcp(80, ip(10, 0, 0, 1)));
        }

        #[test]
        fn test_combined_port_and_destination() {
            let mut fw = FirewallConfig::deny_all();
            fw.allow_tcp(80)
                .allow_tcp(443)
                .deny_destination_str("10.0.0.0/8");

            // Port allowed, destination allowed
            assert!(fw.check_tcp(80, ip(8, 8, 8, 8)));
            assert!(fw.check_tcp(443, ip(8, 8, 8, 8)));

            // Port allowed, destination blocked
            assert!(!fw.check_tcp(80, ip(10, 0, 0, 1)));
            assert!(!fw.check_tcp(443, ip(10, 0, 0, 1)));

            // Port blocked, destination allowed
            assert!(!fw.check_tcp(22, ip(8, 8, 8, 8)));
        }

        #[test]
        fn test_default_is_allow_all() {
            let fw = FirewallConfig::default();
            assert!(fw.check_tcp(80, ip(8, 8, 8, 8)));
            assert!(fw.check_udp(53, ip(8, 8, 8, 8)));
            assert!(fw.check_icmp(ip(8, 8, 8, 8)));
        }

        #[test]
        fn test_ipv6_destination_deny() {
            let mut fw = FirewallConfig::allow_all();
            fw.deny_destination_str("2001:db8::/32");

            // IPv6 destination blocked
            let blocked_v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
            assert!(!fw.check_tcp(80, blocked_v6));

            // Other IPv6 allowed
            let allowed_v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db9, 0, 0, 0, 0, 0, 1));
            assert!(fw.check_tcp(80, allowed_v6));

            // IPv4 still works
            assert!(fw.check_tcp(80, ip(8, 8, 8, 8)));
        }

        #[test]
        fn test_mixed_v4_v6_destinations() {
            let mut fw = FirewallConfig::allow_all();
            fw.deny_destination_str("10.0.0.0/8")
                .deny_destination_str("fe80::/10"); // link-local IPv6

            // IPv4 private blocked
            assert!(!fw.check_tcp(80, ip(10, 0, 0, 1)));

            // IPv6 link-local blocked
            let link_local = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
            assert!(!fw.check_tcp(80, link_local));

            // Others allowed
            assert!(fw.check_tcp(80, ip(8, 8, 8, 8)));
            let global_v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
            assert!(fw.check_tcp(80, global_v6));
        }
    }

    // ==================== FirewallHandler Integration Tests ====================

    mod firewall_handler {
        use super::*;
        use bytes::Bytes;
        use tokio::sync::mpsc;

        use crate::handler::PacketContext;

        const VM_MAC: [u8; 6] = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
        const GW_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x01, 0x02, 0x03];

        /// Build a raw TCP SYN packet
        fn build_tcp_syn_packet(
            src_ip: [u8; 4],
            dst_ip: [u8; 4],
            src_port: u16,
            dst_port: u16,
        ) -> Vec<u8> {
            let mut pkt = Vec::with_capacity(54); // 14 eth + 20 ip + 20 tcp

            // Ethernet header (14 bytes)
            pkt.extend_from_slice(&GW_MAC); // dst mac
            pkt.extend_from_slice(&VM_MAC); // src mac
            pkt.extend_from_slice(&[0x08, 0x00]); // ethertype: IPv4

            // IPv4 header (20 bytes)
            pkt.push(0x45); // version + IHL
            pkt.push(0x00); // DSCP + ECN
            pkt.extend_from_slice(&40u16.to_be_bytes()); // total length
            pkt.extend_from_slice(&[0x00, 0x00]); // identification
            pkt.extend_from_slice(&[0x40, 0x00]); // flags + fragment offset
            pkt.push(64); // TTL
            pkt.push(6); // protocol: TCP
            pkt.extend_from_slice(&[0x00, 0x00]); // checksum (skip for test)
            pkt.extend_from_slice(&src_ip);
            pkt.extend_from_slice(&dst_ip);

            // TCP header (20 bytes)
            pkt.extend_from_slice(&src_port.to_be_bytes());
            pkt.extend_from_slice(&dst_port.to_be_bytes());
            pkt.extend_from_slice(&1000u32.to_be_bytes()); // seq
            pkt.extend_from_slice(&0u32.to_be_bytes()); // ack
            pkt.push(5 << 4); // data offset (5 * 4 = 20 bytes)
            pkt.push(0x02); // flags: SYN
            pkt.extend_from_slice(&65535u16.to_be_bytes()); // window
            pkt.extend_from_slice(&[0x00, 0x00]); // checksum
            pkt.extend_from_slice(&[0x00, 0x00]); // urgent pointer

            pkt
        }

        /// Build a raw TCP ACK packet (not SYN)
        fn build_tcp_ack_packet(
            src_ip: [u8; 4],
            dst_ip: [u8; 4],
            src_port: u16,
            dst_port: u16,
        ) -> Vec<u8> {
            let mut pkt = build_tcp_syn_packet(src_ip, dst_ip, src_port, dst_port);
            // Change flags from SYN (0x02) to ACK (0x10)
            pkt[47] = 0x10;
            pkt
        }

        /// Build a raw UDP packet
        fn build_udp_packet(
            src_ip: [u8; 4],
            dst_ip: [u8; 4],
            src_port: u16,
            dst_port: u16,
        ) -> Vec<u8> {
            let mut pkt = Vec::with_capacity(42); // 14 eth + 20 ip + 8 udp

            // Ethernet header (14 bytes)
            pkt.extend_from_slice(&GW_MAC);
            pkt.extend_from_slice(&VM_MAC);
            pkt.extend_from_slice(&[0x08, 0x00]);

            // IPv4 header (20 bytes)
            pkt.push(0x45);
            pkt.push(0x00);
            pkt.extend_from_slice(&28u16.to_be_bytes()); // total length (20 + 8)
            pkt.extend_from_slice(&[0x00, 0x00]);
            pkt.extend_from_slice(&[0x40, 0x00]);
            pkt.push(64);
            pkt.push(17); // protocol: UDP
            pkt.extend_from_slice(&[0x00, 0x00]);
            pkt.extend_from_slice(&src_ip);
            pkt.extend_from_slice(&dst_ip);

            // UDP header (8 bytes)
            pkt.extend_from_slice(&src_port.to_be_bytes());
            pkt.extend_from_slice(&dst_port.to_be_bytes());
            pkt.extend_from_slice(&8u16.to_be_bytes()); // length
            pkt.extend_from_slice(&[0x00, 0x00]); // checksum

            pkt
        }

        /// Build a raw ICMP echo request packet
        fn build_icmp_echo_request(src_ip: [u8; 4], dst_ip: [u8; 4]) -> Vec<u8> {
            let mut pkt = Vec::with_capacity(42); // 14 eth + 20 ip + 8 icmp

            // Ethernet header
            pkt.extend_from_slice(&GW_MAC);
            pkt.extend_from_slice(&VM_MAC);
            pkt.extend_from_slice(&[0x08, 0x00]);

            // IPv4 header
            pkt.push(0x45);
            pkt.push(0x00);
            pkt.extend_from_slice(&28u16.to_be_bytes());
            pkt.extend_from_slice(&[0x00, 0x00]);
            pkt.extend_from_slice(&[0x40, 0x00]);
            pkt.push(64);
            pkt.push(1); // protocol: ICMP
            pkt.extend_from_slice(&[0x00, 0x00]);
            pkt.extend_from_slice(&src_ip);
            pkt.extend_from_slice(&dst_ip);

            // ICMP header (8 bytes)
            pkt.push(8); // type: echo request
            pkt.push(0); // code
            pkt.extend_from_slice(&[0x00, 0x00]); // checksum
            pkt.extend_from_slice(&[0x00, 0x01]); // identifier
            pkt.extend_from_slice(&[0x00, 0x01]); // sequence

            pkt
        }

        /// Build a raw ICMP echo reply packet
        fn build_icmp_echo_reply(src_ip: [u8; 4], dst_ip: [u8; 4]) -> Vec<u8> {
            let mut pkt = build_icmp_echo_request(src_ip, dst_ip);
            // Change type from echo request (8) to echo reply (0)
            pkt[34] = 0;
            pkt
        }

        #[test]
        fn test_handler_blocks_tcp_syn_to_denied_port() {
            let mut config = FirewallConfig::deny_all();
            config.allow_tcp(80).allow_tcp(443);
            let handler = FirewallHandler::new(config);

            let (tx, _rx) = mpsc::channel::<Bytes>(1);

            // SYN to port 80 (allowed)
            let pkt = build_tcp_syn_packet([192, 168, 1, 100], [8, 8, 8, 8], 12345, 80);
            let ctx = PacketContext::parse(&pkt, VM_MAC, GW_MAC, &tx).unwrap();
            let result = handler.handle(&ctx).unwrap();
            assert!(
                matches!(result, PacketVerdict::Continue),
                "TCP SYN to allowed port 80 should continue"
            );

            // SYN to port 22 (blocked)
            let pkt = build_tcp_syn_packet([192, 168, 1, 100], [8, 8, 8, 8], 12345, 22);
            let ctx = PacketContext::parse(&pkt, VM_MAC, GW_MAC, &tx).unwrap();
            let result = handler.handle(&ctx).unwrap();
            assert!(
                matches!(result, PacketVerdict::Drop),
                "TCP SYN to blocked port 22 should be dropped"
            );
        }

        #[test]
        fn test_handler_allows_non_syn_tcp() {
            // Firewall that blocks all ports
            let config = FirewallConfig::deny_all();
            let handler = FirewallHandler::new(config);

            let (tx, _rx) = mpsc::channel::<Bytes>(1);

            // ACK packet to blocked port should still be allowed (only SYN checked)
            let pkt = build_tcp_ack_packet([192, 168, 1, 100], [8, 8, 8, 8], 12345, 80);
            let ctx = PacketContext::parse(&pkt, VM_MAC, GW_MAC, &tx).unwrap();
            let result = handler.handle(&ctx).unwrap();
            assert!(
                matches!(result, PacketVerdict::Continue),
                "Non-SYN TCP packets should always continue"
            );
        }

        #[test]
        fn test_handler_blocks_udp_to_denied_port() {
            let mut config = FirewallConfig::deny_all();
            config.allow_udp(53);
            let handler = FirewallHandler::new(config);

            let (tx, _rx) = mpsc::channel::<Bytes>(1);

            // UDP to port 53 (allowed)
            let pkt = build_udp_packet([192, 168, 1, 100], [8, 8, 8, 8], 12345, 53);
            let ctx = PacketContext::parse(&pkt, VM_MAC, GW_MAC, &tx).unwrap();
            let result = handler.handle(&ctx).unwrap();
            assert!(
                matches!(result, PacketVerdict::Continue),
                "UDP to allowed port 53 should continue"
            );

            // UDP to port 80 (blocked)
            let pkt = build_udp_packet([192, 168, 1, 100], [8, 8, 8, 8], 12345, 80);
            let ctx = PacketContext::parse(&pkt, VM_MAC, GW_MAC, &tx).unwrap();
            let result = handler.handle(&ctx).unwrap();
            assert!(
                matches!(result, PacketVerdict::Drop),
                "UDP to blocked port 80 should be dropped"
            );
        }

        #[test]
        fn test_handler_blocks_icmp_when_disabled() {
            let config = FirewallConfig::deny_all();
            let handler = FirewallHandler::new(config);

            let (tx, _rx) = mpsc::channel::<Bytes>(1);

            // ICMP echo request (blocked)
            let pkt = build_icmp_echo_request([192, 168, 1, 100], [8, 8, 8, 8]);
            let ctx = PacketContext::parse(&pkt, VM_MAC, GW_MAC, &tx).unwrap();
            let result = handler.handle(&ctx).unwrap();
            assert!(
                matches!(result, PacketVerdict::Drop),
                "ICMP echo request should be dropped when ICMP disabled"
            );
        }

        #[test]
        fn test_handler_allows_icmp_when_enabled() {
            let mut config = FirewallConfig::deny_all();
            config.allow_icmp();
            let handler = FirewallHandler::new(config);

            let (tx, _rx) = mpsc::channel::<Bytes>(1);

            // ICMP echo request (allowed)
            let pkt = build_icmp_echo_request([192, 168, 1, 100], [8, 8, 8, 8]);
            let ctx = PacketContext::parse(&pkt, VM_MAC, GW_MAC, &tx).unwrap();
            let result = handler.handle(&ctx).unwrap();
            assert!(
                matches!(result, PacketVerdict::Continue),
                "ICMP echo request should continue when ICMP enabled"
            );

            // ICMP echo reply should always continue (only requests checked)
            let pkt = build_icmp_echo_reply([192, 168, 1, 100], [8, 8, 8, 8]);
            let ctx = PacketContext::parse(&pkt, VM_MAC, GW_MAC, &tx).unwrap();
            let result = handler.handle(&ctx).unwrap();
            assert!(
                matches!(result, PacketVerdict::Continue),
                "ICMP echo reply should always continue"
            );
        }

        #[test]
        fn test_handler_blocks_denied_destinations() {
            let mut config = FirewallConfig::allow_all();
            config.deny_destination_str("10.0.0.0/8");
            let handler = FirewallHandler::new(config);

            let (tx, _rx) = mpsc::channel::<Bytes>(1);

            // TCP to public IP (allowed)
            let pkt = build_tcp_syn_packet([192, 168, 1, 100], [8, 8, 8, 8], 12345, 80);
            let ctx = PacketContext::parse(&pkt, VM_MAC, GW_MAC, &tx).unwrap();
            let result = handler.handle(&ctx).unwrap();
            assert!(
                matches!(result, PacketVerdict::Continue),
                "TCP to public IP should continue"
            );

            // TCP to blocked private IP
            let pkt = build_tcp_syn_packet([192, 168, 1, 100], [10, 0, 0, 1], 12345, 80);
            let ctx = PacketContext::parse(&pkt, VM_MAC, GW_MAC, &tx).unwrap();
            let result = handler.handle(&ctx).unwrap();
            assert!(
                matches!(result, PacketVerdict::Drop),
                "TCP to blocked 10.x.x.x should be dropped"
            );

            // UDP to blocked private IP
            let pkt = build_udp_packet([192, 168, 1, 100], [10, 0, 0, 1], 12345, 53);
            let ctx = PacketContext::parse(&pkt, VM_MAC, GW_MAC, &tx).unwrap();
            let result = handler.handle(&ctx).unwrap();
            assert!(
                matches!(result, PacketVerdict::Drop),
                "UDP to blocked 10.x.x.x should be dropped"
            );

            // ICMP to blocked private IP
            let pkt = build_icmp_echo_request([192, 168, 1, 100], [10, 0, 0, 1]);
            let ctx = PacketContext::parse(&pkt, VM_MAC, GW_MAC, &tx).unwrap();
            let result = handler.handle(&ctx).unwrap();
            assert!(
                matches!(result, PacketVerdict::Drop),
                "ICMP to blocked 10.x.x.x should be dropped"
            );
        }

        #[test]
        fn test_handler_typical_web_firewall() {
            let mut config = FirewallConfig::deny_all();
            config
                .allow_tcp(80)
                .allow_tcp(443)
                .allow_udp(53)
                .allow_icmp()
                .deny_destination_str("10.0.0.0/8")
                .deny_destination_str("172.16.0.0/12")
                .deny_destination_str("192.168.0.0/16")
                .deny_destination_str("127.0.0.0/8");
            let handler = FirewallHandler::new(config);

            let (tx, _rx) = mpsc::channel::<Bytes>(1);
            let src = [192, 168, 1, 100];
            let public = [8, 8, 8, 8];
            let private = [10, 0, 0, 1];

            // HTTP to public: allowed
            let pkt = build_tcp_syn_packet(src, public, 12345, 80);
            let ctx = PacketContext::parse(&pkt, VM_MAC, GW_MAC, &tx).unwrap();
            assert!(matches!(
                handler.handle(&ctx).unwrap(),
                PacketVerdict::Continue
            ));

            // HTTPS to public: allowed
            let pkt = build_tcp_syn_packet(src, public, 12345, 443);
            let ctx = PacketContext::parse(&pkt, VM_MAC, GW_MAC, &tx).unwrap();
            assert!(matches!(
                handler.handle(&ctx).unwrap(),
                PacketVerdict::Continue
            ));

            // HTTP to private: blocked (destination denied)
            let pkt = build_tcp_syn_packet(src, private, 12345, 80);
            let ctx = PacketContext::parse(&pkt, VM_MAC, GW_MAC, &tx).unwrap();
            assert!(matches!(handler.handle(&ctx).unwrap(), PacketVerdict::Drop));

            // SSH to public: blocked (port not allowed)
            let pkt = build_tcp_syn_packet(src, public, 12345, 22);
            let ctx = PacketContext::parse(&pkt, VM_MAC, GW_MAC, &tx).unwrap();
            assert!(matches!(handler.handle(&ctx).unwrap(), PacketVerdict::Drop));

            // DNS to public: allowed
            let pkt = build_udp_packet(src, public, 12345, 53);
            let ctx = PacketContext::parse(&pkt, VM_MAC, GW_MAC, &tx).unwrap();
            assert!(matches!(
                handler.handle(&ctx).unwrap(),
                PacketVerdict::Continue
            ));

            // DNS to private: blocked
            let pkt = build_udp_packet(src, private, 12345, 53);
            let ctx = PacketContext::parse(&pkt, VM_MAC, GW_MAC, &tx).unwrap();
            assert!(matches!(handler.handle(&ctx).unwrap(), PacketVerdict::Drop));

            // Ping to public: allowed
            let pkt = build_icmp_echo_request(src, public);
            let ctx = PacketContext::parse(&pkt, VM_MAC, GW_MAC, &tx).unwrap();
            assert!(matches!(
                handler.handle(&ctx).unwrap(),
                PacketVerdict::Continue
            ));

            // Ping to private: blocked
            let pkt = build_icmp_echo_request(src, private);
            let ctx = PacketContext::parse(&pkt, VM_MAC, GW_MAC, &tx).unwrap();
            assert!(matches!(handler.handle(&ctx).unwrap(), PacketVerdict::Drop));
        }
    }
}
