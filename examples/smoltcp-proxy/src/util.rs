//! Utility functions for the smoltcp proxy.

use log::{info, warn};

/// Check if unprivileged ICMP sockets are available.
/// Logs a warning with instructions if not configured.
pub fn check_icmp_available() {
    let socket_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };

    if socket_fd < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EACCES) || err.raw_os_error() == Some(libc::EPERM) {
            warn!(
                "ICMP ping forwarding unavailable: permission denied. \
                Pings from VM will show local latency instead of real network latency."
            );

            // On Linux, check the current sysctl setting
            #[cfg(target_os = "linux")]
            if let Ok(contents) = std::fs::read_to_string("/proc/sys/net/ipv4/ping_group_range") {
                let parts: Vec<&str> = contents.trim().split_whitespace().collect();
                if parts.len() == 2 {
                    if let (Ok(min), Ok(max)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                        if min > max {
                            info!(
                                "To enable ICMP forwarding, run: \
                                sudo sysctl -w net.ipv4.ping_group_range=\"0 2147483647\""
                            );
                        } else {
                            let gid = unsafe { libc::getegid() };
                            info!(
                                "Current ping_group_range is {}-{}, your GID is {}. \
                                To fix, run: sudo sysctl -w net.ipv4.ping_group_range=\"0 2147483647\"",
                                min, max, gid
                            );
                        }
                    }
                }
            }
        } else {
            warn!("ICMP socket check failed: {}", err);
        }
    } else {
        unsafe { libc::close(socket_fd) };
        info!("ICMP ping forwarding available");
    }
}

/// Calculate ICMP checksum (RFC 792).
/// The checksum is the 16-bit one's complement of the one's complement sum
/// of all 16-bit words in the ICMP header and data.
#[allow(dead_code)]
pub fn icmp_checksum(data: &[u8]) -> u16 {
    internet_checksum(data)
}

/// Calculate IPv4 header checksum (RFC 791).
#[allow(dead_code)]
pub fn ipv4_header_checksum(header: &[u8]) -> u16 {
    internet_checksum(header)
}

/// Calculate Internet checksum (RFC 1071).
/// Used for both ICMP and IPv4 header checksums.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Sum all 16-bit words
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }

    // Add odd byte if present
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Return one's complement
    !(sum as u16)
}
