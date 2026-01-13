//! smoltcp device implementation for the proxy.
//!
//! Provides a virtual device that queues packets for smoltcp processing.

use bytes::Bytes;
use log::debug;
use smoltcp::time::Instant as SmoltcpInstant;
use std::collections::VecDeque;

/// A smoltcp device with a packet buffer, similar to the old proxy's VirtualDevice.
/// Packets are queued to rx_buffer, then processed by iface.poll().
pub struct ProxyDevice {
    rx_buffer: VecDeque<Bytes>,
    tx_buffer: VecDeque<Bytes>,
}

impl ProxyDevice {
    pub fn new() -> Self {
        Self {
            rx_buffer: VecDeque::new(),
            tx_buffer: VecDeque::new(),
        }
    }

    /// Queue a packet for smoltcp to process
    pub fn queue_rx(&mut self, packet: Bytes) {
        self.rx_buffer.push_back(packet);
    }

    /// Take all transmitted packets
    pub fn take_tx(&mut self) -> Vec<Bytes> {
        self.tx_buffer.drain(..).collect()
    }
}

impl Default for ProxyDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl smoltcp::phy::Device for ProxyDevice {
    type RxToken<'a>
        = ProxyRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = ProxyTxToken<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: SmoltcpInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx_buffer.pop_front().map(|buffer| {
            debug!(
                "ProxyDevice::receive() returning {} byte packet",
                buffer.len()
            );
            (
                ProxyRxToken { buffer },
                ProxyTxToken {
                    tx_buffer: &mut self.tx_buffer,
                },
            )
        })
    }

    fn transmit(&mut self, _timestamp: SmoltcpInstant) -> Option<Self::TxToken<'_>> {
        Some(ProxyTxToken {
            tx_buffer: &mut self.tx_buffer,
        })
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.max_transmission_unit = 1500;
        caps.medium = smoltcp::phy::Medium::Ethernet;
        // Configure checksums:
        // - RX: Don't validate (guest uses checksum offloading, sends partial checksums)
        // - TX: Do fill checksums (guest validates incoming packets)
        caps.checksum.ipv4 = smoltcp::phy::Checksum::Tx;
        caps.checksum.udp = smoltcp::phy::Checksum::Tx;
        caps.checksum.tcp = smoltcp::phy::Checksum::Tx;
        caps.checksum.icmpv4 = smoltcp::phy::Checksum::Tx;
        caps.checksum.icmpv6 = smoltcp::phy::Checksum::Tx;
        caps
    }
}

/// RX token that owns a packet buffer
pub struct ProxyRxToken {
    buffer: Bytes,
}

impl smoltcp::phy::RxToken for ProxyRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        debug!(
            "RxToken::consume() called with {} byte packet",
            self.buffer.len()
        );
        f(&self.buffer)
    }
}

/// TX token that pushes packets to the device's tx_buffer
pub struct ProxyTxToken<'a> {
    tx_buffer: &'a mut VecDeque<Bytes>,
}

impl<'a> smoltcp::phy::TxToken for ProxyTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        debug!("TxToken::consume() called, allocating {} bytes", len);
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        debug!(
            "TxToken::consume() pushing {} byte packet to tx_buffer",
            buf.len()
        );
        self.tx_buffer.push_back(Bytes::from(buf));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::Device;

    /// Test that ProxyDevice has correct checksum capabilities.
    #[test]
    fn test_proxy_device_checksum_capabilities() {
        let device = ProxyDevice::new();
        let caps = device.capabilities();

        // Verify checksum configuration for TCP (critical for TCP handshake)
        assert!(
            !caps.checksum.tcp.rx(),
            "TCP RX checksum validation should be disabled (guest uses checksum offloading)"
        );
        assert!(
            caps.checksum.tcp.tx(),
            "TCP TX checksum filling should be enabled (guest validates incoming packets)"
        );

        // Verify checksum configuration for UDP
        assert!(
            !caps.checksum.udp.rx(),
            "UDP RX checksum validation should be disabled"
        );
        assert!(
            caps.checksum.udp.tx(),
            "UDP TX checksum filling should be enabled"
        );

        // Verify checksum configuration for IPv4
        assert!(
            !caps.checksum.ipv4.rx(),
            "IPv4 RX checksum validation should be disabled"
        );
        assert!(
            caps.checksum.ipv4.tx(),
            "IPv4 TX checksum filling should be enabled"
        );
    }

    #[test]
    fn test_proxy_device_medium_is_ethernet() {
        let device = ProxyDevice::new();
        let caps = device.capabilities();
        assert_eq!(caps.medium, smoltcp::phy::Medium::Ethernet);
    }
}
