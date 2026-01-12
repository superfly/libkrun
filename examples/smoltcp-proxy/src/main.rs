//! Example: Userspace NAT proxy using smoltcp.
//!
//! This example demonstrates how to implement a custom async network backend
//! for libkrun using smoltcp as the TCP/IP stack. It enables network access
//! for VMs without requiring tap/tun interfaces.
//!
//! # Architecture
//!
//! ```text
//! Guest App
//!     | TCP/UDP
//!     v
//! Guest Kernel (virtio-net)
//!     | Ethernet frames
//!     v
//! AsyncNetWorker (virtio queues)
//!     | borrowed &[u8] (zero-copy)
//!     v
//! SmoltcpProxyBackend
//!     |-- smoltcp (TCP/IP stack)
//!     `-- Host connections (tokio tasks)
//!           |
//!           v
//!      Real network
//! ```

use bytes::Bytes;
use clap::Parser;
use krun::{
    AsyncNetBackend, AsyncNetBackendFactory, NetBackendHandle, NetSendBoxFuture, VirtioNetBackend,
    NET_ALL_FEATURES,
};
use log::{debug, error, trace, warn};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp as smoltcp_tcp;
use smoltcp::socket::udp as smoltcp_udp;
use smoltcp::time::Instant as SmoltcpInstant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tracing::info;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/// Channel buffer size for to_guest packets
const CHANNEL_SIZE: usize = 256;

/// Default VM MAC address
const VM_MAC: EthernetAddress = EthernetAddress([0xde, 0xad, 0xbe, 0xef, 0x00, 0x00]);
/// Default proxy/gateway MAC address
const PROXY_MAC: EthernetAddress = EthernetAddress([0x02, 0x00, 0x00, 0x01, 0x02, 0x03]);
/// Default VM IP address
const VM_IP: Ipv4Address = Ipv4Address::new(192, 168, 100, 2);
/// Default proxy/gateway IP address
const PROXY_IP: Ipv4Address = Ipv4Address::new(192, 168, 100, 1);

// ============================================================================
// smoltcp Device - similar to old proxy's VirtualDevice
// ============================================================================

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

// ============================================================================
// Backend Configuration and Factory
// ============================================================================

/// Configuration for the smoltcp proxy backend.
pub struct SmoltcpProxyConfig {
    pub vm_mac: EthernetAddress,
    pub vm_ip: Ipv4Address,
    pub gateway_mac: EthernetAddress,
    pub gateway_ip: Ipv4Address,
    /// Unix socket listeners: maps VM port to Unix socket path on host
    /// When a connection arrives on the Unix socket, it's forwarded to the VM port
    pub unix_listeners: HashMap<u16, PathBuf>,
}

impl Default for SmoltcpProxyConfig {
    fn default() -> Self {
        Self {
            vm_mac: VM_MAC,
            vm_ip: VM_IP,
            gateway_mac: PROXY_MAC,
            gateway_ip: PROXY_IP,
            unix_listeners: HashMap::new(),
        }
    }
}

/// Factory for creating SmoltcpProxyBackend instances.
pub struct SmoltcpProxyFactory {
    config: SmoltcpProxyConfig,
}

impl SmoltcpProxyFactory {
    pub fn new(config: SmoltcpProxyConfig) -> Self {
        Self { config }
    }
}

impl AsyncNetBackendFactory for SmoltcpProxyFactory {
    fn create(self: Box<Self>) -> NetSendBoxFuture<'static, io::Result<NetBackendHandle>> {
        Box::pin(async move {
            let (to_guest_tx, to_guest_rx) = mpsc::channel(CHANNEL_SIZE);
            let (wake_tx, wake_rx) = mpsc::channel(256);
            let (host_events_tx, host_events_rx) = mpsc::channel(CHANNEL_SIZE);

            // Spawn Unix socket listener tasks before creating backend
            let mut next_conn_id = 1_000_000u64; // Start high to avoid collision with TCP conn IDs
            for (vm_port, socket_path) in &self.config.unix_listeners {
                // Remove existing socket file if present
                if socket_path.exists() {
                    if let Err(e) = std::fs::remove_file(socket_path) {
                        error!("Failed to remove existing socket {:?}: {}", socket_path, e);
                    }
                }

                // Create Unix listener
                let listener = match UnixListener::bind(socket_path) {
                    Ok(l) => l,
                    Err(e) => {
                        error!("Failed to bind Unix socket {:?}: {}", socket_path, e);
                        continue;
                    }
                };

                info!(
                    "Unix socket listener started: {:?} -> VM port {}",
                    socket_path, vm_port
                );

                // Spawn listener task
                let events_tx = host_events_tx.clone();
                let wake_tx_clone = wake_tx.clone();
                let vm_port = *vm_port;
                let base_conn_id = next_conn_id;
                next_conn_id += 100_000; // Reserve range for this listener

                tokio::task::spawn_local(async move {
                    let mut conn_counter = 0u64;
                    loop {
                        match listener.accept().await {
                            Ok((stream, _addr)) => {
                                let conn_id = base_conn_id + conn_counter;
                                conn_counter += 1;
                                debug!("Unix listener: accepted connection {}", conn_id);

                                if events_tx
                                    .send(HostEvent::UnixAccepted {
                                        conn_id,
                                        vm_port,
                                        stream,
                                    })
                                    .await
                                    .is_err()
                                {
                                    break; // Channel closed
                                }
                                let _ = wake_tx_clone.try_send(());
                            }
                            Err(e) => {
                                error!("Unix listener accept error: {}", e);
                            }
                        }
                    }
                });
            }

            let backend = SmoltcpProxyBackend::new_with_channels(
                self.config,
                to_guest_tx,
                wake_tx,
                host_events_tx,
                host_events_rx,
            )?;

            Ok(NetBackendHandle {
                backend: Box::new(backend),
                to_guest_rx,
                wake_rx: Some(wake_rx),
            })
        })
    }
}

// ============================================================================
// Backend Implementation
// ============================================================================

/// Messages from host connection tasks to the backend.
enum HostEvent {
    TcpData { conn_id: u64, data: Bytes },
    TcpClosed { conn_id: u64 },
    TcpConnected { conn_id: u64 },
    TcpFailed { conn_id: u64, error: String },
    UdpData { flow_id: u64, data: Bytes },
    UdpClosed { flow_id: u64 },
    /// A new connection was accepted on a Unix socket listener
    UnixAccepted { conn_id: u64, vm_port: u16, stream: UnixStream },
    /// Data received from Unix socket (to be sent to VM)
    UnixData { conn_id: u64, data: Bytes },
    /// Unix socket closed
    UnixClosed { conn_id: u64 },
}

/// Commands sent to host TCP connection tasks.
enum HostCommand {
    Send(Bytes),
    Close,
}

/// Commands sent to host UDP tasks.
enum UdpHostCommand {
    Send { data: Bytes, dest: SocketAddr },
    Close,
}

/// State for a proxied TCP connection.
struct TcpConnection {
    smoltcp_handle: SocketHandle,
    cmd_tx: mpsc::Sender<HostCommand>,
    #[allow(dead_code)]
    guest_endpoint: IpEndpoint,
    host_endpoint: SocketAddr,
    state: TcpConnectionState,
    /// Pending data from host that couldn't be sent to smoltcp yet (backpressure buffer)
    pending_data: VecDeque<Bytes>,
    /// Pending data to send to host task (backpressure when host channel is full)
    pending_host_send: Option<Bytes>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpConnectionState {
    Connecting,
    Established,
    #[allow(dead_code)]
    Closing,
}

/// State for a proxied UDP flow.
/// UDP is connectionless, so we track "flows" by the guest's source endpoint.
struct UdpFlow {
    smoltcp_handle: SocketHandle,
    cmd_tx: mpsc::Sender<UdpHostCommand>,
    guest_endpoint: IpEndpoint,
    last_activity: Instant,
}

/// State for a Unix socket inbound connection (host Unix socket -> VM TCP).
/// This is the reverse direction: connections from the host to the VM.
struct UnixInboundConnection {
    smoltcp_handle: SocketHandle,
    cmd_tx: mpsc::Sender<HostCommand>,
    vm_port: u16,
    state: UnixInboundState,
    /// Pending data from Unix socket that couldn't be sent to smoltcp yet
    pending_to_vm: VecDeque<Bytes>,
    /// Pending data to send to Unix socket (backpressure when channel is full)
    pending_to_unix: Option<Bytes>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnixInboundState {
    /// TCP connection to VM is being established (SYN sent)
    Connecting,
    /// TCP connection to VM is established
    Established,
}

/// The userspace NAT proxy backend using smoltcp.
pub struct SmoltcpProxyBackend {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: ProxyDevice,
    to_guest_tx: mpsc::Sender<Bytes>,
    host_events_tx: mpsc::Sender<HostEvent>,
    host_events_rx: mpsc::Receiver<HostEvent>,
    wake_tx: mpsc::Sender<()>,
    next_conn_id: u64,
    tcp_connections: HashMap<u64, TcpConnection>,
    tcp_nat: HashMap<IpEndpoint, u64>,
    // UDP tracking
    next_flow_id: u64,
    udp_flows: HashMap<u64, UdpFlow>,
    udp_nat: HashMap<IpEndpoint, u64>,
    // Unix socket inbound connections (host -> VM)
    unix_inbound: HashMap<u64, UnixInboundConnection>,
    next_ephemeral_port: u16,
    start_time: Instant,
    config: SmoltcpProxyConfig,
}

impl SmoltcpProxyBackend {
    pub fn new(
        config: SmoltcpProxyConfig,
        to_guest_tx: mpsc::Sender<Bytes>,
        wake_tx: mpsc::Sender<()>,
    ) -> io::Result<Self> {
        let (host_events_tx, host_events_rx) = mpsc::channel(CHANNEL_SIZE);
        Self::new_with_channels(config, to_guest_tx, wake_tx, host_events_tx, host_events_rx)
    }

    pub fn new_with_channels(
        config: SmoltcpProxyConfig,
        to_guest_tx: mpsc::Sender<Bytes>,
        wake_tx: mpsc::Sender<()>,
        host_events_tx: mpsc::Sender<HostEvent>,
        host_events_rx: mpsc::Receiver<HostEvent>,
    ) -> io::Result<Self> {

        // Create the device first - it will be used throughout
        let mut device = ProxyDevice::new();

        // Create smoltcp interface with the device
        let iface_config = smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ethernet(
            config.gateway_mac,
        ));

        let mut iface = Interface::new(iface_config, &mut device, SmoltcpInstant::from_millis(0));

        iface.set_any_ip(true);
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::from(config.gateway_ip), 24))
                .expect("failed to add IP address");
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(config.gateway_ip)
            .expect("failed to add default route");

        let sockets = SocketSet::new(vec![]);

        Ok(Self {
            iface,
            sockets,
            device,
            to_guest_tx,
            host_events_tx,
            host_events_rx,
            wake_tx,
            next_conn_id: 0,
            tcp_connections: HashMap::new(),
            tcp_nat: HashMap::new(),
            next_flow_id: 0,
            udp_flows: HashMap::new(),
            udp_nat: HashMap::new(),
            unix_inbound: HashMap::new(),
            next_ephemeral_port: 49152, // Start of ephemeral port range
            start_time: Instant::now(),
            config,
        })
    }

    /// Get the next ephemeral port for outbound connections from the proxy.
    fn get_ephemeral_port(&mut self) -> u16 {
        let port = self.next_ephemeral_port;
        self.next_ephemeral_port = self.next_ephemeral_port.wrapping_add(1);
        if self.next_ephemeral_port < 49152 {
            self.next_ephemeral_port = 49152;
        }
        port
    }

    fn timestamp(&self) -> SmoltcpInstant {
        SmoltcpInstant::from_millis(self.start_time.elapsed().as_millis() as i64)
    }

    /// Try to intercept a new TCP connection from the guest.
    fn try_intercept_tcp(&mut self, packet: &[u8]) -> bool {
        let Some(eth) = EthernetPacket::new(packet) else {
            return false;
        };
        let Some(ipv4) = Ipv4Packet::new(eth.payload()) else {
            return false;
        };

        if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
            return false;
        }

        let Some(tcp) = TcpPacket::new(ipv4.payload()) else {
            return false;
        };

        // Only intercept SYN (new connection)
        if tcp.get_flags() != TcpFlags::SYN {
            return false;
        }

        let src_ip = IpAddress::from(ipv4.get_source());
        let dst_ip = IpAddress::from(ipv4.get_destination());
        let src_port = tcp.get_source();
        let dst_port = tcp.get_destination();

        let guest_endpoint = IpEndpoint::new(src_ip, src_port);
        let host_addr: SocketAddr = match dst_ip {
            IpAddress::Ipv4(ip) => (std::net::Ipv4Addr::from(ip), dst_port).into(),
            IpAddress::Ipv6(ip) => (std::net::Ipv6Addr::from(ip), dst_port).into(),
        };

        // Check if we already have a connection for this guest endpoint
        // (this handles SYN retransmits - let smoltcp process them)
        if let Some(&conn_id) = self.tcp_nat.get(&guest_endpoint) {
            debug!(
                "TCP SYN retransmit for existing connection {}: {} -> {}",
                conn_id, guest_endpoint, host_addr
            );
            // Return false to let smoltcp process the retransmitted SYN
            return false;
        }

        debug!(
            "intercepting NEW TCP SYN: {} -> {}",
            guest_endpoint, host_addr
        );

        let conn_id = self.next_conn_id;
        self.next_conn_id += 1;

        // Create smoltcp socket for the guest side
        // 64KB is the max TCP window without scaling, keep it safe for smoltcp
        let rx_buffer = smoltcp_tcp::SocketBuffer::new(vec![0; 65535]);
        let tx_buffer = smoltcp_tcp::SocketBuffer::new(vec![0; 65535]);
        let mut socket = smoltcp_tcp::Socket::new(rx_buffer, tx_buffer);

        // Set socket options like the old proxy does
        socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(28)));
        socket.set_timeout(Some(smoltcp::time::Duration::from_secs(7200)));

        // Listen on the specific destination IP and port (matching old proxy behavior)
        let listen_endpoint = IpEndpoint::new(dst_ip, dst_port);
        debug!(
            "TCP {}: calling socket.listen on {:?}",
            conn_id, listen_endpoint
        );
        socket
            .listen(listen_endpoint)
            .expect("failed to listen on smoltcp socket");
        debug!(
            "TCP {}: listen_endpoint={}",
            conn_id,
            socket.listen_endpoint()
        );

        let smoltcp_handle = self.sockets.add(socket);

        let (cmd_tx, cmd_rx) = mpsc::channel::<HostCommand>(512);

        // Spawn host connection task
        let host_events_tx = self.host_events_tx.clone();
        let wake_tx = self.wake_tx.clone();
        tokio::task::spawn_local(Self::host_tcp_task(
            conn_id,
            host_addr,
            host_events_tx,
            wake_tx,
            cmd_rx,
        ));

        self.tcp_connections.insert(
            conn_id,
            TcpConnection {
                smoltcp_handle,
                cmd_tx,
                guest_endpoint,
                host_endpoint: host_addr,
                state: TcpConnectionState::Connecting,
                pending_data: VecDeque::new(),
                pending_host_send: None,
            },
        );
        self.tcp_nat.insert(guest_endpoint, conn_id);

        // Return false like the old proxy does - let the SYN packet go to smoltcp
        // so it can respond with SYN-ACK. The socket is already listening.
        false
    }

    /// Try to intercept a UDP packet from the guest.
    fn try_intercept_udp(&mut self, packet: &[u8]) -> bool {
        let Some(eth) = EthernetPacket::new(packet) else {
            return false;
        };
        let Some(ipv4) = Ipv4Packet::new(eth.payload()) else {
            return false;
        };

        if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
            return false;
        }

        let Some(udp) = UdpPacket::new(ipv4.payload()) else {
            return false;
        };

        let src_ip = IpAddress::from(ipv4.get_source());
        let dst_ip = IpAddress::from(ipv4.get_destination());
        let src_port = udp.get_source();
        let dst_port = udp.get_destination();

        let guest_endpoint = IpEndpoint::new(src_ip, src_port);
        let host_addr: SocketAddr = match dst_ip {
            IpAddress::Ipv4(ip) => (std::net::Ipv4Addr::from(ip), dst_port).into(),
            IpAddress::Ipv6(ip) => (std::net::Ipv6Addr::from(ip), dst_port).into(),
        };

        debug!(
            "UDP packet from guest: {} -> {} ({} bytes payload)",
            guest_endpoint,
            host_addr,
            udp.payload().len()
        );

        // Check if we already have a flow for this guest endpoint
        if let Some(&flow_id) = self.udp_nat.get(&guest_endpoint) {
            // Update activity time and send packet
            if let Some(flow) = self.udp_flows.get_mut(&flow_id) {
                flow.last_activity = Instant::now();
                let payload = Bytes::copy_from_slice(udp.payload());
                debug!(
                    "UDP flow {} reused: sending {} bytes to {}",
                    flow_id,
                    payload.len(),
                    host_addr
                );
                match flow.cmd_tx.try_send(UdpHostCommand::Send {
                    data: payload,
                    dest: host_addr,
                }) {
                    Ok(_) => debug!("UDP flow {} command sent successfully", flow_id),
                    Err(e) => error!("UDP flow {} command send failed: {}", flow_id, e),
                }
            } else {
                warn!(
                    "UDP NAT entry for {} points to missing flow {}",
                    guest_endpoint, flow_id
                );
            }
            return true;
        }

        debug!(
            "creating NEW UDP flow: {} -> {} (port {})",
            guest_endpoint, host_addr, dst_port
        );

        let flow_id = self.next_flow_id;
        self.next_flow_id += 1;

        // Create smoltcp UDP socket for the guest side
        let rx_buffer = smoltcp_udp::PacketBuffer::new(
            vec![smoltcp_udp::PacketMetadata::EMPTY; 64],
            vec![0; 65535],
        );
        let tx_buffer = smoltcp_udp::PacketBuffer::new(
            vec![smoltcp_udp::PacketMetadata::EMPTY; 64],
            vec![0; 65535],
        );
        let mut socket = smoltcp_udp::Socket::new(rx_buffer, tx_buffer);

        // Bind to any IP (since we use any_ip mode) with the destination port
        socket
            .bind(IpEndpoint::new(dst_ip, dst_port))
            .expect("failed to bind smoltcp UDP socket");

        let smoltcp_handle = self.sockets.add(socket);

        let (cmd_tx, cmd_rx) = mpsc::channel::<UdpHostCommand>(512);

        // Spawn host UDP task
        let host_events_tx = self.host_events_tx.clone();
        let wake_tx = self.wake_tx.clone();
        debug!("UDP flow {}: spawning host task", flow_id);
        tokio::task::spawn_local(Self::host_udp_task(
            flow_id,
            host_events_tx,
            wake_tx,
            cmd_rx,
        ));

        // Send the first packet
        let payload = Bytes::copy_from_slice(udp.payload());
        debug!(
            "UDP flow {}: sending initial {} bytes to {}",
            flow_id,
            payload.len(),
            host_addr
        );
        match cmd_tx.try_send(UdpHostCommand::Send {
            data: payload,
            dest: host_addr,
        }) {
            Ok(_) => debug!("UDP flow {}: initial command sent", flow_id),
            Err(e) => error!("UDP flow {}: initial command failed: {}", flow_id, e),
        }

        self.udp_flows.insert(
            flow_id,
            UdpFlow {
                smoltcp_handle,
                cmd_tx,
                guest_endpoint,
                last_activity: Instant::now(),
            },
        );
        self.udp_nat.insert(guest_endpoint, flow_id);

        debug!(
            "UDP flow {} created: guest={}, smoltcp_handle={:?}",
            flow_id, guest_endpoint, smoltcp_handle
        );

        true
    }

    async fn host_udp_task(
        flow_id: u64,
        events_tx: mpsc::Sender<HostEvent>,
        wake_tx: mpsc::Sender<()>,
        mut cmd_rx: mpsc::Receiver<UdpHostCommand>,
    ) {
        debug!("UDP host task {}: starting", flow_id);

        // Create an unbound UDP socket that can send to any destination
        let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => {
                debug!("UDP host task {}: bound to {:?}", flow_id, s.local_addr());
                s
            }
            Err(e) => {
                error!("UDP host task {}: failed to bind socket: {e}", flow_id);
                let _ = events_tx.send(HostEvent::UdpClosed { flow_id }).await;
                let _ = wake_tx.try_send(());
                return;
            }
        };

        let mut buf = vec![0u8; 65535];

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((n, from)) => {
                            debug!(
                                "UDP host task {}: received {} bytes from {}",
                                flow_id, n, from
                            );
                            let data = Bytes::copy_from_slice(&buf[..n]);
                            match events_tx.send(HostEvent::UdpData { flow_id, data }).await {
                                Ok(_) => {
                                    debug!("UDP host task {}: sent UdpData event", flow_id);
                                    // Wake the worker to process this event
                                    let _ = wake_tx.try_send(());
                                }
                                Err(e) => error!("UDP host task {}: failed to send event: {}", flow_id, e),
                            }
                        }
                        Err(e) => {
                            error!("UDP host task {}: recv error: {e}", flow_id);
                            let _ = events_tx.send(HostEvent::UdpClosed { flow_id }).await;
                            let _ = wake_tx.try_send(());
                            break;
                        }
                    }
                }

                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        UdpHostCommand::Send { data, dest } => {
                            debug!(
                                "UDP host task {}: sending {} bytes to {}",
                                flow_id,
                                data.len(),
                                dest
                            );
                            match socket.send_to(&data, dest).await {
                                Ok(n) => debug!("UDP host task {}: sent {} bytes", flow_id, n),
                                Err(e) => error!("UDP host task {}: send error: {e}", flow_id),
                            }
                        }
                        UdpHostCommand::Close => {
                            debug!("UDP host task {}: received Close command", flow_id);
                            break;
                        }
                    }
                }

                // Timeout after 30 seconds of no activity
                _ = tokio::time::sleep(Duration::from_secs(30)) => {
                    debug!("UDP host task {}: idle timeout (30s)", flow_id);
                    let _ = events_tx.send(HostEvent::UdpClosed { flow_id }).await;
                    let _ = wake_tx.try_send(());
                    break;
                }
            }
        }

        debug!("UDP host task {}: exiting", flow_id);
    }

    async fn host_tcp_task(
        conn_id: u64,
        addr: SocketAddr,
        events_tx: mpsc::Sender<HostEvent>,
        wake_tx: mpsc::Sender<()>,
        mut cmd_rx: mpsc::Receiver<HostCommand>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let stream = match tokio::net::TcpStream::connect(addr).await {
            Ok(s) => s,
            Err(e) => {
                let _ = events_tx
                    .send(HostEvent::TcpFailed {
                        conn_id,
                        error: e.to_string(),
                    })
                    .await;
                let _ = wake_tx.try_send(());
                return;
            }
        };

        let _ = events_tx.send(HostEvent::TcpConnected { conn_id }).await;
        let _ = wake_tx.try_send(());

        let (mut reader, mut writer) = stream.into_split();
        let mut buf = vec![0u8; 65535];

        loop {
            tokio::select! {
                result = reader.read(&mut buf) => {
                    match result {
                        Ok(0) => {
                            let _ = events_tx.send(HostEvent::TcpClosed { conn_id }).await;
                            let _ = wake_tx.try_send(());
                            break;
                        }
                        Ok(n) => {
                            let data = Bytes::copy_from_slice(&buf[..n]);
                            let _ = events_tx.send(HostEvent::TcpData { conn_id, data }).await;
                            let _ = wake_tx.try_send(());
                        }
                        Err(e) => {
                            error!("TCP read error: {e}");
                            let _ = events_tx.send(HostEvent::TcpClosed { conn_id }).await;
                            let _ = wake_tx.try_send(());
                            break;
                        }
                    }
                }

                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        HostCommand::Send(data) => {
                            if let Err(e) = writer.write_all(&data).await {
                                trace!("TCP write error: {e}");
                                break;
                            }
                            // Wake main loop so it can send more data if backpressured
                            let _ = wake_tx.try_send(());
                        }
                        HostCommand::Close => break,
                    }
                }
            }
        }
    }

    fn process_host_events(&mut self) {
        while let Ok(event) = self.host_events_rx.try_recv() {
            match event {
                HostEvent::TcpConnected { conn_id } => {
                    if let Some(conn) = self.tcp_connections.get_mut(&conn_id) {
                        debug!("TCP {} established to {}", conn_id, conn.host_endpoint);
                        conn.state = TcpConnectionState::Established;
                    }
                }
                HostEvent::TcpFailed { conn_id, error } => {
                    warn!("TCP {} failed: {}", conn_id, error);
                    self.close_tcp_connection(conn_id);
                }
                HostEvent::TcpData { conn_id, data } => {
                    trace!(
                        "process_host_events: TcpData for conn {}, {} bytes",
                        conn_id,
                        data.len()
                    );
                    if let Some(conn) = self.tcp_connections.get_mut(&conn_id) {
                        // Add new data to pending buffer
                        conn.pending_data.push_back(data);

                        // Try to drain pending data to smoltcp
                        let socket = self
                            .sockets
                            .get_mut::<smoltcp_tcp::Socket>(conn.smoltcp_handle);

                        loop {
                            if !socket.can_send() {
                                trace!(
                                    "TCP {}: smoltcp buffer full, {} chunks pending",
                                    conn_id,
                                    conn.pending_data.len()
                                );
                                break;
                            }

                            let Some(chunk) = conn.pending_data.pop_front() else {
                                break;
                            };

                            match socket.send_slice(&chunk) {
                                Ok(sent) if sent == chunk.len() => {
                                    // Sent entire chunk, continue to next
                                }
                                Ok(sent) => {
                                    // Partial send - keep remaining bytes at front
                                    let remaining = chunk.slice(sent..);
                                    conn.pending_data.push_front(remaining);
                                    trace!(
                                        "TCP {}: partial send {}/{} bytes",
                                        conn_id,
                                        sent,
                                        chunk.len()
                                    );
                                    break;
                                }
                                Err(e) => {
                                    // Put chunk back and stop
                                    conn.pending_data.push_front(chunk);
                                    error!("TCP {}: smoltcp send error: {e}", conn_id);
                                    break;
                                }
                            }
                        }
                    } else {
                        warn!("TCP {}: connection not found for TcpData", conn_id);
                    }
                }
                HostEvent::TcpClosed { conn_id } => {
                    debug!("TCP {} closed by host", conn_id);
                    self.close_tcp_connection(conn_id);
                }
                HostEvent::UdpData { flow_id, data } => {
                    debug!(
                        "process_host_events: UdpData for flow {}, {} bytes",
                        flow_id,
                        data.len()
                    );
                    if let Some(flow) = self.udp_flows.get_mut(&flow_id) {
                        flow.last_activity = Instant::now();
                        let guest_endpoint = flow.guest_endpoint;
                        let socket = self
                            .sockets
                            .get_mut::<smoltcp_udp::Socket>(flow.smoltcp_handle);
                        // Send response back to guest (the flow's guest_endpoint)
                        debug!(
                            "UDP flow {}: smoltcp socket can_send={}, sending to {}",
                            flow_id,
                            socket.can_send(),
                            guest_endpoint
                        );
                        if socket.can_send() {
                            match socket.send_slice(&data, guest_endpoint) {
                                Ok(()) => debug!(
                                    "UDP flow {}: queued {} bytes to smoltcp for {}",
                                    flow_id,
                                    data.len(),
                                    guest_endpoint
                                ),
                                Err(e) => error!("UDP flow {}: smoltcp send error: {e}", flow_id),
                            }
                        } else {
                            trace!(
                                "UDP flow {}: smoltcp socket cannot send (backpressure)",
                                flow_id
                            );
                        }
                    } else {
                        warn!("process_host_events: UdpData for unknown flow {}", flow_id);
                    }
                }
                HostEvent::UdpClosed { flow_id } => {
                    debug!("process_host_events: UdpClosed for flow {}", flow_id);
                    self.close_udp_flow(flow_id);
                }
                HostEvent::UnixAccepted {
                    conn_id,
                    vm_port,
                    stream,
                } => {
                    debug!(
                        "Unix connection {} accepted, forwarding to VM port {}",
                        conn_id, vm_port
                    );
                    self.handle_unix_accept(conn_id, vm_port, stream);
                }
                HostEvent::UnixData { conn_id, data } => {
                    trace!(
                        "Unix connection {}: received {} bytes from host",
                        conn_id,
                        data.len()
                    );
                    if let Some(conn) = self.unix_inbound.get_mut(&conn_id) {
                        conn.pending_to_vm.push_back(data);

                        // Try to send to smoltcp
                        let socket = self
                            .sockets
                            .get_mut::<smoltcp_tcp::Socket>(conn.smoltcp_handle);

                        loop {
                            if !socket.can_send() {
                                break;
                            }

                            let Some(chunk) = conn.pending_to_vm.pop_front() else {
                                break;
                            };

                            match socket.send_slice(&chunk) {
                                Ok(sent) if sent == chunk.len() => {}
                                Ok(sent) => {
                                    let remaining = chunk.slice(sent..);
                                    conn.pending_to_vm.push_front(remaining);
                                    break;
                                }
                                Err(e) => {
                                    conn.pending_to_vm.push_front(chunk);
                                    error!("Unix {}: smoltcp send error: {e}", conn_id);
                                    break;
                                }
                            }
                        }
                    }
                }
                HostEvent::UnixClosed { conn_id } => {
                    debug!("Unix connection {} closed by host", conn_id);
                    self.close_unix_connection(conn_id);
                }
            }
        }
    }

    fn close_tcp_connection(&mut self, conn_id: u64) {
        if let Some(conn) = self.tcp_connections.remove(&conn_id) {
            let socket = self
                .sockets
                .get_mut::<smoltcp_tcp::Socket>(conn.smoltcp_handle);
            socket.close();
            self.tcp_nat.remove(&conn.guest_endpoint);
            let _ = conn.cmd_tx.try_send(HostCommand::Close);
        }
    }

    fn close_udp_flow(&mut self, flow_id: u64) {
        debug!("close_udp_flow: closing flow {}", flow_id);
        if let Some(flow) = self.udp_flows.remove(&flow_id) {
            debug!(
                "close_udp_flow: flow {} removed, guest_endpoint={}",
                flow_id, flow.guest_endpoint
            );
            let socket = self
                .sockets
                .get_mut::<smoltcp_udp::Socket>(flow.smoltcp_handle);
            socket.close();
            self.udp_nat.remove(&flow.guest_endpoint);
            let _ = flow.cmd_tx.try_send(UdpHostCommand::Close);
        } else {
            warn!("close_udp_flow: flow {} not found", flow_id);
        }
    }

    /// Handle a new Unix socket connection by creating a smoltcp TCP connection to the VM.
    fn handle_unix_accept(&mut self, conn_id: u64, vm_port: u16, stream: UnixStream) {
        // Create smoltcp TCP socket to connect to VM
        let rx_buffer = smoltcp_tcp::SocketBuffer::new(vec![0; 65535]);
        let tx_buffer = smoltcp_tcp::SocketBuffer::new(vec![0; 65535]);
        let mut socket = smoltcp_tcp::Socket::new(rx_buffer, tx_buffer);

        // The remote endpoint is the VM's IP and port
        let remote_endpoint = IpEndpoint::new(IpAddress::from(self.config.vm_ip), vm_port);
        let local_port = self.get_ephemeral_port();

        // Initiate connection to VM
        if let Err(e) = socket.connect(
            self.iface.context(),
            remote_endpoint,
            smoltcp::wire::IpListenEndpoint {
                port: local_port,
                addr: Some(IpAddress::from(self.config.gateway_ip)),
            },
        ) {
            error!(
                "Unix {}: failed to connect smoltcp socket to VM: {}",
                conn_id, e
            );
            return;
        }

        let smoltcp_handle = self.sockets.add(socket);

        // Create channel for sending data to Unix socket
        let (cmd_tx, cmd_rx) = mpsc::channel::<HostCommand>(512);

        // Spawn task to handle Unix socket I/O
        let events_tx = self.host_events_tx.clone();
        let wake_tx = self.wake_tx.clone();
        tokio::task::spawn_local(Self::unix_socket_task(
            conn_id,
            stream,
            events_tx,
            wake_tx,
            cmd_rx,
        ));

        // Track the connection
        self.unix_inbound.insert(
            conn_id,
            UnixInboundConnection {
                smoltcp_handle,
                cmd_tx,
                vm_port,
                state: UnixInboundState::Connecting,
                pending_to_vm: VecDeque::new(),
                pending_to_unix: None,
            },
        );

        debug!(
            "Unix {}: created smoltcp connection to VM {}:{}",
            conn_id, self.config.vm_ip, vm_port
        );
    }

    /// Task to handle Unix socket I/O.
    async fn unix_socket_task(
        conn_id: u64,
        stream: UnixStream,
        events_tx: mpsc::Sender<HostEvent>,
        wake_tx: mpsc::Sender<()>,
        mut cmd_rx: mpsc::Receiver<HostCommand>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut reader, mut writer) = stream.into_split();
        let mut buf = vec![0u8; 65535];

        loop {
            tokio::select! {
                result = reader.read(&mut buf) => {
                    match result {
                        Ok(0) => {
                            let _ = events_tx.send(HostEvent::UnixClosed { conn_id }).await;
                            let _ = wake_tx.try_send(());
                            break;
                        }
                        Ok(n) => {
                            let data = Bytes::copy_from_slice(&buf[..n]);
                            let _ = events_tx.send(HostEvent::UnixData { conn_id, data }).await;
                            let _ = wake_tx.try_send(());
                        }
                        Err(e) => {
                            error!("Unix {} read error: {e}", conn_id);
                            let _ = events_tx.send(HostEvent::UnixClosed { conn_id }).await;
                            let _ = wake_tx.try_send(());
                            break;
                        }
                    }
                }

                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        HostCommand::Send(data) => {
                            if let Err(e) = writer.write_all(&data).await {
                                trace!("Unix {} write error: {e}", conn_id);
                                break;
                            }
                            let _ = wake_tx.try_send(());
                        }
                        HostCommand::Close => break,
                    }
                }
            }
        }
    }

    fn close_unix_connection(&mut self, conn_id: u64) {
        if let Some(conn) = self.unix_inbound.remove(&conn_id) {
            let socket = self
                .sockets
                .get_mut::<smoltcp_tcp::Socket>(conn.smoltcp_handle);
            socket.close();
            let _ = conn.cmd_tx.try_send(HostCommand::Close);
        }
    }

    fn process_sockets(&mut self) {
        let conn_ids: Vec<u64> = self.tcp_connections.keys().copied().collect();

        for conn_id in conn_ids {
            let Some(conn) = self.tcp_connections.get_mut(&conn_id) else {
                continue;
            };

            let socket = self
                .sockets
                .get_mut::<smoltcp_tcp::Socket>(conn.smoltcp_handle);

            // Log socket state periodically for debugging
            let state = socket.state();
            if state != smoltcp_tcp::State::Established && state != smoltcp_tcp::State::Listen {
                trace!(
                    "process_sockets: TCP {} state={}, can_recv={}, can_send={}",
                    conn_id,
                    state,
                    socket.can_recv(),
                    socket.can_send()
                );
            }

            // Try to drain pending data to smoltcp (handles backpressure)
            loop {
                if !socket.can_send() {
                    break;
                }

                let Some(chunk) = conn.pending_data.pop_front() else {
                    break;
                };

                match socket.send_slice(&chunk) {
                    Ok(sent) if sent == chunk.len() => {
                        // Sent entire chunk, continue
                    }
                    Ok(sent) if sent > 0 => {
                        let remaining = chunk.slice(sent..);
                        conn.pending_data.push_front(remaining);
                        break;
                    }
                    Ok(_) => {
                        conn.pending_data.push_front(chunk);
                        break;
                    }
                    Err(_) => {
                        conn.pending_data.push_front(chunk);
                        break;
                    }
                }
            }

            // Try to drain pending_host_send first (backpressure handling)
            if let Some(pending) = conn.pending_host_send.take() {
                match conn.cmd_tx.try_send(HostCommand::Send(pending)) {
                    Ok(_) => {
                        trace!("TCP {}: drained pending host send", conn_id);
                    }
                    Err(mpsc::error::TrySendError::Full(HostCommand::Send(data))) => {
                        // Still full, put it back
                        conn.pending_host_send = Some(data);
                    }
                    Err(_) => {
                        // Channel closed, will be cleaned up
                    }
                }
            }

            // Only read from smoltcp if we don't have pending data (backpressure)
            // If pending_host_send is Some, we wait until host drains the channel
            if conn.pending_host_send.is_none() && socket.can_recv() {
                let mut buf = vec![0u8; 65535];
                match socket.recv_slice(&mut buf) {
                    Ok(n) if n > 0 => {
                        trace!(
                            "process_sockets: TCP {} received {} bytes from guest, forwarding to host",
                            conn_id, n
                        );
                        let data = Bytes::copy_from_slice(&buf[..n]);
                        match conn.cmd_tx.try_send(HostCommand::Send(data)) {
                            Ok(_) => {}
                            Err(mpsc::error::TrySendError::Full(HostCommand::Send(data))) => {
                                // Channel full - store for later, don't read more until drained
                                // This causes smoltcp to stop ACKing, shrinking TCP window
                                trace!("TCP {}: host channel full, applying backpressure", conn_id);
                                conn.pending_host_send = Some(data);
                            }
                            Err(_) => {
                                // Channel closed
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        trace!("TCP {}: recv_slice error: {}", conn_id, e);
                    }
                }
            }

            if socket.state() == smoltcp_tcp::State::Closed {
                trace!("process_sockets: TCP {} smoltcp socket closed", conn_id);
            }
        }

        // Process Unix inbound connections (host Unix socket -> VM)
        let unix_conn_ids: Vec<u64> = self.unix_inbound.keys().copied().collect();

        for conn_id in unix_conn_ids {
            let Some(conn) = self.unix_inbound.get_mut(&conn_id) else {
                continue;
            };

            let socket = self
                .sockets
                .get_mut::<smoltcp_tcp::Socket>(conn.smoltcp_handle);

            // Check if connection is established
            if conn.state == UnixInboundState::Connecting
                && socket.state() == smoltcp_tcp::State::Established
            {
                debug!("Unix {}: connection to VM established", conn_id);
                conn.state = UnixInboundState::Established;
            }

            // Try to drain pending data to smoltcp (host -> VM)
            loop {
                if !socket.can_send() {
                    break;
                }

                let Some(chunk) = conn.pending_to_vm.pop_front() else {
                    break;
                };

                match socket.send_slice(&chunk) {
                    Ok(sent) if sent == chunk.len() => {}
                    Ok(sent) => {
                        let remaining = chunk.slice(sent..);
                        conn.pending_to_vm.push_front(remaining);
                        break;
                    }
                    Err(e) => {
                        conn.pending_to_vm.push_front(chunk);
                        error!("Unix {}: smoltcp send error: {e}", conn_id);
                        break;
                    }
                }
            }

            // Try to drain pending_to_unix first (backpressure handling)
            if let Some(pending) = conn.pending_to_unix.take() {
                match conn.cmd_tx.try_send(HostCommand::Send(pending)) {
                    Ok(_) => {
                        trace!("Unix {}: drained pending unix send", conn_id);
                    }
                    Err(mpsc::error::TrySendError::Full(HostCommand::Send(data))) => {
                        conn.pending_to_unix = Some(data);
                    }
                    Err(_) => {}
                }
            }

            // Read from smoltcp (VM -> Unix socket)
            if conn.pending_to_unix.is_none() && socket.can_recv() {
                let mut buf = vec![0u8; 65535];
                match socket.recv_slice(&mut buf) {
                    Ok(n) if n > 0 => {
                        trace!(
                            "Unix {}: received {} bytes from VM, forwarding to unix socket",
                            conn_id, n
                        );
                        let data = Bytes::copy_from_slice(&buf[..n]);
                        match conn.cmd_tx.try_send(HostCommand::Send(data)) {
                            Ok(_) => {}
                            Err(mpsc::error::TrySendError::Full(HostCommand::Send(data))) => {
                                trace!("Unix {}: unix channel full, applying backpressure", conn_id);
                                conn.pending_to_unix = Some(data);
                            }
                            Err(_) => {}
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        trace!("Unix {}: recv_slice error: {}", conn_id, e);
                    }
                }
            }

            // Check for closed connection
            if socket.state() == smoltcp_tcp::State::Closed {
                trace!("Unix {}: smoltcp socket closed", conn_id);
            }
        }
    }

    fn flush_tx(&mut self) {
        let packets = self.device.take_tx();
        if !packets.is_empty() {
            debug!("flush_tx: {} packets to send to guest", packets.len());
        }
        for packet in packets {
            debug!("flush_tx: sending {} byte packet to guest", packet.len());
            if self.to_guest_tx.try_send(packet).is_err() {
                warn!("to_guest channel full, dropping packet");
            }
        }
    }
}

impl AsyncNetBackend for SmoltcpProxyBackend {
    fn handle_guest_tx(&mut self, packet: &[u8]) {
        // Log packet details for debugging
        if let Some(eth) = EthernetPacket::new(packet) {
            debug!(
                "handle_guest_tx: Ethernet {} -> {}",
                eth.get_source(),
                eth.get_destination()
            );
            if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                let proto = ipv4.get_next_level_protocol();
                if proto == IpNextHeaderProtocols::Tcp {
                    if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                        debug!(
                            "handle_guest_tx: TCP packet {}:{} -> {}:{} flags={:#x}",
                            ipv4.get_source(),
                            tcp.get_source(),
                            ipv4.get_destination(),
                            tcp.get_destination(),
                            tcp.get_flags()
                        );
                    }
                }
            }
        }

        // Try to intercept new TCP connections or UDP packets
        // TCP returns false even for new SYN (like old proxy) - packet goes to smoltcp
        // UDP returns true - packet is fully handled, not queued to smoltcp
        let tcp_intercepted = self.try_intercept_tcp(packet);
        let udp_intercepted = self.try_intercept_udp(packet);

        // Only queue non-intercepted packets to smoltcp (matching old proxy behavior)
        let packet_was_intercepted = tcp_intercepted || udp_intercepted;
        if !packet_was_intercepted {
            debug!("Packet not intercepted, queueing to smoltcp");
            self.device.queue_rx(Bytes::copy_from_slice(packet));
        }

        // Log TCP socket states before poll
        for (conn_id, conn) in &self.tcp_connections {
            let socket = self.sockets.get::<smoltcp_tcp::Socket>(conn.smoltcp_handle);
            debug!(
                "before poll: TCP {} state={}, listen_endpoint={}, local={:?}, remote={:?}",
                conn_id,
                socket.state(),
                socket.listen_endpoint(),
                socket.local_endpoint(),
                socket.remote_endpoint()
            );
        }

        // Process all queued packets with smoltcp
        let timestamp = self.timestamp();
        let poll_result = self
            .iface
            .poll(timestamp, &mut self.device, &mut self.sockets);
        debug!("iface.poll() result: {:?}", poll_result);

        // Log TCP socket states after poll
        for (conn_id, conn) in &self.tcp_connections {
            let socket = self.sockets.get::<smoltcp_tcp::Socket>(conn.smoltcp_handle);
            debug!(
                "after poll: TCP {} state={}, listen_endpoint={}, local={:?}, remote={:?}",
                conn_id,
                socket.state(),
                socket.listen_endpoint(),
                socket.local_endpoint(),
                socket.remote_endpoint()
            );
        }

        self.process_host_events();
        self.process_sockets();

        // Poll again to transmit any responses we wrote to sockets
        let timestamp = self.timestamp();
        self.iface
            .poll(timestamp, &mut self.device, &mut self.sockets);

        self.flush_tx();
    }

    fn poll(&mut self) {
        let timestamp = self.timestamp();
        self.iface
            .poll(timestamp, &mut self.device, &mut self.sockets);

        self.process_host_events();
        self.process_sockets();

        // Poll again to transmit any responses we wrote to sockets
        let timestamp = self.timestamp();
        self.iface
            .poll(timestamp, &mut self.device, &mut self.sockets);

        self.flush_tx();
    }

    fn poll_delay(&mut self) -> Option<Duration> {
        // If any connection has pending data to send, poll quickly to retry
        let has_pending_tcp = self
            .tcp_connections
            .values()
            .any(|conn| conn.pending_host_send.is_some());

        let has_pending_unix = self
            .unix_inbound
            .values()
            .any(|conn| conn.pending_to_unix.is_some() || !conn.pending_to_vm.is_empty());

        if has_pending_tcp || has_pending_unix {
            // Retry quickly when backpressured
            return Some(Duration::from_micros(100));
        }

        let timestamp = self.timestamp();
        self.iface
            .poll_delay(timestamp, &self.sockets)
            .map(|d| Duration::from_millis(d.total_millis() as u64))
    }

    fn on_exit(&mut self) {
        let conn_ids: Vec<u64> = self.tcp_connections.keys().copied().collect();
        for conn_id in conn_ids {
            self.close_tcp_connection(conn_id);
        }
        let flow_ids: Vec<u64> = self.udp_flows.keys().copied().collect();
        for flow_id in flow_ids {
            self.close_udp_flow(flow_id);
        }
    }
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(long, default_value = "examples/rootfs_debian")]
    rootfs: String,

    /// Unix socket listener mapping (format: /path/to/socket:vm_port)
    /// Example: --unix-listener /tmp/vm.sock:8080
    #[arg(long = "unix-listener", value_name = "PATH:PORT")]
    unix_listeners: Vec<String>,

    command: Vec<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let (non_blocking, _guard) = tracing_appender::non_blocking(std::io::stdout());
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(non_blocking)
                .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE),
        )
        .with(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    let mut builder = krun::Builder::new();

    builder.set_root(&cli.rootfs);

    builder.vm_config(2, 1024);

    let mut command = cli.command.clone();

    let (exec_path, args) = if command.is_empty() {
        ("/usr/bin/bash".to_string(), None)
    } else {
        (
            command.remove(0),
            if command.is_empty() {
                None
            } else {
                Some(command.join(" "))
            },
        )
    };

    println!("using exec path: {exec_path} and args {:?}", args);

    builder.exec_path(exec_path);
    if let Some(args) = args {
        builder.args(args);
    }

    // Parse Unix socket listeners from CLI
    let mut unix_listeners = HashMap::new();
    for listener_spec in &cli.unix_listeners {
        // Format: /path/to/socket:port
        if let Some((path, port_str)) = listener_spec.rsplit_once(':') {
            match port_str.parse::<u16>() {
                Ok(port) => {
                    println!("Adding Unix socket listener: {} -> VM port {}", path, port);
                    unix_listeners.insert(port, PathBuf::from(path));
                }
                Err(e) => {
                    eprintln!("Invalid port in '{}': {}", listener_spec, e);
                }
            }
        } else {
            eprintln!("Invalid listener format '{}', expected /path:port", listener_spec);
        }
    }

    builder.add_net_device(
        VirtioNetBackend::CustomAsyncFactory(Box::new(SmoltcpProxyFactory::new(
            SmoltcpProxyConfig {
                vm_mac: EthernetAddress([0xde, 0xad, 0xbe, 0xef, 0x00, 0x00]),
                vm_ip: Ipv4Address::new(192, 168, 100, 2),
                gateway_mac: EthernetAddress([0x02, 0x00, 0x00, 0x01, 0x02, 0x03]),
                gateway_ip: Ipv4Address::new(192, 168, 100, 1),
                unix_listeners,
            },
        ))),
        [0xde, 0xad, 0xbe, 0xef, 0x00, 0x00],
        NET_ALL_FEATURES,
    );

    let ctx = builder.build();

    let ctx_result = tokio::task::spawn_blocking(move || {
        println!("entering krun vm");
        ctx.start_enter()
    })
    .await
    .unwrap();

    info!("VM is done, res: {ctx_result:?}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::Device;

    /// Test that ProxyDevice has correct checksum capabilities.
    ///
    /// This is critical for virtio-net with checksum offloading (VIRTIO_NET_F_CSUM):
    /// - RX: Don't validate checksums (guest sends partial checksums expecting host to complete)
    /// - TX: DO fill checksums (guest validates incoming packets)
    ///
    /// If RX validation is enabled, smoltcp silently drops packets with bad checksums.
    /// If TX filling is disabled, guest rejects our packets (e.g., SYN-ACK) with zero checksums.
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

    #[test]
    fn test_proxy_device_mtu() {
        let device = ProxyDevice::new();
        let caps = device.capabilities();
        assert_eq!(caps.max_transmission_unit, 1500);
    }
}
