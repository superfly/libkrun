//! Backend implementation for the smoltcp proxy.
//!
//! Contains the SmoltcpProxyBackend that handles the NAT/proxy logic.

pub mod tcp;
pub mod udp;
pub mod unix;

pub use tcp::{DeferredConnection, ProxiedTcpFlow, SocketBuffers, TcpConnection, TcpConnectionState};
pub use udp::{UdpFlow, UdpHostCommand};
pub use unix::{UnixInboundConnection, UnixInboundState};

use bytes::Bytes;
use futures::task::{noop_waker_ref, Context as FuturesContext};
use futures::{Future, Stream};
use krun::{AsyncNetBackend, AsyncNetBackendFactory, NetBackendHandle, NetSendBoxFuture};
use log::{debug, error, trace, warn};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use smoltcp::iface::{Interface, SocketSet};
use smoltcp::socket::tcp as smoltcp_tcp;
use smoltcp::socket::udp as smoltcp_udp;
use smoltcp::time::Instant as SmoltcpInstant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv6Address};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{StreamMap, StreamNotifyClose};

use crate::device::ProxyDevice;
use crate::handler::{
    FlowChannels, PacketContext, PacketHandler, PacketVerdict, TransportProtocol,
};
use crate::util::{check_icmp_available, internet_checksum};

/// Channel buffer size for to_guest packets
pub const CHANNEL_SIZE: usize = 256;

/// Default VM MAC address
pub const VM_MAC: EthernetAddress = EthernetAddress([0xde, 0xad, 0xbe, 0xef, 0x00, 0x00]);
/// Default proxy/gateway MAC address
pub const PROXY_MAC: EthernetAddress = EthernetAddress([0x02, 0x00, 0x00, 0x01, 0x02, 0x03]);
/// Default VM IP address
pub const VM_IP: Ipv4Address = Ipv4Address::new(192, 168, 100, 2);
/// Default proxy/gateway IP address
pub const PROXY_IP: Ipv4Address = Ipv4Address::new(192, 168, 100, 1);
/// Default VM IPv6 address
pub const VM_IP6: Ipv6Address = Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
/// Default proxy/gateway IPv6 address
pub const PROXY_IP6: Ipv6Address = Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);

/// Commands sent to host TCP connection tasks.
pub enum HostCommand {
    Send(Bytes),
    Close,
}

/// Messages from host connection tasks to the backend.
pub enum HostEvent {
    TcpData {
        conn_id: u64,
        data: Bytes,
    },
    TcpClosed {
        conn_id: u64,
    },
    TcpConnected {
        conn_id: u64,
    },
    TcpFailed {
        conn_id: u64,
        error: String,
    },
    UdpData {
        flow_id: u64,
        data: Bytes,
    },
    UdpClosed {
        flow_id: u64,
    },
    /// A new connection was accepted on a Unix socket listener
    UnixAccepted {
        conn_id: u64,
        vm_port: u16,
        stream: UnixStream,
    },
    /// Data received from Unix socket (to be sent to VM)
    UnixData {
        conn_id: u64,
        data: Bytes,
    },
    /// Unix socket closed
    UnixClosed {
        conn_id: u64,
    },
    /// ICMP echo reply received from host
    IcmpReply {
        dest_ip: Ipv4Addr,
        source_ip: Ipv4Addr,
        id: u16,
        sequence: u16,
        payload: Bytes,
    },
}

/// Configuration for the smoltcp proxy backend.
pub struct SmoltcpProxyConfig {
    pub vm_mac: EthernetAddress,
    pub vm_ip: Ipv4Address,
    pub vm_ip6: Ipv6Address,
    pub gateway_mac: EthernetAddress,
    pub gateway_ip: Ipv4Address,
    pub gateway_ip6: Ipv6Address,
    /// Unix socket listeners: maps VM port to Unix socket path on host
    pub unix_listeners: HashMap<u16, PathBuf>,
    /// Packet handlers - processed in order before NAT.
    pub handlers: Vec<Arc<dyn PacketHandler>>,
}

impl Default for SmoltcpProxyConfig {
    fn default() -> Self {
        Self {
            vm_mac: VM_MAC,
            vm_ip: VM_IP,
            vm_ip6: VM_IP6,
            gateway_mac: PROXY_MAC,
            gateway_ip: PROXY_IP,
            gateway_ip6: PROXY_IP6,
            unix_listeners: HashMap::new(),
            handlers: Vec::new(),
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
            let mut next_conn_id = 1_000_000u64;
            for (vm_port, socket_path) in &self.config.unix_listeners {
                if socket_path.exists() {
                    if let Err(e) = std::fs::remove_file(socket_path) {
                        error!("Failed to remove existing socket {:?}: {}", socket_path, e);
                    }
                }

                let listener = match UnixListener::bind(socket_path) {
                    Ok(l) => l,
                    Err(e) => {
                        error!("Failed to bind Unix socket {:?}: {}", socket_path, e);
                        continue;
                    }
                };

                debug!(
                    "Unix socket listener started: {:?} -> VM port {}",
                    socket_path, vm_port
                );

                let events_tx = host_events_tx.clone();
                let wake_tx_clone = wake_tx.clone();
                let vm_port = *vm_port;
                let base_conn_id = next_conn_id;
                next_conn_id += 100_000;

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
                                    break;
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

            check_icmp_available();

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

/// Stream type for receiving data from handlers (with close notification).
type HandlerStream = StreamNotifyClose<ReceiverStream<Bytes>>;

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
    next_flow_id: u64,
    udp_flows: HashMap<u64, UdpFlow>,
    udp_nat: HashMap<IpEndpoint, u64>,
    proxied_flows: HashMap<u64, ProxiedTcpFlow>,
    proxied_nat: HashMap<IpEndpoint, u64>,
    /// Streams for receiving data from handlers (properly async polled)
    from_handler_streams: StreamMap<u64, HandlerStream>,
    /// Connections waiting for handler decision (deferred accept)
    deferred_connections: HashMap<u64, DeferredConnection>,
    /// Track endpoints with pending deferred connections (to drop SYN retransmits)
    deferred_endpoints: HashMap<IpEndpoint, u64>,
    unix_inbound: HashMap<u64, UnixInboundConnection>,
    next_ephemeral_port: u16,
    start_time: Instant,
    config: SmoltcpProxyConfig,
    handlers: Vec<Arc<dyn PacketHandler>>,
}

impl SmoltcpProxyBackend {
    #[allow(dead_code)]
    pub fn new(
        config: SmoltcpProxyConfig,
        to_guest_tx: mpsc::Sender<Bytes>,
        wake_tx: mpsc::Sender<()>,
    ) -> io::Result<Self> {
        let (host_events_tx, host_events_rx) = mpsc::channel(CHANNEL_SIZE);
        Self::new_with_channels(config, to_guest_tx, wake_tx, host_events_tx, host_events_rx)
    }

    pub fn new_with_channels(
        mut config: SmoltcpProxyConfig,
        to_guest_tx: mpsc::Sender<Bytes>,
        wake_tx: mpsc::Sender<()>,
        host_events_tx: mpsc::Sender<HostEvent>,
        host_events_rx: mpsc::Receiver<HostEvent>,
    ) -> io::Result<Self> {
        let mut device = ProxyDevice::new();

        let iface_config = smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ethernet(
            config.gateway_mac,
        ));

        let mut iface = Interface::new(iface_config, &mut device, SmoltcpInstant::from_millis(0));

        iface.set_any_ip(true);
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::from(config.gateway_ip), 24))
                .expect("failed to add IPv4 address");
            addrs
                .push(IpCidr::new(IpAddress::from(config.gateway_ip6), 64))
                .expect("failed to add IPv6 address");
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(config.gateway_ip)
            .expect("failed to add default IPv4 route");
        iface
            .routes_mut()
            .add_default_ipv6_route(config.gateway_ip6)
            .expect("failed to add default IPv6 route");

        let sockets = SocketSet::new(vec![]);
        let handlers = std::mem::take(&mut config.handlers);

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
            proxied_flows: HashMap::new(),
            proxied_nat: HashMap::new(),
            from_handler_streams: StreamMap::new(),
            deferred_connections: HashMap::new(),
            deferred_endpoints: HashMap::new(),
            unix_inbound: HashMap::new(),
            next_ephemeral_port: 49152,
            start_time: Instant::now(),
            config,
            handlers,
        })
    }

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

    fn setup_proxied_flow(
        &mut self,
        guest_endpoint: IpEndpoint,
        dst_port: u16,
        channels: FlowChannels,
    ) {
        let (buffers, rx_slice, tx_slice) = SocketBuffers::new(65535);
        let tcp_rx_buf = smoltcp_tcp::SocketBuffer::new(rx_slice);
        let tcp_tx_buf = smoltcp_tcp::SocketBuffer::new(tx_slice);
        let mut socket = smoltcp_tcp::Socket::new(tcp_rx_buf, tcp_tx_buf);

        socket
            .listen(dst_port)
            .expect("failed to listen on proxied port");

        let handle = self.sockets.add(socket);
        let flow_id = self.next_conn_id;
        self.next_conn_id += 1;

        // Add from_handler to StreamMap for proper async polling
        let stream = StreamNotifyClose::new(ReceiverStream::new(channels.from_handler));
        self.from_handler_streams.insert(flow_id, stream);

        self.proxied_flows.insert(
            flow_id,
            ProxiedTcpFlow {
                smoltcp_handle: handle,
                guest_endpoint,
                to_handler: channels.to_handler,
                pending_to_guest: VecDeque::new(),
                pending_to_handler: None,
                buffers,
            },
        );
        self.proxied_nat.insert(guest_endpoint, flow_id);

        debug!(
            "Created proxied flow {} for {} -> port {}",
            flow_id, guest_endpoint, dst_port
        );
    }

    fn setup_deferred_connection(
        &mut self,
        guest_endpoint: IpEndpoint,
        dst_port: u16,
        syn_packet: Bytes,
        decision_rx: tokio::sync::oneshot::Receiver<crate::handler::DeferredFlowDecision>,
    ) {
        let conn_id = self.next_conn_id;
        self.next_conn_id += 1;

        self.deferred_connections.insert(
            conn_id,
            DeferredConnection {
                guest_endpoint,
                dst_port,
                syn_packet,
                decision_rx,
            },
        );
        self.deferred_endpoints.insert(guest_endpoint, conn_id);

        debug!(
            "Created deferred connection {} for {} -> port {}",
            conn_id, guest_endpoint, dst_port
        );
    }

    fn accept_deferred_connection(&mut self, conn_id: u64, channels: FlowChannels) {
        let Some(conn) = self.deferred_connections.remove(&conn_id) else {
            warn!(
                "accept_deferred_connection: connection {} not found",
                conn_id
            );
            return;
        };
        self.deferred_endpoints.remove(&conn.guest_endpoint);

        debug!(
            "Accepting deferred connection {} for {} -> port {}",
            conn_id, conn.guest_endpoint, conn.dst_port
        );

        // Set up the proxied flow
        self.setup_proxied_flow(conn.guest_endpoint, conn.dst_port, channels);

        // Feed the SYN packet to smoltcp to complete the handshake
        self.device.queue_rx(conn.syn_packet);
        let timestamp = self.timestamp();
        self.iface
            .poll(timestamp, &mut self.device, &mut self.sockets);
        self.flush_tx();
    }

    fn reject_deferred_connection(&mut self, conn_id: u64) {
        let Some(conn) = self.deferred_connections.remove(&conn_id) else {
            warn!(
                "reject_deferred_connection: connection {} not found",
                conn_id
            );
            return;
        };
        self.deferred_endpoints.remove(&conn.guest_endpoint);

        debug!(
            "Rejecting deferred connection {} for {} -> port {} with RST",
            conn_id, conn.guest_endpoint, conn.dst_port
        );

        // Build and send a TCP RST packet
        let rst_packet = self.build_tcp_rst_for_syn(&conn.syn_packet);
        if let Some(rst) = rst_packet {
            let _ = self.to_guest_tx.try_send(rst);
        }
    }

    fn build_tcp_rst_for_syn(&self, syn_packet: &[u8]) -> Option<Bytes> {
        // Parse the SYN packet to extract necessary info
        let eth = EthernetPacket::new(syn_packet)?;
        let ipv4 = Ipv4Packet::new(eth.payload())?;
        let tcp = TcpPacket::new(ipv4.payload())?;

        let src_mac = self.config.gateway_mac.0;
        let dst_mac = self.config.vm_mac.0;
        let src_ip = ipv4.get_destination();
        let dst_ip = ipv4.get_source();
        let src_port = tcp.get_destination();
        let dst_port = tcp.get_source();
        let their_seq = tcp.get_sequence();

        // Build RST+ACK response
        let mut rst = vec![0u8; 14 + 20 + 20]; // Eth + IP + TCP

        // Ethernet header
        rst[0..6].copy_from_slice(&dst_mac);
        rst[6..12].copy_from_slice(&src_mac);
        rst[12..14].copy_from_slice(&[0x08, 0x00]); // IPv4

        // IP header
        rst[14] = 0x45; // Version + IHL
        rst[15] = 0x00; // DSCP + ECN
        rst[16..18].copy_from_slice(&40u16.to_be_bytes()); // Total length
        rst[18..20].copy_from_slice(&[0x00, 0x00]); // ID
        rst[20..22].copy_from_slice(&[0x40, 0x00]); // Flags + Fragment
        rst[22] = 64; // TTL
        rst[23] = 6; // Protocol: TCP
        rst[24..26].copy_from_slice(&[0x00, 0x00]); // Checksum placeholder
        rst[26..30].copy_from_slice(&src_ip.octets());
        rst[30..34].copy_from_slice(&dst_ip.octets());

        // IP checksum
        let ip_checksum = internet_checksum(&rst[14..34]);
        rst[24..26].copy_from_slice(&ip_checksum.to_be_bytes());

        // TCP header
        rst[34..36].copy_from_slice(&src_port.to_be_bytes());
        rst[36..38].copy_from_slice(&dst_port.to_be_bytes());
        rst[38..42].copy_from_slice(&0u32.to_be_bytes()); // Seq = 0
        let ack_num = their_seq.wrapping_add(1);
        rst[42..46].copy_from_slice(&ack_num.to_be_bytes()); // Ack = their_seq + 1
        rst[46] = 5 << 4; // Data offset: 5 (20 bytes)
        rst[47] = 0x14; // Flags: RST + ACK
        rst[48..50].copy_from_slice(&0u16.to_be_bytes()); // Window
        rst[50..52].copy_from_slice(&[0x00, 0x00]); // Checksum placeholder
        rst[52..54].copy_from_slice(&0u16.to_be_bytes()); // Urgent pointer

        // TCP checksum with pseudo-header
        let mut pseudo = Vec::with_capacity(12 + 20);
        pseudo.extend_from_slice(&src_ip.octets());
        pseudo.extend_from_slice(&dst_ip.octets());
        pseudo.push(0);
        pseudo.push(6); // TCP protocol
        pseudo.extend_from_slice(&20u16.to_be_bytes()); // TCP length
        pseudo.extend_from_slice(&rst[34..54]);
        let tcp_checksum = internet_checksum(&pseudo);
        rst[50..52].copy_from_slice(&tcp_checksum.to_be_bytes());

        Some(Bytes::from(rst))
    }

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

        if let Some(&conn_id) = self.tcp_nat.get(&guest_endpoint) {
            debug!(
                "TCP SYN retransmit for existing connection {}: {} -> {}",
                conn_id, guest_endpoint, host_addr
            );
            return false;
        }

        debug!(
            "intercepting NEW TCP SYN: {} -> {}",
            guest_endpoint, host_addr
        );

        let conn_id = self.next_conn_id;
        self.next_conn_id += 1;

        let (buffers, rx_slice, tx_slice) = SocketBuffers::new(65535);
        let rx_buffer = smoltcp_tcp::SocketBuffer::new(rx_slice);
        let tx_buffer = smoltcp_tcp::SocketBuffer::new(tx_slice);
        let mut socket = smoltcp_tcp::Socket::new(rx_buffer, tx_buffer);

        socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(28)));
        socket.set_timeout(Some(smoltcp::time::Duration::from_secs(7200)));

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
                buffers,
            },
        );
        self.tcp_nat.insert(guest_endpoint, conn_id);

        false
    }

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

        if let Some(&flow_id) = self.udp_nat.get(&guest_endpoint) {
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

        // Use lazy mmap buffers for the payload storage (main memory consumer)
        let (buffers, rx_payload_slice, tx_payload_slice) = SocketBuffers::new(65535);
        let rx_buffer = smoltcp_udp::PacketBuffer::new(
            vec![smoltcp_udp::PacketMetadata::EMPTY; 64],
            rx_payload_slice,
        );
        let tx_buffer = smoltcp_udp::PacketBuffer::new(
            vec![smoltcp_udp::PacketMetadata::EMPTY; 64],
            tx_payload_slice,
        );
        let mut socket = smoltcp_udp::Socket::new(rx_buffer, tx_buffer);

        socket
            .bind(IpEndpoint::new(dst_ip, dst_port))
            .expect("failed to bind smoltcp UDP socket");

        let smoltcp_handle = self.sockets.add(socket);

        let (cmd_tx, cmd_rx) = mpsc::channel::<UdpHostCommand>(512);

        let host_events_tx = self.host_events_tx.clone();
        let wake_tx = self.wake_tx.clone();
        debug!("UDP flow {}: spawning host task", flow_id);
        tokio::task::spawn_local(Self::host_udp_task(
            flow_id,
            host_events_tx,
            wake_tx,
            cmd_rx,
        ));

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
                buffers,
            },
        );
        self.udp_nat.insert(guest_endpoint, flow_id);

        debug!(
            "UDP flow {} created: guest={}, smoltcp_handle={:?}",
            flow_id, guest_endpoint, smoltcp_handle
        );

        true
    }

    fn try_intercept_icmp(&self, packet: &[u8]) -> bool {
        let eth = match EthernetPacket::new(packet) {
            Some(p) => p,
            None => return false,
        };

        let ipv4 = match Ipv4Packet::new(eth.payload()) {
            Some(p) => p,
            None => return false,
        };

        if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
            return false;
        }

        let icmp = match IcmpPacket::new(ipv4.payload()) {
            Some(p) => p,
            None => return false,
        };

        if icmp.get_icmp_type() != IcmpTypes::EchoRequest {
            return false;
        }

        let dest_ip = ipv4.get_destination();
        let payload = icmp.payload();
        if payload.len() < 4 {
            return false;
        }

        let id = u16::from_be_bytes([payload[0], payload[1]]);
        let sequence = u16::from_be_bytes([payload[2], payload[3]]);
        let echo_data = Bytes::copy_from_slice(&payload[4..]);
        let source_ip = ipv4.get_source();

        debug!(
            "ICMP: intercepted echo request from {} to {}, id={}, seq={}",
            source_ip, dest_ip, id, sequence
        );

        let events_tx = self.host_events_tx.clone();
        let wake_tx = self.wake_tx.clone();
        tokio::task::spawn_local(Self::icmp_ping_task(
            source_ip, dest_ip, id, sequence, echo_data, events_tx, wake_tx,
        ));

        true
    }

    async fn icmp_ping_task(
        source_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        id: u16,
        sequence: u16,
        data: Bytes,
        events_tx: mpsc::Sender<HostEvent>,
        wake_tx: mpsc::Sender<()>,
    ) {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        use tokio::io::unix::AsyncFd;

        debug!(
            "ICMP ping task: sending to {}, id={}, seq={}",
            dest_ip, id, sequence
        );

        let socket_fd =
            unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };

        if socket_fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EACCES) || err.raw_os_error() == Some(libc::EPERM) {
                static WARNED: std::sync::atomic::AtomicBool =
                    std::sync::atomic::AtomicBool::new(false);
                if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    warn!(
                        "ICMP ping forwarding unavailable: permission denied. \
                        On Linux, run: sudo sysctl -w net.ipv4.ping_group_range=\"0 2147483647\""
                    );
                }
            } else {
                error!("ICMP ping task: failed to create socket: {}", err);
            }
            return;
        }

        unsafe {
            let flags = libc::fcntl(socket_fd, libc::F_GETFL);
            libc::fcntl(socket_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        let mut icmp_packet = Vec::with_capacity(8 + data.len());
        icmp_packet.push(8);
        icmp_packet.push(0);
        icmp_packet.extend_from_slice(&[0, 0]);
        icmp_packet.extend_from_slice(&id.to_be_bytes());
        icmp_packet.extend_from_slice(&sequence.to_be_bytes());
        icmp_packet.extend_from_slice(&data);

        let checksum = internet_checksum(&icmp_packet);
        icmp_packet[2..4].copy_from_slice(&checksum.to_be_bytes());

        let dest_addr = libc::sockaddr_in {
            sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
            sin_family: libc::AF_INET as u8,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(dest_ip.octets()),
            },
            sin_zero: [0; 8],
        };

        let sent = unsafe {
            libc::sendto(
                socket_fd,
                icmp_packet.as_ptr() as *const libc::c_void,
                icmp_packet.len(),
                0,
                &dest_addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };

        if sent < 0 {
            error!(
                "ICMP ping task: sendto failed: {}",
                std::io::Error::last_os_error()
            );
            unsafe { libc::close(socket_fd) };
            return;
        }

        debug!("ICMP ping task: sent {} bytes to {}", sent, dest_ip);

        let owned_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(socket_fd) };
        let async_fd = match AsyncFd::new(owned_fd) {
            Ok(fd) => fd,
            Err(e) => {
                error!("ICMP ping task: failed to create AsyncFd: {}", e);
                return;
            }
        };

        let mut recv_buf = vec![0u8; 1500];

        let result = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let ready = async_fd.readable().await;
                match ready {
                    Ok(mut guard) => {
                        let n = unsafe {
                            libc::recv(
                                async_fd.as_raw_fd(),
                                recv_buf.as_mut_ptr() as *mut libc::c_void,
                                recv_buf.len(),
                                0,
                            )
                        };
                        if n > 0 {
                            return Some(n as usize);
                        } else if n < 0 {
                            let err = std::io::Error::last_os_error();
                            if err.kind() == std::io::ErrorKind::WouldBlock {
                                guard.clear_ready();
                                continue;
                            }
                            error!("ICMP ping task: recv error: {}", err);
                            return None;
                        }
                        guard.clear_ready();
                    }
                    Err(e) => {
                        error!("ICMP ping task: readable error: {}", e);
                        return None;
                    }
                }
            }
        })
        .await;

        match result {
            Ok(Some(n)) => {
                debug!(
                    "ICMP ping task: received {} bytes reply from {}",
                    n, dest_ip
                );

                let icmp_offset = if n >= 20 && (recv_buf[0] >> 4) == 4 {
                    let ihl = (recv_buf[0] & 0x0F) as usize;
                    let ip_header_len = ihl * 4;
                    debug!(
                        "ICMP ping task: detected IPv4 header, IHL={}, header_len={}",
                        ihl, ip_header_len
                    );
                    ip_header_len
                } else {
                    0
                };

                if n >= icmp_offset + 8 {
                    let reply_type = recv_buf[icmp_offset];
                    let reply_id =
                        u16::from_be_bytes([recv_buf[icmp_offset + 4], recv_buf[icmp_offset + 5]]);
                    let reply_seq =
                        u16::from_be_bytes([recv_buf[icmp_offset + 6], recv_buf[icmp_offset + 7]]);
                    let reply_data = Bytes::copy_from_slice(&recv_buf[icmp_offset + 8..n]);

                    debug!(
                        "ICMP reply: type={}, id={}, seq={}, data_len={} (expected id={}, seq={})",
                        reply_type,
                        reply_id,
                        reply_seq,
                        reply_data.len(),
                        id,
                        sequence
                    );

                    if reply_type == 0 {
                        let _ = events_tx
                            .send(HostEvent::IcmpReply {
                                dest_ip,
                                source_ip,
                                id,
                                sequence,
                                payload: reply_data,
                            })
                            .await;
                        let _ = wake_tx.try_send(());
                    }
                }
            }
            Ok(None) => {
                debug!("ICMP ping task: no reply received");
            }
            Err(_) => {
                debug!("ICMP ping task: timeout waiting for reply from {}", dest_ip);
            }
        }
    }

    async fn host_udp_task(
        flow_id: u64,
        events_tx: mpsc::Sender<HostEvent>,
        wake_tx: mpsc::Sender<()>,
        mut cmd_rx: mpsc::Receiver<UdpHostCommand>,
    ) {
        debug!("UDP host task {}: starting", flow_id);

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
                        conn.pending_data.push_back(data);

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
                                Ok(sent) if sent == chunk.len() => {}
                                Ok(sent) => {
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
                HostEvent::IcmpReply {
                    dest_ip,
                    source_ip,
                    id,
                    sequence,
                    payload,
                } => {
                    debug!(
                        "ICMP reply: {} -> {}, id={}, seq={}",
                        dest_ip, source_ip, id, sequence
                    );
                    if let Some(packet) =
                        self.build_icmp_reply(dest_ip, source_ip, id, sequence, &payload)
                    {
                        if self.to_guest_tx.try_send(packet).is_err() {
                            warn!("ICMP reply: failed to send to guest (channel full)");
                        }
                    }
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

    fn close_proxied_flow(&mut self, flow_id: u64) {
        debug!("close_proxied_flow: closing flow {}", flow_id);

        // Remove from StreamMap (if not already removed)
        self.from_handler_streams.remove(&flow_id);

        if let Some(flow) = self.proxied_flows.remove(&flow_id) {
            debug!(
                "close_proxied_flow: flow {} removed, guest_endpoint={}",
                flow_id, flow.guest_endpoint
            );
            let socket = self
                .sockets
                .get_mut::<smoltcp_tcp::Socket>(flow.smoltcp_handle);
            socket.close();
            self.proxied_nat.remove(&flow.guest_endpoint);
            // Dropping flow.to_handler will signal handler that connection is closed
        } else {
            warn!("close_proxied_flow: flow {} not found", flow_id);
        }
    }

    fn handle_unix_accept(&mut self, conn_id: u64, vm_port: u16, stream: UnixStream) {
        let (buffers, rx_slice, tx_slice) = SocketBuffers::new(65535);
        let rx_buffer = smoltcp_tcp::SocketBuffer::new(rx_slice);
        let tx_buffer = smoltcp_tcp::SocketBuffer::new(tx_slice);
        let mut socket = smoltcp_tcp::Socket::new(rx_buffer, tx_buffer);

        let remote_endpoint = IpEndpoint::new(IpAddress::from(self.config.vm_ip), vm_port);
        let local_port = self.get_ephemeral_port();

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

        let (cmd_tx, cmd_rx) = mpsc::channel::<HostCommand>(512);

        let events_tx = self.host_events_tx.clone();
        let wake_tx = self.wake_tx.clone();
        tokio::task::spawn_local(Self::unix_socket_task(
            conn_id, stream, events_tx, wake_tx, cmd_rx,
        ));

        self.unix_inbound.insert(
            conn_id,
            UnixInboundConnection {
                smoltcp_handle,
                cmd_tx,
                vm_port,
                state: UnixInboundState::Connecting,
                pending_to_vm: VecDeque::new(),
                pending_to_unix: None,
                buffers,
            },
        );

        debug!(
            "Unix {}: created smoltcp connection to VM {}:{}",
            conn_id, self.config.vm_ip, vm_port
        );
    }

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

            loop {
                if !socket.can_send() {
                    break;
                }

                let Some(chunk) = conn.pending_data.pop_front() else {
                    break;
                };

                match socket.send_slice(&chunk) {
                    Ok(sent) if sent == chunk.len() => {}
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

            if let Some(pending) = conn.pending_host_send.take() {
                match conn.cmd_tx.try_send(HostCommand::Send(pending)) {
                    Ok(_) => {
                        trace!("TCP {}: drained pending host send", conn_id);
                    }
                    Err(mpsc::error::TrySendError::Full(HostCommand::Send(data))) => {
                        conn.pending_host_send = Some(data);
                    }
                    Err(_) => {}
                }
            }

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
                                trace!("TCP {}: host channel full, applying backpressure", conn_id);
                                conn.pending_host_send = Some(data);
                            }
                            Err(_) => {}
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

        // Process Unix inbound connections
        let unix_conn_ids: Vec<u64> = self.unix_inbound.keys().copied().collect();

        for conn_id in unix_conn_ids {
            let Some(conn) = self.unix_inbound.get_mut(&conn_id) else {
                continue;
            };

            let socket = self
                .sockets
                .get_mut::<smoltcp_tcp::Socket>(conn.smoltcp_handle);

            if conn.state == UnixInboundState::Connecting
                && socket.state() == smoltcp_tcp::State::Established
            {
                debug!("Unix {}: connection to VM established", conn_id);
                conn.state = UnixInboundState::Established;
            }

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

            if conn.pending_to_unix.is_none() && socket.can_recv() {
                let mut buf = vec![0u8; 65535];
                match socket.recv_slice(&mut buf) {
                    Ok(n) if n > 0 => {
                        trace!(
                            "Unix {}: received {} bytes from VM, forwarding to unix socket",
                            conn_id,
                            n
                        );
                        let data = Bytes::copy_from_slice(&buf[..n]);
                        match conn.cmd_tx.try_send(HostCommand::Send(data)) {
                            Ok(_) => {}
                            Err(mpsc::error::TrySendError::Full(HostCommand::Send(data))) => {
                                trace!(
                                    "Unix {}: unix channel full, applying backpressure",
                                    conn_id
                                );
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

            if socket.state() == smoltcp_tcp::State::Closed {
                trace!("Unix {}: smoltcp socket closed", conn_id);
            }
        }

        // Process handler-proxied TCP flows
        // First, poll the StreamMap for data from handlers (properly async)
        let waker = noop_waker_ref();
        let mut cx = FuturesContext::from_waker(waker);
        let mut flows_to_close: Vec<u64> = Vec::new();

        loop {
            match Pin::new(&mut self.from_handler_streams).poll_next(&mut cx) {
                Poll::Ready(Some((flow_id, Some(data)))) => {
                    // Data received from handler
                    trace!(
                        "Proxied flow {}: received {} bytes from handler",
                        flow_id,
                        data.len()
                    );
                    if let Some(flow) = self.proxied_flows.get_mut(&flow_id) {
                        flow.pending_to_guest.push_back(data);
                    }
                }
                Poll::Ready(Some((flow_id, None))) => {
                    // Stream closed - handler dropped sender
                    trace!(
                        "Proxied flow {}: handler stream closed, will close connection",
                        flow_id
                    );
                    flows_to_close.push(flow_id);
                }
                Poll::Ready(None) => {
                    // StreamMap is empty
                    break;
                }
                Poll::Pending => {
                    // No more ready items
                    break;
                }
            }
        }

        // Close flows where handler dropped the channel
        for flow_id in flows_to_close {
            self.close_proxied_flow(flow_id);
        }

        // Process remaining flow operations (drain to guest, read from guest)
        let proxied_ids: Vec<u64> = self.proxied_flows.keys().copied().collect();

        for flow_id in proxied_ids {
            let Some(flow) = self.proxied_flows.get_mut(&flow_id) else {
                continue;
            };

            let socket = self
                .sockets
                .get_mut::<smoltcp_tcp::Socket>(flow.smoltcp_handle);

            let state = socket.state();
            if state != smoltcp_tcp::State::Established && state != smoltcp_tcp::State::Listen {
                trace!(
                    "Proxied flow {}: state={}, can_recv={}, can_send={}",
                    flow_id,
                    state,
                    socket.can_recv(),
                    socket.can_send()
                );
            }

            // Drain pending_to_guest to smoltcp
            loop {
                if !socket.can_send() {
                    break;
                }

                let Some(chunk) = flow.pending_to_guest.pop_front() else {
                    break;
                };

                match socket.send_slice(&chunk) {
                    Ok(sent) if sent == chunk.len() => {
                        trace!("Proxied flow {}: sent {} bytes to guest", flow_id, sent);
                    }
                    Ok(sent) if sent > 0 => {
                        let remaining = chunk.slice(sent..);
                        flow.pending_to_guest.push_front(remaining);
                        break;
                    }
                    Ok(_) => {
                        flow.pending_to_guest.push_front(chunk);
                        break;
                    }
                    Err(e) => {
                        flow.pending_to_guest.push_front(chunk);
                        trace!("Proxied flow {}: smoltcp send error: {}", flow_id, e);
                        break;
                    }
                }
            }

            // Drain pending_to_handler
            if let Some(pending) = flow.pending_to_handler.take() {
                match flow.to_handler.try_send(pending) {
                    Ok(_) => {
                        trace!("Proxied flow {}: drained pending handler send", flow_id);
                    }
                    Err(mpsc::error::TrySendError::Full(data)) => {
                        flow.pending_to_handler = Some(data);
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        trace!("Proxied flow {}: to_handler channel closed", flow_id);
                        // Handler closed receiving end - close the flow
                    }
                }
            }

            // Read from smoltcp (guest -> handler)
            if flow.pending_to_handler.is_none() && socket.can_recv() {
                let mut buf = vec![0u8; 65535];
                match socket.recv_slice(&mut buf) {
                    Ok(n) if n > 0 => {
                        trace!(
                            "Proxied flow {}: received {} bytes from guest, forwarding to handler",
                            flow_id,
                            n
                        );
                        let data = Bytes::copy_from_slice(&buf[..n]);
                        match flow.to_handler.try_send(data) {
                            Ok(_) => {}
                            Err(mpsc::error::TrySendError::Full(data)) => {
                                trace!(
                                    "Proxied flow {}: handler channel full, applying backpressure",
                                    flow_id
                                );
                                flow.pending_to_handler = Some(data);
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                trace!("Proxied flow {}: to_handler channel closed", flow_id);
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        trace!("Proxied flow {}: recv_slice error: {}", flow_id, e);
                    }
                }
            }

            // Check if smoltcp socket is closed (guest initiated close)
            if socket.state() == smoltcp_tcp::State::Closed {
                trace!("Proxied flow {}: smoltcp socket closed by guest", flow_id);
            }
        }

        // Process deferred connections (poll oneshot receivers)
        self.process_deferred_connections();
    }

    fn process_deferred_connections(&mut self) {
        let waker = noop_waker_ref();
        let mut cx = FuturesContext::from_waker(waker);

        // Collect connection IDs to process
        let conn_ids: Vec<u64> = self.deferred_connections.keys().copied().collect();

        for conn_id in conn_ids {
            let Some(conn) = self.deferred_connections.get_mut(&conn_id) else {
                continue;
            };

            // Poll the oneshot receiver
            match Pin::new(&mut conn.decision_rx).poll(&mut cx) {
                Poll::Ready(Ok(Ok(channels))) => {
                    // Handler accepted - set up the proxied flow
                    trace!("Deferred connection {}: handler accepted", conn_id);
                    // Need to remove from map first, then accept
                    let conn = self.deferred_connections.remove(&conn_id).unwrap();
                    self.deferred_endpoints.remove(&conn.guest_endpoint);

                    // Set up the proxied flow
                    self.setup_proxied_flow(conn.guest_endpoint, conn.dst_port, channels);

                    // Feed the SYN packet to smoltcp to complete the handshake
                    self.device.queue_rx(conn.syn_packet);
                    let timestamp = self.timestamp();
                    self.iface
                        .poll(timestamp, &mut self.device, &mut self.sockets);
                    self.flush_tx();
                }
                Poll::Ready(Ok(Err(()))) => {
                    // Handler explicitly rejected
                    trace!("Deferred connection {}: handler rejected", conn_id);
                    self.reject_deferred_connection(conn_id);
                }
                Poll::Ready(Err(_)) => {
                    // Handler dropped the sender without deciding - treat as reject
                    trace!(
                        "Deferred connection {}: handler dropped sender, rejecting",
                        conn_id
                    );
                    self.reject_deferred_connection(conn_id);
                }
                Poll::Pending => {
                    // Still waiting for decision
                }
            }
        }
    }

    fn flush_tx(&mut self) {
        let packets = self.device.take_tx();
        if !packets.is_empty() {
            trace!("flush_tx: {} packets to send to guest", packets.len());
        }
        for packet in packets {
            trace!("flush_tx: sending {} byte packet to guest", packet.len());
            if self.to_guest_tx.try_send(packet).is_err() {
                trace!("flush_tx: to_guest_tx full, dropping packet");
            }
        }
    }

    fn build_icmp_reply(
        &self,
        source_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        id: u16,
        sequence: u16,
        payload: &[u8],
    ) -> Option<Bytes> {
        let mut icmp = Vec::with_capacity(8 + payload.len());
        icmp.push(0); // Type: Echo Reply
        icmp.push(0); // Code
        icmp.extend_from_slice(&[0, 0]); // Checksum placeholder
        icmp.extend_from_slice(&id.to_be_bytes());
        icmp.extend_from_slice(&sequence.to_be_bytes());
        icmp.extend_from_slice(payload);

        let checksum = internet_checksum(&icmp);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

        let ip_total_len = 20 + icmp.len();
        let mut ip = Vec::with_capacity(ip_total_len);

        ip.push(0x45);
        ip.push(0x00);
        ip.extend_from_slice(&(ip_total_len as u16).to_be_bytes());
        ip.extend_from_slice(&[0x00, 0x00]);
        ip.extend_from_slice(&[0x40, 0x00]);
        ip.push(64);
        ip.push(1); // ICMP protocol
        ip.extend_from_slice(&[0x00, 0x00]);
        ip.extend_from_slice(&source_ip.octets());
        ip.extend_from_slice(&dest_ip.octets());

        let ip_checksum = internet_checksum(&ip[..20]);
        ip[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

        ip.extend_from_slice(&icmp);

        let mut eth = Vec::with_capacity(14 + ip.len());
        eth.extend_from_slice(&self.config.vm_mac.0);
        eth.extend_from_slice(&self.config.gateway_mac.0);
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);

        Some(Bytes::from(eth))
    }

    /// Extract guest endpoint from a TCP SYN packet, if it is one.
    fn extract_tcp_syn_endpoint(&self, packet: &[u8]) -> Option<IpEndpoint> {
        let eth = EthernetPacket::new(packet)?;
        let ipv4 = Ipv4Packet::new(eth.payload())?;

        if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
            return None;
        }

        let tcp = TcpPacket::new(ipv4.payload())?;

        // Only match pure SYN (no ACK)
        if tcp.get_flags() != TcpFlags::SYN {
            return None;
        }

        let src_ip = IpAddress::from(ipv4.get_source());
        let src_port = tcp.get_source();

        Some(IpEndpoint::new(src_ip, src_port))
    }
}

impl AsyncNetBackend for SmoltcpProxyBackend {
    fn handle_guest_tx(&mut self, packet: &[u8]) {
        trace!(
            "SmoltcpProxyBackend::handle_guest_tx: received {} bytes",
            packet.len()
        );

        // Check if this is a SYN retransmit for a deferred connection - drop silently
        if let Some(guest_endpoint) = self.extract_tcp_syn_endpoint(packet) {
            if self.deferred_endpoints.contains_key(&guest_endpoint) {
                trace!(
                    "Dropping SYN retransmit for deferred connection: {}",
                    guest_endpoint
                );
                return;
            }
        }

        // Run packet through handler chain
        let vm_mac = self.config.vm_mac.0;
        let gateway_mac = self.config.gateway_mac.0;

        if let Some(ctx) = PacketContext::parse(packet, vm_mac, gateway_mac, &self.to_guest_tx) {
            for handler in &self.handlers {
                let handler_clone = Arc::clone(handler);

                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    handler_clone.handle(&ctx)
                }));

                match result {
                    Ok(Ok(PacketVerdict::Drop)) => {
                        trace!("Handler returned Drop");
                        return;
                    }
                    Ok(Ok(PacketVerdict::Respond(response))) => {
                        trace!("Handler returned Respond with {} bytes", response.len());
                        let _ = self.to_guest_tx.try_send(response);
                        return;
                    }
                    Ok(Ok(PacketVerdict::ProxyFlow(channels))) => {
                        if let TransportProtocol::Tcp {
                            src_port, dst_port, ..
                        } = ctx.transport
                        {
                            let guest_endpoint =
                                IpEndpoint::new(IpAddress::from(ctx.src_ip), src_port);
                            self.setup_proxied_flow(guest_endpoint, dst_port, channels);
                            self.device.queue_rx(Bytes::copy_from_slice(packet));
                            let timestamp = self.timestamp();
                            self.iface
                                .poll(timestamp, &mut self.device, &mut self.sockets);
                            self.flush_tx();
                        }
                        return;
                    }
                    Ok(Ok(PacketVerdict::DeferConnection(decision_rx))) => {
                        if let TransportProtocol::Tcp {
                            src_port, dst_port, ..
                        } = ctx.transport
                        {
                            let guest_endpoint =
                                IpEndpoint::new(IpAddress::from(ctx.src_ip), src_port);
                            // Don't send the SYN to smoltcp yet - hold it until handler decides
                            self.setup_deferred_connection(
                                guest_endpoint,
                                dst_port,
                                Bytes::copy_from_slice(packet),
                                decision_rx,
                            );
                        }
                        return;
                    }
                    Ok(Ok(PacketVerdict::Continue)) => {
                        // Continue to next handler
                    }
                    Ok(Err(e)) => {
                        error!("Handler returned error: {}, dropping packet", e);
                        return;
                    }
                    Err(_) => {
                        error!("Handler panicked, dropping packet");
                        return;
                    }
                }
            }
        }

        // Default NAT processing
        if self.try_intercept_icmp(packet) {
            return;
        }

        self.try_intercept_tcp(packet);
        self.try_intercept_udp(packet);

        self.device.queue_rx(Bytes::copy_from_slice(packet));

        let timestamp = self.timestamp();
        self.iface
            .poll(timestamp, &mut self.device, &mut self.sockets);

        self.flush_tx();
    }

    fn poll(&mut self) {
        trace!("SmoltcpProxyBackend::poll");

        let timestamp = self.timestamp();
        self.iface
            .poll(timestamp, &mut self.device, &mut self.sockets);

        self.process_host_events();
        self.process_sockets();

        let timestamp = self.timestamp();
        self.iface
            .poll(timestamp, &mut self.device, &mut self.sockets);

        self.process_host_events();
        self.process_sockets();

        let timestamp = self.timestamp();
        self.iface
            .poll(timestamp, &mut self.device, &mut self.sockets);

        self.flush_tx();
    }

    fn poll_delay(&mut self) -> Option<Duration> {
        let timestamp = self.timestamp();
        self.iface
            .poll_delay(timestamp, &self.sockets)
            .map(|d| Duration::from_millis(d.total_millis() as u64))
    }

    fn on_exit(&mut self) {
        debug!("SmoltcpProxyBackend::on_exit");
        let conn_ids: Vec<u64> = self.tcp_connections.keys().copied().collect();
        for conn_id in conn_ids {
            self.close_tcp_connection(conn_id);
        }
        let flow_ids: Vec<u64> = self.udp_flows.keys().copied().collect();
        for flow_id in flow_ids {
            self.close_udp_flow(flow_id);
        }
        let proxied_ids: Vec<u64> = self.proxied_flows.keys().copied().collect();
        for flow_id in proxied_ids {
            self.close_proxied_flow(flow_id);
        }
    }
}
