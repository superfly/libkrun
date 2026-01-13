//! Packet handler infrastructure for the smoltcp proxy.
//!
//! This module provides the trait and types for implementing packet handlers
//! that can inspect, modify, or intercept network traffic from the VM.

pub mod context;
pub mod info;

pub use context::{PacketContext, TransportProtocol};
pub use info::{IcmpInfo, TcpInfo, UdpInfo};

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};

/// What to do with a packet after handling.
pub enum PacketVerdict {
    /// Drop the packet silently
    Drop,
    /// Respond directly to the guest with this packet
    Respond(Bytes),
    /// Continue to next handler (or default NAT processing if last)
    Continue,
    /// Proxy this TCP flow through handler-provided channels.
    /// smoltcp handles TCP state (handshake, ACKs, retransmits).
    /// Handler just deals with payload byte streams.
    ProxyFlow(FlowChannels),
    /// Defer the connection decision - don't SYN-ACK until handler decides.
    ///
    /// Use this when you need to establish a backend connection before accepting.
    /// The handler receives a oneshot sender to signal accept/reject:
    /// - Send `Ok(FlowChannels)` to accept and proceed with proxied flow
    /// - Send `Err(())` or drop the sender to reject with TCP RST
    ///
    /// The SYN packet is held until the handler decides. If the guest retransmits
    /// the SYN, it will be silently dropped while waiting.
    ///
    /// # Example: Proxy to remote service
    /// ```ignore
    /// fn handle_tcp(&self, ctx: &PacketContext, tcp: TcpInfo) -> HandlerResult {
    ///     if tcp.is_syn() && tcp.dst_port == 8080 {
    ///         let (tx, rx) = oneshot::channel();
    ///
    ///         tokio::spawn(async move {
    ///             // Try to connect to backend
    ///             match TcpStream::connect("backend:8080").await {
    ///                 Ok(stream) => {
    ///                     let (to_handler_tx, to_handler_rx) = mpsc::channel(64);
    ///                     let (from_handler_tx, from_handler_rx) = mpsc::channel(64);
    ///
    ///                     // Spawn relay task...
    ///
    ///                     let _ = tx.send(Ok(FlowChannels {
    ///                         to_handler: to_handler_tx,
    ///                         from_handler: from_handler_rx,
    ///                     }));
    ///                 }
    ///                 Err(_) => {
    ///                     let _ = tx.send(Err(()));
    ///                 }
    ///             }
    ///         });
    ///
    ///         return Ok(PacketVerdict::DeferConnection(rx));
    ///     }
    ///     Ok(PacketVerdict::Continue)
    /// }
    /// ```
    DeferConnection(oneshot::Receiver<DeferredFlowDecision>),
}

/// Decision from handler for a deferred connection.
pub type DeferredFlowDecision = Result<FlowChannels, ()>;

/// Bidirectional channels for proxied flow data.
///
/// Used with `PacketVerdict::ProxyFlow` to let handlers proxy TCP streams
/// without dealing with TCP state machine complexity.
pub struct FlowChannels {
    /// Handler receives payload data from guest on this channel
    pub to_handler: mpsc::Sender<Bytes>,
    /// Handler sends payload data to guest on this channel
    pub from_handler: mpsc::Receiver<Bytes>,
}

/// Error type for packet handlers.
pub type HandlerError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Result type for packet handler methods.
pub type HandlerResult = Result<PacketVerdict, HandlerError>;

/// Trait for packet handlers in the processing chain.
///
/// Handlers are called in order for each outbound packet from the guest.
/// Each handler can inspect the packet and decide to:
/// - `Ok(Drop)` - drop the packet (firewall deny)
/// - `Ok(Respond(...))` - respond directly (DNS, ICMP error, TCP RST)
/// - `Ok(Continue)` - pass to next handler
/// - `Err(...)` - log error and drop packet
///
/// If all handlers return `Ok(Continue)`, the packet proceeds to default NAT processing.
///
/// # Error Handling
///
/// Handlers can return errors, which will be logged and cause the packet to be dropped.
/// Panics are also caught and logged - they won't crash the proxy.
///
/// # Protocol-specific methods
///
/// Override only the methods for protocols you care about. All default to `Ok(Continue)`.
///
/// # Example: Block specific TCP ports
/// ```ignore
/// struct PortBlocker {
///     blocked: HashSet<u16>,
/// }
///
/// impl PacketHandler for PortBlocker {
///     fn handle_tcp(&self, ctx: &PacketContext, tcp: TcpInfo) -> HandlerResult {
///         if self.blocked.contains(&tcp.dst_port) {
///             Ok(PacketVerdict::Drop)
///         } else {
///             Ok(PacketVerdict::Continue)
///         }
///     }
/// }
/// ```
///
/// # Example: Custom DNS responder with error handling
/// ```ignore
/// struct DnsHandler;
///
/// impl PacketHandler for DnsHandler {
///     fn handle_udp(&self, ctx: &PacketContext, udp: UdpInfo) -> HandlerResult {
///         if udp.dst_port == 53 {
///             let response = parse_and_resolve(udp.payload)?;  // can use ?
///             Ok(PacketVerdict::Respond(ctx.build_udp_response(&response)))
///         } else {
///             Ok(PacketVerdict::Continue)
///         }
///     }
/// }
/// ```
pub trait PacketHandler: Send + Sync + 'static {
    /// Handle a TCP packet. Override to process TCP traffic.
    fn handle_tcp(&self, _ctx: &PacketContext, _tcp: TcpInfo) -> HandlerResult {
        Ok(PacketVerdict::Continue)
    }

    /// Handle a UDP packet. Override to process UDP traffic.
    fn handle_udp(&self, _ctx: &PacketContext, _udp: UdpInfo) -> HandlerResult {
        Ok(PacketVerdict::Continue)
    }

    /// Handle an ICMP packet. Override to process ICMP traffic.
    fn handle_icmp(&self, _ctx: &PacketContext, _icmp: IcmpInfo) -> HandlerResult {
        Ok(PacketVerdict::Continue)
    }

    /// Handle packets with other/unknown protocols. Rarely needed.
    fn handle_other(&self, _ctx: &PacketContext, _protocol: u8) -> HandlerResult {
        Ok(PacketVerdict::Continue)
    }

    /// Main dispatch method. Override only if you need custom dispatch logic.
    fn handle(&self, ctx: &PacketContext) -> HandlerResult {
        match &ctx.transport {
            TransportProtocol::Tcp {
                src_port,
                dst_port,
                flags,
                seq,
                ack,
                payload,
            } => self.handle_tcp(
                ctx,
                TcpInfo {
                    src_port: *src_port,
                    dst_port: *dst_port,
                    flags: *flags,
                    seq: *seq,
                    ack: *ack,
                    payload,
                },
            ),
            TransportProtocol::Udp {
                src_port,
                dst_port,
                payload,
            } => self.handle_udp(
                ctx,
                UdpInfo {
                    src_port: *src_port,
                    dst_port: *dst_port,
                    payload,
                },
            ),
            TransportProtocol::Icmp {
                icmp_type,
                code,
                payload,
            } => self.handle_icmp(
                ctx,
                IcmpInfo {
                    icmp_type: *icmp_type,
                    code: *code,
                    payload,
                },
            ),
            TransportProtocol::Other { protocol } => self.handle_other(ctx, *protocol),
        }
    }
}
