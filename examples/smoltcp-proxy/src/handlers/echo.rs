//! Echo handler for testing ProxyFlow and DeferConnection.
//!
//! Provides two handlers:
//! - `EchoHandler`: Immediate accept, echoes TCP/UDP data back
//! - `DeferredEchoHandler`: Defers TCP accept, simulates backend connection

use bytes::Bytes;
use log::debug;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

use crate::handler::{
    DeferredFlowDecision, FlowChannels, HandlerResult, PacketContext, PacketHandler, PacketVerdict,
    TcpInfo, UdpInfo,
};

/// A handler that echoes TCP and UDP data back to the client.
///
/// For TCP: Uses ProxyFlow to let smoltcp handle TCP state while this handler
/// just receives payload bytes and sends them right back.
///
/// For UDP: Returns a direct response packet with the same payload.
pub struct EchoHandler {
    port: u16,
}

impl EchoHandler {
    /// Create an echo handler for the specified port.
    pub fn new(port: u16) -> Self {
        Self { port }
    }
}

impl PacketHandler for EchoHandler {
    fn handle_tcp(&self, ctx: &PacketContext, tcp: TcpInfo) -> HandlerResult {
        // Only intercept SYN packets (new connections) to our port
        if !tcp.is_syn() || tcp.dst_port != self.port {
            return Ok(PacketVerdict::Continue);
        }

        debug!(
            "EchoHandler: intercepting TCP connection {}:{} -> {}:{}",
            ctx.src_ip, tcp.src_port, ctx.dst_ip, tcp.dst_port
        );

        // Create channels for bidirectional communication
        let (to_handler_tx, mut to_handler_rx) = mpsc::channel::<Bytes>(64);
        let (from_handler_tx, from_handler_rx) = mpsc::channel::<Bytes>(64);

        // Spawn task to echo data back
        tokio::task::spawn_local(async move {
            debug!("EchoHandler: echo task started");

            while let Some(data) = to_handler_rx.recv().await {
                debug!("EchoHandler: received {} bytes, echoing back", data.len());

                // Echo the data back
                if from_handler_tx.send(data).await.is_err() {
                    debug!("EchoHandler: channel closed, stopping echo task");
                    break;
                }
            }

            debug!("EchoHandler: echo task finished");
        });

        Ok(PacketVerdict::ProxyFlow(FlowChannels {
            to_handler: to_handler_tx,
            from_handler: from_handler_rx,
        }))
    }

    fn handle_udp(&self, ctx: &PacketContext, udp: UdpInfo) -> HandlerResult {
        // Only echo UDP packets to our port
        if udp.dst_port != self.port {
            return Ok(PacketVerdict::Continue);
        }

        debug!(
            "EchoHandler: echoing UDP {}:{} -> {}:{} ({} bytes)",
            ctx.src_ip,
            udp.src_port,
            ctx.dst_ip,
            udp.dst_port,
            udp.payload.len()
        );

        // Build and return UDP response with same payload
        Ok(PacketVerdict::Respond(ctx.build_udp_response(udp.payload)))
    }
}

/// A handler that defers TCP connection acceptance.
///
/// Demonstrates the DeferConnection flow by:
/// 1. Receiving a SYN packet
/// 2. Simulating a backend connection attempt (with configurable delay)
/// 3. Accepting or rejecting based on configuration
///
/// Useful for testing deferred accept and for proxying to external services.
pub struct DeferredEchoHandler {
    port: u16,
    delay_ms: u64,
    should_accept: bool,
}

impl DeferredEchoHandler {
    /// Create a deferred echo handler.
    ///
    /// - `port`: TCP port to intercept
    /// - `delay_ms`: Simulated backend connection delay
    /// - `should_accept`: Whether to accept (true) or reject (false) after delay
    pub fn new(port: u16, delay_ms: u64, should_accept: bool) -> Self {
        Self {
            port,
            delay_ms,
            should_accept,
        }
    }

    /// Create a handler that accepts after a delay.
    pub fn accepting(port: u16, delay_ms: u64) -> Self {
        Self::new(port, delay_ms, true)
    }

    /// Create a handler that rejects after a delay.
    pub fn rejecting(port: u16, delay_ms: u64) -> Self {
        Self::new(port, delay_ms, false)
    }
}

impl PacketHandler for DeferredEchoHandler {
    fn handle_tcp(&self, ctx: &PacketContext, tcp: TcpInfo) -> HandlerResult {
        // Only intercept SYN packets (new connections) to our port
        if !tcp.is_syn() || tcp.dst_port != self.port {
            return Ok(PacketVerdict::Continue);
        }

        debug!(
            "DeferredEchoHandler: deferring TCP connection {}:{} -> {}:{} (delay={}ms, accept={})",
            ctx.src_ip, tcp.src_port, ctx.dst_ip, tcp.dst_port, self.delay_ms, self.should_accept
        );

        let (decision_tx, decision_rx) = oneshot::channel::<DeferredFlowDecision>();
        let delay = Duration::from_millis(self.delay_ms);
        let should_accept = self.should_accept;

        // Spawn task to simulate backend connection attempt
        tokio::task::spawn_local(async move {
            debug!("DeferredEchoHandler: simulating backend connection...");

            // Simulate connection delay
            tokio::time::sleep(delay).await;

            if should_accept {
                debug!("DeferredEchoHandler: backend connected, accepting");

                // Create channels for the proxied flow
                let (to_handler_tx, mut to_handler_rx) = mpsc::channel::<Bytes>(64);
                let (from_handler_tx, from_handler_rx) = mpsc::channel::<Bytes>(64);

                // Spawn echo task
                tokio::task::spawn_local(async move {
                    debug!("DeferredEchoHandler: echo task started");

                    while let Some(data) = to_handler_rx.recv().await {
                        debug!(
                            "DeferredEchoHandler: received {} bytes, echoing back",
                            data.len()
                        );

                        if from_handler_tx.send(data).await.is_err() {
                            debug!("DeferredEchoHandler: channel closed");
                            break;
                        }
                    }

                    debug!("DeferredEchoHandler: echo task finished");
                });

                // Signal acceptance with the flow channels
                let _ = decision_tx.send(Ok(FlowChannels {
                    to_handler: to_handler_tx,
                    from_handler: from_handler_rx,
                }));
            } else {
                debug!("DeferredEchoHandler: backend connection failed, rejecting");
                let _ = decision_tx.send(Err(()));
            }
        });

        Ok(PacketVerdict::DeferConnection(decision_rx))
    }
}
