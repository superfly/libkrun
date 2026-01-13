//! TCP connection state for the NAT proxy.

use bytes::Bytes;
use smoltcp::iface::SocketHandle;
use smoltcp::wire::IpEndpoint;
use std::collections::VecDeque;
use tokio::sync::{mpsc, oneshot};

use super::HostCommand;
use crate::handler::DeferredFlowDecision;

/// State for a TCP connection being proxied to the host.
pub struct TcpConnection {
    pub smoltcp_handle: SocketHandle,
    pub cmd_tx: mpsc::Sender<HostCommand>,
    #[allow(dead_code)]
    pub guest_endpoint: IpEndpoint,
    pub host_endpoint: std::net::SocketAddr,
    pub state: TcpConnectionState,
    /// Pending data from host that couldn't be sent to smoltcp yet
    pub pending_data: VecDeque<Bytes>,
    /// Pending data to send to host (when channel is full)
    pub pending_host_send: Option<Bytes>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpConnectionState {
    /// TCP SYN received, waiting for host connection
    Connecting,
    /// Host connection established, relaying data
    Established,
    #[allow(dead_code)]
    Closing,
}

/// A TCP flow proxied through handler-provided channels.
/// smoltcp handles TCP state, handler deals with payload streams.
///
/// Note: from_handler is stored separately in a StreamMap for proper async polling.
pub struct ProxiedTcpFlow {
    pub smoltcp_handle: SocketHandle,
    #[allow(dead_code)]
    pub guest_endpoint: IpEndpoint,
    /// Send payload data from guest to handler
    pub to_handler: mpsc::Sender<Bytes>,
    /// Pending data from handler that couldn't be sent to smoltcp yet
    pub pending_to_guest: VecDeque<Bytes>,
    /// Pending data to send to handler (backpressure)
    pub pending_to_handler: Option<Bytes>,
}

/// A TCP connection waiting for handler decision.
///
/// The SYN packet is held until the handler signals accept/reject.
/// Once accepted, this becomes a ProxiedTcpFlow.
pub struct DeferredConnection {
    /// Guest endpoint (src_ip:src_port)
    pub guest_endpoint: IpEndpoint,
    /// Destination port the guest is connecting to
    pub dst_port: u16,
    /// The original SYN packet bytes (to replay when accepted)
    pub syn_packet: Bytes,
    /// Channel to receive handler's decision
    pub decision_rx: oneshot::Receiver<DeferredFlowDecision>,
}
