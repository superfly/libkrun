//! UDP flow state for the NAT proxy.

use bytes::Bytes;
use smoltcp::iface::SocketHandle;
use smoltcp::wire::IpEndpoint;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::sync::mpsc;

use super::tcp::SocketBuffers;

/// Commands sent to host UDP socket tasks.
pub enum UdpHostCommand {
    Send { data: Bytes, dest: SocketAddr },
    Close,
}

/// State for a proxied UDP flow.
/// UDP is connectionless, so we track "flows" by the guest's source endpoint.
pub struct UdpFlow {
    pub smoltcp_handle: SocketHandle,
    pub cmd_tx: mpsc::Sender<UdpHostCommand>,
    pub guest_endpoint: IpEndpoint,
    pub last_activity: Instant,
    /// Lazily-allocated socket buffers (cleaned up on drop)
    pub buffers: SocketBuffers,
}
