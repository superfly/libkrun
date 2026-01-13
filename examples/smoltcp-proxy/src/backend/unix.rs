//! Unix socket inbound connection state.

use bytes::Bytes;
use smoltcp::iface::SocketHandle;
use std::collections::VecDeque;
use tokio::sync::mpsc;

use super::tcp::SocketBuffers;
use super::HostCommand;

/// State for a Unix socket inbound connection (host Unix socket -> VM TCP).
/// This is the reverse direction: connections from the host to the VM.
pub struct UnixInboundConnection {
    pub smoltcp_handle: SocketHandle,
    pub cmd_tx: mpsc::Sender<HostCommand>,
    #[allow(dead_code)]
    pub vm_port: u16,
    pub state: UnixInboundState,
    /// Pending data from Unix socket that couldn't be sent to smoltcp yet
    pub pending_to_vm: VecDeque<Bytes>,
    /// Pending data to send to Unix socket (backpressure when channel is full)
    pub pending_to_unix: Option<Bytes>,
    /// Lazily-allocated socket buffers (cleaned up on drop)
    pub buffers: SocketBuffers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnixInboundState {
    /// TCP connection to VM is being established (SYN sent)
    Connecting,
    /// TCP connection to VM is established
    Established,
}
