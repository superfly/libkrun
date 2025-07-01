use std::{io, os::fd::RawFd};

#[allow(dead_code)]
#[derive(Debug)]
pub enum ConnectError {
    InvalidAddress(nix::Error),
    CreateSocket(io::Error),
    Binding(io::Error),
    SendingMagic(io::Error),
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum ReadError {
    /// Nothing was read from the backend.
    NothingRead,
    /// Another internal error occurred.
    Internal(io::Error),
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum WriteError {
    /// Nothing was written; the frame can be dropped or resent later.
    NothingWritten,
    /// A partial write occurred; the write must be completed with `try_finish_write`.
    PartialWrite,
    /// The backend process does not seem to be running (e.g., received EPIPE).
    ProcessNotRunning,
    /// Another internal error occurred.
    Internal(io::Error),
}

impl From<io::Error> for WriteError {
    fn from(value: io::Error) -> Self {
        Self::Internal(value)
    }
}

/// A simplified trait for a network backend.
///
/// This version removes all token-based scheduling and flow control logic,
/// delegating the responsibility of fairness and packet prioritization to the
/// implementation itself. The `NetWorker` will treat any implementation of this

/// trait as a simple source of packets.
pub trait NetBackend {
    /// Reads a single frame from the backend into the provided buffer.
    /// The implementation is responsible for fairly selecting which connection's
    /// frame to provide if multiple are available.
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError>;

    /// Writes a single frame from the buffer to the backend.
    fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError>;

    /// Checks if a previous write operation was incomplete.
    fn has_unfinished_write(&self) -> bool;

    /// Attempts to complete an unfinished partial write.
    fn try_finish_write(&mut self, hdr_len: usize, buf: &[u8]) -> Result<(), WriteError>;

    /// Returns the raw file descriptor for the backend's main event source.
    /// This is typically a waker `EventFd` that is triggered when the backend
    /// has packets ready for reading.
    fn raw_socket_fd(&self) -> RawFd;

    /// Handles a mio event for a registered connection token.
    /// This is called by the worker when a `mio::event::Event` is received
    /// for a token other than the primary queue/backend tokens.
    fn handle_event(&mut self, _token: mio::Token, _is_readable: bool, _is_writable: bool) {
        // Default implementation does nothing.
    }
}
