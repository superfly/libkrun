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
    /// Nothing was written
    NothingRead,
    /// Another internal error occurred
    Internal(io::Error),
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum WriteError {
    /// Nothing was written, you can drop the frame or try to resend it later
    NothingWritten,
    /// Part of the buffer was written, the write has to be finished using try_finish_write
    PartialWrite,
    /// Passt doesnt seem to be running (received EPIPE)
    ProcessNotRunning,
    /// Another internal error occurred
    Internal(io::Error),
}

impl From<io::Error> for WriteError {
    fn from(value: io::Error) -> Self {
        Self::Internal(value)
    }
}

pub trait NetBackend {
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError>;
    fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError>;
    fn has_unfinished_write(&self) -> bool;
    fn try_finish_write(&mut self, hdr_len: usize, buf: &[u8]) -> Result<(), WriteError>;
    fn raw_socket_fd(&self) -> RawFd;

    fn handle_event(&mut self, _token: mio::Token, _is_readable: bool, _is_writable: bool) {
        // do nothing
    }
    fn get_rx_queue_len(&self) -> usize {
        0
    }
    fn resume_reading(&mut self) {}
    
    // Token-specific reading interface
    fn get_ready_tokens(&self) -> Vec<mio::Token> {
        // Default implementation returns empty - only advanced backends implement this
        Vec::new()
    }
    
    fn has_more_data_for_token(&self, _token: mio::Token) -> bool {
        // Default implementation returns false
        false
    }
    
    fn read_frame_for_token(&mut self, _token: mio::Token, buf: &mut [u8]) -> Result<usize, ReadError> {
        // Default implementation falls back to regular read_frame for backward compatibility
        self.read_frame(buf)
    }
    
    fn resume_tokens(&mut self, _tokens: &std::collections::HashSet<mio::Token>) {
        // Default implementation falls back to regular resume_reading
        self.resume_reading();
    }
}
