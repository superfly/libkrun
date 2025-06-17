use log::{debug, error, warn};
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::sys::socket::{
    bind, connect, getsockopt, recv, send, setsockopt, socket, sockopt, AddressFamily, MsgFlags,
    SockFlag, SockType, UnixAddr,
};
use nix::unistd::unlink;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;

use super::backend::{ConnectError, NetBackend, ReadError, WriteError};

const VFKIT_MAGIC: [u8; 4] = *b"VFKT";

pub struct Gvproxy {
    sock: UnixDatagram,
}

impl Gvproxy {
    /// Connect to a running gvproxy instance, given a socket file descriptor
    pub fn new(path: PathBuf) -> Result<Self, ConnectError> {
        let local_path = format!("{}-krun.sock", path.display());
        _ = unlink(local_path.as_str());

        let sock = UnixDatagram::bind(&local_path).map_err(ConnectError::Binding)?;
        sock.connect(&path).map_err(ConnectError::Binding)?;

        sock.send(&VFKIT_MAGIC)
            .map_err(ConnectError::SendingMagic)?;

        if let Err(e) = sock.set_nonblocking(true) {
            warn!(
                "error switching to non-blocking: fs={}, err={}",
                sock.as_raw_fd(),
                e
            );
        }

        #[cfg(target_os = "macos")]
        {
            // nix doesn't provide an abstraction for SO_NOSIGPIPE, fall back to libc.
            let option_value: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    sock.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    &option_value as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&option_value) as libc::socklen_t,
                )
            };
        }

        if let Err(e) = setsockopt(&sock, sockopt::SndBuf, &(7 * 1024 * 1024)) {
            log::warn!("Failed to increase SO_SNDBUF (performance may be decreased): {e}");
        }
        if let Err(e) = setsockopt(&sock, sockopt::RcvBuf, &(7 * 1024 * 1024)) {
            log::warn!("Failed to increase SO_SNDBUF (performance may be decreased): {e}");
        }

        log::debug!(
            "gvproxy socket (fd {}) buffer sizes: SndBuf={:?} RcvBuf={:?}",
            sock.as_raw_fd(),
            getsockopt(&sock, sockopt::SndBuf),
            getsockopt(&sock, sockopt::RcvBuf)
        );

        Ok(Self { sock })
    }
}

impl NetBackend for Gvproxy {
    /// Try to read a frame from passt. If no bytes are available reports ReadError::NothingRead
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        let frame_length = match self.sock.recv(buf) {
            Ok(f) => f,
            #[allow(unreachable_patterns)]
            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock => return Err(ReadError::NothingRead),
                _ => return Err(ReadError::Internal(e)),
            },
        };
        debug!("Read eth frame from passt: {} bytes", frame_length);
        Ok(frame_length)
    }

    /// Try to write a frame to passt.
    /// (Will mutate and override parts of buf, with a passt header!)
    ///
    /// * `hdr_len` - specifies the size of any existing headers encapsulating the ethernet frame,
    ///   (such as vnet header), that can be overwritten. Must be >= PASST_HEADER_LEN.
    /// * `buf` - the buffer to write to passt, `buf[..hdr_len]` may be overwritten
    ///
    /// If this function returns WriteError::PartialWrite, you have to finish the write using
    /// try_finish_write.
    fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError> {
        let ret = self
            .sock
            .send(&buf[hdr_len..])
            .map_err(WriteError::Internal)?;
        debug!(
            "Written frame size={}, written={}",
            buf.len() - hdr_len,
            ret
        );
        Ok(())
    }

    fn has_unfinished_write(&self) -> bool {
        false
    }

    fn try_finish_write(&mut self, _hdr_len: usize, _buf: &[u8]) -> Result<(), WriteError> {
        // The gvproxy backend doesn't do partial writes.
        Ok(())
    }

    fn raw_socket_fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }
}
