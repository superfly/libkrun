mod device;
mod event_handler;

pub use self::defs::uapi::VIRTIO_ID_RNG as TYPE_RNG;
pub use self::device::Rng;

use rand::{rngs::OsRng, TryRngCore};
use std::io;

/// Trait for RNG backends that provide random bytes to the virtio-rng device.
pub trait RngBackend: Send {
    /// Fill the provided buffer with random bytes.
    fn fill_bytes(&mut self, buf: &mut [u8]) -> io::Result<()>;
}

/// Default RNG backend using the operating system's random number generator.
pub struct OsRngBackend;

impl RngBackend for OsRngBackend {
    fn fill_bytes(&mut self, buf: &mut [u8]) -> io::Result<()> {
        OsRng
            .try_fill_bytes(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

mod defs {
    pub const RNG_DEV_ID: &str = "virtio_rng";
    pub const NUM_QUEUES: usize = 1;
    pub const QUEUE_SIZES: &[u16] = &[256; NUM_QUEUES];

    pub mod uapi {
        pub const VIRTIO_F_VERSION_1: u32 = 32;
        pub const VIRTIO_ID_RNG: u32 = 4;
    }
}

#[derive(Debug)]
pub enum RngError {
    /// Failed to create event fd.
    EventFd(std::io::Error),
}

type Result<T> = std::result::Result<T, RngError>;
