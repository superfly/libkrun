// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod device;
mod worker;

use std::io;

use vm_memory::VolatileSlice;

pub use self::device::{Block, CacheType, DiskProperties};

use vm_memory::GuestMemoryError;

pub const CONFIG_SPACE_SIZE: usize = 8;
pub const SECTOR_SHIFT: u8 = 9;
pub const SECTOR_SIZE: u64 = (0x01_u64) << SECTOR_SHIFT;
pub const QUEUE_SIZE: u16 = 256;
pub const NUM_QUEUES: usize = 1;
pub const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

#[derive(Debug)]
pub enum Error {
    /// Guest gave us too few descriptors in a descriptor chain.
    DescriptorChainTooShort,
    /// Guest gave us a descriptor that was too short to use.
    DescriptorLengthTooSmall,
    /// Getting a block's metadata fails for any reason.
    GetFileMetadata(std::io::Error),
    /// Guest gave us bad memory addresses.
    GuestMemory(GuestMemoryError),
    /// The requested operation would cause a seek beyond disk end.
    InvalidOffset,
    /// Guest gave us a read only descriptor that protocol says to write to.
    UnexpectedReadOnlyDescriptor,
    /// Guest gave us a write only descriptor that protocol says to read from.
    UnexpectedWriteOnlyDescriptor,
}

/// Supported disk image formats
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImageType {
    Raw,
    Qcow2,
    Vmdk,
}

impl TryFrom<u32> for ImageType {
    type Error = ();

    fn try_from(disk_format: u32) -> Result<Self, Self::Error> {
        match disk_format {
            0 => Ok(ImageType::Raw),
            1 => Ok(ImageType::Qcow2),
            2 => Ok(ImageType::Vmdk),
            _ => {
                // Do not continue if the user cannot specify a valid disk format
                Err(())
            }
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum SyncMode {
    None,
    Relaxed,
    #[default]
    Full,
}

impl TryFrom<u32> for SyncMode {
    type Error = ();

    fn try_from(sync_mode: u32) -> Result<Self, Self::Error> {
        match sync_mode {
            0 => Ok(SyncMode::None),
            1 => Ok(SyncMode::Relaxed),
            2 => Ok(SyncMode::Full),
            _ => {
                // Do not continue if the user cannot specify a valid sync mode
                Err(())
            }
        }
    }
}

/// Trait for block device backends.
///
/// This trait abstracts the storage operations needed by the virtio block worker,
/// allowing different backend implementations (disk images, in-memory, networked storage, etc.).
pub trait BlockBackend: Send {
    /// Returns the cache type configuration for this backend.
    fn cache_type(&self) -> CacheType;

    /// Returns the device/image identifier bytes.
    fn image_id(&self) -> &[u8];

    /// Reads data from the backend at the given offset into the provided buffers.
    /// Returns the number of bytes read.
    fn read_vectored_at(&self, bufs: &[VolatileSlice], offset: u64) -> io::Result<usize>;

    /// Writes data to the backend at the given offset from the provided buffers.
    /// Returns the number of bytes written.
    fn write_vectored_at(&self, bufs: &[VolatileSlice], offset: u64) -> io::Result<usize>;

    /// Flushes any cached data to the underlying storage.
    fn flush(&self) -> io::Result<()>;

    /// Syncs data to persistent storage (fsync).
    fn sync(&self) -> io::Result<()>;

    /// Discards/trims the given range, potentially freeing underlying storage.
    fn discard(&self, offset: u64, len: u64) -> io::Result<()>;

    /// Writes zeroes to the given range.
    /// If `unmap` is true, the implementation may also discard the range.
    fn write_zeroes(&self, offset: u64, len: u64, unmap: bool) -> io::Result<()>;
}
