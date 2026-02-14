// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod async_worker;
pub mod device;
mod worker;

use std::io;
use std::sync::Arc;

pub use imago::io_buffers::{IoVector, IoVectorMut};
pub use vm_memory::VolatileSlice;

pub use self::async_worker::AsyncBlockWorker;
pub use self::device::{Block, BlockDeviceType, CacheType, DiskProperties};

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

    /// Returns the number of 512-byte sectors
    fn nsectors(&self) -> u64;

    /// Returns the device/image identifier bytes.
    fn image_id(&self) -> &[u8];

    /// Reads data from the backend at the given offset into the provided buffers.
    /// Returns the number of bytes read.
    fn read_vectored_at(&self, bufs: &[VolatileSlice], offset: u64) -> io::Result<usize>;

    /// Writes data to the backend at the given offset from the provided buffers.
    /// Returns the number of bytes written.
    fn write_vectored_at(&self, bufs: &[VolatileSlice], offset: u64) -> io::Result<usize>;

    /// Flushes any cached data to the underlying storage.
    fn flush(&self) -> io::Result<()> {
        Ok(())
    }

    /// Syncs data to persistent storage (fsync).
    fn sync(&self) -> io::Result<()> {
        Ok(())
    }

    /// Discards/trims the given range, potentially freeing underlying storage.
    #[allow(unused_variables)]
    fn discard(&self, offset: u64, len: u64) -> io::Result<()> {
        Ok(())
    }

    /// Writes zeroes to the given range.
    /// If `unmap` is true, the implementation may also discard the range.
    #[allow(unused_variables)]
    fn write_zeroes(&self, offset: u64, len: u64, unmap: bool) -> io::Result<()> {
        Ok(())
    }

    /// Called when the VMM is shutting down.
    /// Use this for cleanup like flushing data to persistent storage.
    fn on_exit(&self) {}

    /// Serialize backend state for snapshot. Default: no state saved.
    fn save_snapshot_state(&self) -> Option<Vec<u8>> {
        None
    }

    /// Restore backend state from a previous snapshot. Default: no-op.
    fn restore_snapshot_state(&self, _data: &[u8]) {}
}

impl<B> BlockBackend for std::sync::Arc<B>
where
    B: BlockBackend + Send + Sync + ?Sized,
{
    fn cache_type(&self) -> CacheType {
        (**self).cache_type()
    }

    fn nsectors(&self) -> u64 {
        (**self).nsectors()
    }

    fn image_id(&self) -> &[u8] {
        (**self).image_id()
    }

    fn read_vectored_at(&self, bufs: &[VolatileSlice], offset: u64) -> io::Result<usize> {
        (**self).read_vectored_at(bufs, offset)
    }

    fn write_vectored_at(&self, bufs: &[VolatileSlice], offset: u64) -> io::Result<usize> {
        (**self).write_vectored_at(bufs, offset)
    }

    fn flush(&self) -> io::Result<()> {
        (**self).flush()
    }

    fn sync(&self) -> io::Result<()> {
        (**self).sync()
    }

    fn discard(&self, offset: u64, len: u64) -> io::Result<()> {
        (**self).discard(offset, len)
    }

    fn write_zeroes(&self, offset: u64, len: u64, unmap: bool) -> io::Result<()> {
        (**self).write_zeroes(offset, len, unmap)
    }

    fn on_exit(&self) {
        (**self).on_exit()
    }

    fn save_snapshot_state(&self) -> Option<Vec<u8>> {
        (**self).save_snapshot_state()
    }

    fn restore_snapshot_state(&self, data: &[u8]) {
        (**self).restore_snapshot_state(data)
    }
}

/// A boxed future type alias for dyn-compatible async methods.
/// Note: No `Send` bound since futures run on a single-threaded runtime with `LocalSet`.
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + 'a>>;

/// A Send-able boxed future for factory creation (needs to cross thread boundary).
pub type SendBoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Factory trait for creating async block backends.
///
/// This pattern allows the backend to initialize async resources (like database
/// connections) inside the worker's tokio runtime, avoiding issues where async
/// resources are tied to a specific runtime.
///
/// Usage:
/// 1. Create a factory on the main thread with configuration
/// 2. Pass the factory to the VMM
/// 3. The async worker calls `create()` inside its own runtime
/// 4. Backend async resources are properly initialized on the correct runtime
pub trait AsyncBlockBackendFactory: Send + 'static {
    /// Returns the number of 512-byte sectors.
    /// This is needed before create() is called to set up the virtio config space.
    fn nsectors(&self) -> u64;

    /// Returns the cache type configuration.
    /// This is needed before create() is called for virtio feature negotiation.
    fn cache_type(&self) -> CacheType;

    /// Create the backend. Called inside the worker's tokio runtime.
    /// Takes self by value (via Box) so the factory is consumed.
    fn create(
        self: Box<Self>,
    ) -> SendBoxFuture<'static, io::Result<Arc<dyn AsyncBlockBackend + Send + Sync>>>;
}

/// Async version of BlockBackend for backends that benefit from concurrent I/O.
///
/// This trait enables request-level concurrency in the virtio block worker.
/// Multiple requests can be processed simultaneously, which is beneficial
/// for backends with high latency (e.g., object storage, network storage).
pub trait AsyncBlockBackend: Send + Sync + 'static {
    /// Returns the cache type configuration for this backend.
    fn cache_type(&self) -> CacheType;

    /// Returns the number of 512-byte sectors
    fn nsectors(&self) -> u64;

    /// Returns the device/image identifier bytes.
    fn image_id(&self) -> &[u8];

    /// Reads data from the backend at the given offset into the provided buffers.
    /// Returns the number of bytes read.
    fn read_vectored_at(
        &self,
        bufs: Vec<VolatileSliceGuard>,
        offset: u64,
    ) -> BoxFuture<'_, io::Result<usize>>;

    /// Writes data to the backend at the given offset from the provided buffers.
    /// Returns the number of bytes written.
    fn write_vectored_at(
        &self,
        bufs: Vec<VolatileSliceGuard>,
        offset: u64,
    ) -> BoxFuture<'_, io::Result<usize>>;

    /// Writes multiple regions in a single batch operation.
    /// Each tuple contains (offset, buffers) for one write.
    /// Returns the number of bytes written for each write in the batch.
    ///
    /// The default implementation calls write_vectored_at for each write sequentially.
    /// Backends can override this to implement more efficient batching (e.g., single WAL append).
    fn write_batch(
        &self,
        writes: Vec<(u64, Vec<VolatileSliceGuard>)>,
    ) -> BoxFuture<'_, io::Result<Vec<usize>>> {
        Box::pin(async move {
            let mut results = Vec::with_capacity(writes.len());
            for (offset, bufs) in writes {
                results.push(self.write_vectored_at(bufs, offset).await?);
            }
            Ok(results)
        })
    }

    /// Flushes any cached data to the underlying storage.
    fn flush(&self) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    /// Syncs data to persistent storage (fsync).
    fn sync(&self) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    /// Discards/trims the given range, potentially freeing underlying storage.
    fn discard(&self, _offset: u64, _len: u64) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    /// Writes zeroes to the given range.
    /// If `unmap` is true, the implementation may also discard the range.
    fn write_zeroes(&self, _offset: u64, _len: u64, _unmap: bool) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    /// Called when the VMM is shutting down.
    /// Use this for cleanup like flushing data to persistent storage.
    fn on_exit(&self) {}

    /// Serialize backend state for snapshot. Default: no state saved.
    fn save_snapshot_state(&self) -> Option<Vec<u8>> {
        None
    }

    /// Restore backend state from a previous snapshot. Default: no-op.
    fn restore_snapshot_state(&self, _data: &[u8]) {}
}

/// A guard that holds a pointer and length for a volatile memory region.
/// This is Send-safe as it represents owned access to the memory region.
#[derive(Clone)]
pub struct VolatileSliceGuard {
    pub(crate) ptr: *mut u8,
    pub(crate) len: usize,
}

// SAFETY: The VolatileSliceGuard represents exclusive access to a memory region
// that remains valid for the lifetime of the async operation.
unsafe impl Send for VolatileSliceGuard {}
unsafe impl Sync for VolatileSliceGuard {}

impl VolatileSliceGuard {
    /// Create a new guard from a VolatileSlice.
    ///
    /// # Safety
    /// The caller must ensure the underlying memory remains valid for the
    /// lifetime of this guard.
    pub unsafe fn from_volatile_slice(slice: &VolatileSlice) -> Self {
        Self {
            ptr: slice.ptr_guard_mut().as_ptr(),
            len: slice.len(),
        }
    }

    /// Create guards from a slice of VolatileSlices.
    ///
    /// # Safety
    /// The caller must ensure the underlying memory remains valid for the
    /// lifetime of these guards.
    pub unsafe fn from_volatile_slices(slices: &[VolatileSlice]) -> Vec<Self> {
        slices
            .iter()
            .map(|s| Self::from_volatile_slice(s))
            .collect()
    }

    /// Returns the length of the memory region.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the slice is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the raw pointer to the memory region.
    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Copy data from a byte slice into this memory region.
    ///
    /// # Safety
    /// The caller must ensure the source slice length matches or is less than
    /// this region's length.
    pub unsafe fn copy_from(&self, src: &[u8]) {
        debug_assert!(src.len() <= self.len);
        std::ptr::copy_nonoverlapping(src.as_ptr(), self.ptr, src.len());
    }

    /// Copy data from this memory region into a byte slice.
    ///
    /// # Safety
    /// The caller must ensure the destination slice length matches or is less than
    /// this region's length.
    pub unsafe fn copy_to(&self, dst: &mut [u8]) {
        debug_assert!(dst.len() <= self.len);
        std::ptr::copy_nonoverlapping(self.ptr, dst.as_mut_ptr(), dst.len());
    }

    /// Returns a sub-region of this guard.
    pub fn subslice(&self, offset: usize, len: usize) -> Option<Self> {
        if offset + len > self.len {
            return None;
        }
        Some(Self {
            ptr: unsafe { self.ptr.add(offset) },
            len,
        })
    }
}

impl<B> AsyncBlockBackend for std::sync::Arc<B>
where
    B: AsyncBlockBackend + ?Sized,
{
    fn cache_type(&self) -> CacheType {
        (**self).cache_type()
    }

    fn nsectors(&self) -> u64 {
        (**self).nsectors()
    }

    fn image_id(&self) -> &[u8] {
        (**self).image_id()
    }

    fn read_vectored_at(
        &self,
        bufs: Vec<VolatileSliceGuard>,
        offset: u64,
    ) -> BoxFuture<'_, io::Result<usize>> {
        (**self).read_vectored_at(bufs, offset)
    }

    fn write_vectored_at(
        &self,
        bufs: Vec<VolatileSliceGuard>,
        offset: u64,
    ) -> BoxFuture<'_, io::Result<usize>> {
        (**self).write_vectored_at(bufs, offset)
    }

    fn write_batch(
        &self,
        writes: Vec<(u64, Vec<VolatileSliceGuard>)>,
    ) -> BoxFuture<'_, io::Result<Vec<usize>>> {
        (**self).write_batch(writes)
    }

    fn flush(&self) -> BoxFuture<'_, io::Result<()>> {
        (**self).flush()
    }

    fn sync(&self) -> BoxFuture<'_, io::Result<()>> {
        (**self).sync()
    }

    fn discard(&self, offset: u64, len: u64) -> BoxFuture<'_, io::Result<()>> {
        (**self).discard(offset, len)
    }

    fn write_zeroes(&self, offset: u64, len: u64, unmap: bool) -> BoxFuture<'_, io::Result<()>> {
        (**self).write_zeroes(offset, len, unmap)
    }

    fn on_exit(&self) {
        (**self).on_exit()
    }
}
