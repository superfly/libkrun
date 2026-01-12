// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use core::fmt;
use std::cmp;
use std::convert::From;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt;
#[cfg(target_os = "macos")]
use std::os::macos::fs::MetadataExt;
use std::path::PathBuf;
use std::result;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use imago::io_buffers::{IoVector, IoVectorMut};
use imago::{
    file::File as ImagoFile, qcow2::Qcow2, raw::Raw, vmdk::Vmdk, DynStorage, FormatDriverBuilder,
    PermissiveImplicitOpenGate, Storage, StorageOpenOptions, SyncFormatAccess,
};
use log::{error, warn};
use utils::eventfd::{EventFd, EFD_NONBLOCK};
use virtio_bindings::{
    virtio_blk::*, virtio_config::VIRTIO_F_VERSION_1, virtio_ring::VIRTIO_RING_F_EVENT_IDX,
};
use vm_memory::{ByteValued, GuestMemoryMmap, VolatileSlice};

use super::worker::BlockWorker;
use super::{
    super::{ActivateResult, DeviceState, Queue, VirtioDevice, TYPE_BLOCK},
    BlockBackend, Error, QUEUE_SIZES, SECTOR_SHIFT, SECTOR_SIZE,
};

use crate::virtio::block::{AsyncBlockBackendFactory, AsyncBlockWorker};
use crate::virtio::{
    block::{ImageType, SyncMode},
    ActivateError, InterruptTransport, VmmExitObserver,
};

/// Configuration options for disk caching.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CacheType {
    /// Flushing mechanic will be advertised to the guest driver, but
    /// the operation will be a noop.
    #[default]
    Unsafe,
    /// Flushing mechanic will be advertised to the guest driver and
    /// flush requests coming from the guest will be performed using
    /// `fsync`.
    Writeback,
}

impl CacheType {
    /// Picks the appropriate cache type based on disk image or device path.
    /// Special files like `/dev/rdisk*` on macOS do not support flush/sync.
    pub fn auto(_path: &str) -> CacheType {
        #[cfg(target_os = "macos")]
        if _path.starts_with("/dev/rdisk") {
            return CacheType::Unsafe;
        }
        CacheType::Writeback
    }
}

pub enum BlockDeviceType {
    Image {
        path: String,
        format: ImageType,
        sync_mode: SyncMode,
    },
    Custom {
        backend: Arc<dyn BlockBackend + Send + Sync>,
    },
    /// Async backend using factory pattern.
    /// The factory creates the backend inside the worker's tokio runtime,
    /// ensuring async resources (like database connections) are properly initialized.
    CustomAsyncFactory {
        factory: Box<dyn AsyncBlockBackendFactory>,
    },
}

impl fmt::Debug for BlockDeviceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Image {
                path,
                format,
                sync_mode,
            } => f
                .debug_struct("Image")
                .field("path", path)
                .field("format", format)
                .field("sync_mode", sync_mode)
                .finish(),
            Self::Custom { .. } => f.debug_struct("Custom").finish(),
            Self::CustomAsyncFactory { .. } => f.debug_struct("CustomAsyncFactory").finish(),
        }
    }
}

/// Helper object for setting up all `Block` fields derived from its backing file.
pub struct DiskProperties {
    cache_type: CacheType,
    pub(crate) file: Arc<Mutex<SyncFormatAccess<Box<dyn DynStorage>>>>,
    nsectors: u64,
    image_id: Vec<u8>,
}

impl DiskProperties {
    pub fn new(
        disk_image: Arc<Mutex<SyncFormatAccess<Box<dyn DynStorage>>>>,
        disk_image_id: Vec<u8>,
        cache_type: CacheType,
    ) -> io::Result<Self> {
        let disk_size = disk_image.lock().unwrap().size();

        // We only support disk size, which uses the first two words of the configuration space.
        // If the image is not a multiple of the sector size, the tail bits are not exposed.
        if !disk_size.is_multiple_of(SECTOR_SIZE) {
            warn!(
                "Disk size {disk_size} is not a multiple of sector size {SECTOR_SIZE}; \
                 the remainder will not be visible to the guest."
            );
        }

        Ok(Self {
            cache_type,
            nsectors: disk_size >> SECTOR_SHIFT,
            image_id: disk_image_id,
            file: disk_image,
        })
    }

    pub fn nsectors(&self) -> u64 {
        self.nsectors
    }

    pub fn image_id(&self) -> &[u8] {
        &self.image_id
    }

    fn build_device_id(disk_file: &File) -> result::Result<String, Error> {
        let blk_metadata = disk_file.metadata().map_err(Error::GetFileMetadata)?;
        // This is how kvmtool does it.
        let device_id = format!(
            "{}{}{}",
            blk_metadata.st_dev(),
            blk_metadata.st_rdev(),
            blk_metadata.st_ino()
        );
        Ok(device_id)
    }

    fn build_disk_image_id(disk_file: &File) -> Vec<u8> {
        let mut default_id = vec![0; VIRTIO_BLK_ID_BYTES as usize];
        match Self::build_device_id(disk_file) {
            Err(_) => {
                warn!("Could not generate device id. We'll use a default.");
            }
            Ok(m) => {
                // The kernel only knows to read a maximum of VIRTIO_BLK_ID_BYTES.
                // This will also zero out any leftover bytes.
                let disk_id = m.as_bytes();
                let bytes_to_copy = cmp::min(disk_id.len(), VIRTIO_BLK_ID_BYTES as usize);
                default_id[..bytes_to_copy].clone_from_slice(&disk_id[..bytes_to_copy])
            }
        }
        default_id
    }

    pub fn cache_type(&self) -> CacheType {
        self.cache_type
    }
}

impl Drop for DiskProperties {
    fn drop(&mut self) {
        match self.cache_type {
            CacheType::Writeback => {
                // flush() first to force any cached data out.
                if self.file.lock().unwrap().flush().is_err() {
                    error!("Failed to flush block data on drop.");
                }
                // Sync data out to physical media on host.
                if self.file.lock().unwrap().sync().is_err() {
                    error!("Failed to sync block data on drop.")
                }
            }
            CacheType::Unsafe => {
                // This is a noop.
            }
        };
    }
}

impl BlockBackend for DiskProperties {
    fn cache_type(&self) -> CacheType {
        self.cache_type
    }

    fn nsectors(&self) -> u64 {
        self.nsectors
    }

    fn image_id(&self) -> &[u8] {
        &self.image_id
    }

    fn read_vectored_at(&self, bufs: &[VolatileSlice], offset: u64) -> io::Result<usize> {
        if bufs.is_empty() {
            return Ok(0);
        }
        let (iovec, _guard) = IoVectorMut::from_volatile_slice(bufs);
        let full_length = iovec
            .len()
            .try_into()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.file.lock().unwrap().readv(iovec, offset)?;
        Ok(full_length)
    }

    fn write_vectored_at(&self, bufs: &[VolatileSlice], offset: u64) -> io::Result<usize> {
        if bufs.is_empty() {
            return Ok(0);
        }
        let (iovec, _guard) = IoVector::from_volatile_slice(bufs);
        let full_length = iovec
            .len()
            .try_into()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.file.lock().unwrap().writev(iovec, offset)?;
        Ok(full_length)
    }

    fn flush(&self) -> io::Result<()> {
        self.file.lock().unwrap().flush()
    }

    fn sync(&self) -> io::Result<()> {
        self.file.lock().unwrap().sync()
    }

    fn discard(&self, offset: u64, len: u64) -> io::Result<()> {
        self.file.lock().unwrap().discard_to_any(offset, len)
    }

    fn write_zeroes(&self, offset: u64, len: u64, unmap: bool) -> io::Result<()> {
        if unmap {
            self.file.lock().unwrap().discard_to_zero(offset, len)
        } else {
            self.file.lock().unwrap().write_zeroes(offset, len)
        }
    }
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioBlkGeometry {
    cylinders: u16,
    heads: u8,
    sectors: u8,
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioBlkTopology {
    physical_block_exp: u8,
    alignment_offset: u8,
    min_io_size: u16,
    opt_io_size: u32,
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioBlkConfig {
    capacity: u64,
    size_max: u32,
    seg_max: u32,
    geometry: VirtioBlkGeometry,
    blk_size: u32,
    topology: VirtioBlkTopology,
    writeback: u8,
    unused0: u8,
    num_queues: u16,
    max_discard_sectors: u32,
    max_discard_seg: u32,
    discard_sector_alignment: u32,
    max_write_zeroes_sectors: u32,
    max_write_zeroes_seg: u32,
    write_zeroes_may_unmap: u8,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioBlkConfig {}

/// Storage for block device backend - either sync backend or async factory.
enum BlockDeviceBackend {
    /// Synchronous backend (ready to use)
    Sync(Arc<dyn BlockBackend + Send + Sync>),
    /// Async backend factory (creates backend inside worker runtime)
    AsyncFactory(Box<dyn AsyncBlockBackendFactory>),
}

impl BlockDeviceBackend {
    fn nsectors(&self) -> u64 {
        match self {
            Self::Sync(b) => b.nsectors(),
            Self::AsyncFactory(f) => f.nsectors(),
        }
    }

    fn on_exit(&self) {
        match self {
            Self::Sync(b) => b.on_exit(),
            Self::AsyncFactory(_) => {
                // Factory hasn't created a backend yet, nothing to clean up.
                // The actual backend's on_exit is called by the worker when it shuts down.
            }
        }
    }
}

/// Virtio device for exposing block level read/write operations on a host file.
pub struct Block {
    // Host file and properties.
    disk: Option<BlockDeviceBackend>,
    worker_thread: Option<JoinHandle<()>>,
    worker_stopfd: EventFd,

    // Virtio fields.
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    config: VirtioBlkConfig,

    // Transport related fields.
    pub(crate) queues: Vec<Queue>,
    pub(crate) queue_evts: [EventFd; 1],
    pub(crate) device_state: DeviceState,

    // Implementation specific fields.
    pub(crate) id: String,
    pub(crate) partuuid: Option<String>,
}

impl Block {
    /// Create a new virtio block device that operates on the given file.
    ///
    /// The given file must be seekable and sizable.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        partuuid: Option<String>,
        cache_type: CacheType,
        disk_type: BlockDeviceType,
        is_disk_read_only: bool,
        direct_io: bool,
    ) -> io::Result<Block> {
        let (disk, discard_alignment, accepts_flush) = match disk_type {
            BlockDeviceType::Image {
                path,
                format,
                sync_mode,
            } => {
                let disk_image = OpenOptions::new()
                    .read(true)
                    .write(!is_disk_read_only)
                    .open(PathBuf::from(&path))?;

                let disk_image_id = DiskProperties::build_disk_image_id(&disk_image);

                let file_opts = StorageOpenOptions::new()
                    .write(!is_disk_read_only)
                    .filename(path)
                    .direct(direct_io);

                #[cfg(target_os = "macos")]
                let file_opts = file_opts.relaxed_sync(sync_mode == SyncMode::Relaxed);
                let file = ImagoFile::open_sync(file_opts)?;
                let discard_alignment = file.discard_align() as u32 / 512;

                let disk_image = match format {
                    ImageType::Qcow2 => {
                        let mut qcow2 =
                            Qcow2::<Box<dyn DynStorage>, Arc<imago::FormatAccess<_>>>::open_image_sync(
                                Box::new(file),
                                !is_disk_read_only,
                            )?;
                        qcow2.open_implicit_dependencies_sync()?;
                        SyncFormatAccess::new(qcow2)?
                    }
                    ImageType::Raw => {
                        let raw = Raw::<Box<dyn DynStorage>>::open_image_sync(
                            Box::new(file),
                            !is_disk_read_only,
                        )?;
                        SyncFormatAccess::new(raw)?
                    }
                    ImageType::Vmdk => {
                        let vmdk =
                            Vmdk::<Box<dyn DynStorage>, Arc<imago::FormatAccess<_>>>::builder(
                                Box::new(file),
                            )
                            .open_sync(PermissiveImplicitOpenGate::default())?;
                        SyncFormatAccess::new(vmdk)?
                    }
                };

                let disk_image = Arc::new(Mutex::new(disk_image));

                let disk_properties = DiskProperties::new(disk_image, disk_image_id, cache_type)?;

                (
                    BlockDeviceBackend::Sync(
                        Arc::new(disk_properties) as Arc<dyn BlockBackend + Send + Sync>
                    ),
                    discard_alignment,
                    sync_mode != SyncMode::None,
                )
            }
            BlockDeviceType::Custom { backend } => {
                (BlockDeviceBackend::Sync(backend), 128u32, true)
            }
            BlockDeviceType::CustomAsyncFactory { factory } => {
                (BlockDeviceBackend::AsyncFactory(factory), 128u32, true)
            }
        };

        let mut avail_features = (1u64 << VIRTIO_F_VERSION_1)
            | (1u64 << VIRTIO_BLK_F_SEG_MAX)
            | (1u64 << VIRTIO_BLK_F_DISCARD)
            | (1u64 << VIRTIO_BLK_F_WRITE_ZEROES)
            | (1u64 << VIRTIO_RING_F_EVENT_IDX);

        if accepts_flush {
            avail_features |= 1u64 << VIRTIO_BLK_F_FLUSH;
        }

        if is_disk_read_only {
            avail_features |= 1u64 << VIRTIO_BLK_F_RO;
        };

        let queue_evts = [EventFd::new(EFD_NONBLOCK)?];

        let queues = QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect();

        let config = VirtioBlkConfig {
            capacity: disk.nsectors(),
            size_max: 0,
            // QUEUE_SIZE - 2
            seg_max: 254,
            max_discard_sectors: u32::MAX,
            max_discard_seg: 1,
            discard_sector_alignment: discard_alignment,
            max_write_zeroes_sectors: u32::MAX,
            max_write_zeroes_seg: 1,
            write_zeroes_may_unmap: 1,
            ..Default::default()
        };

        Ok(Block {
            id,
            partuuid,
            config,
            disk: Some(disk),
            avail_features,
            acked_features: 0u64,
            queue_evts,
            queues,
            device_state: DeviceState::Inactive,
            worker_thread: None,
            worker_stopfd: EventFd::new(EFD_NONBLOCK)?,
        })
    }

    /// Provides the ID of this block device.
    pub fn id(&self) -> &String {
        &self.id
    }

    /// Provides the PARTUUID of this block device.
    pub fn partuuid(&self) -> Option<&String> {
        self.partuuid.as_ref()
    }

    /// Specifies if this block device is read only.
    pub fn is_read_only(&self) -> bool {
        self.avail_features & (1u64 << VIRTIO_BLK_F_RO) != 0
    }
}

impl VirtioDevice for Block {
    fn device_type(&self) -> u32 {
        TYPE_BLOCK
    }

    fn device_name(&self) -> &str {
        "block"
    }

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_evts
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        error!("Guest attempted to write config");
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn activate(&mut self, mem: GuestMemoryMmap, interrupt: InterruptTransport) -> ActivateResult {
        log::debug!("block: activate called");
        if self.worker_thread.is_some() {
            panic!("virtio_blk: worker thread already exists");
        }

        let event_idx: bool = (self.acked_features & (1 << VIRTIO_RING_F_EVENT_IDX)) != 0;
        self.queues[0].set_event_idx(event_idx);

        // Take ownership of the disk - for async factory we need to move it to the worker
        let disk = self.disk.take().ok_or(ActivateError::BadActivate)?;

        match disk {
            BlockDeviceBackend::Sync(backend) => {
                log::debug!("block: starting sync worker");
                // Put the backend back so on_exit can access it
                self.disk = Some(BlockDeviceBackend::Sync(backend.clone()));

                let worker = BlockWorker::new(
                    self.queues[0].clone(),
                    self.queue_evts[0].try_clone().unwrap(),
                    interrupt.clone(),
                    mem.clone(),
                    backend,
                    self.worker_stopfd.try_clone().unwrap(),
                );
                self.worker_thread = Some(worker.run());
            }
            BlockDeviceBackend::AsyncFactory(factory) => {
                log::debug!("block: starting async worker with factory");
                // Factory is consumed by the worker, don't put it back
                let worker = AsyncBlockWorker::new(
                    self.queues[0].clone(),
                    self.queue_evts[0].try_clone().unwrap(),
                    interrupt.clone(),
                    mem.clone(),
                    factory,
                    self.worker_stopfd.try_clone().unwrap(),
                );
                self.worker_thread = Some(worker.run());
            }
        }

        self.device_state = DeviceState::Activated(mem, interrupt);
        Ok(())
    }

    fn reset(&mut self) -> bool {
        if let Some(worker) = self.worker_thread.take() {
            let _ = self.worker_stopfd.write(1);
            if let Err(e) = worker.join() {
                error!("error waiting for worker thread: {e:?}");
            }
        }
        self.device_state = DeviceState::Inactive;
        true
    }
}

impl VmmExitObserver for Block {
    fn on_vmm_exit(&mut self) {
        // Stop the worker first
        self.reset();

        // Then call on_exit on the backend for cleanup
        if let Some(disk) = &self.disk {
            disk.on_exit();
        }
    }
}
