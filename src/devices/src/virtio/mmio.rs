// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use super::device_status;
use super::*;
use crate::bus::BusDevice;
use crate::legacy::IrqChip;
use crate::snapshot::{SnapshotError, Snapshottable};
use utils::{byte_order, eventfd::EventFd};
use vm_memory::{Address, GuestAddress, GuestMemoryMmap};

//TODO crosvm uses 0 here, but IIRC virtio specified some other vendor id that should be used
const VENDOR_ID: u32 = 0;

//required by the virtio mmio device register layout at offset 0 from base
const MMIO_MAGIC_VALUE: u32 = 0x7472_6976;

//current version specified by the mmio standard (legacy devices used 1 here)
const MMIO_VERSION: u32 = 2;
const SNAPSHOT_QUIESCE_TIMEOUT: Duration = Duration::from_millis(250);
const SNAPSHOT_RESYNC_TIMEOUT: Duration = Duration::from_millis(250);

#[derive(Debug)]
pub enum CreateMmioTransportError {
    CreateInterruptEventFd(io::Error),
}

impl Display for CreateMmioTransportError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            CreateMmioTransportError::CreateInterruptEventFd(err) => {
                write!(f, "failed to create interrupt eventfd: {err}")
            }
        }
    }
}

/// Implements the
/// [MMIO](http://docs.oasis-open.org/virtio/virtio/v1.0/cs04/virtio-v1.0-cs04.html#x1-1090002)
/// transport for virtio devices.
///
/// This requires 3 points of installation to work with a VM:
///
/// 1. Mmio reads and writes must be sent to this device at what is referred to here as MMIO base.
/// 1. `Mmio::queue_evts` must be installed at `virtio::NOTIFY_REG_OFFSET` offset from the MMIO
///    base. Each event in the array must be signaled if the index is written at that offset.
/// 1. `Mmio::interrupt_evt` must signal an interrupt that the guest driver is listening to when it
///    is written to.
///
/// Typically one page (4096 bytes) of MMIO address space is sufficient to handle this transport
/// and inner virtio device.
pub struct MmioTransport {
    device: Arc<Mutex<dyn VirtioDevice>>,
    // The register where feature bits are stored.
    pub(crate) features_select: u32,
    // The register where features page is selected.
    pub(crate) acked_features_select: u32,
    pub(crate) queue_select: u32,
    pub(crate) device_status: u32,
    pub(crate) config_generation: u32,
    mem: GuestMemoryMmap,
    queue_evts: HashMap<u32, EventFd>,
    shm_region_select: u32,
    interrupt: InterruptTransport,
    /// Set by restore_state when the device needs activate() called.
    /// Cleared by complete_restore(). This defers thread spawning until
    /// after all snapshot state (memory, interrupts, devices) is loaded,
    /// preventing races where newly-spawned threads fire IRQs that get
    /// overwritten by later restore steps.
    #[cfg(feature = "snapshot")]
    needs_post_restore_activate: bool,
}

struct InterruptTransportInner {
    log_target: String,
    status: AtomicUsize,
    event: EventFd,
    intc: IrqChip,
    irq_line: Option<u32>,
}

#[derive(Clone)]
pub struct InterruptTransport(Arc<InterruptTransportInner>);

impl InterruptTransport {
    pub fn new(intc: IrqChip, log_target: String) -> Result<Self, CreateMmioTransportError> {
        Ok(Self(Arc::new(InterruptTransportInner {
            log_target,
            status: AtomicUsize::new(0),
            event: EventFd::new(0).map_err(CreateMmioTransportError::CreateInterruptEventFd)?,
            intc,
            irq_line: None,
        })))
    }

    pub fn status(&self) -> &AtomicUsize {
        &self.0.status
    }

    pub fn event(&self) -> &EventFd {
        &self.0.event
    }

    pub fn intc(&self) -> &IrqChip {
        &self.0.intc
    }

    pub fn irq_line(&self) -> Option<u32> {
        self.0.irq_line
    }

    fn set_irq_line(&mut self, irq_line: u32) {
        debug!(target: &self.0.log_target, "set_irq_line: {irq_line}");
        match Arc::get_mut(&mut self.0) {
            None => {
                error!("Cannot change irq_line of activated device");
            }
            Some(interrupt) => {
                interrupt.irq_line = Some(irq_line);
            }
        }
    }

    fn try_signal(&self, status: u32) -> Result<(), crate::Error> {
        self.status().fetch_or(status as usize, Ordering::SeqCst);
        // Always fire the GIC interrupt. Skipping when the ISR bit is
        // already set causes a race: if Thread A sets the bit and fires,
        // and Thread B adds work to the used ring + sets the bit (no-op)
        // while the guest is mid-handler (between reading used_idx and
        // acking), Thread B's work is silently missed — the ack clears
        // the bit and the re-assertion sees remaining=0.
        // A spurious interrupt (guest sees ISR=0) is harmless — the guest
        // just returns from the handler without processing.
        self.intc()
            .lock()
            .unwrap()
            .set_irq(self.0.irq_line, Some(&self.0.event))?;
        Ok(())
    }

    pub fn try_signal_used_queue(&self) -> Result<(), crate::Error> {
        debug!(target: &self.0.log_target, "interrupt: signal_used_queue");
        self.try_signal(VIRTIO_MMIO_INT_VRING)
    }

    pub fn try_signal_config_change(&self) -> Result<(), crate::Error> {
        debug!(target: &self.0.log_target, "interrupt: signal_config_change");
        self.try_signal(VIRTIO_MMIO_INT_CONFIG)
    }

    pub fn signal_used_queue(&self) {
        if let Err(e) = self.try_signal_used_queue() {
            warn!(target: &self.0.log_target, "Failed to signal used queue: {e:?}");
        }
    }

    pub fn signal_config_change(&self) {
        if let Err(e) = self.try_signal_config_change() {
            warn!(target: &self.0.log_target, "Failed to signal config change: {e:?}");
        }
    }
}

impl MmioTransport {
    /// Constructs a new MMIO transport for the given virtio device.
    pub fn new(
        mem: GuestMemoryMmap,
        intc: IrqChip,
        device: Arc<Mutex<dyn VirtioDevice>>,
    ) -> Result<MmioTransport, CreateMmioTransportError> {
        let debug_log_target = format!(
            "{}[{}]",
            module_path!(),
            device
                .try_lock()
                .expect(
                    "Mutex of VirtioDevice should not be locked when calling MmioTransport::new"
                )
                .device_name()
        );

        Ok(MmioTransport {
            interrupt: InterruptTransport::new(intc, debug_log_target)?,
            device,
            features_select: 0,
            acked_features_select: 0,
            queue_select: 0,
            device_status: device_status::INIT,
            config_generation: 0,
            mem,
            queue_evts: HashMap::new(),
            shm_region_select: 0,
            #[cfg(feature = "snapshot")]
            needs_post_restore_activate: false,
        })
    }

    /// Set the irq line for the device.
    /// NOTE: Can only be called when the device is not activated
    pub fn set_irq_line(&mut self, irq_line: u32) {
        self.interrupt.set_irq_line(irq_line);
    }

    pub fn interrupt_evt(&self) -> &EventFd {
        self.interrupt.event()
    }

    pub fn locked_device(&self) -> MutexGuard<'_, dyn VirtioDevice + 'static> {
        self.device.lock().expect("Poisoned device lock")
    }

    // Gets the encapsulated VirtioDevice.
    pub fn device(&self) -> Arc<Mutex<dyn VirtioDevice>> {
        self.device.clone()
    }

    pub fn begin_snapshot_quiesce(&self, timeout: Duration) -> Result<(), SnapshotError> {
        let mut device = self.locked_device();
        let device_id = device.device_name().to_string();

        device
            .begin_snapshot_quiesce(timeout)
            .map_err(|err| map_quiesce_error(device_id, timeout, err))
    }

    pub fn abort_snapshot_quiesce(&self) {
        self.locked_device().abort_snapshot_quiesce();
    }

    pub fn begin_restore_resync(&self, timeout: Duration) -> Result<(), SnapshotError> {
        let mut device = self.locked_device();
        let device_id = device.device_name().to_string();
        debug!("mmio: begin_restore_resync '{}'", device_id);

        device
            .begin_restore_resync(timeout)
            .map_err(|err| map_resync_error(device_id, timeout, err))
    }

    pub fn end_restore_resync(&self) {
        let device_id = self.locked_device().device_name().to_string();
        debug!("mmio: end_restore_resync '{}'", device_id);
        self.locked_device().end_restore_resync();
    }

    pub fn post_restore_kick(&self) {
        self.locked_device().post_restore_kick();
    }

    pub fn register_queue_evt(&mut self, queue_evt: EventFd, id: u32) {
        self.queue_evts.insert(id, queue_evt);
    }

    fn check_device_status(&self, set: u32, clr: u32) -> bool {
        self.device_status & (set | clr) == set
    }

    fn with_queue<U, F>(&self, d: U, f: F) -> U
    where
        F: FnOnce(&Queue) -> U,
    {
        match self
            .locked_device()
            .queues()
            .get(self.queue_select as usize)
        {
            Some(queue) => f(queue),
            None => d,
        }
    }

    fn with_queue_mut<F: FnOnce(&mut Queue)>(&mut self, f: F) -> bool {
        if let Some(queue) = self
            .locked_device()
            .queues_mut()
            .get_mut(self.queue_select as usize)
        {
            f(queue);
            true
        } else {
            false
        }
    }

    fn update_queue_field<F: FnOnce(&mut Queue)>(&mut self, f: F) {
        if self.check_device_status(device_status::FEATURES_OK, device_status::FAILED) {
            self.with_queue_mut(f);
        } else {
            warn!(
                "update virtio queue in invalid state 0x{:x}",
                self.device_status
            );
        }
    }

    fn reset(&mut self) {
        if self.locked_device().is_activated() {
            debug!("reset device while it's still in active state");
        }
        self.features_select = 0;
        self.acked_features_select = 0;
        self.queue_select = 0;
        self.interrupt.0.status.store(0, Ordering::SeqCst);
        self.device_status = device_status::INIT;
        // . Keep interrupt_evt and queue_evts as is. There may be pending
        //   notifications in those eventfds, but nothing will happen other
        //   than supurious wakeups.
        // . Do not reset config_generation and keep it monotonically increasing
        for queue in self.locked_device().queues_mut() {
            *queue = Queue::new(queue.get_max_size());
        }
    }

    /// Update device status according to the state machine defined by VirtIO Spec 1.0.
    /// Please refer to VirtIO Spec 1.0, section 2.1.1 and 3.1.1.
    ///
    /// The driver MUST update device status, setting bits to indicate the completed steps
    /// of the driver initialization sequence specified in 3.1. The driver MUST NOT clear
    /// a device status bit. If the driver sets the FAILED bit, the driver MUST later reset
    /// the device before attempting to re-initialize.
    #[allow(unused_assignments)]
    fn set_device_status(&mut self, status: u32) {
        use device_status::*;
        // match changed bits
        match !self.device_status & status {
            ACKNOWLEDGE if self.device_status == INIT => {
                self.device_status = status;
            }
            DRIVER if self.device_status == ACKNOWLEDGE => {
                self.device_status = status;
            }
            FEATURES_OK if self.device_status == (ACKNOWLEDGE | DRIVER) => {
                self.device_status = status;
            }
            DRIVER_OK if self.device_status == (ACKNOWLEDGE | DRIVER | FEATURES_OK) => {
                self.device_status = status;
                let device_activated = self.locked_device().is_activated();
                if !device_activated {
                    self.locked_device()
                        .activate(self.mem.clone(), self.interrupt.clone())
                        .expect("Failed to activate device");
                }
            }
            _ if (status & FAILED) != 0 => {
                // TODO: notify backend driver to stop the device
                self.device_status |= FAILED;
            }
            _ if status == 0 => {
                if self.locked_device().is_activated() && !self.locked_device().reset() {
                    self.device_status |= FAILED;
                }

                // If the backend device driver doesn't support reset,
                // just leave the device marked as FAILED.
                if self.device_status & FAILED == 0 {
                    self.reset();
                }
            }
            _ => {
                warn!(
                    "invalid virtio driver status transition: 0x{:x} -> 0x{:x}",
                    self.device_status, status
                );
            }
        }
    }
}

fn map_quiesce_error(device_id: String, timeout: Duration, err: SnapshotError) -> SnapshotError {
    match err {
        SnapshotError::QuiesceTimeout { detail, .. } => SnapshotError::QuiesceTimeout {
            device_id,
            timeout_ms: timeout.as_millis() as u64,
            detail,
        },
        SnapshotError::QuiesceFailure { detail, .. } => {
            SnapshotError::QuiesceFailure { device_id, detail }
        }
        other => SnapshotError::QuiesceFailure {
            device_id,
            detail: Some(other.to_string()),
        },
    }
}

fn map_resync_error(device_id: String, timeout: Duration, err: SnapshotError) -> SnapshotError {
    match err {
        SnapshotError::ResyncTimeout { detail, .. } => SnapshotError::ResyncTimeout {
            device_id,
            timeout_ms: timeout.as_millis() as u64,
            detail,
        },
        SnapshotError::ResyncFailure { detail, .. } => {
            SnapshotError::ResyncFailure { device_id, detail }
        }
        other => SnapshotError::ResyncFailure {
            device_id,
            detail: Some(other.to_string()),
        },
    }
}

impl BusDevice for MmioTransport {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        match offset {
            0x00..=0xff if data.len() == 4 => {
                let v = match offset {
                    0x0 => MMIO_MAGIC_VALUE,
                    0x04 => MMIO_VERSION,
                    0x08 => self.locked_device().device_type(),
                    0x0c => VENDOR_ID, // vendor id
                    0x10 => {
                        let mut features = self
                            .locked_device()
                            .avail_features_by_page(self.features_select);
                        if self.features_select == 1 {
                            features |= 0x1; // enable support of VirtIO Version 1
                        }
                        features
                    }
                    0x34 => self.with_queue(0, |q| u32::from(q.get_max_size())),
                    0x44 => self.with_queue(0, |q| q.ready as u32),
                    0x60 => self.interrupt.status().load(Ordering::SeqCst) as u32,
                    0x70 => self.device_status,
                    0xfc => self.config_generation,
                    0xb0..=0xbc => {
                        // For no SHM region or invalid region the kernel looks for length of -1
                        let (shm_base, shm_len) = if self.shm_region_select > 1 {
                            (0, !0)
                        } else {
                            match self.locked_device().shm_region() {
                                Some(region) => (region.guest_addr, region.size as u64),
                                None => (0, !0),
                            }
                        };
                        match offset {
                            0xb0 => shm_len as u32,
                            0xb4 => (shm_len >> 32) as u32,
                            0xb8 => shm_base as u32,
                            0xbc => (shm_base >> 32) as u32,
                            _ => {
                                error!("invalid shm region offset");
                                0
                            }
                        }
                    }
                    _ => {
                        warn!("unknown virtio mmio register read: 0x{offset:x}");
                        return;
                    }
                };
                byte_order::write_le_u32(data, v);
            }
            0x100..=0xfff => self.locked_device().read_config(offset - 0x100, data),
            _ => {
                warn!(
                    "invalid virtio mmio read: 0x{:x}:0x{:x}",
                    offset,
                    data.len()
                );
            }
        };
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        fn hi(v: &mut GuestAddress, x: u32) {
            *v = (*v & 0xffff_ffff) | (u64::from(x) << 32)
        }

        fn lo(v: &mut GuestAddress, x: u32) {
            *v = (*v & !0xffff_ffff) | u64::from(x)
        }

        match offset {
            0x00..=0xff if data.len() == 4 => {
                let v = byte_order::read_le_u32(data);
                match offset {
                    0x14 => self.features_select = v,
                    0x20 => {
                        if self.check_device_status(
                            device_status::DRIVER,
                            device_status::FEATURES_OK | device_status::FAILED,
                        ) {
                            self.locked_device()
                                .ack_features_by_page(self.acked_features_select, v);
                        } else {
                            warn!(
                                "ack virtio features in invalid state 0x{:x}",
                                self.device_status
                            );
                        }
                    }
                    0x24 => self.acked_features_select = v,
                    0x30 => self.queue_select = v,
                    0x38 => self.update_queue_field(|q| q.size = v as u16),
                    0x44 => self.update_queue_field(|q| q.ready = v == 1),
                    0x50 => {
                        if let Some(eventfd) = self.queue_evts.get(&v) {
                            eventfd.write(v as u64).unwrap();
                        }
                    }
                    0x64 => {
                        if self.check_device_status(device_status::DRIVER_OK, 0) {
                            self.interrupt
                                .status()
                                .fetch_and(!(v as usize), Ordering::SeqCst);
                            // Level-triggered re-assertion: if new status bits arrived
                            // between the guest's ISR read and this ack, the ISR is still
                            // non-zero. Re-fire the GIC interrupt so the guest processes them.
                            let remaining =
                                self.interrupt.status().load(Ordering::SeqCst) as u32;
                            if remaining != 0 {
                                if let Err(e) = self
                                    .interrupt
                                    .intc()
                                    .lock()
                                    .unwrap()
                                    .set_irq(self.interrupt.irq_line(), Some(self.interrupt.event()))
                                {
                                    log::error!("failed to re-assert interrupt after ack: {e:?}");
                                }
                            }
                        }
                    }
                    0x70 => self.set_device_status(v),
                    0x80 => self.update_queue_field(|q| lo(&mut q.desc_table, v)),
                    0x84 => self.update_queue_field(|q| hi(&mut q.desc_table, v)),
                    0x90 => self.update_queue_field(|q| lo(&mut q.avail_ring, v)),
                    0x94 => self.update_queue_field(|q| hi(&mut q.avail_ring, v)),
                    0xa0 => self.update_queue_field(|q| lo(&mut q.used_ring, v)),
                    0xa4 => self.update_queue_field(|q| hi(&mut q.used_ring, v)),
                    0xac => self.shm_region_select = v,
                    _ => {
                        warn!("unknown virtio mmio register write: 0x{offset:x}");
                    }
                }
            }
            0x100..=0xfff => {
                if self.check_device_status(device_status::DRIVER, device_status::FAILED) {
                    self.locked_device().write_config(offset - 0x100, data)
                } else {
                    warn!("can not write to device config data area before driver is ready");
                }
            }
            _ => {
                warn!(
                    "invalid virtio mmio write: 0x{:x}:0x{:x}",
                    offset,
                    data.len()
                );
            }
        }
    }

    fn interrupt(&self, irq_mask: u32) -> std::io::Result<()> {
        self.interrupt
            .status()
            .fetch_or(irq_mask as usize, Ordering::SeqCst);
        // interrupt_evt() is safe to unwrap because the inner interrupt_evt is initialized in the
        // constructor.
        // write() is safe to unwrap because the inner syscall is tailored to be safe as well.
        self.interrupt.event().write(1).unwrap();
        Ok(())
    }

    fn as_snapshottable(&self) -> Option<&dyn Snapshottable> {
        Some(self)
    }

    fn as_snapshottable_mut(&mut self) -> Option<&mut dyn Snapshottable> {
        Some(self)
    }

    fn quiesce_workers(
        &self,
        timeout: std::time::Duration,
    ) -> std::result::Result<(), SnapshotError> {
        self.begin_snapshot_quiesce(timeout)
    }

    fn resume_workers(&self) {
        self.abort_snapshot_quiesce();
    }

    #[cfg(feature = "snapshot")]
    fn complete_restore(&mut self) -> std::result::Result<(), SnapshotError> {
        self.complete_restore()
    }
}

/// Serializable state for an MmioTransport device.
#[cfg_attr(feature = "snapshot", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone)]
pub struct MmioTransportState {
    pub features_select: u32,
    pub acked_features_select: u32,
    pub queue_select: u32,
    pub device_status: u32,
    pub config_generation: u32,
    pub interrupt_status: u32,
    pub queue_states: Vec<QueueState>,
    /// The inner device's negotiated features. Without this, after restore
    /// the device has acked_features=0, so event_idx is false while the guest
    /// still uses EVENT_IDX — breaking kick suppression and causing hangs.
    #[cfg_attr(feature = "snapshot", serde(default))]
    pub acked_features: u64,
    /// Opaque backend state blob. Backends that implement
    /// `save_snapshot_state` / `restore_snapshot_state` use this to preserve
    /// connection state (e.g., TCP sockets, NAT mappings) across snapshots.
    #[cfg_attr(feature = "snapshot", serde(default))]
    pub backend_state: Option<Vec<u8>>,
}

/// Serializable state for a virtio queue.
#[cfg_attr(feature = "snapshot", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone)]
pub struct QueueState {
    pub size: u16,
    pub ready: bool,
    pub desc_table: u64,
    pub avail_ring: u64,
    pub used_ring: u64,
    pub next_avail: u16,
    pub next_used: u16,
}

impl Snapshottable for MmioTransport {
    fn snapshot_id(&self) -> &str {
        // Use the device name as the snapshot ID
        // We can't store a String here easily, so return a static-ish identifier
        "mmio-transport"
    }

    fn save_state(&self) -> Result<Vec<u8>, SnapshotError> {
        self.begin_snapshot_quiesce(SNAPSHOT_QUIESCE_TIMEOUT)?;

        let save_result = (|| {
            let mut device = self.locked_device();
            device.sync_queues_for_snapshot();
            let queue_states: Vec<QueueState> = device
                .queues()
                .iter()
                .map(|q| QueueState {
                    size: q.size,
                    ready: q.ready,
                    desc_table: q.desc_table.raw_value(),
                    avail_ring: q.avail_ring.raw_value(),
                    used_ring: q.used_ring.raw_value(),
                    next_avail: q.next_avail().0,
                    next_used: q.next_used().0,
                })
                .collect();

            let backend_state = device.save_backend_state();

            let state = MmioTransportState {
                features_select: self.features_select,
                acked_features_select: self.acked_features_select,
                queue_select: self.queue_select,
                device_status: self.device_status,
                config_generation: self.config_generation,
                interrupt_status: self.interrupt.0.status.load(Ordering::SeqCst) as u32,
                queue_states,
                acked_features: device.acked_features(),
                backend_state,
            };

            #[cfg(feature = "snapshot")]
            {
                bincode::serialize(&state).map_err(|e| SnapshotError::Serialize(e.to_string()))
            }
            #[cfg(not(feature = "snapshot"))]
            {
                let _ = state;
                Err(SnapshotError::Serialize(
                    "snapshot feature not enabled".to_string(),
                ))
            }
        })();

        self.abort_snapshot_quiesce();
        save_result
    }

    fn restore_state(&mut self, data: &[u8]) -> Result<(), SnapshotError> {
        self.begin_restore_resync(SNAPSHOT_RESYNC_TIMEOUT)?;

        let restore_result = (|| {
            #[cfg(feature = "snapshot")]
            {
                let state: MmioTransportState = bincode::deserialize(data)
                    .map_err(|e| SnapshotError::Deserialize(e.to_string()))?;

                self.features_select = state.features_select;
                self.acked_features_select = state.acked_features_select;
                self.queue_select = state.queue_select;
                self.device_status = state.device_status;
                self.config_generation = state.config_generation;
                self.interrupt
                    .0
                    .status
                    .store(state.interrupt_status as usize, Ordering::SeqCst);
                let should_reactivate = (state.device_status & device_status::DRIVER_OK) != 0;

                let mut device = self.locked_device();

                // Restore acked_features BEFORE activate() so the device sees
                // the correct feature set (especially EVENT_IDX).
                device.set_acked_features(state.acked_features);

                for (i, qs) in state.queue_states.iter().enumerate() {
                    if let Some(queue) = device.queues_mut().get_mut(i) {
                        queue.size = qs.size;
                        queue.ready = qs.ready;
                        queue.desc_table = GuestAddress(qs.desc_table);
                        queue.avail_ring = GuestAddress(qs.avail_ring);
                        queue.used_ring = GuestAddress(qs.used_ring);
                        queue.set_next_avail(qs.next_avail);
                        queue.set_next_used(qs.next_used);
                    }
                }

                let device_name = device.device_name().to_string();
                let force_reactivate = matches!(device_name.as_str(), "console");
                if force_reactivate {
                    let _ = device.reset();
                }

                // Compute whether activation is needed while we hold the lock,
                // but defer the actual activate() call to complete_restore().
                let needs_activate =
                    should_reactivate && (!device.is_activated() || force_reactivate);

                debug!(
                    "mmio: restore_state '{}': should_reactivate={} is_activated={} force_reactivate={} needs_activate={}",
                    device_name, should_reactivate, device.is_activated(), force_reactivate, needs_activate
                );

                for (i, qs) in state.queue_states.iter().enumerate() {
                    debug!(
                        "mmio: restore_state '{}': queue[{}] size={} ready={} next_avail={} next_used={}",
                        device_name, i, qs.size, qs.ready, qs.next_avail, qs.next_used
                    );
                }

                if let Some(ref backend_data) = state.backend_state {
                    device.restore_backend_state(backend_data);
                }

                device.post_snapshot_restore();

                // Drop device lock before writing to self.
                drop(device);

                // Defer activation to complete_restore(). This ensures all
                // snapshot state (memory, interrupts, all device states) is
                // fully loaded before any device threads are spawned. Without
                // this, threads spawned by activate() can fire IRQs that race
                // with later restore steps.
                self.needs_post_restore_activate = needs_activate;

                Ok(())
            }
            #[cfg(not(feature = "snapshot"))]
            {
                let _ = data;
                Err(SnapshotError::Deserialize(
                    "snapshot feature not enabled".to_string(),
                ))
            }
        })();

        self.end_restore_resync();
        restore_result
    }
}

#[cfg(feature = "snapshot")]
impl MmioTransport {
    /// Activate the device and kick workers after all snapshot state is loaded.
    ///
    /// Must be called after restore_state() and after interrupt controller
    /// state has been restored. This is the point where device threads are
    /// spawned and can safely fire interrupts.
    pub fn complete_restore(&mut self) -> Result<(), SnapshotError> {
        let device_name = self.locked_device().device_name().to_string();
        debug!(
            "mmio: complete_restore '{}': needs_post_restore_activate={}",
            device_name, self.needs_post_restore_activate
        );
        if self.needs_post_restore_activate {
            self.needs_post_restore_activate = false;
            let mut device = self.locked_device();
            debug!("mmio: complete_restore '{}': calling activate()", device_name);
            device
                .activate(self.mem.clone(), self.interrupt.clone())
                .map_err(|e| {
                    SnapshotError::Deserialize(format!(
                        "failed to reactivate virtio device '{device_name}' during snapshot restore: {e:?}",
                    ))
                })?;
        }

        self.post_restore_kick();
        self.interrupt.signal_used_queue();

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use utils::byte_order::{read_le_u32, write_le_u32};

    use super::*;
    use crate::legacy::DummyIrqChip;
    use utils::eventfd::EventFd;
    use vm_memory::GuestMemoryMmap;

    pub(crate) struct DummyDevice {
        acked_features: u64,
        avail_features: u64,
        queue_evts: Vec<EventFd>,
        queues: Vec<Queue>,
        device_activated: bool,
        config_bytes: [u8; 0xeff],
    }

    impl DummyDevice {
        pub(crate) fn new() -> Self {
            DummyDevice {
                acked_features: 0,
                avail_features: 0,
                queue_evts: vec![
                    EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
                    EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
                ],
                queues: vec![Queue::new(16), Queue::new(32)],
                device_activated: false,
                config_bytes: [0; 0xeff],
            }
        }

        fn set_avail_features(&mut self, avail_features: u64) {
            self.avail_features = avail_features;
        }
    }

    impl VirtioDevice for DummyDevice {
        fn device_type(&self) -> u32 {
            123
        }

        fn device_name(&self) -> &str {
            "dummy"
        }

        fn read_config(&self, offset: u64, data: &mut [u8]) {
            data.copy_from_slice(&self.config_bytes[offset as usize..]);
        }

        fn write_config(&mut self, offset: u64, data: &[u8]) {
            for (i, item) in data.iter().enumerate() {
                self.config_bytes[offset as usize + i] = *item;
            }
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

        fn activate(
            &mut self,
            _mem: GuestMemoryMmap,
            _interrupt: InterruptTransport,
        ) -> ActivateResult {
            self.device_activated = true;
            Ok(())
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

        fn is_activated(&self) -> bool {
            self.device_activated
        }
    }

    fn set_device_status(d: &mut MmioTransport, status: u32) {
        let mut buf = [0; 4];
        write_le_u32(&mut buf[..], status);
        d.write(0, 0x70, &buf[..]);
    }

    #[test]
    fn test_new() {
        let m = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let dummy = DummyDevice::new();
        let mut d =
            MmioTransport::new(m, DummyIrqChip::new().into(), Arc::new(Mutex::new(dummy))).unwrap();

        // We just make sure here that the implementation of a mmio device behaves as we expect,
        // given a known virtio device implementation (the dummy device).

        assert_eq!(d.locked_device().queue_events().len(), 2);

        d.queue_select = 0;
        assert_eq!(d.with_queue(0, Queue::get_max_size), 16);
        assert!(d.with_queue_mut(|q| q.size = 16));
        assert_eq!(d.locked_device().queues()[d.queue_select as usize].size, 16);

        d.queue_select = 1;
        assert_eq!(d.with_queue(0, Queue::get_max_size), 32);
        assert!(d.with_queue_mut(|q| q.size = 16));
        assert_eq!(d.locked_device().queues()[d.queue_select as usize].size, 16);

        d.queue_select = 2;
        assert_eq!(d.with_queue(0, Queue::get_max_size), 0);
        assert!(!d.with_queue_mut(|q| q.size = 16));
    }

    #[test]
    fn test_bus_device_read() {
        let m = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let mut d = MmioTransport::new(
            m,
            DummyIrqChip::new().into(),
            Arc::new(Mutex::new(DummyDevice::new())),
        )
        .unwrap();

        let mut buf = vec![0xff, 0, 0xfe, 0];
        let buf_copy = buf.to_vec();

        // The following read shouldn't be valid, because the length of the buf is not 4.
        buf.push(0);
        d.read(0, 0, &mut buf[..]);
        assert_eq!(buf[..4], buf_copy[..]);

        // the length is ok again
        buf.pop();

        // Now we test that reading at various predefined offsets works as intended.

        d.read(0, 0, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), MMIO_MAGIC_VALUE);

        d.read(0, 0x04, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), MMIO_VERSION);

        d.read(0, 0x08, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), d.locked_device().device_type());

        d.read(0, 0x0c, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), VENDOR_ID);

        d.features_select = 0;
        d.read(0, 0x10, &mut buf[..]);
        assert_eq!(
            read_le_u32(&buf[..]),
            d.locked_device().avail_features_by_page(0)
        );

        d.features_select = 1;
        d.read(0, 0x10, &mut buf[..]);
        assert_eq!(
            read_le_u32(&buf[..]),
            d.locked_device().avail_features_by_page(0) | 0x1
        );

        d.read(0, 0x34, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), 16);

        d.read(0, 0x44, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), false as u32);

        d.interrupt.status().store(111, Ordering::SeqCst);
        d.read(0, 0x60, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), 111);

        d.read(0, 0x70, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), 0);

        d.config_generation = 5;
        d.read(0, 0xfc, &mut buf[..]);
        assert_eq!(read_le_u32(&buf[..]), 5);

        // This read shouldn't do anything, as it's past the readable generic registers, and
        // before the device specific configuration space. Btw, reads from the device specific
        // conf space are going to be tested a bit later, alongside writes.
        buf = buf_copy.to_vec();
        d.read(0, 0xfd, &mut buf[..]);
        assert_eq!(buf[..], buf_copy[..]);

        // Read from an invalid address in generic register range.
        d.read(0, 0xfb, &mut buf[..]);
        assert_eq!(buf[..], buf_copy[..]);

        // Read from an invalid length in generic register range.
        d.read(0, 0xfc, &mut buf[..3]);
        assert_eq!(buf[..], buf_copy[..]);
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_bus_device_write() {
        let m = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let dummy_dev = Arc::new(Mutex::new(DummyDevice::new()));
        let mut d = MmioTransport::new(m, DummyIrqChip::new().into(), dummy_dev.clone()).unwrap();
        let mut buf = vec![0; 5];
        write_le_u32(&mut buf[..4], 1);

        // Nothing should happen, because the slice len > 4.
        d.features_select = 0;
        d.write(0, 0x14, &buf[..]);
        assert_eq!(d.features_select, 0);

        buf.pop();

        assert_eq!(d.device_status, device_status::INIT);
        set_device_status(&mut d, device_status::ACKNOWLEDGE);

        // Acking features in invalid state shouldn't take effect.
        assert_eq!(d.locked_device().acked_features(), 0x0);
        d.acked_features_select = 0x0;
        write_le_u32(&mut buf[..], 1);
        d.write(0, 0x20, &buf[..]);
        assert_eq!(d.locked_device().acked_features(), 0x0);

        // Write to device specific configuration space should be ignored before setting device_status::DRIVER
        let buf1 = vec![1; 0xeff];
        for i in (0..0xeff).rev() {
            let mut buf2 = vec![0; 0xeff];

            d.write(0, 0x100 + i as u64, &buf1[i..]);
            d.read(0, 0x100, &mut buf2[..]);

            for item in buf2.iter().take(0xeff) {
                assert_eq!(*item, 0);
            }
        }

        set_device_status(&mut d, device_status::ACKNOWLEDGE | device_status::DRIVER);
        assert_eq!(
            d.device_status,
            device_status::ACKNOWLEDGE | device_status::DRIVER
        );

        // now writes should work
        d.features_select = 0;
        write_le_u32(&mut buf[..], 1);
        d.write(0, 0x14, &buf[..]);
        assert_eq!(d.features_select, 1);

        // Test acknowledging features on bus.
        d.acked_features_select = 0;
        write_le_u32(&mut buf[..], 0x124);

        // Set the device available features in order to make acknowledging possible.
        dummy_dev.lock().unwrap().set_avail_features(0x124);
        d.write(0, 0x20, &buf[..]);
        assert_eq!(d.locked_device().acked_features(), 0x124);

        d.acked_features_select = 0;
        write_le_u32(&mut buf[..], 2);
        d.write(0, 0x24, &buf[..]);
        assert_eq!(d.acked_features_select, 2);
        set_device_status(
            &mut d,
            device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::FEATURES_OK,
        );

        // Acking features in invalid state shouldn't take effect.
        assert_eq!(d.locked_device().acked_features(), 0x124);
        d.acked_features_select = 0x0;
        write_le_u32(&mut buf[..], 1);
        d.write(0, 0x20, &buf[..]);
        assert_eq!(d.locked_device().acked_features(), 0x124);

        // Setup queues
        d.queue_select = 0;
        write_le_u32(&mut buf[..], 3);
        d.write(0, 0x30, &buf[..]);
        assert_eq!(d.queue_select, 3);

        d.queue_select = 0;
        assert_eq!(d.locked_device().queues()[0].size, 0);
        write_le_u32(&mut buf[..], 16);
        d.write(0, 0x38, &buf[..]);
        assert_eq!(d.locked_device().queues()[0].size, 16);

        assert!(!d.locked_device().queues()[0].ready);
        write_le_u32(&mut buf[..], 1);
        d.write(0, 0x44, &buf[..]);
        assert!(d.locked_device().queues()[0].ready);

        assert_eq!(d.locked_device().queues()[0].desc_table.0, 0);
        write_le_u32(&mut buf[..], 123);
        d.write(0, 0x80, &buf[..]);
        assert_eq!(d.locked_device().queues()[0].desc_table.0, 123);
        d.write(0, 0x84, &buf[..]);
        assert_eq!(
            d.locked_device().queues()[0].desc_table.0,
            123 + (123 << 32)
        );

        assert_eq!(d.locked_device().queues()[0].avail_ring.0, 0);
        write_le_u32(&mut buf[..], 124);
        d.write(0, 0x90, &buf[..]);
        assert_eq!(d.locked_device().queues()[0].avail_ring.0, 124);
        d.write(0, 0x94, &buf[..]);
        assert_eq!(
            d.locked_device().queues()[0].avail_ring.0,
            124 + (124 << 32)
        );

        assert_eq!(d.locked_device().queues()[0].used_ring.0, 0);
        write_le_u32(&mut buf[..], 125);
        d.write(0, 0xa0, &buf[..]);
        assert_eq!(d.locked_device().queues()[0].used_ring.0, 125);
        d.write(0, 0xa4, &buf[..]);
        assert_eq!(d.locked_device().queues()[0].used_ring.0, 125 + (125 << 32));

        set_device_status(
            &mut d,
            device_status::ACKNOWLEDGE
                | device_status::DRIVER
                | device_status::FEATURES_OK
                | device_status::DRIVER_OK,
        );

        d.interrupt.status().store(0b10_1010, Ordering::Relaxed);
        write_le_u32(&mut buf[..], 0b111);
        d.write(0, 0x64, &buf[..]);
        assert_eq!(d.interrupt.status().load(Ordering::Relaxed), 0b10_1000);

        // Write to an invalid address in generic register range.
        write_le_u32(&mut buf[..], 0xf);
        d.config_generation = 0;
        d.write(0, 0xfb, &buf[..]);
        assert_eq!(d.config_generation, 0);

        // Write to an invalid length in generic register range.
        d.write(0, 0xfc, &buf[..2]);
        assert_eq!(d.config_generation, 0);

        // Here we test writes/read into/from the device specific configuration space.
        let buf1 = vec![1; 0xeff];
        for i in (0..0xeff).rev() {
            let mut buf2 = vec![0; 0xeff];

            d.write(0, 0x100 + i as u64, &buf1[i..]);
            d.read(0, 0x100, &mut buf2[..]);

            for item in buf2.iter().take(i) {
                assert_eq!(*item, 0);
            }

            assert_eq!(buf1[i..], buf2[i..]);
        }
    }

    #[test]
    fn test_bus_device_activate() {
        let m = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let mut d = MmioTransport::new(
            m,
            DummyIrqChip::new().into(),
            Arc::new(Mutex::new(DummyDevice::new())),
        )
        .unwrap();

        assert!(!d.locked_device().is_activated());
        assert_eq!(d.device_status, device_status::INIT);

        set_device_status(&mut d, device_status::ACKNOWLEDGE);
        set_device_status(&mut d, device_status::ACKNOWLEDGE | device_status::DRIVER);
        assert_eq!(
            d.device_status,
            device_status::ACKNOWLEDGE | device_status::DRIVER
        );

        // invalid state transition should have no effect
        set_device_status(
            &mut d,
            device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::DRIVER_OK,
        );
        assert_eq!(
            d.device_status,
            device_status::ACKNOWLEDGE | device_status::DRIVER
        );

        set_device_status(
            &mut d,
            device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::FEATURES_OK,
        );
        assert_eq!(
            d.device_status,
            device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::FEATURES_OK
        );

        let mut buf = [0; 4];
        let queue_len = d.locked_device().queues().len();
        for q in 0..queue_len {
            d.queue_select = q as u32;
            write_le_u32(&mut buf[..], 16);
            d.write(0, 0x38, &buf[..]);
            write_le_u32(&mut buf[..], 1);
            d.write(0, 0x44, &buf[..]);
        }
        assert!(!d.locked_device().is_activated());

        // Device should be ready for activation now.

        // A couple of invalid writes; will trigger warnings; shouldn't activate the device.
        d.write(0, 0xa8, &buf[..]);
        d.write(0, 0x1000, &buf[..]);
        assert!(!d.locked_device().is_activated());

        set_device_status(
            &mut d,
            device_status::ACKNOWLEDGE
                | device_status::DRIVER
                | device_status::FEATURES_OK
                | device_status::DRIVER_OK,
        );
        assert_eq!(
            d.device_status,
            device_status::ACKNOWLEDGE
                | device_status::DRIVER
                | device_status::FEATURES_OK
                | device_status::DRIVER_OK
        );
        assert!(d.locked_device().is_activated());
    }

    fn activate_device(d: &mut MmioTransport) {
        set_device_status(d, device_status::ACKNOWLEDGE);
        set_device_status(d, device_status::ACKNOWLEDGE | device_status::DRIVER);
        set_device_status(
            d,
            device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::FEATURES_OK,
        );

        // Setup queue data structures
        let mut buf = [0; 4];
        let queues_count = d.locked_device().queues().len();
        for q in 0..queues_count {
            d.queue_select = q as u32;
            write_le_u32(&mut buf[..], 16);
            d.write(0, 0x38, &buf[..]);
            write_le_u32(&mut buf[..], 1);
            d.write(0, 0x44, &buf[..]);
        }
        assert!(!d.locked_device().is_activated());

        // Device should be ready for activation now.
        set_device_status(
            d,
            device_status::ACKNOWLEDGE
                | device_status::DRIVER
                | device_status::FEATURES_OK
                | device_status::DRIVER_OK,
        );
        assert_eq!(
            d.device_status,
            device_status::ACKNOWLEDGE
                | device_status::DRIVER
                | device_status::FEATURES_OK
                | device_status::DRIVER_OK
        );
        assert!(d.locked_device().is_activated());
    }

    #[test]
    fn test_bus_device_reset() {
        let m = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();

        let mut d = MmioTransport::new(
            m,
            DummyIrqChip::new().into(),
            Arc::new(Mutex::new(DummyDevice::new())),
        )
        .unwrap();
        let mut buf = [0; 4];

        assert!(!d.locked_device().is_activated());
        assert_eq!(d.device_status, 0);
        activate_device(&mut d);

        // Marking device as FAILED should not affect device_activated state
        write_le_u32(&mut buf[..], 0x8f);
        d.write(0, 0x70, &buf[..]);
        assert_eq!(d.device_status, 0x8f);
        assert!(d.locked_device().is_activated());

        // Nothing happens when backend driver doesn't support reset
        write_le_u32(&mut buf[..], 0x0);
        d.write(0, 0x70, &buf[..]);
        assert_eq!(d.device_status, 0x8f);
        assert!(d.locked_device().is_activated());
    }

    #[test]
    fn test_get_avail_features() {
        let dummy_dev = DummyDevice::new();
        assert_eq!(dummy_dev.avail_features(), dummy_dev.avail_features);
    }

    #[test]
    fn test_get_acked_features() {
        let dummy_dev = DummyDevice::new();
        assert_eq!(dummy_dev.acked_features(), dummy_dev.acked_features);
    }

    #[test]
    fn test_set_acked_features() {
        let mut dummy_dev = DummyDevice::new();

        assert_eq!(dummy_dev.acked_features(), 0);
        dummy_dev.set_acked_features(16);
        assert_eq!(dummy_dev.acked_features(), dummy_dev.acked_features);
    }

    #[test]
    fn test_ack_features_by_page() {
        let mut dummy_dev = DummyDevice::new();
        dummy_dev.set_acked_features(16);
        dummy_dev.set_avail_features(8);
        dummy_dev.ack_features_by_page(0, 8);
        assert_eq!(dummy_dev.acked_features(), 24);
    }
}
