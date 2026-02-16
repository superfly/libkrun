// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use super::{ActivateResult, InterruptTransport, Queue};
use crate::snapshot::SnapshotError;
use crate::virtio::AsAny;
use std::time::Duration;
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

/// Enum that indicates if a VirtioDevice is inactive or has been activated
/// and memory attached to it.
pub enum DeviceState {
    Inactive,
    Activated(GuestMemoryMmap, InterruptTransport),
}

impl DeviceState {
    pub fn signal_used_queue(&self) {
        match self {
            Self::Inactive => {
                warn!("DeviceState::signal_used_queue() called, but device is not activated")
            }
            Self::Activated(_, ref interrupt) => interrupt.signal_used_queue(),
        }
    }
}

impl DeviceState {
    pub fn is_activated(&self) -> bool {
        matches!(self, DeviceState::Activated(..))
    }
}

#[derive(Clone)]
pub struct VirtioShmRegion {
    pub host_addr: u64,
    pub guest_addr: u64,
    pub size: usize,
}

/// Trait for virtio devices to be driven by a virtio transport.
///
/// The lifecycle of a virtio device is to be moved to a virtio transport, which will then query the
/// device. The virtio devices needs to create queues, events and event fds for interrupts and expose
/// them to the transport via get_queues/get_queue_events
pub trait VirtioDevice: AsAny + Send {
    /// Get the available features offered by device.
    fn avail_features(&self) -> u64;

    /// Get acknowledged features of the driver.
    fn acked_features(&self) -> u64;

    /// Set acknowledged features of the driver.
    /// This function must maintain the following invariant:
    /// - self.avail_features() & self.acked_features() = self.get_acked_features()
    fn set_acked_features(&mut self, acked_features: u64);

    /// The virtio device type.
    fn device_type(&self) -> u32;

    /// Device name used for logging information about the device at the transport layer
    fn device_name(&self) -> &str;

    /// Returns the device queues.
    fn queues(&self) -> &[Queue];

    /// Returns a mutable reference to the device queues.
    fn queues_mut(&mut self) -> &mut [Queue];

    /// Returns the device queues event fds.
    fn queue_events(&self) -> &[EventFd];

    /// The set of feature bits shifted by `page * 32`.
    fn avail_features_by_page(&self, page: u32) -> u32 {
        let avail_features = self.avail_features();
        match page {
            // Get the lower 32-bits of the features bitfield.
            0 => avail_features as u32,
            // Get the upper 32-bits of the features bitfield.
            1 => (avail_features >> 32) as u32,
            _ => {
                warn!("Received request for unknown features page.");
                0u32
            }
        }
    }

    /// Acknowledges that this set of features should be enabled.
    fn ack_features_by_page(&mut self, page: u32, value: u32) {
        let mut v = match page {
            0 => u64::from(value),
            1 => u64::from(value) << 32,
            _ => {
                warn!("Cannot acknowledge unknown features page: {page}");
                0u64
            }
        };

        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let avail_features = self.avail_features();
        let unrequested_features = v & !avail_features;
        if unrequested_features != 0 {
            warn!("Received acknowledge request for unknown feature: {v:x}");
            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.set_acked_features(self.acked_features() | v);
    }

    /// Reads this device configuration space at `offset`.
    fn read_config(&self, offset: u64, data: &mut [u8]);

    /// Writes to this device configuration space at `offset`.
    fn write_config(&mut self, offset: u64, data: &[u8]);

    /// Performs the formal activation for a device, which can be verified also with `is_activated`.
    fn activate(&mut self, mem: GuestMemoryMmap, interrupt: InterruptTransport) -> ActivateResult;

    /// Checks if the resources of this device are activated.
    fn is_activated(&self) -> bool;

    /// Optionally deactivates this device and returns ownership of the guest memory map, interrupt
    /// event, and queue events.
    fn reset(&mut self) -> bool {
        false
    }

    /// Begin quiescing the device for snapshot save.
    ///
    /// Implementations should complete within `timeout` and leave the device in a snapshot-safe
    /// state. The default implementation is a no-op for backward compatibility.
    fn begin_snapshot_quiesce(&mut self, _timeout: Duration) -> Result<(), SnapshotError> {
        Ok(())
    }

    /// Abort an in-progress snapshot quiesce and return to normal operation.
    fn abort_snapshot_quiesce(&mut self) {}

    /// Synchronize any runtime queue state into `queues()` before snapshot serialization.
    fn sync_queues_for_snapshot(&mut self) {}

    /// Begin restore-time resync after state has been loaded.
    ///
    /// Implementations should complete within `timeout` and prepare workers/queues to continue
    /// normal operation. The default implementation is a no-op for backward compatibility.
    fn begin_restore_resync(&mut self, _timeout: Duration) -> Result<(), SnapshotError> {
        Ok(())
    }

    /// End restore-time resync and transition the device to its steady runtime state.
    fn end_restore_resync(&mut self) {}

    /// Kick all ready queues after snapshot restore so workers process any
    /// pending work. Skips queues the guest never configured (ready=false)
    /// to avoid accessing invalid GuestAddress(0) ring pointers.
    fn post_restore_kick(&mut self) {
        if !self.is_activated() {
            return;
        }
        for (i, (queue, evt)) in self
            .queues()
            .iter()
            .zip(self.queue_events().iter())
            .enumerate()
        {
            if !queue.ready {
                continue;
            }
            if let Err(e) = evt.write(1) {
                error!(
                    "{}: post_restore_kick queue {i} failed: {e}",
                    self.device_name()
                );
            }
        }
    }

    /// Perform any device-specific recovery steps after snapshot restore.
    fn post_snapshot_restore(&mut self) {}

    /// Return the backend's snapshot state, if any.
    ///
    /// Called after quiesce during snapshot save. The returned bytes are
    /// included in the device's serialized state and passed back to
    /// `restore_backend_state` on restore.
    fn save_backend_state(&self) -> Option<Vec<u8>> {
        None
    }

    /// Provide backend snapshot state for restore.
    ///
    /// Called before `post_snapshot_restore`, storing the data so the worker
    /// can pick it up during resync and call `backend.restore_snapshot_state()`.
    fn restore_backend_state(&mut self, _data: &[u8]) {}

    /// Get base and size of the SHM region
    fn shm_region(&self) -> Option<&VirtioShmRegion> {
        None
    }
}

pub trait VmmExitObserver: Send {
    /// Callback to finish processing or cleanup the device resources
    fn on_vmm_exit(&mut self) {}
}

impl<F: Fn() + Send> VmmExitObserver for F {
    fn on_vmm_exit(&mut self) {
        self()
    }
}

impl std::fmt::Debug for dyn VirtioDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "VirtioDevice type {}", self.device_type())
    }
}
