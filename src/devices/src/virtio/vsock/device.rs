// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use utils::byte_order;
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

use super::super::{
    ActivateError, ActivateResult, DeviceState, Queue as VirtQueue, VirtioDevice, VsockError,
};
use super::muxer::VsockMuxer;
use super::packet::VsockPacket;
use super::{defs, defs::uapi};
use crate::snapshot::SnapshotError;
use crate::virtio::InterruptTransport;

pub(crate) const RXQ_INDEX: usize = 0;
pub(crate) const TXQ_INDEX: usize = 1;
pub(crate) const EVQ_INDEX: usize = 2;

/// The virtio features supported by our vsock device:
/// - VIRTIO_F_VERSION_1: the device conforms to at least version 1.0 of the VirtIO spec.
/// - VIRTIO_F_IN_ORDER: the device returns used buffers in the same order that the driver makes
///   them available.
pub(crate) const AVAIL_FEATURES: u64 = (1 << uapi::VIRTIO_F_VERSION_1 as u64)
    | (1 << uapi::VIRTIO_F_IN_ORDER as u64)
    | (1 << uapi::VIRTIO_VSOCK_F_DGRAM);

pub struct Vsock {
    cid: u64,
    host_port_map: Option<HashMap<u16, u16>>,
    unix_ipc_port_map: Option<HashMap<u32, (PathBuf, bool)>>,
    enable_tsi: bool,
    enable_tsi_unix: bool,
    pub(crate) muxer: VsockMuxer,
    pub(crate) queue_rx: Arc<Mutex<VirtQueue>>,
    pub(crate) queue_tx: Arc<Mutex<VirtQueue>>,
    pub(crate) queues: Vec<VirtQueue>,
    pub(crate) queue_events: Vec<EventFd>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,

    muxer_quiesce_fd: EventFd,
    muxer_resume_fd: EventFd,
    muxer_quiesce_ack: Arc<(Mutex<bool>, Condvar)>,
    timesync_quiesce_fd: EventFd,
    timesync_resume_fd: EventFd,
    timesync_quiesce_ack: Arc<(Mutex<bool>, Condvar)>,
}

impl Vsock {
    pub(crate) fn with_queues(
        cid: u64,
        host_port_map: Option<HashMap<u16, u16>>,
        queues: Vec<VirtQueue>,
        unix_ipc_port_map: Option<HashMap<u32, (PathBuf, bool)>>,
        enable_tsi: bool,
        enable_tsi_unix: bool,
    ) -> super::Result<Vsock> {
        let mut queue_events = Vec::new();
        for _ in 0..queues.len() {
            queue_events
                .push(EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(VsockError::EventFd)?);
        }

        let queue_tx = Arc::new(Mutex::new(queues[TXQ_INDEX].clone()));
        let queue_rx = Arc::new(Mutex::new(queues[RXQ_INDEX].clone()));

        Ok(Vsock {
            cid,
            host_port_map: host_port_map.clone(),
            unix_ipc_port_map: unix_ipc_port_map.clone(),
            enable_tsi,
            enable_tsi_unix,
            muxer: VsockMuxer::new(
                cid,
                host_port_map,
                unix_ipc_port_map,
                enable_tsi,
                enable_tsi_unix,
            ),
            queue_rx,
            queue_tx,
            queues,
            queue_events,
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(VsockError::EventFd)?,
            device_state: DeviceState::Inactive,
            muxer_quiesce_fd: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(VsockError::EventFd)?,
            muxer_resume_fd: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(VsockError::EventFd)?,
            muxer_quiesce_ack: Arc::new((Mutex::new(false), Condvar::new())),
            timesync_quiesce_fd: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(VsockError::EventFd)?,
            timesync_resume_fd: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(VsockError::EventFd)?,
            timesync_quiesce_ack: Arc::new((Mutex::new(false), Condvar::new())),
        })
    }

    /// Create a new virtio-vsock device with the given VM CID.
    pub fn new(
        cid: u64,
        host_port_map: Option<HashMap<u16, u16>>,
        unix_ipc_port_map: Option<HashMap<u32, (PathBuf, bool)>>,
        enable_tsi: bool,
        enable_tsi_unix: bool,
    ) -> super::Result<Vsock> {
        let queues: Vec<VirtQueue> = defs::QUEUE_SIZES
            .iter()
            .map(|&max_size| VirtQueue::new(max_size))
            .collect();
        Self::with_queues(
            cid,
            host_port_map,
            queues,
            unix_ipc_port_map,
            enable_tsi,
            enable_tsi_unix,
        )
    }

    pub fn id(&self) -> &str {
        defs::VSOCK_DEV_ID
    }

    pub fn cid(&self) -> u64 {
        self.cid
    }

    /// Walk the driver-provided RX queue buffers and attempt to fill them up with any data that we
    /// have pending. Return `true` if descriptors have been added to the used ring, and `false`
    /// otherwise.
    pub fn process_stream_rx(&mut self) -> bool {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem, _) => mem,
            DeviceState::Inactive => unreachable!(),
        };

        let mut have_used = false;

        let mut queue_rx = self.queue_rx.lock().unwrap();
        debug!(
            "vsock: process_stream_rx: next_avail={} next_used={} pending_rx={}",
            queue_rx.next_avail(),
            queue_rx.next_used(),
            self.muxer.has_pending_rx()
        );
        while let Some(head) = queue_rx.pop(mem) {
            let used_len = match VsockPacket::from_rx_virtq_head(&head) {
                Ok(mut pkt) => {
                    if self.muxer.recv_pkt(&mut pkt).is_ok() {
                        debug!(
                            "vsock: RX pkt: op={} src={}:{} dst={}:{} len={} type={}",
                            pkt.op(),
                            pkt.src_cid(),
                            pkt.src_port(),
                            pkt.dst_cid(),
                            pkt.dst_port(),
                            pkt.len(),
                            pkt.type_()
                        );
                        pkt.hdr().len() as u32 + pkt.len()
                    } else {
                        queue_rx.undo_pop();
                        break;
                    }
                }
                Err(e) => {
                    warn!("vsock: RX queue head error: {e:?}");
                    0
                }
            };

            have_used = true;
            if let Err(e) = queue_rx.add_used(mem, head.index, used_len) {
                error!("vsock: RX add_used failed: {e:?}");
            }
        }

        self.queues[RXQ_INDEX] = queue_rx.clone();

        if have_used {
            debug!(
                "vsock: process_stream_rx: delivered packets, next_avail={} next_used={}",
                self.queues[RXQ_INDEX].next_avail(),
                self.queues[RXQ_INDEX].next_used()
            );
        }
        have_used
    }

    /// Walk the driver-provided TX queue buffers, package them up as vsock packets, and process
    /// them. Return `true` if descriptors have been added to the used ring, and `false` otherwise.
    pub fn process_stream_tx(&mut self) -> bool {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem, _) => mem,
            DeviceState::Inactive => unreachable!(),
        };

        let mut have_used = false;

        let mut queue_tx = self.queue_tx.lock().unwrap();
        debug!(
            "vsock: process_stream_tx: next_avail={} next_used={}",
            queue_tx.next_avail(),
            queue_tx.next_used()
        );
        while let Some(head) = queue_tx.pop(mem) {
            let pkt = match VsockPacket::from_tx_virtq_head(&head) {
                Ok(pkt) => pkt,
                Err(e) => {
                    error!("vsock: TX packet read error: {e:?}");
                    have_used = true;
                    if let Err(e) = queue_tx.add_used(mem, head.index, 0) {
                        error!("vsock: TX add_used failed: {e:?}");
                    }
                    continue;
                }
            };

            debug!(
                "vsock: TX pkt: op={} src={}:{} dst={}:{} len={} type={}",
                pkt.op(),
                pkt.src_cid(),
                pkt.src_port(),
                pkt.dst_cid(),
                pkt.dst_port(),
                pkt.len(),
                pkt.type_()
            );

            if pkt.type_() == uapi::VSOCK_TYPE_DGRAM {
                if self.muxer.send_dgram_pkt(&pkt).is_err() {
                    queue_tx.undo_pop();
                    break;
                }
            } else {
                if self.muxer.send_stream_pkt(&pkt).is_err() {
                    queue_tx.undo_pop();
                    break;
                }
            }

            have_used = true;
            if let Err(e) = queue_tx.add_used(mem, head.index, 0) {
                error!("vsock: TX add_used failed: {e:?}");
            }
        }

        self.queues[TXQ_INDEX] = queue_tx.clone();

        have_used
    }
}

impl VirtioDevice for Vsock {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn device_type(&self) -> u32 {
        uapi::VIRTIO_ID_VSOCK
    }

    fn device_name(&self) -> &str {
        "vsock"
    }

    fn queues(&self) -> &[VirtQueue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [VirtQueue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_events
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        match offset {
            0 if data.len() == 8 => byte_order::write_le_u64(data, self.cid()),
            0 if data.len() == 4 => {
                byte_order::write_le_u32(data, (self.cid() & 0xffff_ffff) as u32)
            }
            4 if data.len() == 4 => {
                byte_order::write_le_u32(data, ((self.cid() >> 32) & 0xffff_ffff) as u32)
            }
            _ => warn!(
                "virtio-vsock received invalid read request of {} bytes at offset {}",
                data.len(),
                offset
            ),
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(&mut self, mem: GuestMemoryMmap, interrupt: InterruptTransport) -> ActivateResult {
        debug!(
            "vsock: activate called, already_activated={}",
            self.device_state.is_activated()
        );
        if self.queues.len() != defs::NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                defs::NUM_QUEUES,
                self.queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        if self.activate_evt.write(1).is_err() {
            error!("Cannot write to activate_evt",);
            return Err(ActivateError::BadActivate);
        }

        self.queue_tx = Arc::new(Mutex::new(self.queues[TXQ_INDEX].clone()));
        self.queue_rx = Arc::new(Mutex::new(self.queues[RXQ_INDEX].clone()));

        let rxq_kick = self.queue_events[RXQ_INDEX]
            .try_clone()
            .map_err(|_| ActivateError::BadActivate)?;
        let muxer_quiesce_fd = self
            .muxer_quiesce_fd
            .try_clone()
            .map_err(|_| ActivateError::BadActivate)?;
        let muxer_resume_fd = self
            .muxer_resume_fd
            .try_clone()
            .map_err(|_| ActivateError::BadActivate)?;
        let timesync_quiesce_fd = self
            .timesync_quiesce_fd
            .try_clone()
            .map_err(|_| ActivateError::BadActivate)?;
        let timesync_resume_fd = self
            .timesync_resume_fd
            .try_clone()
            .map_err(|_| ActivateError::BadActivate)?;
        self.muxer.activate(
            mem.clone(),
            self.queue_rx.clone(),
            interrupt.clone(),
            rxq_kick,
            muxer_quiesce_fd,
            muxer_resume_fd,
            self.muxer_quiesce_ack.clone(),
            timesync_quiesce_fd,
            timesync_resume_fd,
            self.timesync_quiesce_ack.clone(),
        );

        self.device_state = DeviceState::Activated(mem, interrupt);

        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn reset(&mut self) -> bool {
        self.device_state = DeviceState::Inactive;
        self.queue_rx = Arc::new(Mutex::new(self.queues[RXQ_INDEX].clone()));
        self.queue_tx = Arc::new(Mutex::new(self.queues[TXQ_INDEX].clone()));
        self.muxer = VsockMuxer::new(
            self.cid,
            self.host_port_map.clone(),
            self.unix_ipc_port_map.clone(),
            self.enable_tsi,
            self.enable_tsi_unix,
        );
        true
    }

    fn begin_snapshot_quiesce(
        &mut self,
        timeout: Duration,
    ) -> std::result::Result<(), SnapshotError> {
        warn!(
            "vsock: begin_snapshot_quiesce, activated={}",
            self.device_state.is_activated()
        );
        if !self.device_state.is_activated() {
            return Ok(());
        }

        // Quiesce the muxer thread.
        {
            let (lock, _) = &*self.muxer_quiesce_ack;
            *lock.lock().unwrap() = false;
        }
        let _ = self.muxer_quiesce_fd.write(1);

        let (lock, cvar) = &*self.muxer_quiesce_ack;
        let guard = lock.lock().unwrap();
        let (guard, wait_result) = cvar
            .wait_timeout_while(guard, timeout, |acked| !*acked)
            .unwrap();
        if !*guard || wait_result.timed_out() {
            return Err(SnapshotError::QuiesceTimeout {
                device_id: String::new(),
                timeout_ms: timeout.as_millis() as u64,
                detail: Some("vsock muxer thread did not ack quiesce".into()),
            });
        }
        drop(guard);

        // Quiesce the timesync thread.
        {
            let (lock, _) = &*self.timesync_quiesce_ack;
            *lock.lock().unwrap() = false;
        }
        let _ = self.timesync_quiesce_fd.write(1);

        let (lock, cvar) = &*self.timesync_quiesce_ack;
        let guard = lock.lock().unwrap();
        let (guard, wait_result) = cvar
            .wait_timeout_while(guard, timeout, |acked| !*acked)
            .unwrap();
        if !*guard || wait_result.timed_out() {
            // Resume the muxer thread since it already quiesced.
            let _ = self.muxer_resume_fd.write(1);
            return Err(SnapshotError::QuiesceTimeout {
                device_id: String::new(),
                timeout_ms: timeout.as_millis() as u64,
                detail: Some("vsock timesync thread did not ack quiesce".into()),
            });
        }

        Ok(())
    }

    fn abort_snapshot_quiesce(&mut self) {
        warn!(
            "vsock: abort_snapshot_quiesce (resume workers), activated={}",
            self.device_state.is_activated()
        );
        if !self.device_state.is_activated() {
            return;
        }
        // Reset ack flags and resume both threads.
        {
            let (lock, _) = &*self.muxer_quiesce_ack;
            *lock.lock().unwrap() = false;
        }
        {
            let (lock, _) = &*self.timesync_quiesce_ack;
            *lock.lock().unwrap() = false;
        }
        let _ = self.muxer_resume_fd.write(1);
        let _ = self.timesync_resume_fd.write(1);
    }

    fn sync_queues_for_snapshot(&mut self) {
        self.queues[RXQ_INDEX] = self.queue_rx.lock().unwrap().clone();
        self.queues[TXQ_INDEX] = self.queue_tx.lock().unwrap().clone();
        warn!(
            "vsock: sync_queues_for_snapshot: rx(next_avail={}, next_used={}) tx(next_avail={}, next_used={})",
            self.queues[RXQ_INDEX].next_avail(), self.queues[RXQ_INDEX].next_used(),
            self.queues[TXQ_INDEX].next_avail(), self.queues[TXQ_INDEX].next_used(),
        );
    }

    fn post_snapshot_restore(&mut self) {
        warn!(
            "vsock: post_snapshot_restore called, activated={}",
            self.device_state.is_activated()
        );

        let rx_q = &self.queues[RXQ_INDEX];
        let tx_q = &self.queues[TXQ_INDEX];
        warn!(
            "vsock: restore queues from snapshot: rx(ready={}, size={}, next_avail={}, next_used={}) tx(ready={}, size={}, next_avail={}, next_used={})",
            rx_q.ready, rx_q.size, rx_q.next_avail(), rx_q.next_used(),
            tx_q.ready, tx_q.size, tx_q.next_avail(), tx_q.next_used(),
        );

        {
            let shared_rx = self.queue_rx.lock().unwrap();
            let shared_tx = self.queue_tx.lock().unwrap();
            warn!(
                "vsock: shared queues before restore: rx(next_avail={}, next_used={}) tx(next_avail={}, next_used={})",
                shared_rx.next_avail(), shared_rx.next_used(),
                shared_tx.next_avail(), shared_tx.next_used(),
            );
        }

        *self.queue_rx.lock().unwrap() = self.queues[RXQ_INDEX].clone();
        *self.queue_tx.lock().unwrap() = self.queues[TXQ_INDEX].clone();
    }
}
