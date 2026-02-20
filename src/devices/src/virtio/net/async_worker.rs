// Copyright 2024 Anthropic. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Async network worker for virtio-net devices.
//!
//! This worker provides a tokio-based event loop for processing virtio-net
//! queues, delegating actual network handling to a pluggable backend.
//!
//! # Design
//!
//! - Runs on a single-threaded tokio runtime with `LocalSet` for `!Send` futures
//! - TX path: Reads packets from virtio TX queue, passes borrowed slices to backend
//! - RX path: Receives packets from backend via channel, writes to virtio RX queue
//! - Backend handles all networking logic (TCP/IP stack, host sockets, NAT, etc.)

use std::cmp;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use log::{debug, error, trace};
use tokio::io::unix::AsyncFd;
use tokio::task::LocalSet;
use utils::eventfd::EventFd;
use virtio_bindings::virtio_net::virtio_net_hdr_v1;
use vm_memory::{Address, Bytes as VmBytes, GuestMemoryMmap};

use super::async_backend::{AsyncNetBackendFactory, NetBackendHandle};
use crate::virtio::queue::DescriptorChain;
use crate::virtio::{InterruptTransport, Queue};

const VIRTIO_NET_HDR_SIZE: usize = std::mem::size_of::<virtio_net_hdr_v1>();
const MAX_BUFFER_SIZE: usize = 65535;

/// The index of the RX queue (guest receives on this).
const RX_INDEX: usize = 0;
/// The index of the TX queue (guest sends on this).
const TX_INDEX: usize = 1;

/// Async network worker that processes virtio-net queues using tokio.
pub struct AsyncNetWorker {
    queues: Vec<Queue>,
    queue_evts: Vec<EventFd>,
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    factory: Box<dyn AsyncNetBackendFactory>,
    stop_fd: EventFd,
    resync_fd: EventFd,
    shared_queues: Arc<Mutex<Vec<Queue>>>,
    shared_generation: Arc<AtomicU64>,
    quiesce_fd: EventFd,
    resume_fd: EventFd,
    quiesce_ack: Arc<(Mutex<bool>, Condvar)>,
    shared_backend_state: Arc<Mutex<Option<Vec<u8>>>>,
}

impl AsyncNetWorker {
    /// Create a new async network worker.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        factory: Box<dyn AsyncNetBackendFactory>,
        stop_fd: EventFd,
        resync_fd: EventFd,
        shared_queues: Arc<Mutex<Vec<Queue>>>,
        shared_generation: Arc<AtomicU64>,
        quiesce_fd: EventFd,
        resume_fd: EventFd,
        quiesce_ack: Arc<(Mutex<bool>, Condvar)>,
        shared_backend_state: Arc<Mutex<Option<Vec<u8>>>>,
    ) -> Self {
        Self {
            queues,
            queue_evts,
            interrupt,
            mem,
            factory,
            stop_fd,
            resync_fd,
            shared_queues,
            shared_generation,
            quiesce_fd,
            resume_fd,
            quiesce_ack,
            shared_backend_state,
        }
    }

    /// Start the async worker in a new thread.
    pub fn run(self) -> thread::JoinHandle<()> {
        thread::Builder::new()
            .name("async-net-worker".into())
            .spawn(move || {
                debug!("async net worker: thread started, creating runtime");

                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("failed to create tokio runtime");

                let local = LocalSet::new();
                rt.block_on(local.run_until(self.work_async()));

                debug!("async net worker: work_async completed");
            })
            .expect("failed to spawn async net worker")
    }

    /// Main async work loop.
    async fn work_async(self) {
        debug!("async net worker: starting");

        // Destructure self so we can consume factory separately
        let AsyncNetWorker {
            mut queues,
            queue_evts,
            interrupt,
            mem,
            factory,
            stop_fd,
            resync_fd,
            shared_queues,
            shared_generation,
            quiesce_fd,
            resume_fd,
            quiesce_ack,
            shared_backend_state,
        } = self;

        // Wrap TX eventfd for async early — we need to drain TX during backend creation
        // to prevent NETDEV WATCHDOG timeouts if the factory takes a while.
        let async_tx_evt = match AsyncFd::new(dup_fd(&queue_evts[TX_INDEX])) {
            Ok(fd) => fd,
            Err(e) => {
                error!("failed to create AsyncFd for TX queue: {e}");
                return;
            }
        };

        let async_stop = match AsyncFd::new(dup_fd(&stop_fd)) {
            Ok(fd) => fd,
            Err(e) => {
                error!("failed to create AsyncFd for stop: {e}");
                return;
            }
        };

        let async_resync = match AsyncFd::new(dup_fd(&resync_fd)) {
            Ok(fd) => fd,
            Err(e) => {
                error!("failed to create AsyncFd for resync: {e}");
                return;
            }
        };

        let async_quiesce = match AsyncFd::new(dup_fd(&quiesce_fd)) {
            Ok(fd) => fd,
            Err(e) => {
                error!("failed to create AsyncFd for quiesce: {e}");
                return;
            }
        };

        let async_resume = match AsyncFd::new(dup_fd(&resume_fd)) {
            Ok(fd) => fd,
            Err(e) => {
                error!("failed to create AsyncFd for resume: {e}");
                return;
            }
        };

        // Create the backend. While the factory initializes (host socket setup, etc.),
        // drain TX descriptors to prevent NETDEV WATCHDOG timeouts from the guest kernel.
        let mut backend_fut = factory.create();
        let NetBackendHandle {
            mut backend,
            mut to_guest_rx,
            mut wake_rx,
        } = loop {
            tokio::select! {
                biased;
                result = &mut backend_fut => {
                    match result {
                        Ok(handle) => break handle,
                        Err(e) => {
                            error!("failed to create net backend: {e}");
                            return;
                        }
                    }
                }
                ready = async_tx_evt.readable() => {
                    if let Ok(mut guard) = ready {
                        guard.clear_ready();
                        if queue_evts[TX_INDEX].read().is_ok() {
                            discard_tx_queue(&mut queues, &mem, &interrupt);
                        }
                    }
                }
                ready = async_stop.readable() => {
                    if ready.is_ok() {
                        debug!("async net worker: stopping during backend creation");
                        let _ = stop_fd.read();
                        return;
                    }
                }
            }
        };

        debug!("async net worker: backend created");

        // Scratch buffer for reading TX packets - reused to avoid allocations
        let mut tx_buf = vec![0u8; MAX_BUFFER_SIZE];

        debug!("async net worker: entering main loop");
        let mut applied_generation: u64 = 0;

        loop {
            // Cap poll delay to 1 second to ensure timely interrupt re-signaling.
            // Without this cap, idle backends (poll_delay = None → 3600s) would leave
            // the guest waiting too long if an interrupt was lost.
            let delay = backend
                .poll_delay()
                .unwrap_or(Duration::from_secs(1))
                .min(Duration::from_secs(1));

            tokio::select! {
                biased;

                // Snapshot quiesce: publish queue state, ACK, then park until resume
                ready = async_quiesce.readable() => {
                    if let Ok(mut guard) = ready {
                        guard.clear_ready();
                        if quiesce_fd.read().is_ok() {
                            debug!("async net worker: quiesce requested, publishing queue + backend state");
                            // Publish local queues to shared state
                            if let Ok(mut shared) = shared_queues.lock() {
                                for (dst, src) in shared.iter_mut().zip(queues.iter()) {
                                    *dst = src.clone();
                                }
                            }
                            // Publish backend snapshot state
                            if let Ok(mut shared) = shared_backend_state.lock() {
                                *shared = backend.save_snapshot_state();
                            }
                            // Signal the device that we've parked
                            {
                                let (lock, cvar) = &*quiesce_ack;
                                *lock.lock().unwrap() = true;
                                cvar.notify_one();
                            }
                            // Park: wait for resume_fd
                            debug!("async net worker: parked, waiting for resume");
                            loop {
                                match async_resume.readable().await {
                                    Ok(mut rg) => {
                                        rg.clear_ready();
                                        if resume_fd.read().is_ok() {
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        error!("async net worker: resume fd error: {e}");
                                        break;
                                    }
                                }
                            }
                            debug!("async net worker: resumed from quiesce");
                        }
                    }
                }

                // Guest sent packets (TX queue)
                ready = async_tx_evt.readable() => {
                    match ready {
                        Ok(mut guard) => {
                            guard.clear_ready();
                            if queue_evts[TX_INDEX].read().is_ok() {
                                apply_shared_queue_state_if_needed(
                                    &mut queues,
                                    &mem,
                                    &shared_queues,
                                    &shared_generation,
                                    &mut applied_generation,
                                );
                                trace!("async net worker: TX queue event");
                                drain_tx_queue(
                                    &mut queues,
                                    &mem,
                                    &interrupt,
                                    &mut *backend,
                                    &mut tx_buf,
                                );
                                backend.poll();
                            }
                        }
                        Err(e) => {
                            error!("TX queue fd error: {e}");
                        }
                    }
                }

                // Backend has packet for guest
                Some(packet) = to_guest_rx.recv() => {
                    apply_shared_queue_state_if_needed(
                        &mut queues,
                        &mem,
                        &shared_queues,
                        &shared_generation,
                        &mut applied_generation,
                    );
                    trace!("async net worker: RX packet from backend, len={}", packet.len());
                    push_to_rx_queue(
                        &mut queues,
                        &mem,
                        &interrupt,
                        &packet,
                    );
                    // Drain TX while processing RX to prevent TX starvation during RX floods
                    if queues[TX_INDEX].ready && !queues[TX_INDEX].is_empty(&mem) {
                        drain_tx_queue(
                            &mut queues,
                            &mem,
                            &interrupt,
                            &mut *backend,
                            &mut tx_buf,
                        );
                        backend.poll();
                    }
                }

                // Timer for backend polling + interrupt heartbeat
                _ = tokio::time::sleep(delay) => {
                    trace!("async net worker: poll timer");
                    backend.poll();
                    // Heartbeat: re-signal the used queue in case a previous interrupt
                    // was lost to an ISR race condition. This is cheap (one GIC interrupt
                    // per poll cycle) and ensures the guest eventually processes TX
                    // completions even if an interrupt was eaten.
                    if queues[TX_INDEX].ready {
                        let _ = interrupt.try_signal_used_queue();
                    }
                    if queues[TX_INDEX].ready && !queues[TX_INDEX].is_empty(&mem) {
                        trace!("async net worker: timer detected pending TX without event");
                        drain_tx_queue(
                            &mut queues,
                            &mem,
                            &interrupt,
                            &mut *backend,
                            &mut tx_buf,
                        );
                        backend.poll();
                    }
                }

                // Wake notification from backend's background tasks
                Some(_) = async { wake_rx.as_mut()?.recv().await }, if wake_rx.is_some() => {
                    trace!("async net worker: wake notification");
                    backend.poll();
                    if queues[TX_INDEX].ready && !queues[TX_INDEX].is_empty(&mem) {
                        trace!("async net worker: wake detected pending TX without event");
                        drain_tx_queue(
                            &mut queues,
                            &mem,
                            &interrupt,
                            &mut *backend,
                            &mut tx_buf,
                        );
                        backend.poll();
                    }
                }

                // Shutdown
                ready = async_stop.readable() => {
                    if ready.is_ok() {
                        debug!("async net worker: stopping");
                        let _ = stop_fd.read();
                        backend.on_exit();
                        return;
                    }
                }

                // Queue resync after snapshot restore
                ready = async_resync.readable() => {
                    if let Ok(mut guard) = ready {
                        guard.clear_ready();
                        if resync_fd.read().is_ok() {
                            apply_shared_queue_state_if_needed(
                                &mut queues,
                                &mem,
                                &shared_queues,
                                &shared_generation,
                                &mut applied_generation,
                            );
                            // Restore backend state if the device provided one
                            if let Ok(mut shared) = shared_backend_state.lock() {
                                if let Some(data) = shared.take() {
                                    debug!("async net worker: restoring backend state ({} bytes)", data.len());
                                    backend.restore_snapshot_state(&data);
                                }
                            }
                            if queues[TX_INDEX].ready && !queues[TX_INDEX].is_empty(&mem) {
                                trace!("async net worker: resync detected pending TX without event");
                                drain_tx_queue(
                                    &mut queues,
                                    &mem,
                                    &interrupt,
                                    &mut *backend,
                                    &mut tx_buf,
                                );
                                backend.poll();
                            }
                            trace!("async net worker: queues resynced from snapshot state");
                        }
                    }
                }
            }
        }
    }
}

fn apply_shared_queue_state_if_needed(
    queues: &mut [Queue],
    mem: &GuestMemoryMmap,
    shared_queues: &Arc<Mutex<Vec<Queue>>>,
    shared_generation: &Arc<AtomicU64>,
    applied_generation: &mut u64,
) {
    let generation = shared_generation.load(Ordering::Acquire);
    if generation == *applied_generation {
        return;
    }

    if let Ok(shared) = shared_queues.lock() {
        for (dst, src) in queues.iter_mut().zip(shared.iter()) {
            *dst = src.clone();

            if dst.ready {
                if let Some(used_idx_addr) = dst.used_ring.checked_add(2) {
                    if let Ok(used_idx) = mem.read_obj::<u16>(used_idx_addr) {
                        dst.set_next_used(used_idx);
                    }
                }

                if let Some(avail_idx_addr) = dst.avail_ring.checked_add(2) {
                    if let Ok(avail_idx) = mem.read_obj::<u16>(avail_idx_addr) {
                        if dst.next_avail().0 > avail_idx {
                            dst.set_next_avail(avail_idx);
                        }
                    }
                }
            }
        }
        *applied_generation = generation;
    }
}

/// Consume TX descriptors without forwarding to the backend.
/// Used during backend creation to prevent NETDEV WATCHDOG timeouts.
fn discard_tx_queue(queues: &mut [Queue], mem: &GuestMemoryMmap, interrupt: &InterruptTransport) {
    while let Some(head) = queues[TX_INDEX].pop(mem) {
        queues[TX_INDEX].add_used(mem, head.index, 0).ok();
    }
    if let Err(e) = interrupt.try_signal_used_queue() {
        error!("failed to signal TX used queue: {e:?}");
    }
}

/// Drain all packets from the TX queue and pass to backend.
fn drain_tx_queue(
    queues: &mut [Queue],
    mem: &GuestMemoryMmap,
    interrupt: &InterruptTransport,
    backend: &mut dyn super::async_backend::AsyncNetBackend,
    buf: &mut [u8],
) {
    queues[TX_INDEX].disable_notification(mem).ok();

    loop {
        let next_avail_before = queues[TX_INDEX].next_avail();

        while let Some(head) = queues[TX_INDEX].pop(mem) {
            let head_index = head.index;

            // Read packet into scratch buffer
            if let Some(len) = read_tx_packet(mem, &head, buf) {
                trace!(
                    "async net worker: TX packet, index={}, len={}",
                    head_index,
                    len
                );
                // Pass borrowed slice to backend - zero copy at interface
                backend.handle_guest_tx(&buf[..len]);
            }

            // Mark descriptor as used
            queues[TX_INDEX].add_used(mem, head_index, 0).ok();
        }

        if queues[TX_INDEX].next_avail() == next_avail_before {
            // Queue made no progress; distinguish two cases:
            // 1) Guest advanced avail_idx concurrently -> retry without mutating next_avail.
            // 2) next_avail drifted ahead of avail_idx (e.g. after restore) -> rewind.
            if let Some(avail_idx_addr) = queues[TX_INDEX].avail_ring.checked_add(2) {
                if let Ok(avail_idx) = mem.read_obj::<u16>(avail_idx_addr) {
                    let next_avail = queues[TX_INDEX].next_avail().0;
                    if avail_idx != next_avail {
                        let queue_size = queues[TX_INDEX].actual_size();
                        if queue_size != 0 {
                            let pending = avail_idx.wrapping_sub(next_avail);
                            if pending <= queue_size {
                                continue; // New/pending descriptors are available; retry pop()
                            }
                        }

                        error!(
                            "async net worker: TX queue next_avail appears ahead; rewinding {} -> {}",
                            next_avail,
                            avail_idx
                        );
                        queues[TX_INDEX].set_next_avail(avail_idx);
                        continue;
                    }
                }
            }
            break;
        }

        if !queues[TX_INDEX].enable_notification(mem).unwrap_or(false) {
            break;
        }
    }
    // Signal guest that we consumed descriptors.
    // Snapshot restore can desynchronize notification heuristics; signal unconditionally.
    if let Err(e) = interrupt.try_signal_used_queue() {
        error!("failed to signal TX used queue: {e:?}");
    }
}

/// Read a TX packet into buffer, stripping the virtio-net header.
/// Returns the payload length (without header), or None if invalid.
fn read_tx_packet(mem: &GuestMemoryMmap, head: &DescriptorChain, buf: &mut [u8]) -> Option<usize> {
    let mut offset = 0;
    let mut desc = Some(head.clone());

    while let Some(d) = desc {
        if !d.is_write_only() {
            let len = cmp::min(d.len as usize, buf.len() - offset);
            if mem
                .read_slice(&mut buf[offset..offset + len], d.addr)
                .is_ok()
            {
                offset += len;
            }
        }
        desc = d.next_descriptor();
    }

    // Strip virtio-net header
    if offset > VIRTIO_NET_HDR_SIZE {
        // Shift payload to start of buffer to avoid tracking offset
        buf.copy_within(VIRTIO_NET_HDR_SIZE..offset, 0);
        Some(offset - VIRTIO_NET_HDR_SIZE)
    } else {
        None
    }
}

/// Push a packet to the guest via the RX queue.
fn push_to_rx_queue(
    queues: &mut [Queue],
    mem: &GuestMemoryMmap,
    interrupt: &InterruptTransport,
    packet: &[u8],
) {
    let Some(head) = queues[RX_INDEX].pop(mem) else {
        // This is expected under high load - guest can't replenish RX buffers fast enough
        trace!("async net worker: no RX buffers available, dropping packet");
        return;
    };

    let head_index = head.index;
    let mut written = 0;
    let mut desc = Some(head);

    // Virtio-net header (all zeros is valid)
    let header = [0u8; VIRTIO_NET_HDR_SIZE];

    while let Some(d) = desc {
        if d.is_write_only() {
            let available = d.len as usize;

            // First write header, then packet data
            if written < VIRTIO_NET_HDR_SIZE {
                let hdr_remaining = VIRTIO_NET_HDR_SIZE - written;
                let hdr_write = cmp::min(hdr_remaining, available);

                mem.write_slice(&header[written..written + hdr_write], d.addr)
                    .ok();

                if hdr_write < available {
                    // Room for packet data in this descriptor
                    let pkt_write = cmp::min(packet.len(), available - hdr_write);
                    mem.write_slice(&packet[..pkt_write], d.addr.unchecked_add(hdr_write as u64))
                        .ok();
                    written = VIRTIO_NET_HDR_SIZE + pkt_write;
                } else {
                    written += hdr_write;
                }
            } else {
                let pkt_offset = written - VIRTIO_NET_HDR_SIZE;
                let pkt_remaining = packet.len().saturating_sub(pkt_offset);
                let pkt_write = cmp::min(pkt_remaining, available);

                if pkt_write > 0 {
                    mem.write_slice(&packet[pkt_offset..pkt_offset + pkt_write], d.addr)
                        .ok();
                }
                written += pkt_write;
            }
        }
        desc = d.next_descriptor();
    }

    // Mark descriptor as used with the number of bytes written
    queues[RX_INDEX]
        .add_used(mem, head_index, written as u32)
        .ok();

    // Signal guest.
    // Snapshot restore can desynchronize notification heuristics; signal unconditionally.
    if let Err(e) = interrupt.try_signal_used_queue() {
        error!("failed to signal RX used queue: {e:?}");
    }
}

/// Duplicate a file descriptor for use with AsyncFd.
fn dup_fd(evt: &EventFd) -> OwnedFd {
    // SAFETY: We're duplicating a valid fd that we own
    unsafe { OwnedFd::from_raw_fd(libc::dup(evt.as_raw_fd())) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtio_net_hdr_size() {
        // Verify our constant matches the actual struct size
        assert_eq!(
            VIRTIO_NET_HDR_SIZE,
            std::mem::size_of::<virtio_net_hdr_v1>()
        );
    }

    #[test]
    fn test_dup_fd() {
        let evt = EventFd::new(0).unwrap();
        let duped = dup_fd(&evt);
        // The duped fd should be different from the original
        assert_ne!(duped.as_raw_fd(), evt.as_raw_fd());
    }

    use super::super::async_backend::{
        AsyncNetBackend, AsyncNetBackendFactory, NetBackendHandle, SendBoxFuture,
    };
    use crate::legacy::DummyIrqChip;
    use crate::virtio::InterruptTransport;
    use std::sync::Condvar;
    use vm_memory::GuestAddress;

    /// Dummy net backend that does nothing (for quiesce testing).
    struct DummyNetBackend;

    impl AsyncNetBackend for DummyNetBackend {
        fn handle_guest_tx(&mut self, _packet: &[u8]) {}
        fn poll(&mut self) {}
        fn on_exit(&mut self) {}
    }

    /// Factory that creates a DummyNetBackend.
    struct DummyNetBackendFactory;

    impl AsyncNetBackendFactory for DummyNetBackendFactory {
        fn create(self: Box<Self>) -> SendBoxFuture<'static, std::io::Result<NetBackendHandle>> {
            Box::pin(async move {
                let (to_guest_tx, to_guest_rx) = tokio::sync::mpsc::channel(16);
                // Keep tx alive so the channel doesn't close
                std::mem::forget(to_guest_tx);
                Ok(NetBackendHandle {
                    backend: Box::new(DummyNetBackend),
                    to_guest_rx,
                    wake_rx: None,
                })
            })
        }
    }

    /// Test that the quiesce protocol works: signal quiesce → worker acks → resume.
    #[test]
    fn test_quiesce_ack_resume() {
        let mem = vm_memory::GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let irqchip: crate::legacy::IrqChip = DummyIrqChip::new().into();
        let interrupt = InterruptTransport::new(irqchip, "test-net".into()).unwrap();

        let queues = vec![Queue::new(256), Queue::new(256)];
        let queue_evts = vec![
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
        ];
        let stop_fd = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let resync_fd = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let quiesce_fd = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let resume_fd = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();

        let shared_queues = Arc::new(Mutex::new(queues.clone()));
        let shared_generation = Arc::new(AtomicU64::new(0));
        let quiesce_ack = Arc::new((Mutex::new(false), Condvar::new()));

        let quiesce_fd_clone = quiesce_fd.try_clone().unwrap();
        let resume_fd_clone = resume_fd.try_clone().unwrap();
        let stop_fd_clone = stop_fd.try_clone().unwrap();
        let quiesce_ack_clone = quiesce_ack.clone();

        let factory: Box<dyn AsyncNetBackendFactory> = Box::new(DummyNetBackendFactory);

        let shared_backend_state = Arc::new(Mutex::new(None));

        let worker = AsyncNetWorker::new(
            queues,
            queue_evts,
            interrupt,
            mem,
            factory,
            stop_fd,
            resync_fd,
            shared_queues.clone(),
            shared_generation.clone(),
            quiesce_fd,
            resume_fd,
            quiesce_ack.clone(),
            shared_backend_state,
        );

        let _handle = worker.run();

        // Give the worker time to start and create backend
        std::thread::sleep(std::time::Duration::from_millis(100));

        // --- Quiesce cycle 1: verify ack ---
        {
            let (lock, _) = &*quiesce_ack_clone;
            *lock.lock().unwrap() = false;
        }
        quiesce_fd_clone.write(1).unwrap();

        // Wait for ack with timeout
        {
            let (lock, cvar) = &*quiesce_ack_clone;
            let guard = lock.lock().unwrap();
            let (guard, timeout_result) = cvar
                .wait_timeout_while(guard, std::time::Duration::from_secs(5), |acked| !*acked)
                .unwrap();
            assert!(
                *guard && !timeout_result.timed_out(),
                "Net worker did not ack quiesce within timeout"
            );
        }

        // Verify shared queues were updated
        {
            let shared = shared_queues.lock().unwrap();
            assert_eq!(shared.len(), 2);
        }

        // Resume
        {
            let (lock, _) = &*quiesce_ack_clone;
            *lock.lock().unwrap() = false;
        }
        resume_fd_clone.write(1).unwrap();

        // Give worker time to resume
        std::thread::sleep(std::time::Duration::from_millis(50));

        // --- Quiesce cycle 2: verify it works a second time ---
        {
            let (lock, _) = &*quiesce_ack_clone;
            *lock.lock().unwrap() = false;
        }
        quiesce_fd_clone.write(1).unwrap();

        {
            let (lock, cvar) = &*quiesce_ack_clone;
            let guard = lock.lock().unwrap();
            let (guard, timeout_result) = cvar
                .wait_timeout_while(guard, std::time::Duration::from_secs(5), |acked| !*acked)
                .unwrap();
            assert!(
                *guard && !timeout_result.timed_out(),
                "Net worker did not ack second quiesce within timeout"
            );
        }

        // Resume and stop
        resume_fd_clone.write(1).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        stop_fd_clone.write(1).unwrap();
    }
}
