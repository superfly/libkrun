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
use std::thread;
use std::time::Duration;

use log::{debug, error, trace, warn};
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
}

impl AsyncNetWorker {
    /// Create a new async network worker.
    pub fn new(
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        factory: Box<dyn AsyncNetBackendFactory>,
        stop_fd: EventFd,
    ) -> Self {
        Self {
            queues,
            queue_evts,
            interrupt,
            mem,
            factory,
            stop_fd,
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
        } = self;

        // Create the backend
        let NetBackendHandle {
            mut backend,
            mut to_guest_rx,
            mut wake_rx,
        } = match factory.create().await {
            Ok(handle) => handle,
            Err(e) => {
                error!("failed to create net backend: {e}");
                return;
            }
        };

        debug!("async net worker: backend created");

        // Wrap eventfds for async
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

        // Scratch buffer for reading TX packets - reused to avoid allocations
        let mut tx_buf = vec![0u8; MAX_BUFFER_SIZE];

        debug!("async net worker: entering main loop");

        loop {
            let delay = backend.poll_delay().unwrap_or(Duration::from_secs(3600));

            tokio::select! {
                biased;

                // Guest sent packets (TX queue)
                ready = async_tx_evt.readable() => {
                    match ready {
                        Ok(mut guard) => {
                            guard.clear_ready();
                            if queue_evts[TX_INDEX].read().is_ok() {
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
                    trace!("async net worker: RX packet from backend, len={}", packet.len());
                    push_to_rx_queue(
                        &mut queues,
                        &mem,
                        &interrupt,
                        &packet,
                    );
                }

                // Timer for backend polling
                _ = tokio::time::sleep(delay) => {
                    trace!("async net worker: poll timer");
                    backend.poll();
                }

                // Wake notification from backend's background tasks
                Some(_) = async { wake_rx.as_mut()?.recv().await }, if wake_rx.is_some() => {
                    trace!("async net worker: wake notification");
                    backend.poll();
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
            }
        }
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

        if !queues[TX_INDEX].enable_notification(mem).unwrap_or(false) {
            break;
        }
    }

    // Signal guest that we consumed descriptors
    if queues[TX_INDEX].needs_notification(mem).unwrap_or(false) {
        if let Err(e) = interrupt.try_signal_used_queue() {
            error!("failed to signal TX used queue: {e:?}");
        }
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
            if mem.read_slice(&mut buf[offset..offset + len], d.addr).is_ok() {
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
                    mem.write_slice(
                        &packet[..pkt_write],
                        d.addr.unchecked_add(hdr_write as u64),
                    )
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

    // Signal guest
    if queues[RX_INDEX].needs_notification(mem).unwrap_or(false) {
        if let Err(e) = interrupt.try_signal_used_queue() {
            error!("failed to signal RX used queue: {e:?}");
        }
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
        assert_eq!(VIRTIO_NET_HDR_SIZE, std::mem::size_of::<virtio_net_hdr_v1>());
    }

    #[test]
    fn test_dup_fd() {
        let evt = EventFd::new(0).unwrap();
        let duped = dup_fd(&evt);
        // The duped fd should be different from the original
        assert_ne!(duped.as_raw_fd(), evt.as_raw_fd());
    }
}
