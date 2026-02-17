use std::collections::{HashMap, VecDeque};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use log::{debug, error, trace, warn};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, LocalSet};
use utils::eventfd::EventFd;
use virtio_bindings::virtio_blk::*;
use vm_memory::{Address, ByteValued, Bytes, GuestMemoryMmap};

use super::super::Queue;
use super::{AsyncBlockBackend, AsyncBlockBackendFactory, CacheType, VolatileSliceGuard};
use crate::virtio::descriptor_utils::{Reader, Writer};
use crate::virtio::InterruptTransport;

/// Metrics for the async block worker.
#[derive(Default)]
pub struct AsyncWorkerMetrics {
    /// Number of requests currently in flight
    pub in_flight: AtomicU64,
    /// Total read requests processed
    pub reads: AtomicU64,
    /// Total write requests processed
    pub writes: AtomicU64,
    /// Total flush requests processed
    pub flushes: AtomicU64,
    /// Total bytes read
    pub bytes_read: AtomicU64,
    /// Total bytes written
    pub bytes_written: AtomicU64,
    /// Cumulative read latency in microseconds
    pub read_latency_us: AtomicU64,
    /// Cumulative write latency in microseconds
    pub write_latency_us: AtomicU64,
    /// Number of read tasks currently running
    pub concurrent_reads: AtomicU64,
    /// Peak concurrent reads
    pub peak_concurrent_reads: AtomicU64,
}

/// Request error types for async block operations.
#[allow(dead_code)]
#[derive(Debug)]
pub enum RequestError {
    Discarding(io::Error),
    FlushingToDisk(io::Error),
    InvalidDataLength,
    ReadingFromDescriptor(io::Error),
    WritingToDescriptor(io::Error),
    WritingZeroes(io::Error),
    UnknownRequest,
}

/// The request header represents the mandatory fields of each block device request.
#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct RequestHeader {
    request_type: u32,
    _reserved: u32,
    sector: u64,
}
// Safe because RequestHeader only contains plain data.
unsafe impl ByteValued for RequestHeader {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct DiscardWriteData {
    sector: u64,
    num_sectors: u32,
    flags: u32,
}
// Safe because DiscardWriteData only contains plain data.
unsafe impl ByteValued for DiscardWriteData {}

/// The type of block request to process.
enum Request {
    Read {
        bufs: Vec<VolatileSliceGuard>,
        offset: u64,
    },
    Write {
        bufs: Vec<VolatileSliceGuard>,
        offset: u64,
    },
    Flush,
    GetId {
        buf: VolatileSliceGuard,
    },
    Discard {
        offset: u64,
        len: u64,
    },
    WriteZeroes {
        offset: u64,
        len: u64,
        unmap: bool,
    },
}

/// Result of processing a request.
struct RequestResult {
    index: u16,
    #[allow(dead_code)]
    status: u8,
    len: u32,
}

/// A parsed request waiting to be processed.
struct ParsedRequest {
    request: Request,
    index: u16,
    status_ptr: *mut u8,
}

// SAFETY: ParsedRequest contains a raw pointer to guest memory which remains valid
// for the lifetime of the request processing. The pointer is only dereferenced
// within the async worker thread.
unsafe impl Send for ParsedRequest {}

/// A queued write request with metadata for batching.
struct QueuedWrite {
    parsed: ParsedRequest,
    offset: u64,
    len: usize,
    /// Sequence number for ordering (higher = newer)
    seq: u64,
}

/// Result of a batch write operation.
struct BatchWriteResult {
    /// Results for each write in the batch (index, status, len)
    results: Vec<(u16, u8, u32, *mut u8)>,
    /// Total bytes written
    total_bytes: u64,
    /// Total time in microseconds
    elapsed_us: u64,
}

/// Async block worker that processes requests concurrently.
pub struct AsyncBlockWorker {
    queue: Queue,
    queue_evt: EventFd,
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    factory: Box<dyn AsyncBlockBackendFactory>,
    stop_fd: EventFd,
    resync_fd: EventFd,
    shared_queue: Arc<Mutex<Queue>>,
    shared_generation: Arc<AtomicU64>,
    quiesce_fd: EventFd,
    resume_fd: EventFd,
    quiesce_ack: Arc<(Mutex<bool>, Condvar)>,
    shared_backend_state: Arc<Mutex<Option<Vec<u8>>>>,
}

impl AsyncBlockWorker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        queue: Queue,
        queue_evt: EventFd,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        factory: Box<dyn AsyncBlockBackendFactory>,
        stop_fd: EventFd,
        resync_fd: EventFd,
        shared_queue: Arc<Mutex<Queue>>,
        shared_generation: Arc<AtomicU64>,
        quiesce_fd: EventFd,
        resume_fd: EventFd,
        quiesce_ack: Arc<(Mutex<bool>, Condvar)>,
        shared_backend_state: Arc<Mutex<Option<Vec<u8>>>>,
    ) -> Self {
        Self {
            queue,
            queue_evt,
            interrupt,
            mem,
            factory,
            stop_fd,
            resync_fd,
            shared_queue,
            shared_generation,
            quiesce_fd,
            resume_fd,
            quiesce_ack,
            shared_backend_state,
        }
    }

    /// Start the async worker in a new thread with a tokio runtime.
    pub fn run(self) -> thread::JoinHandle<()> {
        log::debug!("async block worker: starting thread");

        thread::Builder::new()
            .name("async block worker".into())
            .spawn(move || {
                log::debug!("async block worker: thread started, creating runtime");

                // Use multi-threaded runtime because some backends (like SlateDB)
                // may internally use tokio::spawn which requires multiple threads
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .expect("failed to create tokio runtime");

                log::debug!("async block worker: runtime created, starting LocalSet");
                // Use LocalSet for !Send futures from our code
                let local = LocalSet::new();
                rt.block_on(local.run_until(self.work_async()));

                log::debug!("async block worker: work_async completed");
            })
            .expect("failed to spawn async block worker thread")
    }

    /// Main async work loop.
    async fn work_async(self) {
        debug!("async block worker: work_async starting");

        // Destructure self so we can consume the factory while keeping other fields
        let AsyncBlockWorker {
            mut queue,
            queue_evt,
            interrupt,
            mem,
            factory,
            stop_fd,
            resync_fd,
            shared_queue,
            shared_generation,
            quiesce_fd,
            resume_fd,
            quiesce_ack,
            shared_backend_state,
        } = self;

        // Create the backend from the factory (inside this runtime)
        debug!("async block worker: creating backend from factory");
        let disk = match factory.create().await {
            Ok(disk) => disk,
            Err(e) => {
                error!("async block worker: failed to create backend: {e}");
                return;
            }
        };
        debug!(
            "async block worker: backend created, nsectors={}",
            disk.nsectors()
        );

        // Create metrics
        let metrics = Arc::new(AsyncWorkerMetrics::default());

        // Spawn periodic metrics logging task
        let metrics_clone = metrics.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            let mut last_reads = 0u64;
            let mut last_writes = 0u64;
            let mut last_bytes_read = 0u64;
            let mut last_bytes_written = 0u64;
            let mut last_read_latency = 0u64;
            let mut last_write_latency = 0u64;
            loop {
                interval.tick().await;
                let in_flight = metrics_clone.in_flight.load(Ordering::Relaxed);
                let reads = metrics_clone.reads.load(Ordering::Relaxed);
                let writes = metrics_clone.writes.load(Ordering::Relaxed);
                let flushes = metrics_clone.flushes.load(Ordering::Relaxed);
                let bytes_read = metrics_clone.bytes_read.load(Ordering::Relaxed);
                let bytes_written = metrics_clone.bytes_written.load(Ordering::Relaxed);
                let read_latency = metrics_clone.read_latency_us.load(Ordering::Relaxed);
                let write_latency = metrics_clone.write_latency_us.load(Ordering::Relaxed);

                let concurrent_reads = metrics_clone.concurrent_reads.load(Ordering::Relaxed);
                let peak_reads = metrics_clone
                    .peak_concurrent_reads
                    .swap(0, Ordering::Relaxed);

                let delta_reads = reads - last_reads;
                let delta_writes = writes - last_writes;
                let delta_bytes_read = bytes_read - last_bytes_read;
                let delta_bytes_written = bytes_written - last_bytes_written;
                let delta_read_latency = read_latency - last_read_latency;
                let delta_write_latency = write_latency - last_write_latency;

                let avg_read_latency_us = if delta_reads > 0 {
                    delta_read_latency / delta_reads
                } else {
                    0
                };
                let avg_write_latency_us = if delta_writes > 0 {
                    delta_write_latency / delta_writes
                } else {
                    0
                };

                trace!(
                    "async-blk metrics: in_flight={} concurrent_reads={} peak_reads={} reads={}/s writes={}/s flushes={} read={:.1}MB/s write={:.1}MB/s avg_read_lat={:.1}ms avg_write_lat={:.1}ms",
                    in_flight,
                    concurrent_reads,
                    peak_reads,
                    delta_reads / 5,
                    delta_writes / 5,
                    flushes,
                    delta_bytes_read as f64 / 5.0 / 1024.0 / 1024.0,
                    delta_bytes_written as f64 / 5.0 / 1024.0 / 1024.0,
                    avg_read_latency_us as f64 / 1000.0,
                    avg_write_latency_us as f64 / 1000.0,
                );

                last_reads = reads;
                last_writes = writes;
                last_bytes_read = bytes_read;
                last_bytes_written = bytes_written;
                last_read_latency = read_latency;
                last_write_latency = write_latency;
            }
        });

        // Channel for completed read requests (reads don't need ordering)
        let (read_completion_tx, mut read_completion_rx) = mpsc::channel::<RequestResult>(256);

        // Write queue with batching
        // Writes are queued and processed one batch at a time.
        // When a batch completes, all queued writes are coalesced into the next batch.
        let mut write_queue: VecDeque<QueuedWrite> = VecDeque::new();
        let mut write_seq: u64 = 0; // Sequence counter for ordering
        let mut current_write_batch: Option<JoinHandle<BatchWriteResult>> = None;

        // Pending flushes wait for current batch to complete
        let mut pending_flushes: VecDeque<ParsedRequest> = VecDeque::new();

        // Current flush task (runs in parallel with writes)
        let mut current_flush: Option<JoinHandle<u8>> = None; // Returns status
        let mut flush_requests_in_progress: Vec<ParsedRequest> = Vec::new();

        // Track if any writes occurred since the last flush started.
        // If no writes happened, we can skip redundant flushes.
        let mut writes_since_flush_started: bool = false;

        // Wrap eventfds in AsyncFd for async-compatible waiting
        // SAFETY: We own these fds and they remain valid for the lifetime of this function.
        // We duplicate the fds because AsyncFd takes ownership but we still need the original EventFd.
        let queue_fd_dup = unsafe { OwnedFd::from_raw_fd(libc::dup(queue_evt.as_raw_fd())) };
        let stop_fd_dup = unsafe { OwnedFd::from_raw_fd(libc::dup(stop_fd.as_raw_fd())) };
        let resync_fd_dup = unsafe { OwnedFd::from_raw_fd(libc::dup(resync_fd.as_raw_fd())) };

        let async_queue_fd =
            AsyncFd::new(queue_fd_dup).expect("failed to create AsyncFd for queue");
        let async_stop_fd = AsyncFd::new(stop_fd_dup).expect("failed to create AsyncFd for stop");
        let async_resync_fd =
            AsyncFd::new(resync_fd_dup).expect("failed to create AsyncFd for resync");

        let quiesce_fd_dup = unsafe { OwnedFd::from_raw_fd(libc::dup(quiesce_fd.as_raw_fd())) };
        let resume_fd_dup = unsafe { OwnedFd::from_raw_fd(libc::dup(resume_fd.as_raw_fd())) };
        let async_quiesce_fd =
            AsyncFd::new(quiesce_fd_dup).expect("failed to create AsyncFd for quiesce");
        let async_resume_fd =
            AsyncFd::new(resume_fd_dup).expect("failed to create AsyncFd for resume");

        let worker_nsectors = disk.nsectors();
        debug!(
            "async block worker [ns={}]: AsyncFd configured, entering main loop",
            worker_nsectors
        );
        let mut applied_generation: u64 = 0;
        let mut total_queue_events: u64 = 0;

        // Periodic poll to detect missed notifications (guest adds to avail ring without kicking)
        let mut poll_interval = tokio::time::interval(std::time::Duration::from_secs(2));
        poll_interval.tick().await; // skip first immediate tick

        loop {
            tokio::select! {
                biased;

                // Snapshot quiesce: drain in-flight ops, publish queue state, ACK, park
                ready = async_quiesce_fd.readable() => {
                    if let Ok(mut guard) = ready {
                        guard.clear_ready();
                        if quiesce_fd.read().is_ok() {
                            debug!("async block worker: quiesce requested, draining in-flight ops");

                            // 1. Drain write_queue: start remaining batch and await completion
                            if !write_queue.is_empty() {
                                if current_write_batch.is_none() {
                                    current_write_batch = Some(start_write_batch(
                                        &mut write_queue,
                                        disk.clone(),
                                    ));
                                }
                            }

                            // 2. Await current_write_batch if in progress, complete its requests
                            if let Some(handle) = current_write_batch.take() {
                                match handle.await {
                                    Ok(batch_result) => {
                                        writes_since_flush_started = true;
                                        metrics.writes.fetch_add(batch_result.results.len() as u64, Ordering::Relaxed);
                                        metrics.bytes_written.fetch_add(batch_result.total_bytes, Ordering::Relaxed);
                                        metrics.write_latency_us.fetch_add(batch_result.elapsed_us, Ordering::Relaxed);
                                        for (index, status, len, status_ptr) in batch_result.results {
                                            unsafe { std::ptr::write_volatile(status_ptr, status); }
                                            metrics.in_flight.fetch_sub(1, Ordering::Relaxed);
                                            complete_request(&mut queue, &mem, &interrupt, RequestResult { index, status, len });
                                        }
                                    }
                                    Err(e) => {
                                        error!("async block worker: quiesce write batch panicked: {e:?}");
                                    }
                                }
                            }

                            // If there were still writes queued (arrived while awaiting batch), drain those too
                            while !write_queue.is_empty() {
                                let handle = start_write_batch(&mut write_queue, disk.clone());
                                match handle.await {
                                    Ok(batch_result) => {
                                        for (index, status, len, status_ptr) in batch_result.results {
                                            unsafe { std::ptr::write_volatile(status_ptr, status); }
                                            metrics.in_flight.fetch_sub(1, Ordering::Relaxed);
                                            complete_request(&mut queue, &mem, &interrupt, RequestResult { index, status, len });
                                        }
                                    }
                                    Err(e) => {
                                        error!("async block worker: quiesce residual write batch panicked: {e:?}");
                                    }
                                }
                            }

                            // 3. Await current_flush if in progress, complete its requests
                            if let Some(handle) = current_flush.take() {
                                let flush_status = match handle.await {
                                    Ok(status) => status,
                                    Err(e) => {
                                        error!("async block worker: quiesce flush panicked: {e:?}");
                                        virtio_bindings::virtio_blk::VIRTIO_BLK_S_IOERR as u8
                                    }
                                };
                                for flush_parsed in flush_requests_in_progress.drain(..) {
                                    unsafe { std::ptr::write_volatile(flush_parsed.status_ptr, flush_status); }
                                    metrics.flushes.fetch_add(1, Ordering::Relaxed);
                                    metrics.in_flight.fetch_sub(1, Ordering::Relaxed);
                                    complete_request(&mut queue, &mem, &interrupt, RequestResult {
                                        index: flush_parsed.index, status: flush_status, len: 0,
                                    });
                                }
                            }

                            // 4. Drain pending_flushes
                            if !pending_flushes.is_empty() {
                                let flush_reqs: Vec<ParsedRequest> = pending_flushes.drain(..).collect();
                                let disk_clone = disk.clone();
                                let flush_status = match tokio::task::spawn_local(async move {
                                    match disk_clone.cache_type() {
                                        CacheType::Writeback => {
                                            if let Err(e) = disk_clone.flush().await {
                                                error!("quiesce flush failed: {e:?}");
                                                VIRTIO_BLK_S_IOERR as u8
                                            } else if let Err(e) = disk_clone.sync().await {
                                                error!("quiesce sync failed: {e:?}");
                                                VIRTIO_BLK_S_IOERR as u8
                                            } else {
                                                VIRTIO_BLK_S_OK as u8
                                            }
                                        }
                                        CacheType::Unsafe => VIRTIO_BLK_S_OK as u8,
                                    }
                                }).await {
                                    Ok(status) => status,
                                    Err(e) => {
                                        error!("quiesce flush task panicked: {e:?}");
                                        VIRTIO_BLK_S_IOERR as u8
                                    }
                                };
                                for flush_parsed in flush_reqs {
                                    unsafe { std::ptr::write_volatile(flush_parsed.status_ptr, flush_status); }
                                    metrics.flushes.fetch_add(1, Ordering::Relaxed);
                                    metrics.in_flight.fetch_sub(1, Ordering::Relaxed);
                                    complete_request(&mut queue, &mem, &interrupt, RequestResult {
                                        index: flush_parsed.index, status: flush_status, len: 0,
                                    });
                                }
                            }

                            // 5. Drain all in-flight read tasks.
                            // Read tasks are spawned via spawn_local and hold raw
                            // pointers into guest memory (VolatileSliceGuard +
                            // status_ptr). They write_volatile the status byte on
                            // completion. We MUST await all of them before parking,
                            // because load_memory overwrites guest RAM during restore
                            // and any late write_volatile would corrupt restored state.
                            //
                            // The key issue: try_recv() never yields to the tokio
                            // runtime, so spawned tasks never get polled to completion.
                            // We use recv().await which yields, letting read tasks
                            // finish their I/O and send completions.
                            {
                                let drain_deadline = Instant::now() + Duration::from_secs(2);
                                loop {
                                    if metrics.concurrent_reads.load(Ordering::Relaxed) == 0 {
                                        while let Ok(result) = read_completion_rx.try_recv() {
                                            complete_request(&mut queue, &mem, &interrupt, result);
                                        }
                                        break;
                                    }
                                    let remaining = drain_deadline.saturating_duration_since(Instant::now());
                                    if remaining.is_zero() {
                                        warn!(
                                            "async block worker: timed out draining {} in-flight reads",
                                            metrics.concurrent_reads.load(Ordering::Relaxed)
                                        );
                                        while let Ok(result) = read_completion_rx.try_recv() {
                                            complete_request(&mut queue, &mem, &interrupt, result);
                                        }
                                        break;
                                    }
                                    match tokio::time::timeout(remaining, read_completion_rx.recv()).await {
                                        Ok(Some(result)) => {
                                            complete_request(&mut queue, &mem, &interrupt, result);
                                        }
                                        _ => break,
                                    }
                                }
                            }

                            // 6. Publish queue state and backend state to shared
                            debug!("async block worker: in-flight drained, publishing queue + backend state");
                            if let Ok(mut shared) = shared_queue.lock() {
                                *shared = queue.clone();
                            }
                            if let Ok(mut shared) = shared_backend_state.lock() {
                                *shared = disk.save_snapshot_state();
                            }

                            // 7. Signal the device that we've parked
                            {
                                let (lock, cvar) = &*quiesce_ack;
                                *lock.lock().unwrap() = true;
                                cvar.notify_one();
                            }

                            // 8. Park: wait for resume_fd
                            debug!("async block worker: parked, waiting for resume");
                            loop {
                                match async_resume_fd.readable().await {
                                    Ok(mut rg) => {
                                        rg.clear_ready();
                                        if resume_fd.read().is_ok() {
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        error!("async block worker: resume fd error: {e}");
                                        break;
                                    }
                                }
                            }
                            debug!("async block worker: resumed from quiesce");
                        }
                    }
                }

                ready = async_resync_fd.readable() => {
                    match ready {
                        Ok(mut guard) => {
                            guard.clear_ready();
                            if resync_fd.read().is_ok() {
                                apply_shared_queue_state_if_needed(
                                    &mut queue,
                                    &mem,
                                    &shared_queue,
                                    &shared_generation,
                                    &mut applied_generation,
                                );
                                debug!("async block worker [ns={}]: resync applied, queue avail={} used={}",
                                    worker_nsectors, queue.next_avail().0, queue.next_used().0);
                                // Restore backend state if the device provided one
                                if let Ok(mut shared) = shared_backend_state.lock() {
                                    if let Some(data) = shared.take() {
                                        debug!("async block worker [ns={}]: restoring backend state ({} bytes)", worker_nsectors, data.len());
                                        disk.restore_snapshot_state(&data);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("resync fd ready error: {e}");
                        }
                    }
                }

                // Wait for queue event
                ready = async_queue_fd.readable() => {
                    match ready {
                        Ok(mut guard) => {
                            // Clear the ready state
                            guard.clear_ready();
                            // Read the eventfd to acknowledge
                            // WouldBlock is expected - it means a spurious wakeup or the event was already consumed
                            match queue_evt.read() {
                                Ok(_) => {
                                    apply_shared_queue_state_if_needed(
                                        &mut queue,
                                        &mem,
                                        &shared_queue,
                                        &shared_generation,
                                        &mut applied_generation,
                                    );
                                    total_queue_events += 1;
                                    // Pop and parse all available requests
                                    let requests = pop_and_parse_requests(&mut queue, &mem);
                                    debug!("async block worker [ns={}]: queue event #{}, parsed {} requests, queue avail={} used={}",
                                        worker_nsectors, total_queue_events, requests.len(),
                                        queue.next_avail().0, queue.next_used().0);

                                    for parsed in requests {
                                        metrics.in_flight.fetch_add(1, Ordering::Relaxed);

                                        // Extract write metadata before matching (to avoid borrow issues)
                                        let write_info = if let Request::Write { bufs, offset } = &parsed.request {
                                            let len: usize = bufs.iter().map(|b| b.len()).sum();
                                            Some((*offset, len))
                                        } else {
                                            None
                                        };

                                        match &parsed.request {
                                            Request::Read { .. } | Request::GetId { .. } |
                                            Request::Discard { .. } | Request::WriteZeroes { .. } => {
                                                // Reads and other non-write ops can proceed immediately
                                                spawn_read_task(
                                                    parsed,
                                                    disk.clone(),
                                                    read_completion_tx.clone(),
                                                    metrics.clone(),
                                                );
                                            }
                                            Request::Write { .. } => {
                                                // Queue writes for batching
                                                let (offset, len) = write_info.unwrap();
                                                write_seq += 1;
                                                write_queue.push_back(QueuedWrite {
                                                    parsed,
                                                    offset,
                                                    len,
                                                    seq: write_seq,
                                                });
                                                trace!("async block worker: queued write, offset={}, len={}, queue_len={}",
                                                       offset, len, write_queue.len());
                                            }
                                            Request::Flush => {
                                                // Queue flush - it will execute after current batch completes
                                                if current_write_batch.is_none() && write_queue.is_empty() && current_flush.is_none() {
                                                    // No writes in progress or queued, no flush running - start flush now
                                                    trace!("async block worker: flush with no pending writes, starting immediately");
                                                    writes_since_flush_started = false;
                                                    flush_requests_in_progress.push(parsed);

                                                    let disk_clone = disk.clone();
                                                    current_flush = Some(tokio::task::spawn_local(async move {
                                                        match disk_clone.cache_type() {
                                                            CacheType::Writeback => {
                                                                if let Err(e) = disk_clone.flush().await {
                                                                    error!("flush failed: {e:?}");
                                                                    VIRTIO_BLK_S_IOERR as u8
                                                                } else if let Err(e) = disk_clone.sync().await {
                                                                    error!("sync failed: {e:?}");
                                                                    VIRTIO_BLK_S_IOERR as u8
                                                                } else {
                                                                    VIRTIO_BLK_S_OK as u8
                                                                }
                                                            }
                                                            CacheType::Unsafe => VIRTIO_BLK_S_OK as u8,
                                                        }
                                                    }));
                                                } else {
                                                    trace!("async block worker: queueing flush, batch_in_progress={}, queue_len={}, flush_in_progress={}",
                                                           current_write_batch.is_some(), write_queue.len(), current_flush.is_some());
                                                    pending_flushes.push_back(parsed);
                                                }
                                            }
                                        }
                                    }

                                    // Try to start a write batch if none is running
                                    if current_write_batch.is_none() && !write_queue.is_empty() {
                                        current_write_batch = Some(start_write_batch(
                                            &mut write_queue,
                                            disk.clone(),
                                        ));
                                    }
                                }
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    // Spurious wakeup - this is normal with edge-triggered async fd
                                    trace!("async block worker: spurious queue wakeup (WouldBlock)");
                                }
                                Err(e) => {
                                    error!("Failed to get queue event: {e:?}");
                                }
                            }
                        }
                        Err(e) => {
                            error!("queue fd ready error: {e}");
                        }
                    }
                }

                // Periodic poll: detect missed notifications
                _ = poll_interval.tick() => {
                    // Read avail_idx directly from guest memory
                    if let Some(avail_idx_addr) = queue.avail_ring.checked_add(2) {
                        if let Ok(avail_idx) = mem.read_obj::<u16>(avail_idx_addr) {
                            let next_avail = queue.next_avail().0;
                            if avail_idx != next_avail {
                                warn!("async block worker [ns={}]: MISSED NOTIFICATION! avail_idx_in_mem={} next_avail={} next_used={} total_events={}",
                                    worker_nsectors, avail_idx, next_avail, queue.next_used().0, total_queue_events);
                                // Try to process the missed requests
                                let requests = pop_and_parse_requests(&mut queue, &mem);
                                if !requests.is_empty() {
                                    warn!("async block worker [ns={}]: recovered {} missed requests!", worker_nsectors, requests.len());
                                    for parsed in requests {
                                        metrics.in_flight.fetch_add(1, Ordering::Relaxed);
                                        match &parsed.request {
                                            Request::Read { .. } | Request::GetId { .. } |
                                            Request::Discard { .. } | Request::WriteZeroes { .. } => {
                                                spawn_read_task(parsed, disk.clone(), read_completion_tx.clone(), metrics.clone());
                                            }
                                            Request::Write { .. } | Request::Flush => {
                                                // For simplicity, treat as read path
                                                spawn_read_task(parsed, disk.clone(), read_completion_tx.clone(), metrics.clone());
                                            }
                                        }
                                    }
                                }
                            } else {
                                trace!("async block worker [ns={}]: poll ok, avail_idx={} next_avail={} next_used={} events={}",
                                    worker_nsectors, avail_idx, next_avail, queue.next_used().0, total_queue_events);
                            }
                        }
                    }
                }

                // Wait for stop event
                ready = async_stop_fd.readable() => {
                    match ready {
                        Ok(_) => {
                            debug!("stopping async worker thread");
                            let _ = stop_fd.read();
                            disk.on_exit();
                            return;
                        }
                        Err(e) => {
                            error!("stop fd ready error: {e}");
                        }
                    }
                }

                // Current write batch completed
                result = async {
                    match &mut current_write_batch {
                        Some(handle) => handle.await,
                        None => std::future::pending().await,
                    }
                }, if current_write_batch.is_some() => {
                    current_write_batch = None;

                    match result {
                        Ok(batch_result) => {
                            debug!("async block worker: write batch completed, {} writes, {} bytes in {}us ({}ms)",
                                   batch_result.results.len(), batch_result.total_bytes, batch_result.elapsed_us,
                                   batch_result.elapsed_us / 1000);

                            // Mark that writes occurred - next flush cannot be skipped
                            writes_since_flush_started = true;

                            // Update metrics
                            metrics.writes.fetch_add(batch_result.results.len() as u64, Ordering::Relaxed);
                            metrics.bytes_written.fetch_add(batch_result.total_bytes, Ordering::Relaxed);
                            metrics.write_latency_us.fetch_add(batch_result.elapsed_us, Ordering::Relaxed);

                            // Complete all requests in the batch
                            for (index, status, len, status_ptr) in batch_result.results {
                                // Write status byte to guest memory
                                unsafe {
                                    std::ptr::write_volatile(status_ptr, status);
                                }
                                metrics.in_flight.fetch_sub(1, Ordering::Relaxed);
                                complete_request(&mut queue, &mem, &interrupt, RequestResult { index, status, len });
                            }

                            // Start flush if there are pending flushes and no flush is running
                            if !pending_flushes.is_empty() && current_flush.is_none() {
                                let flush_count = pending_flushes.len();
                                trace!("async block worker: spawning flush for {} requests", flush_count);

                                // Reset flag - we're starting a flush now
                                writes_since_flush_started = false;

                                // Move pending flushes to in-progress
                                flush_requests_in_progress.extend(pending_flushes.drain(..));

                                // Spawn non-blocking flush task
                                let disk_clone = disk.clone();
                                current_flush = Some(tokio::task::spawn_local(async move {
                                    match disk_clone.cache_type() {
                                        CacheType::Writeback => {
                                            if let Err(e) = disk_clone.flush().await {
                                                error!("flush failed: {e:?}");
                                                VIRTIO_BLK_S_IOERR as u8
                                            } else if let Err(e) = disk_clone.sync().await {
                                                error!("sync failed: {e:?}");
                                                VIRTIO_BLK_S_IOERR as u8
                                            } else {
                                                VIRTIO_BLK_S_OK as u8
                                            }
                                        }
                                        CacheType::Unsafe => VIRTIO_BLK_S_OK as u8,
                                    }
                                }));
                            }

                            // Start next batch if there are queued writes
                            if !write_queue.is_empty() {
                                current_write_batch = Some(start_write_batch(
                                    &mut write_queue,
                                    disk.clone(),
                                ));
                            }
                        }
                        Err(e) => {
                            error!("write batch task panicked: {e:?}");
                            // On panic, we lose the writes - mark them as failed
                            // Note: This shouldn't happen in normal operation
                        }
                    }
                }

                // Process completed read requests
                Some(result) = read_completion_rx.recv() => {
                    trace!("async block worker: read completed, index={}", result.index);
                    complete_request(&mut queue, &mem, &interrupt, result);
                }

                // Flush completed
                result = async {
                    match &mut current_flush {
                        Some(handle) => handle.await,
                        None => std::future::pending().await,
                    }
                }, if current_flush.is_some() => {
                    current_flush = None;

                    let flush_status = match result {
                        Ok(status) => status,
                        Err(e) => {
                            error!("flush task panicked: {e:?}");
                            VIRTIO_BLK_S_IOERR as u8
                        }
                    };

                    let flush_count = flush_requests_in_progress.len();
                    trace!("async block worker: flush completed, completing {} requests with status {}",
                           flush_count, flush_status);

                    // Complete all flush requests that were waiting
                    for flush_parsed in flush_requests_in_progress.drain(..) {
                        unsafe {
                            std::ptr::write_volatile(flush_parsed.status_ptr, flush_status);
                        }
                        metrics.flushes.fetch_add(1, Ordering::Relaxed);
                        metrics.in_flight.fetch_sub(1, Ordering::Relaxed);
                        complete_request(
                            &mut queue,
                            &mem,
                            &interrupt,
                            RequestResult {
                                index: flush_parsed.index,
                                status: flush_status,
                                len: 0,
                            },
                        );
                    }

                    // If more flushes arrived while we were flushing, check if we need another
                    if !pending_flushes.is_empty() {
                        if writes_since_flush_started {
                            // Writes occurred since flush started - need to actually flush
                            let flush_count = pending_flushes.len();
                            trace!("async block worker: starting another flush for {} new requests (writes occurred)", flush_count);

                            writes_since_flush_started = false;
                            flush_requests_in_progress.extend(pending_flushes.drain(..));

                            let disk_clone = disk.clone();
                            current_flush = Some(tokio::task::spawn_local(async move {
                                match disk_clone.cache_type() {
                                    CacheType::Writeback => {
                                        if let Err(e) = disk_clone.flush().await {
                                            error!("flush failed: {e:?}");
                                            VIRTIO_BLK_S_IOERR as u8
                                        } else if let Err(e) = disk_clone.sync().await {
                                            error!("sync failed: {e:?}");
                                            VIRTIO_BLK_S_IOERR as u8
                                        } else {
                                            VIRTIO_BLK_S_OK as u8
                                        }
                                    }
                                    CacheType::Unsafe => VIRTIO_BLK_S_OK as u8,
                                }
                            }));
                        } else {
                            // No writes since flush started - just completed flush covers these too
                            let flush_count = pending_flushes.len();
                            trace!("async block worker: coalescing {} flushes (no writes since last flush)", flush_count);

                            for flush_parsed in pending_flushes.drain(..) {
                                unsafe {
                                    std::ptr::write_volatile(flush_parsed.status_ptr, flush_status);
                                }
                                metrics.flushes.fetch_add(1, Ordering::Relaxed);
                                metrics.in_flight.fetch_sub(1, Ordering::Relaxed);
                                complete_request(
                                    &mut queue,
                                    &mem,
                                    &interrupt,
                                    RequestResult {
                                        index: flush_parsed.index,
                                        status: flush_status,
                                        len: 0,
                                    },
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

fn apply_shared_queue_state_if_needed(
    queue: &mut Queue,
    mem: &GuestMemoryMmap,
    shared_queue: &Arc<Mutex<Queue>>,
    shared_generation: &Arc<AtomicU64>,
    applied_generation: &mut u64,
) {
    let generation = shared_generation.load(Ordering::Acquire);
    if generation == *applied_generation {
        return;
    }

    if let Ok(shared) = shared_queue.lock() {
        *queue = shared.clone();

        if queue.ready {
            if let Some(used_idx_addr) = queue.used_ring.checked_add(2) {
                if let Ok(used_idx) = mem.read_obj::<u16>(used_idx_addr) {
                    queue.set_next_used(used_idx);
                }
            }
            if let Some(avail_idx_addr) = queue.avail_ring.checked_add(2) {
                if let Ok(avail_idx) = mem.read_obj::<u16>(avail_idx_addr) {
                    if queue.next_avail().0 > avail_idx {
                        queue.set_next_avail(avail_idx);
                    }
                }
            }
        }

        *applied_generation = generation;
    }
}

/// Pop all available requests from the queue and parse them.
fn pop_and_parse_requests(queue: &mut Queue, mem: &GuestMemoryMmap) -> Vec<ParsedRequest> {
    let mut requests = Vec::new();

    loop {
        queue.disable_notification(mem).unwrap();

        while let Some(head) = queue.pop(mem) {
            trace!(
                "async block worker: popped request, head index={}",
                head.index
            );
            let index = head.index;

            // Parse the request
            match parse_request(mem, head.clone()) {
                Ok((request, status_ptr)) => {
                    requests.push(ParsedRequest {
                        request,
                        index,
                        status_ptr,
                    });
                }
                Err(e) => {
                    error!("failed to parse request: {e:?}");
                    // Complete with error
                    if let Err(e) = queue.add_used(mem, index, 0) {
                        error!("failed to add used: {e:?}");
                    }
                }
            }
        }

        if !queue.enable_notification(mem).unwrap() {
            break;
        }
    }

    requests
}

/// Spawn a task for read-like operations (reads, get_id, discard, write_zeroes).
/// These don't need flush ordering and can proceed concurrently.
fn spawn_read_task(
    parsed: ParsedRequest,
    disk: Arc<dyn AsyncBlockBackend + Send + Sync>,
    completion_tx: mpsc::Sender<RequestResult>,
    metrics: Arc<AsyncWorkerMetrics>,
) {
    // Track concurrent reads
    let concurrent = metrics.concurrent_reads.fetch_add(1, Ordering::Relaxed) + 1;
    // Update peak if this is a new high
    let mut peak = metrics.peak_concurrent_reads.load(Ordering::Relaxed);
    while concurrent > peak {
        match metrics.peak_concurrent_reads.compare_exchange_weak(
            peak,
            concurrent,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(p) => peak = p,
        }
    }

    tokio::task::spawn_local(async move {
        let start = Instant::now();
        let (status, len, req_type) =
            process_request_async_with_metrics(&disk, parsed.request).await;
        let elapsed_us = start.elapsed().as_micros() as u64;

        // Update metrics
        match req_type {
            RequestType::Read => {
                metrics.reads.fetch_add(1, Ordering::Relaxed);
                metrics.bytes_read.fetch_add(len as u64, Ordering::Relaxed);
                metrics
                    .read_latency_us
                    .fetch_add(elapsed_us, Ordering::Relaxed);
            }
            RequestType::Other => {}
            _ => {}
        }
        metrics.in_flight.fetch_sub(1, Ordering::Relaxed);
        metrics.concurrent_reads.fetch_sub(1, Ordering::Relaxed);

        // Write status byte to guest memory
        unsafe {
            std::ptr::write_volatile(parsed.status_ptr, status);
        }

        let _ = completion_tx
            .send(RequestResult {
                index: parsed.index,
                status,
                len,
            })
            .await;
    });
}

/// Start a batch write operation, coalescing and deduplicating queued writes.
///
/// Deduplication: For writes to the exact same (offset, len), only the latest is kept.
/// All other writes are processed in a single batch call to the backend.
fn start_write_batch(
    write_queue: &mut VecDeque<QueuedWrite>,
    disk: Arc<dyn AsyncBlockBackend + Send + Sync>,
) -> JoinHandle<BatchWriteResult> {
    // Drain all queued writes
    let writes: Vec<QueuedWrite> = write_queue.drain(..).collect();

    debug!("start_write_batch: processing {} writes", writes.len());

    // Deduplicate: for same (offset, len), keep only the highest seq (latest)
    // Key: (offset, len) -> (seq, index in writes vec)
    let mut dedup_map: HashMap<(u64, usize), (u64, usize)> = HashMap::new();

    for (idx, w) in writes.iter().enumerate() {
        let key = (w.offset, w.len);
        match dedup_map.get(&key) {
            Some(&(existing_seq, _)) if existing_seq >= w.seq => {
                // Existing write is newer or same, skip this one
                // But we still need to complete the request as successful
            }
            _ => {
                // This write is newer, replace
                dedup_map.insert(key, (w.seq, idx));
            }
        }
    }

    // Collect writes to actually process (the deduplicated ones)
    let mut to_process: Vec<&QueuedWrite> =
        dedup_map.values().map(|&(_, idx)| &writes[idx]).collect();

    // Sort by offset for better sequential I/O
    to_process.sort_by_key(|w| w.offset);

    // Track which writes were deduplicated (not in to_process)
    let processed_indices: std::collections::HashSet<usize> =
        dedup_map.values().map(|&(_, idx)| idx).collect();

    debug!(
        "start_write_batch: after dedup, {} writes to process, {} deduplicated",
        to_process.len(),
        writes.len() - to_process.len()
    );

    // Prepare batch data
    // Each entry: (offset, bufs, index, status_ptr)
    let mut batch_writes: Vec<(u64, Vec<VolatileSliceGuard>)> =
        Vec::with_capacity(to_process.len());
    let mut batch_meta: Vec<(u16, *mut u8)> = Vec::with_capacity(to_process.len());

    for w in &to_process {
        if let Request::Write { bufs, offset } = &w.parsed.request {
            batch_writes.push((*offset, bufs.clone()));
            batch_meta.push((w.parsed.index, w.parsed.status_ptr));
        }
    }

    // Collect deduplicated writes (completed with success, 0 bytes)
    let mut deduped_completions: Vec<(u16, u8, u32, *mut u8)> = Vec::new();
    for (idx, w) in writes.iter().enumerate() {
        if !processed_indices.contains(&idx) {
            // This write was deduplicated - complete it immediately as success
            deduped_completions.push((
                w.parsed.index,
                VIRTIO_BLK_S_OK as u8,
                0, // 0 bytes written (deduplicated)
                w.parsed.status_ptr,
            ));
        }
    }

    tokio::task::spawn_local(async move {
        let start = Instant::now();

        // Call the batch write on the backend
        let batch_results = disk.write_batch(batch_writes).await;
        let elapsed_us = start.elapsed().as_micros() as u64;

        let mut results: Vec<(u16, u8, u32, *mut u8)> =
            Vec::with_capacity(batch_meta.len() + deduped_completions.len());
        let mut total_bytes: u64 = 0;

        match batch_results {
            Ok(lens) => {
                // Successful batch - create results for each write
                for ((index, status_ptr), len) in batch_meta.into_iter().zip(lens.into_iter()) {
                    total_bytes += len as u64;
                    results.push((index, VIRTIO_BLK_S_OK as u8, len as u32, status_ptr));
                }
            }
            Err(e) => {
                error!("batch write failed: {e:?}");
                // All writes in this batch failed
                for (index, status_ptr) in batch_meta {
                    results.push((index, VIRTIO_BLK_S_IOERR as u8, 0, status_ptr));
                }
            }
        }

        // Add the deduplicated completions
        results.extend(deduped_completions);

        BatchWriteResult {
            results,
            total_bytes,
            elapsed_us,
        }
    })
}

/// Request type for metrics tracking.
#[derive(Debug, Clone, Copy)]
enum RequestType {
    Read,
    Write,
    Flush,
    Other,
}

/// Parse a descriptor chain into a request.
fn parse_request(
    mem: &GuestMemoryMmap,
    head: crate::virtio::queue::DescriptorChain,
) -> Result<(Request, *mut u8), RequestError> {
    let mut reader = Reader::new(mem, head.clone())
        .map_err(|e| RequestError::ReadingFromDescriptor(io::Error::other(e)))?;

    let writer = Writer::new(mem, head.clone())
        .map_err(|e| RequestError::WritingToDescriptor(io::Error::other(e)))?;

    let request_header: RequestHeader = reader
        .read_obj()
        .map_err(RequestError::ReadingFromDescriptor)?;

    // Get pointer to status byte (last byte of writer region)
    let status_ptr = unsafe {
        let available = writer.available_bytes();
        if available == 0 {
            return Err(RequestError::InvalidDataLength);
        }
        writer.get_status_ptr()
    };

    let request = match request_header.request_type {
        VIRTIO_BLK_T_IN => {
            let data_len = writer.available_bytes() - 1; // -1 for status byte
            if !data_len.is_multiple_of(512) {
                return Err(RequestError::InvalidDataLength);
            }
            let bufs =
                unsafe { VolatileSliceGuard::from_volatile_slices(writer.get_slices(data_len)) };
            Request::Read {
                bufs,
                offset: request_header.sector * 512,
            }
        }
        VIRTIO_BLK_T_OUT => {
            let data_len = reader.available_bytes();
            if !data_len.is_multiple_of(512) {
                return Err(RequestError::InvalidDataLength);
            }
            let bufs =
                unsafe { VolatileSliceGuard::from_volatile_slices(reader.get_slices(data_len)) };
            Request::Write {
                bufs,
                offset: request_header.sector * 512,
            }
        }
        VIRTIO_BLK_T_FLUSH => Request::Flush,
        VIRTIO_BLK_T_GET_ID => {
            let data_len = writer.available_bytes() - 1;
            let bufs =
                unsafe { VolatileSliceGuard::from_volatile_slices(writer.get_slices(data_len)) };
            if bufs.is_empty() {
                return Err(RequestError::InvalidDataLength);
            }
            Request::GetId {
                buf: bufs.into_iter().next().unwrap(),
            }
        }
        VIRTIO_BLK_T_DISCARD => {
            let discard_data: DiscardWriteData = reader
                .read_obj()
                .map_err(RequestError::ReadingFromDescriptor)?;
            Request::Discard {
                offset: discard_data.sector * 512,
                len: discard_data.num_sectors as u64 * 512,
            }
        }
        VIRTIO_BLK_T_WRITE_ZEROES => {
            let discard_data: DiscardWriteData = reader
                .read_obj()
                .map_err(RequestError::ReadingFromDescriptor)?;
            let unmap = (discard_data.flags & VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP) != 0;
            Request::WriteZeroes {
                offset: discard_data.sector * 512,
                len: discard_data.num_sectors as u64 * 512,
                unmap,
            }
        }
        _ => return Err(RequestError::UnknownRequest),
    };

    Ok((request, status_ptr))
}

/// Complete a request by adding it to the used ring and signaling if needed.
fn complete_request(
    queue: &mut Queue,
    mem: &GuestMemoryMmap,
    interrupt: &InterruptTransport,
    result: RequestResult,
) {
    if let Err(e) = queue.add_used(mem, result.index, result.len) {
        error!("failed to add used: {e:?}");
    }

    if let Err(e) = interrupt.try_signal_used_queue() {
        error!("complete_request: error signalling queue: {e:?}");
    }
    trace!(
        "complete_request: index={} status={} len={} queue_used={}",
        result.index,
        result.status,
        result.len,
        queue.next_used().0
    );
}

/// Process a single request asynchronously, returning request type for metrics.
async fn process_request_async_with_metrics<B: AsyncBlockBackend>(
    disk: &B,
    request: Request,
) -> (u8, u32, RequestType) {
    let (result, req_type) = match request {
        Request::Read { bufs, offset } => {
            log::debug!(
                "process_request_async: READ offset={} num_bufs={}",
                offset,
                bufs.len()
            );
            let res = disk.read_vectored_at(bufs, offset).await;
            log::debug!(
                "process_request_async: READ completed, result={:?}",
                res.as_ref().map(|n| *n)
            );
            (res.map(|n| n as u32), RequestType::Read)
        }
        Request::Write { bufs, offset } => {
            log::trace!(
                "process_request_async: WRITE offset={} num_bufs={}",
                offset,
                bufs.len()
            );
            (
                disk.write_vectored_at(bufs, offset).await.map(|n| n as u32),
                RequestType::Write,
            )
        }
        Request::Flush => {
            log::trace!("process_request_async: FLUSH");
            let res = match disk.cache_type() {
                CacheType::Writeback => {
                    if let Err(e) = disk.flush().await {
                        Err(e)
                    } else {
                        disk.sync().await.map(|_| 0)
                    }
                }
                CacheType::Unsafe => Ok(0),
            };
            (res, RequestType::Flush)
        }
        Request::GetId { buf } => {
            log::trace!("process_request_async: GET_ID");
            let id = disk.image_id();
            let len = id.len().min(buf.len());
            unsafe {
                buf.copy_from(&id[..len]);
            }
            (Ok(len as u32), RequestType::Other)
        }
        Request::Discard { offset, len } => {
            log::trace!(
                "process_request_async: DISCARD offset={} len={}",
                offset,
                len
            );
            (
                disk.discard(offset, len).await.map(|_| 0),
                RequestType::Other,
            )
        }
        Request::WriteZeroes { offset, len, unmap } => {
            log::trace!(
                "process_request_async: WRITE_ZEROES offset={} len={} unmap={}",
                offset,
                len,
                unmap
            );
            (
                disk.write_zeroes(offset, len, unmap).await.map(|_| 0),
                RequestType::Other,
            )
        }
    };

    match result {
        Ok(len) => (VIRTIO_BLK_S_OK as u8, len, req_type),
        Err(e) => {
            error!("async request error: {e:?}");
            (VIRTIO_BLK_S_IOERR as u8, 0, req_type)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::block::BoxFuture;
    use std::sync::atomic::{AtomicU64, AtomicUsize};
    use std::sync::{Mutex, RwLock};
    use tokio::sync::Notify;

    // ========================================================================
    // Test Helpers
    // ========================================================================

    /// Creates a VolatileSliceGuard from a mutable buffer.
    fn make_guard(buf: &mut [u8]) -> VolatileSliceGuard {
        VolatileSliceGuard {
            ptr: buf.as_mut_ptr(),
            len: buf.len(),
        }
    }

    // ========================================================================
    // Basic VolatileSliceGuard Tests
    // ========================================================================

    #[test]
    fn test_volatile_slice_guard() {
        let mut data = vec![0u8; 1024];
        let guard = make_guard(&mut data);

        assert_eq!(guard.len(), 1024);
        assert!(!guard.is_empty());

        let sub = guard.subslice(100, 200).unwrap();
        assert_eq!(sub.len(), 200);

        // Out of bounds should return None
        assert!(guard.subslice(1000, 100).is_none());
    }

    #[test]
    fn test_volatile_slice_guard_copy() {
        let mut data = vec![0u8; 512];
        let guard = make_guard(&mut data);

        // Copy data in
        let src = vec![0xAB_u8; 512];
        unsafe { guard.copy_from(&src) };

        // Verify it's there
        assert_eq!(data, vec![0xAB_u8; 512]);

        // Copy data out
        let mut dst = vec![0u8; 512];
        unsafe { guard.copy_to(&mut dst) };
        assert_eq!(dst, vec![0xAB_u8; 512]);
    }

    // ========================================================================
    // Test Backend with Operation Tracking
    // ========================================================================

    /// Event types for tracking operation order
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum OpEvent {
        WriteStart { offset: u64, len: usize },
        WriteEnd { offset: u64, len: usize },
        ReadStart { offset: u64, len: usize },
        ReadEnd { offset: u64, len: usize },
        FlushStart,
        FlushEnd,
        SyncStart,
        SyncEnd,
        Discard { offset: u64, len: u64 },
        WriteZeroes { offset: u64, len: u64, unmap: bool },
        GetId,
    }

    /// Test backend that tracks operations and supports artificial delays
    struct TrackingBackend {
        data: RwLock<Vec<u8>>,
        sectors: u64,
        events: Mutex<Vec<OpEvent>>,
        /// Delay to add to read operations (simulates slow storage)
        read_delay_ms: AtomicU64,
        /// Delay to add to write operations (simulates slow storage)
        write_delay_ms: AtomicU64,
        /// Delay to add to flush operations
        flush_delay_ms: AtomicU64,
        /// Counter for operations in progress
        writes_in_progress: AtomicUsize,
        /// Notify when all writes complete (for testing)
        writes_done: Notify,
        /// Image ID
        image_id: Vec<u8>,
    }

    impl TrackingBackend {
        fn new(size_bytes: usize) -> Self {
            let sectors = size_bytes as u64 / 512;
            Self {
                data: RwLock::new(vec![0u8; size_bytes]),
                sectors,
                events: Mutex::new(Vec::new()),
                read_delay_ms: AtomicU64::new(0),
                write_delay_ms: AtomicU64::new(0),
                flush_delay_ms: AtomicU64::new(0),
                writes_in_progress: AtomicUsize::new(0),
                writes_done: Notify::new(),
                image_id: b"test-tracking-disk".to_vec(),
            }
        }

        fn set_read_delay(&self, ms: u64) {
            self.read_delay_ms.store(ms, Ordering::SeqCst);
        }

        fn set_write_delay(&self, ms: u64) {
            self.write_delay_ms.store(ms, Ordering::SeqCst);
        }

        fn set_flush_delay(&self, ms: u64) {
            self.flush_delay_ms.store(ms, Ordering::SeqCst);
        }

        fn events(&self) -> Vec<OpEvent> {
            self.events.lock().unwrap().clone()
        }

        fn clear_events(&self) {
            self.events.lock().unwrap().clear();
        }

        fn record(&self, event: OpEvent) {
            self.events.lock().unwrap().push(event);
        }

        /// Read raw data (for verification)
        fn read_raw(&self, offset: usize, len: usize) -> Vec<u8> {
            let data = self.data.read().unwrap();
            data[offset..offset + len].to_vec()
        }
    }

    impl AsyncBlockBackend for TrackingBackend {
        fn cache_type(&self) -> CacheType {
            CacheType::Writeback
        }

        fn nsectors(&self) -> u64 {
            self.sectors
        }

        fn image_id(&self) -> &[u8] {
            &self.image_id
        }

        fn read_vectored_at(
            &self,
            bufs: Vec<VolatileSliceGuard>,
            offset: u64,
        ) -> BoxFuture<'_, io::Result<usize>> {
            let total_len: usize = bufs.iter().map(|b| b.len()).sum();
            self.record(OpEvent::ReadStart {
                offset,
                len: total_len,
            });

            Box::pin(async move {
                let delay = self.read_delay_ms.load(Ordering::SeqCst);
                if delay > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }

                let data = self.data.read().unwrap();
                let mut total = 0;
                let mut current_offset = offset as usize;

                for buf in bufs {
                    let len = buf.len().min(data.len().saturating_sub(current_offset));
                    if len > 0 {
                        unsafe {
                            buf.copy_from(&data[current_offset..current_offset + len]);
                        }
                        current_offset += len;
                        total += len;
                    }
                }
                self.record(OpEvent::ReadEnd { offset, len: total });
                Ok(total)
            })
        }

        fn write_vectored_at(
            &self,
            bufs: Vec<VolatileSliceGuard>,
            offset: u64,
        ) -> BoxFuture<'_, io::Result<usize>> {
            let total_len: usize = bufs.iter().map(|b| b.len()).sum();
            self.record(OpEvent::WriteStart {
                offset,
                len: total_len,
            });
            self.writes_in_progress.fetch_add(1, Ordering::SeqCst);

            Box::pin(async move {
                // Add artificial delay if configured
                let delay = self.write_delay_ms.load(Ordering::SeqCst);
                if delay > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }

                let mut data = self.data.write().unwrap();
                let mut total = 0;
                let mut current_offset = offset as usize;

                for buf in bufs {
                    let len = buf.len().min(data.len().saturating_sub(current_offset));
                    if len > 0 {
                        let mut temp = vec![0u8; len];
                        unsafe {
                            buf.copy_to(&mut temp);
                        }
                        data[current_offset..current_offset + len].copy_from_slice(&temp);
                        current_offset += len;
                        total += len;
                    }
                }

                self.record(OpEvent::WriteEnd { offset, len: total });
                if self.writes_in_progress.fetch_sub(1, Ordering::SeqCst) == 1 {
                    self.writes_done.notify_waiters();
                }
                Ok(total)
            })
        }

        fn flush(&self) -> BoxFuture<'_, io::Result<()>> {
            self.record(OpEvent::FlushStart);
            Box::pin(async move {
                let delay = self.flush_delay_ms.load(Ordering::SeqCst);
                if delay > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }
                self.record(OpEvent::FlushEnd);
                Ok(())
            })
        }

        fn sync(&self) -> BoxFuture<'_, io::Result<()>> {
            self.record(OpEvent::SyncStart);
            Box::pin(async move {
                self.record(OpEvent::SyncEnd);
                Ok(())
            })
        }

        fn discard(&self, offset: u64, len: u64) -> BoxFuture<'_, io::Result<()>> {
            self.record(OpEvent::Discard { offset, len });
            Box::pin(async move {
                // Zero out the discarded region
                let mut data = self.data.write().unwrap();
                let start = offset as usize;
                let end = (offset + len) as usize;
                if end <= data.len() {
                    data[start..end].fill(0);
                }
                Ok(())
            })
        }

        fn write_zeroes(
            &self,
            offset: u64,
            len: u64,
            unmap: bool,
        ) -> BoxFuture<'_, io::Result<()>> {
            self.record(OpEvent::WriteZeroes { offset, len, unmap });
            Box::pin(async move {
                let mut data = self.data.write().unwrap();
                let start = offset as usize;
                let end = (offset + len) as usize;
                if end <= data.len() {
                    data[start..end].fill(0);
                }
                Ok(())
            })
        }
    }

    // ========================================================================
    // Basic Backend Tests
    // ========================================================================

    #[test]
    fn test_backend_read_write() {
        let backend = Arc::new(TrackingBackend::new(4096));

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        // Write data
        let mut write_buf = vec![0xAB_u8; 512];
        let written = rt.block_on(async {
            backend
                .write_vectored_at(vec![make_guard(&mut write_buf)], 0)
                .await
                .unwrap()
        });
        assert_eq!(written, 512);

        // Read it back
        let mut read_buf = vec![0u8; 512];
        let read = rt.block_on(async {
            backend
                .read_vectored_at(vec![make_guard(&mut read_buf)], 0)
                .await
                .unwrap()
        });
        assert_eq!(read, 512);
        assert_eq!(read_buf, vec![0xAB_u8; 512]);

        // Verify events
        let events = backend.events();
        assert!(matches!(
            events[0],
            OpEvent::WriteStart {
                offset: 0,
                len: 512
            }
        ));
        assert!(matches!(
            events[1],
            OpEvent::WriteEnd {
                offset: 0,
                len: 512
            }
        ));
        assert!(matches!(
            events[2],
            OpEvent::ReadStart {
                offset: 0,
                len: 512
            }
        ));
        assert!(matches!(
            events[3],
            OpEvent::ReadEnd {
                offset: 0,
                len: 512
            }
        ));
    }

    #[test]
    fn test_backend_flush_sync() {
        let backend = Arc::new(TrackingBackend::new(4096));

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        rt.block_on(async {
            backend.flush().await.unwrap();
            backend.sync().await.unwrap();
        });

        let events = backend.events();
        assert_eq!(events[0], OpEvent::FlushStart);
        assert_eq!(events[1], OpEvent::FlushEnd);
        assert_eq!(events[2], OpEvent::SyncStart);
        assert_eq!(events[3], OpEvent::SyncEnd);
    }

    #[test]
    fn test_backend_discard() {
        let backend = Arc::new(TrackingBackend::new(4096));

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        // Write some data
        let mut write_buf = vec![0xFF_u8; 1024];
        rt.block_on(async {
            backend
                .write_vectored_at(vec![make_guard(&mut write_buf)], 0)
                .await
                .unwrap()
        });

        // Discard part of it
        rt.block_on(async {
            backend.discard(256, 512).await.unwrap();
        });

        // Verify the discarded region is zeroed
        let data = backend.read_raw(0, 1024);
        assert_eq!(&data[0..256], &vec![0xFF_u8; 256][..]);
        assert_eq!(&data[256..768], &vec![0x00_u8; 512][..]);
        assert_eq!(&data[768..1024], &vec![0xFF_u8; 256][..]);

        // Verify event
        let events = backend.events();
        assert!(events.iter().any(|e| matches!(
            e,
            OpEvent::Discard {
                offset: 256,
                len: 512
            }
        )));
    }

    #[test]
    fn test_backend_write_zeroes() {
        let backend = Arc::new(TrackingBackend::new(4096));

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        // Write some data
        let mut write_buf = vec![0xFF_u8; 1024];
        rt.block_on(async {
            backend
                .write_vectored_at(vec![make_guard(&mut write_buf)], 0)
                .await
                .unwrap()
        });

        // Write zeroes to part of it
        rt.block_on(async {
            backend.write_zeroes(128, 256, false).await.unwrap();
        });

        // Verify
        let data = backend.read_raw(0, 1024);
        assert_eq!(&data[0..128], &vec![0xFF_u8; 128][..]);
        assert_eq!(&data[128..384], &vec![0x00_u8; 256][..]);
        assert_eq!(&data[384..1024], &vec![0xFF_u8; 640][..]);

        // Verify event
        let events = backend.events();
        assert!(events.iter().any(|e| matches!(
            e,
            OpEvent::WriteZeroes {
                offset: 128,
                len: 256,
                unmap: false
            }
        )));
    }

    // ========================================================================
    // Concurrent Operation Tests
    // ========================================================================

    #[test]
    fn test_concurrent_writes() {
        let backend = Arc::new(TrackingBackend::new(8192));

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        rt.block_on(async {
            let local = tokio::task::LocalSet::new();

            local
                .run_until(async {
                    let mut handles = vec![];

                    // Spawn 10 concurrent writes to different offsets
                    for i in 0..10u8 {
                        let backend = backend.clone();
                        let offset = (i as u64) * 512;

                        let handle = tokio::task::spawn_local(async move {
                            let mut write_buf = vec![i; 512];
                            backend
                                .write_vectored_at(vec![make_guard(&mut write_buf)], offset)
                                .await
                                .unwrap();
                        });
                        handles.push(handle);
                    }

                    for handle in handles {
                        handle.await.unwrap();
                    }
                })
                .await;
        });

        // Verify all writes completed with correct data
        for i in 0..10u8 {
            let data = backend.read_raw((i as usize) * 512, 512);
            assert_eq!(data, vec![i; 512], "Data mismatch at sector {}", i);
        }
    }

    #[test]
    fn test_concurrent_reads_and_writes() {
        let backend = Arc::new(TrackingBackend::new(8192));

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        // Pre-write some data
        rt.block_on(async {
            for i in 0..8u8 {
                let mut write_buf = vec![i; 512];
                backend
                    .write_vectored_at(vec![make_guard(&mut write_buf)], (i as u64) * 512)
                    .await
                    .unwrap();
            }
        });

        backend.clear_events();

        // Now do concurrent reads and writes
        rt.block_on(async {
            let local = tokio::task::LocalSet::new();

            local
                .run_until(async {
                    let mut handles = vec![];

                    // Reads
                    for i in 0..4u8 {
                        let backend = backend.clone();
                        let offset = (i as u64) * 512;
                        let expected = i;

                        let handle = tokio::task::spawn_local(async move {
                            let mut read_buf = vec![0u8; 512];
                            backend
                                .read_vectored_at(vec![make_guard(&mut read_buf)], offset)
                                .await
                                .unwrap();
                            assert_eq!(read_buf, vec![expected; 512]);
                        });
                        handles.push(handle);
                    }

                    // Writes to different sectors
                    for i in 8..12u8 {
                        let backend = backend.clone();
                        let offset = (i as u64) * 512;

                        let handle = tokio::task::spawn_local(async move {
                            let mut write_buf = vec![i; 512];
                            backend
                                .write_vectored_at(vec![make_guard(&mut write_buf)], offset)
                                .await
                                .unwrap();
                        });
                        handles.push(handle);
                    }

                    for handle in handles {
                        handle.await.unwrap();
                    }
                })
                .await;
        });

        // Verify events show interleaved operations
        let events = backend.events();
        let read_starts = events
            .iter()
            .filter(|e| matches!(e, OpEvent::ReadStart { .. }))
            .count();
        let write_starts = events
            .iter()
            .filter(|e| matches!(e, OpEvent::WriteStart { .. }))
            .count();
        assert_eq!(read_starts, 4);
        assert_eq!(write_starts, 4);
    }

    // ========================================================================
    // Write Batching and Deduplication Tests
    // ========================================================================

    /// Test that write deduplication works for exact matches
    #[test]
    fn test_write_deduplication_logic() {
        // Simulate the deduplication logic from start_write_batch
        let writes = vec![
            (0u64, 512usize, 1u64), // offset=0, len=512, seq=1
            (512, 512, 2),          // offset=512, len=512, seq=2
            (0, 512, 3),            // offset=0, len=512, seq=3 (should override seq=1)
            (1024, 512, 4),         // offset=1024, len=512, seq=4
            (512, 512, 5),          // offset=512, len=512, seq=5 (should override seq=2)
        ];

        let mut dedup_map: HashMap<(u64, usize), (u64, usize)> = HashMap::new();

        for (idx, &(offset, len, seq)) in writes.iter().enumerate() {
            let key = (offset, len);
            match dedup_map.get(&key) {
                Some(&(existing_seq, _)) if existing_seq >= seq => {
                    // Existing write is newer or same, skip this one
                }
                _ => {
                    // This write is newer, replace
                    dedup_map.insert(key, (seq, idx));
                }
            }
        }

        // Should have 3 unique writes after dedup
        assert_eq!(dedup_map.len(), 3);

        // Check that we kept the right ones (highest seq for each offset/len)
        assert_eq!(dedup_map.get(&(0, 512)), Some(&(3, 2))); // seq=3, idx=2
        assert_eq!(dedup_map.get(&(512, 512)), Some(&(5, 4))); // seq=5, idx=4
        assert_eq!(dedup_map.get(&(1024, 512)), Some(&(4, 3))); // seq=4, idx=3
    }

    /// Test that different sizes at same offset are not deduplicated
    #[test]
    fn test_write_dedup_different_sizes() {
        let writes = vec![
            (0u64, 512usize, 1u64), // offset=0, len=512, seq=1
            (0, 1024, 2),           // offset=0, len=1024, seq=2 (different size, not deduped)
            (0, 512, 3),            // offset=0, len=512, seq=3 (overrides seq=1)
        ];

        let mut dedup_map: HashMap<(u64, usize), (u64, usize)> = HashMap::new();

        for (idx, &(offset, len, seq)) in writes.iter().enumerate() {
            let key = (offset, len);
            match dedup_map.get(&key) {
                Some(&(existing_seq, _)) if existing_seq >= seq => {}
                _ => {
                    dedup_map.insert(key, (seq, idx));
                }
            }
        }

        // Should have 2 unique writes (different sizes)
        assert_eq!(dedup_map.len(), 2);
        assert_eq!(dedup_map.get(&(0, 512)), Some(&(3, 2))); // seq=3
        assert_eq!(dedup_map.get(&(0, 1024)), Some(&(2, 1))); // seq=2
    }

    /// Test write queue draining and batching
    #[test]
    fn test_write_queue_batching() {
        let mut write_queue: VecDeque<QueuedWrite> = VecDeque::new();
        let mut write_seq = 0u64;

        // Simulate queueing writes
        for i in 0..5 {
            write_seq += 1;
            let mut buf = vec![0u8; 512];
            write_queue.push_back(QueuedWrite {
                parsed: ParsedRequest {
                    request: Request::Write {
                        bufs: vec![make_guard(&mut buf)],
                        offset: i * 512,
                    },
                    index: i as u16,
                    status_ptr: std::ptr::null_mut(),
                },
                offset: i * 512,
                len: 512,
                seq: write_seq,
            });
        }

        assert_eq!(write_queue.len(), 5);

        // Drain all writes (simulating start_write_batch)
        let writes: Vec<QueuedWrite> = write_queue.drain(..).collect();
        assert_eq!(writes.len(), 5);
        assert!(write_queue.is_empty());
    }

    // ========================================================================
    // Integration-style Tests (simulating full request flow)
    // ========================================================================

    #[test]
    fn test_write_read_consistency() {
        let backend = Arc::new(TrackingBackend::new(65536));

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        // Write patterns to multiple sectors
        let patterns: Vec<(u64, u8)> = vec![
            (0, 0xAA),
            (512, 0xBB),
            (1024, 0xCC),
            (2048, 0xDD),
            (4096, 0xEE),
        ];

        for (offset, pattern) in &patterns {
            let mut buf = vec![*pattern; 512];
            rt.block_on(async {
                backend
                    .write_vectored_at(vec![make_guard(&mut buf)], *offset)
                    .await
                    .unwrap()
            });
        }

        // Read back and verify
        for (offset, expected_pattern) in &patterns {
            let mut buf = vec![0u8; 512];
            rt.block_on(async {
                backend
                    .read_vectored_at(vec![make_guard(&mut buf)], *offset)
                    .await
                    .unwrap()
            });
            assert_eq!(
                buf,
                vec![*expected_pattern; 512],
                "Data mismatch at offset {}",
                offset
            );
        }
    }

    #[test]
    fn test_vectored_write_read() {
        let backend = Arc::new(TrackingBackend::new(4096));

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        // Write using multiple buffers (vectored I/O)
        let mut buf1 = vec![0xAA_u8; 256];
        let mut buf2 = vec![0xBB_u8; 256];
        let mut buf3 = vec![0xCC_u8; 512];

        rt.block_on(async {
            backend
                .write_vectored_at(
                    vec![
                        make_guard(&mut buf1),
                        make_guard(&mut buf2),
                        make_guard(&mut buf3),
                    ],
                    0,
                )
                .await
                .unwrap()
        });

        // Read back as a single buffer
        let mut read_buf = vec![0u8; 1024];
        rt.block_on(async {
            backend
                .read_vectored_at(vec![make_guard(&mut read_buf)], 0)
                .await
                .unwrap()
        });

        // Verify the pattern
        assert_eq!(&read_buf[0..256], &vec![0xAA_u8; 256][..]);
        assert_eq!(&read_buf[256..512], &vec![0xBB_u8; 256][..]);
        assert_eq!(&read_buf[512..1024], &vec![0xCC_u8; 512][..]);
    }

    #[test]
    fn test_overwrite() {
        let backend = Arc::new(TrackingBackend::new(4096));

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        // Write initial data
        let mut buf1 = vec![0xAA_u8; 512];
        rt.block_on(async {
            backend
                .write_vectored_at(vec![make_guard(&mut buf1)], 0)
                .await
                .unwrap()
        });

        // Overwrite with different data
        let mut buf2 = vec![0xBB_u8; 512];
        rt.block_on(async {
            backend
                .write_vectored_at(vec![make_guard(&mut buf2)], 0)
                .await
                .unwrap()
        });

        // Read back - should see the second write
        let mut read_buf = vec![0u8; 512];
        rt.block_on(async {
            backend
                .read_vectored_at(vec![make_guard(&mut read_buf)], 0)
                .await
                .unwrap()
        });

        assert_eq!(read_buf, vec![0xBB_u8; 512]);
    }

    // ========================================================================
    // process_request_async_with_metrics Tests
    // ========================================================================

    #[test]
    fn test_process_read_request() {
        let backend = Arc::new(TrackingBackend::new(4096));

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        // Pre-populate data
        {
            let mut data = backend.data.write().unwrap();
            data[0..512].fill(0xDE);
        }

        // Create a read request
        let mut buf = vec![0u8; 512];
        let request = Request::Read {
            bufs: vec![make_guard(&mut buf)],
            offset: 0,
        };

        let (status, len, req_type) =
            rt.block_on(async { process_request_async_with_metrics(&backend, request).await });

        assert_eq!(status, VIRTIO_BLK_S_OK as u8);
        assert_eq!(len, 512);
        assert!(matches!(req_type, RequestType::Read));
        assert_eq!(buf, vec![0xDE_u8; 512]);
    }

    #[test]
    fn test_process_write_request() {
        let backend = Arc::new(TrackingBackend::new(4096));

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        // Create a write request
        let mut buf = vec![0xAB_u8; 512];
        let request = Request::Write {
            bufs: vec![make_guard(&mut buf)],
            offset: 0,
        };

        let (status, len, req_type) =
            rt.block_on(async { process_request_async_with_metrics(&backend, request).await });

        assert_eq!(status, VIRTIO_BLK_S_OK as u8);
        assert_eq!(len, 512);
        assert!(matches!(req_type, RequestType::Write));

        // Verify data was written
        let data = backend.read_raw(0, 512);
        assert_eq!(data, vec![0xAB_u8; 512]);
    }

    #[test]
    fn test_process_flush_request() {
        let backend = Arc::new(TrackingBackend::new(4096));

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        let request = Request::Flush;

        let (status, len, req_type) =
            rt.block_on(async { process_request_async_with_metrics(&backend, request).await });

        assert_eq!(status, VIRTIO_BLK_S_OK as u8);
        assert_eq!(len, 0);
        assert!(matches!(req_type, RequestType::Flush));

        // Verify flush and sync were called
        let events = backend.events();
        assert!(events.contains(&OpEvent::FlushStart));
        assert!(events.contains(&OpEvent::FlushEnd));
        assert!(events.contains(&OpEvent::SyncStart));
        assert!(events.contains(&OpEvent::SyncEnd));
    }

    #[test]
    fn test_process_get_id_request() {
        let backend = Arc::new(TrackingBackend::new(4096));

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        let mut buf = vec![0u8; 64];
        let request = Request::GetId {
            buf: make_guard(&mut buf),
        };

        let (status, len, req_type) =
            rt.block_on(async { process_request_async_with_metrics(&backend, request).await });

        assert_eq!(status, VIRTIO_BLK_S_OK as u8);
        assert_eq!(len, backend.image_id.len() as u32);
        assert!(matches!(req_type, RequestType::Other));
        assert_eq!(&buf[..backend.image_id.len()], backend.image_id.as_slice());
    }

    #[test]
    fn test_process_discard_request() {
        let backend = Arc::new(TrackingBackend::new(4096));

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        // Pre-populate data
        {
            let mut data = backend.data.write().unwrap();
            data[0..1024].fill(0xFF);
        }

        let request = Request::Discard {
            offset: 256,
            len: 512,
        };

        let (status, _len, req_type) =
            rt.block_on(async { process_request_async_with_metrics(&backend, request).await });

        assert_eq!(status, VIRTIO_BLK_S_OK as u8);
        assert!(matches!(req_type, RequestType::Other));

        // Verify discarded region is zeroed
        let data = backend.read_raw(0, 1024);
        assert_eq!(&data[0..256], &vec![0xFF_u8; 256][..]);
        assert_eq!(&data[256..768], &vec![0x00_u8; 512][..]);
        assert_eq!(&data[768..1024], &vec![0xFF_u8; 256][..]);
    }

    #[test]
    fn test_process_write_zeroes_request() {
        let backend = Arc::new(TrackingBackend::new(4096));

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        // Pre-populate data
        {
            let mut data = backend.data.write().unwrap();
            data[0..1024].fill(0xFF);
        }

        let request = Request::WriteZeroes {
            offset: 128,
            len: 256,
            unmap: true,
        };

        let (status, _len, req_type) =
            rt.block_on(async { process_request_async_with_metrics(&backend, request).await });

        assert_eq!(status, VIRTIO_BLK_S_OK as u8);
        assert!(matches!(req_type, RequestType::Other));

        // Verify zeroed region
        let data = backend.read_raw(0, 1024);
        assert_eq!(&data[0..128], &vec![0xFF_u8; 128][..]);
        assert_eq!(&data[128..384], &vec![0x00_u8; 256][..]);
        assert_eq!(&data[384..1024], &vec![0xFF_u8; 640][..]);
    }

    // ========================================================================
    // Snapshot Quiesce Tests
    // ========================================================================

    use super::super::SendBoxFuture;
    use crate::legacy::DummyIrqChip;
    use crate::virtio::InterruptTransport;
    use std::sync::Condvar;
    use vm_memory::GuestAddress;

    /// Factory that wraps TrackingBackend for use with AsyncBlockWorker.
    struct TrackingBackendFactory {
        size_bytes: usize,
    }

    impl TrackingBackendFactory {
        fn new(size_bytes: usize) -> Self {
            Self { size_bytes }
        }
    }

    impl AsyncBlockBackendFactory for TrackingBackendFactory {
        fn nsectors(&self) -> u64 {
            self.size_bytes as u64 / 512
        }

        fn cache_type(&self) -> CacheType {
            CacheType::Unsafe
        }

        fn create(
            self: Box<Self>,
        ) -> SendBoxFuture<
            'static,
            std::io::Result<Arc<dyn super::super::AsyncBlockBackend + Send + Sync>>,
        > {
            Box::pin(async move {
                Ok(Arc::new(TrackingBackend::new(self.size_bytes))
                    as Arc<dyn super::super::AsyncBlockBackend + Send + Sync>)
            })
        }
    }

    /// Test that the quiesce protocol works: signal quiesce → worker acks → resume.
    #[test]
    fn test_quiesce_ack_resume() {
        let mem = vm_memory::GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let irqchip: crate::legacy::IrqChip = DummyIrqChip::new().into();
        let interrupt = InterruptTransport::new(irqchip, "test-blk".into()).unwrap();

        let queue = Queue::new(256);
        let queue_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let stop_fd = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let resync_fd = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let quiesce_fd = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let resume_fd = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();

        let shared_queue = Arc::new(Mutex::new(queue.clone()));
        let shared_generation = Arc::new(AtomicU64::new(0));
        let quiesce_ack = Arc::new((Mutex::new(false), Condvar::new()));

        let quiesce_fd_clone = quiesce_fd.try_clone().unwrap();
        let resume_fd_clone = resume_fd.try_clone().unwrap();
        let stop_fd_clone = stop_fd.try_clone().unwrap();
        let quiesce_ack_clone = quiesce_ack.clone();
        let shared_queue_clone = shared_queue.clone();

        let factory = Box::new(TrackingBackendFactory::new(4096));
        let shared_backend_state = Arc::new(Mutex::new(None));

        let worker = AsyncBlockWorker::new(
            queue,
            queue_evt,
            interrupt,
            mem,
            factory,
            stop_fd,
            resync_fd,
            shared_queue.clone(),
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
                "Worker did not ack quiesce within timeout"
            );
        }

        // Verify shared queue was updated (worker published its state)
        {
            let shared = shared_queue_clone.lock().unwrap();
            // Just verify it's accessible — the worker cloned its local queue into shared
            let _ = shared.next_avail();
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
                "Worker did not ack second quiesce within timeout"
            );
        }

        // Resume and stop
        resume_fd_clone.write(1).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        stop_fd_clone.write(1).unwrap();
    }

    // ========================================================================
    // End-to-End Snapshot/Restore Test with Real Virtio Queue I/O
    // ========================================================================

    use crate::virtio::queue::Descriptor;
    use vm_memory::Bytes;

    // Memory layout constants for virtio queue (queue size = 16)
    const TEST_QUEUE_SIZE: u16 = 16;
    const DESC_TABLE_ADDR: u64 = 0x0000; // 16*16=256 bytes, 16-byte aligned
    const AVAIL_RING_ADDR: u64 = 0x0100; // 4 + 2*16 + 2 = 38 bytes, 2-byte aligned
    const USED_RING_ADDR: u64 = 0x0200; // 4 + 8*16 + 2 = 134 bytes, 4-byte aligned
    const DATA_AREA_ADDR: u64 = 0x1000; // request headers, data, status bytes
                                        // Each request uses 0x300 bytes: 0x00=header(16), 0x10=data(512), 0x210+1=status(1)
    const REQ_STRIDE: u64 = 0x300;

    /// Write a single virtio-blk WRITE request into guest memory as a 3-descriptor chain.
    /// Returns the head descriptor index.
    fn write_blk_write_request(
        mem: &GuestMemoryMmap,
        request_idx: u16,
        sector: u64,
        fill_byte: u8,
    ) -> u16 {
        let base_desc = request_idx * 3; // each request uses 3 descriptors
        let data_base = DATA_AREA_ADDR + (request_idx as u64) * REQ_STRIDE;
        let header_addr = data_base;
        let data_addr = data_base + 0x10; // after 16-byte header
        let status_addr = data_base + 0x210; // after 512-byte data

        // Write RequestHeader into guest memory
        let header = RequestHeader {
            request_type: VIRTIO_BLK_T_OUT,
            _reserved: 0,
            sector,
        };
        mem.write_obj(header, GuestAddress(header_addr)).unwrap();

        // Write data (512 bytes filled with fill_byte)
        let data = vec![fill_byte; 512];
        mem.write_slice(&data, GuestAddress(data_addr)).unwrap();

        // Write status byte (initially 0xFF to distinguish from success)
        mem.write_obj(0xFFu8, GuestAddress(status_addr)).unwrap();

        // Write descriptor chain:
        // desc[base+0]: header, readable, NEXT
        let desc0 = Descriptor {
            addr: header_addr,
            len: 16,
            flags: 0x1, // VIRTQ_DESC_F_NEXT
            next: base_desc + 1,
        };
        mem.write_obj(
            desc0,
            GuestAddress(DESC_TABLE_ADDR + (base_desc as u64) * 16),
        )
        .unwrap();

        // desc[base+1]: data, readable, NEXT
        let desc1 = Descriptor {
            addr: data_addr,
            len: 512,
            flags: 0x1, // VIRTQ_DESC_F_NEXT
            next: base_desc + 2,
        };
        mem.write_obj(
            desc1,
            GuestAddress(DESC_TABLE_ADDR + ((base_desc + 1) as u64) * 16),
        )
        .unwrap();

        // desc[base+2]: status, writable, no NEXT
        let desc2 = Descriptor {
            addr: status_addr,
            len: 1,
            flags: 0x2, // VIRTQ_DESC_F_WRITE
            next: 0,
        };
        mem.write_obj(
            desc2,
            GuestAddress(DESC_TABLE_ADDR + ((base_desc + 2) as u64) * 16),
        )
        .unwrap();

        base_desc
    }

    /// Add a descriptor chain head to the avail ring and bump the avail idx.
    fn add_to_avail_ring(mem: &GuestMemoryMmap, avail_slot: u16, head_desc_idx: u16) {
        // Write the head descriptor index into avail ring[slot]
        let ring_entry_addr = AVAIL_RING_ADDR + 4 + 2 * (avail_slot as u64);
        mem.write_obj(head_desc_idx, GuestAddress(ring_entry_addr))
            .unwrap();

        // Bump avail idx (at avail_ring + 2)
        let new_idx: u16 = avail_slot + 1;
        mem.write_obj(new_idx, GuestAddress(AVAIL_RING_ADDR + 2))
            .unwrap();
    }

    /// Create a configured Queue pointing at the test memory layout.
    fn make_test_queue() -> Queue {
        let mut q = Queue::new(TEST_QUEUE_SIZE);
        q.size = TEST_QUEUE_SIZE;
        q.ready = true;
        q.desc_table = GuestAddress(DESC_TABLE_ADDR);
        q.avail_ring = GuestAddress(AVAIL_RING_ADDR);
        q.used_ring = GuestAddress(USED_RING_ADDR);
        q
    }

    /// Read the status byte for a given request from guest memory.
    fn read_status(mem: &GuestMemoryMmap, request_idx: u16) -> u8 {
        let status_addr = DATA_AREA_ADDR + (request_idx as u64) * REQ_STRIDE + 0x210;
        mem.read_obj::<u8>(GuestAddress(status_addr)).unwrap()
    }

    /// Full end-to-end test: submit requests → quiesce → verify queue state →
    /// simulate restore → submit more requests → verify correctness.
    #[test]
    fn test_snapshot_restore_with_real_io() {
        // 128KB guest memory
        let mem = vm_memory::GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();

        // Zero out the avail ring flags + idx
        mem.write_obj(0u16, GuestAddress(AVAIL_RING_ADDR)).unwrap(); // flags
        mem.write_obj(0u16, GuestAddress(AVAIL_RING_ADDR + 2))
            .unwrap(); // idx
                       // Zero out used ring flags + idx
        mem.write_obj(0u16, GuestAddress(USED_RING_ADDR)).unwrap(); // flags
        mem.write_obj(0u16, GuestAddress(USED_RING_ADDR + 2))
            .unwrap(); // idx

        let irqchip: crate::legacy::IrqChip = DummyIrqChip::new().into();
        let interrupt = InterruptTransport::new(irqchip, "test-blk-snap".into()).unwrap();

        let queue = make_test_queue();
        let queue_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let stop_fd = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let resync_fd = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let quiesce_fd = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let resume_fd = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();

        let shared_queue = Arc::new(Mutex::new(queue.clone()));
        let shared_generation = Arc::new(AtomicU64::new(0));
        let quiesce_ack = Arc::new((Mutex::new(false), Condvar::new()));

        let queue_evt_clone = queue_evt.try_clone().unwrap();
        let quiesce_fd_clone = quiesce_fd.try_clone().unwrap();
        let resume_fd_clone = resume_fd.try_clone().unwrap();
        let stop_fd_clone = stop_fd.try_clone().unwrap();
        let resync_fd_clone = resync_fd.try_clone().unwrap();
        let quiesce_ack_clone = quiesce_ack.clone();
        let shared_queue_clone = shared_queue.clone();
        let shared_generation_clone = shared_generation.clone();

        // 8KB disk (16 sectors)
        let factory = Box::new(TrackingBackendFactory::new(8192));
        let shared_backend_state = Arc::new(Mutex::new(None));

        let worker = AsyncBlockWorker::new(
            queue,
            queue_evt,
            interrupt,
            mem.clone(),
            factory,
            stop_fd,
            resync_fd,
            shared_queue.clone(),
            shared_generation.clone(),
            quiesce_fd,
            resume_fd,
            quiesce_ack.clone(),
            shared_backend_state,
        );

        let _handle = worker.run();

        // Give the worker time to start
        std::thread::sleep(std::time::Duration::from_millis(200));

        // ============================================================
        // Phase 1: Submit 2 write requests (sectors 0 and 1)
        // ============================================================

        // Request 0: write 0xAA to sector 0
        let head0 = write_blk_write_request(&mem, 0, 0, 0xAA);
        add_to_avail_ring(&mem, 0, head0);

        // Request 1: write 0xBB to sector 1
        let head1 = write_blk_write_request(&mem, 1, 1, 0xBB);
        add_to_avail_ring(&mem, 1, head1);

        // Signal the queue event to wake the worker
        queue_evt_clone.write(1).unwrap();

        // Wait for both requests to complete (poll status bytes)
        for attempt in 0..100 {
            let s0 = read_status(&mem, 0);
            let s1 = read_status(&mem, 1);
            if s0 == VIRTIO_BLK_S_OK as u8 && s1 == VIRTIO_BLK_S_OK as u8 {
                break;
            }
            if attempt == 99 {
                panic!(
                    "Requests did not complete in time. status[0]={}, status[1]={}",
                    s0, s1
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        // ============================================================
        // Phase 2: Quiesce and verify queue state
        // ============================================================

        {
            let (lock, _) = &*quiesce_ack_clone;
            *lock.lock().unwrap() = false;
        }
        quiesce_fd_clone.write(1).unwrap();

        // Wait for ack
        {
            let (lock, cvar) = &*quiesce_ack_clone;
            let guard = lock.lock().unwrap();
            let (guard, timeout_result) = cvar
                .wait_timeout_while(guard, std::time::Duration::from_secs(5), |acked| !*acked)
                .unwrap();
            assert!(
                *guard && !timeout_result.timed_out(),
                "Worker did not ack quiesce within timeout"
            );
        }

        // Read the published queue state
        let snapshot_queue = {
            let shared = shared_queue_clone.lock().unwrap();
            shared.clone()
        };

        // After processing 2 requests:
        // next_avail should be 2 (popped 2 from avail ring)
        // next_used should be 2 (added 2 to used ring)
        assert_eq!(
            snapshot_queue.next_avail().0,
            2,
            "Expected next_avail=2 after 2 requests, got {}",
            snapshot_queue.next_avail().0
        );
        assert_eq!(
            snapshot_queue.next_used().0,
            2,
            "Expected next_used=2 after 2 requests, got {}",
            snapshot_queue.next_used().0
        );

        // ============================================================
        // Phase 3: Simulate snapshot/restore
        // ============================================================
        // Save the queue state (this is what the snapshot would capture)
        let saved_next_avail = snapshot_queue.next_avail().0;
        let saved_next_used = snapshot_queue.next_used().0;

        // Resume the worker (simulates abort_snapshot_quiesce)
        {
            let (lock, _) = &*quiesce_ack_clone;
            *lock.lock().unwrap() = false;
        }
        resume_fd_clone.write(1).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Now simulate restore: push the saved queue state into the shared queue
        // and signal resync (this is what post_snapshot_restore does)
        {
            let mut shared = shared_queue_clone.lock().unwrap();
            shared.set_next_avail(saved_next_avail);
            shared.set_next_used(saved_next_used);
        }
        shared_generation_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        resync_fd_clone.write(1).unwrap();

        // Give worker time to apply the resync
        std::thread::sleep(std::time::Duration::from_millis(100));

        // ============================================================
        // Phase 4: Submit 2 more write requests (sectors 2 and 3)
        // ============================================================

        // Request 2: write 0xCC to sector 2
        let head2 = write_blk_write_request(&mem, 2, 2, 0xCC);
        add_to_avail_ring(&mem, 2, head2);

        // Request 3: write 0xDD to sector 3
        let head3 = write_blk_write_request(&mem, 3, 3, 0xDD);
        add_to_avail_ring(&mem, 3, head3);

        // Signal the queue
        queue_evt_clone.write(1).unwrap();

        // Wait for requests 2 and 3 to complete
        for attempt in 0..100 {
            let s2 = read_status(&mem, 2);
            let s3 = read_status(&mem, 3);
            if s2 == VIRTIO_BLK_S_OK as u8 && s3 == VIRTIO_BLK_S_OK as u8 {
                break;
            }
            if attempt == 99 {
                panic!(
                    "Post-restore requests did not complete. status[2]={}, status[3]={}",
                    s2, s3
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        // ============================================================
        // Phase 5: Quiesce again and verify final queue state
        // ============================================================

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
                "Worker did not ack second quiesce within timeout"
            );
        }

        let final_queue = {
            let shared = shared_queue_clone.lock().unwrap();
            shared.clone()
        };

        // After restore at (2,2) and processing 2 more requests:
        // next_avail should be 4 (2 from restore + 2 new)
        // next_used should be 4 (2 from restore + 2 new)
        assert_eq!(
            final_queue.next_avail().0,
            4,
            "Expected next_avail=4 after restore + 2 more requests, got {}",
            final_queue.next_avail().0
        );
        assert_eq!(
            final_queue.next_used().0,
            4,
            "Expected next_used=4 after restore + 2 more requests, got {}",
            final_queue.next_used().0
        );

        // ============================================================
        // Cleanup
        // ============================================================
        resume_fd_clone.write(1).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        stop_fd_clone.write(1).unwrap();
    }

    // ========================================================================
    // Regression Test: Quiesce Drains In-Flight Ops Before Memory Overwrite
    // ========================================================================

    /// Factory that wraps a pre-existing Arc<TrackingBackend> so the test can
    /// control write delays and inspect backend state externally.
    struct SharedBackendFactory {
        backend: Arc<TrackingBackend>,
    }

    impl AsyncBlockBackendFactory for SharedBackendFactory {
        fn nsectors(&self) -> u64 {
            self.backend.nsectors()
        }

        fn cache_type(&self) -> CacheType {
            CacheType::Writeback
        }

        fn create(
            self: Box<Self>,
        ) -> SendBoxFuture<
            'static,
            std::io::Result<Arc<dyn super::super::AsyncBlockBackend + Send + Sync>>,
        > {
            let backend = self.backend.clone();
            Box::pin(async move {
                Ok(backend as Arc<dyn super::super::AsyncBlockBackend + Send + Sync>)
            })
        }
    }

    /// Regression test for the snapshot-restore race condition:
    ///
    /// Before the fix, `restore_snapshot` would overwrite guest RAM via
    /// `load_memory` while async workers were still running. If a worker held
    /// a VolatileSliceGuard pointing into guest RAM and was mid-I/O, it would
    /// read stale data from the overwritten memory and/or write stale used-ring
    /// entries, corrupting the restored VM state.
    ///
    /// This test verifies that:
    /// 1. In-flight ops are fully drained before quiesce acks
    /// 2. After quiesce, guest memory can be safely overwritten
    /// 3. The overwritten memory is not corrupted by the worker
    #[test]
    fn test_quiesce_drains_inflight_before_memory_overwrite() {
        // 128KB guest memory
        let mem = vm_memory::GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();

        // Zero out queue rings
        mem.write_obj(0u16, GuestAddress(AVAIL_RING_ADDR)).unwrap();
        mem.write_obj(0u16, GuestAddress(AVAIL_RING_ADDR + 2))
            .unwrap();
        mem.write_obj(0u16, GuestAddress(USED_RING_ADDR)).unwrap();
        mem.write_obj(0u16, GuestAddress(USED_RING_ADDR + 2))
            .unwrap();

        let irqchip: crate::legacy::IrqChip = DummyIrqChip::new().into();
        let interrupt = InterruptTransport::new(irqchip, "test-blk-race".into()).unwrap();

        let queue = make_test_queue();
        let queue_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let stop_fd = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let resync_fd = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let quiesce_fd = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let resume_fd = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();

        let shared_queue = Arc::new(Mutex::new(queue.clone()));
        let shared_generation = Arc::new(AtomicU64::new(0));
        let quiesce_ack = Arc::new((Mutex::new(false), Condvar::new()));

        let queue_evt_clone = queue_evt.try_clone().unwrap();
        let quiesce_fd_clone = quiesce_fd.try_clone().unwrap();
        let resume_fd_clone = resume_fd.try_clone().unwrap();
        let stop_fd_clone = stop_fd.try_clone().unwrap();
        let quiesce_ack_clone = quiesce_ack.clone();

        // Create a shared backend with a 500ms write delay to ensure the
        // write is still in-flight when we trigger quiesce.
        let backend = Arc::new(TrackingBackend::new(8192));
        backend.set_write_delay(500);

        let factory = Box::new(SharedBackendFactory {
            backend: backend.clone(),
        });
        let shared_backend_state = Arc::new(Mutex::new(None));

        let worker = AsyncBlockWorker::new(
            queue,
            queue_evt,
            interrupt,
            mem.clone(),
            factory,
            stop_fd,
            resync_fd,
            shared_queue.clone(),
            shared_generation.clone(),
            quiesce_fd,
            resume_fd,
            quiesce_ack.clone(),
            shared_backend_state,
        );

        let _handle = worker.run();

        // Give the worker time to start and create backend
        std::thread::sleep(std::time::Duration::from_millis(200));

        // === Step 1: Submit a write request that will be slow (500ms delay) ===
        let head0 = write_blk_write_request(&mem, 0, 0, 0xAA);
        add_to_avail_ring(&mem, 0, head0);
        queue_evt_clone.write(1).unwrap();

        // Give the worker just enough time to pick up the request (but NOT
        // enough for the 500ms write to complete).
        std::thread::sleep(std::time::Duration::from_millis(100));

        // === Step 2: Trigger quiesce while write is in-flight ===
        {
            let (lock, _) = &*quiesce_ack_clone;
            *lock.lock().unwrap() = false;
        }
        quiesce_fd_clone.write(1).unwrap();

        // The quiesce should NOT ack until the in-flight write drains.
        // Wait for the ack — it should arrive after ~400ms more (when the
        // 500ms write delay completes).
        let quiesce_start = std::time::Instant::now();
        {
            let (lock, cvar) = &*quiesce_ack_clone;
            let guard = lock.lock().unwrap();
            let (guard, timeout_result) = cvar
                .wait_timeout_while(guard, std::time::Duration::from_secs(10), |acked| !*acked)
                .unwrap();
            assert!(
                *guard && !timeout_result.timed_out(),
                "Worker did not ack quiesce within timeout"
            );
        }
        let quiesce_duration = quiesce_start.elapsed();

        // Verify the in-flight write completed (it was drained before ack).
        assert_eq!(
            read_status(&mem, 0),
            VIRTIO_BLK_S_OK as u8,
            "In-flight write should have completed before quiesce ack"
        );

        // The quiesce ack should have taken at least ~300ms (remaining delay),
        // proving it waited for the in-flight write to drain.
        assert!(
            quiesce_duration >= std::time::Duration::from_millis(200),
            "Quiesce acked too fast ({:?}), likely didn't drain in-flight ops",
            quiesce_duration
        );

        // Verify the backend received the write data correctly.
        let written_data = backend.read_raw(0, 512);
        assert!(
            written_data.iter().all(|&b| b == 0xAA),
            "Backend should have received the 0xAA write"
        );

        // === Step 3: Overwrite guest memory (simulating load_memory) ===
        // Write a sentinel pattern over the data area where the request was.
        let sentinel = vec![0x55u8; 512];
        let data_addr = DATA_AREA_ADDR + 0x10; // data portion of request 0
        mem.write_slice(&sentinel, GuestAddress(data_addr)).unwrap();

        // Also overwrite the used ring area to simulate a full memory restore.
        mem.write_obj(0u16, GuestAddress(USED_RING_ADDR)).unwrap();
        mem.write_obj(0u16, GuestAddress(USED_RING_ADDR + 2))
            .unwrap();

        // === Step 4: Resume worker and verify memory is not corrupted ===
        {
            let (lock, _) = &*quiesce_ack_clone;
            *lock.lock().unwrap() = false;
        }
        resume_fd_clone.write(1).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));

        // The sentinel data we wrote should still be intact — the worker
        // should NOT have written anything back into guest memory after resume
        // (since there are no new requests pending).
        let mut readback = vec![0u8; 512];
        mem.read_slice(&mut readback, GuestAddress(data_addr))
            .unwrap();
        assert_eq!(
            readback, sentinel,
            "Guest memory was corrupted after restore! Worker wrote stale data."
        );

        // Cleanup
        stop_fd_clone.write(1).unwrap();
    }

    // ========================================================================
    // Regression Test: Quiesce Drains In-Flight READS Before Ack
    // ========================================================================

    /// Write a virtio-blk READ request (VIRTIO_BLK_T_IN) descriptor chain.
    /// Returns the head descriptor index.
    fn write_blk_read_request(mem: &GuestMemoryMmap, request_idx: u16, sector: u64) -> u16 {
        let base_desc = request_idx * 3;
        let data_base = DATA_AREA_ADDR + (request_idx as u64) * REQ_STRIDE;
        let header_addr = data_base;
        let data_addr = data_base + 0x10;
        let status_addr = data_base + 0x210;

        // Write RequestHeader (VIRTIO_BLK_T_IN = read)
        let header = RequestHeader {
            request_type: VIRTIO_BLK_T_IN,
            _reserved: 0,
            sector,
        };
        mem.write_obj(header, GuestAddress(header_addr)).unwrap();

        // Zero out data buffer (device will write read data here)
        let data = vec![0u8; 512];
        mem.write_slice(&data, GuestAddress(data_addr)).unwrap();

        // Status byte initially 0xFF
        mem.write_obj(0xFFu8, GuestAddress(status_addr)).unwrap();

        // desc[0]: header, readable, NEXT
        let desc0 = Descriptor {
            addr: header_addr,
            len: 16,
            flags: 0x1, // VIRTQ_DESC_F_NEXT
            next: base_desc + 1,
        };
        mem.write_obj(
            desc0,
            GuestAddress(DESC_TABLE_ADDR + (base_desc as u64) * 16),
        )
        .unwrap();

        // desc[1]: data buffer, WRITABLE + NEXT (device writes read data here)
        let desc1 = Descriptor {
            addr: data_addr,
            len: 512,
            flags: 0x3, // VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE
            next: base_desc + 2,
        };
        mem.write_obj(
            desc1,
            GuestAddress(DESC_TABLE_ADDR + ((base_desc + 1) as u64) * 16),
        )
        .unwrap();

        // desc[2]: status, writable, no NEXT
        let desc2 = Descriptor {
            addr: status_addr,
            len: 1,
            flags: 0x2, // VIRTQ_DESC_F_WRITE
            next: 0,
        };
        mem.write_obj(
            desc2,
            GuestAddress(DESC_TABLE_ADDR + ((base_desc + 2) as u64) * 16),
        )
        .unwrap();

        base_desc
    }

    /// Regression test for the spawn_local read task drain bug:
    ///
    /// Read tasks are dispatched via tokio::task::spawn_local and hold raw
    /// pointers (VolatileSliceGuard + status_ptr) into guest memory. Before
    /// the fix, the quiesce branch only did try_recv() (non-blocking) to
    /// drain read completions. Since try_recv() never yields to the tokio
    /// runtime, spawned read tasks never got polled to completion. The worker
    /// would park on resume_fd.await while in-flight reads still held pointers
    /// into guest RAM. When load_memory overwrote guest RAM during restore,
    /// the completing read tasks would write_volatile stale data, corrupting
    /// the restored state.
    ///
    /// This test verifies that:
    /// 1. In-flight reads are fully drained (awaited) before quiesce acks
    /// 2. After quiesce + memory overwrite, no stale read writes corrupt RAM
    #[test]
    fn test_quiesce_drains_inflight_reads_before_ack() {
        let mem = vm_memory::GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();

        // Zero out queue rings
        mem.write_obj(0u16, GuestAddress(AVAIL_RING_ADDR)).unwrap();
        mem.write_obj(0u16, GuestAddress(AVAIL_RING_ADDR + 2))
            .unwrap();
        mem.write_obj(0u16, GuestAddress(USED_RING_ADDR)).unwrap();
        mem.write_obj(0u16, GuestAddress(USED_RING_ADDR + 2))
            .unwrap();

        let irqchip: crate::legacy::IrqChip = DummyIrqChip::new().into();
        let interrupt = InterruptTransport::new(irqchip, "test-blk-read-drain".into()).unwrap();

        let queue = make_test_queue();
        let queue_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let stop_fd = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let resync_fd = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let quiesce_fd = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let resume_fd = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();

        let shared_queue = Arc::new(Mutex::new(queue.clone()));
        let shared_generation = Arc::new(AtomicU64::new(0));
        let quiesce_ack = Arc::new((Mutex::new(false), Condvar::new()));

        let queue_evt_clone = queue_evt.try_clone().unwrap();
        let quiesce_fd_clone = quiesce_fd.try_clone().unwrap();
        let resume_fd_clone = resume_fd.try_clone().unwrap();
        let stop_fd_clone = stop_fd.try_clone().unwrap();
        let quiesce_ack_clone = quiesce_ack.clone();

        // Create a backend with a 300ms READ delay so the read is in-flight
        // when we trigger quiesce. Pre-populate sector 0 with 0xBB.
        let backend = Arc::new(TrackingBackend::new(8192));
        backend.set_read_delay(300);
        {
            let mut data = backend.data.write().unwrap();
            data[..512].fill(0xBB);
        }

        let factory = Box::new(SharedBackendFactory {
            backend: backend.clone(),
        });
        let shared_backend_state = Arc::new(Mutex::new(None));

        let worker = AsyncBlockWorker::new(
            queue,
            queue_evt,
            interrupt,
            mem.clone(),
            factory,
            stop_fd,
            resync_fd,
            shared_queue.clone(),
            shared_generation.clone(),
            quiesce_fd,
            resume_fd,
            quiesce_ack.clone(),
            shared_backend_state,
        );

        let _handle = worker.run();
        std::thread::sleep(std::time::Duration::from_millis(200));

        // === Step 1: Submit a read request (will take 500ms due to delay) ===
        let head0 = write_blk_read_request(&mem, 0, 0);
        add_to_avail_ring(&mem, 0, head0);
        queue_evt_clone.write(1).unwrap();

        // Give the worker time to dispatch the read (but not enough for
        // the 300ms delay to complete).
        std::thread::sleep(std::time::Duration::from_millis(100));

        // === Step 2: Trigger quiesce while read is in-flight ===
        {
            let (lock, _) = &*quiesce_ack_clone;
            *lock.lock().unwrap() = false;
        }
        quiesce_fd_clone.write(1).unwrap();

        // The quiesce should NOT ack until the spawned read task completes.
        let quiesce_start = std::time::Instant::now();
        {
            let (lock, cvar) = &*quiesce_ack_clone;
            let guard = lock.lock().unwrap();
            let (guard, timeout_result) = cvar
                .wait_timeout_while(guard, std::time::Duration::from_secs(10), |acked| !*acked)
                .unwrap();
            assert!(
                *guard && !timeout_result.timed_out(),
                "Worker did not ack quiesce within timeout"
            );
        }
        let quiesce_duration = quiesce_start.elapsed();

        // The read should have completed before the quiesce ack.
        assert_eq!(
            read_status(&mem, 0),
            VIRTIO_BLK_S_OK as u8,
            "In-flight read should have completed before quiesce ack"
        );

        // Verify the read data was written to guest memory.
        let data_addr = DATA_AREA_ADDR + 0x10;
        let mut readback = vec![0u8; 512];
        mem.read_slice(&mut readback, GuestAddress(data_addr))
            .unwrap();
        assert!(
            readback.iter().all(|&b| b == 0xBB),
            "Read data should have been written to guest memory before quiesce"
        );

        // The quiesce should have waited for the read (~200ms remaining delay).
        // Use a generous lower bound to avoid timing flakes.
        assert!(
            quiesce_duration >= std::time::Duration::from_millis(100),
            "Quiesce acked too fast ({:?}), likely didn't drain in-flight reads",
            quiesce_duration
        );

        // === Step 3: Overwrite guest memory (simulating load_memory) ===
        let sentinel = vec![0x55u8; 512];
        mem.write_slice(&sentinel, GuestAddress(data_addr)).unwrap();
        mem.write_obj(0u16, GuestAddress(USED_RING_ADDR)).unwrap();
        mem.write_obj(0u16, GuestAddress(USED_RING_ADDR + 2))
            .unwrap();

        // === Step 4: Resume and verify no corruption ===
        {
            let (lock, _) = &*quiesce_ack_clone;
            *lock.lock().unwrap() = false;
        }
        resume_fd_clone.write(1).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Sentinel should be intact — no stale read writes after resume.
        let mut final_readback = vec![0u8; 512];
        mem.read_slice(&mut final_readback, GuestAddress(data_addr))
            .unwrap();
        assert_eq!(
            final_readback, sentinel,
            "Guest memory was corrupted after restore! Stale read wrote data."
        );

        // Cleanup
        stop_fd_clone.write(1).unwrap();
    }
}
