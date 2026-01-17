use std::collections::{HashMap, VecDeque};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use log::{debug, error, info, trace};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, LocalSet};
use utils::eventfd::EventFd;
use virtio_bindings::virtio_blk::*;
use vm_memory::{ByteValued, GuestMemoryMmap};

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
    ) -> Self {
        Self {
            queue,
            queue_evt,
            interrupt,
            mem,
            factory,
            stop_fd,
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
        log::debug!("async block worker: work_async starting");

        // Destructure self so we can consume the factory while keeping other fields
        let AsyncBlockWorker {
            mut queue,
            queue_evt,
            interrupt,
            mem,
            factory,
            stop_fd,
        } = self;

        // Create the backend from the factory (inside this runtime)
        log::debug!("async block worker: creating backend from factory");
        let disk = match factory.create().await {
            Ok(disk) => disk,
            Err(e) => {
                error!("async block worker: failed to create backend: {e}");
                return;
            }
        };
        log::debug!("async block worker: backend created successfully");

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

        let async_queue_fd =
            AsyncFd::new(queue_fd_dup).expect("failed to create AsyncFd for queue");
        let async_stop_fd = AsyncFd::new(stop_fd_dup).expect("failed to create AsyncFd for stop");

        log::debug!("async block worker: AsyncFd configured, entering main loop");

        loop {
            tokio::select! {
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
                                    trace!("async block worker: queue event received");
                                    // Pop and parse all available requests
                                    let requests = pop_and_parse_requests(&mut queue, &mem);

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

    if queue.needs_notification(mem).unwrap() {
        if let Err(e) = interrupt.try_signal_used_queue() {
            error!("error signalling queue: {e:?}");
        }
    }
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
                write_delay_ms: AtomicU64::new(0),
                flush_delay_ms: AtomicU64::new(0),
                writes_in_progress: AtomicUsize::new(0),
                writes_done: Notify::new(),
                image_id: b"test-tracking-disk".to_vec(),
            }
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
}
