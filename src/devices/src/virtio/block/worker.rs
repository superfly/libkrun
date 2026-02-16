use crate::virtio::descriptor_utils::{Reader, Writer};
use crate::virtio::file_traits::BlockBackendAdapter;

use super::super::Queue;
use super::{BlockBackend, CacheType};

use crate::virtio::InterruptTransport;
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::result;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use virtio_bindings::virtio_blk::*;
use vm_memory::{Address, ByteValued, Bytes, GuestMemoryMmap};

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
///
/// A request header contains the following fields:
///   * request_type: an u32 value mapping to a read, write or flush operation.
///   * reserved: 32 bits are reserved for future extensions of the Virtio Spec.
///   * sector: an u64 value representing the offset where a read/write is to occur.
///
/// The header simplifies reading the request from memory as all request follow
/// the same memory layout.
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

pub struct BlockWorker<B: BlockBackend> {
    queue: Queue,
    queue_evt: EventFd,
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    disk: B,
    stop_fd: EventFd,
    shared_queue: Arc<Mutex<Queue>>,
    shared_generation: Arc<AtomicU64>,
    applied_generation: u64,
    resync_fd: EventFd,
    quiesce_fd: EventFd,
    resume_fd: EventFd,
    quiesce_ack: Arc<(Mutex<bool>, Condvar)>,
}

impl<B: BlockBackend + 'static> BlockWorker<B> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        queue: Queue,
        queue_evt: EventFd,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        disk: B,
        stop_fd: EventFd,
        shared_queue: Arc<Mutex<Queue>>,
        shared_generation: Arc<AtomicU64>,
        resync_fd: EventFd,
        quiesce_fd: EventFd,
        resume_fd: EventFd,
        quiesce_ack: Arc<(Mutex<bool>, Condvar)>,
    ) -> Self {
        let applied_generation = shared_generation.load(Ordering::Acquire);
        Self {
            queue,
            queue_evt,
            interrupt,
            mem,
            disk,
            stop_fd,
            shared_queue,
            shared_generation,
            applied_generation,
            resync_fd,
            quiesce_fd,
            resume_fd,
            quiesce_ack,
        }
    }

    pub fn run(self) -> thread::JoinHandle<()> {
        thread::Builder::new()
            .name("block worker".into())
            .spawn(|| self.work())
            .unwrap()
    }

    fn work(mut self) {
        let virtq_ev_fd = self.queue_evt.as_raw_fd();
        let stop_ev_fd = self.stop_fd.as_raw_fd();
        let resync_ev_fd = self.resync_fd.as_raw_fd();
        let quiesce_ev_fd = self.quiesce_fd.as_raw_fd();

        let worker_nsectors = self.disk.nsectors();
        let mut total_queue_events: u64 = 0;
        let mut total_requests: u64 = 0;

        log::warn!(
            "sync block worker [ns={}]: starting, queue ready={} avail={} used={}",
            worker_nsectors,
            self.queue.ready,
            self.queue.next_avail().0,
            self.queue.next_used().0,
        );

        let epoll = Epoll::new().unwrap();

        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_ev_fd as u64),
        );

        let _ = epoll.ctl(
            ControlOperation::Add,
            stop_ev_fd,
            &EpollEvent::new(EventSet::IN, stop_ev_fd as u64),
        );

        let _ = epoll.ctl(
            ControlOperation::Add,
            resync_ev_fd,
            &EpollEvent::new(EventSet::IN, resync_ev_fd as u64),
        );

        let _ = epoll.ctl(
            ControlOperation::Add,
            quiesce_ev_fd,
            &EpollEvent::new(EventSet::IN, quiesce_ev_fd as u64),
        );

        loop {
            let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
            match epoll.wait(epoll_events.len(), -1, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for event in &epoll_events[0..ev_cnt] {
                        let source = event.fd();
                        let event_set = event.event_set();
                        match event_set {
                            EventSet::IN if source == virtq_ev_fd => {
                                total_queue_events += 1;
                                log::warn!(
                                    "sync block worker [ns={}]: queue event #{} avail={} used={}",
                                    worker_nsectors,
                                    total_queue_events,
                                    self.queue.next_avail().0,
                                    self.queue.next_used().0,
                                );
                                let before = total_requests;
                                self.process_queue_event_counted(&mut total_requests);
                                let processed = total_requests - before;
                                log::warn!(
                                    "sync block worker [ns={}]: queue event #{} done, processed {} requests (total={})",
                                    worker_nsectors,
                                    total_queue_events,
                                    processed,
                                    total_requests,
                                );
                            }
                            EventSet::IN if source == resync_ev_fd => {
                                let _ = self.resync_fd.read();
                                log::warn!(
                                    "sync block worker [ns={}]: resync event, before: avail={} used={}",
                                    worker_nsectors,
                                    self.queue.next_avail().0,
                                    self.queue.next_used().0,
                                );
                                self.apply_shared_queue_state();
                                log::warn!(
                                    "sync block worker [ns={}]: resync done, after: avail={} used={}",
                                    worker_nsectors,
                                    self.queue.next_avail().0,
                                    self.queue.next_used().0,
                                );
                            }
                            EventSet::IN if source == quiesce_ev_fd => {
                                log::warn!("sync block worker [ns={}]: quiesce event", worker_nsectors);
                                let _ = self.quiesce_fd.read();
                                self.handle_quiesce();
                                log::warn!("sync block worker [ns={}]: resumed after quiesce", worker_nsectors);
                            }
                            EventSet::IN if source == stop_ev_fd => {
                                log::warn!("sync block worker [ns={}]: stopping", worker_nsectors);
                                let _ = self.stop_fd.read();
                                return;
                            }
                            _ => {
                                log::warn!(
                                    "sync block worker [ns={}]: unknown event: {event_set:?} from fd: {source:?}",
                                    worker_nsectors,
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    log::warn!("sync block worker [ns={}]: epoll error: {e}", worker_nsectors);
                }
            }
        }
    }

    fn handle_quiesce(&mut self) {
        // Publish current queue state so sync_queues_for_snapshot captures reality.
        if let Ok(mut shared) = self.shared_queue.lock() {
            *shared = self.queue.clone();
        }

        // Signal the device that we're quiesced.
        let (lock, cvar) = &*self.quiesce_ack;
        {
            let mut acked = lock.lock().unwrap();
            *acked = true;
            cvar.notify_one();
        }

        // Park until resume_fd is signalled.
        let _ = self.resume_fd.read();
    }

    fn apply_shared_queue_state(&mut self) {
        let generation = self.shared_generation.load(Ordering::Acquire);
        if generation == self.applied_generation {
            return;
        }

        if let Ok(shared) = self.shared_queue.lock() {
            self.queue = shared.clone();

            if self.queue.ready {
                if let Some(used_idx_addr) = self.queue.used_ring.checked_add(2) {
                    if let Ok(used_idx) = self.mem.read_obj::<u16>(used_idx_addr) {
                        self.queue.set_next_used(used_idx);
                    }
                }
                if let Some(avail_idx_addr) = self.queue.avail_ring.checked_add(2) {
                    if let Ok(avail_idx) = self.mem.read_obj::<u16>(avail_idx_addr) {
                        if self.queue.next_avail().0 > avail_idx {
                            self.queue.set_next_avail(avail_idx);
                        }
                    }
                }
            }

            self.applied_generation = generation;
        }
    }

    fn process_queue_event_counted(&mut self, total_requests: &mut u64) {
        if let Err(e) = self.queue_evt.read() {
            error!("Failed to get queue event: {e:?}");
        } else {
            self.process_virtio_queues_counted(total_requests);
        }
    }

    fn process_queue_event(&mut self) {
        let mut dummy = 0u64;
        self.process_queue_event_counted(&mut dummy);
    }

    /// Process device virtio queue(s).
    fn process_virtio_queues_counted(&mut self, total_requests: &mut u64) {
        let mem = self.mem.clone();
        loop {
            self.queue.disable_notification(&mem).unwrap();

            self.process_queue_counted(&mem, total_requests);

            if !self.queue.enable_notification(&mem).unwrap() {
                break;
            }
        }
    }

    fn process_queue_counted(&mut self, mem: &GuestMemoryMmap, total_requests: &mut u64) {
        let worker_nsectors = self.disk.nsectors();
        while let Some(head) = self.queue.pop(mem) {
            *total_requests += 1;
            let mut reader = match Reader::new(mem, head.clone()) {
                Ok(r) => r,
                Err(e) => {
                    error!("invalid descriptor chain: {e:?}");
                    continue;
                }
            };
            let mut writer = match Writer::new(mem, head.clone()) {
                Ok(r) => r,
                Err(e) => {
                    error!("invalid descriptor chain: {e:?}");
                    continue;
                }
            };
            let request_header: RequestHeader = match reader.read_obj() {
                Ok(h) => h,
                Err(e) => {
                    error!("invalid request header: {e:?}");
                    continue;
                }
            };

            let req_type = request_header.request_type;
            let req_sector = request_header.sector;
            let req_type_str = match req_type {
                VIRTIO_BLK_T_IN => "READ",
                VIRTIO_BLK_T_OUT => "WRITE",
                VIRTIO_BLK_T_FLUSH => "FLUSH",
                VIRTIO_BLK_T_GET_ID => "GET_ID",
                VIRTIO_BLK_T_DISCARD => "DISCARD",
                VIRTIO_BLK_T_WRITE_ZEROES => "WRITE_ZEROES",
                _ => "UNKNOWN",
            };

            let (status, len): (u8, usize) =
                match self.process_request(request_header, &mut reader, &mut writer) {
                    Ok(l) => (VIRTIO_BLK_S_OK.try_into().unwrap(), l),
                    Err(e) => {
                        log::warn!(
                            "sync block worker [ns={}]: request #{} {} sector={} ERROR: {e:?}",
                            worker_nsectors, total_requests, req_type_str, req_sector,
                        );
                        (VIRTIO_BLK_S_IOERR.try_into().unwrap(), 0)
                    }
                };

            if let Err(e) = writer.write_obj(status) {
                error!("Failed to write virtio block status: {e:?}")
            }

            if let Err(e) = self.queue.add_used(mem, head.index, len as u32) {
                error!("failed to add used elements to the queue: {e:?}");
            }

            if self.queue.needs_notification(mem).unwrap() {
                if let Err(e) = self.interrupt.try_signal_used_queue() {
                    error!("error signalling queue: {e:?}");
                }
            }
        }
    }

    fn process_request(
        &mut self,
        request_header: RequestHeader,
        reader: &mut Reader,
        writer: &mut Writer,
    ) -> result::Result<usize, RequestError> {
        match request_header.request_type {
            VIRTIO_BLK_T_IN => {
                let data_len = writer.available_bytes() - 1;
                if !data_len.is_multiple_of(512) {
                    Err(RequestError::InvalidDataLength)
                } else {
                    writer
                        .write_from_at(
                            BlockBackendAdapter(&self.disk),
                            data_len,
                            request_header.sector * 512,
                        )
                        .map_err(RequestError::WritingToDescriptor)
                }
            }
            VIRTIO_BLK_T_OUT => {
                let data_len = reader.available_bytes();
                if !data_len.is_multiple_of(512) {
                    Err(RequestError::InvalidDataLength)
                } else {
                    reader
                        .read_to_at(
                            BlockBackendAdapter(&self.disk),
                            data_len,
                            request_header.sector * 512,
                        )
                        .map_err(RequestError::ReadingFromDescriptor)
                }
            }
            VIRTIO_BLK_T_FLUSH => match self.disk.cache_type() {
                CacheType::Writeback => {
                    log::warn!("sync block worker [ns={}]: FLUSH start", self.disk.nsectors());
                    self.disk.flush().map_err(RequestError::FlushingToDisk)?;
                    self.disk.sync().map_err(RequestError::FlushingToDisk)?;
                    log::warn!("sync block worker [ns={}]: FLUSH done", self.disk.nsectors());
                    Ok(0)
                }
                CacheType::Unsafe => Ok(0),
            },
            VIRTIO_BLK_T_GET_ID => {
                let data_len = writer.available_bytes();
                let disk_id = self.disk.image_id();
                if data_len < disk_id.len() {
                    Err(RequestError::InvalidDataLength)
                } else {
                    writer
                        .write_all(disk_id)
                        .map_err(RequestError::WritingToDescriptor)?;
                    Ok(disk_id.len())
                }
            }
            VIRTIO_BLK_T_DISCARD => {
                let discard_write_data: DiscardWriteData = reader
                    .read_obj()
                    .map_err(RequestError::ReadingFromDescriptor)?;
                self.disk
                    .discard(
                        discard_write_data.sector * 512,
                        discard_write_data.num_sectors as u64 * 512,
                    )
                    .map_err(RequestError::Discarding)?;
                Ok(0)
            }
            VIRTIO_BLK_T_WRITE_ZEROES => {
                let discard_write_data: DiscardWriteData = reader
                    .read_obj()
                    .map_err(RequestError::ReadingFromDescriptor)?;
                let unmap = (discard_write_data.flags & VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP) != 0;
                self.disk
                    .write_zeroes(
                        discard_write_data.sector * 512,
                        discard_write_data.num_sectors as u64 * 512,
                        unmap,
                    )
                    .map_err(RequestError::WritingZeroes)?;
                Ok(0)
            }
            _ => Err(RequestError::UnknownRequest),
        }
    }
}
