use crate::legacy::IrqChip;
// use crate::virtio::net::passt::Passt;
use crate::virtio::net::{MAX_BUFFER_SIZE, QUEUE_SIZE, RX_INDEX, TX_INDEX};
use crate::virtio::{Queue, VIRTIO_MMIO_INT_VRING};
use crate::Error as DeviceError;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use net_proxy::gvproxy::Gvproxy;

use super::device::{FrontendError, RxError, TxError, VirtioNetBackend};
use net_proxy::backend::{NetBackend, ReadError, WriteError};

use std::os::fd::AsRawFd;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::{cmp, mem, result};
use std::{io, thread};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::{EventFd, EFD_NONBLOCK};
use virtio_bindings::virtio_net::virtio_net_hdr_v1;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

fn vnet_hdr_len() -> usize {
    mem::size_of::<virtio_net_hdr_v1>()
}

// This initializes to all 0 the virtio_net_hdr part of a buf and return the length of the header
// https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-2050006
fn write_virtio_net_hdr(buf: &mut [u8]) -> usize {
    let len = vnet_hdr_len();
    buf[0..len].fill(0);
    len
}

pub struct NetWorker {
    queues: Vec<Queue>,
    queue_evts: Vec<EventFd>,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
    intc: Option<IrqChip>,
    irq_line: Option<u32>,

    mem: GuestMemoryMmap,
    backend: Box<dyn NetBackend + Send>,

    poll: Poll,
    waker: Option<Arc<EventFd>>,

    rx_frame_buf: [u8; MAX_BUFFER_SIZE],
    rx_frame_buf_len: usize,
    rx_has_deferred_frame: bool,

    tx_iovec: Vec<(GuestAddress, usize)>,
    tx_frame_buf: [u8; MAX_BUFFER_SIZE],
    tx_frame_len: usize,
}

const VIRTQ_TX_TOKEN: Token = Token(0); // Packets from guest
const VIRTQ_RX_TOKEN: Token = Token(1); // Notifies that guest has provided new RX buffers
const BACKEND_WAKER_TOKEN: Token = Token(2);
const PROXY_START_TOKEN: usize = 3;

impl NetWorker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
        interrupt_status: Arc<AtomicUsize>,
        interrupt_evt: EventFd,
        intc: Option<IrqChip>,
        irq_line: Option<u32>,
        mem: GuestMemoryMmap,
        cfg_backend: VirtioNetBackend,
    ) -> Self {
        let poll = Poll::new().unwrap();
        let (backend, waker) = match cfg_backend {
            // VirtioNetBackend::Passt(fd) => Box::new(Passt::new(fd)) as Box<dyn NetBackend + Send>,
            VirtioNetBackend::Gvproxy(path) => (
                Box::new(Gvproxy::new(path).unwrap()) as Box<dyn NetBackend + Send>,
                None,
            ),
            VirtioNetBackend::DirectProxy(listeners) => {
                let waker = Arc::new(EventFd::new(EFD_NONBLOCK).unwrap());
                let backend = Box::new(
                    net_proxy::proxy::NetProxy::new(
                        waker.clone(),
                        poll.registry()
                            .try_clone()
                            .expect("could not clone mio registry"),
                        PROXY_START_TOKEN,
                        listeners,
                    )
                    .expect("could not create direct proxy"),
                );
                (backend as Box<dyn NetBackend + Send>, Some(waker))
            }
        };

        Self {
            queues,
            queue_evts,
            interrupt_status,
            interrupt_evt,
            intc,
            irq_line,

            mem,
            backend,

            poll,
            waker,

            rx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            rx_frame_buf_len: 0,
            rx_has_deferred_frame: false,

            tx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            tx_frame_len: 0,
            tx_iovec: Vec::with_capacity(QUEUE_SIZE as usize),
        }
    }

    pub fn run(self) {
        thread::Builder::new()
            .name("virtio-net worker".into())
            .spawn(|| self.work())
            .unwrap();
    }

    fn work(mut self) {
        let mut events = Events::with_capacity(1024);

        self.poll
            .registry()
            .register(
                &mut SourceFd(&self.queue_evts[TX_INDEX].as_raw_fd()),
                VIRTQ_TX_TOKEN,
                Interest::READABLE,
            )
            .expect("could not register VIRTQ_TX_TOKEN");
        self.poll
            .registry()
            .register(
                &mut SourceFd(&self.queue_evts[RX_INDEX].as_raw_fd()),
                VIRTQ_RX_TOKEN,
                Interest::READABLE,
            )
            .expect("could not register VIRTQ_RX_TOKEN");

        let backend_socket = self.backend.raw_socket_fd();
        self.poll
            .registry()
            .register(
                &mut SourceFd(&backend_socket.as_raw_fd()),
                BACKEND_WAKER_TOKEN,
                Interest::READABLE | Interest::WRITABLE,
            )
            .expect("could not register BACKEND_WAKER_TOKEN");

        loop {
            self.poll
                .poll(&mut events, None)
                .expect("could not poll mio events");

            for event in events.iter() {
                match event.token() {
                    VIRTQ_RX_TOKEN => {
                        self.process_rx_queue_event();
                        // self.backend.resume_reading();
                    }
                    VIRTQ_TX_TOKEN => {
                        self.process_tx_queue_event();
                    }
                    BACKEND_WAKER_TOKEN => {
                        if event.is_readable() {
                            trace!("backend was readable");
                            if let Some(waker) = &self.waker {
                                _ = waker.read(); // Correctly reset the waker
                            }
                            // This call is now budgeted and will not get stuck.
                            self.process_backend_socket_readable();
                            // self.backend.resume_reading();
                        }
                        if event.is_writable() {
                            // The `if` is important
                            trace!("backend was writable");
                            self.process_backend_socket_writeable();
                        }
                    }
                    token => {
                        // log::trace!("passing through token to backend: {token:?}");
                        self.backend.handle_event(
                            event.token(),
                            event.is_readable(),
                            event.is_writable(),
                        );
                    }
                }
            }
        }
    }

    pub(crate) fn process_rx_queue_event(&mut self) {
        if let Err(e) = self.queue_evts[RX_INDEX].read() {
            log::error!("Failed to get rx event from queue: {:?}", e);
        }
        if let Err(e) = self.queues[RX_INDEX].disable_notification(&self.mem) {
            error!("error disabling queue notifications: {:?}", e);
        }
        if let Err(e) = self.process_rx() {
            log::error!("Failed to process rx: {e:?} (triggered by queue event)")
        };
        if let Err(e) = self.queues[RX_INDEX].enable_notification(&self.mem) {
            error!("error disabling queue notifications: {:?}", e);
        }
    }

    pub(crate) fn process_tx_queue_event(&mut self) {
        match self.queue_evts[TX_INDEX].read() {
            Ok(_) => self.process_tx_loop(),
            Err(e) => {
                log::error!("Failed to get tx queue event from queue: {e:?}");
            }
        }
    }

    pub(crate) fn process_backend_socket_readable(&mut self) {
        if let Err(e) = self.queues[RX_INDEX].enable_notification(&self.mem) {
            error!("error disabling queue notifications: {:?}", e);
        }
        if let Err(e) = self.process_rx() {
            log::error!("Failed to process rx: {e:?} (triggered by backend socket readable)");
        };
        if let Err(e) = self.queues[RX_INDEX].disable_notification(&self.mem) {
            error!("error disabling queue notifications: {:?}", e);
        }
    }

    pub(crate) fn process_backend_socket_writeable(&mut self) {
        match self
            .backend
            .try_finish_write(vnet_hdr_len(), &self.tx_frame_buf[..self.tx_frame_len])
        {
            Ok(()) => self.process_tx_loop(),
            Err(WriteError::PartialWrite | WriteError::NothingWritten) => {}
            Err(e @ WriteError::Internal(_)) => {
                log::error!("Failed to finish write: {e:?}");
            }
            Err(e @ WriteError::ProcessNotRunning) => {
                log::debug!("Failed to finish write: {e:?}");
            }
        }
    }

    fn process_rx(&mut self) -> result::Result<(), RxError> {
        let mut signal_queue = false;

        // --- START: FINAL CORRECTED LOGIC ---
        // This single loop will now handle everything resiliently.
        loop {
            // Step 1: Handle a previously failed/deferred frame first.
            if self.rx_has_deferred_frame {
                if self.write_frame_to_guest() {
                    // Success! We sent the deferred frame.
                    self.rx_has_deferred_frame = false;
                    signal_queue = true;
                } else {
                    // Guest is still full. We can't do anything more on this connection.
                    // Drop the frame to prevent getting stuck, and break the loop
                    // to wait for a new event (like the guest freeing buffers).
                    log::warn!(
                        "Guest RX queue still full. Dropping deferred frame to prevent deadlock."
                    );
                    self.rx_has_deferred_frame = false;
                    break;
                }
            }

            // Step 2: Try to read a new frame from the proxy.
            match self.read_into_rx_frame_buf_from_backend() {
                Ok(()) => {
                    // We got a new frame. Now try to write it to the guest.
                    if self.write_frame_to_guest() {
                        signal_queue = true;
                    } else {
                        // Guest RX queue just became full. Defer this frame and break.
                        self.rx_has_deferred_frame = true;
                        log::warn!("Guest RX queue became full. Deferring frame.");
                        break;
                    }
                }
                // If the proxy's queue is empty, we are done.
                Err(ReadError::NothingRead) => break,
                // Handle any real errors.
                Err(e) => return Err(RxError::Backend(e)),
            }
        }
        // --- END: FINAL CORRECTED LOGIC ---

        if signal_queue {
            self.signal_used_queue().map_err(RxError::DeviceError)?;
        }

        Ok(())
    }

    fn process_tx_loop(&mut self) {
        loop {
            self.queues[TX_INDEX]
                .disable_notification(&self.mem)
                .unwrap();

            if let Err(e) = self.process_tx() {
                log::error!("Failed to process rx: {e:?} (triggered by backend socket readable)");
            };

            if !self.queues[TX_INDEX]
                .enable_notification(&self.mem)
                .unwrap()
            {
                break;
            }
        }
    }

    fn process_tx(&mut self) -> result::Result<(), TxError> {
        let tx_queue = &mut self.queues[TX_INDEX];

        if self.backend.has_unfinished_write()
            && self
                .backend
                .try_finish_write(vnet_hdr_len(), &self.tx_frame_buf[..self.tx_frame_len])
                .is_err()
        {
            log::trace!("Cannot process tx because of unfinished partial write!");
            return Ok(());
        }

        let mut raise_irq = false;

        while let Some(head) = tx_queue.pop(&self.mem) {
            let head_index = head.index;
            let mut read_count = 0;
            let mut next_desc = Some(head);

            self.tx_iovec.clear();
            while let Some(desc) = next_desc {
                if desc.is_write_only() {
                    self.tx_iovec.clear();
                    break;
                }
                self.tx_iovec.push((desc.addr, desc.len as usize));
                read_count += desc.len as usize;
                next_desc = desc.next_descriptor();
            }

            // Copy buffer from across multiple descriptors.
            read_count = 0;
            for (desc_addr, desc_len) in self.tx_iovec.drain(..) {
                let limit = cmp::min(read_count + desc_len, self.tx_frame_buf.len());

                let read_result = self
                    .mem
                    .read_slice(&mut self.tx_frame_buf[read_count..limit], desc_addr);
                match read_result {
                    Ok(()) => {
                        read_count += limit - read_count;
                    }
                    Err(e) => {
                        log::error!("Failed to read slice: {:?}", e);
                        read_count = 0;
                        break;
                    }
                }
            }

            self.tx_frame_len = read_count;
            match self
                .backend
                .write_frame(vnet_hdr_len(), &mut self.tx_frame_buf[..read_count])
            {
                Ok(()) => {
                    self.tx_frame_len = 0;
                    tx_queue
                        .add_used(&self.mem, head_index, 0)
                        .map_err(TxError::QueueError)?;
                    raise_irq = true;
                }
                Err(WriteError::NothingWritten) => {
                    tx_queue.undo_pop();
                    break;
                }
                Err(WriteError::PartialWrite) => {
                    log::trace!("process_tx: partial write");
                    /*
                    This situation should be pretty rare, assuming reasonably sized socket buffers.
                    We have written only a part of a frame to the backend socket (the socket is full).

                    The frame we have read from the guest remains in tx_frame_buf, and will be sent
                    later.

                    Note that we cannot wait for the backend to process our sending frames, because
                    the backend could be blocked on sending a remainder of a frame to us - us waiting
                    for backend would cause a deadlock.
                     */
                    tx_queue
                        .add_used(&self.mem, head_index, 0)
                        .map_err(TxError::QueueError)?;
                    raise_irq = true;
                    break;
                }
                Err(e @ WriteError::Internal(_) | e @ WriteError::ProcessNotRunning) => {
                    return Err(TxError::Backend(e))
                }
            }
        }

        if raise_irq && tx_queue.needs_notification(&self.mem).unwrap() {
            self.signal_used_queue().map_err(TxError::DeviceError)?;
        }

        Ok(())
    }

    fn signal_used_queue(&mut self) -> result::Result<(), DeviceError> {
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);
        if let Some(intc) = &self.intc {
            intc.lock()
                .unwrap()
                .set_irq(self.irq_line, Some(&self.interrupt_evt))?;
        }
        Ok(())
    }

    // Copies a single frame from `self.rx_frame_buf` into the guest.
    fn write_frame_to_guest_impl(&mut self) -> result::Result<(), FrontendError> {
        let mut result: std::result::Result<(), FrontendError> = Ok(());

        let queue = &mut self.queues[RX_INDEX];
        let head_descriptor = queue.pop(&self.mem).ok_or(FrontendError::EmptyQueue)?;
        let head_index = head_descriptor.index;

        let mut frame_slice = &self.rx_frame_buf[..self.rx_frame_buf_len];

        let frame_len = frame_slice.len();
        let mut maybe_next_descriptor = Some(head_descriptor);
        while let Some(descriptor) = &maybe_next_descriptor {
            if frame_slice.is_empty() {
                break;
            }

            if !descriptor.is_write_only() {
                result = Err(FrontendError::ReadOnlyDescriptor);
                break;
            }

            let len = std::cmp::min(frame_slice.len(), descriptor.len as usize);
            match self.mem.write_slice(&frame_slice[..len], descriptor.addr) {
                Ok(()) => {
                    frame_slice = &frame_slice[len..];
                }
                Err(e) => {
                    log::error!("Failed to write slice: {:?}", e);
                    result = Err(FrontendError::GuestMemory(e));
                    break;
                }
            };

            maybe_next_descriptor = descriptor.next_descriptor();
        }
        if result.is_ok() && !frame_slice.is_empty() {
            log::warn!("Receiving buffer is too small to hold frame of current size");
            result = Err(FrontendError::DescriptorChainTooSmall);
        }

        // Mark the descriptor chain as used. If an error occurred, skip the descriptor chain.
        let used_len = if result.is_err() { 0 } else { frame_len as u32 };
        queue
            .add_used(&self.mem, head_index, used_len)
            .map_err(FrontendError::QueueError)?;
        result
    }

    // Copies a single frame from `self.rx_frame_buf` into the guest. In case of an error retries
    // the operation if possible. Returns true if the operation was successfull.
    fn write_frame_to_guest(&mut self) -> bool {
        let max_iterations = self.queues[RX_INDEX].actual_size();
        for _ in 0..max_iterations {
            match self.write_frame_to_guest_impl() {
                Ok(()) => return true,
                Err(FrontendError::EmptyQueue) => {
                    // retry
                    continue;
                }
                Err(_) => {
                    // retry
                    continue;
                }
            }
        }

        false
    }

    /// Fills self.rx_frame_buf with an ethernet frame from backend and prepends virtio_net_hdr to it
    fn read_into_rx_frame_buf_from_backend(&mut self) -> result::Result<(), ReadError> {
        let mut len = 0;
        len += write_virtio_net_hdr(&mut self.rx_frame_buf);
        len += self.backend.read_frame(&mut self.rx_frame_buf[len..])?;
        self.rx_frame_buf_len = len;
        Ok(())
    }
}
