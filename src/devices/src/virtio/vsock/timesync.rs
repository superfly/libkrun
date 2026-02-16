use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use super::super::Queue as VirtQueue;
use super::defs::uapi;
use super::packet::VsockPacket;

use crate::virtio::InterruptTransport;
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

const UPDATE_INTERVAL: u64 = 60 * 1000 * 1000 * 1000;
const SLEEP_NSECS: u64 = 2 * 1000 * 1000 * 1000;
const TSYNC_PORT: u32 = 123;

pub struct TimesyncThread {
    cid: u64,
    mem: GuestMemoryMmap,
    queue_mutex: Arc<Mutex<VirtQueue>>,
    interrupt: InterruptTransport,
    quiesce_fd: EventFd,
    resume_fd: EventFd,
    quiesce_ack: Arc<(Mutex<bool>, Condvar)>,
}

impl TimesyncThread {
    pub fn new(
        cid: u64,
        mem: GuestMemoryMmap,
        queue_mutex: Arc<Mutex<VirtQueue>>,
        interrupt: InterruptTransport,
        quiesce_fd: EventFd,
        resume_fd: EventFd,
        quiesce_ack: Arc<(Mutex<bool>, Condvar)>,
    ) -> Self {
        Self {
            cid,
            mem,
            queue_mutex,
            interrupt,
            quiesce_fd,
            resume_fd,
            quiesce_ack,
        }
    }

    fn send_time(&self, time: u64) {
        let mut queue = self.queue_mutex.lock().unwrap();
        if let Some(head) = queue.pop(&self.mem) {
            if let Ok(mut pkt) = VsockPacket::from_rx_virtq_head(&head) {
                pkt.set_op(uapi::VSOCK_OP_RW)
                    .set_src_cid(uapi::VSOCK_HOST_CID)
                    .set_dst_cid(self.cid)
                    .set_src_port(TSYNC_PORT)
                    .set_dst_port(TSYNC_PORT)
                    .set_type(uapi::VSOCK_TYPE_DGRAM);

                pkt.write_time_sync(time);
                pkt.set_len(pkt.buf().unwrap().len() as u32);
                if let Err(e) =
                    queue.add_used(&self.mem, head.index, pkt.hdr().len() as u32 + pkt.len())
                {
                    error!("failed to add used elements to the queue: {e:?}");
                }
                self.interrupt.signal_used_queue();
            }
        }
    }

    fn handle_quiesce(&self) {
        let _ = self.quiesce_fd.read();
        warn!("vsock: timesync_thread quiesced");

        // Signal the device that we're quiesced.
        let (lock, cvar) = &*self.quiesce_ack;
        {
            let mut acked = lock.lock().unwrap();
            *acked = true;
            cvar.notify_one();
        }

        // Park until resume_fd is signalled.
        let _ = self.resume_fd.read();
        warn!("vsock: timesync_thread resumed");
    }

    fn work(&mut self) {
        // Use epoll to wait on quiesce_fd with timeout instead of thread::sleep.
        // The macOS epoll (kqueue wrapper) has a hardcoded 3s timeout which is
        // close enough to the 2s sleep interval.
        let epoll = Epoll::new().unwrap();
        let _ = epoll.ctl(
            ControlOperation::Add,
            self.quiesce_fd.as_raw_fd(),
            &EpollEvent::new(EventSet::IN, 0),
        );

        let mut last_update = 0u64;
        let mut last_awake = utils::time::get_time(utils::time::ClockType::Real);
        loop {
            let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 1];
            match epoll.wait(1, -1, epoll_events.as_mut_slice()) {
                Ok(0) => {
                    // Timeout — check if time sync is needed
                    let now = utils::time::get_time(utils::time::ClockType::Real);
                    if (now - last_awake) >= (SLEEP_NSECS * 3)
                        || (now - last_update) >= UPDATE_INTERVAL
                    {
                        self.send_time(now);
                        last_update = now;
                    }
                    last_awake = utils::time::get_time(utils::time::ClockType::Real);
                }
                Ok(_) => {
                    // Quiesce event
                    self.handle_quiesce();
                }
                Err(e) => {
                    debug!("timesync epoll error: {e}");
                }
            }
        }
    }

    pub fn run(mut self) {
        thread::Builder::new()
            .name("vsock timesync".into())
            .spawn(move || self.work())
            .unwrap();
    }
}
