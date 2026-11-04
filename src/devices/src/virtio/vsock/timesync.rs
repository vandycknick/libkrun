use std::sync::{Arc, Mutex};
use std::thread;
use std::time;

use crate::virtio::vsock::defs::uapi;
use crate::virtio::vsock::packet::PacketQueue as VirtQueue;
use crate::virtio::vsock::packet::VsockPacket;
use crate::virtio::vsock::worker_control::{Owner, WorkerControl};

use crate::virtio::InterruptTransport;
use crate::virtio::RuntimeGuestMemory;

const UPDATE_INTERVAL: u64 = 60 * 1000 * 1000 * 1000;
const SLEEP_NSECS: u64 = 2 * 1000 * 1000 * 1000;
const TSYNC_PORT: u32 = 123;

pub(crate) struct TimesyncThread {
    cid: u64,
    mem: RuntimeGuestMemory,
    queue_mutex: Arc<Mutex<VirtQueue>>,
    interrupt: InterruptTransport,
    control: Arc<WorkerControl>,
}

impl TimesyncThread {
    pub(crate) fn new(
        cid: u64,
        mem: RuntimeGuestMemory,
        queue_mutex: Arc<Mutex<VirtQueue>>,
        interrupt: InterruptTransport,
        control: Arc<WorkerControl>,
    ) -> Self {
        Self {
            cid,
            mem,
            queue_mutex,
            interrupt,
            control,
        }
    }

    fn send_time(&self, time: u64) -> bool {
        let Ok(mut queue) = self.queue_mutex.lock() else {
            self.control.fail();
            return false;
        };
        let Some(head) = queue.pop(&self.mem) else {
            return false;
        };
        let Ok(mut packet) = VsockPacket::from_rx_virtq_head(&head, &mut queue.snapshot) else {
            queue.record_processing_failure();
            self.control.fail();
            if queue.add_used(&self.mem, head.index, 0).is_ok() {
                self.interrupt.signal_used_queue();
            }
            return false;
        };
        if packet.buf().is_none_or(|buffer| buffer.len() < 8) {
            if queue.undo_pop(head.index).is_err() {
                self.control.fail();
            }
            return false;
        }
        packet
            .set_op(uapi::VSOCK_OP_RW)
            .set_src_cid(uapi::VSOCK_HOST_CID)
            .set_dst_cid(self.cid)
            .set_src_port(TSYNC_PORT)
            .set_dst_port(TSYNC_PORT)
            .set_type(uapi::VSOCK_TYPE_DGRAM)
            .set_flags(0)
            .set_buf_alloc(0)
            .set_fwd_cnt(0)
            .set_len(8);
        packet.write_time_sync(time);
        if queue
            .add_used(&self.mem, head.index, packet.hdr().len() as u32 + 8)
            .is_err()
            || self.interrupt.try_signal_used_queue().is_err()
        {
            self.control.fail();
            return false;
        }
        true
    }

    fn work(&mut self) {
        let mut last_update = 0u64;
        let mut last_awake = utils::time::get_time(utils::time::ClockType::Real);
        while self.control.boundary(Owner::Timesync) {
            let epoch = self.control.epoch();
            let now = utils::time::get_time(utils::time::ClockType::Real);
            /*
             * We send a time sync packet if we slept for 3 times more
             * nanoseconds than expected (which is an indication the
             * system forced us to take a long nap), or if UPDATE_INTERVAL
             * has been reached.
             */
            if !self.control.activation_fenced()
                && (now.saturating_sub(last_awake) >= SLEEP_NSECS * 3
                    || now.saturating_sub(last_update) >= UPDATE_INTERVAL)
                && self.send_time(now)
            {
                last_update = now;
            }

            last_awake = utils::time::get_time(utils::time::ClockType::Real);
            self.control.reconciled(Owner::Timesync, epoch);
            self.control.wait(time::Duration::from_nanos(SLEEP_NSECS));
        }
    }

    pub fn run(mut self) -> std::io::Result<thread::JoinHandle<()>> {
        thread::Builder::new()
            .name("vsock timesync".into())
            .spawn(move || self.work())
    }
}
