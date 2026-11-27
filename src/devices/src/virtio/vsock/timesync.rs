use std::sync::{Arc, Mutex};
use std::thread;
use std::time;

use crate::virtio::vsock::defs::uapi;
use crate::virtio::vsock::muxer_rxq::{MuxerRxQ, RxDrainStop};
use crate::virtio::vsock::packet::PacketQueue as VirtQueue;
use crate::virtio::vsock::packet::RxPacket;
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
    rxq: Arc<Mutex<MuxerRxQ>>,
    interrupt: InterruptTransport,
    control: Arc<WorkerControl>,
}

impl TimesyncThread {
    pub(crate) fn new(
        cid: u64,
        mem: RuntimeGuestMemory,
        queue_mutex: Arc<Mutex<VirtQueue>>,
        rxq: Arc<Mutex<MuxerRxQ>>,
        interrupt: InterruptTransport,
        control: Arc<WorkerControl>,
    ) -> Self {
        Self {
            cid,
            mem,
            rxq,
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
        let Ok(mut rxq) = self.rxq.lock() else {
            self.control.fail();
            return false;
        };
        let drained = rxq.drain(self.cid, &mut queue, &self.mem);
        drop(rxq);
        let sent = match drained.stop {
            RxDrainStop::Empty => self.try_send_time(&mut queue, time),
            RxDrainStop::NoBuffer => None,
            RxDrainStop::Fault => {
                self.control.fail();
                None
            }
        };
        drop(queue);
        if (drained.used_queue || sent.is_some()) && self.interrupt.try_signal_used_queue().is_err()
        {
            self.control.fail();
            return false;
        }
        sent == Some(true)
    }

    fn try_send_time(&self, queue: &mut VirtQueue, time: u64) -> Option<bool> {
        let head = queue.pop(&self.mem)?;
        let Ok(mut packet) = RxPacket::from_rx_virtq_head(&head, &mut queue.snapshot) else {
            queue.record_processing_failure();
            self.control.fail();
            return queue
                .add_used(&self.mem, head.index, 0)
                .ok()
                .map(|()| false);
        };
        if packet.buf().is_none_or(|buffer| buffer.len() < 8) {
            if queue.undo_pop(head.index).is_err() {
                self.control.fail();
            }
            return None;
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
        drop(packet);
        if queue
            .add_used(
                &self.mem,
                head.index,
                crate::virtio::vsock::packet::VSOCK_PKT_HDR_SIZE as u32 + 8,
            )
            .is_err()
        {
            self.control.fail();
            return None;
        }
        Some(true)
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
