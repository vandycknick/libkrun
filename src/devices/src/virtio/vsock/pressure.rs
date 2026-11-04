use std::thread::ThreadId;

use crate::virtio::lifecycle::{ProviderFault, ProviderStage};
use crate::virtio::vsock::Vsock;

#[derive(Clone, Copy, Debug)]
pub struct VsockPressureObservation {
    pub stage: ProviderStage,
    pub accepted: bool,
    pub pending_reset: bool,
    pub reset_deliveries: u64,
    pub event_queue_held: bool,
    pub event_queue_owned: bool,
    pub worker_threads: [Option<ThreadId>; 3],
    pub unfinished_workers: usize,
    pub expected: u8,
    pub started: u8,
    pub parked: u8,
    pub exited: u8,
    pub reconciled: u8,
    pub paused: bool,
    pub activation_fenced: bool,
    pub transport_ready: bool,
    pub host_connects: u64,
    pub guest_requests: u64,
    pub admitted: u64,
    pub rejected: u64,
    pub credit_queued: u64,
    pub credit_delivered: u64,
    pub reaps: u64,
    pub overflowed: bool,
    pub sessions: usize,
    pub listeners: usize,
    pub connected: usize,
    pub waiting_credit: usize,
    pub pending_host: usize,
    pub deferred_credits: usize,
    pub response_queue_len: usize,
}

impl Vsock {
    /// The standalone controller calls this under the actual device mutex.
    /// Release scans the retained EVQ, never manufactures a buffer or reset.
    pub fn hold_event_queue(&mut self, held: bool) -> Result<(), ProviderFault> {
        self.event_queue_held = held;
        if !held && self.provider.processing_allowed() && self.process_transport_reset() {
            self.signal_used_queue();
        }
        if let Some(fault) = self.provider.effect_fault() {
            return Err(fault);
        }
        Ok(())
    }

    pub fn pressure_observation(&self) -> Result<VsockPressureObservation, ProviderFault> {
        let worker = self.muxer.worker_control.observation()?;
        let proxies = self.muxer.proxy_observation()?;
        if self.muxer.workers.len() > 3 {
            return Err(ProviderFault::Worker);
        }
        let mut worker_threads = [None; 3];
        for (slot, (_, handle)) in worker_threads.iter_mut().zip(&self.muxer.workers) {
            *slot = Some(handle.thread().id());
        }
        Ok(VsockPressureObservation {
            stage: self.provider.journal.snapshot.stage,
            accepted: self.provider.journal.snapshot.accepted,
            pending_reset: self.pending_reset,
            reset_deliveries: self.reset_deliveries,
            event_queue_held: self.event_queue_held,
            event_queue_owned: self.queue_ev.is_some(),
            expected: worker.expected,
            started: worker.started,
            parked: worker.parked,
            exited: worker.exited,
            reconciled: worker.reconciled,
            paused: worker.paused,
            activation_fenced: worker.activation_fenced,
            transport_ready: worker.transport_ready,
            worker_threads,
            unfinished_workers: self
                .muxer
                .workers
                .iter()
                .filter(|(_, worker)| !worker.is_finished())
                .count(),
            host_connects: worker.counters.host_connects,
            guest_requests: worker.counters.guest_requests,
            admitted: worker.counters.admitted,
            rejected: worker.counters.rejected,
            credit_queued: worker.counters.credit_queued,
            credit_delivered: worker.counters.credit_delivered,
            reaps: worker.counters.reaps,
            overflowed: worker.counters.overflowed,
            sessions: proxies.sessions,
            listeners: proxies.listeners,
            connected: proxies.connected,
            waiting_credit: proxies.waiting_credit,
            pending_host: proxies.pending_host,
            deferred_credits: proxies.deferred_credits,
            response_queue_len: proxies.response_queue_len,
        })
    }
}
