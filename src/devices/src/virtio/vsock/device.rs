// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::num::Wrapping;
#[cfg(unix)]
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::atomic::{Ordering, fence};
use std::sync::{Arc, Mutex};

use utils::byte_order;
use utils::eventfd::EventFd;

use crate::virtio::descriptor_utils::DescriptorChainSnapshot;
use crate::virtio::lifecycle::ProviderFault;
use crate::virtio::queue::{Descriptor, DescriptorChain, VIRTQ_DESC_F_WRITE};
use crate::virtio::vsock::TsiFlags;
#[cfg(unix)]
use crate::virtio::vsock::UnixSocketIdentity;
use crate::virtio::vsock::muxer::VsockMuxer;
use crate::virtio::vsock::packet::{PacketQueue, VsockPacket};
use crate::virtio::vsock::state::ProviderState;
use crate::virtio::vsock::{defs, defs::uapi};
use crate::virtio::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, InterruptTransport,
    Queue as VirtQueue, QueueConfig, RuntimeGuestMemory, VirtioDevice,
};
use vm_memory::{Address, GuestAddress};

pub(crate) const RXQ_INDEX: usize = 0;
pub(crate) const TXQ_INDEX: usize = 1;
pub(crate) const EVQ_INDEX: usize = 2;

/// The virtio features supported by our vsock device:
/// - VIRTIO_F_VERSION_1: the device conforms to at least version 1.0 of the VirtIO spec.
/// - VIRTIO_F_IN_ORDER: the device returns used buffers in the same order that the driver makes
///   them available.
pub(crate) const AVAIL_FEATURES: u64 = (1 << uapi::VIRTIO_F_VERSION_1 as u64)
    | (1 << uapi::VIRTIO_F_IN_ORDER as u64)
    | (1 << uapi::VIRTIO_VSOCK_F_DGRAM);

pub struct Vsock {
    pub(crate) cid: u64,
    pub(crate) muxer: VsockMuxer,
    pub(crate) queue_rx: Option<Arc<Mutex<PacketQueue>>>,
    pub(crate) queue_tx: Option<Arc<Mutex<VirtQueue>>>,
    pub(crate) queue_ev: Option<VirtQueue>,
    // Parked producers retain these preallocated, unready slots, never the escrowed queues.
    pub(crate) parked_slots: [Option<VirtQueue>; 2],
    pub(crate) provider: ProviderState,
    pub(crate) pending_reset: bool,
    reset_repost: Option<([GuestAddress; 4], Wrapping<u16>)>,
    // Queue events are stored separately for event handling.
    pub(crate) queue_events: Vec<Arc<EventFd>>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
    tx_snapshot: DescriptorChainSnapshot,
    ev_snapshot: DescriptorChainSnapshot,
    tx_buffer: Vec<u8>,
    #[cfg(feature = "native-device-probe")]
    pub(crate) event_queue_held: bool,
    #[cfg(feature = "native-device-probe")]
    pub(crate) reset_deliveries: u64,
}

impl Vsock {
    /// Create a new virtio-vsock device with the given VM CID.
    pub fn new(
        cid: u64,
        host_port_map: Option<HashMap<u16, u16>>,
        unix_ipc_port_map: Option<HashMap<u32, (PathBuf, bool)>>,
        tsi_flags: TsiFlags,
    ) -> super::Result<Vsock> {
        Ok(Vsock {
            cid,
            muxer: VsockMuxer::new(cid, host_port_map, unix_ipc_port_map, tsi_flags)
                .map_err(crate::virtio::vsock::VsockError::EventFd)?,
            queue_rx: None,
            queue_tx: None,
            queue_ev: None,
            parked_slots: [Some(VirtQueue::new(256)), Some(VirtQueue::new(256))],
            provider: ProviderState::new(),
            pending_reset: false,
            reset_repost: None,
            queue_events: Vec::new(),
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(super::VsockError::EventFd)?,
            device_state: DeviceState::Inactive,
            tx_snapshot: DescriptorChainSnapshot::new(256),
            ev_snapshot: DescriptorChainSnapshot::new(256),
            tx_buffer: vec![0; defs::MAX_PKT_BUF_SIZE],
            #[cfg(feature = "native-device-probe")]
            event_queue_held: false,
            #[cfg(feature = "native-device-probe")]
            reset_deliveries: 0,
        })
    }

    pub fn id(&self) -> &str {
        defs::VSOCK_DEV_ID
    }

    pub fn cid(&self) -> u64 {
        self.cid
    }

    #[cfg(unix)]
    pub fn set_unix_mux_fd(&mut self, fd: OwnedFd) -> std::io::Result<()> {
        self.muxer.set_unix_mux_fd(fd)
    }

    #[cfg(unix)]
    pub fn add_unix_mux_protected_identity(&mut self, identity: UnixSocketIdentity) {
        self.muxer.add_unix_mux_protected_identity(identity);
    }

    fn reset_buffer_identity(
        descriptors: &[Descriptor],
    ) -> Result<[GuestAddress; 4], ProviderFault> {
        let mut identity = [GuestAddress(0); 4];
        let mut written = 0;
        for descriptor in descriptors {
            if descriptor.flags & VIRTQ_DESC_F_WRITE == 0 {
                return Err(ProviderFault::QueueState);
            }
            let count = (descriptor.len as usize).min(identity.len() - written);
            for offset in 0..count {
                identity[written + offset] = GuestAddress(descriptor.addr)
                    .checked_add(offset as u64)
                    .ok_or(ProviderFault::QueueState)?;
            }
            written += count;
        }
        if written != identity.len() {
            return Err(ProviderFault::QueueState);
        }
        Ok(identity)
    }

    fn reset_buffer_reposted(
        memory: &RuntimeGuestMemory,
        queue: &mut VirtQueue,
        snapshot: &mut DescriptorChainSnapshot,
        identity: [GuestAddress; 4],
        index: Wrapping<u16>,
    ) -> Result<bool, ProviderFault> {
        let size = queue.actual_size();
        let mut scanned = 0;
        for _ in 0..=size {
            let armed = queue
                .avail_idx(memory, Ordering::Acquire)
                .map_err(|_| ProviderFault::QueueState)?;
            queue
                .arm_available_notification(memory, armed.0)
                .map_err(|_| ProviderFault::QueueState)?;
            // Recheck after arming so a concurrent repost cannot strand admission.
            fence(Ordering::SeqCst);
            let available = queue
                .avail_idx(memory, Ordering::Acquire)
                .map_err(|_| ProviderFault::QueueState)?;
            let count = (available - index).0;
            if size == 0
                || count > size
                || count < scanned
                || (available - queue.next_avail).0 > size
            {
                return Err(ProviderFault::QueueState);
            }
            for offset in scanned..count {
                let slot = (index + Wrapping(offset)).0 % size;
                let address = queue
                    .avail_ring
                    .checked_add(4 + 2 * u64::from(slot))
                    .ok_or(ProviderFault::QueueState)?;
                let head = memory
                    .load::<u16>(address, Ordering::Relaxed)
                    .map_err(|_| ProviderFault::QueueState)?;
                let chain = DescriptorChain::checked_new(memory, queue.desc_table, size, head)
                    .ok_or(ProviderFault::QueueState)?;
                let chain = snapshot
                    .read(chain)
                    .map_err(|_| ProviderFault::QueueState)?;
                if Self::reset_buffer_identity(chain.descriptors())? == identity {
                    return Ok(true);
                }
            }
            if available == armed {
                return Ok(false);
            }
            scanned = count;
        }
        Err(ProviderFault::QueueState)
    }

    pub(crate) fn process_transport_reset(&mut self) -> bool {
        if !self.provider.processing_allowed() {
            return false;
        }
        #[cfg(feature = "native-device-probe")]
        if self.event_queue_held {
            return false;
        }
        if !self.pending_reset {
            return false;
        }
        let DeviceState::Activated(memory, _) = &self.device_state else {
            return false;
        };
        let Some(queue) = &mut self.queue_ev else {
            return false;
        };
        if let Some((identity, index)) = self.reset_repost {
            match Self::reset_buffer_reposted(memory, queue, &mut self.ev_snapshot, identity, index)
            {
                Ok(true) => {
                    self.reset_repost = None;
                    self.pending_reset = false;
                    self.muxer.worker_control.transport_reset_completed();
                }
                Ok(false) => {}
                Err(_) => {
                    queue.record_processing_failure();
                    self.provider.retain_fault(ProviderFault::QueueState);
                }
            }
            return false;
        }
        let mut have_used = false;
        if let Some(head) = queue.pop(memory) {
            let chain = match self.ev_snapshot.read(head.clone()) {
                Ok(chain) => chain,
                Err(_) => {
                    queue.record_processing_failure();
                    self.provider.retain_fault(ProviderFault::QueueState);
                    have_used |= queue.add_used(memory, head.index, 0).is_ok();
                    return have_used;
                }
            };
            let total = chain
                .descriptors()
                .iter()
                .try_fold(0usize, |total, descriptor| {
                    total.checked_add(descriptor.len as usize)
                });
            if chain
                .descriptors()
                .iter()
                .any(|descriptor| descriptor.flags & VIRTQ_DESC_F_WRITE == 0)
                || total.is_none_or(|total| total < 4)
            {
                queue.record_processing_failure();
                self.provider.retain_fault(ProviderFault::QueueState);
                have_used |= queue.add_used(memory, head.index, 0).is_ok();
                return have_used;
            }
            let reset = 0u32.to_le_bytes();
            let mut written = 0;
            for descriptor in chain.descriptors() {
                let count = (descriptor.len as usize).min(reset.len() - written);
                if memory
                    .write_slice(
                        &reset[written..written + count],
                        GuestAddress(descriptor.addr),
                    )
                    .is_err()
                {
                    queue.record_processing_failure();
                    self.provider.retain_fault(ProviderFault::QueueState);
                    return have_used;
                }
                written += count;
                if written == reset.len() {
                    break;
                }
            }
            // The admitted Linux driver reposts the same event storage only after
            // event_work resets connected sockets. IN_ORDER may change its head.
            // This is Linux-profile evidence, not a portable virtio reset ACK;
            // drivers without this behavior remain fenced.
            let identity = match Self::reset_buffer_identity(chain.descriptors()) {
                Ok(identity) => identity,
                Err(fault) => {
                    self.provider.retain_fault(fault);
                    return have_used;
                }
            };
            let index = match queue.avail_idx(memory, Ordering::Acquire) {
                Ok(index) => index,
                Err(_) => {
                    self.provider.retain_fault(ProviderFault::QueueState);
                    return have_used;
                }
            };
            if queue.arm_available_notification(memory, index.0).is_err() {
                self.provider.retain_fault(ProviderFault::QueueState);
                return have_used;
            }
            if queue.add_used(memory, head.index, 4).is_err() {
                self.provider.retain_fault(ProviderFault::QueueState);
                return have_used;
            }
            self.reset_repost = Some((identity, index));
            #[cfg(feature = "native-device-probe")]
            {
                self.reset_deliveries = self.reset_deliveries.saturating_add(1);
            }
            return true;
        }
        have_used
    }

    pub(crate) fn signal_used_queue(&mut self) {
        match &self.device_state {
            DeviceState::Activated(_, interrupt) => {
                if interrupt.try_signal_used_queue().is_err() {
                    self.provider.retain_fault(ProviderFault::Notification);
                }
            }
            DeviceState::Inactive => self.provider.retain_fault(ProviderFault::DeviceState),
        }
    }

    /// Walk the driver-provided RX queue buffers and attempt to fill them up with any data that we
    /// have pending. Return `true` if descriptors have been added to the used ring, and `false`
    /// otherwise.
    pub fn process_stream_rx(&mut self) -> bool {
        if !self.provider.processing_allowed() {
            return false;
        }
        debug!("process_stream_rx()");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem, _) => mem,
            DeviceState::Inactive => return false,
        };

        let mut have_used = false;

        debug!("process_rx before while");
        let Some(queue_rx) = self.queue_rx.as_ref() else {
            return false;
        };
        let Ok(mut queue_rx) = queue_rx.lock() else {
            return false;
        };
        while let Some(head) = queue_rx.pop(mem) {
            debug!("process_rx inside while");
            let used_len = match VsockPacket::from_rx_virtq_head(&head, &mut queue_rx.snapshot) {
                Ok(mut pkt) => match self.muxer.recv_pkt(&mut pkt) {
                    Ok(()) => pkt.hdr().len() as u32 + pkt.len(),
                    Err(crate::virtio::vsock::VsockError::BufDescTooSmall) => 0,
                    Err(crate::virtio::vsock::VsockError::NoData) => {
                        if queue_rx.undo_pop(head.index).is_err() {
                            self.provider.retain_fault(ProviderFault::QueueState);
                        }
                        break;
                    }
                    Err(_) => {
                        queue_rx.record_processing_failure();
                        self.provider.retain_fault(ProviderFault::QueueState);
                        break;
                    }
                },
                Err(e) => {
                    warn!("RX queue error: {e:?}");
                    queue_rx.record_processing_failure();
                    self.provider.retain_fault(ProviderFault::QueueState);
                    have_used |= queue_rx.add_used(mem, head.index, 0).is_ok();
                    break;
                }
            };

            debug!("process_rx: something to queue");
            have_used = true;
            if let Err(e) = queue_rx.add_used(mem, head.index, used_len) {
                error!("failed to add used elements to the queue: {e:?}");
                self.provider.retain_fault(ProviderFault::QueueState);
                break;
            }
        }

        drop(queue_rx);
        if self.provider.processing_allowed() {
            have_used |= self.muxer.retry_deferred_credit();
        }

        have_used
    }

    /// Walk the driver-provided TX queue buffers, package them up as vsock packets, and process
    /// them. Return `true` if descriptors have been added to the used ring, and `false` otherwise.
    pub fn process_stream_tx(&mut self) -> bool {
        if !self.provider.processing_allowed() {
            return false;
        }
        debug!("process_stream_tx()");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem, _) => mem,
            DeviceState::Inactive => return false,
        };

        let mut have_used = false;

        let Some(queue_tx) = self.queue_tx.as_ref() else {
            return false;
        };
        let Ok(mut queue_tx) = queue_tx.lock() else {
            return false;
        };
        while let Some(head) = queue_tx.pop(mem) {
            if self.pending_reset || self.provider.discard_tx {
                let valid = self.tx_snapshot.read(head.clone()).is_ok_and(|chain| {
                    chain
                        .descriptors()
                        .iter()
                        .all(|descriptor| descriptor.flags & VIRTQ_DESC_F_WRITE == 0)
                });
                if !valid {
                    queue_tx.record_processing_failure();
                    self.provider.retain_fault(ProviderFault::QueueState);
                    have_used |= queue_tx.add_used(mem, head.index, 0).is_ok();
                    break;
                }
                have_used = true;
                if queue_tx.add_used(mem, head.index, 0).is_err() {
                    self.provider.retain_fault(ProviderFault::QueueState);
                    break;
                }
                continue;
            }
            let pkt = match VsockPacket::from_tx_virtq_head(
                &head,
                &mut self.tx_snapshot,
                Some(&mut self.tx_buffer),
            ) {
                Ok(pkt) => pkt,
                Err(e) => {
                    error!("error reading TX packet: {e:?}");
                    queue_tx.record_processing_failure();
                    self.provider.retain_fault(ProviderFault::QueueState);
                    have_used = true;
                    if let Err(e) = queue_tx.add_used(mem, head.index, 0) {
                        error!("failed to add used elements to the queue: {e:?}");
                    }
                    break;
                }
            };

            if pkt.type_() == uapi::VSOCK_TYPE_DGRAM {
                debug!("process_stream_tx() is DGRAM");
                if self.muxer.send_dgram_pkt(&pkt).is_err() {
                    queue_tx.record_processing_failure();
                    self.provider.retain_fault(ProviderFault::QueueState);
                    break;
                }
            } else {
                debug!("process_stream_tx() is STREAM");
                if self.muxer.send_stream_pkt(&pkt).is_err() {
                    queue_tx.record_processing_failure();
                    self.provider.retain_fault(ProviderFault::QueueState);
                    break;
                }
            }

            have_used = true;
            if let Err(e) = queue_tx.add_used(mem, head.index, 0) {
                error!("failed to add used elements to the queue: {e:?}");
                self.provider.retain_fault(ProviderFault::QueueState);
                break;
            }
        }

        have_used
    }
}

impl VirtioDevice for Vsock {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn device_type(&self) -> u32 {
        uapi::VIRTIO_ID_VSOCK
    }

    fn device_name(&self) -> &str {
        "vsock"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &defs::QUEUE_CONFIG
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        match offset {
            0 if data.len() == 8 => byte_order::write_le_u64(data, self.cid()),
            0 if data.len() == 4 => {
                byte_order::write_le_u32(data, (self.cid() & 0xffff_ffff) as u32)
            }
            4 if data.len() == 4 => {
                byte_order::write_le_u32(data, ((self.cid() >> 32) & 0xffff_ffff) as u32)
            }
            _ => warn!(
                "virtio-vsock received invalid read request of {} bytes at offset {}",
                data.len(),
                offset
            ),
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: RuntimeGuestMemory,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if queues.len() != defs::NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                defs::NUM_QUEUES,
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        if self.activate_evt.write(1).is_err() {
            error!("Cannot write to activate_evt",);
            return Err(ActivateError::BadActivate);
        }

        // Store queue events for event handling.
        self.queue_events = queues.iter().map(|dq| dq.event.clone()).collect();

        // Extract queues from DeviceQueues and wrap in Arc<Mutex<>>.
        let mut queues = queues.into_iter();
        let Some(rx) = queues.next() else {
            return Err(ActivateError::BadActivate);
        };
        let Some(tx) = queues.next() else {
            return Err(ActivateError::BadActivate);
        };
        let Some(ev) = queues.next() else {
            return Err(ActivateError::BadActivate);
        };
        let mut rx = PacketQueue::from_queue(rx.queue);
        rx.bind_admission(self.muxer.worker_control.clone());
        let rx = Arc::new(Mutex::new(rx));
        self.queue_tx = Some(Arc::new(Mutex::new(tx.queue)));
        self.queue_rx = Some(rx.clone());
        self.queue_ev = Some(ev.queue);
        if self
            .muxer
            .activate(mem.clone(), rx, interrupt.clone())
            .is_err()
        {
            self.muxer.worker_control.stop();
            return Err(ActivateError::BadActivate);
        }

        self.device_state = DeviceState::Activated(mem, interrupt);
        self.provider.dormant = false;

        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn state_provider(&self) -> Option<&dyn crate::virtio::lifecycle::VirtioStateProvider> {
        Some(self)
    }

    fn state_provider_mut(
        &mut self,
    ) -> Option<&mut dyn crate::virtio::lifecycle::VirtioStateProvider> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::queue::tests::VirtQueue as GuestQueue;

    #[test]
    fn reset_repost_matches_buffer_across_index_wrap_and_rearms_event_idx() {
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let guest = GuestQueue::new(GuestAddress(0), &memory, 8);
        let mut queue = guest.create_queue();
        queue.next_avail = Wrapping(u16::MAX - 1);
        queue.set_event_idx(true);
        let mut snapshot = DescriptorChainSnapshot::new(8);
        let identity = std::array::from_fn(|offset| GuestAddress(0x6000 + offset as u64));
        let baseline = Wrapping(u16::MAX);
        guest.dtable[0].set(0x6000, 4, 2, 0);
        guest.avail.ring[6].set(0);
        guest.avail.idx.set(u16::MAX);
        assert_eq!(
            Vsock::reset_buffer_reposted(&memory, &mut queue, &mut snapshot, identity, baseline),
            Ok(false),
            "an existing matching buffer is not post-reset evidence"
        );
        guest.dtable[1].set(0x6010, 4, 2, 0);
        guest.avail.ring[7].set(1);
        guest.avail.idx.set(0);
        assert_eq!(
            Vsock::reset_buffer_reposted(&memory, &mut queue, &mut snapshot, identity, baseline),
            Ok(false)
        );
        let avail_event = queue.used_ring.checked_add(4 + 8 * 8).unwrap();
        assert_eq!(memory.read_obj::<u16>(avail_event).unwrap(), 0);
        guest.dtable[2].set(0x6000, 4, 2, 0);
        guest.avail.ring[0].set(2);
        guest.avail.idx.set(1);
        assert_eq!(
            Vsock::reset_buffer_reposted(&memory, &mut queue, &mut snapshot, identity, baseline),
            Ok(true),
            "IN_ORDER can return the same buffer under a different descriptor head"
        );
        assert_eq!(queue.next_avail, Wrapping(u16::MAX - 1));
        assert_eq!(
            guest.used.idx.get(),
            0,
            "observation must not consume buffers"
        );
    }

    #[test]
    fn reset_repost_rejects_overrun_and_nonwritable_buffer() {
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let guest = GuestQueue::new(GuestAddress(0), &memory, 8);
        let mut queue = guest.create_queue();
        let mut snapshot = DescriptorChainSnapshot::new(8);
        let identity = std::array::from_fn(|offset| GuestAddress(0x6000 + offset as u64));
        guest.avail.idx.set(9);
        for baseline in [Wrapping(0), Wrapping(1)] {
            assert_eq!(
                Vsock::reset_buffer_reposted(
                    &memory,
                    &mut queue,
                    &mut snapshot,
                    identity,
                    baseline
                ),
                Err(ProviderFault::QueueState)
            );
        }
        guest.dtable[0].set(0x6000, 4, 0, 0);
        guest.avail.ring[0].set(0);
        guest.avail.idx.set(1);
        assert_eq!(
            Vsock::reset_buffer_reposted(&memory, &mut queue, &mut snapshot, identity, Wrapping(0)),
            Err(ProviderFault::QueueState)
        );
    }
}
