// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//

//! Bounded ordered protocol responses, retained with the source mux while parked.
use std::collections::VecDeque;

use crate::virtio::RuntimeGuestMemory;
use crate::virtio::vsock::defs;
use crate::virtio::vsock::defs::uapi;
use crate::virtio::vsock::muxer::MuxerRx;
use crate::virtio::vsock::packet::{
    PacketQueue, RxPacket, TsiAcceptRsp, TsiConnectRsp, TsiListenRsp, VSOCK_PKT_HDR_SIZE,
};

#[derive(Default, PartialEq, Eq)]
pub(crate) enum RxDrainStop {
    #[default]
    Empty,
    NoBuffer,
    Fault,
}

#[derive(Default)]
pub(crate) struct RxDrain {
    pub used_queue: bool,
    pub stop: RxDrainStop,
}

pub(crate) enum RxDelivery {
    Delivered,
    TooSmall,
    NoBuffer,
    Fault { used_queue: bool },
}

/// The muxer RX queue.
///
/// Take the guest RX virtqueue lock before locking this queue to deliver packets.
pub struct MuxerRxQ {
    /// The RX queue data.
    q: VecDeque<MuxerRx>,
}

impl MuxerRxQ {
    const SIZE: usize = defs::MUXER_RXQ_SIZE;

    /// Trivial RX queue constructor.
    pub fn new() -> Self {
        Self {
            q: VecDeque::with_capacity(Self::SIZE),
        }
    }

    /// Refuses overflow without dropping an accepted protocol response.
    pub fn push(&mut self, rx: MuxerRx) -> bool {
        if self.is_full() {
            return false;
        }
        self.q.push_back(rx);
        true
    }

    pub(crate) fn drain(
        &mut self,
        cid: u64,
        queue: &mut PacketQueue,
        mem: &RuntimeGuestMemory,
    ) -> RxDrain {
        let mut used_queue = false;
        let stop = loop {
            let Some(rx) = self.q.front() else {
                break RxDrainStop::Empty;
            };
            match try_push_virtqueue(cid, rx, queue, mem) {
                RxDelivery::Delivered => {
                    self.q.pop_front();
                    used_queue = true;
                }
                RxDelivery::TooSmall => used_queue = true,
                RxDelivery::NoBuffer => break RxDrainStop::NoBuffer,
                RxDelivery::Fault {
                    used_queue: published,
                } => {
                    used_queue |= published;
                    break RxDrainStop::Fault;
                }
            }
        };
        RxDrain { used_queue, stop }
    }

    /// Get the total number of items in the queue.
    pub fn len(&self) -> usize {
        self.q.len()
    }

    /// Check if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Check if the queue is full.
    pub fn is_full(&self) -> bool {
        self.len() == Self::SIZE
    }
}

pub(crate) fn try_push_virtqueue(
    cid: u64,
    rx: &MuxerRx,
    queue: &mut PacketQueue,
    mem: &RuntimeGuestMemory,
) -> RxDelivery {
    let Some(head) = queue.pop(mem) else {
        return RxDelivery::NoBuffer;
    };
    let (len, delivery) = match RxPacket::from_rx_virtq_head(&head, &mut queue.snapshot) {
        Ok(mut pkt) => {
            if rx_to_pkt(cid, rx, &mut pkt) {
                (VSOCK_PKT_HDR_SIZE as u32 + pkt.len(), RxDelivery::Delivered)
            } else {
                (0, RxDelivery::TooSmall)
            }
        }
        Err(error) => {
            log::warn!("RX queue error: {error:?}");
            queue.record_processing_failure();
            (0, RxDelivery::Fault { used_queue: true })
        }
    };
    if let Err(error) = queue.add_used(mem, head.index, len) {
        log::error!("failed to publish vsock packet: {error:?}");
        return RxDelivery::Fault { used_queue: false };
    }
    #[cfg(feature = "native-device-probe")]
    if matches!(delivery, RxDelivery::Delivered)
        && matches!(
            rx,
            MuxerRx::CreditRequest { .. } | MuxerRx::CreditUpdate { .. }
        )
    {
        queue.record_counter(crate::virtio::vsock::worker_control::WorkerCounter::CreditDelivered);
    }
    delivery
}

fn rx_to_pkt(cid: u64, rx: &MuxerRx, pkt: &mut RxPacket) -> bool {
    let required = match rx {
        MuxerRx::ConnResponse { .. }
        | MuxerRx::ListenResponse { .. }
        | MuxerRx::AcceptResponse { .. } => 4,
        MuxerRx::GetnameResponse { data, .. } => {
            let Some(length) = data.payload_len() else {
                return false;
            };
            length
        }
        _ => 0,
    };
    let buffer_len = pkt.buf().map_or(0, |buffer| buffer.len() as u32);
    if (buffer_len as usize) < required {
        return false;
    }
    match *rx {
        MuxerRx::Reset {
            local_port,
            peer_port,
        } => {
            pkt.set_op(uapi::VSOCK_OP_RST)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_len(0)
                .set_type(uapi::VSOCK_TYPE_STREAM)
                .set_flags(0)
                .set_buf_alloc(0)
                .set_fwd_cnt(0);
        }
        MuxerRx::Shutdown {
            local_port,
            peer_port,
            flags,
        } => {
            pkt.set_op(uapi::VSOCK_OP_SHUTDOWN)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_len(0)
                .set_type(uapi::VSOCK_TYPE_STREAM)
                .set_flags(flags)
                .set_buf_alloc(defs::CONN_TX_BUF_SIZE as u32)
                .set_fwd_cnt(0);
        }
        MuxerRx::ConnResponse {
            local_port,
            peer_port,
            result,
        } => {
            pkt.set_op(uapi::VSOCK_OP_RW)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_DGRAM);

            pkt.write_connect_rsp(TsiConnectRsp { result });
            pkt.set_len(required as u32);
        }
        MuxerRx::OpRequest {
            local_port,
            peer_port,
        } => {
            pkt.set_op(uapi::VSOCK_OP_REQUEST)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_STREAM)
                .set_buf_alloc(defs::CONN_TX_BUF_SIZE as u32);

            pkt.set_len(0).set_flags(0).set_fwd_cnt(0);
        }
        MuxerRx::OpResponse {
            local_port,
            peer_port,
        } => {
            pkt.set_op(uapi::VSOCK_OP_RESPONSE)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_STREAM)
                .set_buf_alloc(defs::CONN_TX_BUF_SIZE as u32);

            pkt.set_len(0).set_flags(0).set_fwd_cnt(0);
        }
        MuxerRx::GetnameResponse {
            local_port,
            peer_port,
            ref data,
        } => {
            pkt.set_op(uapi::VSOCK_OP_RW)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_DGRAM);

            pkt.write_getname_rsp(data);
            pkt.set_len(required as u32);
        }
        MuxerRx::CreditRequest {
            local_port,
            peer_port,
            fwd_cnt,
        } => {
            pkt.set_op(uapi::VSOCK_OP_CREDIT_REQUEST)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_STREAM)
                .set_buf_alloc(defs::CONN_TX_BUF_SIZE as u32)
                .set_fwd_cnt(fwd_cnt)
                .set_len(0)
                .set_flags(0);
        }
        MuxerRx::CreditUpdate {
            local_port,
            peer_port,
            fwd_cnt,
        } => {
            pkt.set_op(uapi::VSOCK_OP_CREDIT_UPDATE)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_STREAM)
                .set_buf_alloc(defs::CONN_TX_BUF_SIZE as u32)
                .set_fwd_cnt(fwd_cnt)
                .set_len(0)
                .set_flags(0);
        }
        MuxerRx::ListenResponse {
            local_port,
            peer_port,
            result,
        } => {
            pkt.set_op(uapi::VSOCK_OP_RW)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_DGRAM);

            pkt.write_listen_rsp(TsiListenRsp { result });
            pkt.set_len(required as u32);
        }
        MuxerRx::AcceptResponse {
            local_port,
            peer_port,
            result,
        } => {
            pkt.set_op(uapi::VSOCK_OP_RW)
                .set_src_cid(uapi::VSOCK_HOST_CID)
                .set_dst_cid(cid)
                .set_src_port(local_port)
                .set_dst_port(peer_port)
                .set_type(uapi::VSOCK_TYPE_DGRAM);

            pkt.write_accept_rsp(TsiAcceptRsp { result });
            pkt.set_len(required as u32);
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use vm_memory::GuestAddress;

    use crate::virtio::descriptor_utils::DescriptorChainSnapshot;
    use crate::virtio::queue::tests::VirtQueue;
    use crate::virtio::vsock::muxer::MuxerRx;
    use crate::virtio::vsock::muxer_rxq::{MuxerRxQ, RxDrainStop};
    use crate::virtio::vsock::packet::{PacketQueue, RxPacket, TsiGetnameRsp, VSOCK_PKT_HDR_SIZE};
    use crate::virtio::{DescriptorChain, RuntimeGuestMemory};

    #[test]
    fn provider_vsock_mux_responses_complete_only_initialized_payload_bytes() {
        for capacity in [3u32, 4, 23, 24, 132] {
            for kind in 0..4 {
                let memory =
                    RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
                let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
                ring.dtable[0].set(0x4000, VSOCK_PKT_HDR_SIZE as u32, 3, 1);
                ring.dtable[1].set(0x5000, capacity, 2, 0);
                ring.avail.ring[0].set(0);
                ring.avail.idx.set(1);
                memory
                    .write_slice(&[0xa5; VSOCK_PKT_HDR_SIZE], GuestAddress(0x4000))
                    .unwrap();
                memory
                    .write_slice(&vec![0xa5; capacity as usize], GuestAddress(0x5000))
                    .unwrap();
                let mut queue = PacketQueue::from_queue(ring.create_queue());
                let response = match kind {
                    0 => MuxerRx::ConnResponse {
                        local_port: 7,
                        peer_port: 9,
                        result: -5,
                    },
                    1 => MuxerRx::ListenResponse {
                        local_port: 7,
                        peer_port: 9,
                        result: -5,
                    },
                    2 => MuxerRx::AcceptResponse {
                        local_port: 7,
                        peer_port: 9,
                        result: -5,
                    },
                    _ => MuxerRx::GetnameResponse {
                        local_port: 7,
                        peer_port: 9,
                        data: TsiGetnameRsp::default(),
                    },
                };
                let required = if kind == 3 { 24u32 } else { 4 };
                let mut responses = MuxerRxQ::new();
                assert!(responses.push(response));
                let drained = responses.drain(3, &mut queue, &memory);
                assert!(drained.used_queue);
                assert_eq!(ring.used.idx.get(), 1);
                let used = ring.used.ring[0].get();
                assert_eq!(used.id, 0);
                let mut bytes = vec![0; capacity as usize];
                memory.read_slice(&mut bytes, GuestAddress(0x5000)).unwrap();
                if capacity < required {
                    assert!(drained.stop == RxDrainStop::NoBuffer);
                    assert_eq!(responses.len(), 1);
                    assert_eq!(bytes, vec![0xa5; capacity as usize]);
                    let mut header = [0; VSOCK_PKT_HDR_SIZE];
                    memory
                        .read_slice(&mut header, GuestAddress(0x4000))
                        .unwrap();
                    assert_eq!(header, [0xa5; VSOCK_PKT_HDR_SIZE]);
                    assert_eq!(used.len, 0);
                } else {
                    assert!(drained.stop == RxDrainStop::Empty);
                    assert!(responses.is_empty());
                    let head =
                        DescriptorChain::checked_new(&memory, GuestAddress(0), 8, 0).unwrap();
                    let packet =
                        RxPacket::from_rx_virtq_head(&head, &mut DescriptorChainSnapshot::new(8))
                            .unwrap();
                    assert_eq!(packet.len(), required);
                    assert_eq!(
                        &bytes[..4],
                        &(if kind == 3 { -1i32 } else { -5 }).to_le_bytes()
                    );
                    if kind == 3 {
                        assert_eq!(&bytes[4..8], &16u32.to_le_bytes());
                    }
                    assert!(bytes[required as usize..].iter().all(|byte| *byte == 0xa5));
                    assert_eq!(used.len, VSOCK_PKT_HDR_SIZE as u32 + required);
                }
            }
        }
    }

    #[test]
    fn provider_vsock_mux_getname_rejects_invalid_source_length_before_writing() {
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        ring.dtable[0].set(0x4000, VSOCK_PKT_HDR_SIZE as u32, 3, 1);
        ring.dtable[1].set(0x5000, 132, 2, 0);
        memory
            .write_slice(&[0xa5; VSOCK_PKT_HDR_SIZE], GuestAddress(0x4000))
            .unwrap();
        ring.avail.ring[0].set(0);
        ring.avail.idx.set(1);
        let mut queue = PacketQueue::from_queue(ring.create_queue());
        let data = TsiGetnameRsp {
            addr_len: u32::MAX,
            ..TsiGetnameRsp::default()
        };
        let mut responses = MuxerRxQ::new();
        assert!(responses.push(MuxerRx::GetnameResponse {
            local_port: 7,
            peer_port: 9,
            data,
        }));
        let drained = responses.drain(3, &mut queue, &memory);
        assert!(drained.used_queue);
        assert!(drained.stop == RxDrainStop::NoBuffer);
        assert_eq!(ring.used.idx.get(), 1);
        assert_eq!(ring.used.ring[0].get().len, 0);
        assert_eq!(responses.len(), 1);
        let mut header = [0; VSOCK_PKT_HDR_SIZE];
        memory
            .read_slice(&mut header, GuestAddress(0x4000))
            .unwrap();
        assert_eq!(header, [0xa5; VSOCK_PKT_HDR_SIZE]);
    }
}
