// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//

//! Bounded ordered protocol responses, retained with the source mux while parked.
use std::collections::VecDeque;

use crate::virtio::vsock::defs;
use crate::virtio::vsock::defs::uapi;
use crate::virtio::vsock::muxer::MuxerRx;
use crate::virtio::vsock::packet::{RxPacket, TsiAcceptRsp, TsiConnectRsp, TsiListenRsp};

/// The muxer RX queue.
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
    pub fn push(&mut self, rx: MuxerRx) -> Result<(), Box<MuxerRx>> {
        if !self.is_full() {
            self.q.push_back(rx);
            return Ok(());
        }

        Err(Box::new(rx))
    }

    pub(crate) fn fill_packet(
        &mut self,
        cid: u64,
        packet: &mut RxPacket,
    ) -> crate::virtio::vsock::Result<()> {
        let Some(rx) = self.q.pop_front() else {
            return Err(crate::virtio::vsock::VsockError::NoData);
        };
        match rx_to_pkt(cid, rx, packet) {
            Ok(()) => Ok(()),
            Err(rx) => {
                self.q.push_front(*rx);
                Err(crate::virtio::vsock::VsockError::BufDescTooSmall)
            }
        }
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

pub(crate) fn rx_to_pkt(cid: u64, rx: MuxerRx, pkt: &mut RxPacket) -> Result<(), Box<MuxerRx>> {
    let required = match &rx {
        MuxerRx::ConnResponse { .. }
        | MuxerRx::ListenResponse { .. }
        | MuxerRx::AcceptResponse { .. } => 4,
        MuxerRx::GetnameResponse { data, .. } => {
            let Some(length) = data.payload_len() else {
                return Err(Box::new(rx));
            };
            length
        }
        _ => 0,
    };
    let buffer_len = pkt.buf().map_or(0, |buffer| buffer.len() as u32);
    if (buffer_len as usize) < required {
        return Err(Box::new(rx));
    }
    match rx {
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
            data,
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use vm_memory::GuestAddress;

    use crate::virtio::RuntimeGuestMemory;
    use crate::virtio::descriptor_utils::DescriptorChainSnapshot;
    use crate::virtio::queue::tests::VirtQueue;
    use crate::virtio::vsock::VsockError;
    use crate::virtio::vsock::muxer::MuxerRx;
    use crate::virtio::vsock::muxer_rxq::MuxerRxQ;
    use crate::virtio::vsock::packet::{RxPacket, TsiGetnameRsp, VSOCK_PKT_HDR_SIZE};

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
                let mut queue = ring.create_queue();
                let head = queue.pop(&memory).unwrap();
                let mut packet =
                    RxPacket::from_rx_virtq_head(&head, &mut DescriptorChainSnapshot::new(8))
                        .unwrap();
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
                responses.push(response).unwrap();
                let result = responses.fill_packet(3, &mut packet);
                let mut bytes = vec![0; capacity as usize];
                packet.buf().unwrap().read_slice(&mut bytes, 0).unwrap();
                if capacity < required {
                    assert!(matches!(result, Err(VsockError::BufDescTooSmall)));
                    assert_eq!(responses.len(), 1);
                    assert_eq!(bytes, vec![0xa5; capacity as usize]);
                    let mut header = [0; VSOCK_PKT_HDR_SIZE];
                    memory
                        .read_slice(&mut header, GuestAddress(0x4000))
                        .unwrap();
                    assert_eq!(header, [0xa5; VSOCK_PKT_HDR_SIZE]);
                    queue.undo_pop(head.index).unwrap();
                    assert_eq!(ring.used.idx.get(), 0);
                } else {
                    result.unwrap();
                    assert!(responses.is_empty());
                    assert_eq!(packet.len(), required);
                    assert_eq!(
                        &bytes[..4],
                        &(if kind == 3 { -1i32 } else { -5 }).to_le_bytes()
                    );
                    if kind == 3 {
                        assert_eq!(&bytes[4..8], &16u32.to_le_bytes());
                    }
                    assert!(bytes[required as usize..].iter().all(|byte| *byte == 0xa5));
                    queue
                        .add_used(
                            &memory,
                            head.index,
                            VSOCK_PKT_HDR_SIZE as u32 + packet.len(),
                        )
                        .unwrap();
                    assert_eq!(ring.used.idx.get(), 1);
                    let used = ring.used.ring[0].get();
                    assert_eq!(used.id, u32::from(head.index));
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
        let head =
            crate::virtio::DescriptorChain::checked_new(&memory, GuestAddress(0), 8, 0).unwrap();
        let mut packet =
            RxPacket::from_rx_virtq_head(&head, &mut DescriptorChainSnapshot::new(8)).unwrap();
        let data = TsiGetnameRsp {
            addr_len: u32::MAX,
            ..TsiGetnameRsp::default()
        };
        let mut responses = MuxerRxQ::new();
        responses
            .push(MuxerRx::GetnameResponse {
                local_port: 7,
                peer_port: 9,
                data,
            })
            .unwrap();
        assert!(matches!(
            responses.fill_packet(3, &mut packet),
            Err(VsockError::BufDescTooSmall)
        ));
        assert_eq!(responses.len(), 1);
        let mut header = [0; VSOCK_PKT_HDR_SIZE];
        memory
            .read_slice(&mut header, GuestAddress(0x4000))
            .unwrap();
        assert_eq!(header, [0xa5; VSOCK_PKT_HDR_SIZE]);
    }
}
