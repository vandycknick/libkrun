// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use utils::windows::AsRawFd;

use polly::event_manager::{EventManager, Subscriber};
use utils::epoll::{EpollEvent, EventSet};

use crate::virtio::VirtioDevice;
use crate::virtio::vsock::device::{EVQ_INDEX, RXQ_INDEX, TXQ_INDEX, Vsock};

impl Vsock {
    pub(crate) fn handle_rxq_event(&mut self, event: &EpollEvent) -> bool {
        debug!("RX queue event");

        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("rxq unexpected event {event_set:?}");
            return false;
        }

        let mut raise_irq = false;
        if let Err(e) = self.queue_events[RXQ_INDEX].read() {
            error!("Failed to get vsock rx queue event: {e:?}");
        } else {
            raise_irq |= self.process_stream_rx();
        }
        raise_irq
    }

    pub(crate) fn handle_txq_event(&mut self, event: &EpollEvent) -> bool {
        debug!("TX queue event");

        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("txq unexpected event {event_set:?}");
            return false;
        }

        let mut raise_irq = false;
        if let Err(e) = self.queue_events[TXQ_INDEX].read() {
            error!("Failed to get vsock tx queue event: {e:?}");
        } else {
            raise_irq |= self.process_stream_tx();
            // The backend may have queued up responses to the packets we sent during
            // TX queue processing. If that happened, we need to fetch those responses
            // and place them into RX buffers.
            if self.muxer.has_pending_rx() {
                raise_irq |= self.process_stream_rx();
            }
        }
        raise_irq
    }

    fn handle_evq_event(&mut self, event: &EpollEvent) -> bool {
        debug!("event queue event");

        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("evq unexpected event {event_set:?}");
            return false;
        }

        if let Err(e) = self.queue_events[EVQ_INDEX].read() {
            error!("Failed to consume vsock evq event: {e:?}");
        }
        self.process_transport_reset()
    }

    fn handle_activate_event(&mut self, event_manager: &mut EventManager) {
        if let Err(error) = self.activate_evt.read()
            && error.kind() != std::io::ErrorKind::WouldBlock
        {
            self.provider
                .retain_fault(crate::virtio::lifecycle::ProviderFault::Notification);
            return;
        }
        let Ok(subscriber) = event_manager.subscriber(self.activate_evt.as_raw_fd()) else {
            self.provider
                .retain_fault(crate::virtio::lifecycle::ProviderFault::Notification);
            return;
        };
        for event in &self.queue_events {
            if let Err(error) = event_manager.register(
                event.as_raw_fd(),
                EpollEvent::new(EventSet::IN, event.as_raw_fd() as u64),
                subscriber.clone(),
            ) {
                log::error!("failed to register vsock queue callback: {error:?}");
                self.provider
                    .retain_fault(crate::virtio::lifecycle::ProviderFault::Notification);
            }
        }
        if let Err(error) = event_manager.unregister(self.activate_evt.as_raw_fd()) {
            log::error!("failed to unregister vsock activation callback: {error:?}");
            self.provider
                .retain_fault(crate::virtio::lifecycle::ProviderFault::Notification);
        }
        let used =
            self.process_transport_reset() | self.process_stream_tx() | self.process_stream_rx();
        if used {
            self.signal_used_queue();
        }
    }
}

impl Subscriber for Vsock {
    fn process(&mut self, event: &EpollEvent, event_manager: &mut EventManager) {
        if !self.is_activated() || !self.provider.callback_allowed() {
            return;
        }
        let source = event.fd();
        let rxq = self.queue_events[RXQ_INDEX].as_raw_fd();
        let txq = self.queue_events[TXQ_INDEX].as_raw_fd();
        let evq = self.queue_events[EVQ_INDEX].as_raw_fd();
        //let backend = self.backend.as_raw_fd();
        let activate_evt = self.activate_evt.as_raw_fd();

        if self.is_activated() {
            let mut raise_irq = false;
            match source {
                _ if source == rxq => raise_irq = self.handle_rxq_event(event),
                _ if source == txq => raise_irq = self.handle_txq_event(event),
                _ if source == evq => raise_irq = self.handle_evq_event(event),
                /*
                _ if source == backend => {
                    raise_irq = self.notify_backend(event);
                }
                */
                _ if source == activate_evt => {
                    self.handle_activate_event(event_manager);
                }
                _ => warn!("Unexpected vsock event received: {source:?}"),
            }
            if raise_irq {
                debug!("raising IRQ");
                self.signal_used_queue();
            }
        } else {
            warn!("The device is not yet activated. Spurious event received: {source:?}");
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        vec![EpollEvent::new(
            EventSet::IN,
            self.activate_evt.as_raw_fd() as u64,
        )]
    }
}
