#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(target_os = "windows")]
use utils::windows::AsRawFd;

use polly::event_manager::{Error as EventManagerError, EventManager, Subscriber};
use std::sync::Arc;
use utils::epoll::{EpollEvent, EventSet};

use crate::virtio::device::VirtioDevice;
use crate::virtio::lifecycle::ProviderFault;
use crate::virtio::rng::device::{REQ_INDEX, Rng};

impl Rng {
    pub(crate) fn handle_req_event(&mut self, event: &EpollEvent) {
        if !self.callbacks.admission_open() || event.event_set() != EventSet::IN {
            return;
        }
        let Some(queue_event) = self.queue_event(REQ_INDEX) else {
            self.callbacks.retain_fault(ProviderFault::QueueCount);
            return;
        };
        if let Err(error) = queue_event.read() {
            if error.kind() != std::io::ErrorKind::WouldBlock {
                self.callbacks.retain_fault(ProviderFault::Notification);
            }
            return;
        }
        self.process_and_notify();
    }

    fn handle_activate_event(&mut self, event_manager: &mut EventManager) {
        if let Err(error) = self.activate_evt.read()
            && error.kind() != std::io::ErrorKind::WouldBlock
        {
            self.callbacks.retain_fault(ProviderFault::Notification);
            return;
        }
        let Ok(subscriber) = event_manager.subscriber(self.activate_evt.as_raw_fd()) else {
            self.callbacks.retain_fault(ProviderFault::Notification);
            return;
        };
        let Some(queue_event) = self.queue_event(REQ_INDEX) else {
            self.callbacks.retain_fault(ProviderFault::QueueCount);
            return;
        };
        let fd = queue_event.as_raw_fd();
        let registration = match event_manager.subscriber(fd) {
            Ok(existing) if Arc::ptr_eq(&existing, &subscriber) => Ok(()),
            Ok(_) => Err(EventManagerError::AlreadyExists(fd)),
            Err(EventManagerError::NotFound(missing)) if missing == fd => {
                event_manager.register(fd, EpollEvent::new(EventSet::IN, fd as u64), subscriber)
            }
            Err(error) => Err(error),
        };
        if let Err(error) = registration {
            error!("rng: failed queue callback registration: {error:?}");
            self.callbacks.retain_fault(ProviderFault::Notification);
            return;
        }
        if event_manager
            .unregister(self.activate_evt.as_raw_fd())
            .is_err()
        {
            self.callbacks.retain_fault(ProviderFault::Notification);
        }
    }
}

impl Subscriber for Rng {
    fn process(&mut self, event: &EpollEvent, event_manager: &mut EventManager) {
        if !self.callbacks.admission_open() {
            return;
        }
        let source = event.fd();
        if source == self.activate_evt.as_raw_fd() {
            self.handle_activate_event(event_manager);
        } else if self.is_activated()
            && self
                .queue_event(REQ_INDEX)
                .is_some_and(|queue| queue.as_raw_fd() == source)
        {
            self.handle_req_event(event);
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        if let Some(queues) = &self.queues {
            queues
                .iter()
                .map(|queue| EpollEvent::new(EventSet::IN, queue.event.as_raw_fd() as u64))
                .collect()
        } else {
            vec![EpollEvent::new(
                EventSet::IN,
                self.activate_evt.as_raw_fd() as u64,
            )]
        }
    }
}
