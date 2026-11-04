#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use utils::windows::AsRawFd;

use polly::event_manager::{Error as EventManagerError, EventManager, Subscriber};
use std::sync::Arc;
use utils::epoll::{EpollEvent, EventSet};

use crate::virtio::balloon::device::{
    Balloon, DFQ_INDEX, FRQ_INDEX, IFQ_INDEX, PHQ_INDEX, STQ_INDEX,
};
use crate::virtio::device::VirtioDevice;
use crate::virtio::lifecycle::ProviderFault;

impl Balloon {
    fn handle_queue_event(&mut self, index: usize, event: &EpollEvent) {
        if !self.callbacks.admission_open() || event.event_set() != EventSet::IN {
            return;
        }
        let Some(queue) = self.queues.as_ref().and_then(|queues| queues.get(index)) else {
            self.callbacks.retain_fault(ProviderFault::QueueCount);
            return;
        };
        if let Err(error) = queue.event.read() {
            if error.kind() != std::io::ErrorKind::WouldBlock {
                self.callbacks.retain_fault(ProviderFault::Notification);
            }
            return;
        }
        match index {
            FRQ_INDEX => self.process_and_notify(),
            STQ_INDEX => debug!("balloon: stats queue event (ignored)"),
            IFQ_INDEX | DFQ_INDEX | PHQ_INDEX => {
                error!("balloon: unsupported queue event: {index}")
            }
            _ => self.callbacks.retain_fault(ProviderFault::QueueCount),
        }
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
        let Some(queues) = &self.queues else {
            self.callbacks.retain_fault(ProviderFault::QueueCount);
            return;
        };
        for queue in queues {
            let fd = queue.event.as_raw_fd();
            let registration = match event_manager.subscriber(fd) {
                Ok(existing) if Arc::ptr_eq(&existing, &subscriber) => Ok(()),
                Ok(_) => Err(EventManagerError::AlreadyExists(fd)),
                Err(EventManagerError::NotFound(missing)) if missing == fd => event_manager
                    .register(
                        fd,
                        EpollEvent::new(EventSet::IN, fd as u64),
                        subscriber.clone(),
                    ),
                Err(error) => Err(error),
            };
            if let Err(error) = registration {
                error!("balloon: failed queue callback registration: {error:?}");
                self.callbacks.retain_fault(ProviderFault::Notification);
                return;
            }
        }
        if event_manager
            .unregister(self.activate_evt.as_raw_fd())
            .is_err()
        {
            self.callbacks.retain_fault(ProviderFault::Notification);
        }
    }
}

impl Subscriber for Balloon {
    fn process(&mut self, event: &EpollEvent, event_manager: &mut EventManager) {
        if !self.callbacks.admission_open() {
            return;
        }
        if event.fd() == self.activate_evt.as_raw_fd() {
            self.handle_activate_event(event_manager);
            return;
        }
        if self.is_activated()
            && let Some(index) = self.queues.as_ref().and_then(|queues| {
                queues
                    .iter()
                    .position(|queue| queue.event.as_raw_fd() == event.fd())
            })
        {
            self.handle_queue_event(index, event);
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
