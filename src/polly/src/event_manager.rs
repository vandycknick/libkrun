// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt::Formatter;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(target_os = "windows")]
use utils::windows::{AsRawFd, RawFd};

use utils::epoll::{self, Epoll, EpollEvent};

pub type Result<T> = std::result::Result<T, Error>;
pub type Pollable = RawFd;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BarrierGeneration(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BarrierKey {
    pub operation: OperationId,
    pub generation: BarrierGeneration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BarrierRequest {
    pub key: BarrierKey,
    pub deadline: Instant,
}

/// Completion callbacks may only finish work whose provider has closed admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchRole {
    Ingress,
    Completion,
    Control,
    Exit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchPhase {
    Draining,
    Parked,
}

struct DispatchFence {
    request: BarrierRequest,
    phase: DispatchPhase,
}

struct Registration {
    identity: u64,
    subscriber: Arc<Mutex<dyn Subscriber>>,
    interest: EpollEvent,
    role: DispatchRole,
    installed: bool,
    pending: u32,
}

/// Errors associated with epoll events handling.
pub enum Error {
    /// Cannot create epoll fd.
    EpollCreate(io::Error),
    /// Polling I/O error.
    Poll(io::Error),
    /// The specified pollable already registered.
    AlreadyExists(Pollable),
    /// The specified pollable is not registered.
    NotFound(Pollable),
    PoisonedSubscriber,
    RegistrationExhausted,
    BarrierActive(BarrierKey),
    ForeignBarrier(BarrierKey),
    Deadline(BarrierKey),
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::Error::*;

        match self {
            EpollCreate(err) => write!(f, "Unable to create epoll fd: {err}"),
            Poll(err) => write!(f, "Error during epoll call: {err}"),
            AlreadyExists(pollable) => write!(
                f,
                "A handler for the specified pollable {:?} already exists.",
                pollable
            ),
            NotFound(pollable) => write!(
                f,
                "A handler for the specified pollable {:?} was not found.",
                pollable
            ),
            PoisonedSubscriber => write!(f, "Subscriber lock is poisoned"),
            RegistrationExhausted => write!(f, "Event registration identity exhausted"),
            BarrierActive(key) => write!(f, "Callback barrier {key:?} is already active"),
            ForeignBarrier(key) => write!(f, "Callback barrier {key:?} does not own the fence"),
            Deadline(key) => write!(f, "Callback barrier {key:?} exceeded its deadline"),
        }
    }
}

/// A trait to express the ability to respond to I/O event readiness
/// using callbacks.
pub trait Subscriber {
    /// Callback called when an event is available.
    ///
    /// # Arguments
    /// * event - the available `EpollEvent` ready for processing
    /// * event_manager - Reference to the `EventManager` that gives the implementor
    ///   the possibility to directly call the required update operations.
    ///
    /// Registration and fence operations are nonblocking. A callback must never
    /// wait for work that needs this owner or its subscriber lock.
    fn process(&mut self, event: &EpollEvent, event_manager: &mut EventManager);

    /// Returns a list of `EpollEvent` that this subscriber is interested in.
    fn interest_list(&self) -> Vec<EpollEvent>;
}

/// Manages I/O notifications using epoll mechanism.
pub struct EventManager {
    epoll: Epoll,
    subscribers: HashMap<RawFd, Registration>,
    registrations: HashMap<u64, RawFd>,
    next_registration: u64,
    fence: Option<DispatchFence>,
    ready_events: Vec<EpollEvent>,
}

impl AsRawFd for EventManager {
    fn as_raw_fd(&self) -> RawFd {
        self.epoll.as_raw_fd()
    }
}

impl EventManager {
    const EVENT_BUFFER_SIZE: usize = 128;

    /// Create a new EventManager.
    pub fn new() -> Result<EventManager> {
        let epoll_fd = epoll::Epoll::new().map_err(Error::EpollCreate)?;

        Ok(EventManager {
            epoll: epoll_fd,
            subscribers: HashMap::new(),
            registrations: HashMap::new(),
            next_registration: 1,
            fence: None,
            // This buffer is used for storing the events returned by `epoll_wait()`.
            // We preallocate memory for this buffer in order to not repeat this
            // operation every time `run()` loop is executed.
            ready_events: vec![epoll::EpollEvent::default(); EventManager::EVENT_BUFFER_SIZE],
        })
    }

    /// Returns a clone of the subscriber associated with the `fd`.
    pub fn subscriber(&self, fd: Pollable) -> Result<Arc<Mutex<dyn Subscriber>>> {
        self.subscribers
            .get(&fd)
            .map(|registration| registration.subscriber.clone())
            .ok_or(Error::NotFound(fd))
    }

    /// Register a new subscriber. All events that the subscriber is interested are registered.
    ///
    // TODO: Remove this workaround method. The desired state in the future is for each
    // subscriber to call `register` directly when it needs to register an event and not have
    // all events registered at once. This way we can also remove the `interest_list` which is
    // only used once in this function.
    pub fn add_subscriber(&mut self, subscriber: Arc<Mutex<dyn Subscriber>>) -> Result<()> {
        let interest_list = subscriber
            .lock()
            .map_err(|_| Error::PoisonedSubscriber)?
            .interest_list();

        for event in interest_list {
            self.register(event.data() as Pollable, event, subscriber.clone())?
        }

        Ok(())
    }

    /// Register a new `pollable` file descriptor with the corresponding `epoll_event`
    /// for `subscriber`.
    pub fn register(
        &mut self,
        pollable: Pollable,
        epoll_event: EpollEvent,
        subscriber: Arc<Mutex<dyn Subscriber>>,
    ) -> Result<()> {
        self.register_with_role(pollable, epoll_event, subscriber, DispatchRole::Ingress)
    }

    pub fn register_with_role(
        &mut self,
        pollable: Pollable,
        interest: EpollEvent,
        subscriber: Arc<Mutex<dyn Subscriber>>,
        role: DispatchRole,
    ) -> Result<()> {
        if self.subscribers.contains_key(&pollable) {
            return Err(Error::AlreadyExists(pollable));
        }
        let identity = self.next_registration;
        self.next_registration = identity
            .checked_add(1)
            .ok_or(Error::RegistrationExhausted)?;
        let installed = self.permits(role);
        if installed {
            let event = EpollEvent::new(interest.event_set(), identity);
            self.epoll
                .ctl(epoll::ControlOperation::Add, pollable, &event)
                .map_err(Error::Poll)?;
        }
        self.subscribers.insert(
            pollable,
            Registration {
                identity,
                subscriber,
                interest,
                role,
                installed,
                pending: 0,
            },
        );
        self.registrations.insert(identity, pollable);
        Ok(())
    }

    /// Unregister the `pollable` file descriptor.
    pub fn unregister(&mut self, pollable: Pollable) -> Result<()> {
        let registration = self
            .subscribers
            .get(&pollable)
            .ok_or(Error::NotFound(pollable))?;
        if registration.installed {
            self.epoll
                .ctl(
                    epoll::ControlOperation::Delete,
                    pollable,
                    &EpollEvent::default(),
                )
                .map_err(Error::Poll)?;
        }
        self.registrations.remove(&registration.identity);
        self.subscribers.remove(&pollable);
        Ok(())
    }

    /// Update the events monitored by `pollable`.
    pub fn modify(&mut self, pollable: Pollable, epoll_event: EpollEvent) -> Result<()> {
        let registration = self
            .subscribers
            .get_mut(&pollable)
            .ok_or(Error::NotFound(pollable))?;
        if registration.installed {
            let event = EpollEvent::new(epoll_event.event_set(), registration.identity);
            self.epoll
                .ctl(epoll::ControlOperation::Modify, pollable, &event)
                .map_err(Error::Poll)?;
        }
        registration.interest = epoll_event;
        Ok(())
    }

    /// Check if a file descriptor is pollable
    pub fn is_pollable(&mut self, pollable: Pollable) -> bool {
        self.epoll
            .ctl(
                epoll::ControlOperation::Add,
                pollable,
                &epoll::EpollEvent::default(),
            )
            .is_ok_and(|_| {
                self.epoll
                    .ctl(
                        epoll::ControlOperation::Delete,
                        pollable,
                        &epoll::EpollEvent::default(),
                    )
                    .is_ok()
            })
    }

    pub fn set_dispatch_role(&mut self, pollable: Pollable, role: DispatchRole) -> Result<()> {
        if let Some(fence) = &self.fence {
            return Err(Error::BarrierActive(fence.request.key));
        }
        self.subscribers
            .get_mut(&pollable)
            .ok_or(Error::NotFound(pollable))?
            .role = role;
        Ok(())
    }

    pub fn dispatch_fence(&self) -> Option<(BarrierRequest, DispatchPhase)> {
        self.fence
            .as_ref()
            .map(|fence| (fence.request, fence.phase))
    }

    pub fn begin_ingress_fence(&mut self, request: BarrierRequest) -> Result<()> {
        if let Some(fence) = &self.fence {
            return Err(Error::BarrierActive(fence.request.key));
        }
        Self::check_deadline(request)?;
        self.fence = Some(DispatchFence {
            request,
            phase: DispatchPhase::Draining,
        });
        self.suspend_disallowed()?;
        Self::check_deadline(request)
    }

    pub fn park_callbacks(&mut self, key: BarrierKey) -> Result<()> {
        let fence = self.fence.as_mut().ok_or(Error::ForeignBarrier(key))?;
        if fence.request.key != key {
            return Err(Error::ForeignBarrier(key));
        }
        Self::check_deadline(fence.request)?;
        fence.phase = DispatchPhase::Parked;
        let request = fence.request;
        self.suspend_disallowed()?;
        Self::check_deadline(request)
    }

    /// Safety closure cannot be refused merely because an operation timed out.
    /// Per-callback admission closes before any fallible epoll modification.
    pub fn fail_closed(&mut self, request: BarrierRequest) -> Result<()> {
        self.fence = Some(DispatchFence {
            request,
            phase: DispatchPhase::Parked,
        });
        self.suspend_disallowed()
    }

    /// Call only after source routes and producers are prepared, before CPU release.
    /// A cancellation has its own request/deadline and names the original fence.
    pub fn reopen_ingress(&mut self, key: BarrierKey, request: BarrierRequest) -> Result<()> {
        let fence = self.fence.as_ref().ok_or(Error::ForeignBarrier(key))?;
        if fence.request.key != key
            || request.key.generation != key.generation
            || request.key.operation == key.operation
        {
            return Err(Error::ForeignBarrier(key));
        }
        Self::check_deadline(request)?;
        let restored = self
            .restore_interests()
            .and_then(|()| Self::check_deadline(request));
        if let Err(error) = restored {
            self.suspend_disallowed()?;
            return Err(error);
        }
        self.fence = None;
        Ok(())
    }

    fn restore_interests(&mut self) -> Result<()> {
        for (fd, registration) in &mut self.subscribers {
            if !registration.installed {
                let event =
                    EpollEvent::new(registration.interest.event_set(), registration.identity);
                self.epoll
                    .ctl(epoll::ControlOperation::Add, *fd, &event)
                    .map_err(Error::Poll)?;
                registration.installed = true;
            }
        }
        Ok(())
    }

    fn check_deadline(request: BarrierRequest) -> Result<()> {
        if Instant::now() >= request.deadline {
            return Err(Error::Deadline(request.key));
        }
        Ok(())
    }

    fn permits(&self, role: DispatchRole) -> bool {
        match (&self.fence, role) {
            (None, _) | (_, DispatchRole::Control | DispatchRole::Exit) => true,
            (Some(fence), DispatchRole::Completion) => fence.phase == DispatchPhase::Draining,
            _ => false,
        }
    }

    fn suspend_disallowed(&mut self) -> Result<()> {
        let phase = self.fence.as_ref().map(|fence| fence.phase);
        for (fd, registration) in &mut self.subscribers {
            let allowed = match registration.role {
                DispatchRole::Control | DispatchRole::Exit => true,
                DispatchRole::Completion => phase == Some(DispatchPhase::Draining),
                DispatchRole::Ingress => false,
            };
            if registration.installed && !allowed {
                self.epoll
                    .ctl(epoll::ControlOperation::Delete, *fd, &EpollEvent::default())
                    .map_err(Error::Poll)?;
                registration.installed = false;
            }
        }
        Ok(())
    }

    /// Wait for events, then dispatch to the registered event handlers.
    pub fn run(&mut self) -> Result<usize> {
        self.run_with_timeout(-1)
    }

    /// Wait for events for a maximum timeout of `miliseconds`. Dispatch the events to the
    /// registered signal handlers.
    pub fn run_with_timeout(&mut self, milliseconds: i32) -> Result<usize> {
        let mut pending_count = 0;
        for registration in self.subscribers.values() {
            if registration.pending != 0 && self.permits(registration.role) {
                self.ready_events[pending_count] = EpollEvent::new(
                    epoll::EventSet::from_bits_truncate(registration.pending),
                    registration.identity,
                );
                pending_count += 1;
                if pending_count == Self::EVENT_BUFFER_SIZE {
                    break;
                }
            }
        }
        if pending_count != 0 {
            self.dispatch_events(pending_count)?;
            return Ok(pending_count);
        }
        let event_count = match self.epoll.wait(
            EventManager::EVENT_BUFFER_SIZE,
            milliseconds,
            &mut self.ready_events[..],
        ) {
            Ok(event_count) => event_count,
            #[cfg(unix)]
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => 0,
            Err(e) => return Err(Error::Poll(e)),
        };
        self.dispatch_events(event_count)?;

        Ok(event_count)
    }

    fn dispatch_events(&mut self, event_count: usize) -> Result<()> {
        for ev_index in 0..event_count {
            let event = self.ready_events[ev_index].clone();
            let Some(fd) = self.registrations.get(&event.data()).copied() else {
                continue;
            };
            let Some(registration) = self.subscribers.get(&fd) else {
                continue;
            };
            if !self.permits(registration.role) {
                if let Some(registration) = self.subscribers.get_mut(&fd) {
                    registration.pending |= event.events();
                }
                continue;
            }
            let subscriber = registration.subscriber.clone();
            let delivered = EpollEvent::new(
                epoll::EventSet::from_bits_truncate(event.events() | registration.pending),
                registration.interest.data(),
            );
            if let Some(registration) = self.subscribers.get_mut(&fd) {
                registration.pending = 0;
            }
            subscriber
                .lock()
                .map_err(|_| Error::PoisonedSubscriber)?
                .process(&delivered, self);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::event_manager::*;
    use utils::epoll::EventSet;
    use utils::eventfd::EventFd;

    struct DummySubscriber {
        event_fd_1: EventFd,
        event_fd_2: EventFd,

        // Flags used for checking that the event manager called the `process`
        // function for ev1/ev2.
        processed_ev1_in: bool,
        processed_ev2_in: bool,

        // Flags used for driving register/unregister/modify of events from
        // outside of the `process` function.
        register_ev2: bool,
        unregister_ev1: bool,
        modify_ev1: bool,
    }

    impl DummySubscriber {
        fn new() -> Self {
            let event_fd_1 = EventFd::new(0).unwrap();
            let event_fd_2 = EventFd::new(0).unwrap();
            // On Windows the IOCP only delivers a packet when the underlying
            // Event object is signaled.  Linux eventfds are always writable
            // (EPOLLOUT fires instantly) so this isn't needed there.
            #[cfg(target_os = "windows")]
            {
                event_fd_1.write(1).unwrap();
                event_fd_2.write(1).unwrap();
            }
            DummySubscriber {
                event_fd_1,
                event_fd_2,
                processed_ev1_in: false,
                processed_ev2_in: false,
                register_ev2: false,
                unregister_ev1: false,
                modify_ev1: false,
            }
        }
    }

    impl DummySubscriber {
        fn register_ev2(&mut self) {
            self.register_ev2 = true;
        }

        fn unregister_ev1(&mut self) {
            self.unregister_ev1 = true;
        }

        fn modify_ev1(&mut self) {
            self.modify_ev1 = true;
        }

        fn processed_ev1_in(&self) -> bool {
            self.processed_ev1_in
        }

        fn processed_ev2_in(&self) -> bool {
            self.processed_ev2_in
        }

        fn reset_state(&mut self) {
            self.processed_ev1_in = false;
            self.processed_ev2_in = false;
        }

        fn handle_updates(&mut self, event_manager: &mut EventManager) {
            if self.register_ev2 {
                event_manager
                    .register(
                        self.event_fd_2.as_raw_fd(),
                        EpollEvent::new(EventSet::IN, self.event_fd_2.as_raw_fd() as u64),
                        event_manager
                            .subscriber(self.event_fd_1.as_raw_fd())
                            .unwrap(),
                    )
                    .unwrap();
                self.register_ev2 = false;
            }

            if self.unregister_ev1 {
                event_manager
                    .unregister(self.event_fd_1.as_raw_fd())
                    .unwrap();
                self.unregister_ev1 = false;
            }

            if self.modify_ev1 {
                event_manager
                    .modify(
                        self.event_fd_1.as_raw_fd(),
                        EpollEvent::new(EventSet::IN, self.event_fd_1.as_raw_fd() as u64),
                    )
                    .unwrap();
                self.modify_ev1 = false;
            }
        }

        fn handle_in(&mut self, source: RawFd) {
            match source {
                _ if self.event_fd_1.as_raw_fd() == source => {
                    self.processed_ev1_in = true;
                }
                _ if self.event_fd_2.as_raw_fd() == source => {
                    self.processed_ev2_in = true;
                }
                _ => {}
            }
        }
    }

    impl Subscriber for DummySubscriber {
        fn process(&mut self, event: &EpollEvent, event_manager: &mut EventManager) {
            let source = event.data() as Pollable;
            let event_set = EventSet::from_bits(event.events()).unwrap();

            // We only know how to treat EPOLLOUT and EPOLLIN.
            // If we received anything else just stop processing the event.
            let all_but_in_out = EventSet::all() - EventSet::OUT - EventSet::IN;
            if event_set.intersects(all_but_in_out) {
                return;
            }

            self.handle_updates(event_manager);

            if event_set.contains(EventSet::IN) {
                self.handle_in(source);
            }
        }

        fn interest_list(&self) -> Vec<EpollEvent> {
            vec![EpollEvent::new(
                EventSet::IN,
                self.event_fd_1.as_raw_fd() as u64,
            )]
        }
    }

    // Test that registering a new event while processing an existing event works.
    #[test]
    fn test_register() {
        let mut event_manager = EventManager::new().unwrap();
        let dummy_subscriber = Arc::new(Mutex::new(DummySubscriber::new()));

        // Write to eventfds to make them readable (trigger IN events).
        dummy_subscriber
            .lock()
            .unwrap()
            .event_fd_1
            .write(1)
            .unwrap();
        dummy_subscriber
            .lock()
            .unwrap()
            .event_fd_2
            .write(1)
            .unwrap();

        event_manager
            .add_subscriber(dummy_subscriber.clone())
            .unwrap();

        dummy_subscriber.lock().unwrap().register_ev2();

        // When running the loop the first time, ev1 should be processed, but ev2 shouldn't
        // because it was just added as part of processing ev1.
        event_manager.run().unwrap();
        assert!(dummy_subscriber.lock().unwrap().processed_ev1_in());
        assert!(!dummy_subscriber.lock().unwrap().processed_ev2_in());

        // Check that both ev1 and ev2 are processed.
        dummy_subscriber.lock().unwrap().reset_state();
        event_manager.run().unwrap();
        assert!(dummy_subscriber.lock().unwrap().processed_ev1_in());
        assert!(dummy_subscriber.lock().unwrap().processed_ev2_in());
    }

    // Test that unregistering an event while processing another one works.
    #[test]
    fn test_unregister() {
        let mut event_manager = EventManager::new().unwrap();
        let dummy_subscriber = Arc::new(Mutex::new(DummySubscriber::new()));

        // Write to ev1 to make it readable.
        dummy_subscriber
            .lock()
            .unwrap()
            .event_fd_1
            .write(1)
            .unwrap();

        event_manager
            .add_subscriber(dummy_subscriber.clone())
            .unwrap();

        // Disable ev1. We should only receive this event once.
        dummy_subscriber.lock().unwrap().unregister_ev1();

        event_manager.run().unwrap();
        assert!(dummy_subscriber.lock().unwrap().processed_ev1_in());

        dummy_subscriber.lock().unwrap().reset_state();

        // We expect no events to be available. Let's run with timeout so that run exists.
        event_manager.run_with_timeout(100).unwrap();
        assert!(!dummy_subscriber.lock().unwrap().processed_ev1_in());
    }

    #[test]
    fn test_modify() {
        let mut event_manager = EventManager::new().unwrap();
        let dummy_subscriber = Arc::new(Mutex::new(DummySubscriber::new()));

        // Write to ev1 to make it readable.
        dummy_subscriber
            .lock()
            .unwrap()
            .event_fd_1
            .write(1)
            .unwrap();

        event_manager
            .add_subscriber(dummy_subscriber.clone())
            .unwrap();

        // Modify ev1 (exercises the modify code path).
        dummy_subscriber.lock().unwrap().modify_ev1();
        event_manager.run().unwrap();
        assert!(dummy_subscriber.lock().unwrap().processed_ev1_in());
        assert!(!dummy_subscriber.lock().unwrap().processed_ev2_in());

        dummy_subscriber.lock().unwrap().reset_state();

        // ev1 should still fire after modification (data still readable).
        event_manager.run().unwrap();
        assert!(dummy_subscriber.lock().unwrap().processed_ev1_in());
        assert!(!dummy_subscriber.lock().unwrap().processed_ev2_in());

        // Create a valid epoll event, but do not register it to check error path for modify.
        let event_fd = EventFd::new(0).unwrap();
        let event = EpollEvent::new(EventSet::IN, event_fd.as_raw_fd() as u64);
        let result = event_manager.modify(event_fd.as_raw_fd(), event);
        match result {
            Err(Error::NotFound(_)) => {}
            _ => panic!("Modifying event did not fail with expected error."),
        };
    }

    // Test that registering the same event twice throws an error.
    #[test]
    fn test_register_errors() {
        let mut event_manager = EventManager::new().unwrap();
        let dummy_subscriber = Arc::new(Mutex::new(DummySubscriber::new()));

        event_manager
            .add_subscriber(dummy_subscriber.clone())
            .unwrap();

        assert!(event_manager.add_subscriber(dummy_subscriber).is_err())
    }

    #[test]
    fn test_unregister_errors() {
        let mut event_manager = EventManager::new().unwrap();
        let dummy_subscriber = Arc::new(Mutex::new(DummySubscriber::new()));

        event_manager
            .add_subscriber(dummy_subscriber.clone())
            .unwrap();

        // At this point ev2 is not registered. Check that unregistering it throws an error.
        assert!(
            event_manager
                .unregister(dummy_subscriber.lock().unwrap().event_fd_2.as_raw_fd())
                .is_err()
        );

        // Try to unregister ev1 twice. Only the first call should be successful.
        assert!(
            event_manager
                .unregister(dummy_subscriber.lock().unwrap().event_fd_1.as_raw_fd())
                .is_ok()
        );
        assert!(
            event_manager
                .unregister(dummy_subscriber.lock().unwrap().event_fd_1.as_raw_fd())
                .is_err()
        );
    }

    #[test]
    fn test_get_handler() {
        let mut event_manager = EventManager::new().unwrap();
        let dummy_subscriber = Arc::new(Mutex::new(DummySubscriber::new()));

        event_manager
            .add_subscriber(dummy_subscriber.clone())
            .unwrap();

        let dummy_fd = dummy_subscriber.lock().unwrap().event_fd_1.as_raw_fd();
        assert!(event_manager.subscriber(dummy_fd).is_ok());

        #[cfg(unix)]
        let bad_fd: Pollable = -1;
        #[cfg(windows)]
        let bad_fd: Pollable = std::ptr::null_mut();
        assert!(event_manager.subscriber(bad_fd).is_err());
    }

    struct EventConsumer {
        event: EventFd,
        consumed: u64,
        close_ingress: Option<BarrierRequest>,
    }

    impl Subscriber for EventConsumer {
        fn process(&mut self, _: &EpollEvent, manager: &mut EventManager) {
            self.consumed += self.event.read().unwrap();
            if let Some(request) = self.close_ingress.take() {
                manager.begin_ingress_fence(request).unwrap();
            }
        }

        fn interest_list(&self) -> Vec<EpollEvent> {
            vec![EpollEvent::new(EventSet::IN, self.event.as_raw_fd() as u64)]
        }
    }

    fn barrier_request(operation: u64) -> BarrierRequest {
        BarrierRequest {
            key: BarrierKey {
                operation: OperationId(operation),
                generation: BarrierGeneration(1),
            },
            deadline: Instant::now() + std::time::Duration::from_secs(10),
        }
    }

    fn consumer(manager: &mut EventManager, role: DispatchRole) -> Arc<Mutex<EventConsumer>> {
        let consumer = Arc::new(Mutex::new(EventConsumer {
            event: EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
            consumed: 0,
            close_ingress: None,
        }));
        manager.add_subscriber(consumer.clone()).unwrap();
        manager
            .set_dispatch_role(consumer.lock().unwrap().event.as_raw_fd(), role)
            .unwrap();
        consumer
    }

    #[test]
    fn callback_fence_gates_already_fetched_batch_and_replays_readiness() {
        let mut manager = EventManager::new().unwrap();
        let request = barrier_request(1);
        let control = consumer(&mut manager, DispatchRole::Control);
        let ingress = consumer(&mut manager, DispatchRole::Ingress);
        control.lock().unwrap().close_ingress = Some(request);
        control.lock().unwrap().event.write(1).unwrap();
        ingress.lock().unwrap().event.write(7).unwrap();
        let count = manager
            .epoll
            .wait(128, 0, &mut manager.ready_events)
            .unwrap();
        assert_eq!(count, 2);
        let control_fd = control.lock().unwrap().event.as_raw_fd();
        let control_identity = manager.subscribers[&control_fd].identity;
        if manager.ready_events[0].data() != control_identity {
            manager.ready_events.swap(0, 1);
        }
        manager.dispatch_events(count).unwrap();
        assert_eq!(control.lock().unwrap().consumed, 1);
        assert_eq!(ingress.lock().unwrap().consumed, 0);
        assert_eq!(manager.run_with_timeout(0).unwrap(), 0);
        manager
            .reopen_ingress(request.key, barrier_request(2))
            .unwrap();
        manager.run_with_timeout(0).unwrap();
        assert_eq!(ingress.lock().unwrap().consumed, 7);
    }

    #[test]
    fn callback_fence_keeps_completion_control_exit_until_parked() {
        let mut manager = EventManager::new().unwrap();
        let completion = consumer(&mut manager, DispatchRole::Completion);
        let control = consumer(&mut manager, DispatchRole::Control);
        let exit = consumer(&mut manager, DispatchRole::Exit);
        let request = barrier_request(3);
        manager.begin_ingress_fence(request).unwrap();
        completion.lock().unwrap().event.write(1).unwrap();
        control.lock().unwrap().event.write(1).unwrap();
        exit.lock().unwrap().event.write(1).unwrap();
        assert_eq!(manager.run_with_timeout(0).unwrap(), 3);
        manager.park_callbacks(request.key).unwrap();
        completion.lock().unwrap().event.write(2).unwrap();
        control.lock().unwrap().event.write(2).unwrap();
        exit.lock().unwrap().event.write(2).unwrap();
        assert_eq!(manager.run_with_timeout(0).unwrap(), 2);
        assert_eq!(completion.lock().unwrap().consumed, 1);
        assert_eq!(control.lock().unwrap().consumed, 3);
        assert_eq!(exit.lock().unwrap().consumed, 3);
        assert!(
            manager
                .reopen_ingress(barrier_request(99).key, barrier_request(4))
                .is_err()
        );
        manager
            .reopen_ingress(request.key, barrier_request(4))
            .unwrap();
        manager.run_with_timeout(0).unwrap();
        assert_eq!(completion.lock().unwrap().consumed, 3);
    }

    #[test]
    fn callback_registration_identity_rejects_stale_cached_event() {
        let mut manager = EventManager::new().unwrap();
        let subscriber = consumer(&mut manager, DispatchRole::Ingress);
        subscriber.lock().unwrap().event.write(5).unwrap();
        let count = manager
            .epoll
            .wait(128, 0, &mut manager.ready_events)
            .unwrap();
        assert_eq!(count, 1);
        let fd = subscriber.lock().unwrap().event.as_raw_fd();
        manager.unregister(fd).unwrap();
        manager.add_subscriber(subscriber.clone()).unwrap();
        manager.dispatch_events(count).unwrap();
        assert_eq!(subscriber.lock().unwrap().consumed, 0);
        manager.run_with_timeout(0).unwrap();
        assert_eq!(subscriber.lock().unwrap().consumed, 5);
    }

    #[test]
    fn callback_fence_preserves_edge_oneshot_and_expired_reopen() {
        let mut manager = EventManager::new().unwrap();
        let subscriber = consumer(&mut manager, DispatchRole::Ingress);
        let fd = subscriber.lock().unwrap().event.as_raw_fd();
        manager
            .modify(
                fd,
                EpollEvent::new(
                    EventSet::IN | EventSet::EDGE_TRIGGERED | EventSet::ONE_SHOT,
                    fd as u64,
                ),
            )
            .unwrap();
        subscriber.lock().unwrap().event.write(9).unwrap();
        let count = manager
            .epoll
            .wait(128, 0, &mut manager.ready_events)
            .unwrap();
        assert_eq!(count, 1);
        let request = barrier_request(5);
        manager.begin_ingress_fence(request).unwrap();
        manager.dispatch_events(count).unwrap();
        let expired = BarrierRequest {
            deadline: Instant::now(),
            ..barrier_request(6)
        };
        assert!(matches!(
            manager.reopen_ingress(request.key, expired),
            Err(Error::Deadline(_))
        ));
        assert_eq!(manager.run_with_timeout(0).unwrap(), 0);
        manager
            .reopen_ingress(request.key, barrier_request(6))
            .unwrap();
        manager.run_with_timeout(0).unwrap();
        assert_eq!(subscriber.lock().unwrap().consumed, 9);
    }

    #[test]
    fn callback_failed_release_fences_expired_cached_readiness() {
        let mut manager = EventManager::new().unwrap();
        let ingress = consumer(&mut manager, DispatchRole::Ingress);
        let completion = consumer(&mut manager, DispatchRole::Completion);
        let control = consumer(&mut manager, DispatchRole::Control);
        let write_event = |subscriber: &Arc<Mutex<EventConsumer>>| match subscriber.lock() {
            Ok(subscriber) => subscriber.event.write(1).unwrap(),
            Err(error) => panic!("event subscriber poisoned: {error}"),
        };
        write_event(&ingress);
        write_event(&completion);
        write_event(&control);
        let count = manager
            .epoll
            .wait(128, 0, &mut manager.ready_events)
            .unwrap();
        assert_eq!(count, 3);
        let request = BarrierRequest {
            deadline: Instant::now(),
            ..barrier_request(8)
        };
        manager.fail_closed(request).unwrap();
        manager.dispatch_events(count).unwrap();
        let consumed = |subscriber: &Arc<Mutex<EventConsumer>>| match subscriber.lock() {
            Ok(subscriber) => subscriber.consumed,
            Err(error) => panic!("event subscriber poisoned: {error}"),
        };
        assert_eq!(consumed(&ingress), 0);
        assert_eq!(consumed(&completion), 0);
        assert_eq!(consumed(&control), 1);
        assert_eq!(manager.run_with_timeout(0).unwrap(), 0);
        assert_eq!(
            manager.dispatch_fence(),
            Some((request, DispatchPhase::Parked))
        );
    }
}
