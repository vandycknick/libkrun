// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::thread::{self, JoinHandle};
use std::time::Instant;
use std::{fmt, io};

use crate::vmm::device_manager::quiescence::{
    AttachmentIdentity, DeviceQuiescence, LegacyAttachment, LegacyDevice, LegacyKind, ManagerError,
};
use devices::DeviceType;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
use devices::fdt::DeviceInfoForFDT;
use devices::legacy::IrqChip;
use kernel::cmdline as kernel_cmdline;
use kvm_ioctls::{IoEventAddress, VmFd};
use polly::event_manager::{BarrierKey, BarrierRequest};
use utils::eventfd::EventFd;

/// Errors for MMIO device manager.
#[allow(clippy::enum_variant_names)]
#[allow(unused)]
#[derive(Debug)]
pub enum Error {
    /// Failed to create MmioTransport
    CreateMmioTransport(devices::virtio::CreateMmioTransportError),
    /// Failed to perform an operation on the bus.
    BusError(devices::BusError),
    /// Appending to kernel command line failed.
    Cmdline(kernel_cmdline::Error),
    /// Failure in creating or cloning an event fd.
    EventFd(io::Error),
    /// No more IRQs are available.
    IrqsExhausted,
    /// Registering an IO Event failed.
    RegisterIoEvent(kvm_ioctls::Error),
    /// Registering an IRQ FD failed.
    RegisterIrqFd(kvm_ioctls::Error),
    Provider(devices::virtio::lifecycle::ProviderFault),
    BarrierActive,
    DeviceLock,
    /// Failed to create vhost-user device.
    #[cfg(all(feature = "vhost-user", target_os = "linux"))]
    VhostUserDevice(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::CreateMmioTransport(e) => {
                write!(f, "failed to create mmio transport for the device {e}")
            }
            Error::BusError(e) => write!(f, "failed to perform bus operation: {e}"),
            Error::Cmdline(e) => {
                write!(f, "unable to add device to kernel command line: {e}")
            }
            Error::EventFd(e) => write!(f, "failed to create or clone event descriptor: {e}"),
            Error::IrqsExhausted => write!(f, "no more IRQs are available"),
            Error::RegisterIoEvent(e) => write!(f, "failed to register IO event: {e}"),
            Error::RegisterIrqFd(e) => write!(f, "failed to register irqfd: {e}"),
            Error::Provider(e) => write!(f, "failed to bind transport attachment: {e:?}"),
            Error::BarrierActive => write!(f, "device topology is fenced"),
            Error::DeviceLock => write!(f, "device lock unavailable"),
            #[cfg(all(feature = "vhost-user", target_os = "linux"))]
            Error::VhostUserDevice(e) => write!(f, "failed to create vhost-user device: {e}"),
        }
    }
}

impl From<devices::virtio::CreateMmioTransportError> for Error {
    fn from(e: devices::virtio::CreateMmioTransportError) -> Self {
        Self::CreateMmioTransport(e)
    }
}

type Result<T> = ::std::result::Result<T, Error>;

/// This represents the size of the mmio device specified to the kernel as a cmdline option
/// It has to be larger than 0x100 (the offset where the configuration space starts from
/// the beginning of the memory mapped device registers) + the size of the configuration space
/// Currently hardcoded to 4K.
const MMIO_LEN: u64 = 0x1000;

/// One actual event object/GSI registration. Independent event objects sharing a
/// GSI are deliberately separate routes.
pub struct IrqRoute {
    pub gsi: u32,
    pub members: Vec<u64>,
    event: Arc<EventFd>,
    registered: bool,
}

impl IrqRoute {
    pub fn notifier(&self) -> &Arc<EventFd> {
        &self.event
    }

    pub fn is_registered(&self) -> bool {
        self.registered
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteTransition {
    Fence,
    Rearm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteFault {
    ForeignBarrier,
    InvalidTransition,
    ProducersNotQuiesced,
    Deadline,
    Native {
        gsi: u32,
        error: kvm_ioctls::Error,
    },
    Host {
        kind: io::ErrorKind,
        raw_os_error: Option<i32>,
    },
    WorkerPanicked,
    WorkerPoisoned,
}

impl From<io::Error> for RouteFault {
    fn from(error: io::Error) -> Self {
        Self::Host {
            kind: error.kind(),
            raw_os_error: error.raw_os_error(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteError {
    pub key: BarrierKey,
    pub request: Option<BarrierRequest>,
    pub transition: RouteTransition,
    pub fault: RouteFault,
}

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IRQ route {:?} for {:?}: {:?}",
            self.transition, self.key, self.fault
        )
    }
}

impl std::error::Error for RouteError {}

struct RouteWork {
    routes: Vec<IrqRoute>,
    request: BarrierRequest,
    transition: RouteTransition,
    failure: Option<RouteFault>,
}

struct RouteWorker {
    work: Arc<Mutex<RouteWork>>,
    handle: JoinHandle<()>,
}

fn run_route_work(vm: Arc<VmFd>, work: &Mutex<RouteWork>, completion: &EventFd) {
    let mut work = match work.lock() {
        Ok(work) => work,
        Err(_) => return,
    };
    let request = work.request;
    let transition = work.transition;
    for index in 0..work.routes.len() {
        if Instant::now() >= request.deadline {
            work.failure = Some(RouteFault::Deadline);
            break;
        }
        let route = &mut work.routes[index];
        let result = match (transition, route.registered) {
            (RouteTransition::Fence, true) => vm.unregister_irqfd(&route.event, route.gsi),
            (RouteTransition::Rearm, false) => vm.register_irqfd(&route.event, route.gsi),
            _ => continue,
        };
        if let Err(error) = result {
            let gsi = route.gsi;
            work.failure = Some(RouteFault::Native { gsi, error });
            break;
        }
        route.registered = transition == RouteTransition::Rearm;
        if Instant::now() >= request.deadline {
            work.failure = Some(RouteFault::Deadline);
            break;
        }
    }
    if let Err(error) = completion.write(1) {
        work.failure.get_or_insert(RouteFault::from(error));
    }
}

/// Manages the complexities of registering a MMIO device.
pub struct MMIODeviceManager {
    pub bus: devices::Bus,
    mmio_base: u64,
    irq: u32,
    last_irq: u32,
    id_to_dev_info: HashMap<(DeviceType, String), MMIODeviceInfo>,
    pub quiescence: DeviceQuiescence,
    routes: Vec<IrqRoute>,
    #[cfg(target_arch = "x86_64")]
    shared_irq: Option<usize>,
    route_request: Option<(BarrierRequest, RouteTransition)>,
    route_failure: Option<RouteError>,
    route_worker: Option<RouteWorker>,
    route_completion: Option<Arc<EventFd>>,
    #[cfg(target_arch = "x86_64")]
    legacy_route_range: Option<std::ops::Range<usize>>,
}

impl MMIODeviceManager {
    /// Create a new DeviceManager handling mmio devices (virtio net, block).
    pub fn new(mmio_base: &mut u64, irq_interval: (u32, u32)) -> MMIODeviceManager {
        if cfg!(any(target_arch = "aarch64", target_arch = "riscv64")) {
            *mmio_base += MMIO_LEN;
        }
        MMIODeviceManager {
            mmio_base: *mmio_base,
            irq: irq_interval.0,
            last_irq: irq_interval.1,
            bus: devices::Bus::new(),
            id_to_dev_info: HashMap::new(),
            quiescence: DeviceQuiescence::default(),
            routes: Vec::new(),
            #[cfg(target_arch = "x86_64")]
            shared_irq: None,
            route_request: None,
            route_failure: None,
            route_worker: None,
            route_completion: None,
            #[cfg(target_arch = "x86_64")]
            legacy_route_range: None,
        }
    }

    fn virtio_route(&mut self) -> Result<usize> {
        #[cfg(target_arch = "x86_64")]
        if self.irq == self.last_irq
            && let Some(index) = self.shared_irq
        {
            return Ok(index);
        }
        let index = self.routes.len();
        self.routes.push(IrqRoute {
            gsi: self.irq,
            members: Vec::new(),
            event: Arc::new(EventFd::new(0).map_err(Error::EventFd)?),
            registered: false,
        });
        #[cfg(target_arch = "x86_64")]
        if self.irq == self.last_irq {
            self.shared_irq = Some(index);
        }
        Ok(index)
    }

    pub fn irq_routes(&self) -> Option<&[IrqRoute]> {
        if self.route_worker.is_some() {
            None
        } else {
            Some(&self.routes)
        }
    }

    pub fn irq_completion_event(&self) -> Option<&EventFd> {
        self.route_completion.as_deref()
    }

    pub fn preflight_quiesce(&self) -> std::result::Result<(), ManagerError> {
        self.quiescence.preflight_quiesce()
    }

    /// Native deassignment runs on an owned worker, after every producer is quiet.
    /// The control owner must poll this completion while servicing control/exit.
    pub fn begin_irq_fence(
        &mut self,
        vm: Arc<VmFd>,
        request: BarrierRequest,
    ) -> std::result::Result<(), RouteError> {
        if self.route_request.is_some() {
            return Err(Self::route_error(
                request,
                RouteTransition::Fence,
                RouteFault::InvalidTransition,
            ));
        }
        if !self.quiescence.fully_quiesced(request.key).map_err(|_| {
            Self::route_error(
                request,
                RouteTransition::Fence,
                RouteFault::ProducersNotQuiesced,
            )
        })? {
            return Err(Self::route_error(
                request,
                RouteTransition::Fence,
                RouteFault::ProducersNotQuiesced,
            ));
        }
        self.start_route_work(vm, request, RouteTransition::Fence)
    }

    /// Routes are restored before workers, callback ingress and CPU release.
    /// Cancellation names the original fence but has its own absolute deadline.
    pub fn begin_irq_rearm(
        &mut self,
        vm: Arc<VmFd>,
        fenced: BarrierKey,
        request: BarrierRequest,
    ) -> std::result::Result<(), RouteError> {
        match self.route_request {
            Some((original, RouteTransition::Fence))
                if original.key == fenced && self.route_worker.is_none() => {}
            _ => {
                return Err(Self::route_error(
                    request,
                    RouteTransition::Rearm,
                    RouteFault::ForeignBarrier,
                ));
            }
        }
        if request.key.generation != fenced.generation || request.key.operation == fenced.operation
        {
            return Err(Self::route_error(
                request,
                RouteTransition::Rearm,
                RouteFault::ForeignBarrier,
            ));
        }
        if self.route_failure.as_ref().is_some_and(|error| {
            matches!(
                error.fault,
                RouteFault::WorkerPanicked | RouteFault::WorkerPoisoned,
            )
        }) {
            return Err(Self::route_error(
                request,
                RouteTransition::Rearm,
                RouteFault::InvalidTransition,
            ));
        }
        self.start_route_work(vm, request, RouteTransition::Rearm)
    }

    pub fn poll_irq_routes(
        &mut self,
        key: BarrierKey,
    ) -> std::result::Result<Poll<()>, RouteError> {
        let (request, transition) = self.route_request.ok_or(RouteError {
            key,
            request: None,
            transition: RouteTransition::Fence,
            fault: RouteFault::ForeignBarrier,
        })?;
        if request.key != key {
            return Err(Self::route_error(
                request,
                transition,
                RouteFault::ForeignBarrier,
            ));
        }
        if self
            .route_worker
            .as_ref()
            .is_some_and(|worker| !worker.handle.is_finished())
        {
            if Instant::now() >= request.deadline {
                let error = Self::route_error(request, transition, RouteFault::Deadline);
                return Err(*self.route_failure.get_or_insert(error));
            }
            return self.route_failure.map_or(Ok(Poll::Pending), Err);
        }
        if let Some(worker) = self.route_worker.take() {
            let panicked = worker.handle.join().is_err();
            let mut work = match worker.work.lock() {
                Ok(work) => work,
                Err(poisoned) => {
                    let mut work = poisoned.into_inner();
                    self.routes = std::mem::take(&mut work.routes);
                    let error = Self::route_error(request, transition, RouteFault::WorkerPoisoned);
                    return Err(*self.route_failure.get_or_insert(error));
                }
            };
            self.routes = std::mem::take(&mut work.routes);
            if panicked {
                let error = Self::route_error(request, transition, RouteFault::WorkerPanicked);
                return Err(*self.route_failure.get_or_insert(error));
            }
            if let Some(fault) = work.failure.take() {
                let error = Self::route_error(request, transition, fault);
                return Err(*self.route_failure.get_or_insert(error));
            }
        }
        if Instant::now() >= request.deadline {
            let error = Self::route_error(request, transition, RouteFault::Deadline);
            return Err(*self.route_failure.get_or_insert(error));
        }
        if let Some(error) = &self.route_failure {
            return Err(*error);
        }
        if transition == RouteTransition::Rearm {
            self.route_request = None;
        }
        Ok(Poll::Ready(()))
    }

    fn start_route_work(
        &mut self,
        vm: Arc<VmFd>,
        request: BarrierRequest,
        transition: RouteTransition,
    ) -> std::result::Result<(), RouteError> {
        if Instant::now() >= request.deadline {
            return Err(Self::route_error(request, transition, RouteFault::Deadline));
        }
        if self.route_worker.is_some() {
            return Err(Self::route_error(
                request,
                transition,
                RouteFault::InvalidTransition,
            ));
        }
        if self.route_completion.is_none() {
            self.route_completion = Some(Arc::new(
                EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(|error| {
                    Self::route_error(request, transition, RouteFault::from(error))
                })?,
            ));
        }
        let completion = self
            .route_completion
            .clone()
            .ok_or_else(|| Self::route_error(request, transition, RouteFault::InvalidTransition))?;
        let work = Arc::new(Mutex::new(RouteWork {
            routes: std::mem::take(&mut self.routes),
            request,
            transition,
            failure: None,
        }));
        let worker_work = work.clone();
        self.route_request = Some((request, transition));
        self.route_failure = None;
        match thread::Builder::new()
            .name("irq-route-barrier".into())
            .spawn(move || {
                run_route_work(vm, &worker_work, &completion);
            }) {
            Ok(handle) => {
                self.route_worker = Some(RouteWorker { work, handle });
                Ok(())
            }
            Err(error) => {
                let mut work = match work.lock() {
                    Ok(work) => work,
                    Err(poisoned) => poisoned.into_inner(),
                };
                self.routes = std::mem::take(&mut work.routes);
                let error = Self::route_error(request, transition, RouteFault::from(error));
                self.route_failure = Some(error);
                Err(error)
            }
        }
    }

    fn route_error(
        request: BarrierRequest,
        transition: RouteTransition,
        fault: RouteFault,
    ) -> RouteError {
        RouteError {
            key: request.key,
            request: Some(request),
            transition,
            fault,
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn retain_legacy_routes(
        &mut self,
        legacy: &crate::vmm::device_manager::legacy::PortIODeviceManager,
    ) -> Result<()> {
        if self.legacy_route_range.is_some() || self.route_request.is_some() {
            return Err(Error::BarrierActive);
        }
        let start = self.routes.len();
        self.legacy_route_range = Some(start..start);
        legacy.retain_live_inventory(&mut self.quiescence);
        for ((gsi, event), address) in legacy
            .irq_events()
            .into_iter()
            .zip([0x3f8, 0x2f8, 0x3e8, 0x2e8, 0x60])
        {
            self.routes.push(IrqRoute {
                gsi,
                members: vec![address],
                event: Arc::new(event.try_clone().map_err(Error::EventFd)?),
                registered: false,
            });
            if let Some(range) = &mut self.legacy_route_range {
                range.end = self.routes.len();
            }
        }
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    pub fn register_legacy_irq_routes(
        &mut self,
        vm: &VmFd,
        legacy: &crate::vmm::device_manager::legacy::PortIODeviceManager,
    ) -> Result<()> {
        self.retain_legacy_routes(legacy)?;
        if let Some(range) = &self.legacy_route_range {
            for index in range.clone() {
                let route = &mut self.routes[index];
                vm.register_irqfd(&route.event, route.gsi)
                    .map_err(Error::RegisterIrqFd)?;
                route.registered = true;
            }
        }
        Ok(())
    }

    /// Register a MMIO IOAPIC device.
    #[cfg(target_arch = "x86_64")]
    pub fn register_mmio_ioapic(
        &mut self,
        intc: Option<Arc<Mutex<devices::legacy::IrqChipDevice>>>,
    ) -> Result<()> {
        if let Some(intc) = intc {
            let (addr, size) = {
                let intc = intc.lock().map_err(|_| Error::DeviceLock)?;
                (intc.get_mmio_addr(), intc.get_mmio_size())
            };
            self.bus
                .insert(intc.clone(), addr, size)
                .map_err(Error::BusError)?;
            self.quiescence.retain_legacy(
                LegacyAttachment {
                    kind: LegacyKind::InterruptController,
                    address: addr,
                    irq: None,
                },
                LegacyDevice::InterruptController(intc),
            );
        }

        Ok(())
    }

    /// Construct and register a device with its manager-owned IRQ notification.
    pub fn register_mmio_device(
        &mut self,
        vm: &VmFd,
        memory: devices::virtio::RuntimeGuestMemory,
        intc: IrqChip,
        device: Arc<Mutex<dyn devices::virtio::VirtioDevice>>,
        device_id: String,
    ) -> Result<(u64, u32)> {
        if self.route_request.is_some() {
            return Err(Error::BarrierActive);
        }
        if self.irq > self.last_irq {
            return Err(Error::IrqsExhausted);
        }

        let route_index = self.virtio_route()?;
        let shared_event = Some(self.routes[route_index].event.clone());
        let type_id = device
            .try_lock()
            .map_err(|_| Error::DeviceLock)?
            .device_type();
        let mut mmio_device =
            devices::virtio::MmioTransport::new(memory, intc, device, shared_event)
                .map_err(Error::CreateMmioTransport)?;
        mmio_device
            .set_attachment_address(self.mmio_base)
            .map_err(Error::Provider)?;

        for (i, queue_evt) in mmio_device.queue_evts().iter().enumerate() {
            let io_addr = IoEventAddress::Mmio(
                self.mmio_base + u64::from(devices::virtio::NOTIFY_REG_OFFSET),
            );

            vm.register_ioevent(queue_evt, &io_addr, i as u32)
                .map_err(Error::RegisterIoEvent)?;
        }

        if !self.routes[route_index].registered {
            vm.register_irqfd(&self.routes[route_index].event, self.irq)
                .map_err(Error::RegisterIrqFd)?;
            self.routes[route_index].registered = true;
        }

        mmio_device.set_irq_line(self.irq);

        let transport = Arc::new(Mutex::new(mmio_device));
        self.bus
            .insert(transport.clone(), self.mmio_base, MMIO_LEN)
            .map_err(Error::BusError)?;
        self.routes[route_index].members.push(self.mmio_base);
        self.quiescence.retain_transport(
            AttachmentIdentity {
                device_type: DeviceType::Virtio(type_id),
                configured_id: device_id.clone(),
                address: self.mmio_base,
                irq: self.irq,
            },
            transport,
        );
        let ret = (self.mmio_base, self.irq);
        self.id_to_dev_info.insert(
            (DeviceType::Virtio(type_id), device_id),
            MMIODeviceInfo {
                addr: self.mmio_base,
                _len: MMIO_LEN,
                _irq: self.irq,
            },
        );
        self.mmio_base += MMIO_LEN;
        #[cfg(target_arch = "x86_64")]
        if self.irq < self.last_irq {
            self.irq += 1;
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            self.irq += 1;
        }

        Ok(ret)
    }

    /// Append a registered MMIO device to the kernel cmdline.
    #[cfg(target_arch = "x86_64")]
    pub fn add_device_to_cmdline(
        &mut self,
        cmdline: &mut kernel_cmdline::Cmdline,
        mmio_base: u64,
        irq: u32,
    ) -> Result<()> {
        // as per doc, [virtio_mmio.]device=<size>@<baseaddr>:<irq> needs to be appended
        // to kernel commandline for virtio mmio devices to get recognized
        // the size parameter has to be transformed to KiB, so dividing hexadecimal value in
        // bytes to 1024; further, the '{}' formatting rust construct will automatically
        // transform it to decimal
        cmdline
            .insert(
                "virtio_mmio.device",
                &format!("{}K@0x{:08x}:{}", MMIO_LEN / 1024, mmio_base, irq),
            )
            .map_err(Error::Cmdline)
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    /// Register an early console at some MMIO address.
    pub fn register_mmio_serial(
        &mut self,
        vm: &VmFd,
        cmdline: &mut kernel_cmdline::Cmdline,
        intc: IrqChip,
        serial: Arc<Mutex<devices::legacy::Serial>>,
    ) -> Result<()> {
        if self.irq > self.last_irq {
            return Err(Error::IrqsExhausted);
        }

        let event = Arc::new(
            serial
                .lock()
                .map_err(|_| Error::DeviceLock)?
                .interrupt_evt()
                .try_clone()
                .map_err(Error::EventFd)?,
        );
        vm.register_irqfd(&event, self.irq)
            .map_err(Error::RegisterIrqFd)?;
        self.routes.push(IrqRoute {
            gsi: self.irq,
            members: vec![self.mmio_base],
            event,
            registered: true,
        });

        {
            let mut serial = serial.lock().map_err(|_| Error::DeviceLock)?;
            serial.set_intc(intc);
            serial.set_irq_line(self.irq);
        }

        self.bus
            .insert(serial.clone(), self.mmio_base, MMIO_LEN)
            .map_err(Error::BusError)?;
        self.quiescence.retain_legacy(
            LegacyAttachment {
                kind: LegacyKind::Serial,
                address: self.mmio_base,
                irq: Some(self.irq),
            },
            LegacyDevice::Serial(serial),
        );

        cmdline
            .insert(
                "earlycon",
                #[cfg(target_arch = "aarch64")]
                &format!("pl011,mmio32,0x{:08x}", self.mmio_base),
                #[cfg(target_arch = "riscv64")]
                &format!("uart,mmio,0x{:08x}", self.mmio_base),
            )
            .map_err(Error::Cmdline)?;

        let ret = self.mmio_base;
        self.id_to_dev_info.insert(
            (DeviceType::Serial, DeviceType::Serial.to_string()),
            MMIODeviceInfo {
                addr: ret,
                _len: MMIO_LEN,
                _irq: self.irq,
            },
        );

        self.mmio_base += MMIO_LEN;
        self.irq += 1;

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    /// Register a MMIO RTC device.
    pub fn register_mmio_rtc(&mut self, vm: &VmFd) -> Result<()> {
        if self.irq > self.last_irq {
            return Err(Error::IrqsExhausted);
        }

        // Attaching the RTC device.
        let rtc_evt = Arc::new(EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(Error::EventFd)?);
        let device = Arc::new(Mutex::new(devices::legacy::RTC::new(
            rtc_evt.try_clone().map_err(Error::EventFd)?,
        )));
        vm.register_irqfd(&rtc_evt, self.irq)
            .map_err(Error::RegisterIrqFd)?;
        self.routes.push(IrqRoute {
            gsi: self.irq,
            members: vec![self.mmio_base],
            event: rtc_evt,
            registered: true,
        });

        self.bus
            .insert(device.clone(), self.mmio_base, MMIO_LEN)
            .map_err(Error::BusError)?;
        self.quiescence.retain_legacy(
            LegacyAttachment {
                kind: LegacyKind::Rtc,
                address: self.mmio_base,
                irq: Some(self.irq),
            },
            LegacyDevice::Rtc(device),
        );

        let ret = self.mmio_base;
        self.id_to_dev_info.insert(
            (DeviceType::RTC, "rtc".to_string()),
            MMIODeviceInfo {
                addr: ret,
                _len: MMIO_LEN,
                _irq: self.irq,
            },
        );

        self.mmio_base += MMIO_LEN;
        self.irq += 1;

        Ok(())
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    /// Gets the information of the devices registered up to some point in time.
    pub fn get_device_info(&self) -> &HashMap<(DeviceType, String), MMIODeviceInfo> {
        &self.id_to_dev_info
    }
}

/// Private structure for storing information about the MMIO device registered at some address on the bus.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct MMIODeviceInfo {
    addr: u64,
    _irq: u32,
    _len: u64,
}

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
impl DeviceInfoForFDT for MMIODeviceInfo {
    fn addr(&self) -> u64 {
        self.addr
    }
    fn irq(&self) -> u32 {
        self._irq
    }
    fn length(&self) -> u64 {
        self._len
    }
}

#[cfg(test)]
mod tests {
    use crate::vmm::builder;
    use crate::vmm::device_manager::kvm::mmio::*;
    use arch;
    use devices::legacy::DummyIrqChip;
    #[cfg(target_arch = "aarch64")]
    use devices::legacy::KvmGicV3;
    #[cfg(target_arch = "x86_64")]
    use devices::legacy::KvmIoapic;
    use devices::virtio::{
        ActivateResult, DeviceQueue, InterruptTransport, QueueConfig, RuntimeGuestMemory,
        VirtioDevice,
    };
    use std::sync::Arc;
    use utils::errno;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    const QUEUE_CONFIG: &[QueueConfig] = &[QueueConfig::new(64)];

    impl MMIODeviceManager {
        fn register_virtio_device(
            &mut self,
            vm: &VmFd,
            guest_mem: GuestMemoryMmap,
            device: Arc<Mutex<dyn devices::virtio::VirtioDevice>>,
            _cmdline: &mut kernel_cmdline::Cmdline,
            device_id: &str,
        ) -> Result<u64> {
            let (mmio_base, _irq) = self.register_mmio_device(
                vm,
                guest_mem.into(),
                DummyIrqChip::new().into(),
                device,
                device_id.to_string(),
            )?;
            #[cfg(target_arch = "x86_64")]
            self.add_device_to_cmdline(_cmdline, mmio_base, _irq)?;
            Ok(mmio_base)
        }
    }

    #[allow(dead_code)]
    struct DummyDevice {
        dummy: u32,
    }

    impl DummyDevice {
        pub fn new() -> Self {
            DummyDevice { dummy: 0 }
        }
    }

    impl devices::virtio::VirtioDevice for DummyDevice {
        fn avail_features(&self) -> u64 {
            0
        }

        fn acked_features(&self) -> u64 {
            0
        }

        fn set_acked_features(&mut self, _: u64) {}

        fn device_type(&self) -> u32 {
            0
        }

        fn device_name(&self) -> &str {
            "dummy"
        }

        fn queue_config(&self) -> &[QueueConfig] {
            QUEUE_CONFIG
        }

        fn read_config(&self, offset: u64, data: &mut [u8]) {
            let _ = offset;
            let _ = data;
        }

        fn write_config(&mut self, offset: u64, data: &[u8]) {
            let _ = offset;
            let _ = data;
        }

        fn activate(
            &mut self,
            _mem: RuntimeGuestMemory,
            _intc: InterruptTransport,
            _queues: Vec<DeviceQueue>,
        ) -> ActivateResult {
            Ok(())
        }

        fn is_activated(&self) -> bool {
            false
        }
    }

    #[test]
    fn test_register_virtio_device() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemoryMmap::from_ranges(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let vm = builder::setup_vm(&guest_mem, false).unwrap();
        let mut device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));
        #[cfg(target_arch = "x86_64")]
        let _kvmioapic = KvmIoapic::new(vm.fd()).unwrap();
        #[cfg(target_arch = "aarch64")]
        let _gic = KvmGicV3::new(vm.fd(), 1).unwrap();

        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let dummy = Arc::new(Mutex::new(DummyDevice::new()));

        assert!(
            device_manager
                .register_virtio_device(vm.fd(), guest_mem, dummy, &mut cmdline, "dummy")
                .is_ok()
        );
    }

    #[cfg(not(target_arch = "x86_64"))]
    #[test]
    fn test_register_too_many_devices() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemoryMmap::from_ranges(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let vm = builder::setup_vm(&guest_mem, false).unwrap();
        let mut device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));
        #[cfg(target_arch = "x86_64")]
        let _kvmioapic = KvmIoapic::new(vm.fd()).unwrap();
        #[cfg(target_arch = "aarch64")]
        let _gic = KvmGicV3::new(vm.fd(), 1).unwrap();

        let mut cmdline = kernel_cmdline::Cmdline::new(4096);

        for _i in arch::IRQ_BASE..=arch::IRQ_MAX {
            device_manager
                .register_virtio_device(
                    vm.fd(),
                    guest_mem.clone(),
                    Arc::new(Mutex::new(DummyDevice::new())),
                    &mut cmdline,
                    "dummy1",
                )
                .unwrap();
        }
        assert_eq!(
            format!(
                "{}",
                device_manager
                    .register_virtio_device(
                        vm.fd(),
                        guest_mem,
                        Arc::new(Mutex::new(DummyDevice::new())),
                        &mut cmdline,
                        "dummy2"
                    )
                    .unwrap_err()
            ),
            "no more IRQs are available".to_string()
        );
    }

    #[test]
    fn test_dummy_device() {
        let dummy = DummyDevice::new();
        assert_eq!(dummy.device_type(), 0);
        assert_eq!(dummy.queue_config().len(), QUEUE_CONFIG.len());
    }

    #[test]
    fn test_error_messages() {
        let device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));
        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let e = Error::Cmdline(
            cmdline
                .insert(
                    "virtio_mmio=device",
                    &format!(
                        "{}K@0x{:08x}:{}",
                        MMIO_LEN / 1024,
                        device_manager.mmio_base,
                        device_manager.irq
                    ),
                )
                .unwrap_err(),
        );
        assert_eq!(
            format!("{e}"),
            format!(
                "unable to add device to kernel command line: {}",
                kernel_cmdline::Error::HasEquals
            ),
        );
        assert_eq!(
            format!("{}", Error::BusError(devices::BusError::Overlap)),
            format!(
                "failed to perform bus operation: {}",
                devices::BusError::Overlap
            )
        );
        assert_eq!(
            format!("{}", Error::IrqsExhausted),
            "no more IRQs are available"
        );
        assert_eq!(
            format!("{}", Error::RegisterIoEvent(errno::Error::new(0))),
            format!("failed to register IO event: {}", errno::Error::new(0))
        );
        assert_eq!(
            format!("{}", Error::RegisterIrqFd(errno::Error::new(0))),
            format!("failed to register irqfd: {}", errno::Error::new(0))
        );
    }

    #[test]
    fn test_device_info() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemoryMmap::from_ranges(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let vm = builder::setup_vm(&guest_mem, false).unwrap();
        let mut device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));
        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let dummy = Arc::new(Mutex::new(DummyDevice::new()));

        let type_id = 0;
        let id = String::from("foo");
        if let Ok(addr) =
            device_manager.register_virtio_device(vm.fd(), guest_mem, dummy, &mut cmdline, &id)
        {
            assert_eq!(
                addr,
                device_manager.id_to_dev_info[&(DeviceType::Virtio(type_id), id.clone())].addr
            );
            assert_eq!(
                arch::IRQ_BASE,
                device_manager.id_to_dev_info[&(DeviceType::Virtio(type_id), id.clone())]._irq
            );
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn quiescence_route_plan_owns_ten_dedicated_notifiers_and_one_shared_line() {
        let mut manager = MMIODeviceManager::new(&mut 0xd000_0000, (5, 15));
        for irq in 5..15 {
            manager.irq = irq;
            let index = manager.virtio_route().unwrap();
            assert_eq!(manager.routes[index].gsi, irq);
            assert!(!manager.routes[index].is_registered());
        }
        manager.irq = 15;
        let first = manager.virtio_route().unwrap();
        let peer = manager.virtio_route().unwrap();
        assert_eq!(first, peer);
        assert_eq!(manager.routes.len(), 11);
        for dedicated in &manager.routes[..10] {
            assert!(!Arc::ptr_eq(
                dedicated.notifier(),
                manager.routes[first].notifier()
            ));
        }
        let survivor = manager.routes[first].notifier().clone();
        let dropped_peer = survivor.clone();
        dropped_peer.write(3).unwrap();
        drop(dropped_peer);
        survivor.write(4).unwrap();
        assert_eq!(manager.routes[first].notifier().read().unwrap(), 7);
        assert!(manager.routes.iter().all(|route| !route.is_registered()));
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn quiescence_route_inventory_preserves_independent_legacy_producers() {
        use crate::vmm::device_manager::legacy::PortIODeviceManager;
        let mut legacy = PortIODeviceManager::new(
            Arc::new(Mutex::new(devices::legacy::Cmos::new(0, 0))),
            Vec::new(),
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
        )
        .unwrap();
        legacy.register_devices().unwrap();
        let mut manager = MMIODeviceManager::new(&mut 0xd000_0000, (5, 15));
        manager.retain_legacy_routes(&legacy).unwrap();
        assert_eq!(
            manager
                .routes
                .iter()
                .map(|route| route.gsi)
                .collect::<Vec<_>>(),
            [4, 3, 4, 3, 1]
        );
        assert!(manager.routes.iter().all(|route| !route.is_registered()));
        assert!(!Arc::ptr_eq(
            manager.routes[0].notifier(),
            manager.routes[2].notifier()
        ));
        legacy.com_evt_1.write(2).unwrap();
        legacy.com_evt_3.write(6).unwrap();
        assert_eq!(manager.routes[0].notifier().read().unwrap(), 2);
        assert_eq!(manager.routes[2].notifier().read().unwrap(), 6);
        assert!(manager.preflight_quiesce().is_err());
        assert!(manager.retain_legacy_routes(&legacy).is_err());
        assert_eq!(manager.routes.len(), 5);
    }

    #[test]
    fn quiescence_route_deadline_retains_failure_and_notifier_ownership() {
        use polly::event_manager::{BarrierGeneration, OperationId};
        let mut manager = MMIODeviceManager::new(&mut 0xd000_0000, (5, 15));
        let route = manager.virtio_route().unwrap();
        let request = BarrierRequest {
            key: BarrierKey {
                operation: OperationId(8),
                generation: BarrierGeneration(2),
            },
            deadline: Instant::now(),
        };
        manager.route_request = Some((request, RouteTransition::Fence));
        assert!(matches!(
            manager.poll_irq_routes(request.key).unwrap_err().fault,
            RouteFault::Deadline
        ));
        assert!(matches!(
            manager.poll_irq_routes(request.key).unwrap_err().fault,
            RouteFault::Deadline
        ));
        assert!(!manager.routes[route].is_registered());
        manager.routes[route].notifier().write(11).unwrap();
        assert_eq!(manager.routes[route].notifier().read().unwrap(), 11);
        assert_eq!(
            manager.route_request,
            Some((request, RouteTransition::Fence))
        );
    }
}
