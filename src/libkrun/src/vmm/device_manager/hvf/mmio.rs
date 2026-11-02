// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::sync::TryLockError;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Instant;
use std::{fmt, io};

use devices::DeviceType;
use devices::fdt::DeviceInfoForFDT;
use devices::legacy::IrqChip;
use kernel::cmdline as kernel_cmdline;
use polly::event_manager::{BarrierKey, BarrierRequest, EventManager};
#[cfg(target_arch = "aarch64")]
use utils::eventfd::EventFd;

use crate::vmm::device_manager::quiescence::{
    AttachmentIdentity, DeviceQuiescence, LegacyAttachment, LegacyKind, ManagerError,
};
use crate::vmm::vstate::Vm;

/// Errors for MMIO device manager.
#[allow(clippy::enum_variant_names)]
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
    Provider(devices::virtio::lifecycle::ProviderFault),
    DeviceLock,
    BarrierActive,
    EventManager(polly::event_manager::Error),
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
            Error::Provider(e) => write!(f, "failed to bind transport attachment: {e:?}"),
            Error::DeviceLock => write!(f, "device lock unavailable"),
            Error::BarrierActive => write!(f, "device topology is fenced"),
            Error::EventManager(e) => write!(f, "failed to register device callback: {e:?}"),
        }
    }
}

impl From<devices::virtio::CreateMmioTransportError> for crate::vmm::device_manager::mmio::Error {
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

/// HVF publishes synchronously through the retained controller lock, rather than
/// through a KVM irqfd registration. Pending device/controller bits stay separate.
pub struct IrqRoute {
    pub gsi: u32,
    pub address: u64,
    source: devices::virtio::InterruptTransport,
    fenced: bool,
}

impl IrqRoute {
    pub fn source(&self) -> &devices::virtio::InterruptTransport {
        &self.source
    }

    pub fn is_fenced(&self) -> bool {
        self.fenced
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteFault {
    ForeignBarrier,
    InvalidTransition,
    ProducersNotQuiesced,
    Deadline,
    ControllerPoisoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteError {
    pub key: BarrierKey,
    pub fault: RouteFault,
}

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HVF IRQ route for {:?}: {:?}", self.key, self.fault)
    }
}

impl std::error::Error for RouteError {}

/// Manages the complexities of registering a MMIO device.
pub struct MMIODeviceManager {
    pub bus: devices::Bus,
    mmio_base: u64,
    irq: u32,
    last_irq: u32,
    id_to_dev_info: HashMap<(DeviceType, String), MMIODeviceInfo>,
    pub quiescence: DeviceQuiescence,
    routes: Vec<IrqRoute>,
    route_request: Option<BarrierRequest>,
    route_failure: Option<RouteError>,
    route_rearming: bool,
}

impl MMIODeviceManager {
    /// Create a new DeviceManager handling mmio devices (virtio net, block).
    pub fn new(mmio_base: &mut u64, irq_interval: (u32, u32)) -> MMIODeviceManager {
        if cfg!(target_arch = "aarch64") {
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
            route_request: None,
            route_failure: None,
            route_rearming: false,
        }
    }

    pub fn irq_routes(&self) -> &[IrqRoute] {
        &self.routes
    }

    pub fn preflight_quiesce(&self) -> std::result::Result<(), ManagerError> {
        self.quiescence.preflight_quiesce()
    }

    pub fn irq_barrier_key(&self) -> Option<BarrierKey> {
        self.route_request.map(|request| request.key)
    }

    /// HVF publication is owner-synchronous and has no in-flight route worker.
    pub fn poll_irq_cleanup(&mut self) -> bool {
        true
    }

    pub fn begin_irq_fence(
        &mut self,
        request: BarrierRequest,
    ) -> std::result::Result<(), RouteError> {
        if self.route_request.is_some() {
            return Err(RouteError {
                key: request.key,
                fault: RouteFault::InvalidTransition,
            });
        }
        if Instant::now() >= request.deadline {
            return Err(RouteError {
                key: request.key,
                fault: RouteFault::Deadline,
            });
        }
        if !self
            .quiescence
            .fully_quiesced(request.key)
            .map_err(|_| RouteError {
                key: request.key,
                fault: RouteFault::ProducersNotQuiesced,
            })?
        {
            return Err(RouteError {
                key: request.key,
                fault: RouteFault::ProducersNotQuiesced,
            });
        }
        self.route_request = Some(request);
        self.route_failure = None;
        self.route_rearming = false;
        Ok(())
    }

    pub fn poll_irq_routes(
        &mut self,
        key: BarrierKey,
    ) -> std::result::Result<Poll<()>, RouteError> {
        let request = self
            .route_request
            .filter(|request| request.key == key)
            .ok_or(RouteError {
                key,
                fault: RouteFault::ForeignBarrier,
            })?;
        if self.route_rearming {
            if Instant::now() >= request.deadline {
                let error = RouteError {
                    key,
                    fault: RouteFault::Deadline,
                };
                return Err(*self.route_failure.get_or_insert(error));
            }
            if let Some(error) = self.route_failure {
                return Err(error);
            }
            self.route_request = None;
            self.route_rearming = false;
            return Ok(Poll::Ready(()));
        }
        for route in &mut self.routes {
            if !route.fenced {
                match route.source.intc().try_lock() {
                    Ok(controller) => {
                        drop(controller);
                        route.fenced = true;
                    }
                    Err(TryLockError::WouldBlock) => {
                        if Instant::now() >= request.deadline {
                            let error = RouteError {
                                key,
                                fault: RouteFault::Deadline,
                            };
                            return Err(*self.route_failure.get_or_insert(error));
                        }
                        return Ok(Poll::Pending);
                    }
                    Err(TryLockError::Poisoned(_)) => {
                        let error = RouteError {
                            key,
                            fault: RouteFault::ControllerPoisoned,
                        };
                        return Err(*self.route_failure.get_or_insert(error));
                    }
                }
            }
        }
        if Instant::now() >= request.deadline {
            let error = RouteError {
                key,
                fault: RouteFault::Deadline,
            };
            return Err(*self.route_failure.get_or_insert(error));
        }
        self.route_failure.map_or(Ok(Poll::Ready(())), Err)
    }

    pub fn begin_irq_rearm(
        &mut self,
        fenced: BarrierKey,
        request: BarrierRequest,
    ) -> std::result::Result<(), RouteError> {
        if self
            .route_request
            .is_none_or(|original| original.key != fenced)
            || request.key.generation != fenced.generation
            || request.key.operation == fenced.operation
            || self.route_rearming
        {
            return Err(RouteError {
                key: request.key,
                fault: RouteFault::ForeignBarrier,
            });
        }
        if self.routes.iter().any(|route| !route.fenced)
            || self
                .route_failure
                .is_some_and(|error| error.fault == RouteFault::ControllerPoisoned)
        {
            return Err(RouteError {
                key: request.key,
                fault: RouteFault::InvalidTransition,
            });
        }
        if Instant::now() >= request.deadline {
            return Err(RouteError {
                key: request.key,
                fault: RouteFault::Deadline,
            });
        }
        for route in &mut self.routes {
            route.fenced = false;
        }
        self.route_request = Some(request);
        self.route_rearming = true;
        self.route_failure = None;
        Ok(())
    }

    /// Register an already created MMIO device to be used via MMIO transport.
    pub fn register_mmio_device(
        &mut self,
        mut mmio_device: devices::virtio::MmioTransport,
        type_id: u32,
        device_id: String,
    ) -> Result<(u64, u32)> {
        if self.route_request.is_some() {
            return Err(Error::BarrierActive);
        }
        if self.irq > self.last_irq {
            return Err(Error::IrqsExhausted);
        }

        mmio_device.set_irq_line(self.irq);
        mmio_device
            .set_attachment_address(self.mmio_base)
            .map_err(Error::Provider)?;
        let source = mmio_device.interrupt_transport().clone();

        let transport = Arc::new(Mutex::new(mmio_device));
        self.bus
            .insert(transport.clone(), self.mmio_base, MMIO_LEN)
            .map_err(Error::BusError)?;
        self.routes.push(IrqRoute {
            gsi: self.irq,
            address: self.mmio_base,
            source,
            fenced: false,
        });
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
                len: MMIO_LEN,
                irq: self.irq,
            },
        );
        self.mmio_base += MMIO_LEN;
        self.irq += 1;

        Ok(ret)
    }

    #[cfg(target_arch = "aarch64")]
    /// Register an early console at some MMIO address.
    pub fn register_mmio_serial(
        &mut self,
        _vm: &Vm,
        cmdline: &mut kernel_cmdline::Cmdline,
        intc: IrqChip,
        serial: Arc<Mutex<devices::legacy::Serial>>,
    ) -> Result<()> {
        if self.irq > self.last_irq {
            return Err(Error::IrqsExhausted);
        }

        {
            let mut serial = serial.lock().map_err(|_| Error::DeviceLock)?;
            serial.set_intc(intc);
            serial.set_irq_line(self.irq);
        }

        self.bus
            .insert(serial, self.mmio_base, MMIO_LEN)
            .map_err(Error::BusError)?;
        self.quiescence.retain_legacy(LegacyAttachment {
            kind: LegacyKind::Serial,
            address: self.mmio_base,
            irq: Some(self.irq),
        });

        cmdline
            .insert(
                "earlycon",
                &format!("pl011,mmio32,0x{:08x}", self.mmio_base),
            )
            .map_err(Error::Cmdline)?;

        let ret = self.mmio_base;
        self.id_to_dev_info.insert(
            (DeviceType::Serial, DeviceType::Serial.to_string()),
            MMIODeviceInfo {
                addr: ret,
                len: MMIO_LEN,
                irq: self.irq,
            },
        );

        self.mmio_base += MMIO_LEN;
        self.irq += 1;

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    /// Register a MMIO RTC device.
    pub fn register_mmio_rtc(&mut self, _vm: &Vm, _intc: IrqChip) -> Result<()> {
        if self.irq > self.last_irq {
            return Err(Error::IrqsExhausted);
        }

        // Attaching the RTC device.
        let rtc_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(Error::EventFd)?;
        let device = Arc::new(Mutex::new(devices::legacy::RTC::new(
            rtc_evt.try_clone().map_err(Error::EventFd)?,
        )));

        self.bus
            .insert(device, self.mmio_base, MMIO_LEN)
            .map_err(Error::BusError)?;
        self.quiescence.retain_legacy(LegacyAttachment {
            kind: LegacyKind::Rtc,
            address: self.mmio_base,
            irq: Some(self.irq),
        });

        let ret = self.mmio_base;
        self.id_to_dev_info.insert(
            (DeviceType::RTC, "rtc".to_string()),
            MMIODeviceInfo {
                addr: ret,
                len: MMIO_LEN,
                irq: self.irq,
            },
        );

        self.mmio_base += MMIO_LEN;
        self.irq += 1;

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    /// Register a GPIO
    pub fn register_mmio_gpio(
        &mut self,
        _vm: &Vm,
        intc: IrqChip,
        event_manager: &mut EventManager,
        shutdown_efd: EventFd,
    ) -> Result<()> {
        // Attaching the GPIO device.
        let gpio_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(Error::EventFd)?;
        let gpio = Arc::new(Mutex::new(devices::legacy::Gpio::new(
            shutdown_efd,
            gpio_evt.try_clone().map_err(Error::EventFd)?,
        )));

        event_manager
            .add_subscriber(gpio.clone())
            .map_err(Error::EventManager)?;

        if self.irq > self.last_irq {
            return Err(Error::IrqsExhausted);
        }

        {
            let mut gpio = gpio.lock().map_err(|_| Error::DeviceLock)?;
            gpio.set_intc(intc);
            gpio.set_irq_line(self.irq);
        }

        self.bus
            .insert(gpio, self.mmio_base, MMIO_LEN)
            .map_err(Error::BusError)?;
        self.quiescence.retain_legacy(LegacyAttachment {
            kind: LegacyKind::Gpio,
            address: self.mmio_base,
            irq: Some(self.irq),
        });

        let ret = self.mmio_base;
        self.id_to_dev_info.insert(
            (DeviceType::Gpio, DeviceType::Gpio.to_string()),
            MMIODeviceInfo {
                addr: ret,
                len: MMIO_LEN,
                irq: self.irq,
            },
        );

        self.mmio_base += MMIO_LEN;
        self.irq += 1;

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    /// Register a MMIO GIC device.
    pub fn register_mmio_gic(&mut self, _vm: &Vm, intc: IrqChip) -> Result<()> {
        let (mmio_addr, mmio_size) = {
            let intc = intc.lock().map_err(|_| Error::DeviceLock)?;
            (intc.get_mmio_addr(), intc.get_mmio_size())
        };

        // The in-kernel GIC reports a size of 0 to tell us we don't need to map
        // anything in the guest.
        if mmio_size != 0 {
            self.bus
                .insert(intc, mmio_addr, mmio_size)
                .map_err(Error::BusError)?;
        }
        self.quiescence.retain_legacy(LegacyAttachment {
            kind: LegacyKind::InterruptController,
            address: mmio_addr,
            irq: None,
        });

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    /// Gets the information of the devices registered up to some point in time.
    pub fn get_device_info(&self) -> &HashMap<(DeviceType, String), MMIODeviceInfo> {
        &self.id_to_dev_info
    }
}

/// Private structure for storing information about the MMIO device registered at some address on the bus.
#[derive(Clone, Debug)]
pub struct MMIODeviceInfo {
    addr: u64,
    irq: u32,
    len: u64,
}

#[cfg(target_arch = "aarch64")]
impl DeviceInfoForFDT for MMIODeviceInfo {
    fn addr(&self) -> u64 {
        self.addr
    }
    fn irq(&self) -> u32 {
        self.irq
    }
    fn length(&self) -> u64 {
        self.len
    }
}

#[cfg(test)]
mod tests {
    use crate::vmm::device_manager::hvf::mmio::*;
    use arch;
    use devices::legacy::DummyIrqChip;
    use devices::virtio::{
        ActivateResult, DeviceQueue, InterruptTransport, QueueConfig, RuntimeGuestMemory,
        VirtioDevice,
    };
    use std::sync::Arc;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    const QUEUE_SIZES: &[u16] = &[64];

    impl MMIODeviceManager {
        fn register_virtio_device(
            &mut self,
            guest_mem: GuestMemoryMmap,
            device: Arc<Mutex<dyn devices::virtio::VirtioDevice>>,
            _cmdline: &mut kernel_cmdline::Cmdline,
            type_id: u32,
            device_id: &str,
        ) -> Result<u64> {
            let mmio_device = devices::virtio::MmioTransport::new(
                guest_mem,
                DummyIrqChip::new().into(),
                device,
                None,
            )
            .unwrap();
            let (mmio_base, _irq) =
                self.register_mmio_device(mmio_device, type_id, device_id.to_string())?;
            Ok(mmio_base)
        }
    }

    #[allow(dead_code)]
    struct DummyDevice {
        dummy: u32,
        queue_config: Vec<QueueConfig>,
    }

    impl DummyDevice {
        pub fn new() -> Self {
            DummyDevice {
                dummy: 0,
                queue_config: QUEUE_SIZES.iter().map(|&s| QueueConfig::new(s)).collect(),
            }
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
            &self.queue_config
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
            _interrupt: InterruptTransport,
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
        let mut device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));

        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let dummy = Arc::new(Mutex::new(DummyDevice::new()));

        assert!(
            device_manager
                .register_virtio_device(guest_mem, dummy, &mut cmdline, 0, "dummy")
                .is_ok()
        );
    }

    #[test]
    fn test_register_too_many_devices() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemoryMmap::from_ranges(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let mut device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));

        let mut cmdline = kernel_cmdline::Cmdline::new(4096);

        for _i in arch::IRQ_BASE..=arch::IRQ_MAX {
            device_manager
                .register_virtio_device(
                    guest_mem.clone(),
                    Arc::new(Mutex::new(DummyDevice::new())),
                    &mut cmdline,
                    0,
                    "dummy1",
                )
                .unwrap();
        }
        assert_eq!(
            format!(
                "{}",
                device_manager
                    .register_virtio_device(
                        guest_mem,
                        Arc::new(Mutex::new(DummyDevice::new())),
                        &mut cmdline,
                        0,
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
        assert_eq!(dummy.queue_config().len(), QUEUE_SIZES.len());
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
            format!("{}", e),
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
    }

    #[test]
    fn test_device_info() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemoryMmap::from_ranges(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let mut device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));
        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let dummy = Arc::new(Mutex::new(DummyDevice::new()));

        let type_id = 0;
        let id = String::from("foo");
        if let Ok(addr) =
            device_manager.register_virtio_device(guest_mem, dummy, &mut cmdline, type_id, &id)
        {
            assert_eq!(
                addr,
                device_manager.id_to_dev_info[&(DeviceType::Virtio(type_id), id.clone())].addr
            );
            assert_eq!(
                arch::IRQ_BASE,
                device_manager.id_to_dev_info[&(DeviceType::Virtio(type_id), id.clone())].irq
            );
        }
    }

    #[test]
    #[cfg(not(feature = "tee"))]
    fn hvf_route_inventory_retains_source_and_refuses_missing_provider() {
        use polly::event_manager::{BarrierGeneration, OperationId};
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let device = Arc::new(Mutex::new(devices::virtio::Rng::new().unwrap()));
        let transport =
            devices::virtio::MmioTransport::new(memory, DummyIrqChip::new().into(), device, None)
                .unwrap();
        let source = transport.interrupt_transport().clone();
        let mut manager = MMIODeviceManager::new(&mut 0xd000_0000, (32, 64));
        let (address, irq) = manager
            .register_mmio_device(transport, 4, "rng0".into())
            .unwrap();
        let route = &manager.irq_routes()[0];
        assert_eq!(route.address, address);
        assert_eq!(route.gsi, irq);
        assert!(std::ptr::eq(route.source().status(), source.status()));
        assert!(!route.is_fenced());
        let error = manager.preflight_quiesce().unwrap_err();
        assert_eq!(error.attachment.unwrap().configured_id, "rng0");
        let request = BarrierRequest {
            key: BarrierKey {
                operation: OperationId(1),
                generation: BarrierGeneration(1),
            },
            deadline: Instant::now() + std::time::Duration::from_secs(10),
        };
        assert_eq!(
            manager.begin_irq_fence(request).unwrap_err().fault,
            RouteFault::ProducersNotQuiesced
        );
        assert!(!manager.irq_routes()[0].is_fenced());
        assert!(manager.route_request.is_none());
    }
}
