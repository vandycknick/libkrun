// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
#![cfg(target_arch = "x86_64")]

use std::fmt;
use std::sync::{Arc, Mutex};

use devices;
use utils::eventfd::EventFd;

use crate::vmm::device_manager::quiescence::{
    DeviceQuiescence, LegacyAttachment, LegacyHandle, LegacyKind,
};

/// Errors corresponding to the `PortIODeviceManager`.
#[derive(Debug)]
pub enum Error {
    /// Cannot add legacy device to Bus.
    BusError(devices::BusError),
    /// Cannot create EventFd.
    EventFd(std::io::Error),
    DeviceLock,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            BusError(err) => write!(f, "Failed to add legacy device to Bus: {err}"),
            EventFd(err) => write!(f, "Failed to create EventFd: {err}"),
            DeviceLock => write!(f, "Legacy device lock is poisoned"),
        }
    }
}

type Result<T> = ::std::result::Result<T, Error>;

/// The `PortIODeviceManager` is a wrapper that is used for registering legacy devices
/// on an I/O Bus. It currently manages the uart and i8042 devices.
/// The `LegacyDeviceManger` should be initialized only by using the constructor.
pub struct PortIODeviceManager {
    pub io_bus: devices::Bus,
    pub cmos: Arc<Mutex<devices::legacy::Cmos>>,
    pub stdio_serial: Vec<Arc<Mutex<devices::legacy::Serial>>>,
    pub i8042: Arc<Mutex<devices::legacy::I8042Device>>,

    pub com_evt_1: EventFd,
    pub com_evt_2: EventFd,
    pub com_evt_3: EventFd,
    pub com_evt_4: EventFd,
    pub kbd_evt: EventFd,
    attached_serial: Vec<(u64, Arc<Mutex<devices::legacy::Serial>>)>,
    cmos_attached: bool,
    i8042_attached: bool,
}

impl PortIODeviceManager {
    /// Create a new DeviceManager handling legacy devices (uart, i8042).
    pub fn new(
        cmos: Arc<Mutex<devices::legacy::Cmos>>,
        stdio_serial: Vec<Arc<Mutex<devices::legacy::Serial>>>,
        i8042_reset_evfd: EventFd,
    ) -> Result<Self> {
        let io_bus = devices::Bus::new();
        let mut evts: Vec<EventFd> = Vec::new();
        for i in 0..4 {
            let com_evt = match stdio_serial.get(i) {
                Some(s) => s
                    .lock()
                    .map_err(|_| Error::DeviceLock)?
                    .interrupt_evt()
                    .try_clone()
                    .map_err(Error::EventFd)?,
                None => EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(Error::EventFd)?,
            };
            evts.push(com_evt);
        }

        let kbd_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(Error::EventFd)?;

        let i8042 = Arc::new(Mutex::new(devices::legacy::I8042Device::new(
            i8042_reset_evfd,
            kbd_evt.try_clone().map_err(Error::EventFd)?,
        )));

        Ok(PortIODeviceManager {
            io_bus,
            cmos,
            stdio_serial,
            i8042,
            com_evt_1: evts[0].try_clone().map_err(Error::EventFd)?,
            com_evt_2: evts[1].try_clone().map_err(Error::EventFd)?,
            com_evt_3: evts[2].try_clone().map_err(Error::EventFd)?,
            com_evt_4: evts[3].try_clone().map_err(Error::EventFd)?,
            kbd_evt,
            attached_serial: Vec::new(),
            cmos_attached: false,
            i8042_attached: false,
        })
    }

    /// Register supported legacy devices.
    pub fn register_devices(&mut self) -> Result<()> {
        self.io_bus
            .insert(self.cmos.clone(), 0x70, 0x8)
            .map_err(Error::BusError)?;
        self.cmos_attached = true;

        if let Some(serial) = self.stdio_serial.first() {
            self.io_bus
                .insert(serial.clone(), 0x3f8, 0x8)
                .map_err(Error::BusError)?;
            self.attached_serial.push((0x3f8, serial.clone()));
        }
        for (index, address, event) in [
            (1, 0x2f8, &self.com_evt_2),
            (2, 0x3e8, &self.com_evt_3),
            (3, 0x2e8, &self.com_evt_4),
        ] {
            let serial = match self.stdio_serial.get(index) {
                Some(serial) => serial.clone(),
                None => Arc::new(Mutex::new(devices::legacy::Serial::new_sink(
                    event.try_clone().map_err(Error::EventFd)?,
                ))),
            };
            self.io_bus
                .insert(serial.clone(), address, 0x8)
                .map_err(Error::BusError)?;
            self.attached_serial.push((address, serial));
        }
        self.io_bus
            .insert(self.i8042.clone(), 0x060, 0x5)
            .map_err(Error::BusError)?;
        self.i8042_attached = true;
        Ok(())
    }

    /// These are five independent registrations, not three deduplicated GSIs.
    pub fn irq_events(&self) -> [(u32, &EventFd); 5] {
        [
            (4, &self.com_evt_1),
            (3, &self.com_evt_2),
            (4, &self.com_evt_3),
            (3, &self.com_evt_4),
            (1, &self.kbd_evt),
        ]
    }

    pub fn retain_live_inventory(&self, inventory: &mut DeviceQuiescence) {
        if self.cmos_attached {
            inventory.retain_legacy_device(
                LegacyAttachment {
                    kind: LegacyKind::Cmos,
                    address: 0x70,
                    irq: None,
                },
                LegacyHandle::Cmos(self.cmos.clone()),
            );
        }
        for (address, serial) in &self.attached_serial {
            let irq = match address {
                0x3f8 | 0x3e8 => 4,
                _ => 3,
            };
            inventory.retain_legacy_device(
                LegacyAttachment {
                    kind: LegacyKind::Serial,
                    address: *address,
                    irq: Some(irq),
                },
                LegacyHandle::Serial(serial.clone()),
            );
        }
        if self.i8042_attached {
            inventory.retain_legacy_device(
                LegacyAttachment {
                    kind: LegacyKind::I8042,
                    address: 0x60,
                    irq: Some(1),
                },
                LegacyHandle::I8042(self.i8042.clone()),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::vmm::device_manager::legacy::*;

    #[test]
    fn test_register_legacy_devices() {
        let serial =
            devices::legacy::Serial::new_sink(EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap());
        let cmos = devices::legacy::Cmos::new(0, 0);
        let ldm = PortIODeviceManager::new(
            Arc::new(Mutex::new(cmos)),
            vec![Arc::new(Mutex::new(serial))],
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
        );
        assert!(ldm.is_ok());
        assert!(&ldm.unwrap().register_devices().is_ok());
    }

    #[test]
    fn test_debug_error() {
        assert_eq!(
            format!("{}", Error::BusError(devices::BusError::Overlap)),
            format!(
                "Failed to add legacy device to Bus: {}",
                devices::BusError::Overlap
            )
        );
        assert_eq!(
            format!("{}", Error::EventFd(std::io::Error::from_raw_os_error(1))),
            format!(
                "Failed to create EventFd: {}",
                std::io::Error::from_raw_os_error(1)
            )
        );
    }

    #[test]
    fn legacy_inventory_retains_bus_only_uart_sinks_and_independent_routes() {
        let cmos = Arc::new(Mutex::new(devices::legacy::Cmos::new(0, 0)));
        let mut manager = PortIODeviceManager::new(
            cmos,
            Vec::new(),
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
        )
        .unwrap();
        manager.register_devices().unwrap();
        assert_eq!(manager.attached_serial.len(), 3);
        let mut inventory = DeviceQuiescence::default();
        manager.retain_live_inventory(&mut inventory);
        let addresses: Vec<_> = inventory
            .legacy_attachments()
            .iter()
            .map(|attachment| attachment.address)
            .collect();
        assert_eq!(addresses, [0x70, 0x2f8, 0x3e8, 0x2e8, 0x60]);
        assert!(inventory.preflight_quiesce().is_ok());
        let cut = inventory.capture_legacy().unwrap();
        assert_eq!(cut.len(), 5);
        inventory.install_legacy(&cut).unwrap();
        assert_eq!(inventory.capture_legacy().unwrap(), cut);
        let routes = manager.irq_events();
        assert_eq!(
            routes.iter().map(|(gsi, _)| *gsi).collect::<Vec<_>>(),
            [4, 3, 4, 3, 1]
        );
        routes[0].1.write(2).unwrap();
        routes[2].1.write(5).unwrap();
        assert_eq!(routes[0].1.read().unwrap(), 2);
        assert_eq!(routes[2].1.read().unwrap(), 5);
    }
}
