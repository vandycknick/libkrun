// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Handles routing to devices in an address space.

use std::cmp::{Ord, Ordering, PartialEq, PartialOrd};
use std::collections::btree_map::BTreeMap;
use std::fmt;
use std::io;
use std::result;
use std::sync::{Arc, Mutex};

use crate::virtio::AsAny;

/// Trait for devices that respond to reads or writes in an arbitrary address space.
///
/// The device does not care where it exists in address space as each method is only given an offset
/// into its allocated portion of address space.
#[allow(unused_variables)]
pub trait BusDevice: AsAny + Send {
    /// Reads at `offset` from this device
    fn read(&mut self, vcpuid: u64, offset: u64, data: &mut [u8]) {}
    /// Writes at `offset` into this device
    fn write(&mut self, vcpuid: u64, offset: u64, data: &[u8]) {}
    /// Triggers the `irq_mask` interrupt on this device
    fn interrupt(&self, irq_mask: u32) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
pub enum Error {
    /// The insertion failed because the new device overlapped with an old device.
    Overlap,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match *self {
            Overlap => write!(f, "New device overlaps with an old device."),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, Copy, Clone)]
struct BusRange(u64, u64);

impl Eq for BusRange {}

impl PartialEq for BusRange {
    fn eq(&self, other: &BusRange) -> bool {
        self.0 == other.0
    }
}

impl Ord for BusRange {
    fn cmp(&self, other: &BusRange) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for BusRange {
    fn partial_cmp(&self, other: &BusRange) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(feature = "native-device-probe")]
pub trait BusAccessObserver: Send + Sync {
    fn completed(&self, cpu: u64, address: u64, write: bool, data: &[u8]);
}

/// A device container for routing reads and writes over some address space.
///
/// This doesn't have any restrictions on what kind of device or address space this applies to. The
/// only restriction is that no two devices can overlap in this address space.
#[derive(Clone, Default)]
pub struct Bus {
    devices: BTreeMap<BusRange, Arc<Mutex<dyn BusDevice>>>,
    #[cfg(feature = "native-device-probe")]
    observer: Arc<Mutex<Option<Arc<dyn BusAccessObserver>>>>,
}

impl Bus {
    /// Constructs an a bus with an empty address space.
    pub fn new() -> Bus {
        Bus {
            devices: BTreeMap::new(),
            #[cfg(feature = "native-device-probe")]
            observer: Arc::new(Mutex::new(None)),
        }
    }

    #[cfg(feature = "native-device-probe")]
    pub fn observe_accesses(&self, observer: Arc<dyn BusAccessObserver>) -> io::Result<()> {
        let mut slot = self
            .observer
            .lock()
            .map_err(|_| io::Error::other("bus observer poisoned"))?;
        if slot.is_some() {
            return Err(io::Error::other("bus observer already installed"));
        }
        *slot = Some(observer);
        Ok(())
    }

    #[cfg(feature = "native-device-probe")]
    fn observe_completion(&self, cpu: u64, address: u64, write: bool, data: &[u8]) {
        let observer = self.observer.lock().ok().and_then(|slot| slot.clone());
        if let Some(observer) = observer {
            observer.completed(cpu, address, write, data);
        }
    }

    fn first_before(&self, addr: u64) -> Option<(BusRange, &Mutex<dyn BusDevice>)> {
        // for when we switch to rustc 1.17: self.devices.range(..addr).iter().rev().next()
        for (range, dev) in self.devices.iter().rev() {
            if range.0 <= addr {
                return Some((*range, dev));
            }
        }
        None
    }

    pub fn get_device(&self, addr: u64) -> Option<(u64, &Mutex<dyn BusDevice>)> {
        if let Some((BusRange(start, len), dev)) = self.first_before(addr) {
            let offset = addr - start;
            if offset < len {
                return Some((offset, dev));
            }
        }
        None
    }

    /// Puts the given device at the given address space.
    pub fn insert(&mut self, device: Arc<Mutex<dyn BusDevice>>, base: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Err(Error::Overlap);
        }

        // Reject all cases where the new device's base is within an old device's range.
        if self.get_device(base).is_some() {
            return Err(Error::Overlap);
        }

        // The above check will miss an overlap in which the new device's base address is before the
        // range of another device. To catch that case, we search for a device with a range before
        // the new device's range's end. If there is no existing device in that range that starts
        // after the new device, then there will be no overlap.
        if let Some((BusRange(start, _), _)) = self.first_before(base + len - 1) {
            // Such a device only conflicts with the new device if it also starts after the new
            // device because of our initial `get_device` check above.
            if start >= base {
                return Err(Error::Overlap);
            }
        }

        if self.devices.insert(BusRange(base, len), device).is_some() {
            return Err(Error::Overlap);
        }

        Ok(())
    }

    /// Reads data from the device that owns the range containing `addr` and puts it into `data`.
    ///
    /// Returns true on success, otherwise `data` is untouched.
    pub fn read(&self, vcpuid: u64, addr: u64, data: &mut [u8]) -> bool {
        if let Some((offset, dev)) = self.get_device(addr) {
            // OK to unwrap as lock() failing is a serious error condition and should panic.
            dev.lock()
                .expect("Failed to acquire device lock")
                .read(vcpuid, offset, data);
            #[cfg(feature = "native-device-probe")]
            self.observe_completion(vcpuid, addr, false, data);
            true
        } else {
            false
        }
    }

    /// Writes `data` to the device that owns the range containing `addr`.
    ///
    /// Returns true on success, otherwise `data` is untouched.
    pub fn write(&self, vcpuid: u64, addr: u64, data: &[u8]) -> bool {
        if let Some((offset, dev)) = self.get_device(addr) {
            // OK to unwrap as lock() failing is a serious error condition and should panic.
            dev.lock()
                .expect("Failed to acquire device lock")
                .write(vcpuid, offset, data);
            #[cfg(feature = "native-device-probe")]
            self.observe_completion(vcpuid, addr, true, data);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyDevice;
    impl BusDevice for DummyDevice {}

    struct ConstantDevice;
    impl BusDevice for ConstantDevice {
        fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
            for (i, v) in data.iter_mut().enumerate() {
                *v = (offset as u8) + (i as u8);
            }
        }

        fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
            for (i, v) in data.iter().enumerate() {
                assert_eq!(*v, (offset as u8) + (i as u8))
            }
        }
    }

    #[test]
    fn bus_insert() {
        let mut bus = Bus::new();
        let dummy = Arc::new(Mutex::new(DummyDevice));
        // Insert len should not be 0.
        assert!(bus.insert(dummy.clone(), 0x10, 0).is_err());
        assert!(bus.insert(dummy.clone(), 0x10, 0x10).is_ok());

        let result = bus.insert(dummy.clone(), 0x0f, 0x10);
        // This overlaps the address space of the existing bus device at 0x10.
        assert!(result.is_err());
        assert_eq!(format!("{result:?}"), "Err(Overlap)");

        // This overlaps the address space of the existing bus device at 0x10.
        assert!(bus.insert(dummy.clone(), 0x10, 0x10).is_err());
        // This overlaps the address space of the existing bus device at 0x10.
        assert!(bus.insert(dummy.clone(), 0x10, 0x15).is_err());
        // This overlaps the address space of the existing bus device at 0x10.
        assert!(bus.insert(dummy.clone(), 0x12, 0x15).is_err());
        // This overlaps the address space of the existing bus device at 0x10.
        assert!(bus.insert(dummy.clone(), 0x12, 0x01).is_err());
        // This overlaps the address space of the existing bus device at 0x10.
        assert!(bus.insert(dummy.clone(), 0x0, 0x20).is_err());
        assert!(bus.insert(dummy.clone(), 0x20, 0x05).is_ok());
        assert!(bus.insert(dummy.clone(), 0x25, 0x05).is_ok());
        assert!(bus.insert(dummy, 0x0, 0x10).is_ok());
    }

    #[test]
    fn bus_read_write() {
        let mut bus = Bus::new();
        let dummy = Arc::new(Mutex::new(DummyDevice));
        assert!(bus.insert(dummy, 0x10, 0x10).is_ok());
        assert!(bus.read(0, 0x10, &mut [0, 0, 0, 0]));
        assert!(bus.write(0, 0x10, &[0, 0, 0, 0]));
        assert!(bus.read(0, 0x11, &mut [0, 0, 0, 0]));
        assert!(bus.write(0, 0x11, &[0, 0, 0, 0]));
        assert!(bus.read(0, 0x16, &mut [0, 0, 0, 0]));
        assert!(bus.write(0, 0x16, &[0, 0, 0, 0]));
        assert!(!bus.read(0, 0x20, &mut [0, 0, 0, 0]));
        assert!(!bus.write(0, 0x20, &[0, 0, 0, 0]));
        assert!(!bus.read(0, 0x06, &mut [0, 0, 0, 0]));
        assert!(!bus.write(0, 0x06, &[0, 0, 0, 0]));
    }

    #[test]
    fn bus_read_write_values() {
        let mut bus = Bus::new();
        let dummy = Arc::new(Mutex::new(ConstantDevice));
        assert!(bus.insert(dummy, 0x10, 0x10).is_ok());

        let mut values = [0, 1, 2, 3];
        assert!(bus.read(0, 0x10, &mut values));
        assert_eq!(values, [0, 1, 2, 3]);
        assert!(bus.write(0, 0x10, &values));
        assert!(bus.read(0, 0x15, &mut values));
        assert_eq!(values, [5, 6, 7, 8]);
        assert!(bus.write(0, 0x15, &values));
    }

    #[test]
    fn busrange_cmp_and_clone() {
        assert_eq!(BusRange(0x10, 2), BusRange(0x10, 3));
        assert_eq!(BusRange(0x10, 2), BusRange(0x10, 2));

        assert!(BusRange(0x10, 2) < BusRange(0x12, 1));
        assert!(BusRange(0x10, 2) < BusRange(0x12, 3));

        let bus_range = BusRange(0x10, 2);
        assert_eq!(bus_range, BusRange(0x10, 2));

        let mut bus = Bus::new();
        let mut data = [1, 2, 3, 4];
        assert!(
            bus.insert(Arc::new(Mutex::new(DummyDevice)), 0x10, 0x10)
                .is_ok()
        );
        assert!(bus.write(0, 0x10, &data));
        let bus_clone = bus.clone();
        assert!(bus.read(0, 0x10, &mut data));
        assert_eq!(data, [1, 2, 3, 4]);
        assert!(bus_clone.read(0, 0x10, &mut data));
        assert_eq!(data, [1, 2, 3, 4]);
    }

    #[test]
    fn test_display_error() {
        assert_eq!(
            format!("{}", Error::Overlap),
            "New device overlaps with an old device."
        );
    }

    #[cfg(feature = "native-device-probe")]
    #[test]
    fn bus_probe_real_serial_completion_is_observed_across_clones() {
        use crate::bus::BusAccessObserver;
        use crate::legacy::Serial;
        use std::sync::atomic::{AtomicU64, Ordering};
        use utils::eventfd::{EFD_NONBLOCK, EventFd};

        #[derive(Default)]
        struct SerialObservation {
            count: AtomicU64,
            written: AtomicU64,
            read: AtomicU64,
        }
        impl BusAccessObserver for SerialObservation {
            fn completed(&self, cpu: u64, address: u64, write: bool, data: &[u8]) {
                assert_eq!(address, 0x3ef);
                assert_eq!(cpu, 2);
                assert_eq!(data, &[0x5a]);
                self.count.fetch_add(1, Ordering::Relaxed);
                if write {
                    self.written.store(u64::from(data[0]), Ordering::Relaxed);
                } else {
                    self.read.store(u64::from(data[0]), Ordering::Relaxed);
                }
            }
        }
        let serial = Arc::new(Mutex::new(Serial::new_sink(
            EventFd::new(EFD_NONBLOCK).unwrap(),
        )));
        let mut bus = Bus::new();
        bus.insert(serial, 0x3e8, 8).unwrap();
        let owner_bus = bus.clone();
        let observation = Arc::new(SerialObservation::default());
        bus.observe_accesses(observation.clone()).unwrap();
        assert!(owner_bus.write(2, 0x3ef, &[0x5a]));
        let mut actual = [0u8];
        assert!(owner_bus.read(2, 0x3ef, &mut actual));
        assert_eq!(actual, [0x5a]);
        assert_eq!(observation.count.load(Ordering::Relaxed), 2);
        assert_eq!(observation.written.load(Ordering::Relaxed), 0x5a);
        assert_eq!(observation.read.load(Ordering::Relaxed), 0x5a);
        assert!(owner_bus.observe_accesses(observation.clone()).is_err());
    }
}
