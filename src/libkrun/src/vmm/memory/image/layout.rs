use arch::ArchMemoryInfo;
use arch::guest_memory::RegisteredRamLayout;
use utils::state::{Error, Reader, StateHeaderError, Writer};

use crate::vmm::execution::{ExecutionLane, ValidatedExecution, host_page_granule};
use crate::vmm::memory::image::{RamImageError, RamRegion, ValidatedRamLayout};

pub const MAX_RAM_LAYOUT_BYTES: usize = 64 * 1024;
pub const MAX_RAM_REGIONS: usize = 512;
pub const MAX_PACKED_RAM_BYTES: u64 = 1 << 40;
pub const MAX_JSON_INTEGER: u64 = (1 << 53) - 1;
const RAM_LAYOUT_MAGIC: &[u8; 8] = b"KRUNRAML";
const RAM_LAYOUT_SCHEMA: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RamTopology {
    X86 {
        firmware: u64,
        initrd: u64,
        above: u64,
        below: u64,
        end: u64,
        shm: u64,
    },
    Arm {
        fdt: u64,
        firmware: u64,
        initrd: u64,
        end: u64,
        start: u64,
        shm: u64,
    },
}

impl RamTopology {
    fn from_info(info: &ArchMemoryInfo) -> Result<Self, RamImageError> {
        #[cfg(target_arch = "x86_64")]
        {
            Ok(Self::X86 {
                firmware: info.firmware_addr,
                initrd: info.initrd_addr,
                above: info.ram_above_gap,
                below: info.ram_below_gap,
                end: info.ram_last_addr,
                shm: info.shm_start_addr,
            })
        }
        #[cfg(target_arch = "aarch64")]
        {
            Ok(Self::Arm {
                fdt: info.fdt_addr,
                firmware: info.firmware_addr,
                initrd: info.initrd_addr,
                end: info.ram_last_addr,
                start: info.ram_start_addr,
                shm: info.shm_start_addr,
            })
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            let _ = info;
            Err(RamImageError::Topology)
        }
    }
}

impl ValidatedRamLayout {
    pub fn from_registered(
        registered: &RegisteredRamLayout,
        info: &ArchMemoryInfo,
        lane: ExecutionLane,
    ) -> Result<Self, RamImageError> {
        registered
            .validate_capture()
            .map_err(RamImageError::Authority)?;
        if info.page_size != registered.granule() as usize {
            return Err(RamImageError::Geometry);
        }
        let mut regions = Vec::new();
        regions
            .try_reserve_exact(registered.regions().len())
            .map_err(|_| RamImageError::Allocation)?;
        for region in registered.regions() {
            regions.push(RamRegion {
                guest_start: region.guest_range().start(),
                length: region.guest_range().byte_len(),
                stream_offset: region.stream_offset(),
                first_page: region.first_page(),
            });
        }
        let topology = RamTopology::from_info(info)?;
        let mut layout = Self {
            regions: regions.into_boxed_slice(),
            granule: registered.granule(),
            packed_len: registered.packed_len(),
            topology,
            canonical: Box::new([]),
        };
        layout.validate_geometry()?;
        layout.validate_topology()?;
        layout.validate_lane(lane)?;
        layout.validate_native()?;
        layout.canonical = layout.encode()?;
        Ok(layout)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RamImageError> {
        let layout = Self::decode_record(bytes)?;
        layout.validate_native()?;
        Ok(layout)
    }

    fn decode_record(bytes: &[u8]) -> Result<Self, RamImageError> {
        if bytes.len() > MAX_RAM_LAYOUT_BYTES {
            return Err(Error::Limit.into());
        }
        let mut p = Parser {
            reader: Reader::new(bytes),
            next: None,
        };
        p.literal(b"{\"architecture\":\"")?;
        let architecture = match p.byte()? {
            b'x' => {
                p.literal(b"86_64\"")?;
                true
            }
            b'a' => {
                p.literal(b"arch64\"")?;
                false
            }
            _ => return Err(Error::Invalid("RAM architecture").into()),
        };
        p.literal(b",\"kind\":\"ram-layout\",\"magic\":\"")?;
        let mut found = [0; 8];
        for byte in &mut found {
            *byte = p.byte()?;
        }
        if found != *RAM_LAYOUT_MAGIC {
            return Err(Error::Header(StateHeaderError::Magic {
                expected: *RAM_LAYOUT_MAGIC,
                found,
            })
            .into());
        }
        p.literal(b"\",\"packedLength\":")?;
        let packed_len = p.integer()?;
        p.literal(b",\"pageGranule\":")?;
        let granule = u32::try_from(p.integer()?).map_err(|_| Error::Overflow)?;
        p.literal(b",\"regions\":[")?;
        let mut regions = Vec::new();
        let mut first_page = 0usize;
        if p.peek()? != b']' {
            loop {
                if regions.len() == MAX_RAM_REGIONS {
                    return Err(Error::Limit.into());
                }
                regions
                    .try_reserve(1)
                    .map_err(|_| RamImageError::Allocation)?;
                p.literal(b"{\"guestPhysicalAddress\":")?;
                let guest_start = p.integer()?;
                p.literal(b",\"length\":")?;
                let length = p.integer()?;
                p.literal(b",\"streamOffset\":")?;
                let stream_offset = p.integer()?;
                p.literal(b"}")?;
                regions.push(RamRegion {
                    guest_start,
                    length,
                    stream_offset,
                    first_page,
                });
                if granule == 0 {
                    return Err(RamImageError::Geometry);
                }
                first_page = first_page
                    .checked_add(
                        usize::try_from(length / u64::from(granule))
                            .map_err(|_| Error::Overflow)?,
                    )
                    .ok_or(Error::Overflow)?;
                if p.peek()? != b',' {
                    break;
                }
                p.byte()?;
            }
        }
        p.literal(b"],\"schema\":")?;
        let found = u16::try_from(p.integer()?).map_err(|_| Error::Invalid("RAM layout schema"))?;
        if found != RAM_LAYOUT_SCHEMA {
            return Err(Error::Header(StateHeaderError::Schema {
                expected: RAM_LAYOUT_SCHEMA,
                found,
            })
            .into());
        }
        p.literal(b",\"topology\":{")?;
        let topology = if architecture {
            p.literal(b"\"firmwareAddress\":")?;
            let firmware = p.integer()?;
            p.literal(b",\"initrdAddress\":")?;
            let initrd = p.integer()?;
            p.literal(b",\"ramAboveGap\":")?;
            let above = p.integer()?;
            p.literal(b",\"ramBelowGap\":")?;
            let below = p.integer()?;
            p.literal(b",\"ramLastAddress\":")?;
            let end = p.integer()?;
            p.literal(b",\"shmStartAddress\":")?;
            let shm = p.integer()?;
            RamTopology::X86 {
                firmware,
                initrd,
                above,
                below,
                end,
                shm,
            }
        } else {
            p.literal(b"\"fdtAddress\":")?;
            let fdt = p.integer()?;
            p.literal(b",\"firmwareAddress\":")?;
            let firmware = p.integer()?;
            p.literal(b",\"initrdAddress\":")?;
            let initrd = p.integer()?;
            p.literal(b",\"ramLastAddress\":")?;
            let end = p.integer()?;
            p.literal(b",\"ramStartAddress\":")?;
            let start = p.integer()?;
            p.literal(b",\"shmStartAddress\":")?;
            let shm = p.integer()?;
            RamTopology::Arm {
                fdt,
                firmware,
                initrd,
                end,
                start,
                shm,
            }
        };
        p.literal(b"}}")?;
        p.finish()?;
        let mut canonical = Vec::new();
        canonical
            .try_reserve_exact(bytes.len())
            .map_err(|_| RamImageError::Allocation)?;
        canonical.extend_from_slice(bytes);
        let layout = Self {
            regions: regions.into_boxed_slice(),
            granule,
            packed_len,
            topology,
            canonical: canonical.into_boxed_slice(),
        };
        layout.validate_geometry()?;
        layout.validate_topology()?;
        Ok(layout)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn packed_len(&self) -> u64 {
        self.packed_len
    }
    pub fn granule(&self) -> u32 {
        self.granule
    }
    pub fn regions(&self) -> &[RamRegion] {
        &self.regions
    }

    pub fn validate_registered(
        &self,
        registered: &RegisteredRamLayout,
    ) -> Result<(), RamImageError> {
        registered
            .validate_capture()
            .map_err(RamImageError::Authority)?;
        if self.granule != registered.granule()
            || self.packed_len != registered.packed_len()
            || self.regions.len() != registered.regions().len()
            || self.regions.iter().zip(registered.regions()).any(|(a, b)| {
                a.guest_start != b.guest_range().start()
                    || a.length != b.guest_range().byte_len()
                    || a.stream_offset != b.stream_offset()
                    || a.first_page != b.first_page()
            })
        {
            return Err(RamImageError::Geometry);
        }
        Ok(())
    }

    pub fn validate_execution(&self, execution: &ValidatedExecution) -> Result<(), RamImageError> {
        let envelope = execution.envelope();
        self.validate_native()?;
        self.validate_lane(envelope.lane)?;
        if self.granule != envelope.page_granule
            || self.regions.len() != envelope.memory_regions.len()
            || self
                .regions
                .iter()
                .zip(&envelope.memory_regions)
                .any(|(a, b)| a.guest_start != b.start() || a.length != b.byte_len())
        {
            return Err(RamImageError::ExecutionBinding);
        }
        Ok(())
    }

    pub fn validate_source(
        &self,
        registered: &RegisteredRamLayout,
        info: &ArchMemoryInfo,
        lane: ExecutionLane,
    ) -> Result<(), RamImageError> {
        self.validate_registered(registered)?;
        self.validate_native()?;
        self.validate_lane(lane)?;
        if info.page_size != self.granule as usize || RamTopology::from_info(info)? != self.topology
        {
            return Err(RamImageError::Topology);
        }
        Ok(())
    }

    fn validate_native(&self) -> Result<(), RamImageError> {
        let matches = match self.topology {
            RamTopology::X86 { .. } => cfg!(target_arch = "x86_64"),
            RamTopology::Arm { .. } => cfg!(target_arch = "aarch64"),
        };
        if !matches || self.granule != host_page_granule()? {
            return Err(RamImageError::Geometry);
        }
        Ok(())
    }

    fn validate_lane(&self, lane: ExecutionLane) -> Result<(), RamImageError> {
        if !matches!(
            (&self.topology, lane),
            (RamTopology::X86 { .. }, ExecutionLane::KvmX86)
                | (
                    RamTopology::Arm { .. },
                    ExecutionLane::KvmArm64 | ExecutionLane::HvfArm64
                )
        ) {
            return Err(RamImageError::ExecutionBinding);
        }
        Ok(())
    }

    fn validate_geometry(&self) -> Result<(), RamImageError> {
        if !self.granule.is_power_of_two()
            || !(4096..=65536).contains(&self.granule)
            || self.regions.is_empty()
            || self.regions.len() > MAX_RAM_REGIONS
            || self.packed_len == 0
            || self.packed_len > MAX_PACKED_RAM_BYTES
        {
            return Err(RamImageError::Geometry);
        }
        let g = u64::from(self.granule);
        let mut end = 0;
        let mut packed = 0u64;
        let mut pages = 0usize;
        for r in &self.regions {
            let guest_end = r
                .guest_start
                .checked_add(r.length)
                .ok_or(RamImageError::Geometry)?;
            let stream_end = r
                .stream_offset
                .checked_add(r.length)
                .ok_or(RamImageError::Geometry)?;
            if r.length == 0
                || r.guest_start < end
                || !r.guest_start.is_multiple_of(g)
                || !r.length.is_multiple_of(g)
                || !r.stream_offset.is_multiple_of(g)
                || r.stream_offset != packed
                || r.first_page != pages
                || guest_end > MAX_JSON_INTEGER
            {
                return Err(RamImageError::Geometry);
            }
            usize::try_from(r.length).map_err(|_| RamImageError::Geometry)?;
            i64::try_from(r.stream_offset).map_err(|_| RamImageError::Geometry)?;
            i64::try_from(stream_end).map_err(|_| RamImageError::Geometry)?;
            pages = pages
                .checked_add(usize::try_from(r.length / g).map_err(|_| RamImageError::Geometry)?)
                .ok_or(RamImageError::Geometry)?;
            end = guest_end;
            packed = stream_end;
        }
        usize::try_from(self.packed_len.div_ceil(8 * 1024 * 1024).div_ceil(64))
            .map_err(|_| RamImageError::Geometry)?;
        if packed != self.packed_len {
            return Err(RamImageError::Geometry);
        }
        Ok(())
    }

    fn covered(&self, start: u64, end: u64) -> bool {
        if start > end {
            return false;
        }
        let mut cursor = start;
        for r in &self.regions {
            if r.guest_start > cursor {
                break;
            }
            let region_end = r.guest_start + r.length;
            if region_end > cursor {
                cursor = region_end.min(end);
            }
            if cursor == end {
                return true;
            }
        }
        cursor == end
    }

    fn validate_topology(&self) -> Result<(), RamImageError> {
        let g = u64::from(self.granule);
        let (end, shm, values): (u64, u64, [u64; 6]) = match self.topology {
            RamTopology::X86 {
                firmware,
                initrd,
                above,
                below,
                end,
                shm,
            } => (end, shm, [firmware, initrd, above, below, end, shm]),
            RamTopology::Arm {
                fdt,
                firmware,
                initrd,
                end,
                start,
                shm,
            } => (end, shm, [fdt, firmware, initrd, end, start, shm]),
        };
        if values.iter().any(|v| *v > MAX_JSON_INTEGER)
            || end == 0
            || !end.is_multiple_of(g)
            || !shm.is_multiple_of(g)
            || shm < end
            || self
                .regions
                .iter()
                .any(|r| r.guest_start <= shm && shm < r.guest_start + r.length)
            || !self.regions.iter().any(|r| r.guest_start + r.length == end)
        {
            return Err(RamImageError::Topology);
        }
        match self.topology {
            RamTopology::X86 {
                firmware,
                initrd,
                above,
                below,
                end,
                ..
            } => {
                const HIGH: u64 = 1 << 32;
                const GAP: u64 = HIGH - (768 << 20);
                let low_end = if above > 0 { GAP } else { end };
                if below == 0
                    || below > GAP
                    || !below.is_multiple_of(g)
                    || !above.is_multiple_of(g)
                    || !initrd.is_multiple_of(g)
                    || initrd > low_end
                    || (initrd < low_end && !self.covered(initrd, low_end))
                    || !self.regions.iter().any(|r| r.guest_start == 0)
                {
                    return Err(RamImageError::Topology);
                }
                if above > 0 {
                    if end.checked_sub(HIGH) != Some(above)
                        || !self.covered(HIGH, end)
                        || below != GAP
                        || !self.regions.iter().any(|r| r.guest_start + r.length == GAP)
                    {
                        return Err(RamImageError::Topology);
                    }
                } else if end > GAP {
                    return Err(RamImageError::Topology);
                }
                if firmware != 0
                    && (firmware < GAP
                        || !self
                            .regions
                            .iter()
                            .any(|r| r.guest_start == firmware && r.guest_start + r.length == HIGH))
                {
                    return Err(RamImageError::Topology);
                }
                if self.regions.iter().any(|r| {
                    r.guest_start >= low_end
                        && !(above > 0 && r.guest_start >= HIGH && r.guest_start + r.length <= end)
                        && !(firmware != 0
                            && r.guest_start == firmware
                            && r.guest_start + r.length == HIGH)
                }) {
                    return Err(RamImageError::Topology);
                }
            }
            RamTopology::Arm {
                fdt,
                firmware,
                initrd,
                end,
                start,
                ..
            } => {
                const EFI: u64 = 0x4000_0000;
                const KERNEL: u64 = 0x8000_0000;
                const FDT: u64 = 0x20_0000;
                if !matches!(start, EFI | KERNEL)
                    || firmware != 0
                    || start >= end
                    || !self.covered(start, end)
                    || initrd > fdt
                    || !self.covered(initrd, fdt)
                {
                    return Err(RamImageError::Topology);
                }
                let fdt_end = fdt.checked_add(FDT).ok_or(RamImageError::Topology)?;
                if !self.covered(fdt, fdt_end)
                    || (start == EFI
                        && (fdt != start
                            || !self
                                .regions
                                .iter()
                                .any(|r| r.guest_start == 0 && r.length <= start)))
                    || (start == KERNEL && end.checked_sub(FDT) != Some(fdt))
                {
                    return Err(RamImageError::Topology);
                }
                if self.regions.iter().any(|r| {
                    !(r.guest_start >= start && r.guest_start + r.length <= end
                        || start == EFI && r.guest_start == 0 && r.length <= start)
                }) {
                    return Err(RamImageError::Topology);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn arch_info(&self) -> Result<ArchMemoryInfo, RamImageError> {
        self.validate_native()?;
        #[cfg(target_arch = "x86_64")]
        if let RamTopology::X86 {
            firmware,
            initrd,
            above,
            below,
            end,
            shm,
        } = self.topology
        {
            return Ok(ArchMemoryInfo {
                ram_below_gap: below,
                ram_above_gap: above,
                ram_last_addr: end,
                shm_start_addr: shm,
                page_size: self.granule as usize,
                initrd_addr: initrd,
                firmware_addr: firmware,
            });
        }
        #[cfg(target_arch = "aarch64")]
        if let RamTopology::Arm {
            fdt,
            firmware,
            initrd,
            end,
            start,
            shm,
        } = self.topology
        {
            return Ok(ArchMemoryInfo {
                ram_start_addr: start,
                ram_last_addr: end,
                shm_start_addr: shm,
                page_size: self.granule as usize,
                fdt_addr: fdt,
                initrd_addr: initrd,
                firmware_addr: firmware,
            });
        }
        Err(RamImageError::Topology)
    }

    fn encode(&self) -> Result<Box<[u8]>, RamImageError> {
        let mut w = Writer::new(MAX_RAM_LAYOUT_BYTES);
        w.fixed(match self.topology {
            RamTopology::X86 { .. } => b"{\"architecture\":\"x86_64\"",
            RamTopology::Arm { .. } => b"{\"architecture\":\"aarch64\"",
        })?;
        w.fixed(b",\"kind\":\"ram-layout\",\"magic\":\"")?;
        w.fixed(RAM_LAYOUT_MAGIC)?;
        w.fixed(b"\",\"packedLength\":")?;
        integer(&mut w, self.packed_len)?;
        w.fixed(b",\"pageGranule\":")?;
        integer(&mut w, u64::from(self.granule))?;
        w.fixed(b",\"regions\":[")?;
        for (i, r) in self.regions.iter().enumerate() {
            if i != 0 {
                w.fixed(b",")?;
            }
            w.fixed(b"{\"guestPhysicalAddress\":")?;
            integer(&mut w, r.guest_start)?;
            w.fixed(b",\"length\":")?;
            integer(&mut w, r.length)?;
            w.fixed(b",\"streamOffset\":")?;
            integer(&mut w, r.stream_offset)?;
            w.fixed(b"}")?;
        }
        w.fixed(b"],\"schema\":")?;
        integer(&mut w, u64::from(RAM_LAYOUT_SCHEMA))?;
        w.fixed(b",\"topology\":{")?;
        let fields = match self.topology {
            RamTopology::X86 {
                firmware,
                initrd,
                above,
                below,
                end,
                shm,
            } => [
                ("firmwareAddress", firmware),
                ("initrdAddress", initrd),
                ("ramAboveGap", above),
                ("ramBelowGap", below),
                ("ramLastAddress", end),
                ("shmStartAddress", shm),
            ],
            RamTopology::Arm {
                fdt,
                firmware,
                initrd,
                end,
                start,
                shm,
            } => [
                ("fdtAddress", fdt),
                ("firmwareAddress", firmware),
                ("initrdAddress", initrd),
                ("ramLastAddress", end),
                ("ramStartAddress", start),
                ("shmStartAddress", shm),
            ],
        };
        for (i, (name, value)) in fields.iter().enumerate() {
            if i != 0 {
                w.fixed(b",")?;
            }
            w.fixed(b"\"")?;
            w.fixed(name.as_bytes())?;
            w.fixed(b"\":")?;
            integer(&mut w, *value)?;
        }
        w.fixed(b"}}")?;
        Ok(w.finish().into_boxed_slice())
    }
}

fn integer(w: &mut Writer, mut value: u64) -> Result<(), Error> {
    if value > MAX_JSON_INTEGER {
        return Err(Error::Limit);
    }
    let mut digits = [0u8; 16];
    let mut pos = digits.len();
    loop {
        pos -= 1;
        digits[pos] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    w.fixed(&digits[pos..])
}

struct Parser<'a> {
    reader: Reader<'a>,
    next: Option<u8>,
}
impl Parser<'_> {
    fn byte(&mut self) -> Result<u8, Error> {
        match self.next.take() {
            Some(b) => Ok(b),
            None => self.reader.u8(),
        }
    }
    fn peek(&mut self) -> Result<u8, Error> {
        let b = self.byte()?;
        self.next = Some(b);
        Ok(b)
    }
    fn literal(&mut self, bytes: &[u8]) -> Result<(), Error> {
        for expected in bytes {
            if self.byte()? != *expected {
                return Err(Error::Invalid("canonical RAM layout"));
            }
        }
        Ok(())
    }
    fn integer(&mut self) -> Result<u64, Error> {
        let first = self.byte()?;
        if !first.is_ascii_digit() {
            return Err(Error::Invalid("RAM integer"));
        }
        let mut value = u64::from(first - b'0');
        while self.peek()?.is_ascii_digit() {
            if first == b'0' {
                return Err(Error::Invalid("RAM leading zero"));
            }
            let digit = u64::from(self.byte()? - b'0');
            value = value
                .checked_mul(10)
                .and_then(|v| v.checked_add(digit))
                .ok_or(Error::Overflow)?;
            if value > MAX_JSON_INTEGER {
                return Err(Error::Limit);
            }
        }
        Ok(value)
    }
    fn finish(self) -> Result<(), Error> {
        if self.next.is_some() {
            return Err(Error::Trailing);
        }
        self.reader.finish()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::vmm::memory::image::layout::{MAX_RAM_LAYOUT_BYTES, RamTopology};
    use crate::vmm::memory::image::{RamImageError, RamRegion, ValidatedRamLayout};

    pub(crate) const X86: &str = "{\"architecture\":\"x86_64\",\"kind\":\"ram-layout\",\"magic\":\"KRUNRAML\",\"packedLength\":12288,\"pageGranule\":4096,\"regions\":[{\"guestPhysicalAddress\":0,\"length\":4096,\"streamOffset\":0},{\"guestPhysicalAddress\":4096,\"length\":8192,\"streamOffset\":4096}],\"schema\":1,\"topology\":{\"firmwareAddress\":0,\"initrdAddress\":12288,\"ramAboveGap\":0,\"ramBelowGap\":12288,\"ramLastAddress\":12288,\"shmStartAddress\":4294967296}}";
    const ARM: &str = "{\"architecture\":\"aarch64\",\"kind\":\"ram-layout\",\"magic\":\"KRUNRAML\",\"packedLength\":4194304,\"pageGranule\":4096,\"regions\":[{\"guestPhysicalAddress\":2147483648,\"length\":4194304,\"streamOffset\":0}],\"schema\":1,\"topology\":{\"fdtAddress\":2149580800,\"firmwareAddress\":0,\"initrdAddress\":2149580799,\"ramLastAddress\":2151677952,\"ramStartAddress\":2147483648,\"shmStartAddress\":3221225472}}";

    #[test]
    fn ram_layout_rejects_wrong_magic_and_schema_with_typed_errors() {
        use utils::state::{Error, StateHeaderError};
        let wrong_magic = X86.replace("KRUNRAML", "WRONGMAG");
        assert!(matches!(
            ValidatedRamLayout::decode_record(wrong_magic.as_bytes()),
            Err(RamImageError::Codec(Error::Header(
                StateHeaderError::Magic { .. }
            )))
        ));
        let wrong_schema = X86.replace("\"schema\":1", "\"schema\":2");
        assert!(matches!(
            ValidatedRamLayout::decode_record(wrong_schema.as_bytes()),
            Err(RamImageError::Codec(Error::Header(
                StateHeaderError::Schema {
                    expected: 1,
                    found: 2
                }
            )))
        ));
    }

    #[test]
    fn exact_architecture_goldens_preserve_segmentation_and_unaligned_arm_initrd() {
        for bytes in [X86, ARM] {
            let layout = ValidatedRamLayout::decode_record(bytes.as_bytes()).unwrap();
            assert_eq!(layout.encode().unwrap().as_ref(), bytes.as_bytes());
        }
        assert_eq!(
            ValidatedRamLayout::decode_record(X86.as_bytes())
                .unwrap()
                .regions()
                .len(),
            2
        );
    }

    #[test]
    fn canonical_grammar_refuses_alternate_encodings_and_closed_schema_changes() {
        for (from, to) in [
            ("\"packedLength\":12288", "\"packedLength\":012288"),
            ("\"packedLength\":12288", "\"packedLength\":1.2288e4"),
            ("\"packedLength\":12288", "\"packedLength\":+12288"),
            ("\"schema\":1", "\"schema\":1,\"schema\":1"),
            ("\"kind\":\"ram-layout\"", "\"unknown\":\"ram-layout\""),
            ("\"schema\":1", "\"schema\":2"),
            ("\"pageGranule\":4096", "\"pageGranule\":9007199254740992"),
        ] {
            assert!(
                ValidatedRamLayout::decode_record(X86.replace(from, to).as_bytes()).is_err(),
                "{to}"
            );
        }
        for len in 0..X86.len() {
            assert!(ValidatedRamLayout::decode_record(&X86.as_bytes()[..len]).is_err());
        }
        assert!(ValidatedRamLayout::decode_record(format!("{X86}\n").as_bytes()).is_err());
        assert!(ValidatedRamLayout::decode_record(&vec![b' '; MAX_RAM_LAYOUT_BYTES + 1]).is_err());
    }

    #[test]
    fn geometry_and_topology_reject_real_boundary_corruption() {
        for (from, to) in [
            ("\"streamOffset\":4096", "\"streamOffset\":8192"),
            (
                "\"guestPhysicalAddress\":4096",
                "\"guestPhysicalAddress\":0",
            ),
            (
                "\"guestPhysicalAddress\":4096",
                "\"guestPhysicalAddress\":4097",
            ),
            ("\"ramLastAddress\":12288", "\"ramLastAddress\":8192"),
            ("\"shmStartAddress\":4294967296", "\"shmStartAddress\":4096"),
            ("\"ramBelowGap\":12288", "\"ramBelowGap\":0"),
            ("\"firmwareAddress\":0", "\"firmwareAddress\":4096"),
        ] {
            assert!(
                ValidatedRamLayout::decode_record(X86.replace(from, to).as_bytes()).is_err(),
                "{to}"
            );
        }
        let mut arm = ValidatedRamLayout::decode_record(ARM.as_bytes()).unwrap();
        if let RamTopology::Arm { ref mut fdt, .. } = arm.topology {
            *fdt += 4096;
        }
        assert!(matches!(
            arm.validate_topology(),
            Err(RamImageError::Topology)
        ));
    }

    #[test]
    fn exact_region_bound_and_native_granule_are_enforced_without_coalescing() {
        for count in [512, 513] {
            let mut layout = ValidatedRamLayout::decode_record(X86.as_bytes()).unwrap();
            layout.regions = (0..count)
                .map(|index| RamRegion {
                    guest_start: index as u64 * 4096,
                    length: 4096,
                    stream_offset: index as u64 * 4096,
                    first_page: index,
                })
                .collect();
            layout.packed_len = count as u64 * 4096;
            layout.topology = RamTopology::X86 {
                firmware: 0,
                initrd: layout.packed_len,
                above: 0,
                below: layout.packed_len,
                end: layout.packed_len,
                shm: 1 << 32,
            };
            let bytes = layout.encode().unwrap();
            assert_eq!(
                ValidatedRamLayout::decode_record(&bytes).is_ok(),
                count == 512
            );
        }
        for granule in [4096u32, 16384, 65536] {
            let mut layout = ValidatedRamLayout::decode_record(X86.as_bytes()).unwrap();
            layout.granule = granule;
            layout.regions = vec![RamRegion {
                guest_start: 0,
                length: u64::from(granule),
                stream_offset: 0,
                first_page: 0,
            }]
            .into_boxed_slice();
            layout.packed_len = u64::from(granule);
            layout.topology = RamTopology::X86 {
                firmware: 0,
                initrd: layout.packed_len,
                above: 0,
                below: layout.packed_len,
                end: layout.packed_len,
                shm: 1 << 32,
            };
            let bytes = layout.encode().unwrap();
            assert!(ValidatedRamLayout::decode_record(&bytes).is_ok());
            assert_eq!(
                ValidatedRamLayout::decode(&bytes).is_ok(),
                cfg!(target_arch = "x86_64")
                    && granule == crate::vmm::execution::host_page_granule().unwrap()
            );
        }
    }

    #[test]
    fn checked_geometry_refuses_overflow_empty_and_wrong_total() {
        let mut layout = ValidatedRamLayout::decode_record(X86.as_bytes()).unwrap();
        layout.regions[1].guest_start = u64::MAX - 4095;
        assert!(layout.validate_geometry().is_err());
        layout.regions[1].guest_start = 4096;
        layout.regions[1].length = 0;
        assert!(layout.validate_geometry().is_err());
        layout.regions[1].length = 8192;
        layout.packed_len += 4096;
        assert!(layout.validate_geometry().is_err());
        layout.regions = Box::new([]);
        assert!(layout.validate_geometry().is_err());
    }

    #[test]
    fn arm_firmware_requires_efi_main_start_and_fdt_reservation() {
        let text = "{\"architecture\":\"aarch64\",\"kind\":\"ram-layout\",\"magic\":\"KRUNRAML\",\"packedLength\":4259840,\"pageGranule\":4096,\"regions\":[{\"guestPhysicalAddress\":0,\"length\":65536,\"streamOffset\":0},{\"guestPhysicalAddress\":1073741824,\"length\":4194304,\"streamOffset\":65536}],\"schema\":1,\"topology\":{\"fdtAddress\":1073741824,\"firmwareAddress\":0,\"initrdAddress\":1073741824,\"ramLastAddress\":1077936128,\"ramStartAddress\":1073741824,\"shmStartAddress\":2147483648}}";
        assert!(ValidatedRamLayout::decode_record(text.as_bytes()).is_ok());
        for (from, to) in [
            ("\"fdtAddress\":1073741824", "\"fdtAddress\":1073745920"),
            ("\"firmwareAddress\":0", "\"firmwareAddress\":4096"),
            (
                "\"initrdAddress\":1073741824",
                "\"initrdAddress\":1073741823",
            ),
            (
                "\"ramStartAddress\":1073741824",
                "\"ramStartAddress\":2147483648",
            ),
        ] {
            assert!(ValidatedRamLayout::decode_record(text.replace(from, to).as_bytes()).is_err());
        }
    }

    #[test]
    fn high_ram_and_firmware_do_not_replace_main_endpoint_or_cmos_metadata() {
        let text = "{\"architecture\":\"x86_64\",\"kind\":\"ram-layout\",\"magic\":\"KRUNRAML\",\"packedLength\":3489730560,\"pageGranule\":4096,\"regions\":[{\"guestPhysicalAddress\":0,\"length\":3489660928,\"streamOffset\":0},{\"guestPhysicalAddress\":4294901760,\"length\":65536,\"streamOffset\":3489660928},{\"guestPhysicalAddress\":4294967296,\"length\":4096,\"streamOffset\":3489726464}],\"schema\":1,\"topology\":{\"firmwareAddress\":4294901760,\"initrdAddress\":3489660928,\"ramAboveGap\":4096,\"ramBelowGap\":3489660928,\"ramLastAddress\":4294971392,\"shmStartAddress\":5368709120}}";
        assert!(ValidatedRamLayout::decode_record(text.as_bytes()).is_ok());
        assert!(
            ValidatedRamLayout::decode_record(
                text.replace("\"ramAboveGap\":4096", "\"ramAboveGap\":8192")
                    .as_bytes()
            )
            .is_err()
        );
        let low_with_firmware = text.replace("\"packedLength\":3489730560","\"packedLength\":3489726464").replace(",{\"guestPhysicalAddress\":4294967296,\"length\":4096,\"streamOffset\":3489726464}","").replace("\"ramAboveGap\":4096","\"ramAboveGap\":0").replace("\"ramLastAddress\":4294971392","\"ramLastAddress\":3489660928").replace("\"shmStartAddress\":5368709120","\"shmStartAddress\":4294967296");
        assert!(ValidatedRamLayout::decode_record(low_with_firmware.as_bytes()).is_ok());
        let mut low = ValidatedRamLayout::decode_record(X86.as_bytes()).unwrap();
        if let RamTopology::X86 { ref mut below, .. } = low.topology {
            *below = 4096;
        }
        assert!(low.validate_topology().is_ok());
    }
}
