//! Native RAM changes v1 (not a Silo map). Integers are little-endian.
//!
//! Every file, including an empty change set, begins with a 16-byte header:
//! `KRUNRAM\0` (8 bytes), version u16 = 1, unit shift u8 = 16, coverage
//! u8 (0 = full, 1 = incremental), and four reserved zero bytes.
//! Each 56-byte record is: first unit u64, count u64, kind u8 (0 = zero,
//! 1 = data), seven reserved zero bytes, raw SHA-256 [u8; 32]. Data has
//! count = 1; zero has count > 0 and a zero digest field. Records are sorted,
//! disjoint, in bounds, and adjacent zero records are always coalesced, including
//! across I/O batches. The final unit hashes its actual length, without padding.
//! Full coverage omits every zero unit and asserts complete cut-bound coverage;
//! incremental coverage includes exactly the units intersecting the dirty union.
//! The bounded receipt binds length, layout/cut (through its enclosing capture),
//! mode, predecessor stream, inode, record count, and SHA-256 of the exact file.
//! The caller must exclude all other writers, as for RAM/layout outputs.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::time::Instant;

use sha2::{Digest, Sha256};

use crate::vmm::memory::image::{
    FileFact, RamCaptureMode, RamFileRole, RamImageError, RamIoOperation, check_deadline, inspect,
    io_error,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RamChangeReceipt {
    pub(super) byte_len: u64,
    sha256: [u8; 32],
    record_count: u64,
    coverage: RamCaptureMode,
    baseline_stream: Option<[u8; 32]>,
    pub(super) fact: FileFact,
}
impl RamChangeReceipt {
    pub fn byte_len(&self) -> u64 {
        self.byte_len
    }
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
    pub fn record_count(&self) -> u64 {
        self.record_count
    }
    pub fn coverage(&self) -> RamCaptureMode {
        self.coverage
    }
    pub fn baseline_stream(&self) -> Option<[u8; 32]> {
        self.baseline_stream
    }
    pub fn output_identity(&self) -> (u64, u64, u64) {
        (
            self.fact.identity.device,
            self.fact.identity.inode,
            self.fact.length,
        )
    }
}

pub(crate) struct ChangeWriter<'a> {
    file: &'a File,
    buffer: Vec<u8>,
    offset: u64,
    hasher: Sha256,
    records: u64,
    zero: Option<(u64, u64)>,
    previous_end: u64,
    units: u64,
    coverage: RamCaptureMode,
    baseline_stream: Option<[u8; 32]>,
    deadline: Instant,
}

impl<'a> ChangeWriter<'a> {
    pub(crate) fn new(
        file: &'a File,
        coverage: RamCaptureMode,
        baseline_stream: Option<[u8; 32]>,
        units: u64,
        deadline: Instant,
    ) -> Result<Self, RamImageError> {
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(65536)
            .map_err(|_| RamImageError::Allocation)?;
        buffer.extend_from_slice(b"KRUNRAM\0\x01\0\x10\0\0\0\0\0");
        buffer[11] = u8::from(coverage == RamCaptureMode::Incremental);
        Ok(Self {
            file,
            buffer,
            offset: 0,
            hasher: Sha256::new(),
            records: 0,
            zero: None,
            previous_end: 0,
            units,
            coverage,
            baseline_stream,
            deadline,
        })
    }

    pub(crate) fn push(
        &mut self,
        index: u64,
        digest: Option<[u8; 32]>,
    ) -> Result<(), RamImageError> {
        check_deadline(self.deadline)?;
        if index < self.previous_end || index >= self.units {
            return Err(RamImageError::Geometry);
        }
        self.previous_end = index + 1;
        if digest.is_none() && self.coverage == RamCaptureMode::Full {
            return Ok(());
        }
        if digest.is_none() {
            if let Some((first, count)) = &mut self.zero
                && *first + *count == index
            {
                *count += 1;
                return Ok(());
            }
            self.flush_zero()?;
            self.zero = Some((index, 1));
        } else {
            self.flush_zero()?;
            self.record(index, 1, digest)?;
        }
        Ok(())
    }

    fn flush_zero(&mut self) -> Result<(), RamImageError> {
        if let Some((first, count)) = self.zero.take() {
            self.record(first, count, None)?;
        }
        Ok(())
    }

    fn record(
        &mut self,
        first: u64,
        count: u64,
        digest: Option<[u8; 32]>,
    ) -> Result<(), RamImageError> {
        if self.buffer.len() + 56 > 65536 {
            self.flush()?;
        }
        let mut record = [0; 56];
        record[..8].copy_from_slice(&first.to_le_bytes());
        record[8..16].copy_from_slice(&count.to_le_bytes());
        if let Some(digest) = digest {
            record[16] = 1;
            record[24..].copy_from_slice(&digest);
        }
        self.buffer.extend_from_slice(&record);
        self.records += 1;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), RamImageError> {
        let mut written = 0;
        while written < self.buffer.len() {
            check_deadline(self.deadline)?;
            match self
                .file
                .write_at(&self.buffer[written..], self.offset + written as u64)
            {
                Ok(0) => {
                    return Err(io_error(
                        RamIoOperation::Write,
                        RamFileRole::OutputChanges,
                        io::Error::new(io::ErrorKind::WriteZero, "zero RAM changes write"),
                    ));
                }
                Ok(count) => written += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(io_error(
                        RamIoOperation::Write,
                        RamFileRole::OutputChanges,
                        error,
                    ));
                }
            }
        }
        self.hasher.update(&self.buffer);
        self.offset += self.buffer.len() as u64;
        self.buffer.clear();
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<RamChangeReceipt, RamImageError> {
        self.flush_zero()?;
        self.flush()?;
        Ok(RamChangeReceipt {
            byte_len: self.offset,
            sha256: self.hasher.finalize().into(),
            record_count: self.records,
            coverage: self.coverage,
            baseline_stream: self.baseline_stream,
            fact: inspect(self.file, RamFileRole::OutputChanges)?,
        })
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
pub(crate) use tests::read_changes as read_test_changes;

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use std::fs::File;
    use std::os::unix::fs::FileExt;

    pub(crate) fn read_changes(file: &File) -> std::collections::BTreeMap<u64, Option<[u8; 32]>> {
        let length = file.metadata().unwrap().len();
        assert!(length >= 16 && (length - 16).is_multiple_of(56));
        let mut header = [0; 16];
        file.read_exact_at(&mut header, 0).unwrap();
        assert_eq!(&header[..11], b"KRUNRAM\0\x01\0\x10");
        assert!(header[11] <= 1);
        assert_eq!(&header[12..], &[0; 4]);
        let mut result = std::collections::BTreeMap::new();
        let mut end = 0;
        let mut previous_zero = false;
        for offset in (16..length).step_by(56) {
            let mut record = [0; 56];
            file.read_exact_at(&mut record, offset).unwrap();
            let first = u64::from_le_bytes(record[..8].try_into().unwrap());
            let count = u64::from_le_bytes(record[8..16].try_into().unwrap());
            assert!(first >= end && count > 0);
            assert_eq!(&record[17..24], &[0; 7]);
            assert!(record[16] <= 1);
            let digest = if record[16] == 1 {
                assert_eq!(count, 1);
                Some(record[24..].try_into().unwrap())
            } else {
                assert_eq!(&record[24..], &[0; 32]);
                assert!(!previous_zero || first != end);
                assert_eq!(header[11], 1);
                None
            };
            previous_zero = digest.is_none();
            end = first.checked_add(count).unwrap();
            for index in first..end {
                assert!(result.insert(index, digest).is_none());
            }
        }
        result
    }
}
