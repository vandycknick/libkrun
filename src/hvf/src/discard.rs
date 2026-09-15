// Copyright 2026 The libkrun Authors
// SPDX-License-Identifier: Apache-2.0

use std::ffi::c_void;
use std::io;

const MADV_FREE: i32 = 5;
const MINCORE_INCORE: u8 = 0x01;
const MINCORE_REFERENCED: u8 = 0x02 | 0x08;
const MINCORE_MODIFIED: u8 = 0x04 | 0x10;
const MINCORE_PAGED_OUT: u8 = 0x20;

// Darwin mincore exposes ref/mod and compressed-page state, unlike portable
// residency APIs. Keep these native operations together with the advice.
unsafe extern "C" {
    fn getpagesize() -> i32;
    fn madvise(address: *mut c_void, length: usize, advice: i32) -> i32;
    fn mincore(address: *const c_void, length: usize, vector: *mut u8) -> i32;
}

pub(crate) fn native_page_size() -> io::Result<usize> {
    match usize::try_from(unsafe { getpagesize() }) {
        Ok(size) if size.is_power_of_two() => Ok(size),
        _ => Err(io::Error::other("unsupported native page size")),
    }
}

fn validate(address: *const c_void, length: usize, page_size: usize) -> io::Result<()> {
    if page_size != native_page_size()?
        || !page_size.is_power_of_two()
        || !(address as usize).is_multiple_of(page_size)
        || length == 0
        || !length.is_multiple_of(page_size)
        || (address as usize).checked_add(length).is_none()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unaligned discard range",
        ));
    }
    Ok(())
}

/// # Safety
/// The range must be live anonymous memory with no guest or host consumer of
/// its contents until the caller has finished restoring the guest mapping.
pub(crate) unsafe fn advise_free(
    address: *mut c_void,
    length: usize,
    page_size: usize,
) -> io::Result<()> {
    validate(address, length, page_size)?;
    // XNU's multi-page fast path walks host PTEs, which need not exist for
    // guest-populated RAM. Single-page advice clears physical-page ref/mod
    // state instead. Do not coalesce these calls along with the HV mappings.
    for offset in (0..length).step_by(page_size) {
        let page = address.cast::<u8>().wrapping_add(offset).cast();
        if unsafe { madvise(page, page_size, MADV_FREE) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PageState {
    pub pages: usize,
    pub resident: usize,
    pub referenced: usize,
    pub modified: usize,
    pub paged_out: usize,
}

impl PageState {
    pub fn is_discardable(self) -> bool {
        self.pages != 0 && self.referenced == 0 && self.modified == 0 && self.paged_out == 0
    }

    /// Observes VM metadata without touching the payload or creating host PTEs.
    pub fn sample(address: *const c_void, length: usize, page_size: usize) -> io::Result<Self> {
        validate(address, length, page_size)?;
        let mut vector = vec![0; length / page_size];
        if unsafe { mincore(address, length, vector.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self::from_flags(&vector))
    }

    fn from_flags(vector: &[u8]) -> Self {
        Self {
            pages: vector.len(),
            resident: vector
                .iter()
                .filter(|flag| **flag & MINCORE_INCORE != 0)
                .count(),
            referenced: vector
                .iter()
                .filter(|flag| **flag & MINCORE_REFERENCED != 0)
                .count(),
            modified: vector
                .iter()
                .filter(|flag| **flag & MINCORE_MODIFIED != 0)
                .count(),
            paged_out: vector
                .iter()
                .filter(|flag| **flag & MINCORE_PAGED_OUT != 0)
                .count(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::discard::{PageState, advise_free};

    #[test]
    fn discardability_requires_clean_unreferenced_uncompressed_pages() {
        assert!(PageState::from_flags(&[0, 1]).is_discardable());
        for flag in [2, 4, 8, 16, 32] {
            assert!(!PageState::from_flags(&[flag]).is_discardable());
        }
        assert!(!PageState::default().is_discardable());
        assert_eq!(
            PageState::from_flags(&[1, 2, 4, 8, 16, 32]),
            PageState {
                pages: 6,
                resident: 1,
                referenced: 2,
                modified: 2,
                paged_out: 1,
            }
        );
    }

    #[test]
    fn invalid_ranges_are_rejected_before_advice() {
        for (address, length, page_size) in [
            (1, 16384, 16384),
            (16384, 1, 16384),
            (0, 1, 0),
            (0, 0, 16384),
        ] {
            let error = unsafe { advise_free(address as *mut _, length, page_size) }.unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        }
    }
}
