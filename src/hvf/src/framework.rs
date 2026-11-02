use std::ffi::c_void;
use std::ptr::NonNull;
use std::sync::Arc;

use crate::Error;
use crate::bindings::{hv_gic_icc_reg_t, hv_gic_state_t, hv_return_t, hv_vcpu_t, os_release};

type StateCreate = unsafe extern "C" fn() -> hv_gic_state_t;
type StateGetSize = unsafe extern "C" fn(hv_gic_state_t, *mut usize) -> hv_return_t;
type StateGetData = unsafe extern "C" fn(hv_gic_state_t, *mut c_void) -> hv_return_t;
type SetState = unsafe extern "C" fn(*const c_void, usize) -> hv_return_t;
type GetIcc = unsafe extern "C" fn(hv_vcpu_t, hv_gic_icc_reg_t, *mut u64) -> hv_return_t;
type SetIcc = unsafe extern "C" fn(hv_vcpu_t, hv_gic_icc_reg_t, u64) -> hv_return_t;

// These complete tables are retained for Phase 9, never invoked by admission discovery.
#[allow(dead_code)]
struct GicBlobApi {
    create: StateCreate,
    get_size: StateGetSize,
    get_data: StateGetData,
    set_state: SetState,
}

#[allow(dead_code)]
struct GicCpuApi {
    get_icc: GetIcc,
    set_icc: SetIcc,
}

pub struct HvfFramework {
    library: libloading::Library,
    gic_symbols: [bool; 6],
    _gic_blob: Option<GicBlobApi>,
    _gic_cpu: Option<GicCpuApi>,
}

impl HvfFramework {
    /// Loads and resolves addresses only, without constructing any hypervisor object.
    pub fn load() -> Result<Arc<Self>, Error> {
        let library = unsafe {
            libloading::Library::new(
                "/System/Library/Frameworks/Hypervisor.framework/Versions/A/Hypervisor",
            )
        }
        .map_err(Error::LoadFramework)?;
        let create = unsafe { optional_symbol::<StateCreate>(&library, b"hv_gic_state_create\0") };
        let get_size =
            unsafe { optional_symbol::<StateGetSize>(&library, b"hv_gic_state_get_size\0") };
        let get_data =
            unsafe { optional_symbol::<StateGetData>(&library, b"hv_gic_state_get_data\0") };
        let set_state = unsafe { optional_symbol::<SetState>(&library, b"hv_gic_set_state\0") };
        let get_icc = unsafe { optional_symbol::<GetIcc>(&library, b"hv_gic_get_icc_reg\0") };
        let set_icc = unsafe { optional_symbol::<SetIcc>(&library, b"hv_gic_set_icc_reg\0") };
        let gic_symbols = [
            create.is_some(),
            get_size.is_some(),
            get_data.is_some(),
            set_state.is_some(),
            get_icc.is_some(),
            set_icc.is_some(),
        ];
        let gic_blob = match (create, get_size, get_data, set_state) {
            (Some(create), Some(get_size), Some(get_data), Some(set_state)) => Some(GicBlobApi {
                create,
                get_size,
                get_data,
                set_state,
            }),
            _ => None,
        };
        let gic_cpu = match (get_icc, set_icc) {
            (Some(get_icc), Some(set_icc)) => Some(GicCpuApi { get_icc, set_icc }),
            _ => None,
        };
        Ok(Arc::new(Self {
            library,
            gic_symbols,
            _gic_blob: gic_blob,
            _gic_cpu: gic_cpu,
        }))
    }

    /// Order: state_create, state_get_size, state_get_data, set_state, get_icc_reg, set_icc_reg.
    pub fn gic_symbols(&self) -> [bool; 6] {
        self.gic_symbols
    }

    /// # Safety
    /// `T` must match the named framework symbol's native ABI. Copied pointers must
    /// retain an owning `Arc<HvfFramework>` for their entire usable lifetime.
    pub unsafe fn symbol<T>(&self, name: &[u8]) -> Result<libloading::Symbol<'_, T>, Error> {
        unsafe { self.library.get(name) }.map_err(Error::FindSymbol)
    }
}

unsafe fn optional_symbol<T: Copy>(library: &libloading::Library, name: &[u8]) -> Option<T> {
    match unsafe { library.get::<T>(name) } {
        Ok(symbol) => Some(*symbol),
        Err(error) => {
            log::debug!("optional HVF symbol {:?} unavailable: {error}", name);
            None
        }
    }
}

/// A constructor-owned OS object, released before its framework owner.
pub struct OwnedConfig<T> {
    object: NonNull<T>,
    _framework: Arc<HvfFramework>,
}

impl<T> OwnedConfig<T> {
    /// # Safety
    /// `object` must be a newly owned Hypervisor configuration object requiring os_release.
    pub unsafe fn new(
        object: *mut T,
        framework: Arc<HvfFramework>,
        constructor: &'static str,
    ) -> Result<Self, Error> {
        Ok(Self {
            object: NonNull::new(object).ok_or(Error::NullObject(constructor))?,
            _framework: framework,
        })
    }

    pub fn as_ptr(&self) -> *mut T {
        self.object.as_ptr()
    }
}

impl<T> Drop for OwnedConfig<T> {
    fn drop(&mut self) {
        unsafe { os_release(self.object.as_ptr().cast()) };
    }
}
