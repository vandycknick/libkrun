// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use crate::virtio::lifecycle::{
    DormantDeviceContext, LifecycleJournal, ProviderBeginError, ProviderFault, ProviderStage,
    QuiesceCompletion, ResumeAcceptance, VirtioStateProvider,
};
use polly::event_manager::{BarrierKey, BarrierRequest};
use std::cmp;
use std::convert::From;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt;
#[cfg(target_os = "macos")]
use std::os::macos::fs::MetadataExt;
use std::path::PathBuf;
use std::result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, TryLockError};
use std::task::Poll;
use std::thread::JoinHandle;
use std::time::Instant;
use utils::state::{Reader, Writer};

use crate::virtio::RuntimeGuestMemory;
use imago::{
    DynStorage, FormatAccess, Storage, StorageOpenOptions, file::File as ImagoFile, qcow2::Qcow2,
    raw::Raw,
};
#[cfg(not(unix))]
use imago::{FormatDriverBuilder, PermissiveImplicitOpenGate, vmdk::Vmdk};
use log::{error, warn};
use utils::eventfd::{EFD_NONBLOCK, EventFd};
use virtio_bindings::{
    virtio_blk::*, virtio_config::VIRTIO_F_VERSION_1, virtio_ring::VIRTIO_RING_F_EVENT_IDX,
};
use vm_memory::ByteValued;

#[cfg(target_os = "windows")]
use std::mem::MaybeUninit;
#[cfg(target_os = "windows")]
use std::os::windows::io::AsRawHandle;
#[cfg(target_os = "windows")]
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
};

use crate::virtio::block::worker::{BlockWorker, WorkerAdmission};
use crate::virtio::block::{Error, NUM_QUEUES, QUEUE_CONFIG, SECTOR_SHIFT, SECTOR_SIZE};
use crate::virtio::{
    ActivateResult, DeviceQueue, DeviceState, QueueConfig, TYPE_BLOCK, VirtioDevice,
};

use crate::virtio::{
    ActivateError, InterruptTransport,
    block::{DiskFormat, ReadonlyVmdk, RestoreBlockBacking, SyncMode},
};

/// Configuration options for disk caching.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CacheType {
    /// Flushing mechanic will be advertised to the guest driver, but
    /// the operation will be a noop.
    #[default]
    Unsafe,
    /// Flushing mechanic will be advertised to the guest driver and
    /// flush requests coming from the guest will be performed using
    /// `fsync`.
    Writeback,
}

impl CacheType {
    /// Picks the appropriate cache type based on disk image or device path.
    /// Special files like `/dev/rdisk*` on macOS do not support flush/sync.
    pub fn auto(_path: &str) -> CacheType {
        #[cfg(target_os = "macos")]
        if _path.starts_with("/dev/rdisk") {
            return CacheType::Unsafe;
        }
        CacheType::Writeback
    }
}

/// Helper object for setting up all `Block` fields derived from its backing file.
pub(crate) struct DiskProperties {
    cache_type: CacheType,
    pub(crate) file: Arc<Mutex<FormatAccess<Box<dyn DynStorage>>>>,
    nsectors: u64,
    image_id: Vec<u8>,
    #[cfg(target_os = "macos")]
    relaxed_sync_file: Option<File>,
}

impl DiskProperties {
    pub fn new(
        disk_image: Arc<Mutex<FormatAccess<Box<dyn DynStorage>>>>,
        disk_image_id: Vec<u8>,
        cache_type: CacheType,
    ) -> io::Result<Self> {
        let disk_size = disk_image
            .lock()
            .map_err(|_| io::Error::other("block backend lock poisoned"))?
            .size();

        // We only support disk size, which uses the first two words of the configuration space.
        // If the image is not a multiple of the sector size, the tail bits are not exposed.
        if !disk_size.is_multiple_of(SECTOR_SIZE) {
            warn!(
                "Disk size {disk_size} is not a multiple of sector size {SECTOR_SIZE}; \
                 the remainder will not be visible to the guest."
            );
        }

        Ok(Self {
            cache_type,
            nsectors: disk_size >> SECTOR_SHIFT,
            image_id: disk_image_id,
            file: disk_image,
            #[cfg(target_os = "macos")]
            relaxed_sync_file: None,
        })
    }

    pub fn nsectors(&self) -> u64 {
        self.nsectors
    }

    pub fn image_id(&self) -> &[u8] {
        &self.image_id
    }

    fn build_device_id(disk_file: &File) -> result::Result<String, Error> {
        // This is how kvmtool does it.
        #[cfg(unix)]
        let device_id = {
            let blk_metadata = disk_file.metadata().map_err(Error::GetFileMetadata)?;
            format!(
                "{}{}{}",
                blk_metadata.st_dev(),
                blk_metadata.st_rdev(),
                blk_metadata.st_ino()
            )
        };
        #[cfg(target_os = "windows")]
        let device_id = {
            let mut info = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
            let ret =
                unsafe { GetFileInformationByHandle(disk_file.as_raw_handle(), info.as_mut_ptr()) };
            if ret != 0 {
                let info = unsafe { info.assume_init() };
                format!(
                    "{}{}{}",
                    info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow
                )
            } else {
                return Err(Error::GetFileMetadata(io::Error::last_os_error()));
            }
        };
        Ok(device_id)
    }

    fn build_disk_image_id(disk_file: &File, block_id: &str) -> Vec<u8> {
        let mut default_id = vec![0; VIRTIO_BLK_ID_BYTES as usize];

        // The public libkrun disk API accepts a caller-provided block_id. Make
        // that the virtio-blk GET_ID value so Linux can expose it as
        // /sys/block/<dev>/serial. Fall back to the historical backing-file
        // derived id only for callers that pass an empty block_id.
        let disk_id = if block_id.is_empty() {
            match Self::build_device_id(disk_file) {
                Err(_) => {
                    warn!("Could not generate device id. We'll use a default.");
                    return default_id;
                }
                Ok(m) => m,
            }
        } else {
            block_id.to_string()
        };

        // The kernel only knows to read a maximum of VIRTIO_BLK_ID_BYTES.
        // This will also zero out any leftover bytes.
        let disk_id = disk_id.as_bytes();
        let bytes_to_copy = cmp::min(disk_id.len(), VIRTIO_BLK_ID_BYTES as usize);
        default_id[..bytes_to_copy].clone_from_slice(&disk_id[..bytes_to_copy]);
        default_id
    }

    pub fn cache_type(&self) -> CacheType {
        self.cache_type
    }

    pub(crate) fn checked_sync(&self) -> io::Result<()> {
        let file = self
            .file
            .lock()
            .map_err(|_| io::Error::other("block backend lock poisoned"))?;
        file.flush()?;
        #[cfg(target_os = "macos")]
        if let Some(sync_file) = &self.relaxed_sync_file {
            nix::unistd::fsync(sync_file)?;
            return Ok(());
        }
        file.sync()
    }
}

impl Drop for DiskProperties {
    fn drop(&mut self) {
        match self.cache_type {
            CacheType::Writeback => {
                if let Err(error) = self.checked_sync() {
                    log::error!("Failed to synchronize block data on drop: {error}");
                }
            }
            CacheType::Unsafe => {
                // This is a noop.
            }
        };
    }
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioBlkGeometry {
    cylinders: u16,
    heads: u8,
    sectors: u8,
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioBlkTopology {
    physical_block_exp: u8,
    alignment_offset: u8,
    min_io_size: u16,
    opt_io_size: u32,
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioBlkConfig {
    capacity: u64,
    size_max: u32,
    seg_max: u32,
    geometry: VirtioBlkGeometry,
    blk_size: u32,
    topology: VirtioBlkTopology,
    writeback: u8,
    unused0: u8,
    num_queues: u16,
    max_discard_sectors: u32,
    max_discard_seg: u32,
    discard_sector_alignment: u32,
    max_write_zeroes_sectors: u32,
    max_write_zeroes_seg: u32,
    write_zeroes_may_unmap: u8,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioBlkConfig {}

#[cfg(feature = "native-device-probe")]
#[derive(Clone, Copy, Debug)]
pub struct BlockPressureOwnership {
    pub worker_handle_retained: bool,
    pub worker_finished: bool,
    pub returned_worker_retained: bool,
    pub backend_retained: bool,
    pub subscribed_wake_held: bool,
    pub wake_errno: Option<i32>,
    pub owned_head: Option<u16>,
    pub available_unpopped: u16,
    pub consumed_kicks: u64,
}

/// Saved block identity and backend facts a restore binding must reproduce.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreBlockShape {
    pub id: String,
    pub format: DiskFormat,
    pub byte_length: u64,
    pub read_only: bool,
    pub direct_io: bool,
    pub sync_mode: SyncMode,
    pub cache_type: CacheType,
}

/// Why destination backing cannot be bound to a saved block payload.
#[derive(Debug)]
pub enum RestoreBindingError {
    /// The saved payload is not a valid native block payload.
    Payload,
    /// The backing format differs from the saved format; raw is never
    /// substituted for a saved VMDK, nor the reverse.
    Format,
    /// The read-only VMDK closure is not the admitted generated closure.
    #[cfg(unix)]
    Closure(crate::virtio::block::vmdk::VmdkClosureFault),
    /// The rebuilt device disagrees with the saved identity or geometry.
    Binding,
    Io(io::Error),
}

impl std::fmt::Display for RestoreBindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Payload => f.write_str("invalid saved block payload"),
            Self::Format => f.write_str("block backing format differs from the saved format"),
            #[cfg(unix)]
            Self::Closure(fault) => write!(f, "read-only VMDK closure: {fault:?}"),
            Self::Binding => f.write_str("block destination binding differs from the saved device"),
            Self::Io(error) => write!(f, "block restore I/O: {error}"),
        }
    }
}

impl std::error::Error for RestoreBindingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

/// Virtio device for exposing block level read/write operations on a host file.
pub struct Block {
    // Host file and properties.
    disk: Option<DiskProperties>,
    cache_type: CacheType,
    disk_image: Arc<Mutex<FormatAccess<Box<dyn DynStorage>>>>,
    disk_image_id: Vec<u8>,
    worker_thread: Option<JoinHandle<()>>,
    worker_stopfd: Arc<EventFd>,
    #[cfg(feature = "native-device-probe")]
    pressure_wake_errno: Option<i32>,
    worker_slot: Arc<Mutex<Option<BlockWorker>>>,
    worker_admission: Arc<Mutex<WorkerAdmission>>,
    worker_running: Arc<AtomicBool>,
    lifecycle: LifecycleJournal,
    provider_fault: Option<ProviderFault>,
    restored: bool,
    disk_format: DiskFormat,
    byte_length: u64,
    direct_io: bool,
    sync_mode: SyncMode,
    /// Every host file the backend reads or writes, as `(device, inode)`.
    backing_identities: Box<[(u64, u64)]>,

    // Virtio fields.
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    config: VirtioBlkConfig,

    // Transport related fields.
    pub(crate) device_state: DeviceState,

    // Implementation specific fields.
    pub(crate) id: String,
    pub(crate) partuuid: Option<String>,
}

impl Block {
    /// Create a new virtio block device that operates on the given file.
    ///
    /// The given file must be seekable and sizable.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        partuuid: Option<String>,
        cache_type: CacheType,
        disk_image_path: String,
        disk_image_format: DiskFormat,
        is_disk_read_only: bool,
        direct_io: bool,
        sync_mode: SyncMode,
    ) -> io::Result<Block> {
        let mut open = OpenOptions::new();
        open.read(true).write(!is_disk_read_only);
        #[cfg(target_os = "linux")]
        if disk_image_format == DiskFormat::Raw && direct_io {
            use std::os::unix::fs::OpenOptionsExt;
            open.custom_flags(nix::fcntl::OFlag::O_DIRECT.bits());
        }
        let disk_image = open.open(PathBuf::from(&disk_image_path))?;

        let disk_image_id = DiskProperties::build_disk_image_id(&disk_image, &id);
        // Every host file the backend reads, so live capture can refuse output
        // files that alias any of them. A VMDK adds each extent as it opens.
        #[cfg(unix)]
        let mut backing_identities = if disk_image_format == DiskFormat::Qcow2 {
            Vec::new()
        } else {
            let metadata = disk_image.metadata()?;
            vec![(
                std::os::unix::fs::MetadataExt::dev(&metadata),
                std::os::unix::fs::MetadataExt::ino(&metadata),
            )]
        };
        #[cfg(not(unix))]
        let backing_identities = Vec::new();
        #[cfg(target_os = "macos")]
        let relaxed_sync_file = if disk_image_format == DiskFormat::Raw {
            Self::prepare_owned_raw_file(&disk_image, direct_io, sync_mode)?
        } else {
            None
        };

        let file = match disk_image_format {
            #[cfg(unix)]
            DiskFormat::Raw => ImagoFile::try_from(disk_image)?,
            // Parse the already opened descriptor whose inode was recorded,
            // keeping its path so relative extent names still resolve. It is
            // read once at open, so it stays buffered regardless of direct_io.
            #[cfg(unix)]
            DiskFormat::Vmdk => {
                let options = StorageOpenOptions::new()
                    .write(!is_disk_read_only)
                    .filename(&disk_image_path);
                #[cfg(target_os = "macos")]
                let options = options.relaxed_sync(sync_mode == SyncMode::Relaxed);
                ImagoFile::from_open_file(disk_image, options)?
            }
            _ => {
                let file_opts = StorageOpenOptions::new()
                    .write(!is_disk_read_only)
                    .filename(disk_image_path)
                    .direct(direct_io);
                #[cfg(target_os = "macos")]
                let file_opts = file_opts.relaxed_sync(sync_mode == SyncMode::Relaxed);
                ImagoFile::open(file_opts)?
            }
        };
        let discard_alignment = file.discard_align();

        let disk_image = match disk_image_format {
            DiskFormat::Qcow2 => {
                let mut qcow2 =
                    Qcow2::<Box<dyn DynStorage>, Arc<imago::FormatAccess<_>>>::open_image(
                        Box::new(file),
                        !is_disk_read_only,
                    )?;
                qcow2.open_implicit_dependencies()?;
                FormatAccess::new(qcow2)
            }
            DiskFormat::Raw => {
                let raw =
                    Raw::<Box<dyn DynStorage>>::open_image(Box::new(file), !is_disk_read_only)?;
                FormatAccess::new(raw)
            }
            #[cfg(unix)]
            DiskFormat::Vmdk => {
                crate::virtio::block::vmdk::open_cold(file, &mut backing_identities)?
            }
            #[cfg(not(unix))]
            DiskFormat::Vmdk => FormatAccess::new(
                Vmdk::<Box<dyn DynStorage>, Arc<imago::FormatAccess<_>>>::builder(Box::new(file))
                    .open(PermissiveImplicitOpenGate::default())?,
            ),
        };

        Self::from_storage(
            id,
            partuuid,
            cache_type,
            disk_image,
            discard_alignment,
            disk_image_format,
            is_disk_read_only,
            direct_io,
            sync_mode,
            disk_image_id,
            backing_identities,
            #[cfg(target_os = "macos")]
            relaxed_sync_file,
        )
    }

    #[cfg(target_os = "macos")]
    fn prepare_owned_raw_file(
        file: &File,
        direct_io: bool,
        sync_mode: SyncMode,
    ) -> io::Result<Option<File>> {
        if direct_io {
            use std::os::fd::AsRawFd;
            // nix has no F_NOCACHE fcntl operation.
            if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_NOCACHE, 1) } == -1 {
                return Err(io::Error::last_os_error());
            }
        }
        if sync_mode == SyncMode::Relaxed {
            file.try_clone().map(Some)
        } else {
            Ok(None)
        }
    }

    /// Decode a saved block payload into the identity and backend facts a
    /// restore binding must reproduce, without any destination resource.
    pub fn inspect_restore_payload(payload: &[u8]) -> Result<RestoreBlockShape, ProviderFault> {
        let saved = BlockPayload::decode(payload)?;
        let capacity = saved.config.capacity;
        if saved.acked & !saved.avail != 0
            || capacity != saved.byte_length >> SECTOR_SHIFT
            || saved.read_only != (saved.avail & (1u64 << VIRTIO_BLK_F_RO) != 0)
        {
            return Err(ProviderFault::DeviceState);
        }
        Ok(RestoreBlockShape {
            id: std::str::from_utf8(saved.id)
                .map_err(|_| ProviderFault::DeviceState)?
                .to_owned(),
            format: saved.disk_format,
            byte_length: saved.byte_length,
            read_only: saved.read_only,
            direct_io: saved.direct_io,
            sync_mode: SyncMode::try_from(saved.sync_mode)
                .map_err(|_| ProviderFault::DeviceState)?,
            cache_type: match saved.cache_type {
                0 => CacheType::Unsafe,
                1 => CacheType::Writeback,
                _ => return Err(ProviderFault::DeviceState),
            },
        })
    }

    /// Bind a saved block payload to destination backing of the same format.
    /// Nothing is opened by path; a read-only VMDK is rebuilt from its held
    /// descriptor and extent handles. Close-on-exec and cross-role alias
    /// checks belong to the caller's preflight.
    #[cfg(unix)]
    pub fn new_restore_binding(
        id: String,
        backing: RestoreBlockBacking,
        payload: &[u8],
    ) -> Result<Self, RestoreBindingError> {
        let saved =
            Self::inspect_restore_payload(payload).map_err(|_| RestoreBindingError::Payload)?;
        let block = match backing {
            RestoreBlockBacking::Raw { file, read_only } => {
                if saved.format != DiskFormat::Raw {
                    return Err(RestoreBindingError::Format);
                }
                Self::restore_raw(id, file, read_only, &saved)?
            }
            RestoreBlockBacking::ReadonlyVmdk(closure) => {
                if saved.format != DiskFormat::Vmdk || !saved.read_only {
                    return Err(RestoreBindingError::Format);
                }
                Self::restore_readonly_vmdk(id, &closure, &saved)?
            }
        };
        block
            .validate_block_payload(payload)
            .map_err(|_| RestoreBindingError::Binding)?;
        Ok(block)
    }

    #[cfg(unix)]
    fn restore_raw(
        id: String,
        file: File,
        read_only: bool,
        saved: &RestoreBlockShape,
    ) -> Result<Self, RestoreBindingError> {
        #[cfg(target_os = "linux")]
        {
            let flags = nix::fcntl::fcntl(&file, nix::fcntl::FcntlArg::F_GETFL)
                .map_err(|error| RestoreBindingError::Io(error.into()))?;
            if nix::fcntl::OFlag::from_bits_truncate(flags).contains(nix::fcntl::OFlag::O_DIRECT)
                != saved.direct_io
            {
                return Err(RestoreBindingError::Binding);
            }
        }
        let metadata = file.metadata().map_err(RestoreBindingError::Io)?;
        let backing_identities = vec![(
            std::os::unix::fs::MetadataExt::dev(&metadata),
            std::os::unix::fs::MetadataExt::ino(&metadata),
        )];
        let disk_image_id = DiskProperties::build_disk_image_id(&file, &id);
        #[cfg(target_os = "macos")]
        let relaxed_sync_file =
            Self::prepare_owned_raw_file(&file, saved.direct_io, saved.sync_mode)
                .map_err(RestoreBindingError::Io)?;
        let file = ImagoFile::try_from(file).map_err(RestoreBindingError::Io)?;
        let discard_alignment = file.discard_align();
        let raw = Raw::<Box<dyn DynStorage>>::open_image(Box::new(file), !read_only)
            .map_err(RestoreBindingError::Io)?;
        Self::from_storage(
            id,
            None,
            saved.cache_type,
            FormatAccess::new(raw),
            discard_alignment,
            DiskFormat::Raw,
            read_only,
            saved.direct_io,
            saved.sync_mode,
            disk_image_id,
            backing_identities,
            #[cfg(target_os = "macos")]
            relaxed_sync_file,
        )
        .map_err(RestoreBindingError::Io)
    }

    /// Mirrors cold VMDK attach: descriptor-derived image ID and discard
    /// alignment, no single backing inode, no relaxed-sync raw clone.
    #[cfg(unix)]
    fn restore_readonly_vmdk(
        id: String,
        closure: &ReadonlyVmdk,
        saved: &RestoreBlockShape,
    ) -> Result<Self, RestoreBindingError> {
        let disk_image_id = DiskProperties::build_disk_image_id(&closure.descriptor, &id);
        let opened =
            crate::virtio::block::vmdk::open_held(closure).map_err(|error| match error {
                crate::virtio::block::vmdk::OpenError::Closure(fault) => {
                    RestoreBindingError::Closure(fault)
                }
                crate::virtio::block::vmdk::OpenError::Io(error) => RestoreBindingError::Io(error),
            })?;
        Self::from_storage(
            id,
            None,
            saved.cache_type,
            opened.access,
            opened.discard_alignment,
            DiskFormat::Vmdk,
            true,
            saved.direct_io,
            saved.sync_mode,
            disk_image_id,
            opened.identities,
            #[cfg(target_os = "macos")]
            None,
        )
        .map_err(RestoreBindingError::Io)
    }

    #[allow(clippy::too_many_arguments)]
    fn from_storage(
        id: String,
        partuuid: Option<String>,
        cache_type: CacheType,
        disk_image: FormatAccess<Box<dyn DynStorage>>,
        discard_alignment: usize,
        disk_image_format: DiskFormat,
        is_disk_read_only: bool,
        direct_io: bool,
        sync_mode: SyncMode,
        disk_image_id: Vec<u8>,
        backing_identities: Vec<(u64, u64)>,
        #[cfg(target_os = "macos")] relaxed_sync_file: Option<File>,
    ) -> io::Result<Self> {
        let disk_image = Arc::new(Mutex::new(disk_image));
        let byte_length = disk_image
            .lock()
            .map_err(|_| io::Error::other("block backend lock poisoned"))?
            .size();

        let disk_properties =
            DiskProperties::new(disk_image.clone(), disk_image_id.clone(), cache_type)?;
        #[cfg(target_os = "macos")]
        let disk_properties = {
            let mut disk_properties = disk_properties;
            disk_properties.relaxed_sync_file = relaxed_sync_file;
            disk_properties
        };

        let mut avail_features = (1u64 << VIRTIO_F_VERSION_1)
            | (1u64 << VIRTIO_BLK_F_SEG_MAX)
            | (1u64 << VIRTIO_BLK_F_DISCARD)
            | (1u64 << VIRTIO_BLK_F_WRITE_ZEROES)
            | (1u64 << VIRTIO_RING_F_EVENT_IDX);

        if sync_mode != SyncMode::None {
            avail_features |= 1u64 << VIRTIO_BLK_F_FLUSH;
        }

        if is_disk_read_only {
            avail_features |= 1u64 << VIRTIO_BLK_F_RO;
        };

        let config = VirtioBlkConfig {
            capacity: disk_properties.nsectors(),
            size_max: 0,
            // QUEUE_SIZE - 2
            seg_max: 254,
            max_discard_sectors: u32::MAX,
            max_discard_seg: 1,
            discard_sector_alignment: discard_alignment as u32 / 512,
            max_write_zeroes_sectors: u32::MAX,
            max_write_zeroes_seg: 1,
            write_zeroes_may_unmap: 1,
            ..Default::default()
        };

        Ok(Block {
            id,
            partuuid,
            config,
            disk: Some(disk_properties),
            cache_type,
            disk_image,
            disk_image_id,
            avail_features,
            acked_features: 0u64,
            device_state: DeviceState::Inactive,
            worker_thread: None,
            worker_stopfd: Arc::new(EventFd::new(EFD_NONBLOCK)?),
            #[cfg(feature = "native-device-probe")]
            pressure_wake_errno: None,
            worker_slot: Arc::new(Mutex::new(None)),
            worker_admission: Arc::new(Mutex::new(WorkerAdmission::default())),
            worker_running: Arc::new(AtomicBool::new(false)),
            lifecycle: LifecycleJournal::new(),
            provider_fault: None,
            restored: false,
            disk_format: disk_image_format,
            byte_length,
            direct_io,
            sync_mode,
            backing_identities: backing_identities.into_boxed_slice(),
        })
    }

    #[cfg(feature = "native-device-probe")]
    /// Hold the real worker at its control-consumption boundary, then saturate
    /// its original subscribed eventfd. The next accepted wake must use that fd.
    pub fn pressure_arm_wake_failure(&mut self) -> Result<(), ProviderFault> {
        if self.worker_thread.is_none() || self.lifecycle.snapshot.stage != ProviderStage::Running {
            return Err(ProviderFault::InvalidTransition);
        }
        let mut admission = self
            .worker_admission
            .lock()
            .map_err(|_| ProviderFault::Worker)?;
        if admission.pressure_hold_until.is_some() || admission.barrier.is_some() {
            return Err(ProviderFault::InvalidTransition);
        }
        admission.pressure_hold_until = Some(Instant::now() + std::time::Duration::from_secs(30));
        if let Err(error) = self.worker_stopfd.write(u64::MAX - 1) {
            admission.pressure_hold_until = None;
            self.pressure_wake_errno = error.raw_os_error();
            return Err(ProviderFault::Worker);
        }
        self.pressure_wake_errno = None;
        Ok(())
    }

    #[cfg(feature = "native-device-probe")]
    pub fn pressure_restore_wake(&mut self) -> Result<(), ProviderFault> {
        let mut admission = self
            .worker_admission
            .lock()
            .map_err(|_| ProviderFault::Worker)?;
        if admission.pressure_hold_until.take().is_none() {
            return Err(ProviderFault::InvalidTransition);
        }
        Ok(())
    }

    #[cfg(feature = "native-device-probe")]
    pub fn pressure_hold_request(&mut self, owned: bool) -> Result<(), ProviderFault> {
        if self.worker_thread.is_none() || self.lifecycle.snapshot.stage != ProviderStage::Running {
            return Err(ProviderFault::InvalidTransition);
        }
        let mut admission = self
            .worker_admission
            .lock()
            .map_err(|_| ProviderFault::Worker)?;
        if admission.pressure_owned_hold_until.is_some()
            || admission.pressure_unpopped_hold_until.is_some()
        {
            return Err(ProviderFault::InvalidTransition);
        }
        let until = Some(Instant::now() + std::time::Duration::from_secs(30));
        if owned {
            admission.pressure_owned_hold_until = until;
        } else {
            admission.pressure_unpopped_hold_until = until;
        }
        Ok(())
    }

    #[cfg(feature = "native-device-probe")]
    pub fn pressure_release_request(&mut self) -> Result<(), ProviderFault> {
        let mut admission = self
            .worker_admission
            .lock()
            .map_err(|_| ProviderFault::Worker)?;
        admission.pressure_owned_hold_until = None;
        admission.pressure_unpopped_hold_until = None;
        Ok(())
    }

    #[cfg(feature = "native-device-probe")]
    pub fn pressure_ownership(&self) -> Result<BlockPressureOwnership, ProviderFault> {
        let admission = self
            .worker_admission
            .try_lock()
            .map_err(|error| match error {
                TryLockError::WouldBlock => ProviderFault::LockBusy,
                TryLockError::Poisoned(_) => ProviderFault::Worker,
            })?;
        Ok(BlockPressureOwnership {
            worker_handle_retained: self.worker_thread.is_some(),
            worker_finished: self
                .worker_thread
                .as_ref()
                .is_some_and(JoinHandle::is_finished),
            returned_worker_retained: self
                .worker_slot
                .try_lock()
                .map_err(|error| match error {
                    TryLockError::WouldBlock => ProviderFault::LockBusy,
                    TryLockError::Poisoned(_) => ProviderFault::Worker,
                })?
                .is_some(),
            backend_retained: self.disk.is_some(),
            subscribed_wake_held: admission
                .pressure_hold_until
                .is_some_and(|until| Instant::now() < until),
            wake_errno: self.pressure_wake_errno,
            owned_head: admission.pressure_owned_head,
            available_unpopped: admission.pressure_unpopped,
            consumed_kicks: admission.pressure_consumed_kicks,
        })
    }

    fn start_worker(
        &mut self,
        queue: DeviceQueue,
        disk: DiskProperties,
        memory: RuntimeGuestMemory,
        interrupt: InterruptTransport,
    ) -> Result<(), ProviderFault> {
        // A failed thread spawn leaves the complete worker in this retained slot.
        let _ = self.worker_stopfd.read();
        match self.worker_admission.lock() {
            Ok(mut admission) => *admission = WorkerAdmission::default(),
            Err(poison) => {
                *poison.into_inner() = WorkerAdmission::default();
                self.provider_fault.get_or_insert(ProviderFault::Worker);
            }
        }
        self.worker_running.store(false, Ordering::Release);
        let worker = BlockWorker::new(
            queue,
            interrupt,
            memory,
            disk,
            self.worker_stopfd.clone(),
            self.worker_admission.clone(),
            self.worker_running.clone(),
        );
        match self.worker_slot.lock() {
            Ok(mut slot) => *slot = Some(worker),
            Err(poison) => *poison.into_inner() = Some(worker),
        }
        let slot = self.worker_slot.clone();
        let thread = std::thread::Builder::new()
            .name("block worker".into())
            .spawn(move || {
                let worker = match slot.lock() {
                    Ok(mut slot) => slot.take(),
                    Err(poison) => poison.into_inner().take(),
                };
                if let Some(worker) = worker {
                    let worker = worker.work();
                    match slot.lock() {
                        Ok(mut slot) => *slot = Some(worker),
                        Err(poison) => *poison.into_inner() = Some(worker),
                    }
                }
            })
            .map_err(|_| {
                self.provider_fault.get_or_insert(ProviderFault::Worker);
                ProviderFault::Worker
            })?;
        self.worker_thread = Some(thread);
        Ok(())
    }

    fn check_cut(&self, key: BarrierKey) -> Result<(), ProviderFault> {
        self.lifecycle.check(key).map_err(|error| error.fault)?;
        if self.lifecycle.snapshot.stage != ProviderStage::Quiesced {
            return Err(ProviderFault::InvalidTransition);
        }
        if let Some(error) = self.lifecycle.snapshot.failure {
            return Err(error.fault);
        }
        if let Some(fault) = self.provider_fault {
            return Err(fault);
        }
        Ok(())
    }

    /// Provides the ID of this block device.
    pub fn id(&self) -> &String {
        &self.id
    }

    /// Provides the PARTUUID of this block device.
    pub fn partuuid(&self) -> Option<&String> {
        self.partuuid.as_ref()
    }

    /// Specifies if this block device is read only.
    pub fn is_read_only(&self) -> bool {
        self.avail_features & (1u64 << VIRTIO_BLK_F_RO) != 0
    }
}

impl VirtioDevice for Block {
    fn device_type(&self) -> u32 {
        TYPE_BLOCK
    }

    fn device_name(&self) -> &str {
        "block"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &QUEUE_CONFIG
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            let _ =
                data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize]);
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        error!("Guest attempted to write config");
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn state_provider(&self) -> Option<&dyn VirtioStateProvider> {
        Some(self)
    }

    fn state_provider_mut(&mut self) -> Option<&mut dyn VirtioStateProvider> {
        Some(self)
    }

    fn activate(
        &mut self,
        mem: RuntimeGuestMemory,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if self.worker_thread.is_some() {
            return Err(ActivateError::BadActivate);
        }

        let [blk_q]: [_; NUM_QUEUES] = queues.try_into().map_err(|_| {
            error!("Cannot perform activate. Expected {} queue(s)", NUM_QUEUES);
            ActivateError::BadActivate
        })?;

        let disk = match self.disk.take() {
            Some(d) => d,
            None => DiskProperties::new(
                Arc::clone(&self.disk_image),
                self.disk_image_id.clone(),
                self.cache_type,
            )
            .map_err(|_| ActivateError::BadActivate)?,
        };

        self.device_state = DeviceState::Activated(mem.clone(), interrupt.clone());
        self.start_worker(blk_q, disk, mem, interrupt)
            .map_err(|_| ActivateError::BadActivate)
    }

    fn reset(&mut self) -> bool {
        if let Some(worker) = self.worker_thread.take() {
            let _ = self.worker_stopfd.write(1);
            if worker.join().is_err() {
                self.provider_fault.get_or_insert(ProviderFault::Worker);
            }
        }
        if let Ok(mut slot) = self.worker_slot.lock()
            && let Some(worker) = slot.take()
        {
            let (_, disk, fault) = worker.into_parts();
            self.disk = Some(disk);
            self.provider_fault = self.provider_fault.or(fault);
        }
        match self.worker_admission.lock() {
            Ok(mut admission) => *admission = WorkerAdmission::default(),
            Err(poison) => *poison.into_inner() = WorkerAdmission::default(),
        }
        self.worker_running.store(false, Ordering::Release);
        self.lifecycle = LifecycleJournal::new();
        self.device_state = DeviceState::Inactive;
        true
    }
}

const BLOCK_STATE_LIMIT: usize = 4096;
pub(crate) const BLOCK_STATE_MAGIC: &[u8; 8] = b"KRUNBLKS";
pub(crate) const BLOCK_STATE_SCHEMA: u16 = 1;
const BLOCK_ID_LIMIT: usize = 1024;

impl VirtioBlkConfig {
    fn encode(&self, writer: &mut Writer) -> Result<(), utils::state::Error> {
        writer.u64(self.capacity)?;
        writer.u32(self.size_max)?;
        writer.u32(self.seg_max)?;
        writer.u16(self.geometry.cylinders)?;
        writer.u8(self.geometry.heads)?;
        writer.u8(self.geometry.sectors)?;
        writer.u32(self.blk_size)?;
        writer.u8(self.topology.physical_block_exp)?;
        writer.u8(self.topology.alignment_offset)?;
        writer.u16(self.topology.min_io_size)?;
        writer.u32(self.topology.opt_io_size)?;
        writer.u8(self.writeback)?;
        writer.u8(self.unused0)?;
        writer.u16(self.num_queues)?;
        writer.u32(self.max_discard_sectors)?;
        writer.u32(self.max_discard_seg)?;
        writer.u32(self.discard_sector_alignment)?;
        writer.u32(self.max_write_zeroes_sectors)?;
        writer.u32(self.max_write_zeroes_seg)?;
        writer.u8(self.write_zeroes_may_unmap)
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, utils::state::Error> {
        Ok(Self {
            capacity: reader.u64()?,
            size_max: reader.u32()?,
            seg_max: reader.u32()?,
            geometry: VirtioBlkGeometry {
                cylinders: reader.u16()?,
                heads: reader.u8()?,
                sectors: reader.u8()?,
            },
            blk_size: reader.u32()?,
            topology: VirtioBlkTopology {
                physical_block_exp: reader.u8()?,
                alignment_offset: reader.u8()?,
                min_io_size: reader.u16()?,
                opt_io_size: reader.u32()?,
            },
            writeback: reader.u8()?,
            unused0: reader.u8()?,
            num_queues: reader.u16()?,
            max_discard_sectors: reader.u32()?,
            max_discard_seg: reader.u32()?,
            discard_sector_alignment: reader.u32()?,
            max_write_zeroes_sectors: reader.u32()?,
            max_write_zeroes_seg: reader.u32()?,
            write_zeroes_may_unmap: reader.u8()?,
        })
    }
}

struct BlockPayload<'a> {
    avail: u64,
    acked: u64,
    byte_length: u64,
    read_only: bool,
    disk_format: DiskFormat,
    direct_io: bool,
    sync_mode: u32,
    cache_type: u8,
    id: &'a [u8],
    serial: [u8; VIRTIO_BLK_ID_BYTES as usize],
    config: VirtioBlkConfig,
}

impl<'a> BlockPayload<'a> {
    fn decode(payload: &'a [u8]) -> Result<Self, ProviderFault> {
        let decode = || -> Result<Self, utils::state::Error> {
            if payload.len() > BLOCK_STATE_LIMIT {
                return Err(utils::state::Error::Limit);
            }
            let mut reader = Reader::new(payload);
            reader.header(BLOCK_STATE_MAGIC, BLOCK_STATE_SCHEMA)?;
            if reader.u16()? != 1 || reader.u32()? != TYPE_BLOCK {
                return Err(utils::state::Error::Invalid("block framing"));
            }
            let avail = reader.u64()?;
            let acked = reader.u64()?;
            let disk_format = DiskFormat::try_from(u32::from(reader.u8()?))
                .map_err(|_| utils::state::Error::Invalid("block backend"))?;
            let state = BlockPayload {
                avail,
                acked,
                byte_length: reader.u64()?,
                read_only: reader.bool()?,
                disk_format,
                direct_io: reader.bool()?,
                sync_mode: reader.u32()?,
                cache_type: reader.u8()?,
                id: reader.bytes(BLOCK_ID_LIMIT)?,
                serial: reader.fixed()?,
                config: VirtioBlkConfig::decode(&mut reader)?,
            };
            reader.finish()?;
            if state.disk_format != DiskFormat::Raw
                && !(state.disk_format == DiskFormat::Vmdk && state.read_only)
            {
                return Err(utils::state::Error::Invalid("block backend"));
            }
            Ok(state)
        };
        decode().map_err(ProviderFault::from)
    }
}

impl Block {
    fn validate_block_payload<'a>(
        &self,
        payload: &'a [u8],
    ) -> Result<BlockPayload<'a>, ProviderFault> {
        self.preflight()?;
        let saved = BlockPayload::decode(payload)?;
        if !self.id.is_empty() {
            let mut serial = [0; VIRTIO_BLK_ID_BYTES as usize];
            let length = self.id.len().min(serial.len());
            serial[..length].copy_from_slice(&self.id.as_bytes()[..length]);
            if saved.serial != serial {
                return Err(ProviderFault::DeviceState);
            }
        }
        if saved.avail != self.avail_features
            || saved.acked & !saved.avail != 0
            || saved.byte_length != self.byte_length
            || saved.disk_format != self.disk_format
            || saved.read_only != self.is_read_only()
            || saved.direct_io != self.direct_io
            || saved.sync_mode != self.sync_mode as u32
            || saved.cache_type != self.cache_type as u8
            || saved.id != self.id.as_bytes()
            || saved.config.as_slice() != self.config.as_slice()
        {
            return Err(ProviderFault::DeviceState);
        }
        Ok(saved)
    }
}

impl VirtioStateProvider for Block {
    fn backing_file_identities(&self) -> Result<&[(u64, u64)], ProviderFault> {
        Ok(&self.backing_identities)
    }

    fn preflight(&self) -> Result<(), ProviderFault> {
        if self.disk_format != DiskFormat::Raw
            && !(self.disk_format == DiskFormat::Vmdk && self.is_read_only())
        {
            return Err(ProviderFault::Unsupported);
        }
        if let Some(fault) = self.provider_fault {
            return Err(fault);
        }
        if self.id.len() > BLOCK_ID_LIMIT
            || self.disk_image_id.len() != VIRTIO_BLK_ID_BYTES as usize
            || self.acked_features & !self.avail_features != 0
        {
            return Err(ProviderFault::DeviceState);
        }
        if self.byte_length >> SECTOR_SHIFT != self.config.capacity {
            return Err(ProviderFault::DeviceState);
        }
        if self.worker_thread.is_none() {
            let backend = self.disk_image.try_lock().map_err(|error| match error {
                TryLockError::WouldBlock => ProviderFault::LockBusy,
                TryLockError::Poisoned(_) => ProviderFault::DeviceLock,
            })?;
            if backend.size() != self.byte_length {
                return Err(ProviderFault::DeviceState);
            }
        }
        Ok(())
    }

    fn begin_quiesce(&mut self, request: BarrierRequest) -> Result<(), ProviderBeginError> {
        let refuse = |fault| ProviderBeginError {
            accepted: false,
            fault,
        };
        if self.disk_format != DiskFormat::Raw
            && !(self.disk_format == DiskFormat::Vmdk && self.is_read_only())
        {
            return Err(refuse(ProviderFault::Unsupported));
        }
        // Stop must recover a real owner even after an effects/IRQ fault.
        if !matches!(
            self.lifecycle.snapshot.stage,
            ProviderStage::Running | ProviderStage::Resuming
        ) {
            return Err(refuse(ProviderFault::InvalidTransition));
        }
        if Instant::now() >= request.deadline {
            return Err(refuse(ProviderFault::Deadline));
        }
        {
            let mut admission = self
                .worker_admission
                .lock()
                .map_err(|_| refuse(ProviderFault::Worker))?;
            admission.barrier = Some(request.key);
        }
        self.lifecycle.begin(request, ProviderStage::Quiescing);
        if self.worker_thread.is_some()
            && let Err(error) = self.worker_stopfd.write(1)
        {
            #[cfg(feature = "native-device-probe")]
            {
                self.pressure_wake_errno = error.raw_os_error();
            }
            #[cfg(not(feature = "native-device-probe"))]
            let _ = error;
            self.lifecycle.fail(request.key, ProviderFault::Worker);
            return Err(ProviderBeginError {
                accepted: true,
                fault: ProviderFault::Worker,
            });
        }
        Ok(())
    }

    fn poll_quiesce(&mut self, key: BarrierKey) -> Result<Poll<QuiesceCompletion>, ProviderFault> {
        self.lifecycle.check(key).map_err(|error| error.fault)?;
        if self.lifecycle.snapshot.stage != ProviderStage::Quiescing {
            return Err(ProviderFault::InvalidTransition);
        }
        self.lifecycle.expired(Instant::now());
        if self
            .worker_thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
        {
            return Ok(Poll::Pending);
        }
        if let Some(thread) = self.worker_thread.take()
            && thread.join().is_err()
        {
            self.provider_fault.get_or_insert(ProviderFault::Worker);
            return Err(ProviderFault::Worker);
        }
        let worker = self
            .worker_slot
            .lock()
            .map_err(|_| ProviderFault::Worker)?
            .take();
        let queues = if let Some(worker) = worker {
            let (mut queue, disk, fault) = worker.into_parts();
            if queue.queue.close_admission(key).is_err() {
                self.provider_fault.get_or_insert(ProviderFault::QueueState);
            }
            self.disk = Some(disk);
            self.provider_fault = self.provider_fault.or(fault);
            vec![queue]
        } else if self.is_activated() {
            return Err(ProviderFault::Worker);
        } else {
            Vec::new()
        };
        self.lifecycle.snapshot.stage = ProviderStage::Quiesced;
        Ok(Poll::Ready(QuiesceCompletion {
            queues,
            fault: self
                .provider_fault
                .or(self.lifecycle.snapshot.failure.map(|error| error.fault)),
        }))
    }

    fn validate_terminal_drain(&self, key: BarrierKey) -> Result<(), ProviderFault> {
        self.lifecycle.check(key).map_err(|error| error.fault)?;
        if let Some(fault) = self.provider_fault {
            return Err(fault);
        }
        if self.lifecycle.snapshot.stage != ProviderStage::Quiesced
            || self.worker_thread.is_some()
            || self.disk.is_none()
        {
            return Err(ProviderFault::InvalidTransition);
        }
        let slot = self.worker_slot.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => ProviderFault::LockBusy,
            TryLockError::Poisoned(_) => ProviderFault::DeviceLock,
        })?;
        if slot.is_some() {
            return Err(ProviderFault::Worker);
        }
        drop(slot);
        let admission = self
            .worker_admission
            .try_lock()
            .map_err(|error| match error {
                TryLockError::WouldBlock => ProviderFault::LockBusy,
                TryLockError::Poisoned(_) => ProviderFault::DeviceLock,
            })?;
        if admission.barrier != Some(key) {
            return Err(ProviderFault::ForeignBarrier);
        }
        drop(admission);
        self.preflight()
    }

    fn begin_resume(
        &mut self,
        request: BarrierRequest,
        mut queues: Vec<DeviceQueue>,
    ) -> ResumeAcceptance {
        let refuse = |queues, fault| ResumeAcceptance::Rejected { queues, fault };
        let previous = self.lifecycle.snapshot.request;
        if self.lifecycle.snapshot.stage != ProviderStage::Quiesced
            || previous.is_none_or(|old| {
                old.key.generation != request.key.generation || old.key == request.key
            })
        {
            return refuse(queues, ProviderFault::InvalidTransition);
        }
        if let Some(fault) = self.provider_fault {
            return refuse(queues, fault);
        }
        if Instant::now() >= request.deadline {
            return refuse(queues, ProviderFault::Deadline);
        }
        if queues.len() != if self.is_activated() { NUM_QUEUES } else { 0 } {
            return refuse(queues, ProviderFault::QueueCount);
        }
        if self.is_activated() && self.disk.is_none() {
            return refuse(queues, ProviderFault::Worker);
        }
        if !self.restored {
            let Some(previous) = previous else {
                return refuse(queues, ProviderFault::ForeignBarrier);
            };
            for queue in &mut queues {
                if queue.queue.reopen_admission(previous.key).is_err() {
                    return refuse(queues, ProviderFault::QueueState);
                }
            }
        }
        self.lifecycle.begin(request, ProviderStage::Resuming);
        if let DeviceState::Activated(memory, interrupt) = &self.device_state {
            let memory = memory.clone();
            let interrupt = interrupt.clone();
            let Some(queue) = queues.pop() else {
                return ResumeAcceptance::AcceptedWithFailure(ProviderFault::QueueCount);
            };
            let Some(disk) = self.disk.take() else {
                return ResumeAcceptance::AcceptedWithFailure(ProviderFault::Worker);
            };
            if let Err(fault) = self.start_worker(queue, disk, memory, interrupt) {
                self.provider_fault.get_or_insert(fault);
                return ResumeAcceptance::AcceptedWithFailure(fault);
            }
        }
        self.restored = false;
        ResumeAcceptance::Accepted
    }

    fn poll_resume(&mut self, key: BarrierKey) -> Result<Poll<()>, ProviderFault> {
        self.lifecycle.check(key).map_err(|error| error.fault)?;
        if self.lifecycle.snapshot.stage == ProviderStage::Running {
            return Ok(Poll::Ready(()));
        }
        if self.lifecycle.snapshot.stage != ProviderStage::Resuming {
            return Err(ProviderFault::InvalidTransition);
        }
        if let Some(fault) = self.provider_fault {
            return Err(fault);
        }
        if self.is_activated() {
            if self
                .worker_thread
                .as_ref()
                .is_some_and(JoinHandle::is_finished)
            {
                self.provider_fault.get_or_insert(ProviderFault::Worker);
                return Err(ProviderFault::Worker);
            }
            if !self.worker_running.load(Ordering::Acquire) {
                return Ok(Poll::Pending);
            }
        }
        self.lifecycle.snapshot.stage = ProviderStage::Running;
        Ok(Poll::Ready(()))
    }

    fn state_limit(&self) -> u32 {
        BLOCK_STATE_LIMIT as u32
    }

    fn flush_for_capture(&self, key: BarrierKey) -> Result<(), ProviderFault> {
        self.check_cut(key)?;
        if self.is_read_only() {
            return Ok(());
        }
        self.disk
            .as_ref()
            .ok_or(ProviderFault::Worker)?
            .checked_sync()
            .map_err(|_| ProviderFault::Worker)
    }

    fn capture_payload(&self, key: BarrierKey) -> Result<Vec<u8>, ProviderFault> {
        self.check_cut(key)?;
        self.preflight()?;
        let encode = || -> Result<Vec<u8>, utils::state::Error> {
            let mut writer = Writer::new(BLOCK_STATE_LIMIT);
            writer.header(BLOCK_STATE_MAGIC, BLOCK_STATE_SCHEMA)?;
            writer.u16(1)?;
            writer.u32(TYPE_BLOCK)?;
            writer.u64(self.avail_features)?;
            writer.u64(self.acked_features)?;
            writer.u8(self.disk_format as u8)?;
            writer.u64(self.byte_length)?;
            writer.bool(self.is_read_only())?;
            writer.bool(self.direct_io)?;
            writer.u32(self.sync_mode as u32)?;
            writer.u8(self.cache_type as u8)?;
            writer.bytes(self.id.as_bytes(), BLOCK_ID_LIMIT)?;
            writer.fixed(&self.disk_image_id)?;
            self.config.encode(&mut writer)?;
            Ok(writer.finish())
        };
        encode().map_err(|_| ProviderFault::DeviceState)
    }

    fn validate_payload(&self, payload: &[u8]) -> Result<(), ProviderFault> {
        self.validate_block_payload(payload).map(|_| ())
    }

    fn validate_restore(&self, payload: &[u8]) -> Result<(), ProviderFault> {
        if self.is_activated() || self.worker_thread.is_some() {
            return Err(ProviderFault::InvalidTransition);
        }
        self.validate_payload(payload)
    }

    fn apply_payload(&mut self, payload: &[u8]) -> Result<(), ProviderFault> {
        if self.lifecycle.snapshot.stage != ProviderStage::Quiesced || self.worker_thread.is_some()
        {
            return Err(ProviderFault::InvalidTransition);
        }
        let saved = self.validate_block_payload(payload)?;
        let serial = saved.serial;
        let acked = saved.acked;
        self.disk_image_id.copy_from_slice(&serial);
        if let Some(disk) = &mut self.disk {
            disk.image_id.copy_from_slice(&serial);
        }
        self.acked_features = acked;
        Ok(())
    }

    fn prepare_restore(
        &mut self,
        request: BarrierRequest,
        payload: &[u8],
        context: DormantDeviceContext,
    ) -> Result<(), ProviderFault> {
        self.validate_restore(payload)?;
        if self.lifecycle.snapshot.request.is_some() {
            return Err(ProviderFault::InvalidTransition);
        }
        self.lifecycle.begin(request, ProviderStage::Quiescing);
        self.lifecycle.snapshot.stage = ProviderStage::Quiesced;
        self.apply_payload(payload)?;
        self.restored = true;
        if context.activated {
            self.device_state = DeviceState::Activated(context.memory, context.interrupt);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::virtio::block::device::*;

    use utils::tempfile::TempFile;

    #[test]
    fn disk_image_id_prefers_supplied_block_id() {
        let backing = TempFile::new().expect("create backing file");
        backing
            .as_file()
            .set_len(SECTOR_SIZE)
            .expect("size backing file");

        let image_id = DiskProperties::build_disk_image_id(backing.as_file(), "workload-rootfs");

        assert_eq!(image_id.len(), VIRTIO_BLK_ID_BYTES as usize);
        assert_eq!(&image_id[..b"workload-rootfs".len()], b"workload-rootfs");
        assert!(
            image_id[b"workload-rootfs".len()..]
                .iter()
                .all(|byte| *byte == 0)
        );
    }

    #[test]
    fn disk_image_id_truncates_supplied_block_id_to_virtio_limit() {
        let backing = TempFile::new().expect("create backing file");
        backing
            .as_file()
            .set_len(SECTOR_SIZE)
            .expect("size backing file");
        let long_id = "volume-name-that-is-longer-than-virtio-limit";

        let image_id = DiskProperties::build_disk_image_id(backing.as_file(), long_id);

        assert_eq!(image_id.len(), VIRTIO_BLK_ID_BYTES as usize);
        assert_eq!(
            &image_id,
            &long_id.as_bytes()[..VIRTIO_BLK_ID_BYTES as usize]
        );
    }

    #[test]
    fn disk_image_id_accepts_empty_block_id() {
        let backing = TempFile::new().expect("create backing file");
        backing
            .as_file()
            .set_len(SECTOR_SIZE)
            .expect("size backing file");

        let image_id = DiskProperties::build_disk_image_id(backing.as_file(), "");

        assert_eq!(image_id.len(), VIRTIO_BLK_ID_BYTES as usize);
    }

    fn raw_block(backing: &TempFile, id: &str, read_only: bool) -> Block {
        Block::new(
            id.into(),
            None,
            CacheType::Unsafe,
            backing
                .as_path()
                .to_str()
                .expect("tempfile UTF-8 path")
                .into(),
            DiskFormat::Raw,
            read_only,
            false,
            SyncMode::Relaxed,
        )
        .expect("open actual raw destination binding")
    }

    #[cfg(unix)]
    #[test]
    fn cold_raw_identity_and_io_remain_bound_to_adopted_inode_after_path_replacement()
    -> io::Result<()> {
        use std::os::unix::fs::FileExt;
        let backing = TempFile::new().unwrap();
        backing.as_file().set_len(4096).unwrap();
        backing.as_file().write_all_at(&[17], 0).unwrap();
        let metadata = backing.as_file().metadata().unwrap();
        let identity = (
            std::os::unix::fs::MetadataExt::dev(&metadata),
            std::os::unix::fs::MetadataExt::ino(&metadata),
        );
        let block = raw_block(&backing, "data", false);
        std::fs::remove_file(backing.as_path()).unwrap();
        let replacement = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(backing.as_path())
            .unwrap();
        replacement.set_len(4096).unwrap();
        replacement.write_all_at(&[29], 0).unwrap();
        assert_eq!(block.backing_file_identities().unwrap(), [identity]);
        let mut observed = [0; 1];
        {
            let disk = block
                .disk_image
                .lock()
                .map_err(|_| io::Error::other("actual Raw backend lock poisoned"))?;
            let (mapping, _) = disk.get_mapping(0, 1)?;
            let imago::Mapping::Raw { storage, .. } = mapping else {
                panic!("Raw mapping required")
            };
            assert!(storage.get_filename().is_none());
            disk.read(&mut observed[..], 0)?;
            assert_eq!(observed, [17]);
            disk.write(&[41u8][..], 0)?;
        }
        backing.as_file().read_exact_at(&mut observed, 0).unwrap();
        assert_eq!(observed, [41]);
        replacement.read_exact_at(&mut observed, 0).unwrap();
        assert_eq!(observed, [29]);
        #[cfg(target_os = "macos")]
        {
            assert!(block.disk.as_ref().unwrap().relaxed_sync_file.is_some());
            block.disk.as_ref().unwrap().checked_sync().unwrap();
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn restore_raw_constructor_consumes_exact_owned_file_without_reopening_path() {
        let source_file = TempFile::new().unwrap();
        source_file.as_file().set_len(4096).unwrap();
        let mut source = raw_block(&source_file, "data", false);
        let pause = request(1, 1);
        quiesce(&mut source, pause);
        let payload = source.capture_payload(pause.key).unwrap();
        let destination = TempFile::new().unwrap();
        destination.as_file().set_len(4096).unwrap();
        let owned = destination.as_file().try_clone().unwrap();
        let metadata = owned.metadata().unwrap();
        let identity = (
            std::os::unix::fs::MetadataExt::dev(&metadata),
            std::os::unix::fs::MetadataExt::ino(&metadata),
        );
        std::fs::remove_file(destination.as_path()).unwrap();
        let block = Block::new_restore_binding(
            "data".into(),
            RestoreBlockBacking::Raw {
                file: owned,
                read_only: false,
            },
            &payload,
        )
        .unwrap();
        assert_eq!(block.backing_file_identities().unwrap(), [identity]);
        block.validate_restore(&payload).unwrap();
        let wrong = TempFile::new().unwrap();
        wrong.as_file().set_len(8192).unwrap();
        assert!(matches!(
            Block::new_restore_binding(
                "data".into(),
                RestoreBlockBacking::Raw {
                    file: wrong.as_file().try_clone().unwrap(),
                    read_only: false,
                },
                &payload,
            ),
            Err(RestoreBindingError::Binding)
        ));
        assert!(matches!(
            Block::new_restore_binding(
                "foreign".into(),
                RestoreBlockBacking::Raw {
                    file: source_file.as_file().try_clone().unwrap(),
                    read_only: false,
                },
                &payload,
            ),
            Err(RestoreBindingError::Binding)
        ));
        assert!(matches!(
            Block::new_restore_binding(
                "data".into(),
                RestoreBlockBacking::Raw {
                    file: source_file.as_file().try_clone().unwrap(),
                    read_only: false,
                },
                &payload[..payload.len() - 1],
            ),
            Err(RestoreBindingError::Payload)
        ));
        assert_eq!(
            Block::inspect_restore_payload(&payload).unwrap(),
            RestoreBlockShape {
                id: "data".into(),
                format: DiskFormat::Raw,
                byte_length: 4096,
                read_only: false,
                direct_io: false,
                sync_mode: SyncMode::Relaxed,
                cache_type: CacheType::Unsafe,
            }
        );
    }

    #[test]
    #[cfg(feature = "native-device-probe")]
    fn pressure_observation_block_actual_owner_locks_distinguish_busy_and_poison() {
        let backing = TempFile::new().unwrap();
        backing.as_file().set_len(4096).unwrap();
        let mut block = raw_block(&backing, "pressure", false);
        let admission = block.worker_admission.clone();
        let held = admission.lock().expect("hold the actual acquisition gate");
        std::thread::scope(|scope| {
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            let block = &mut block;
            let observation = scope.spawn(move || sender.send(block.pressure_ownership()).unwrap());
            let observed = receiver.recv_timeout(std::time::Duration::from_secs(1));
            drop(held);
            observation.join().unwrap();
            assert!(matches!(observed, Ok(Err(ProviderFault::LockBusy))));
        });
        let slot = block.worker_slot.clone();
        let held = slot.lock().expect("hold the actual returned-worker slot");
        std::thread::scope(|scope| {
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            let block = &mut block;
            let observation = scope.spawn(move || sender.send(block.pressure_ownership()).unwrap());
            let observed = receiver.recv_timeout(std::time::Duration::from_secs(1));
            drop(held);
            observation.join().unwrap();
            assert!(matches!(observed, Ok(Err(ProviderFault::LockBusy))));
        });
        let observed = block.pressure_ownership().unwrap();
        assert!(observed.backend_retained);
        assert!(!observed.worker_handle_retained);
        assert_eq!(observed.owned_head, None);
        assert_eq!(observed.available_unpopped, 0);
        assert_eq!(observed.consumed_kicks, 0);
        assert!(
            std::thread::spawn(move || {
                let _held = admission
                    .lock()
                    .expect("poison the actual acquisition gate");
                panic!("poison the actual acquisition gate");
            })
            .join()
            .is_err()
        );
        assert!(matches!(
            block.pressure_ownership(),
            Err(ProviderFault::Worker)
        ));
    }

    fn request(operation: u64, generation: u64) -> BarrierRequest {
        use polly::event_manager::{BarrierGeneration, OperationId};
        BarrierRequest {
            key: BarrierKey {
                operation: OperationId(operation),
                generation: BarrierGeneration(generation),
            },
            deadline: Instant::now() + std::time::Duration::from_secs(2),
        }
    }

    fn quiesce(block: &mut Block, request: BarrierRequest) -> QuiesceCompletion {
        block.begin_quiesce(request).expect("accept real raw pause");
        loop {
            match block
                .poll_quiesce(request.key)
                .expect("poll raw worker ownership")
            {
                Poll::Ready(completion) => return completion,
                Poll::Pending => {
                    assert!(
                        Instant::now() < request.deadline,
                        "real block worker did not park"
                    );
                    std::thread::yield_now();
                }
            }
        }
    }

    #[cfg(unix)]
    fn generated_vmdk(records: &[(u64, &TempFile, u64)]) -> TempFile {
        use std::os::unix::fs::FileExt;
        let mut text = String::from(
            "# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\ncreateType=\"twoGbMaxExtentFlat\"\n\n",
        );
        for (sectors, extent, offset) in records {
            text.push_str(&format!(
                "RW {sectors} FLAT \"{}\" {offset}\n",
                extent.as_path().display()
            ));
        }
        let descriptor = TempFile::new().unwrap();
        descriptor
            .as_file()
            .write_all_at(text.as_bytes(), 0)
            .unwrap();
        descriptor
    }

    #[cfg(unix)]
    fn held_vmdk(descriptor: &TempFile, extents: &[&TempFile]) -> RestoreBlockBacking {
        RestoreBlockBacking::ReadonlyVmdk(ReadonlyVmdk {
            descriptor: File::open(descriptor.as_path()).unwrap(),
            extents: extents
                .iter()
                .map(|extent| crate::virtio::block::VmdkExtent {
                    path: extent.as_path().to_path_buf(),
                    file: File::open(extent.as_path()).unwrap(),
                })
                .collect(),
        })
    }

    fn captured(block: &mut Block) -> Vec<u8> {
        let pause = request(1, 1);
        let completed = quiesce(block, pause);
        assert_eq!(completed.fault, None);
        block.flush_for_capture(pause.key).unwrap();
        block.capture_payload(pause.key).unwrap()
    }

    fn read_byte(block: &Block, offset: u64) -> u8 {
        let mut observed = [0];
        block
            .disk_image
            .lock()
            .unwrap()
            .read(&mut observed[..], offset)
            .unwrap();
        observed[0]
    }

    #[cfg(unix)]
    #[test]
    fn readonly_vmdk_restore_preserves_format_from_held_closure_and_rejects_raw_substitution() {
        use std::os::unix::fs::FileExt;

        let first = TempFile::new().unwrap();
        first.as_file().set_len(4096).unwrap();
        first.as_file().write_all_at(&[37], 0).unwrap();
        first.as_file().write_all_at(&[38], 2048).unwrap();
        let second = TempFile::new().unwrap();
        second.as_file().set_len(512).unwrap();
        second.as_file().write_all_at(&[39], 0).unwrap();
        // A split first extent, a second extent and a repeat of the first.
        let descriptor = generated_vmdk(&[
            (4, &first, 0),
            (4, &first, 4),
            (1, &second, 0),
            (1, &first, 0),
        ]);
        let mut block = Block::new(
            "lower".into(),
            None,
            CacheType::Unsafe,
            descriptor.as_path().to_str().unwrap().into(),
            DiskFormat::Vmdk,
            true,
            false,
            SyncMode::Relaxed,
        )
        .unwrap();
        let payload = captured(&mut block);
        let shape = Block::inspect_restore_payload(&payload).unwrap();
        assert_eq!(shape.format, DiskFormat::Vmdk);
        assert!(shape.read_only);
        assert_eq!(shape.byte_length, 10 * 512);
        assert_eq!(shape.id, "lower");
        block.validate_payload(&payload).unwrap();
        let inode = |file: &TempFile| {
            let metadata = file.as_file().metadata().unwrap();
            (
                std::os::unix::fs::MetadataExt::dev(&metadata),
                std::os::unix::fs::MetadataExt::ino(&metadata),
            )
        };
        // Descriptor first, then every extent once in first-reference order:
        // live capture refuses outputs that alias any of them.
        let identities = [inode(&descriptor), inode(&first), inode(&second)];
        assert_eq!(block.backing_file_identities().unwrap(), identities);

        let raw = raw_block(&first, "lower", true);
        assert!(raw.validate_payload(&payload).is_err());
        assert!(matches!(
            Block::new_restore_binding(
                "lower".into(),
                RestoreBlockBacking::Raw {
                    file: File::open(first.as_path()).unwrap(),
                    read_only: true,
                },
                &payload,
            ),
            Err(RestoreBindingError::Format)
        ));

        let held = held_vmdk(&descriptor, &[&first, &second]);
        // The restore seam never opens a descriptor-named path.
        std::fs::remove_file(descriptor.as_path()).unwrap();
        std::fs::remove_file(first.as_path()).unwrap();
        std::fs::remove_file(second.as_path()).unwrap();
        let restored = Block::new_restore_binding("lower".into(), held, &payload).unwrap();
        restored.validate_restore(&payload).unwrap();
        assert_eq!(restored.disk_format, DiskFormat::Vmdk);
        assert!(restored.is_read_only());
        assert_eq!(restored.backing_file_identities().unwrap(), identities);
        assert_eq!(restored.disk_image_id, block.disk_image_id);
        for (offset, expected) in [(0, 37), (2048, 38), (4096, 39), (4608, 37)] {
            assert_eq!(read_byte(&restored, offset), expected, "offset {offset}");
        }
        assert!(
            restored
                .disk_image
                .lock()
                .unwrap()
                .write(&[1u8][..], 0)
                .is_err()
        );

        let mut writable = payload.clone();
        writable[41] = 0;
        assert!(BlockPayload::decode(&writable).is_err());
        assert!(Block::inspect_restore_payload(&writable).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn cold_vmdk_resolves_relative_extents_and_records_every_backing_inode() {
        use std::os::unix::fs::FileExt;

        let extent = TempFile::new().unwrap();
        extent.as_file().set_len(1024).unwrap();
        extent.as_file().write_all_at(&[53], 512).unwrap();
        let name = extent.as_path().file_name().unwrap().to_str().unwrap();
        // Relative names resolve against the descriptor's directory, as
        // before; the restore seam alone requires absolute generated paths.
        let descriptor = TempFile::new_in(extent.as_path().parent().unwrap()).unwrap();
        descriptor
            .as_file()
            .write_all_at(
                format!(
                    "# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\ncreateType=\"monolithicFlat\"\nRW 2 FLAT \"{name}\" 0\nRW 1 FLAT \"{name}\" 1\n"
                )
                .as_bytes(),
                0,
            )
            .unwrap();
        let block = Block::new(
            "lower".into(),
            None,
            CacheType::Unsafe,
            descriptor.as_path().to_str().unwrap().into(),
            DiskFormat::Vmdk,
            true,
            false,
            SyncMode::Relaxed,
        )
        .unwrap();
        let inode = |file: &TempFile| {
            let metadata = file.as_file().metadata().unwrap();
            (
                std::os::unix::fs::MetadataExt::dev(&metadata),
                std::os::unix::fs::MetadataExt::ino(&metadata),
            )
        };
        assert_eq!(
            block.backing_file_identities().unwrap(),
            [inode(&descriptor), inode(&extent)]
        );
        assert_eq!(read_byte(&block, 1024), 53);
    }

    #[cfg(unix)]
    #[test]
    fn readonly_vmdk_restore_rejects_wrong_saved_format_identity_geometry_and_closure() {
        use std::os::unix::fs::FileExt;

        let extent = TempFile::new().unwrap();
        extent.as_file().set_len(4096).unwrap();
        extent.as_file().write_all_at(&[41], 0).unwrap();
        let other = TempFile::new().unwrap();
        other.as_file().set_len(4096).unwrap();
        let descriptor = generated_vmdk(&[(8, &extent, 0)]);
        let mut cold = Block::new(
            "lower".into(),
            None,
            CacheType::Unsafe,
            descriptor.as_path().to_str().unwrap().into(),
            DiskFormat::Vmdk,
            true,
            false,
            SyncMode::Relaxed,
        )
        .unwrap();
        let payload = captured(&mut cold);

        // A saved raw device is never rebuilt from a VMDK closure.
        let mut raw = raw_block(&extent, "lower", true);
        let raw_payload = captured(&mut raw);
        assert!(matches!(
            Block::new_restore_binding(
                "lower".into(),
                held_vmdk(&descriptor, &[&extent]),
                &raw_payload
            ),
            Err(RestoreBindingError::Format)
        ));
        // A saved writable VMDK payload is not a valid payload at all.
        let mut writable = payload.clone();
        writable[41] = 0;
        assert!(matches!(
            Block::new_restore_binding(
                "lower".into(),
                held_vmdk(&descriptor, &[&extent]),
                &writable
            ),
            Err(RestoreBindingError::Payload)
        ));
        assert!(matches!(
            Block::new_restore_binding(
                "upper".into(),
                held_vmdk(&descriptor, &[&extent]),
                &payload
            ),
            Err(RestoreBindingError::Binding)
        ));
        let shorter = generated_vmdk(&[(4, &extent, 0)]);
        assert!(matches!(
            Block::new_restore_binding("lower".into(), held_vmdk(&shorter, &[&extent]), &payload),
            Err(RestoreBindingError::Binding)
        ));
        assert!(matches!(
            Block::new_restore_binding(
                "lower".into(),
                held_vmdk(&descriptor, &[&extent, &other]),
                &payload
            ),
            Err(RestoreBindingError::Closure(
                crate::virtio::block::vmdk::VmdkClosureFault::UnreferencedExtent
            ))
        ));
        assert!(matches!(
            Block::new_restore_binding("lower".into(), held_vmdk(&descriptor, &[&other]), &payload),
            Err(RestoreBindingError::Closure(
                crate::virtio::block::vmdk::VmdkClosureFault::UndeclaredExtent
            ))
        ));
        let past_end = generated_vmdk(&[(8, &extent, 1)]);
        assert!(matches!(
            Block::new_restore_binding("lower".into(), held_vmdk(&past_end, &[&extent]), &payload),
            Err(RestoreBindingError::Closure(
                crate::virtio::block::vmdk::VmdkClosureFault::ExtentRange
            ))
        ));
        let restored = Block::new_restore_binding(
            "lower".into(),
            held_vmdk(&descriptor, &[&extent]),
            &payload,
        )
        .unwrap();
        assert_eq!(read_byte(&restored, 0), 41);
    }

    #[test]
    fn block_provider_inactive_capture_is_explicit_bounded_and_cut_bound() {
        let backing = TempFile::new().unwrap();
        backing.as_file().set_len(4096).unwrap();
        let mut block = raw_block(&backing, "root", false);
        let pause = request(1, 1);
        assert!(block.capture_payload(pause.key).is_err());
        let completed = quiesce(&mut block, pause);
        assert!(completed.queues.is_empty());
        assert_eq!(completed.fault, None);
        assert!(!block.is_activated());
        block.flush_for_capture(pause.key).unwrap();
        let payload = block.capture_payload(pause.key).unwrap();
        use utils::state::StateHeaderError;
        assert_eq!(&payload[..10], b"KRUNBLKS\x01\x00");
        let mut wrong_magic = payload.clone();
        wrong_magic[0] ^= 1;
        assert!(matches!(
            block.validate_payload(&wrong_magic),
            Err(ProviderFault::StateHeader(StateHeaderError::Magic { .. }))
        ));
        let mut wrong_schema = payload.clone();
        wrong_schema[8..10].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            block.validate_payload(&wrong_schema),
            Err(ProviderFault::StateHeader(StateHeaderError::Schema { expected: 1, found: 2 }))
        );
        assert!(!payload.is_empty());
        assert!(payload.len() <= block.state_limit() as usize);
        block.validate_payload(&payload).unwrap();
        assert_eq!(payload, block.capture_payload(pause.key).unwrap());
        assert!(block.capture_payload(request(2, 1).key).is_err());
        assert!(matches!(
            block.poll_quiesce(pause.key),
            Err(ProviderFault::InvalidTransition)
        ));
        for length in 0..payload.len() {
            assert!(block.validate_payload(&payload[..length]).is_err());
        }
        let mut trailing = payload.clone();
        trailing.push(0);
        assert!(block.validate_payload(&trailing).is_err());
        let mut unknown = payload.clone();
        unknown[10] = 2;
        assert!(block.validate_payload(&unknown).is_err());
        let mut wrong_kind = payload.clone();
        wrong_kind[12..16].copy_from_slice(&crate::virtio::TYPE_RNG.to_le_bytes());
        assert!(block.validate_payload(&wrong_kind).is_err());
        assert!(
            block
                .validate_payload(&vec![0; BLOCK_STATE_LIMIT + 1])
                .is_err()
        );
        let mut bad_features = payload;
        bad_features[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(block.validate_payload(&bad_features).is_err());
    }

    #[test]
    fn block_provider_destination_binding_rejects_geometry_readonly_identity_and_profile() {
        let source_file = TempFile::new().unwrap();
        source_file.as_file().set_len(4096).unwrap();
        let mut source = raw_block(&source_file, "data", false);
        let pause = request(1, 1);
        quiesce(&mut source, pause);
        let payload = source.capture_payload(pause.key).unwrap();
        let wrong_size_file = TempFile::new().unwrap();
        wrong_size_file.as_file().set_len(8192).unwrap();
        let wrong_size = raw_block(&wrong_size_file, "data", false);
        assert!(wrong_size.validate_restore(&payload).is_err());
        let destination_file = TempFile::new().unwrap();
        destination_file.as_file().set_len(4096).unwrap();
        let mut destination = raw_block(&destination_file, "data", false);
        destination.validate_restore(&payload).unwrap();
        let mut wrong_serial = payload.clone();
        let serial_offset = wrong_serial.len()
            - std::mem::size_of::<VirtioBlkConfig>()
            - VIRTIO_BLK_ID_BYTES as usize;
        wrong_serial[serial_offset] ^= 1;
        assert!(destination.validate_restore(&wrong_serial).is_err());
        destination.byte_length += 512;
        assert!(destination.validate_restore(&payload).is_err());
        destination.byte_length -= 512;
        destination.direct_io = true;
        assert!(destination.validate_restore(&payload).is_err());
        destination.direct_io = false;
        destination.sync_mode = SyncMode::Full;
        assert!(destination.validate_restore(&payload).is_err());
        destination.sync_mode = SyncMode::Relaxed;
        destination.cache_type = CacheType::Writeback;
        assert!(destination.validate_restore(&payload).is_err());
        destination.cache_type = CacheType::Unsafe;
        destination.disk_format = DiskFormat::Qcow2;
        assert_eq!(
            destination.validate_restore(&payload),
            Err(ProviderFault::Unsupported)
        );
        destination.disk_format = DiskFormat::Raw;
        destination.id = "other-data".into();
        assert!(destination.validate_restore(&payload).is_err());
        let read_only = raw_block(&destination_file, "data", true);
        assert!(read_only.validate_restore(&payload).is_err());
        assert!(!destination.is_activated());
        assert!(destination.worker_thread.is_none());
    }

    #[test]
    fn block_provider_preflight_contention_is_retryable_without_mutation() {
        let backing = TempFile::new().unwrap();
        backing.as_file().set_len(4096).unwrap();
        let mut block = raw_block(&backing, "data", false);
        let backend = block.disk_image.clone();
        let guard = backend.lock().expect("actual backend lock");
        assert_eq!(block.preflight(), Err(ProviderFault::LockBusy));
        assert_eq!(block.lifecycle.snapshot.stage, ProviderStage::Running);
        assert!(block.lifecycle.snapshot.request.is_none());
        assert!(block.worker_thread.is_none());
        block.provider_fault = Some(ProviderFault::Worker);
        assert_eq!(block.preflight(), Err(ProviderFault::Worker));
        block.provider_fault = None;
        drop(guard);
        assert_eq!(block.preflight(), Ok(()));
    }

    #[test]
    fn block_provider_capture_sync_failure_retains_completed_pause() {
        let backing = TempFile::new().unwrap();
        backing.as_file().set_len(4096).unwrap();
        let mut block = raw_block(&backing, "data", false);
        let pause = request(1, 1);
        quiesce(&mut block, pause);
        let backend = block.disk_image.clone();
        let _ = std::thread::spawn(move || {
            let _guard = backend.lock().expect("actual backend lock");
            panic!("poison the actual backend lock");
        })
        .join();
        assert_eq!(
            block.flush_for_capture(pause.key),
            Err(ProviderFault::Worker)
        );
        assert_eq!(block.preflight(), Err(ProviderFault::DeviceLock));
        assert_eq!(block.lifecycle.snapshot.stage, ProviderStage::Quiesced);
        assert_eq!(block.lifecycle.snapshot.quiesce_request, Some(pause));
        assert!(block.disk.is_some());
        assert!(block.worker_thread.is_none());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn interrupt() -> InterruptTransport {
        use crate::legacy::{IrqChipDevice, KvmIoapic};
        let controller = IrqChipDevice::new(Box::new(KvmIoapic {}));
        InterruptTransport::new(
            Arc::new(Mutex::new(controller)),
            "block-provider".into(),
            Some(Arc::new(EventFd::new(EFD_NONBLOCK).unwrap())),
        )
        .unwrap()
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn block_provider_source_resume_scans_original_queue_without_new_kick() {
        use crate::virtio::queue::tests::VirtQueue;
        use vm_memory::GuestAddress;

        let backing = TempFile::new().unwrap();
        backing.as_file().set_len(4096).unwrap();
        let mut block = raw_block(&backing, "data", false);
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        let queue = ring.create_queue();
        let identity = queue.identity();
        let event = Arc::new(EventFd::new(EFD_NONBLOCK).unwrap());
        let irq = interrupt();
        let completion_event = irq.event().try_clone().unwrap();
        block
            .activate(
                memory.clone(),
                irq,
                vec![DeviceQueue::new(queue, event.clone())],
            )
            .unwrap();
        let pause = request(1, 1);
        let completed = quiesce(&mut block, pause);
        assert_eq!(completed.fault, None);
        assert_eq!(completed.queues.len(), 1);
        assert!(Arc::ptr_eq(
            &completed.queues[0].queue.identity(),
            &identity
        ));
        assert!(Arc::ptr_eq(&completed.queues[0].event, &event));
        let backend = block.disk_image.clone();
        assert!(Arc::ptr_eq(&block.disk.as_ref().unwrap().file, &backend));
        ring.dtable[0].set(0x1000, 16, 1, 1);
        ring.dtable[1].set(0x1100, 512, 1, 2);
        ring.dtable[2].set(0x1300, 1, 2, 0);
        // The guest request header is an explicit little-endian virtio wire record.
        memory
            .write_slice(
                &virtio_bindings::virtio_blk::VIRTIO_BLK_T_OUT.to_le_bytes(),
                GuestAddress(0x1000),
            )
            .unwrap();
        memory.write_obj(0_u32, GuestAddress(0x1004)).unwrap();
        memory.write_obj(0_u64, GuestAddress(0x1008)).unwrap();
        memory
            .write_slice(&[0x75; 512], GuestAddress(0x1100))
            .unwrap();
        memory.write_obj(0xff_u8, GuestAddress(0x1300)).unwrap();
        ring.avail.ring[0].set(0);
        ring.avail.idx.set(1);
        assert!(event.read().is_err());
        let resume = request(2, 1);
        assert!(matches!(
            block.begin_resume(resume, completed.queues),
            ResumeAcceptance::Accepted
        ));
        while block.poll_resume(resume.key).unwrap().is_pending() {
            assert!(Instant::now() < resume.deadline);
            std::thread::yield_now();
        }
        assert_eq!(ring.used.idx.get(), 1);
        assert_eq!(ring.used.ring[0].get().len, 1);
        assert_eq!(
            memory.read_obj::<u8>(GuestAddress(0x1300)).unwrap(),
            VIRTIO_BLK_S_OK as u8
        );
        assert_eq!(completion_event.read().unwrap(), 1);
        assert_eq!(
            &std::fs::read(backing.as_path()).unwrap()[..512],
            &[0x75; 512]
        );
        let next_pause = request(3, 2);
        let completed = quiesce(&mut block, next_pause);
        assert_eq!(completed.fault, None);
        let state = completed.queues[0].queue.capture_state().unwrap();
        assert_eq!((state.next_avail, state.next_used), (1, 1));
        assert!(Arc::ptr_eq(&completed.queues[0].event, &event));
        assert!(Arc::ptr_eq(&block.disk.as_ref().unwrap().file, &backend));
        block.flush_for_capture(next_pause.key).unwrap();
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        feature = "native-device-probe"
    ))]
    #[test]
    fn pressure_real_wake_failure_retains_and_recovers_actual_worker_queue() {
        use crate::virtio::queue::tests::VirtQueue;
        use vm_memory::GuestAddress;

        let backing = TempFile::new().unwrap();
        backing.as_file().set_len(4096).unwrap();
        let mut block = raw_block(&backing, "pressure", false);
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        let queue = ring.create_queue();
        let identity = queue.identity();
        let event = Arc::new(EventFd::new(EFD_NONBLOCK).unwrap());
        block
            .activate(
                memory,
                interrupt(),
                vec![DeviceQueue::new(queue, event.clone())],
            )
            .unwrap();
        block.pressure_arm_wake_failure().unwrap();
        let pause = request(1, 1);
        let failure = block.begin_quiesce(pause).unwrap_err();
        assert!(failure.accepted);
        assert_eq!(failure.fault, ProviderFault::Worker);
        let ownership = block.pressure_ownership().unwrap();
        assert!(ownership.worker_handle_retained);
        assert!(ownership.subscribed_wake_held);
        assert_eq!(ownership.wake_errno, Some(nix::errno::Errno::EAGAIN as i32));
        assert!(!ownership.worker_finished);
        assert!(block.lifecycle.snapshot.accepted);
        assert!(block.lifecycle.snapshot.failure.is_some());
        block.pressure_restore_wake().unwrap();
        let completion = loop {
            match block.poll_quiesce(pause.key).unwrap() {
                Poll::Ready(completion) => break completion,
                Poll::Pending => {
                    assert!(Instant::now() < pause.deadline);
                    std::thread::yield_now();
                }
            }
        };
        assert_eq!(completion.fault, Some(ProviderFault::Worker));
        assert_eq!(completion.queues.len(), 1);
        assert!(Arc::ptr_eq(
            &completion.queues[0].queue.identity(),
            &identity
        ));
        assert!(Arc::ptr_eq(&completion.queues[0].event, &event));
        let ownership = block.pressure_ownership().unwrap();
        assert!(ownership.backend_retained);
        assert!(!ownership.worker_handle_retained);
        assert!(!ownership.subscribed_wake_held);
        assert!(block.poll_quiesce(pause.key).is_err());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn block_provider_restore_adopts_serial_and_stays_dormant_without_dma_or_irq() {
        use crate::virtio::lifecycle::RestoredReclaimPolicy;
        use crate::virtio::queue::tests::VirtQueue;
        use vm_memory::GuestAddress;

        let source_file = TempFile::new().unwrap();
        source_file.as_file().set_len(4096).unwrap();
        let mut source = raw_block(&source_file, "", false);
        let pause = request(1, 1);
        quiesce(&mut source, pause);
        let payload = source.capture_payload(pause.key).unwrap();
        let destination_file = TempFile::new().unwrap();
        destination_file.as_file().set_len(4096).unwrap();
        let mut destination = raw_block(&destination_file, "", false);
        assert_ne!(source.disk_image_id, destination.disk_image_id);
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        memory
            .write_slice(&[0xa5; 128], GuestAddress(0x1000))
            .unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
        ring.dtable[0].set(0x2000, 16, 1, 1);
        ring.dtable[1].set(0x2100, 20, 3, 2);
        ring.dtable[2].set(0x2114, 1, 2, 0);
        memory
            .write_slice(&VIRTIO_BLK_T_GET_ID.to_le_bytes(), GuestAddress(0x2000))
            .unwrap();
        memory.write_obj(0_u32, GuestAddress(0x2004)).unwrap();
        memory.write_obj(0_u64, GuestAddress(0x2008)).unwrap();
        memory.write_obj(0xff_u8, GuestAddress(0x2114)).unwrap();
        ring.avail.ring[0].set(0);
        ring.avail.idx.set(1);
        let irq = interrupt();
        let completion = irq.event().try_clone().unwrap();
        destination
            .prepare_restore(
                pause,
                &payload,
                DormantDeviceContext {
                    memory: memory.clone(),
                    interrupt: irq,
                    activated: true,
                    reclaim_policy: RestoredReclaimPolicy::Disabled,
                },
            )
            .unwrap();
        assert_eq!(destination.disk_image_id, source.disk_image_id);
        assert_eq!(
            destination.disk.as_ref().unwrap().image_id(),
            source.disk_image_id
        );
        assert!(destination.worker_thread.is_none());
        assert!(
            destination
                .worker_admission
                .lock()
                .expect("acquisition gate")
                .barrier
                .is_none()
        );
        assert!(completion.read().is_err());
        let mut unchanged = [0; 128];
        memory
            .read_slice(&mut unchanged, GuestAddress(0x1000))
            .unwrap();
        assert_eq!(unchanged, [0xa5; 128]);
        assert_eq!(destination.capture_payload(pause.key).unwrap(), payload);
        assert_eq!(
            std::fs::read(destination_file.as_path()).unwrap(),
            vec![0; 4096]
        );
        assert_eq!(ring.used.idx.get(), 0);
        let event = Arc::new(EventFd::new(EFD_NONBLOCK).unwrap());
        let resume = request(2, 1);
        assert!(matches!(
            destination.begin_resume(resume, vec![DeviceQueue::new(ring.create_queue(), event),]),
            ResumeAcceptance::Accepted
        ));
        while destination.poll_resume(resume.key).unwrap().is_pending() {
            assert!(Instant::now() < resume.deadline);
            std::thread::yield_now();
        }
        assert_eq!(ring.used.idx.get(), 1);
        assert_eq!(ring.used.ring[0].get().len, 21);
        assert_eq!(
            memory.read_obj::<u8>(GuestAddress(0x2114)).unwrap(),
            VIRTIO_BLK_S_OK as u8
        );
        let mut serial = [0; VIRTIO_BLK_ID_BYTES as usize];
        memory
            .read_slice(&mut serial, GuestAddress(0x2100))
            .unwrap();
        assert_eq!(serial.as_slice(), source.disk_image_id);
        assert_eq!(completion.read().unwrap(), 1);
        assert_eq!(quiesce(&mut destination, request(3, 2)).fault, None);
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        feature = "native-device-probe"
    ))]
    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn terminal_stop_reconciles_real_wake_eagain_only_after_clean_ownership() {
        use crate::bus::BusDevice;
        use crate::legacy::{IrqChipDevice, KvmIoapic};
        use crate::virtio::MmioTransport;
        use crate::virtio::lifecycle::LifecycleError;
        use crate::virtio::queue::tests::VirtQueue;
        use std::io;
        use std::time::Duration;
        use vm_memory::GuestAddress;

        fn ownership(block: &Arc<Mutex<Block>>, deadline: Instant) -> BlockPressureOwnership {
            loop {
                assert!(
                    Instant::now() < deadline,
                    "actual block observation remained busy"
                );
                let observation = {
                    let block = block.lock().expect("actual block owner");
                    block.pressure_ownership()
                };
                match observation {
                    Ok(owner) => return owner,
                    Err(ProviderFault::LockBusy) => std::thread::yield_now(),
                    Err(fault) => panic!("actual block observation failed: {fault:?}"),
                }
            }
        }

        #[derive(Clone, Copy)]
        enum Case {
            Pending,
            Quiesced,
            SlotPoison,
            BackendPoison,
            InvalidEscrow,
            IrqFailure,
            ExpiredStop,
            LateOldDeadline,
        }
        for case in [
            Case::Pending,
            Case::Quiesced,
            Case::SlotPoison,
            Case::BackendPoison,
            Case::InvalidEscrow,
            Case::IrqFailure,
            Case::ExpiredStop,
            Case::LateOldDeadline,
        ] {
            let backing = TempFile::new().unwrap();
            backing.as_file().set_len(4096).unwrap();
            let block = Arc::new(Mutex::new(raw_block(&backing, "terminal-drain", false)));
            let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
            let ring = VirtQueue::new(GuestAddress(0), &memory, 8);
            ring.dtable[0].set(0x1000, 16, 1, 1);
            ring.dtable[1].set(0x1100, 512, 1, 2);
            ring.dtable[2].set(0x1400, 1, 2, 0);
            memory.write_obj(1u32, GuestAddress(0x1000)).unwrap();
            memory
                .write_slice(&[0x5a; 512], GuestAddress(0x1100))
                .unwrap();
            memory.write_obj(0xffu8, GuestAddress(0x1400)).unwrap();
            ring.avail.ring[0].set(0);
            ring.avail.idx.set(1);
            let configured = ring.create_queue();
            let line = Arc::new(EventFd::new(EFD_NONBLOCK).unwrap());
            let mut transport = MmioTransport::new(
                memory.clone(),
                Arc::new(Mutex::new(IrqChipDevice::new(Box::new(KvmIoapic {})))),
                block.clone(),
                Some(line.clone()),
            )
            .unwrap();
            transport.set_attachment_address(0x1000).unwrap();
            for status in [1u32, 3, 11] {
                transport.write(0, 0x70, &status.to_le_bytes());
            }
            for (offset, value) in [
                (0x38, 8u32),
                (0x80, configured.desc_table.0 as u32),
                (0x90, configured.avail_ring.0 as u32),
                (0xa0, configured.used_ring.0 as u32),
                (0x44, 1u32),
            ] {
                transport.write(0, offset, &value.to_le_bytes());
            }
            transport.write(0, 0x70, &15u32.to_le_bytes());
            let io_deadline = Instant::now() + Duration::from_secs(2);
            while ring.used.idx.get() != 1 {
                assert!(
                    Instant::now() < io_deadline,
                    "actual Raw write did not finish"
                );
                std::thread::yield_now();
            }
            assert_eq!(memory.read_obj::<u8>(GuestAddress(0x1400)).unwrap(), 0);
            assert_eq!(
                &std::fs::read(backing.as_path()).unwrap()[..512],
                &[0x5a; 512]
            );
            loop {
                match line.read() {
                    Ok(_) => break,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < io_deadline,
                            "actual Raw IRQ did not finish"
                        );
                        std::thread::yield_now();
                    }
                    Err(error) => panic!("actual Raw IRQ failed: {error}"),
                }
            }
            transport.write(0, 0x64, &1u32.to_le_bytes());

            block
                .lock()
                .expect("actual block owner")
                .pressure_arm_wake_failure()
                .unwrap();
            let observation_deadline = Instant::now() + Duration::from_secs(2);
            let mut pause = request(1, 1);
            let historical = if matches!(case, Case::LateOldDeadline) {
                // Keep the real worker hold but allow its original begin wake
                // to succeed, so only the old deadline fails during cleanup.
                block
                    .lock()
                    .expect("actual block owner")
                    .worker_stopfd
                    .read()
                    .unwrap();
                pause.deadline = Instant::now() + Duration::from_millis(40);
                transport.begin_quiesce(pause).unwrap();
                LifecycleError {
                    key: pause.key,
                    stage: ProviderStage::Quiescing,
                    accepted: true,
                    fault: ProviderFault::Deadline,
                }
            } else {
                let failure = transport.begin_quiesce(pause).unwrap_err();
                assert!(failure.accepted);
                assert_eq!(failure.fault, ProviderFault::Worker);
                failure
            };
            let owner = ownership(&block, observation_deadline);
            assert!(owner.worker_handle_retained);
            assert!(owner.subscribed_wake_held);
            assert_eq!(
                owner.wake_errno,
                if matches!(case, Case::LateOldDeadline) {
                    None
                } else {
                    Some(nix::errno::Errno::EAGAIN as i32)
                }
            );
            assert!(transport.capture_transport(pause.key).is_err());

            if matches!(case, Case::Quiesced) {
                block
                    .lock()
                    .expect("actual block owner")
                    .pressure_restore_wake()
                    .unwrap();
                while transport.lifecycle_snapshot().stage != ProviderStage::Quiesced {
                    assert!(Instant::now() < pause.deadline);
                    assert_eq!(transport.poll_quiesce(pause.key).unwrap_err(), historical);
                    std::thread::yield_now();
                }
            }
            let changed_pause = BarrierRequest {
                deadline: pause.deadline + Duration::from_secs(1),
                ..pause
            };
            assert_eq!(
                transport.poll_stop(changed_pause).unwrap_err().fault,
                ProviderFault::ForeignBarrier
            );
            assert_eq!(transport.lifecycle_snapshot().request, Some(pause));
            let mut stop = request(2, 1);
            if matches!(case, Case::ExpiredStop) {
                stop.deadline = Instant::now() + Duration::from_millis(40);
            }
            if !matches!(case, Case::Quiesced) {
                assert!(transport.poll_stop(stop).unwrap().is_pending());
                assert_eq!(
                    transport.lifecycle_snapshot().stage,
                    ProviderStage::Stopping
                );
                assert_eq!(transport.lifecycle_snapshot().request, Some(stop));
                assert_eq!(
                    transport.lifecycle_snapshot().previous_failure,
                    if matches!(case, Case::LateOldDeadline) {
                        None
                    } else {
                        Some(historical)
                    }
                );
                assert_eq!(transport.lifecycle_snapshot().failure, None);
                assert!(ownership(&block, observation_deadline).worker_handle_retained);
                if matches!(case, Case::SlotPoison) {
                    let slot = block
                        .lock()
                        .expect("actual block owner")
                        .worker_slot
                        .clone();
                    std::thread::spawn(move || {
                        let _guard = slot.lock().expect("actual returned worker slot");
                        panic!("poison the real block return slot after historical wake failure");
                    })
                    .join()
                    .unwrap_err();
                } else if matches!(case, Case::BackendPoison) {
                    let backend = block.lock().expect("actual block owner").disk_image.clone();
                    std::thread::spawn(move || {
                        let _guard = backend.lock().expect("actual Raw backend");
                        panic!("poison the real backend after historical wake failure");
                    })
                    .join()
                    .unwrap_err();
                } else if matches!(case, Case::IrqFailure) {
                    line.write(u64::MAX - 1).unwrap();
                    assert_eq!(
                        transport.interrupt(1).unwrap_err().raw_os_error(),
                        Some(nix::errno::Errno::EAGAIN as i32)
                    );
                }
                if matches!(case, Case::ExpiredStop) {
                    while Instant::now() < stop.deadline {
                        std::thread::yield_now();
                    }
                    let failure = transport.poll_stop(stop).unwrap_err();
                    assert_eq!(failure.key, stop.key);
                    assert_eq!(failure.fault, ProviderFault::Deadline);
                    assert!(ownership(&block, observation_deadline).worker_handle_retained);
                }
                if matches!(case, Case::LateOldDeadline) {
                    while Instant::now() < pause.deadline {
                        std::thread::yield_now();
                    }
                }
                block
                    .lock()
                    .expect("actual block owner")
                    .pressure_restore_wake()
                    .unwrap();
                if matches!(case, Case::InvalidEscrow) {
                    while !block
                        .lock()
                        .expect("actual block owner")
                        .worker_thread
                        .as_ref()
                        .unwrap()
                        .is_finished()
                    {
                        assert!(Instant::now() < stop.deadline);
                        std::thread::yield_now();
                    }
                    let block = block.lock().expect("actual returned block owner");
                    let mut slot = block.worker_slot.lock().expect("actual returned queue");
                    slot.as_mut().unwrap().device_queue.queue.desc_table = GuestAddress(1);
                }
            }
            let outcome = loop {
                match transport.poll_stop(stop) {
                    Ok(Poll::Pending) => {
                        assert!(
                            Instant::now() < stop.deadline,
                            "accepted original owner did not settle"
                        );
                        std::thread::yield_now();
                    }
                    result => break result,
                }
            };
            assert_eq!(
                transport.lifecycle_snapshot().previous_failure,
                Some(historical)
            );
            match case {
                Case::Pending | Case::Quiesced | Case::LateOldDeadline => {
                    assert!(outcome.unwrap().is_ready());
                    assert!(transport.poll_stop(stop).unwrap().is_ready());
                    assert_eq!(transport.lifecycle_snapshot().stage, ProviderStage::Stopped);
                    assert_eq!(transport.lifecycle_snapshot().failure, None);
                    let block = block.lock().expect("retained completed block owner");
                    assert!(block.worker_thread.is_none());
                    assert!(block.disk.is_some());
                    assert!(block.worker_slot.lock().expect("returned slot").is_none());
                    assert_eq!(block.lifecycle.snapshot.failure.unwrap(), historical);
                    assert!(block.validate_terminal_drain(pause.key).is_ok());
                }
                Case::ExpiredStop => {
                    let failure = outcome.unwrap_err();
                    assert_eq!(failure.key, stop.key);
                    assert_eq!(failure.fault, ProviderFault::Deadline);
                    let reap_deadline = Instant::now() + Duration::from_secs(2);
                    while transport.lifecycle_snapshot().stage != ProviderStage::Stopped {
                        assert!(
                            Instant::now() < reap_deadline,
                            "late accepted owner did not reap"
                        );
                        assert_eq!(transport.poll_stop(stop).unwrap_err(), failure);
                        std::thread::yield_now();
                    }
                    assert_eq!(transport.poll_stop(stop).unwrap_err(), failure);
                    assert!(
                        block
                            .lock()
                            .expect("late reaped owner")
                            .worker_thread
                            .is_none()
                    );
                }
                Case::SlotPoison | Case::BackendPoison | Case::InvalidEscrow | Case::IrqFailure => {
                    let failure = outcome.unwrap_err();
                    assert_eq!(failure.key, stop.key);
                    assert!(failure.accepted);
                    assert_eq!(
                        failure.fault,
                        match case {
                            Case::SlotPoison => ProviderFault::Worker,
                            Case::BackendPoison => ProviderFault::DeviceLock,
                            Case::InvalidEscrow => ProviderFault::QueueState,
                            Case::IrqFailure => ProviderFault::Notification,
                            Case::Pending
                            | Case::Quiesced
                            | Case::ExpiredStop
                            | Case::LateOldDeadline => unreachable!(),
                        }
                    );
                    assert_eq!(transport.poll_stop(stop).unwrap_err(), failure);
                }
            }
            assert_eq!(ring.used.idx.get(), 1);
            assert!(transport.capture_transport(stop.key).is_err());
            assert!(transport.capture_device_state(stop.key).is_err());
        }
    }
}
