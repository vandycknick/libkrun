#[cfg(target_os = "macos")]
use crossbeam_channel::Sender;
use std::cmp;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use utils::eventfd::{EFD_NONBLOCK, EventFd};
#[cfg(target_os = "macos")]
use utils::worker_message::WorkerMessage;
use virtio_bindings::{virtio_config::VIRTIO_F_VERSION_1, virtio_ring::VIRTIO_RING_F_EVENT_IDX};
use vm_memory::ByteValued;

use super::super::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, FsError, QueueConfig,
    RuntimeGuestMemory, VirtioDevice, VirtioShmRegion,
};
use super::ExportTable;
#[cfg(target_os = "macos")]
use super::immutable::RosettaFsConfig;
use super::passthrough;
use super::virtual_entry::VirtualDirEntry;
use super::worker::FsWorker;
use super::{defs, defs::uapi};
use crate::virtio::InterruptTransport;
use crate::virtio::passthrough::PermissionSemantics;

// Defined by Linux UAPI include/uapi/linux/virtio_fs.h and the public
// VIRTIO 1.3 specification, section 5.11.4 (Device configuration layout).
const VIRTIO_FS_TAG_LEN: usize = 36;

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct VirtioFsConfig {
    tag: [u8; VIRTIO_FS_TAG_LEN],
    num_request_queues: u32,
}

impl Default for VirtioFsConfig {
    fn default() -> Self {
        VirtioFsConfig {
            tag: [0; VIRTIO_FS_TAG_LEN],
            num_request_queues: 0,
        }
    }
}

unsafe impl ByteValued for VirtioFsConfig {}

pub struct Fs {
    avail_features: u64,
    acked_features: u64,
    device_state: DeviceState,
    config: VirtioFsConfig,
    allow_idmap: bool,
    shm_region: Option<VirtioShmRegion>,
    passthrough_cfg: Option<passthrough::Config>,
    read_only: bool,
    virtual_entries: Vec<VirtualDirEntry<'static>>,
    worker_thread: Option<JoinHandle<()>>,
    worker_stopfd: EventFd,
    exit_code: Arc<AtomicI32>,
    #[cfg(target_os = "macos")]
    map_sender: Option<Sender<WorkerMessage>>,
    #[cfg(target_os = "macos")]
    rosetta: Option<RosettaFsConfig>,
}

impl Fs {
    pub fn new(
        fs_id: String,
        semantics: PermissionSemantics,
        shared_dir: Option<String>,
        exit_code: Arc<AtomicI32>,
        read_only: bool,
        virtual_entries: Vec<VirtualDirEntry<'static>>,
    ) -> super::Result<Fs> {
        let tag_len = fs_id.len();
        if tag_len > VIRTIO_FS_TAG_LEN {
            return Err(FsError::InvalidTagLength {
                length: tag_len,
                max: VIRTIO_FS_TAG_LEN,
            });
        }

        let avail_features = (1u64 << VIRTIO_F_VERSION_1) | (1u64 << VIRTIO_RING_F_EVENT_IDX);

        let tag = fs_id.into_bytes();
        let mut config = VirtioFsConfig::default();
        config.tag[..tag.len()].copy_from_slice(tag.as_slice());
        config.num_request_queues = 1;

        let attr_timeout = if matches!(semantics, PermissionSemantics::LinuxSimplified) {
            // As uid/gid are context-dependent, attributes can't be cached.
            Duration::from_secs(0)
        } else {
            // The value defined as default in virtio-fs.
            Duration::from_secs(5)
        };

        let fs_cfg = shared_dir.map(|root_dir| passthrough::Config {
            root_dir,
            semantics,
            attr_timeout,
            ..Default::default()
        });

        let allow_idmap = matches!(semantics, PermissionSemantics::LinuxComplete);

        Ok(Fs {
            avail_features,
            acked_features: 0,
            device_state: DeviceState::Inactive,
            config,
            allow_idmap,
            shm_region: None,
            passthrough_cfg: fs_cfg,
            read_only,
            virtual_entries,
            worker_thread: None,
            worker_stopfd: EventFd::new(EFD_NONBLOCK).map_err(FsError::EventFd)?,
            exit_code,
            #[cfg(target_os = "macos")]
            map_sender: None,
            #[cfg(target_os = "macos")]
            rosetta: None,
        })
    }

    #[cfg(target_os = "macos")]
    pub fn new_rosetta(fs_id: String, config: RosettaFsConfig) -> super::Result<Fs> {
        if fs_id != "rosetta" {
            return Err(FsError::InvalidRosettaTag);
        }
        let mut fs = Self::new(
            fs_id,
            PermissionSemantics::LinuxComplete,
            None,
            Arc::new(AtomicI32::new(i32::MAX)),
            true,
            Vec::new(),
        )?;
        fs.rosetta = Some(config);
        Ok(fs)
    }

    pub fn id(&self) -> &str {
        defs::FS_DEV_ID
    }

    pub fn set_shm_region(&mut self, shm_region: VirtioShmRegion) {
        self.shm_region = Some(shm_region);
    }

    pub fn set_export_table(&mut self, export_table: ExportTable) -> u64 {
        static FS_UNIQUE_ID: AtomicU64 = AtomicU64::new(0);

        let Some(cfg) = self.passthrough_cfg.as_mut() else {
            // NullFs-backed devices have no passthrough config and don't
            // participate in cross-domain fd export. Consume (and waste) an
            // fsid so numbering stays dense, but don't store the table.
            return FS_UNIQUE_ID.fetch_add(1, Ordering::Relaxed);
        };
        cfg.export_fsid = FS_UNIQUE_ID.fetch_add(1, Ordering::Relaxed);
        cfg.export_table = Some(export_table);

        cfg.export_fsid
    }

    pub fn add_virtual_entry(&mut self, entry: VirtualDirEntry<'static>) {
        self.virtual_entries.push(entry);
    }

    pub fn set_exit_code(&mut self, exit_code: Arc<AtomicI32>) {
        self.exit_code = exit_code;
    }

    #[cfg(target_os = "macos")]
    pub fn set_map_sender(&mut self, map_sender: Sender<WorkerMessage>) {
        self.map_sender = Some(map_sender);
    }
}

impl VirtioDevice for Fs {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn device_type(&self) -> u32 {
        uapi::VIRTIO_ID_FS
    }

    fn device_name(&self) -> &str {
        "fs"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &defs::QUEUE_CONFIG
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
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "fs: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: RuntimeGuestMemory,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if self.worker_thread.is_some() {
            panic!("virtio_fs: worker thread already exists");
        }

        // Extract queues and eventfds from DeviceQueues.
        let mut worker_queues = Vec::with_capacity(queues.len());
        let mut queue_evts = Vec::with_capacity(queues.len());
        for dq in queues {
            worker_queues.push(dq.queue);
            queue_evts.push(dq.event);
        }

        let virtual_entries = self.virtual_entries.clone();
        let worker = FsWorker::new(
            worker_queues,
            queue_evts,
            interrupt.clone(),
            mem.clone(),
            self.allow_idmap,
            self.shm_region.clone(),
            self.passthrough_cfg.clone(),
            self.read_only,
            virtual_entries,
            self.worker_stopfd.try_clone().unwrap(),
            self.exit_code.clone(),
            #[cfg(target_os = "macos")]
            self.map_sender.clone(),
            #[cfg(target_os = "macos")]
            self.rosetta.clone(),
        )
        .map_err(|e| {
            error!("virtio_fs: failed to create worker: {}", e);
            ActivateError::BadActivate
        })?;
        self.worker_thread = Some(worker.run());

        self.device_state = DeviceState::Activated(mem, interrupt);
        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn shm_region(&self) -> Option<&VirtioShmRegion> {
        self.shm_region.as_ref()
    }

    fn reset(&mut self) -> bool {
        if let Some(worker) = self.worker_thread.take() {
            let _ = self.worker_stopfd.write(1);
            if let Err(e) = worker.join() {
                error!("error waiting for worker thread: {e:?}");
            }
        }
        self.device_state = DeviceState::Inactive;
        true
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicI32;

    use crate::virtio::fs::FsError;
    use crate::virtio::fs::device::{Fs, VIRTIO_FS_TAG_LEN};
    use crate::virtio::fs::virtual_entry::VirtualDirEntry;
    use crate::virtio::passthrough::PermissionSemantics;

    fn new_fs(tag: String) -> Result<Fs, FsError> {
        Fs::new(
            tag,
            PermissionSemantics::LinuxComplete,
            None,
            Arc::new(AtomicI32::new(0)),
            false,
            Vec::<VirtualDirEntry<'static>>::new(),
        )
    }

    fn tag_error(tag: String) -> FsError {
        match new_fs(tag) {
            Err(error) => error,
            Ok(_) => panic!("oversized tag was accepted"),
        }
    }

    #[test]
    fn accepts_tag_at_protocol_limit() {
        let tag = "x".repeat(VIRTIO_FS_TAG_LEN);
        let fs = new_fs(tag.clone()).unwrap();

        assert_eq!(fs.config.tag.as_slice(), tag.as_bytes());
    }

    #[test]
    fn preserves_empty_tag() {
        let fs = new_fs(String::new()).unwrap();

        assert_eq!(fs.config.tag, [0; VIRTIO_FS_TAG_LEN]);
    }

    #[test]
    fn rejects_tag_over_protocol_limit() {
        let error = tag_error("x".repeat(VIRTIO_FS_TAG_LEN + 1));

        assert!(matches!(
            error,
            FsError::InvalidTagLength {
                length: 37,
                max: VIRTIO_FS_TAG_LEN,
            }
        ));
    }

    #[test]
    fn measures_multibyte_tag_in_bytes() {
        let accepted = "é".repeat(VIRTIO_FS_TAG_LEN / 2);
        let fs = new_fs(accepted.clone()).unwrap();
        assert_eq!(fs.config.tag.as_slice(), accepted.as_bytes());

        let rejected = "é".repeat(VIRTIO_FS_TAG_LEN / 2 + 1);
        let error = tag_error(rejected);
        assert!(matches!(
            error,
            FsError::InvalidTagLength {
                length: 38,
                max: VIRTIO_FS_TAG_LEN,
            }
        ));
    }

    #[test]
    fn rejects_huge_tag_with_controlled_error() {
        let error = tag_error("x".repeat(1_000_000));

        assert!(matches!(
            error,
            FsError::InvalidTagLength {
                length: 1_000_000,
                max: VIRTIO_FS_TAG_LEN,
            }
        ));
    }
}
