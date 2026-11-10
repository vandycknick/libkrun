use std::borrow::Cow;
use std::fs::File;
use std::marker::PhantomData;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use devices::legacy::Serial;
use devices::virtio::PortDescription;
use devices::virtio::block::MAX_VMDK_FLAT_RECORDS;
use devices::virtio::generation::{DEVICE_TYPE, Generation};
use devices::virtio::{VirtioDevice, port_io};
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use polly::event_manager::{
    DispatchRole, Error as EventManagerError, EventManager, Pollable, Subscriber,
};
use utils::epoll::{EpollEvent, EventSet};
use utils::eventfd::{EFD_NONBLOCK, EventFd};

use crate::api::device_builders::{BalloonBinding, GenerationBinding};
use crate::api::live::restore::*;
use crate::api::vmm_builder::{Vmm, VmmBuilder, VmmInner};
use crate::vmm::builder::restore::build_restore_prepared;
use crate::vmm::control::ControlState;
use crate::vmm::execution::device_restore::{
    DeviceEnvelope, PreparedDeviceInstall, RestoreDeviceBinding, ValidatedDevices,
};
use crate::vmm::execution::{ExecutionEnvelope, MAX_EXECUTION_BYTES, ValidatedExecution};
use crate::vmm::memory::image::{AuthenticatedRamImage, map_restore_ram};

pub(crate) const MAX_DEVICES_BYTES: usize = 32 * 1024 * 1024;
type Inode = (u64, u64);

fn descriptor(role: RestoreRole, problem: RestoreProblem) -> RestoreError {
    RestoreError::Descriptor { role, problem }
}
fn io(role: RestoreRole, source: std::io::Error) -> RestoreError {
    RestoreError::Io { role, source }
}
fn native(stage: RestoreStage, cause: impl ToString) -> RestoreError {
    RestoreError::Native {
        stage,
        cause: cause.to_string(),
    }
}
fn refusal<'a>(reason: RestoreError) -> RestoreBuildFailure<'a> {
    RestoreBuildFailure {
        reason,
        failed: None,
    }
}

fn flags(fd: impl AsFd, role: RestoreRole) -> Result<OFlag, RestoreError> {
    let close = fcntl(fd.as_fd(), FcntlArg::F_GETFD).map_err(|error| io(role, error.into()))?;
    if !FdFlag::from_bits_truncate(close).contains(FdFlag::FD_CLOEXEC) {
        return Err(descriptor(role, RestoreProblem::CloseOnExec));
    }
    fcntl(fd.as_fd(), FcntlArg::F_GETFL)
        .map(OFlag::from_bits_truncate)
        .map_err(|error| io(role, error.into()))
}
pub(crate) fn inspect(
    file: &File,
    role: RestoreRole,
    writable: bool,
) -> Result<Inode, RestoreError> {
    let flags = flags(file, role)?;
    let expected = if writable {
        OFlag::O_RDWR
    } else {
        OFlag::O_RDONLY
    };
    if flags & OFlag::O_ACCMODE != expected || flags.contains(OFlag::O_APPEND) {
        return Err(descriptor(role, RestoreProblem::Access));
    }
    #[cfg(target_os = "linux")]
    if flags.contains(OFlag::O_PATH) {
        return Err(descriptor(role, RestoreProblem::Access));
    }
    let metadata = file.metadata().map_err(|error| io(role, error))?;
    if !metadata.is_file() {
        return Err(descriptor(role, RestoreProblem::NotRegular));
    }
    Ok((metadata.dev(), metadata.ino()))
}
fn distinct(inodes: &mut Vec<Inode>, inode: Inode, role: RestoreRole) -> Result<(), RestoreError> {
    if inodes.contains(&inode) {
        return Err(descriptor(role, RestoreProblem::Alias));
    }
    inodes.push(inode);
    Ok(())
}
pub(crate) fn read_object(
    file: &File,
    role: RestoreRole,
    expected: &StateObjectIdentity,
    limit: usize,
) -> Result<Vec<u8>, RestoreError> {
    let length = file.metadata().map_err(|error| io(role, error))?.len();
    if length != expected.length || length == 0 || length > limit as u64 {
        return Err(descriptor(role, RestoreProblem::Length));
    }
    let mut bytes = vec![0; length as usize];
    file.read_exact_at(&mut bytes, 0)
        .map_err(|error| io(role, error))?;
    if sha256(&bytes) != expected.sha256 {
        return Err(descriptor(role, RestoreProblem::Digest));
    }
    Ok(bytes)
}

#[allow(clippy::unnecessary_cast)]
fn socket_inode(stat: &nix::sys::stat::FileStat) -> Inode {
    // dev_t and ino_t have different widths on the admitted host platforms.
    (stat.st_dev as u64, stat.st_ino as u64)
}

fn preflight(inputs: &RestoreInputs, resources: &RestoreResources) -> Result<(), RestoreError> {
    let mut inodes = Vec::with_capacity(260);
    for (role, file) in [
        (RestoreRole::Ram, &inputs.ram),
        (RestoreRole::Layout, &inputs.layout),
        (RestoreRole::Execution, &inputs.execution),
        (RestoreRole::Devices, &inputs.devices),
    ] {
        distinct(&mut inodes, inspect(file, role, false)?, role)?;
    }
    let counts = [
        resources.blocks.len(),
        resources.networks.len(),
        resources.vsocks.len(),
        resources.consoles.len(),
    ];
    if counts.into_iter().any(|count| count > 256)
        || counts.into_iter().sum::<usize>() > 256
        || resources.serial.len() > 64
        || resources.consoles.iter().any(|console| {
            console.ports.len() > 256 || console.ports.iter().any(|port| port.name.len() > 256)
        })
    {
        return Err(RestoreError::Refused(RestoreProblem::Inventory));
    }
    // Repeated read-only extents are legitimate (split and repeated layers,
    // ADR 0014), so they stay out of the exclusive set and are checked against
    // it once every exclusive role is known.
    let mut extents: Vec<Inode> = Vec::new();
    for block in &resources.blocks {
        match &block.backing {
            RestoreBlockBacking::Raw { file, read_only } => distinct(
                &mut inodes,
                inspect(file, RestoreRole::Block, !read_only)?,
                RestoreRole::Block,
            )?,
            RestoreBlockBacking::ReadonlyVmdk(closure) => {
                preflight_vmdk(closure, &mut inodes, &mut extents)?
            }
        }
    }
    for net in &resources.networks {
        flags(&net.socket, RestoreRole::Network)?;
        let stat = nix::sys::stat::fstat(&net.socket)
            .map_err(|error| io(RestoreRole::Network, error.into()))?;
        distinct(&mut inodes, socket_inode(&stat), RestoreRole::Network)?;
    }
    for vsock in &resources.vsocks {
        flags(&vsock.mux, RestoreRole::Vsock)?;
        let stat = nix::sys::stat::fstat(&vsock.mux)
            .map_err(|error| io(RestoreRole::Vsock, error.into()))?;
        distinct(&mut inodes, socket_inode(&stat), RestoreRole::Vsock)?;
    }
    for (role, input, output) in resources
        .consoles
        .iter()
        .flat_map(|console| console.ports.iter())
        .map(|port| (RestoreRole::Console, &port.input, &port.output))
        .chain(
            resources
                .serial
                .iter()
                .map(|serial| (RestoreRole::Serial, &serial.input, &serial.output)),
        )
    {
        let mut endpoint = Vec::with_capacity(2);
        for (file, is_output) in [(input, false), (output, true)] {
            let Some(file) = file else { continue };
            let status = flags(file, role)?;
            #[cfg(target_os = "linux")]
            if status.contains(OFlag::O_PATH) {
                return Err(descriptor(role, RestoreProblem::Access));
            }
            let access = status & OFlag::O_ACCMODE;
            if (is_output && access == OFlag::O_RDONLY) || (!is_output && access == OFlag::O_WRONLY)
            {
                return Err(descriptor(role, RestoreProblem::Access));
            }
            let metadata = file.metadata().map_err(|error| io(role, error))?;
            let inode = (metadata.dev(), metadata.ino());
            if inodes.contains(&inode) {
                return Err(descriptor(role, RestoreProblem::Alias));
            }
            if !endpoint.contains(&inode) {
                endpoint.push(inode);
            }
        }
        inodes.extend(endpoint);
    }
    if extents.iter().any(|extent| inodes.contains(extent)) {
        return Err(descriptor(RestoreRole::VmdkExtent, RestoreProblem::Alias));
    }
    Ok(())
}

fn preflight_vmdk(
    closure: &ReadonlyVmdk,
    inodes: &mut Vec<Inode>,
    extents: &mut Vec<Inode>,
) -> Result<(), RestoreError> {
    if closure.extents.is_empty() {
        return Err(descriptor(RestoreRole::VmdkExtent, RestoreProblem::Closure));
    }
    if closure.extents.len() > MAX_VMDK_FLAT_RECORDS.saturating_sub(extents.len()) {
        return Err(RestoreError::Refused(RestoreProblem::Inventory));
    }
    distinct(
        inodes,
        inspect(&closure.descriptor, RestoreRole::VmdkDescriptor, false)?,
        RestoreRole::VmdkDescriptor,
    )?;
    let mut held = Vec::with_capacity(closure.extents.len());
    for extent in &closure.extents {
        let inode = inspect(&extent.file, RestoreRole::VmdkExtent, false)?;
        // Cold attach reads extents through buffered read-only opens.
        #[cfg(target_os = "linux")]
        if flags(&extent.file, RestoreRole::VmdkExtent)?.contains(OFlag::O_DIRECT) {
            return Err(descriptor(RestoreRole::VmdkExtent, RestoreProblem::Access));
        }
        // One path per held inode: a second spelling is not a repeat.
        distinct(&mut held, inode, RestoreRole::VmdkExtent)?;
    }
    extents.extend(held);
    Ok(())
}

#[cfg(feature = "blk")]
fn block_binding(error: devices::virtio::block::RestoreBindingError) -> RestoreError {
    use devices::virtio::block::RestoreBindingError as Binding;
    use devices::virtio::block::vmdk::VmdkClosureFault as Fault;
    match error {
        Binding::Payload => RestoreError::Codec(utils::state::Error::Invalid("block payload")),
        Binding::Format => descriptor(RestoreRole::Block, RestoreProblem::Format),
        Binding::Binding => RestoreError::Refused(RestoreProblem::Topology),
        Binding::Io(source) => io(RestoreRole::Block, source),
        Binding::Closure(fault) => {
            let (role, problem) = match fault {
                Fault::DescriptorLength => (RestoreRole::VmdkDescriptor, RestoreProblem::Length),
                Fault::DescriptorGrammar | Fault::RecordLimit | Fault::Reader => {
                    (RestoreRole::VmdkDescriptor, RestoreProblem::Closure)
                }
                Fault::UndeclaredExtent | Fault::UnreferencedExtent | Fault::DuplicateExtent => {
                    (RestoreRole::VmdkExtent, RestoreProblem::Closure)
                }
                Fault::ExtentRange => (RestoreRole::VmdkExtent, RestoreProblem::Length),
                Fault::ExtentAccess => (RestoreRole::VmdkExtent, RestoreProblem::Access),
            };
            descriptor(role, problem)
        }
    }
}

fn matches(
    attachment: &RestoreAttachment,
    record: &crate::vmm::execution::device_restore::DeviceRecord,
) -> bool {
    attachment.configured_id == record.identity.configured_id
        && attachment.address == record.identity.address
        && attachment.irq == record.identity.irq
}
fn validate_bindings<T>(
    items: &[T],
    records: &[crate::vmm::execution::device_restore::DeviceRecord],
    kind: u32,
    attachment: impl Fn(&T) -> &RestoreAttachment,
) -> Result<(), RestoreError> {
    if items.len()
        != records
            .iter()
            .filter(|record| record.state.device_type == kind)
            .count()
    {
        return Err(RestoreError::Refused(RestoreProblem::Inventory));
    }
    for record in records
        .iter()
        .filter(|record| record.state.device_type == kind)
    {
        if items
            .iter()
            .filter(|item| matches(attachment(item), record))
            .count()
            != 1
        {
            return Err(RestoreError::Refused(RestoreProblem::Inventory));
        }
    }
    Ok(())
}

fn take_binding<T>(
    items: &mut Vec<T>,
    record: &crate::vmm::execution::device_restore::DeviceRecord,
    attachment: impl Fn(&T) -> &RestoreAttachment,
) -> Result<T, RestoreError> {
    let mut indices = items
        .iter()
        .enumerate()
        .filter(|(_, item)| matches(attachment(item), record))
        .map(|(index, _)| index);
    let index = indices
        .next()
        .ok_or(RestoreError::Refused(RestoreProblem::Inventory))?;
    if indices.next().is_some() {
        return Err(RestoreError::Refused(RestoreProblem::Inventory));
    }
    Ok(items.remove(index))
}

pub(crate) fn validate_profile(
    records: &[crate::vmm::execution::device_restore::DeviceRecord],
) -> Result<(), RestoreError> {
    if records
        .iter()
        .filter(|record| record.state.device_type == DEVICE_TYPE)
        .count()
        != 1
    {
        return Err(RestoreError::Refused(RestoreProblem::Generation));
    }
    for record in records {
        match record.state.device_type {
            1 if cfg!(feature = "net") => {}
            2 if cfg!(feature = "blk") => {}
            3 | 4 | 5 | 19 => {}
            DEVICE_TYPE => {
                if !record.state.activated {
                    return Err(RestoreError::Refused(RestoreProblem::Generation));
                }
                Generation::validate_live_restore_payload(&record.payload)
                    .map_err(|_| RestoreError::Refused(RestoreProblem::Generation))?;
            }
            _ => return Err(RestoreError::Refused(RestoreProblem::Inventory)),
        }
    }
    Ok(())
}

fn reconstruct(
    validated: ValidatedDevices,
    saved: &ExecutionEnvelope,
    mut resources: RestoreResources,
) -> Result<(PreparedDeviceInstall, Vec<File>), RestoreError> {
    let envelope = validated.into_envelope();
    let records = &envelope.records;
    validate_bindings(&resources.blocks, records, 2, |item| &item.attachment)?;
    validate_bindings(&resources.networks, records, 1, |item| &item.attachment)?;
    validate_bindings(&resources.vsocks, records, 19, |item| &item.attachment)?;
    validate_bindings(&resources.consoles, records, 3, |item| &item.attachment)?;
    validate_profile(records)?;
    for (index, endpoint) in resources.serial.iter().enumerate() {
        if resources.serial[..index]
            .iter()
            .any(|previous| previous.address == endpoint.address)
        {
            return Err(RestoreError::Refused(RestoreProblem::Inventory));
        }
        let shape = saved.legacy.iter().find_map(|legacy| {
            if legacy.address != endpoint.address {
                return None;
            }
            match &legacy.payload {
                devices::legacy::state::LegacyPayload::Uart(state) => {
                    Some((state.has_input, state.has_output))
                }
                devices::legacy::state::LegacyPayload::Pl011(state) => {
                    Some((state.has_input, state.has_output))
                }
                _ => None,
            }
        });
        if shape != Some((endpoint.input.is_some(), endpoint.output.is_some())) {
            return Err(RestoreError::Refused(RestoreProblem::Inventory));
        }
    }
    for legacy in &saved.legacy {
        let connected = match &legacy.payload {
            devices::legacy::state::LegacyPayload::Uart(state) => {
                state.has_input || state.has_output
            }
            devices::legacy::state::LegacyPayload::Pl011(state) => {
                state.has_input || state.has_output
            }
            _ => false,
        };
        if connected
            && !resources
                .serial
                .iter()
                .any(|endpoint| endpoint.address == legacy.address)
        {
            return Err(RestoreError::Refused(RestoreProblem::Inventory));
        }
    }
    let mut bindings = Vec::with_capacity(envelope.records.len());
    let mut balloons = Vec::new();
    let mut retained = Vec::new();
    for record in envelope.records {
        let mut subscriber = None;
        let mut generation_binding = None;
        let resource: Arc<Mutex<dyn VirtioDevice>> = match record.state.device_type {
            #[cfg(feature = "blk")]
            2 => {
                let block = take_binding(&mut resources.blocks, &record, |item| &item.attachment)?;
                Arc::new(Mutex::new(
                    devices::virtio::Block::new_restore_binding(
                        block.attachment.configured_id,
                        block.backing,
                        &record.payload,
                    )
                    .map_err(block_binding)?,
                ))
            }
            #[cfg(feature = "net")]
            1 => {
                let net = take_binding(&mut resources.networks, &record, |item| &item.attachment)?;
                let features = u32::try_from(record.state.avail_features & !(1 << 32))
                    .map_err(|_| RestoreError::Refused(RestoreProblem::Inventory))?;
                Arc::new(Mutex::new(
                    devices::virtio::Net::new_restore_binding(
                        net.attachment.configured_id,
                        net.socket.into(),
                        net.mac,
                        features,
                    )
                    .map_err(|error| {
                        native(RestoreStage::Reconstruction, format!("network: {error:?}"))
                    })?,
                ))
            }
            19 => {
                let vsock = take_binding(&mut resources.vsocks, &record, |item| &item.attachment)?;
                let mut device = devices::virtio::Vsock::new(
                    vsock.cid,
                    None,
                    None,
                    devices::virtio::vsock::TsiFlags::empty(),
                )
                .map_err(|error| {
                    native(RestoreStage::Reconstruction, format!("vsock: {error:?}"))
                })?;
                device
                    .set_unix_mux_fd(vsock.mux)
                    .map_err(|error| io(RestoreRole::Vsock, error))?;
                device
                    .bind_restore_control_service(vsock.agent_port.get())
                    .map_err(|error| {
                        native(
                            RestoreStage::Reconstruction,
                            format!("vsock control: {error:?}"),
                        )
                    })?;
                let device = Arc::new(Mutex::new(device));
                subscriber =
                    Some(device.clone() as Arc<Mutex<dyn polly::event_manager::Subscriber + Send>>);
                device
            }
            3 => {
                let console =
                    take_binding(&mut resources.consoles, &record, |item| &item.attachment)?;
                let mut ports = Vec::with_capacity(console.ports.len());
                for port in console.ports {
                    let input = port
                        .input
                        .as_ref()
                        .map(|file| port_io::input_to_raw_fd_dup(file.as_raw_fd()))
                        .transpose()
                        .map_err(|error| io(RestoreRole::Console, error.into()))?;
                    let output = port
                        .output
                        .as_ref()
                        .map(|file| port_io::output_to_raw_fd_dup(file.as_raw_fd()))
                        .transpose()
                        .map_err(|error| io(RestoreRole::Console, error.into()))?;
                    let terminal: Option<Box<dyn port_io::PortTerminalProperties>> =
                        if port.terminal {
                            let file = port
                                .input
                                .as_ref()
                                .or(port.output.as_ref())
                                .ok_or(RestoreError::Refused(RestoreProblem::Inventory))?;
                            Some(
                                port_io::term_fd(file.as_raw_fd())
                                    .map_err(|error| io(RestoreRole::Console, error.into()))?,
                            )
                        } else {
                            None
                        };
                    ports.push(PortDescription {
                        name: Cow::Owned(port.name),
                        input,
                        output,
                        terminal,
                    });
                    retained.extend(port.input);
                    retained.extend(port.output);
                }
                let device = Arc::new(Mutex::new(devices::virtio::Console::new(ports).map_err(
                    |error| native(RestoreStage::Reconstruction, format!("console: {error:?}")),
                )?));
                subscriber =
                    Some(device.clone() as Arc<Mutex<dyn polly::event_manager::Subscriber + Send>>);
                device
            }
            4 => {
                let device = Arc::new(Mutex::new(devices::virtio::Rng::new().map_err(
                    |error| native(RestoreStage::Reconstruction, format!("RNG: {error:?}")),
                )?));
                subscriber =
                    Some(device.clone() as Arc<Mutex<dyn polly::event_manager::Subscriber + Send>>);
                device
            }
            5 => {
                let device = Arc::new(Mutex::new(
                    devices::virtio::Balloon::new_restore_binding(record.state.avail_features)
                        .map_err(|error| {
                            native(RestoreStage::Reconstruction, format!("balloon: {error:?}"))
                        })?,
                ));
                balloons.push(BalloonBinding::new(device.clone()));
                subscriber =
                    Some(device.clone() as Arc<Mutex<dyn polly::event_manager::Subscriber + Send>>);
                device
            }
            DEVICE_TYPE => {
                let device = Arc::new(Mutex::new(Generation::new()));
                generation_binding = Some(GenerationBinding::new(device.clone()));
                device
            }
            _ => return Err(RestoreError::Refused(RestoreProblem::Inventory)),
        };
        bindings.push(RestoreDeviceBinding {
            identity: record.identity,
            state: record.state,
            payload: record.payload,
            resource,
            subscriber,
            generation_binding,
        });
    }
    let mut serial = Vec::with_capacity(resources.serial.len());
    for endpoint in resources.serial {
        let input = endpoint
            .input
            .map(|file| Box::new(file) as Box<dyn devices::legacy::ReadableFd + Send>);
        let output = endpoint
            .output
            .map(|file| Box::new(file) as Box<dyn std::io::Write + Send>);
        let event = EventFd::new(EFD_NONBLOCK).map_err(|error| io(RestoreRole::Serial, error))?;
        serial.push((
            endpoint.address,
            Arc::new(Mutex::new(Serial::new(event, output, input))),
        ));
    }
    let shutdown = if saved.legacy.iter().any(|legacy| {
        matches!(
            legacy.payload,
            devices::legacy::state::LegacyPayload::Gpio(_)
        )
    }) {
        Some(EventFd::new(EFD_NONBLOCK).map_err(|error| io(RestoreRole::Serial, error))?)
    } else {
        None
    };
    let mut prepared =
        PreparedDeviceInstall::validate(envelope.binding, bindings, serial, shutdown)
            .map_err(|error| native(RestoreStage::Reconstruction, error))?;
    prepared.balloon_bindings = balloons;
    Ok((prepared, retained))
}

impl<'a> VmmBuilder<'a> {
    pub fn build_restored(
        self,
        inputs: RestoreInputs,
        resources: RestoreResources,
        deadline: Instant,
    ) -> Result<(Vmm<'a>, RestoreToken), RestoreBuildFailure<'a>> {
        if self.payload.is_some()
            || self.device_manager.is_some()
            || self.nested_virt
            || self.split_irqchip
            || self.kernel_console.is_some()
            || !self.smbios_oem_strings.is_empty()
            || self.shutdown_support
            || !self.serial_consoles.is_empty()
        {
            return Err(refusal(RestoreError::Refused(
                RestoreProblem::ColdConfiguration,
            )));
        }
        if Instant::now() >= deadline {
            return Err(refusal(RestoreError::Refused(RestoreProblem::Deadline)));
        }
        preflight(&inputs, &resources).map_err(refusal)?;
        if inputs.expected.binding != inputs.expected.ram_image.state
            || inputs.expected.ram_image.stream == [0; 32]
        {
            return Err(refusal(RestoreError::Refused(RestoreProblem::Topology)));
        }
        let bytes = read_object(
            &inputs.execution,
            RestoreRole::Execution,
            &inputs.expected.execution_object,
            MAX_EXECUTION_BYTES,
        )
        .map_err(refusal)?;
        let envelope = ExecutionEnvelope::decode(&bytes)
            .map_err(RestoreError::from)
            .map_err(refusal)?;
        let lane = crate::api::live::inspection::native_lane();
        let execution = ValidatedExecution::validate(envelope, &inputs.expected.binding, lane)
            .map_err(RestoreError::from)
            .map_err(refusal)?;
        let saved = execution.envelope();
        crate::api::live::inspection::validate_execution_profile(&execution)
            .map_err(|error| refusal(native(RestoreStage::Validation, error)))?;
        let ram_length = saved
            .memory_regions
            .iter()
            .try_fold(0u64, |length, region| length.checked_add(region.byte_len()))
            .ok_or_else(|| refusal(RestoreError::Refused(RestoreProblem::Topology)))?;
        if self
            .vcpus
            .is_some_and(|count| usize::from(count) != saved.cpus.len())
            || self
                .ram_mib
                .is_some_and(|mib| u64::from(mib) * 1024 * 1024 != ram_length)
        {
            return Err(refusal(RestoreError::Refused(RestoreProblem::Topology)));
        }
        let bytes = read_object(
            &inputs.devices,
            RestoreRole::Devices,
            &inputs.expected.devices_object,
            MAX_DEVICES_BYTES,
        )
        .map_err(refusal)?;
        let devices = ValidatedDevices::validate(
            DeviceEnvelope::decode(&bytes)
                .map_err(RestoreError::from)
                .map_err(refusal)?,
            saved,
        )
        .map_err(RestoreError::from)
        .map_err(refusal)?;
        let image = Arc::new(
            AuthenticatedRamImage::for_restore(
                inputs.ram,
                inputs.layout,
                inputs.expected.ram_image,
                &execution,
            )
            .map_err(RestoreError::from)
            .map_err(refusal)?,
        );
        let ram = map_restore_ram(image, &execution)
            .map_err(RestoreError::from)
            .map_err(refusal)?;
        let (devices, mut retained) = reconstruct(devices, saved, resources).map_err(refusal)?;
        retained.push(inputs.execution);
        retained.push(inputs.devices);
        let mut events = EventManager::new().map_err(|error| {
            refusal(native(
                RestoreStage::DispatchRegistration,
                format!("{error:?}"),
            ))
        })?;
        let inner = match build_restore_prepared(ram, execution, devices, &mut events, deadline) {
            Ok(inner) => inner,
            Err(failure) => {
                let failed = failure
                    .attempt
                    .map(|attempt| wrap(*attempt, events, retained).retain_failed_restore());
                return Err(RestoreBuildFailure {
                    reason: native(RestoreStage::NativeInstall, failure.error),
                    failed,
                });
            }
        };
        let mut vm = wrap(inner, events, retained);
        let VmmInner::Vmm {
            vmm, event_manager, ..
        } = &mut vm.inner;
        let setup = (|| {
            let (control, exit) = {
                let inner = vmm
                    .lock()
                    .map_err(|_| native(RestoreStage::DispatchRegistration, "VMM lock"))?;
                (
                    inner.control.receiver.as_raw_fd(),
                    inner.exit_evt.as_raw_fd(),
                )
            };
            register_owner_roles(event_manager, vmm.clone(), control, exit).map_err(|error| {
                native(RestoreStage::DispatchRegistration, format!("{error:?}"))
            })?;
            vmm.lock()
                .map_err(|_| native(RestoreStage::DispatchRegistration, "VMM lock"))?
                .control
                .restore_token()
                .map_err(RestoreError::Control)
        })();
        match setup {
            Ok(token) => Ok((vm, token)),
            Err(reason) => Err(RestoreBuildFailure {
                reason,
                failed: Some(vm.retain_failed_restore()),
            }),
        }
    }
}

impl<'a> Vmm<'a> {
    /// Retain the complete prepared owner when callback or handle setup fails.
    pub fn retain_failed_restore(self) -> FailedRestore<'a> {
        FailedRestore {
            vm: Some(Box::new(self)),
            cleanup: RestoreCleanup::default(),
        }
    }
}

/// Restore parks the ingress fence before the owner exists, and role changes
/// are refused under a fence, so the owner registers directly with its
/// fence-exempt roles instead of the cold path's register-then-retag.
fn register_owner_roles(
    events: &mut EventManager,
    owner: Arc<Mutex<dyn Subscriber>>,
    control: Pollable,
    exit: Pollable,
) -> Result<(), EventManagerError> {
    for (pollable, role) in [(control, DispatchRole::Control), (exit, DispatchRole::Exit)] {
        events.register_with_role(
            pollable,
            EpollEvent::new(EventSet::IN, pollable as u64),
            owner.clone(),
            role,
        )?;
    }
    Ok(())
}

fn wrap<'a>(inner: crate::vmm::Vmm, event_manager: EventManager, retained: Vec<File>) -> Vmm<'a> {
    let (sender, _) = crossbeam_channel::unbounded();
    Vmm {
        inner: VmmInner::Vmm {
            vmm: Arc::new(Mutex::new(inner)),
            event_manager,
            _worker_sender: sender,
            #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
            shutdown_efd: None,
        },
        _lifetime: PhantomData,
        _restore_files: retained,
    }
}

pub(crate) fn cleanup(vm: &mut Vmm<'_>, cleanup: &mut RestoreCleanup, deadline: Instant) -> bool {
    let VmmInner::Vmm {
        vmm, event_manager, ..
    } = &mut vm.inner;
    let client = match vmm.lock() {
        Ok(inner) if inner.control.state == ControlState::Stopped => return true,
        Ok(inner) => inner.control.client.clone(),
        Err(_) => return false,
    };
    if Instant::now() >= deadline {
        return false;
    }
    if cleanup.ensure_started(&client, deadline).is_err() {
        return false;
    }
    while Instant::now() < deadline {
        // Dispatch remains fenced, but owner/control completion roles still run.
        if event_manager.run_with_timeout(1).is_err() {
            return false;
        }
        match vmm.lock() {
            Ok(mut inner) => {
                inner.service_control(event_manager);
                if inner.control.state == ControlState::Stopped {
                    return true;
                }
            }
            Err(_) => return false,
        }
    }
    false
}

pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let padded = (bytes.len() + 9).div_ceil(64) * 64;
    for block in 0..padded / 64 {
        let mut chunk = [0u8; 64];
        for (index, byte) in chunk.iter_mut().enumerate() {
            let offset = block * 64 + index;
            *byte = if offset < bytes.len() {
                bytes[offset]
            } else if offset == bytes.len() {
                0x80
            } else if offset >= padded - 8 {
                ((bytes.len() as u64 * 8) >> ((padded - 1 - offset) * 8)) as u8
            } else {
                0
            };
        }
        let mut words = [0u32; 64];
        for (word, bytes) in words.iter_mut().zip(chunk.chunks_exact(4)) {
            *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for index in 16..64 {
            let x = words[index - 15];
            let y = words[index - 2];
            let s0 = x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3);
            let s1 = y.rotate_right(17) ^ y.rotate_right(19) ^ (y >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let t2 = s0.wrapping_add((a & b) ^ (a & c) ^ (b & c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (word, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *word = word.wrapping_add(value);
        }
    }
    let mut digest = [0; 32];
    for (output, word) in digest.chunks_exact_mut(4).zip(state) {
        output.copy_from_slice(&word.to_be_bytes());
    }
    digest
}

#[cfg(test)]
mod tests {
    use crate::api::live::restore::*;
    #[cfg(feature = "blk")]
    use crate::api::vmm_builder::restored::block_binding;
    use crate::api::vmm_builder::restored::{
        distinct, inspect, preflight, read_object, register_owner_roles, sha256, take_binding,
        validate_bindings, validate_profile,
    };
    use crate::vmm::device_manager::quiescence::AttachmentIdentity;
    use crate::vmm::execution::device_restore::{DeviceEnvelope, DeviceRecord};
    use devices::virtio::{MmioTransportState, VirtioDevice};
    use polly::event_manager::{
        BarrierGeneration, BarrierKey, BarrierRequest, DispatchPhase, DispatchRole,
        Error as EventManagerError, EventManager, OperationId, Subscriber,
    };
    use std::fs::File;
    use std::io::Write;
    use std::os::fd::{AsFd, AsRawFd, RawFd};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use utils::epoll::{EpollEvent, EventSet};
    use utils::eventfd::{EFD_NONBLOCK, EventFd};
    use utils::tempfile::TempFile;

    struct Owner {
        control: EventFd,
        exit: EventFd,
        dispatched: Vec<RawFd>,
    }

    impl Owner {
        fn new() -> Arc<Mutex<Self>> {
            Arc::new(Mutex::new(Owner {
                control: EventFd::new(EFD_NONBLOCK).unwrap(),
                exit: EventFd::new(EFD_NONBLOCK).unwrap(),
                dispatched: Vec::new(),
            }))
        }
    }

    impl Subscriber for Owner {
        fn process(&mut self, event: &EpollEvent, _: &mut EventManager) {
            let source = event.fd();
            if source == self.control.as_raw_fd() {
                self.control.read().unwrap();
            } else {
                self.exit.read().unwrap();
            }
            self.dispatched.push(source);
        }

        fn interest_list(&self) -> Vec<EpollEvent> {
            Vec::new()
        }
    }

    fn file(bytes: &[u8]) -> TempFile {
        let file = TempFile::new().unwrap();
        let mut output = file.as_file();
        output.write_all(bytes).unwrap();
        file
    }

    fn record() -> DeviceRecord {
        let rng = devices::virtio::Rng::new().unwrap();
        DeviceRecord {
            identity: AttachmentIdentity {
                device_type: devices::DeviceType::Virtio(4),
                configured_id: "rng0".into(),
                address: 0xd0000000,
                irq: 5,
            },
            state: MmioTransportState {
                device_type: 4,
                device_name: rng.device_name().into(),
                attachment_address: 0xd0000000,
                irq_line: Some(5),
                avail_features: rng.avail_features(),
                acked_features: 0,
                features_select: 0,
                acked_features_select: 0,
                queue_select: 0,
                device_status: 0,
                config_generation: 0,
                shm_region_select: 0,
                interrupt_status: 0,
                activated: false,
                queues: Vec::new(),
            },
            payload: Vec::new(),
        }
    }

    fn inputs(files: &[TempFile; 4]) -> RestoreInputs {
        let binding = crate::api::live::StateBinding {
            live_state_schema: crate::api::capabilities::LIVE_STATE_SCHEMA.into(),
            architecture: crate::api::capabilities::guest_architecture().into(),
            profile: [2; 32],
            topology: [3; 32],
            ram_layout: [4; 32],
            source_run: [5; 16],
            pause_generation: 1,
            capture: [6; 16],
        };
        RestoreInputs {
            ram: File::open(files[0].as_path()).unwrap(),
            layout: File::open(files[1].as_path()).unwrap(),
            execution: File::open(files[2].as_path()).unwrap(),
            devices: File::open(files[3].as_path()).unwrap(),
            expected: RestoreIdentity {
                ram_image: crate::api::live::RamImageAuthentication {
                    state: binding.clone(),
                    stream: [7; 32],
                },
                binding,
                execution_object: StateObjectIdentity {
                    length: 3,
                    sha256: sha256(b"bad"),
                },
                devices_object: StateObjectIdentity {
                    length: 3,
                    sha256: sha256(b"bad"),
                },
            },
        }
    }

    #[test]
    fn complete_state_set_and_attached_backings_are_validated_before_native_effects() {
        let files = [file(b"ram"), file(b"layout"), file(b"bad"), file(b"bad")];
        let mut restore = inputs(&files);
        assert!(preflight(&restore, &RestoreResources::default()).is_ok());
        restore.devices = restore.execution.try_clone().unwrap();
        assert!(matches!(
            preflight(&restore, &RestoreResources::default()),
            Err(RestoreError::Descriptor {
                problem: RestoreProblem::Alias,
                ..
            })
        ));
        let restore = inputs(&files);
        let resources = RestoreResources {
            blocks: vec![RestoreBlock::raw(
                RestoreAttachment {
                    configured_id: "root".into(),
                    address: 0xd0000000,
                    irq: 5,
                },
                restore.ram.try_clone().unwrap(),
                true,
            )],
            ..RestoreResources::default()
        };
        assert!(matches!(
            preflight(&restore, &resources),
            Err(RestoreError::Descriptor {
                role: RestoreRole::Block,
                problem: RestoreProblem::Alias
            })
        ));
        let failure = crate::api::vmm_builder::VmmBuilder::new()
            .build_restored(
                inputs(&files),
                RestoreResources::default(),
                std::time::Instant::now() + std::time::Duration::from_secs(1),
            )
            .err()
            .expect("malformed state must refuse before constructing a VM");
        assert!(matches!(failure.reason, RestoreError::Codec(_)));
        assert!(failure.failed.is_none());
    }

    fn lower(descriptor: File, extents: Vec<VmdkExtent>) -> RestoreBlock {
        RestoreBlock::readonly_vmdk(
            RestoreAttachment {
                configured_id: "silo-root-lower".into(),
                address: 0xd0000000,
                irq: 5,
            },
            descriptor,
            extents,
        )
    }

    fn held(path: &str, backing: &TempFile) -> VmdkExtent {
        VmdkExtent {
            path: path.into(),
            file: File::open(backing.as_path()).unwrap(),
        }
    }

    fn refusal(
        resources: RestoreResources,
        files: &[TempFile; 4],
    ) -> (RestoreRole, RestoreProblem) {
        match preflight(&inputs(files), &resources) {
            Err(RestoreError::Descriptor { role, problem }) => (role, problem),
            other => panic!("expected descriptor refusal, got {other:?}"),
        }
    }

    #[test]
    fn vmdk_preflight_admits_repeated_readonly_extents_and_rejects_aliases_and_access() {
        let files = [file(b"ram"), file(b"layout"), file(b"bad"), file(b"bad")];
        let descriptor = file(b"descriptor");
        let other_descriptor = file(b"descriptor");
        let first = file(b"first");
        let second = file(b"second");
        let only = |blocks| RestoreResources {
            blocks,
            ..RestoreResources::default()
        };

        // The same immutable extent may back several read-only closures.
        preflight(
            &inputs(&files),
            &only(vec![
                lower(
                    File::open(descriptor.as_path()).unwrap(),
                    vec![held("/pool/first", &first), held("/pool/second", &second)],
                ),
                lower(
                    File::open(other_descriptor.as_path()).unwrap(),
                    vec![held("/pool/first", &first)],
                ),
            ]),
        )
        .unwrap();

        let cases: Vec<(&str, Vec<RestoreBlock>, (RestoreRole, RestoreProblem))> = vec![
            (
                "one inode under two paths",
                vec![lower(
                    File::open(descriptor.as_path()).unwrap(),
                    vec![held("/pool/a", &first), held("/pool/b", &first)],
                )],
                (RestoreRole::VmdkExtent, RestoreProblem::Alias),
            ),
            (
                "extent aliases a writable raw disk",
                vec![
                    RestoreBlock::raw(
                        RestoreAttachment {
                            configured_id: "silo-root-upper".into(),
                            address: 0xd0001000,
                            irq: 6,
                        },
                        File::options()
                            .read(true)
                            .write(true)
                            .open(first.as_path())
                            .unwrap(),
                        false,
                    ),
                    lower(
                        File::open(descriptor.as_path()).unwrap(),
                        vec![held("/pool/first", &first)],
                    ),
                ],
                (RestoreRole::VmdkExtent, RestoreProblem::Alias),
            ),
            (
                "extent aliases its descriptor",
                vec![lower(
                    File::open(first.as_path()).unwrap(),
                    vec![held("/pool/first", &first)],
                )],
                (RestoreRole::VmdkExtent, RestoreProblem::Alias),
            ),
            (
                "descriptor shared by two closures",
                vec![
                    lower(
                        File::open(descriptor.as_path()).unwrap(),
                        vec![held("/pool/first", &first)],
                    ),
                    lower(
                        File::open(descriptor.as_path()).unwrap(),
                        vec![held("/pool/first", &first)],
                    ),
                ],
                (RestoreRole::VmdkDescriptor, RestoreProblem::Alias),
            ),
            (
                "writable extent",
                vec![lower(
                    File::open(descriptor.as_path()).unwrap(),
                    vec![VmdkExtent {
                        path: "/pool/first".into(),
                        file: File::options()
                            .read(true)
                            .write(true)
                            .open(first.as_path())
                            .unwrap(),
                    }],
                )],
                (RestoreRole::VmdkExtent, RestoreProblem::Access),
            ),
            (
                "writable descriptor",
                vec![lower(
                    File::options()
                        .read(true)
                        .write(true)
                        .open(descriptor.as_path())
                        .unwrap(),
                    vec![held("/pool/first", &first)],
                )],
                (RestoreRole::VmdkDescriptor, RestoreProblem::Access),
            ),
            (
                "empty closure",
                vec![lower(File::open(descriptor.as_path()).unwrap(), Vec::new())],
                (RestoreRole::VmdkExtent, RestoreProblem::Closure),
            ),
        ];
        for (name, blocks, expected) in cases {
            assert_eq!(refusal(only(blocks), &files), expected, "{name}");
        }

        let restore = inputs(&files);
        let ram_extent = only(vec![lower(
            File::open(descriptor.as_path()).unwrap(),
            vec![VmdkExtent {
                path: "/pool/ram".into(),
                file: restore.ram.try_clone().unwrap(),
            }],
        )]);
        assert!(matches!(
            preflight(&restore, &ram_extent),
            Err(RestoreError::Descriptor {
                role: RestoreRole::VmdkExtent,
                problem: RestoreProblem::Alias
            })
        ));

        let inherited = held("/pool/first", &first);
        nix::fcntl::fcntl(
            inherited.file.as_fd(),
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
        )
        .unwrap();
        assert_eq!(
            refusal(
                only(vec![lower(
                    File::open(descriptor.as_path()).unwrap(),
                    vec![inherited]
                )]),
                &files
            ),
            (RestoreRole::VmdkExtent, RestoreProblem::CloseOnExec)
        );

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // tmpfs may refuse O_DIRECT; the check needs a real direct handle.
            if let Ok(direct) = File::options()
                .read(true)
                .custom_flags(nix::fcntl::OFlag::O_DIRECT.bits())
                .open(first.as_path())
            {
                assert_eq!(
                    refusal(
                        only(vec![lower(
                            File::open(descriptor.as_path()).unwrap(),
                            vec![VmdkExtent {
                                path: "/pool/first".into(),
                                file: direct,
                            }]
                        )]),
                        &files
                    ),
                    (RestoreRole::VmdkExtent, RestoreProblem::Access)
                );
            }
        }
    }

    #[cfg(feature = "blk")]
    #[test]
    fn block_binding_failures_keep_typed_vmdk_roles() {
        use devices::virtio::block::RestoreBindingError as Binding;
        use devices::virtio::block::vmdk::VmdkClosureFault as Fault;
        for (fault, role, problem) in [
            (
                Fault::DescriptorLength,
                RestoreRole::VmdkDescriptor,
                RestoreProblem::Length,
            ),
            (
                Fault::DescriptorGrammar,
                RestoreRole::VmdkDescriptor,
                RestoreProblem::Closure,
            ),
            (
                Fault::RecordLimit,
                RestoreRole::VmdkDescriptor,
                RestoreProblem::Closure,
            ),
            (
                Fault::Reader,
                RestoreRole::VmdkDescriptor,
                RestoreProblem::Closure,
            ),
            (
                Fault::UndeclaredExtent,
                RestoreRole::VmdkExtent,
                RestoreProblem::Closure,
            ),
            (
                Fault::UnreferencedExtent,
                RestoreRole::VmdkExtent,
                RestoreProblem::Closure,
            ),
            (
                Fault::DuplicateExtent,
                RestoreRole::VmdkExtent,
                RestoreProblem::Closure,
            ),
            (
                Fault::ExtentRange,
                RestoreRole::VmdkExtent,
                RestoreProblem::Length,
            ),
            (
                Fault::ExtentAccess,
                RestoreRole::VmdkExtent,
                RestoreProblem::Access,
            ),
        ] {
            assert!(
                matches!(
                    block_binding(Binding::Closure(fault)),
                    RestoreError::Descriptor { role: r, problem: p } if r == role && p == problem
                ),
                "{fault:?}"
            );
        }
        assert!(matches!(
            block_binding(Binding::Format),
            RestoreError::Descriptor {
                role: RestoreRole::Block,
                problem: RestoreProblem::Format
            }
        ));
        assert!(matches!(
            block_binding(Binding::Binding),
            RestoreError::Refused(RestoreProblem::Topology)
        ));
        assert!(matches!(
            block_binding(Binding::Payload),
            RestoreError::Codec(_)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn endpoint_preflight_rejects_opath_console_and_serial_inputs() {
        use std::os::unix::fs::OpenOptionsExt;
        let files = [file(b"ram"), file(b"layout"), file(b"bad"), file(b"bad")];
        let endpoint = file(b"input");
        let path_only = || {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::fcntl::OFlag::O_PATH.bits())
                .open(endpoint.as_path())
                .unwrap()
        };
        let console = RestoreResources {
            consoles: vec![RestoreConsole {
                attachment: RestoreAttachment {
                    configured_id: "hvc0".into(),
                    address: 0xd0000000,
                    irq: 5,
                },
                ports: vec![RestoreConsolePort {
                    name: String::new(),
                    input: Some(path_only()),
                    output: None,
                    terminal: false,
                }],
            }],
            ..RestoreResources::default()
        };
        assert!(matches!(
            preflight(&inputs(&files), &console),
            Err(RestoreError::Descriptor {
                role: RestoreRole::Console,
                problem: RestoreProblem::Access
            })
        ));
        let serial = RestoreResources {
            serial: vec![RestoreSerial {
                address: 0x3f8,
                input: Some(path_only()),
                output: None,
            }],
            ..RestoreResources::default()
        };
        assert!(matches!(
            preflight(&inputs(&files), &serial),
            Err(RestoreError::Descriptor {
                role: RestoreRole::Serial,
                problem: RestoreProblem::Access
            })
        ));
    }

    #[test]
    fn descriptor_roles_reject_writers_missing_cloexec_nonfiles_and_aliases() {
        let backing = file(b"metadata");
        let writable = File::options()
            .read(true)
            .write(true)
            .open(backing.as_path())
            .unwrap();
        assert!(matches!(
            inspect(&writable, RestoreRole::Execution, false),
            Err(RestoreError::Descriptor {
                problem: RestoreProblem::Access,
                ..
            })
        ));
        let readonly = File::open(backing.as_path()).unwrap();
        let identity = inspect(&readonly, RestoreRole::Execution, false).unwrap();
        let mut inodes = vec![identity];
        assert!(matches!(
            distinct(&mut inodes, identity, RestoreRole::Devices),
            Err(RestoreError::Descriptor {
                problem: RestoreProblem::Alias,
                ..
            })
        ));
        nix::fcntl::fcntl(
            readonly.as_fd(),
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
        )
        .unwrap();
        assert!(matches!(
            inspect(&readonly, RestoreRole::Execution, false),
            Err(RestoreError::Descriptor {
                problem: RestoreProblem::CloseOnExec,
                ..
            })
        ));
        assert!(matches!(
            inspect(
                &File::open("/dev/null").unwrap(),
                RestoreRole::Execution,
                false
            ),
            Err(RestoreError::Descriptor {
                problem: RestoreProblem::NotRegular,
                ..
            })
        ));
    }

    #[test]
    fn bounded_metadata_rejects_wrong_digest_length_truncation_and_trailing_codecs() {
        let backing = file(b"abc");
        let input = File::open(backing.as_path()).unwrap();
        let mut expected = StateObjectIdentity {
            length: 3,
            sha256: sha256(b"abc"),
        };
        assert_eq!(
            read_object(&input, RestoreRole::Execution, &expected, 3).unwrap(),
            b"abc"
        );
        assert!(read_object(&input, RestoreRole::Execution, &expected, 2).is_err());
        expected.sha256[0] ^= 1;
        assert!(matches!(
            read_object(&input, RestoreRole::Execution, &expected, 3),
            Err(RestoreError::Descriptor {
                problem: RestoreProblem::Digest,
                ..
            })
        ));
        expected.length = 4;
        assert!(matches!(
            read_object(&input, RestoreRole::Execution, &expected, 4),
            Err(RestoreError::Descriptor {
                problem: RestoreProblem::Length,
                ..
            })
        ));
        assert!(DeviceEnvelope::decode(b"").is_err());
        assert!(DeviceEnvelope::decode(&vec![0; 32 * 1024 * 1024 + 1]).is_err());
    }

    #[test]
    fn restore_profile_never_inserts_missing_or_duplicate_generation() {
        assert!(matches!(
            validate_profile(&[record()]),
            Err(RestoreError::Refused(RestoreProblem::Generation))
        ));
        let mut generation = record();
        generation.state.device_type = devices::virtio::generation::DEVICE_TYPE;
        assert!(validate_profile(std::slice::from_ref(&generation)).is_err());
        assert!(validate_profile(&[generation.clone(), generation]).is_err());
    }

    #[test]
    fn inventory_requires_exact_identity_and_rejects_missing_duplicate_and_extra() {
        let saved = record();
        let attachment = RestoreAttachment {
            configured_id: "rng0".into(),
            address: saved.identity.address,
            irq: 5,
        };
        let mut missing: Vec<RestoreAttachment> = Vec::new();
        assert!(validate_bindings(&missing, std::slice::from_ref(&saved), 4, |item| item).is_err());
        assert!(take_binding(&mut missing, &saved, |item| item).is_err());
        let mut duplicate = vec![attachment.clone(), attachment.clone()];
        assert!(
            validate_bindings(&duplicate, std::slice::from_ref(&saved), 4, |item| item).is_err()
        );
        assert!(take_binding(&mut duplicate, &saved, |item| item).is_err());
        assert_eq!(duplicate.len(), 2);
        let mut foreign = vec![RestoreAttachment {
            irq: 6,
            ..attachment.clone()
        }];
        assert!(validate_bindings(&foreign, std::slice::from_ref(&saved), 4, |item| item).is_err());
        assert!(take_binding(&mut foreign, &saved, |item| item).is_err());
        let mut exact = vec![
            attachment.clone(),
            RestoreAttachment {
                address: 0xe0000000,
                ..attachment.clone()
            },
        ];
        assert!(validate_bindings(&exact, std::slice::from_ref(&saved), 4, |item| item).is_err());
        assert!(
            validate_bindings(
                std::slice::from_ref(&attachment),
                std::slice::from_ref(&saved),
                4,
                |item| item
            )
            .is_ok()
        );
        assert_eq!(
            take_binding(&mut exact, &saved, |item| item).unwrap(),
            attachment
        );
        assert_eq!(exact.len(), 1);
    }

    #[test]
    fn metadata_sha256_known_answers_cover_padding_and_multiple_blocks() {
        fn hex(value: [u8; 32]) -> String {
            value.iter().map(|byte| format!("{byte:02x}")).collect()
        }
        assert_eq!(
            hex(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn restored_owner_roles_register_and_dispatch_under_the_parked_restore_fence() {
        let mut events = EventManager::new().unwrap();
        let ingress = Owner::new();
        let ingress_fd = ingress.lock().unwrap().control.as_raw_fd();
        events
            .register(
                ingress_fd,
                EpollEvent::new(EventSet::IN, ingress_fd as u64),
                ingress.clone(),
            )
            .unwrap();
        let request = BarrierRequest {
            key: BarrierKey {
                operation: OperationId(0),
                generation: BarrierGeneration(1),
            },
            deadline: Instant::now() + Duration::from_secs(60),
        };
        events.begin_ingress_fence(request).unwrap();
        events.park_callbacks(request.key).unwrap();

        let owner = Owner::new();
        let (control, exit) = {
            let owner = owner.lock().unwrap();
            (owner.control.as_raw_fd(), owner.exit.as_raw_fd())
        };
        assert!(matches!(
            events.set_dispatch_role(control, DispatchRole::Control),
            Err(EventManagerError::BarrierActive(key)) if key == request.key
        ));
        register_owner_roles(&mut events, owner.clone(), control, exit).unwrap();
        assert!(matches!(
            events.set_dispatch_role(control, DispatchRole::Ingress),
            Err(EventManagerError::BarrierActive(key)) if key == request.key
        ));

        ingress.lock().unwrap().control.write(1).unwrap();
        owner.lock().unwrap().control.write(1).unwrap();
        owner.lock().unwrap().exit.write(1).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while owner.lock().unwrap().dispatched.len() < 2 && Instant::now() < deadline {
            events.run_with_timeout(10).unwrap();
        }
        events.run_with_timeout(10).unwrap();

        let mut dispatched = owner.lock().unwrap().dispatched.clone();
        dispatched.sort_unstable();
        let mut expected = vec![control, exit];
        expected.sort_unstable();
        assert_eq!(dispatched, expected);
        assert!(ingress.lock().unwrap().dispatched.is_empty());
        assert_eq!(
            events
                .dispatch_fence()
                .map(|(fence, phase)| (fence.key, phase)),
            Some((request.key, DispatchPhase::Parked))
        );
    }
}
