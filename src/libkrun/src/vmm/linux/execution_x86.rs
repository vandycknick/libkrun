use crate::vmm::execution::kvm::{
    CpuidEntry, KvmCpuState, KvmCpuTimePlan, KvmVmState, MAX_MSRS, MAX_XSAVE, MsrDescriptor,
    MsrValue, PitChannel, Segment, X86CpuState, X86Special, X86VmState, XstateComponent,
    common_tsc_offset, lapic_u32,
};
use crate::vmm::linux::execution::{CpuCaptureConfig, validate_native};
use arch::guest_memory::NativeEffectsPermit;
use arch::x86_state::{CpuFeatures, MsrClass};
use kvm_bindings::*;
use kvm_ioctls::{VcpuFd, VmFd};
use vmm_sys_util::ioctl::{ioctl_with_mut_ref, ioctl_with_ref};
use vmm_sys_util::{ioctl_ior_nr, ioctl_iow_nr};

ioctl_ior_nr!(get_sregs2, KVMIO, 0xcc, kvm_sregs2);
ioctl_iow_nr!(set_sregs2, KVMIO, 0xcd, kvm_sregs2);
// The attribute descriptor is input; KVM writes through its addr, so GET uses _IOW too.
ioctl_iow_nr!(get_vcpu_attr, KVMIO, 0xe2, kvm_device_attr);
ioctl_iow_nr!(set_vcpu_attr, KVMIO, 0xe1, kvm_device_attr);
ioctl_iow_nr!(has_vcpu_attr, KVMIO, 0xe3, kvm_device_attr);
ioctl_iow_nr!(setup_mce, KVMIO, 0x9c, u64);

fn native_error(operation: &str, error: impl std::fmt::Display) -> String {
    format!("kvm/{operation}: {error}")
}
fn ioctl_result(ret: i32, operation: &str) -> Result<(), String> {
    if ret < 0 {
        return Err(native_error(operation, std::io::Error::last_os_error()));
    }
    if ret != 0 {
        return Err(format!("kvm/{operation}/unexpected-result/{ret}"));
    }
    Ok(())
}

fn offset(fd: &VcpuFd, value: Option<u64>) -> Result<u64, String> {
    let mut data = value.unwrap_or_default();
    let attr = kvm_device_attr {
        group: KVM_VCPU_TSC_CTRL,
        attr: u64::from(KVM_VCPU_TSC_OFFSET),
        addr: &mut data as *mut u64 as u64,
        flags: 0,
    };
    // The pinned wrapper exposes device attributes only on ARM; these x86 ioctls use the same ABI.
    ioctl_result(
        unsafe { ioctl_with_ref(fd, has_vcpu_attr(), &attr) },
        "HAS_TSC_OFFSET",
    )?;
    let ret = if value.is_some() {
        unsafe { ioctl_with_ref(fd, set_vcpu_attr(), &attr) }
    } else {
        unsafe { ioctl_with_ref(fd, get_vcpu_attr(), &attr) }
    };
    ioctl_result(ret, "TSC_OFFSET")?;
    Ok(data)
}

fn verify_msr_count(
    id: u8,
    operation: &str,
    requested: usize,
    completed: usize,
    first_missing: Option<u32>,
) -> Result<(), String> {
    if completed == requested {
        return Ok(());
    }
    if let Some(index) = first_missing {
        return Err(format!(
            "cpu/{id}/{operation} requested={requested} completed={completed} first-missing={index:#x}"
        ));
    }
    Err(format!(
        "cpu/{id}/{operation} requested={requested} invalid-completed-count={completed}"
    ))
}
fn get_msrs(fd: &VcpuFd, id: u8, indices: &[u32]) -> Result<Vec<MsrValue>, String> {
    let mut result = Vec::with_capacity(indices.len());
    for batch in indices.chunks(256) {
        let mut native =
            Msrs::new(batch.len()).map_err(|e| format!("cpu/{id}/GET_MSRS/allocation: {e:?}"))?;
        for (entry, index) in native.as_mut_slice().iter_mut().zip(batch) {
            entry.index = *index;
        }
        let completed = fd
            .get_msrs(&mut native)
            .map_err(|e| native_error(&format!("cpu/{id}/GET_MSRS"), e))?;
        verify_msr_count(
            id,
            "GET_MSRS",
            batch.len(),
            completed,
            batch.get(completed).copied(),
        )?;
        result.extend(native.as_slice().iter().map(|e| MsrValue {
            index: e.index,
            value: e.data,
        }));
    }
    Ok(result)
}
fn set_msrs(fd: &VcpuFd, id: u8, values: &[MsrValue]) -> Result<(), String> {
    for batch in values.chunks(256) {
        let mut native =
            Msrs::new(batch.len()).map_err(|e| format!("cpu/{id}/SET_MSRS/allocation: {e:?}"))?;
        for (entry, value) in native.as_mut_slice().iter_mut().zip(batch) {
            entry.index = value.index;
            entry.data = value.value;
        }
        let completed = fd
            .set_msrs(&native)
            .map_err(|e| native_error(&format!("cpu/{id}/SET_MSRS"), e))?;
        verify_msr_count(
            id,
            "SET_MSRS",
            batch.len(),
            completed,
            batch.get(completed).map(|e| e.index),
        )?;
    }
    Ok(())
}
fn one_msr(fd: &VcpuFd, id: u8, index: u32) -> Result<u64, String> {
    let mut msr = Msrs::new(1).map_err(|e| format!("cpu/{id}/GET_MSRS/allocation: {e:?}"))?;
    let entry = msr
        .as_mut_slice()
        .first_mut()
        .ok_or("kvm/msr/allocation-empty")?;
    entry.index = index;
    let completed = fd
        .get_msrs(&mut msr)
        .map_err(|e| native_error(&format!("cpu/{id}/GET_MSRS/{index:#x}"), e))?;
    verify_msr_count(
        id,
        "GET_MSRS",
        1,
        completed,
        (completed == 0).then_some(index),
    )?;
    msr.as_slice()
        .first()
        .map(|e| e.data)
        .ok_or_else(|| format!("cpu/{id}/msr/{index:#x}/missing"))
}

pub(crate) fn mce_inventory(cap: u64) -> Result<Vec<u32>, String> {
    let banks = (cap & 255) as u32;
    if banks > 32 {
        return Err(format!("kvm/mce/banks/{banks}"));
    }
    if cap & (1 << 9) != 0 || cap & (255 << 16) != 0 {
        return Err("kvm/mce/extended-register-file-unqualified".into());
    }
    let mut indices = vec![0x17a];
    if cap & (1 << 8) != 0 {
        indices.push(0x17b);
    }
    if cap & (1 << 27) != 0 {
        indices.push(0x4d0);
    }
    for bank in 0..banks {
        for field in 0..4 {
            indices.push(0x400 + 4 * bank + field);
        }
        if cap & (1 << 10) != 0 {
            indices.push(0x280 + bank);
        }
    }
    indices.sort_unstable();
    Ok(indices)
}
fn xstate_layout() -> Vec<XstateComponent> {
    // XSAVE transfer offsets are host CPUID facts, not guest CPUID.0xD offsets.
    let root = std::arch::x86_64::__cpuid_count(0xd, 0);
    let supervisor = std::arch::x86_64::__cpuid_count(0xd, 1);
    let bits = u64::from(root.eax)
        | (u64::from(root.edx) << 32)
        | u64::from(supervisor.ecx)
        | (u64::from(supervisor.edx) << 32);
    let mut result = Vec::new();
    for id in 2..64 {
        if bits & (1u64 << id) != 0 {
            let c = std::arch::x86_64::__cpuid_count(0xd, id);
            result.push(XstateComponent {
                id,
                size: c.eax,
                offset: c.ebx,
                flags: c.ecx,
            });
        }
    }
    result
}
fn xsave_buffer(size: usize) -> Result<Xsave, String> {
    if !(4096..=MAX_XSAVE).contains(&size) || !size.is_multiple_of(4) {
        return Err(format!("kvm/xsave2/extent/{size}"));
    }
    Xsave::new((size - 4096) / 4).map_err(|e| format!("kvm/xsave2/allocation: {e:?}"))
}
fn segment(s: kvm_segment) -> Segment {
    Segment {
        base: s.base,
        limit: s.limit,
        selector: s.selector,
        attributes: [
            s.type_, s.present, s.dpl, s.db, s.s, s.l, s.g, s.avl, s.unusable,
        ],
    }
}
fn native_segment(s: &Segment) -> kvm_segment {
    let a = s.attributes;
    kvm_segment {
        base: s.base,
        limit: s.limit,
        selector: s.selector,
        type_: a[0],
        present: a[1],
        dpl: a[2],
        db: a[3],
        s: a[4],
        l: a[5],
        g: a[6],
        avl: a[7],
        unusable: a[8],
        padding: 0,
    }
}
fn events(e: kvm_vcpu_events) -> [u64; 24] {
    [
        e.exception.injected.into(),
        e.exception.nr.into(),
        e.exception.has_error_code.into(),
        e.exception.pending.into(),
        e.exception.error_code.into(),
        e.interrupt.injected.into(),
        e.interrupt.nr.into(),
        e.interrupt.soft.into(),
        e.interrupt.shadow.into(),
        e.nmi.injected.into(),
        e.nmi.pending.into(),
        e.nmi.masked.into(),
        e.sipi_vector.into(),
        e.flags.into(),
        e.smi.smm.into(),
        e.smi.pending.into(),
        e.smi.smm_inside_nmi.into(),
        e.smi.latched_init.into(),
        e.triple_fault.pending.into(),
        e.exception_has_payload.into(),
        e.exception_payload,
        0,
        0,
        0,
    ]
}
fn native_events(v: [u64; 24]) -> Result<kvm_vcpu_events, String> {
    let byte = |i: usize| u8::try_from(v[i]).map_err(|_| "kvm/events/byte".to_owned());
    let word = |i: usize| u32::try_from(v[i]).map_err(|_| "kvm/events/word".to_owned());
    if v[21..].iter().any(|v| *v != 0) {
        return Err("kvm/events/reserved".into());
    }
    Ok(kvm_vcpu_events {
        exception: kvm_vcpu_events__bindgen_ty_1 {
            injected: byte(0)?,
            nr: byte(1)?,
            has_error_code: byte(2)?,
            pending: byte(3)?,
            error_code: word(4)?,
        },
        interrupt: kvm_vcpu_events__bindgen_ty_2 {
            injected: byte(5)?,
            nr: byte(6)?,
            soft: byte(7)?,
            shadow: byte(8)?,
        },
        nmi: kvm_vcpu_events__bindgen_ty_3 {
            injected: byte(9)?,
            pending: byte(10)?,
            masked: byte(11)?,
            pad: 0,
        },
        sipi_vector: word(12)?,
        flags: word(13)?,
        smi: kvm_vcpu_events__bindgen_ty_4 {
            smm: byte(14)?,
            pending: byte(15)?,
            smm_inside_nmi: byte(16)?,
            latched_init: byte(17)?,
        },
        triple_fault: kvm_vcpu_events__bindgen_ty_5 { pending: byte(18)? },
        exception_has_payload: byte(19)?,
        exception_payload: v[20],
        ..Default::default()
    })
}
fn actual_cpuid(fd: &VcpuFd) -> Result<CpuId, String> {
    fd.get_cpuid2(KVM_MAX_CPUID_ENTRIES)
        .map_err(|e| native_error("GET_CPUID2", e))
}
fn cpuid_entries(cpu: &CpuId) -> Vec<CpuidEntry> {
    let mut entries: Vec<_> = cpu
        .as_slice()
        .iter()
        .map(|e| CpuidEntry {
            function: e.function,
            index: e.index,
            flags: e.flags,
            values: [e.eax, e.ebx, e.ecx, e.edx],
        })
        .collect();
    entries.sort_by_key(|e| (e.function, e.index));
    entries
}
fn classify(raw: &[u32], cpuid: &CpuId) -> Result<Vec<MsrDescriptor>, String> {
    if raw.len() > MAX_MSRS {
        return Err("kvm/msr/raw-count".into());
    }
    let mut inventory = Vec::with_capacity(raw.len());
    let features = CpuFeatures::from_cpuid(|function, index| {
        cpuid
            .as_slice()
            .iter()
            .find(|e| e.function == function && e.index == index)
            .map(|e| [e.eax, e.ebx, e.ecx, e.edx])
    });
    for index in raw {
        inventory.push(MsrDescriptor {
            index: *index,
            class: features
                .classify(*index)
                .map_err(|index| format!("kvm/msr/{index:#x}/unknown-or-uncovered-exposed-state"))?
                as u8,
        });
    }
    inventory.sort_by_key(|e| e.index);
    features
        .validate_inventory(inventory.iter().map(|e| (e.index, e.class)))
        .map_err(|index| format!("kvm/msr/{index:#x}/missing-or-inconsistent-exposed-state"))?;
    Ok(inventory)
}

fn admit_cpuid(cpuid: &CpuId, config: &CpuCaptureConfig) -> Result<(), String> {
    for e in cpuid.as_slice() {
        if e.function == 1 {
            // The production CPUID transformer derives these from virtual topology,
            // independently of the host's HTT bit or physical package/APIC identity.
            let package_slots = (e.ebx >> 16) & 0xff;
            let apic_id = e.ebx >> 24;
            if !package_slots.is_power_of_two() || (e.edx & (1 << 28) != 0) != (package_slots > 1) {
                return Err("kvm/cpuid/0x1/virtual-topology/package-slots-or-htt".into());
            }
            if apic_id != u32::from(config.logical_id) || apic_id >= package_slots {
                return Err("kvm/cpuid/0x1/virtual-topology/apic-id".into());
            }
        }
        let registers: &[usize] = match e.function {
            1 => &[2, 3],
            7 if e.index == 0 => &[1, 2, 3],
            0x80000001 => &[2, 3],
            0xd if e.index == 0 => &[0, 3],
            _ => continue,
        };
        let host = config
            .host_cpuid
            .as_slice()
            .iter()
            .find(|h| h.function == e.function && h.index == e.index)
            .ok_or("kvm/cpuid/destination-leaf-missing")?;
        let actual = [e.eax, e.ebx, e.ecx, e.edx];
        let supported = [host.eax, host.ebx, host.ecx, host.edx];
        for register in registers {
            let emulated = if e.function == 1 && *register == 2 {
                (1 << 27)
                    | if config.deadline_supported {
                        1 << 24
                    } else {
                        0
                    }
            } else if e.function == 1 && *register == 3 {
                // HTT describes the validated virtual package, not host SMT support.
                1 << 28
            } else {
                0
            };
            let unsupported = actual[*register] & !(supported[*register] | emulated);
            if unsupported != 0 {
                return Err(format!(
                    "kvm/cpuid/{:#x}/{}/unsupported-feature/register={}/actual={:#x}/supported={:#x}/unsupported-mask={:#x}",
                    e.function,
                    e.index,
                    ["eax", "ebx", "ecx", "edx"][*register],
                    actual[*register],
                    supported[*register],
                    unsupported,
                ));
            }
        }
        if e.function == 1 && e.eax != host.eax {
            return Err("kvm/cpuid/destination-family-model-stepping".into());
        }
    }
    Ok(())
}

pub(crate) fn capture_cpu(
    fd: &VcpuFd,
    id: u8,
    config: &CpuCaptureConfig,
) -> Result<KvmCpuState, String> {
    let mp_state = fd
        .get_mp_state()
        .map_err(|e| native_error("GET_MP_STATE", e))?
        .mp_state;
    let cpuid = actual_cpuid(fd)?;
    if cpuid.as_slice().iter().any(|e| {
        (e.function == 1 && e.ecx & (1 << 5) != 0)
            || (e.function == 0x80000001 && e.ecx & (1 << 2) != 0)
    }) {
        return Err("kvm/cpu/nested-exposed".into());
    }
    admit_cpuid(&cpuid, config)?;
    let inventory = classify(&config.raw_msrs, &cpuid)?;
    let mce_cap = one_msr(fd, id, 0x179)?;
    let mut indices: Vec<_> = inventory
        .iter()
        .filter(|e| e.class == MsrClass::Mutable as u8)
        .map(|e| e.index)
        .collect();
    indices.extend(mce_inventory(mce_cap)?);
    indices.sort_unstable();
    indices.dedup();
    let msrs = get_msrs(fd, id, &indices)?;
    let model_indices: Vec<_> = inventory
        .iter()
        .filter(|e| e.class == MsrClass::Model as u8)
        .map(|e| e.index)
        .collect();
    let model_msrs = get_msrs(fd, id, &model_indices)?;
    let tsc_offset = offset(fd, None)?;
    let tsc_khz = fd
        .get_tsc_khz()
        .map_err(|e| native_error("GET_TSC_KHZ", e))?;
    let regs = fd.get_regs().map_err(|e| native_error("GET_REGS", e))?;
    let mut s = kvm_sregs2::default();
    ioctl_result(
        unsafe { ioctl_with_mut_ref(fd, get_sregs2(), &mut s) },
        "GET_SREGS2",
    )?;
    let mut xsave = xsave_buffer(config.xsave_size)?;
    // Buffer uses the exact VM-reported extent, including the flexible tail.
    unsafe { fd.get_xsave2(&mut xsave) }.map_err(|e| native_error("GET_XSAVE2", e))?;
    let mut xsave_bytes = Vec::with_capacity(config.xsave_size);
    for word in &xsave.as_fam_struct_ref().xsave.region {
        xsave_bytes.extend_from_slice(&word.to_le_bytes());
    }
    for word in xsave.as_slice() {
        xsave_bytes.extend_from_slice(&word.to_le_bytes());
    }
    let xcr = fd.get_xcrs().map_err(|e| native_error("GET_XCRS", e))?;
    let xcr_count = usize::try_from(xcr.nr_xcrs).map_err(|_| "kvm/xcr/count")?;
    if xcr.flags != 0 || xcr_count > xcr.xcrs.len() {
        return Err("kvm/xcr/flags-count".into());
    }
    let xcrs = xcr.xcrs[..xcr_count]
        .iter()
        .map(|e| MsrValue {
            index: e.xcr,
            value: e.value,
        })
        .collect();
    let d = fd
        .get_debug_regs()
        .map_err(|e| native_error("GET_DEBUGREGS", e))?;
    let lapic = fd.get_lapic().map_err(|e| native_error("GET_LAPIC", e))?;
    let deadline = one_msr(fd, id, 0x6e0)?;
    let tsc_observed = one_msr(fd, id, 0x10)?;
    let e = fd
        .get_vcpu_events()
        .map_err(|e| native_error("GET_VCPU_EVENTS", e))?;
    let state = KvmCpuState::X86(X86CpuState {
        id,
        cpuid: cpuid_entries(&cpuid),
        inventory,
        msrs,
        model_msrs,
        mce_cap,
        xstate: xstate_layout(),
        xsave: xsave_bytes,
        xcrs,
        regs: [
            regs.rax,
            regs.rbx,
            regs.rcx,
            regs.rdx,
            regs.rsi,
            regs.rdi,
            regs.rsp,
            regs.rbp,
            regs.r8,
            regs.r9,
            regs.r10,
            regs.r11,
            regs.r12,
            regs.r13,
            regs.r14,
            regs.r15,
            regs.rip,
            regs.rflags,
        ],
        special: X86Special {
            segments: [s.cs, s.ds, s.es, s.fs, s.gs, s.ss, s.tr, s.ldt].map(segment),
            gdt: (s.gdt.base, s.gdt.limit),
            idt: (s.idt.base, s.idt.limit),
            values: [
                s.cr0,
                s.cr2,
                s.cr3,
                s.cr4,
                s.cr8,
                s.efer,
                s.apic_base,
                s.flags,
                s.pdptrs[0],
                s.pdptrs[1],
                s.pdptrs[2],
                s.pdptrs[3],
            ],
        },
        debug: [d.db[0], d.db[1], d.db[2], d.db[3], d.dr6, d.dr7, d.flags],
        lapic: lapic.regs.iter().map(|b| *b as u8).collect(),
        events: events(e),
        mp_state,
        tsc_offset,
        tsc_khz,
        tsc_observed,
        deadline,
    });
    state.validate()?;
    Ok(state)
}

pub(crate) fn fence_cpu_timer(fd: &VcpuFd, state: &KvmCpuState) -> Result<(), String> {
    let KvmCpuState::X86(s) = state else {
        return Err("kvm/x86/backend".into());
    };
    set_msrs(
        fd,
        s.id,
        &[MsrValue {
            index: 0x6e0,
            value: 0,
        }],
    )?;
    let lapic = native_lapic(&s.lapic)?;
    fd.set_lapic(&lapic)
        .map_err(|e| native_error("SET_LAPIC/fence", e))
}
fn native_lapic(bytes: &[u8]) -> Result<kvm_lapic_state, String> {
    if bytes.len() != 1024 {
        return Err("kvm/lapic/extent".into());
    }
    let mut lapic = kvm_lapic_state::default();
    for (dst, src) in lapic.regs.iter_mut().zip(bytes) {
        *dst = *src as i8;
    }
    Ok(lapic)
}
fn native_cpuid(entries: &[CpuidEntry]) -> Result<CpuId, String> {
    let native: Vec<_> = entries
        .iter()
        .map(|e| kvm_cpuid_entry2 {
            function: e.function,
            index: e.index,
            flags: e.flags,
            eax: e.values[0],
            ebx: e.values[1],
            ecx: e.values[2],
            edx: e.values[3],
            ..Default::default()
        })
        .collect();
    CpuId::from_entries(&native).map_err(|e| format!("kvm/cpuid/allocation: {e:?}"))
}
fn set_execution_registers(fd: &VcpuFd, s: &X86CpuState) -> Result<(), String> {
    let r = &s.regs;
    fd.set_regs(&kvm_regs {
        rax: r[0],
        rbx: r[1],
        rcx: r[2],
        rdx: r[3],
        rsi: r[4],
        rdi: r[5],
        rsp: r[6],
        rbp: r[7],
        r8: r[8],
        r9: r[9],
        r10: r[10],
        r11: r[11],
        r12: r[12],
        r13: r[13],
        r14: r[14],
        r15: r[15],
        rip: r[16],
        rflags: r[17],
    })
    .map_err(|e| native_error("SET_REGS", e))?;
    let t = &s.special;
    let v = t.values;
    let special = kvm_sregs2 {
        cs: native_segment(&t.segments[0]),
        ds: native_segment(&t.segments[1]),
        es: native_segment(&t.segments[2]),
        fs: native_segment(&t.segments[3]),
        gs: native_segment(&t.segments[4]),
        ss: native_segment(&t.segments[5]),
        tr: native_segment(&t.segments[6]),
        ldt: native_segment(&t.segments[7]),
        gdt: kvm_dtable {
            base: t.gdt.0,
            limit: t.gdt.1,
            ..Default::default()
        },
        idt: kvm_dtable {
            base: t.idt.0,
            limit: t.idt.1,
            ..Default::default()
        },
        cr0: v[0],
        cr2: v[1],
        cr3: v[2],
        cr4: v[3],
        cr8: v[4],
        efer: v[5],
        apic_base: v[6],
        flags: v[7],
        pdptrs: [v[8], v[9], v[10], v[11]],
    };
    ioctl_result(
        unsafe { ioctl_with_ref(fd, set_sregs2(), &special) },
        "SET_SREGS2",
    )?;
    Ok(())
}

#[cfg(feature = "native-device-probe")]
pub(crate) fn initialize_device_witness(fd: &VcpuFd, state: &X86CpuState) -> Result<(), String> {
    set_execution_registers(fd, state)?;
    fd.set_mp_state(kvm_mp_state { mp_state: 0 })
        .map_err(|e| native_error("SET_MP_STATE", e))
}

pub(crate) fn install_cpu(
    fd: &VcpuFd,
    state: &KvmCpuState,
    config: &CpuCaptureConfig,
) -> Result<(), String> {
    let KvmCpuState::X86(s) = state else {
        return Err("kvm/x86/backend".into());
    };
    if s.xsave.len() != config.xsave_size || s.xstate != xstate_layout() {
        return Err("kvm/xsave2/destination-layout".into());
    }
    let cpuid = native_cpuid(&s.cpuid)?;
    admit_cpuid(&cpuid, config)?;
    if classify(&config.raw_msrs, &cpuid)? != s.inventory {
        return Err("kvm/msr/destination-inventory".into());
    }
    let current_cap = one_msr(fd, s.id, 0x179)?;
    if s.mce_cap & !255 != current_cap & !255 || s.mce_cap & 255 > current_cap & 255 {
        return Err("kvm/mce/destination-capability".into());
    }
    let model_indices: Vec<_> = s.model_msrs.iter().map(|e| e.index).collect();
    if get_msrs(fd, s.id, &model_indices)? != s.model_msrs {
        return Err("kvm/msr/destination-model-values".into());
    }
    native_events(s.events)?;
    fd.set_cpuid2(&cpuid)
        .map_err(|e| native_error("SET_CPUID2", e))?;
    ioctl_result(
        unsafe { ioctl_with_ref(fd, setup_mce(), &s.mce_cap) },
        "SETUP_MCE",
    )?;
    if fd
        .get_tsc_khz()
        .map_err(|e| native_error("GET_TSC_KHZ", e))?
        != s.tsc_khz
    {
        return Err("kvm/clock/unscaled-rate-mismatch".into());
    }
    set_execution_registers(fd, s)?;
    let mut xcr = kvm_xcrs {
        nr_xcrs: s.xcrs.len() as u32,
        ..Default::default()
    };
    for (to, from) in xcr.xcrs.iter_mut().zip(&s.xcrs) {
        to.xcr = from.index;
        to.value = from.value;
    }
    fd.set_xcrs(&xcr).map_err(|e| native_error("SET_XCRS", e))?;
    let mut xsave = xsave_buffer(config.xsave_size)?;
    let mut words = s
        .xsave
        .chunks_exact(4)
        .map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]));
    for dst in &mut unsafe { xsave.as_mut_fam_struct() }.xsave.region {
        *dst = words.next().ok_or("kvm/xsave/header")?;
    }
    for dst in xsave.as_mut_slice() {
        *dst = words.next().ok_or("kvm/xsave/tail")?;
    }
    // Exact VM extent and host layout were checked before any mutation.
    unsafe { fd.set_xsave2(&xsave) }.map_err(|e| native_error("SET_XSAVE2", e))?;
    let d = s.debug;
    fd.set_debug_regs(&kvm_debugregs {
        db: [d[0], d[1], d[2], d[3]],
        dr6: d[4],
        dr7: d[5],
        flags: d[6],
        ..Default::default()
    })
    .map_err(|e| native_error("SET_DEBUGREGS", e))?;
    set_msrs(fd, s.id, &s.msrs)?;
    fence_cpu_timer(fd, state)?;
    fd.set_vcpu_events(&native_events(s.events)?)
        .map_err(|e| native_error("SET_VCPU_EVENTS", e))?;
    fd.set_mp_state(kvm_mp_state {
        mp_state: s.mp_state,
    })
    .map_err(|e| native_error("SET_MP_STATE", e))?;
    if cpuid_entries(&actual_cpuid(fd)?) != s.cpuid {
        return Err("kvm/cpuid/effective-restored-model".into());
    }
    Ok(())
}
pub(crate) fn prepare_cpu_time(
    fd: &VcpuFd,
    state: &KvmCpuState,
    plan: &KvmCpuTimePlan,
) -> Result<(), String> {
    let (
        KvmCpuState::X86(s),
        KvmCpuTimePlan::X86 {
            id,
            offset: target,
            tsc_khz,
        },
    ) = (state, plan)
    else {
        return Err("kvm/clock/backend".into());
    };
    if *id != s.id || *tsc_khz != s.tsc_khz {
        return Err("kvm/clock/cpu-rate".into());
    }
    fence_cpu_timer(fd, state)?;
    offset(fd, Some(*target))?;
    if offset(fd, None)? != *target {
        return Err("kvm/clock/offset-readback".into());
    }
    for value in s
        .msrs
        .iter()
        .filter(|v| matches!(v.index, 0x3b | 0xc0000103))
    {
        if one_msr(fd, s.id, value.index)? != value.value {
            return Err(format!("kvm/clock/msr/{:#x}/readback", value.index));
        }
    }
    // IA32_TSC is never replayed. TSC_ADJUST and TSC_AUX remain independent saved MSRs.
    set_msrs(
        fd,
        s.id,
        &[MsrValue {
            index: 0x6e0,
            value: s.deadline,
        }],
    )?;
    fd.set_vcpu_events(&native_events(s.events)?)
        .map_err(|e| native_error("SET_VCPU_EVENTS/time", e))?;
    fd.set_mp_state(kvm_mp_state {
        mp_state: s.mp_state,
    })
    .map_err(|e| native_error("SET_MP_STATE/time", e))?;
    Ok(())
}

#[derive(Clone, Debug)]
pub(crate) enum KvmCaptureProfile {
    // Only the separately built execution diagnostic constructs an unprogrammed-PIT profile.
    #[cfg_attr(not(feature = "native-execution-probe"), allow(dead_code))]
    ResetPit,
    // Normal-guest callers require commit6 providers and the commit11 capture API.
    // Keeping the real predicate compiled does not satisfy the pending production-guest gate.
    #[allow(dead_code)]
    RetiredLinuxPit {
        kernel_identity: String,
        clocksource_tsc: bool,
        all_online_clockevents_deadline: bool,
        broadcast_uses_pit: bool,
        speaker_or_counter_consumer: bool,
    },
}
fn host_clock_profile() -> Result<(String, u8), String> {
    let disabled = |path: &str| -> Result<(), String> {
        let value = std::fs::read_to_string(path)
            .map_err(|e| format!("kvm/clock/host-profile/{path}: {e}"))?;
        if !matches!(value.trim(), "N" | "0") {
            return Err(format!("kvm/clock/unqualified-acceleration/{path}"));
        }
        Ok(())
    };
    disabled("/sys/module/kvm/parameters/pi_inject_timer")?;
    let vendor = std::arch::x86_64::__cpuid(0);
    let mode = if vendor.ebx == 0x68747541 && vendor.edx == 0x69746e65 && vendor.ecx == 0x444d4163 {
        disabled("/sys/module/kvm_amd/parameters/avic")?;
        0
    } else if vendor.ebx == 0x756e6547 && vendor.edx == 0x49656e69 && vendor.ecx == 0x6c65746e {
        disabled("/sys/module/kvm_intel/parameters/enable_apicv")?;
        disabled("/sys/module/kvm_intel/parameters/preemption_timer")?;
        1
    } else {
        return Err("kvm/clock/unqualified-host-vendor".into());
    };
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map_err(|e| format!("kvm/clock/kernel-profile: {e}"))?;
    let kernel = kernel.trim();
    if kernel.is_empty() || kernel.len() > 256 {
        return Err("kvm/clock/kernel-profile-length".into());
    }
    Ok((kernel.to_owned(), mode))
}
fn admit_host_clock(s: &X86VmState) -> Result<(), String> {
    let (kernel, mode) = host_clock_profile()?;
    if kernel != s.host_kernel || mode != s.host_mode {
        return Err("kvm/clock/destination-host-semantics-profile".into());
    }
    Ok(())
}
fn irqchip(fd: &VmFd, id: u32) -> Result<kvm_irqchip, String> {
    let mut chip = kvm_irqchip {
        chip_id: id,
        ..Default::default()
    };
    fd.get_irqchip(&mut chip)
        .map_err(|e| native_error("GET_IRQCHIP", e))?;
    Ok(chip)
}
fn pic(p: kvm_pic_state) -> [u8; 16] {
    [
        p.last_irr,
        p.irr,
        p.imr,
        p.isr,
        p.priority_add,
        p.irq_base,
        p.read_reg_select,
        p.poll,
        p.special_mask,
        p.init_state,
        p.auto_eoi,
        p.rotate_on_auto_eoi,
        p.special_fully_nested_mode,
        p.init4,
        p.elcr,
        p.elcr_mask,
    ]
}
fn native_pic(v: [u8; 16]) -> kvm_pic_state {
    kvm_pic_state {
        last_irr: v[0],
        irr: v[1],
        imr: v[2],
        isr: v[3],
        priority_add: v[4],
        irq_base: v[5],
        read_reg_select: v[6],
        poll: v[7],
        special_mask: v[8],
        init_state: v[9],
        auto_eoi: v[10],
        rotate_on_auto_eoi: v[11],
        special_fully_nested_mode: v[12],
        init4: v[13],
        elcr: v[14],
        elcr_mask: v[15],
    }
}
fn pit_channel(c: kvm_pit_channel_state) -> PitChannel {
    PitChannel {
        count: c.count,
        latched_count: c.latched_count,
        bytes: [
            c.count_latched,
            c.status_latched,
            c.status,
            c.read_state,
            c.write_state,
            c.write_latch,
            c.rw_mode,
            c.mode,
            c.bcd,
            c.gate,
        ],
        count_load_time: c.count_load_time as u64,
    }
}
fn native_pit(s: &X86VmState) -> kvm_pit_state2 {
    kvm_pit_state2 {
        channels: std::array::from_fn(|i| {
            let c = &s.pit[i];
            let b = c.bytes;
            kvm_pit_channel_state {
                count: c.count,
                latched_count: c.latched_count,
                count_latched: b[0],
                status_latched: b[1],
                status: b[2],
                read_state: b[3],
                write_state: b[4],
                write_latch: b[5],
                rw_mode: b[6],
                mode: b[7],
                bcd: b[8],
                gate: b[9],
                count_load_time: c.count_load_time as i64,
            }
        }),
        flags: s.pit_flags,
        ..Default::default()
    }
}
#[cfg(feature = "native-device-probe")]
pub(crate) type ControllerWrites = [std::sync::atomic::AtomicU64; 5];

#[cfg(feature = "native-device-probe")]
fn observed_write(writes: &ControllerWrites, index: usize) {
    writes[index].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

pub(crate) fn capture_vm(
    fd: &VmFd,
    profile: &KvmCaptureProfile,
    retained: &mut Option<kvm_pit_state2>,
    #[cfg(feature = "native-device-probe")] writes: &ControllerWrites,
    permit: &NativeEffectsPermit,
) -> Result<KvmVmState, String> {
    validate_native(permit)?;
    let (host_kernel, host_mode) = host_clock_profile()?;
    let pit = match retained {
        Some(p) => *p,
        None => fd.get_pit2().map_err(|e| native_error("GET_PIT2", e))?,
    };
    let master = irqchip(fd, KVM_IRQCHIP_PIC_MASTER)?;
    let io = irqchip(fd, KVM_IRQCHIP_IOAPIC)?;
    let pit_profile = match profile {
        KvmCaptureProfile::ResetPit => {
            if pit.channels.iter().any(|c| c.mode != 255) {
                return Err("pit/reset/programmed-channel".into());
            }
            0
        }
        KvmCaptureProfile::RetiredLinuxPit {
            kernel_identity,
            clocksource_tsc,
            all_online_clockevents_deadline,
            broadcast_uses_pit,
            speaker_or_counter_consumer,
        } => {
            if kernel_identity.is_empty()
                || !*clocksource_tsc
                || !*all_online_clockevents_deadline
                || *broadcast_uses_pit
                || *speaker_or_counter_consumer
            {
                return Err("pit/profile/unobserved-passive-kernel".into());
            }
            if pit.flags & !KVM_PIT_FLAGS_HPET_LEGACY != 0 {
                return Err("pit/2/speaker-or-unknown-flags".into());
            }
            if unsafe { master.chip.pic.imr } & 1 == 0
                || unsafe { io.chip.ioapic.redirtbl[0].bits } & (1 << 16) == 0
            {
                return Err("pit/0/unmasked-route".into());
            }
            for (i, c) in pit.channels.iter().enumerate() {
                if c.count_latched != 0
                    || c.status_latched != 0
                    || c.write_state == 4
                    || c.read_state == 4
                {
                    return Err(format!("pit/{i}/partial-programming-or-latched-read"));
                }
                if i == 0 && !((c.mode == 0 && c.count == 65536) || c.mode == 255) {
                    return Err("pit/0/unqualified-retired-shape".into());
                }
                if i == 2 && c.gate != 0 && c.mode != 255 {
                    return Err("pit/2/active-speaker-counter".into());
                }
            }
            1
        }
    };
    // Own the original state before the first mutating ioctl, including partial failure.
    *retained = Some(pit);
    let mut inhibited = pit;
    inhibited.flags |= KVM_PIT_FLAGS_HPET_LEGACY;
    fd.set_pit2(&inhibited)
        .map_err(|e| native_error("SET_PIT2/passive-fence", e))?;
    #[cfg(feature = "native-device-probe")]
    observed_write(writes, 3);
    let m = irqchip(fd, KVM_IRQCHIP_PIC_MASTER)?;
    let s = irqchip(fd, KVM_IRQCHIP_PIC_SLAVE)?;
    let io = irqchip(fd, KVM_IRQCHIP_IOAPIC)?;
    let clock = fd.get_clock().map_err(|e| native_error("GET_CLOCK", e))?;
    let io = unsafe { io.chip.ioapic };
    let state = KvmVmState::X86(X86VmState {
        clock: clock.clock,
        clock_flags: clock.flags,
        host_tsc: clock.host_tsc,
        realtime: clock.realtime,
        host_kernel,
        host_mode,
        pit: pit.channels.map(pit_channel),
        pit_flags: pit.flags,
        pit_profile,
        pic: [pic(unsafe { m.chip.pic }), pic(unsafe { s.chip.pic })],
        ioapic_base: io.base_address,
        ioapic_select: io.ioregsel,
        ioapic_id: io.id,
        ioapic_irr: io.irr,
        ioapic_routes: io.redirtbl.map(|e| unsafe { e.bits }),
    });
    state.validate()?;
    Ok(state)
}
fn install_controllers(
    fd: &VmFd,
    s: &X86VmState,
    #[cfg(feature = "native-device-probe")] writes: &ControllerWrites,
) -> Result<(), String> {
    for (index, chip_id) in [KVM_IRQCHIP_PIC_MASTER, KVM_IRQCHIP_PIC_SLAVE]
        .into_iter()
        .enumerate()
    {
        let mut chip = kvm_irqchip {
            chip_id,
            ..Default::default()
        };
        chip.chip.pic = native_pic(s.pic[index]);
        fd.set_irqchip(&chip)
            .map_err(|e| native_error("SET_IRQCHIP/PIC", e))?;
        #[cfg(feature = "native-device-probe")]
        observed_write(writes, index);
    }
    let mut chip = kvm_irqchip {
        chip_id: KVM_IRQCHIP_IOAPIC,
        ..Default::default()
    };
    chip.chip.ioapic = kvm_ioapic_state {
        base_address: s.ioapic_base,
        ioregsel: s.ioapic_select,
        id: s.ioapic_id,
        irr: s.ioapic_irr,
        pad: 0,
        redirtbl: s
            .ioapic_routes
            .map(|bits| kvm_ioapic_state__bindgen_ty_1 { bits }),
    };
    fd.set_irqchip(&chip)
        .map_err(|e| native_error("SET_IRQCHIP/IOAPIC", e))?;
    #[cfg(feature = "native-device-probe")]
    observed_write(writes, 2);
    Ok(())
}
pub(crate) fn install_vm(
    fd: &VmFd,
    state: &KvmVmState,
    #[cfg(feature = "native-device-probe")] writes: &ControllerWrites,
    permit: &NativeEffectsPermit,
) -> Result<(), String> {
    validate_native(permit)?;
    state.validate()?;
    let KvmVmState::X86(s) = state else {
        return Err("kvm/vm/backend".into());
    };
    admit_host_clock(s)?;
    let mut pit = native_pit(s);
    pit.flags |= KVM_PIT_FLAGS_HPET_LEGACY;
    fd.set_pit2(&pit)
        .map_err(|e| native_error("SET_PIT2/install-fence", e))?;
    #[cfg(feature = "native-device-probe")]
    observed_write(writes, 3);
    install_controllers(
        fd,
        s,
        #[cfg(feature = "native-device-probe")]
        writes,
    )
}
pub(crate) fn prepare_vm_time(
    fd: &VmFd,
    state: &KvmVmState,
    cpus: &[KvmCpuState],
    observation: &mut Option<crate::vmm::linux::execution::KvmClockObservation>,
    #[cfg(feature = "native-device-probe")] writes: &ControllerWrites,
    permit: &NativeEffectsPermit,
) -> Result<Vec<KvmCpuTimePlan>, String> {
    validate_native(permit)?;
    let KvmVmState::X86(s) = state else {
        return Err("kvm/clock/backend".into());
    };
    admit_host_clock(s)?;
    let Some(KvmCpuState::X86(first)) = cpus.first() else {
        return Err("kvm/clock/no-cpus".into());
    };
    for cpu in cpus {
        let KvmCpuState::X86(c) = cpu else {
            return Err("kvm/clock/mixed-backend".into());
        };
        if c.tsc_khz != first.tsc_khz {
            return Err("kvm/clock/rate-disagreement".into());
        }
        if s.pit_profile == 1 && lapic_u32(&c.lapic, 0x350)? & (7 << 8) == (4 << 8) {
            return Err("pit/lvt0/virtual-wire-nmi".into());
        }
    }
    fd.set_pit2(&native_pit(s))
        .map_err(|e| native_error("SET_PIT2/passive-release", e))?;
    #[cfg(feature = "native-device-probe")]
    observed_write(writes, 3);
    install_controllers(
        fd,
        s,
        #[cfg(feature = "native-device-probe")]
        writes,
    )?;
    fd.set_clock(&kvm_clock_data {
        clock: s.clock,
        flags: 0,
        ..Default::default()
    })
    .map_err(|e| native_error("SET_CLOCK/final", e))?;
    #[cfg(feature = "native-device-probe")]
    observed_write(writes, 4);
    let destination = fd
        .get_clock()
        .map_err(|e| native_error("GET_CLOCK/final", e))?;
    *observation = Some(crate::vmm::linux::execution::KvmClockObservation {
        source: [s.clock, s.clock_flags.into(), s.host_tsc, s.realtime],
        destination: [
            destination.clock,
            destination.flags.into(),
            destination.host_tsc,
            destination.realtime,
        ],
    });
    if destination.flags & (KVM_CLOCK_HOST_TSC | KVM_CLOCK_TSC_STABLE)
        != (KVM_CLOCK_HOST_TSC | KVM_CLOCK_TSC_STABLE)
    {
        return Err("kvm/clock/destination-unpaired".into());
    }
    cpus.iter()
        .map(|cpu| {
            let KvmCpuState::X86(c) = cpu else {
                return Err("kvm/clock/backend".into());
            };
            Ok(KvmCpuTimePlan::X86 {
                id: c.id,
                offset: common_tsc_offset(
                    s.clock,
                    s.host_tsc,
                    c.tsc_offset,
                    destination.clock,
                    destination.host_tsc,
                    c.tsc_khz,
                )?,
                tsc_khz: c.tsc_khz,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::vmm::linux::execution::CpuCaptureConfig;
    use crate::vmm::linux::execution::native::{
        admit_cpuid, get_vcpu_attr, mce_inventory, verify_msr_count,
    };
    use kvm_bindings::{CpuId, kvm_cpuid_entry2};
    #[test]
    fn kvm_execution_mce_inventory_uses_actual_capability_banks() {
        let list = mce_inventory(3 | (1 << 8) | (1 << 10)).unwrap();
        assert!(list.contains(&0x17b));
        assert!(list.contains(&0x282));
        assert!(list.contains(&0x40b));
        assert!(!list.contains(&0x40c));
        assert!(mce_inventory(33).is_err());
    }
    #[test]
    fn kvm_execution_short_msr_transfer_names_first_missing_without_retry() {
        assert!(verify_msr_count(2, "SET_MSRS", 3, 3, None).is_ok());
        let error = verify_msr_count(2, "SET_MSRS", 3, 1, Some(0xc0010201)).unwrap_err();
        assert!(error.contains("cpu/2/SET_MSRS"));
        assert!(error.contains("first-missing=0xc0010201"));
        assert!(
            verify_msr_count(2, "GET_MSRS", 3, 4, None)
                .unwrap_err()
                .contains("invalid-completed-count=4")
        );
    }

    #[test]
    fn kvm_execution_get_device_attr_uses_input_descriptor_ioctl() {
        assert_eq!(get_vcpu_attr(), 0x4018_aee2);
    }

    fn admission_config(id: u8) -> CpuCaptureConfig {
        CpuCaptureConfig {
            logical_id: id,
            host_cpuid: CpuId::from_entries(&[kvm_cpuid_entry2 {
                function: 1,
                eax: 0xa20f10,
                ..Default::default()
            }])
            .unwrap(),
            raw_msrs: Vec::new(),
            xsave_size: 4096,
            deadline_supported: true,
        }
    }

    fn topology_cpuid(apic_id: u8, package_slots: u8, edx: u32, ecx: u32) -> CpuId {
        CpuId::from_entries(&[kvm_cpuid_entry2 {
            function: 1,
            eax: 0xa20f10,
            ebx: (u32::from(apic_id) << 24) | (u32::from(package_slots) << 16),
            ecx,
            edx,
            ..Default::default()
        }])
        .unwrap()
    }

    #[test]
    fn kvm_execution_cpuid_htt_uses_virtual_package_not_host_feature_mask() {
        for id in 0..2 {
            let config = admission_config(id);
            let guest = topology_cpuid(id, 2, 1 << 28, 0);
            assert!(admit_cpuid(&guest, &config).is_ok());
        }
        let guest = topology_cpuid(0, 1, 0, 0);
        assert!(admit_cpuid(&guest, &admission_config(0)).is_ok());
    }

    #[test]
    fn kvm_execution_cpuid_rejects_inconsistent_virtual_topology() {
        for (id, apic_id, slots, edx) in [
            (0, 0, 0, 0),
            (0, 0, 1, 1 << 28),
            (0, 0, 2, 0),
            (0, 0, 3, 1 << 28),
            (1, 0, 2, 1 << 28),
            (2, 2, 2, 1 << 28),
        ] {
            let guest = topology_cpuid(apic_id, slots, edx, 0);
            let error = admit_cpuid(&guest, &admission_config(id)).unwrap_err();
            assert!(error.contains("virtual-topology"), "{error}");
        }
    }

    #[test]
    fn kvm_execution_cpuid_topology_does_not_admit_unavailable_real_features() {
        for (edx, ecx, register) in [((1 << 28) | (1 << 25), 0, "edx"), (1 << 28, 1 << 28, "ecx")] {
            let guest = topology_cpuid(1, 2, edx, ecx);
            let error = admit_cpuid(&guest, &admission_config(1)).unwrap_err();
            assert!(error.contains("unsupported-feature"), "{error}");
            assert!(error.contains(&format!("register={register}")), "{error}");
            assert!(error.contains("unsupported-mask="), "{error}");
        }
    }
}
