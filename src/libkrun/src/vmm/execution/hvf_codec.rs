use crate::vmm::execution::{HvfVmState, hvf};
use utils::state::{Error, Reader, Writer};

const HVF_CPU_STATE_MAGIC: &[u8; 8] = b"KRUNHCPU";
const HVF_CPU_STATE_SCHEMA: u16 = 1;
const HVF_VM_STATE_MAGIC: &[u8; 8] = b"KRUNHVMS";
const HVF_VM_STATE_SCHEMA: u16 = 1;

fn put_registers(values: &[hvf::RegisterValue], w: &mut Writer) -> Result<(), Error> {
    w.count(values.len(), 128)?;
    for value in values {
        w.u16(value.id)?;
        w.u64(value.value)?;
    }
    Ok(())
}

fn get_registers(r: &mut Reader<'_>) -> Result<Vec<hvf::RegisterValue>, Error> {
    let count = r.count(128, 10)?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(hvf::RegisterValue {
            id: r.u16()?,
            value: r.u64()?,
        });
    }
    Ok(values)
}

pub fn encode_cpu(state: &hvf::CpuState, w: &mut Writer) -> Result<(), Error> {
    state
        .validate()
        .map_err(|_| Error::Invalid("HVF CPU inventory"))?;
    w.header(HVF_CPU_STATE_MAGIC, HVF_CPU_STATE_SCHEMA)?;
    w.u8(state.logical_id)?;
    w.u64(state.mpidr)?;
    w.u64(state.frequency)?;
    put_registers(&state.model, w)?;
    for value in state.general {
        w.u64(value)?;
    }
    for value in &state.simd {
        w.fixed(value)?;
    }
    put_registers(&state.system, w)?;
    put_registers(&state.debug, w)?;
    put_registers(&state.icc, w)?;
    w.u64(state.timer.offset)?;
    w.bool(state.timer.masked)?;
    w.u64(state.timer.virtual_compare)?;
    w.u64(state.timer.virtual_control)?;
    w.u64(state.timer.physical_compare)?;
    w.u64(state.timer.physical_control)?;
    w.bool(state.pending_irq)?;
    w.bool(state.pending_fiq)?;
    w.u8(match state.software.disposition {
        hvf::CpuDisposition::Offline => 0,
        hvf::CpuDisposition::Runnable => 1,
        hvf::CpuDisposition::Waiting => 2,
    })?;
    w.count(state.software.pending_irqs.len(), hvf::MAX_PENDING_IRQS)?;
    for irq in &state.software.pending_irqs {
        w.u32(*irq)?;
    }
    w.bool(state.software.wake_pending)?;
    w.bool(state.software.cpu_on.is_some())?;
    if let Some(cpu_on) = state.software.cpu_on {
        w.u64(cpu_on.entry)?;
        w.u64(cpu_on.context)?;
    }
    Ok(())
}

pub fn decode_cpu(r: &mut Reader<'_>) -> Result<hvf::CpuState, Error> {
    r.header(HVF_CPU_STATE_MAGIC, HVF_CPU_STATE_SCHEMA)?;
    let logical_id = r.u8()?;
    let mpidr = r.u64()?;
    let frequency = r.u64()?;
    let model = get_registers(r)?;
    let mut general = [0; 35];
    for value in &mut general {
        *value = r.u64()?;
    }
    let mut simd = [[0; 16]; 32];
    for value in &mut simd {
        *value = r.fixed()?;
    }
    let system = get_registers(r)?;
    let debug = get_registers(r)?;
    let icc = get_registers(r)?;
    let timer = hvf::TimerState {
        offset: r.u64()?,
        masked: r.bool()?,
        virtual_compare: r.u64()?,
        virtual_control: r.u64()?,
        physical_compare: r.u64()?,
        physical_control: r.u64()?,
    };
    let pending_irq = r.bool()?;
    let pending_fiq = r.bool()?;
    let disposition = match r.u8()? {
        0 => hvf::CpuDisposition::Offline,
        1 => hvf::CpuDisposition::Runnable,
        2 => hvf::CpuDisposition::Waiting,
        _ => return Err(Error::Invalid("HVF CPU disposition")),
    };
    let count = r.count(hvf::MAX_PENDING_IRQS, 4)?;
    let mut pending_irqs = Vec::with_capacity(count);
    for _ in 0..count {
        pending_irqs.push(r.u32()?);
    }
    let wake_pending = r.bool()?;
    let cpu_on = if r.bool()? {
        Some(hvf::CpuOn {
            entry: r.u64()?,
            context: r.u64()?,
        })
    } else {
        None
    };
    let state = hvf::CpuState {
        logical_id,
        mpidr,
        frequency,
        model,
        general,
        simd,
        system,
        debug,
        icc,
        timer,
        pending_irq,
        pending_fiq,
        software: hvf::SoftwareState {
            disposition,
            pending_irqs,
            wake_pending,
            cpu_on,
        },
    };
    state
        .validate()
        .map_err(|_| Error::Invalid("HVF CPU inventory"))?;
    Ok(state)
}

pub fn encode_vm(state: &HvfVmState, w: &mut Writer) -> Result<(), Error> {
    state
        .clock
        .validate()
        .map_err(|_| Error::Invalid("HVF clock"))?;
    state
        .gic
        .validate()
        .map_err(|_| Error::Invalid("HVF GIC"))?;
    w.header(HVF_VM_STATE_MAGIC, HVF_VM_STATE_SCHEMA)?;
    w.u64(state.clock.host_counter)?;
    w.u64(state.clock.frequency)?;
    w.u32(state.clock.timebase_numer)?;
    w.u32(state.clock.timebase_denom)?;
    w.u8(state.gic.vcpu_count)?;
    for property in state.gic.properties {
        w.u64(property)?;
    }
    w.bytes(&state.gic.bytes, hvf::MAX_GIC_BYTES)
}

pub fn decode_vm(r: &mut Reader<'_>) -> Result<HvfVmState, Error> {
    r.header(HVF_VM_STATE_MAGIC, HVF_VM_STATE_SCHEMA)?;
    let clock = hvf::ClockCut {
        host_counter: r.u64()?,
        frequency: r.u64()?,
        timebase_numer: r.u32()?,
        timebase_denom: r.u32()?,
    };
    let vcpu_count = r.u8()?;
    let mut properties = [0; 4];
    for property in &mut properties {
        *property = r.u64()?;
    }
    let gic = hvf::GicState {
        vcpu_count,
        properties,
        bytes: r.bytes(hvf::MAX_GIC_BYTES)?.to_vec(),
    };
    clock.validate().map_err(|_| Error::Invalid("HVF clock"))?;
    gic.validate().map_err(|_| Error::Invalid("HVF GIC"))?;
    Ok(HvfVmState { clock, gic })
}

#[cfg(test)]
mod tests {
    use crate::vmm::execution::hvf_codec::{decode_cpu, decode_vm, encode_cpu, encode_vm};
    use crate::vmm::execution::{CpuExecutionState, VmExecutionState};
    use utils::state::{Error, Reader, StateHeaderError, Writer};

    #[test]
    fn hvf_cpu_and_vm_codecs_roundtrip_and_reject_wrong_headers() {
        let envelope = crate::vmm::execution::tests::envelope();
        let CpuExecutionState::Hvf(cpu) = &envelope.cpus[0] else {
            panic!("HVF fixture required");
        };
        let VmExecutionState::Hvf(vm) = &envelope.vm else {
            panic!("HVF fixture required");
        };
        let mut writer = Writer::new(65536);
        encode_cpu(cpu, &mut writer).unwrap();
        let cpu_bytes = writer.finish();
        let mut reader = Reader::new(&cpu_bytes);
        assert_eq!(&decode_cpu(&mut reader).unwrap(), cpu);
        reader.finish().unwrap();
        let mut writer = Writer::new(65536);
        encode_vm(vm, &mut writer).unwrap();
        let vm_bytes = writer.finish();
        let mut reader = Reader::new(&vm_bytes);
        assert_eq!(&decode_vm(&mut reader).unwrap(), vm);
        reader.finish().unwrap();
        for (bytes, is_cpu) in [(cpu_bytes, true), (vm_bytes, false)] {
            for offset in [0, 8] {
                let mut wrong = bytes.clone();
                wrong[offset] ^= 1;
                let mut reader = Reader::new(&wrong);
                let result = if is_cpu {
                    decode_cpu(&mut reader).map(|_| ())
                } else {
                    decode_vm(&mut reader).map(|_| ())
                };
                match offset {
                    0 => assert!(matches!(
                        result,
                        Err(Error::Header(StateHeaderError::Magic { .. }))
                    )),
                    _ => assert!(matches!(
                        result,
                        Err(Error::Header(StateHeaderError::Schema { .. }))
                    )),
                }
            }
        }
    }
}
