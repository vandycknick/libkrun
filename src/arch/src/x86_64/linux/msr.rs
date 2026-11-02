// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Model Specific Registers (MSRs) related functionality.
use std::result;

use arch_gen::x86::msr_index::*;
use kvm_bindings::{MsrList, Msrs, kvm_msr_entry};
use kvm_ioctls::{Kvm, VcpuFd};

use crate::x86_64::msr::{Error, MTRR_ENABLE, MTRR_MEM_TYPE_WB};

type Result<T> = result::Result<T, Error>;

// Creates and populates required MSR entries for booting Linux on X86_64.
fn create_boot_msr_entries() -> Vec<kvm_msr_entry> {
    let msr_entry_default = |msr| kvm_msr_entry {
        index: msr,
        data: 0x0,
        ..Default::default()
    };

    vec![
        msr_entry_default(MSR_IA32_SYSENTER_CS),
        msr_entry_default(MSR_IA32_SYSENTER_ESP),
        msr_entry_default(MSR_IA32_SYSENTER_EIP),
        // x86_64 specific msrs, we only run on x86_64 not x86.
        msr_entry_default(MSR_STAR),
        msr_entry_default(MSR_CSTAR),
        msr_entry_default(MSR_KERNEL_GS_BASE),
        msr_entry_default(MSR_SYSCALL_MASK),
        msr_entry_default(MSR_LSTAR),
        // end of x86_64 specific code
        msr_entry_default(MSR_IA32_TSC),
        kvm_msr_entry {
            index: MSR_IA32_MISC_ENABLE,
            data: u64::from(MSR_IA32_MISC_ENABLE_FAST_STRING),
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_MTRRdefType,
            data: (MTRR_ENABLE | MTRR_MEM_TYPE_WB),
            ..Default::default()
        },
    ]
}

/// Configure Model Specific Registers (MSRs) required to boot Linux for a given x86_64 vCPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
pub fn setup_msrs(vcpu: &VcpuFd) -> Result<()> {
    let entry_vec = create_boot_msr_entries();
    let msrs =
        Msrs::from_entries(&entry_vec).map_err(|_| Error::ModelSpecificRegisterAllocation)?;
    vcpu.set_msrs(&msrs)
        .map_err(Error::SetModelSpecificRegisters)
        .and_then(|msrs_written| {
            if msrs_written as u32 != msrs.as_fam_struct_ref().nmsrs {
                Err(Error::SetModelSpecificRegistersCount)
            } else {
                Ok(())
            }
        })
}

/// The complete raw KVM index list. Classification belongs to the effective CPU contract.
pub fn supported_guest_msrs(kvm_fd: &Kvm) -> Result<MsrList> {
    kvm_fd
        .get_msr_index_list()
        .map_err(Error::GetSupportedModelSpecificRegisters)
}

#[cfg(test)]
mod tests {
    use crate::x86_64::linux::msr::{create_boot_msr_entries, setup_msrs};
    use arch_gen::x86::msr_index::*;
    use kvm_bindings::{Msrs, kvm_msr_entry};
    use kvm_ioctls::Kvm;

    #[test]
    #[allow(clippy::cast_ptr_alignment)]
    fn test_setup_msrs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        setup_msrs(&vcpu).unwrap();

        // This test will check against the last MSR entry configured (the tenth one).
        // See create_msr_entries() for details.
        let test_kvm_msrs_entry = [kvm_msr_entry {
            index: MSR_IA32_MISC_ENABLE,
            ..Default::default()
        }];
        let mut kvm_msrs_wrapper = Msrs::from_entries(&test_kvm_msrs_entry).unwrap();

        // Get_msrs() returns the number of msrs that it succeed in reading.
        // We only want to read one in this test case scenario.
        let read_nmsrs = vcpu.get_msrs(&mut kvm_msrs_wrapper).unwrap();
        // Validate it only read one.
        assert_eq!(read_nmsrs, 1);

        // Official entries that were setup when we did setup_msrs. We need to assert that the
        // tenth one (i.e the one with index MSR_IA32_MISC_ENABLE has the data we
        // expect.
        let entry_vec = create_boot_msr_entries();
        assert_eq!(entry_vec[9], kvm_msrs_wrapper.as_slice()[0]);
    }
}
