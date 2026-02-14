// Copyright 2021 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

#[allow(non_camel_case_types)]
#[allow(improper_ctypes)]
#[allow(dead_code)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[allow(deref_nullptr)]
pub mod bindings;

#[macro_use]
extern crate log;

use bindings::*;

#[cfg(target_arch = "aarch64")]
use std::arch::asm;

use std::convert::TryInto;
use std::ffi::c_void;
use std::fmt::{Display, Formatter};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

#[cfg(feature = "snapshot")]
use serde::{Deserialize, Serialize};

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
use arch::aarch64::sysreg::{sys_reg_name, SYSREG_MASK};
use log::debug;

extern "C" {
    pub fn mach_absolute_time() -> u64;
}

const HV_EXIT_REASON_CANCELED: hv_exit_reason_t = 0;
const HV_EXIT_REASON_EXCEPTION: hv_exit_reason_t = 1;
const HV_EXIT_REASON_VTIMER_ACTIVATED: hv_exit_reason_t = 2;

const TMR_CTL_ENABLE: u64 = 1 << 0;
const TMR_CTL_IMASK: u64 = 1 << 1;
const TMR_CTL_ISTATUS: u64 = 1 << 2;

const PSR_MODE_EL1H: u64 = 0x0000_0005;
const PSR_MODE_EL2H: u64 = 0x0000_0009;
const PSR_F_BIT: u64 = 0x0000_0040;
const PSR_I_BIT: u64 = 0x0000_0080;
const PSR_A_BIT: u64 = 0x0000_0100;
const PSR_D_BIT: u64 = 0x0000_0200;
const PSTATE_EL1_FAULT_BITS_64: u64 = PSR_MODE_EL1H | PSR_A_BIT | PSR_F_BIT | PSR_I_BIT | PSR_D_BIT;
const PSTATE_EL2_FAULT_BITS_64: u64 = PSR_MODE_EL2H | PSR_A_BIT | PSR_F_BIT | PSR_I_BIT | PSR_D_BIT;

const HCR_TLOR: u64 = 1 << 35;
const HCR_RW: u64 = 1 << 31;
const HCR_TSW: u64 = 1 << 22;
const HCR_TACR: u64 = 1 << 21;
const HCR_TIDCP: u64 = 1 << 20;
const HCR_TSC: u64 = 1 << 19;
const HCR_TID3: u64 = 1 << 18;
const HCR_TWE: u64 = 1 << 14;
const HCR_TWI: u64 = 1 << 13;
const HCR_BSU_IS: u64 = 1 << 10;
const HCR_FB: u64 = 1 << 9;
const HCR_AMO: u64 = 1 << 5;
const HCR_IMO: u64 = 1 << 4;
const HCR_FMO: u64 = 1 << 3;
const HCR_PTW: u64 = 1 << 2;
const HCR_SWIO: u64 = 1 << 1;
const HCR_VM: u64 = 1 << 0;
// Use the same bits as KVM uses in vcpu reset.
const HCR_EL2_BITS: u64 = HCR_TSC
    | HCR_TSW
    | HCR_TWE
    | HCR_TWI
    | HCR_VM
    | HCR_BSU_IS
    | HCR_FB
    | HCR_TACR
    | HCR_AMO
    | HCR_SWIO
    | HCR_TIDCP
    | HCR_RW
    | HCR_TLOR
    | HCR_FMO
    | HCR_IMO
    | HCR_PTW
    | HCR_TID3;

const CNTHCTL_EL0VCTEN: u64 = 1 << 1;
const CNTHCTL_EL0PCTEN: u64 = 1 << 0;
// Trap accesses to both virtual and physical counter registers.
const CNTHCTL_EL2_BITS: u64 = CNTHCTL_EL0VCTEN | CNTHCTL_EL0PCTEN;

const AA64PFR0_EL1_EL2EN: u64 = 1 << 8;
const AA64PFR0_EL1_GIC3EN: u64 = 1 << 24;
const AA64PFR1_EL1_SMEMASK: u64 = 3 << 24;

const EC_WFX_TRAP: u64 = 0x1;
const EC_AA64_HVC: u64 = 0x16;
const EC_AA64_SMC: u64 = 0x17;
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
const EC_SYSTEMREGISTERTRAP: u64 = 0x18;
const EC_DATAABORT: u64 = 0x24;
const EC_AA64_BKPT: u64 = 0x3c;

/// Apple Silicon page size (16KB).
const PAGE_SIZE_16K: u64 = 16384;

#[cfg(feature = "snapshot")]
mod serde_array_u64_35 {
    use serde::de::{self, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &[u64; 35], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tuple = serializer.serialize_tuple(35)?;
        for item in value {
            tuple.serialize_element(item)?;
        }
        tuple.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u64; 35], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct U64ArrayVisitor;

        impl<'de> Visitor<'de> for U64ArrayVisitor {
            type Value = [u64; 35];

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an array with exactly 35 u64 values")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = [0u64; 35];
                for (i, slot) in values.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                if seq.next_element::<u64>()?.is_some() {
                    return Err(de::Error::invalid_length(36, &self));
                }
                Ok(values)
            }
        }

        deserializer.deserialize_tuple(35, U64ArrayVisitor)
    }
}

#[derive(Debug)]
pub enum Error {
    EnableEL2,
    FindSymbol(libloading::Error),
    MemoryMap,
    MemoryProtect,
    MemoryUnmap,
    NestedCheck,
    VcpuCreate,
    VcpuInitialRegisters,
    VcpuReadRegister,
    VcpuReadSimdFpRegister,
    VcpuReadSystemRegister,
    VcpuRequestExit,
    VcpuRun,
    VcpuSetPendingIrq,
    VcpuSetRegister,
    VcpuSetSimdFpRegister,
    VcpuSetSystemRegister(u16, u64),
    VcpuSetVtimerMask,
    VcpuSetVtimerOffset,
    VcpuGetVtimerOffset,
    GicStateCreate,
    GicStateSize,
    GicStateRead,
    GicStateRestore,
    VmCreate,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::Error::*;

        match self {
            EnableEL2 => write!(f, "Error enabling EL2 mode in HVF"),
            FindSymbol(ref err) => write!(f, "Couldn't find symbol in HVF library: {err}"),
            MemoryMap => write!(f, "Error registering memory region in HVF"),
            MemoryProtect => write!(f, "Error changing memory protection in HVF"),
            MemoryUnmap => write!(f, "Error unregistering memory region in HVF"),
            NestedCheck => write!(
                f,
                "Nested virtualization was requested but it's not support in this system"
            ),
            VcpuCreate => write!(f, "Error creating HVF vCPU instance"),
            VcpuInitialRegisters => write!(f, "Error setting up initial HVF vCPU registers"),
            VcpuReadRegister => write!(f, "Error reading HVF vCPU register"),
            VcpuReadSimdFpRegister => write!(f, "Error reading HVF vCPU SIMD/FP register"),
            VcpuReadSystemRegister => write!(f, "Error reading HVF vCPU system register"),
            VcpuRequestExit => write!(f, "Error requesting HVF vCPU exit"),
            VcpuRun => write!(f, "Error running HVF vCPU"),
            VcpuSetPendingIrq => write!(f, "Error setting HVF vCPU pending irq"),
            VcpuSetRegister => write!(f, "Error setting HVF vCPU register"),
            VcpuSetSimdFpRegister => write!(f, "Error setting HVF vCPU SIMD/FP register"),
            VcpuSetSystemRegister(reg, val) => write!(
                f,
                "Error setting HVF vCPU system register 0x{reg:#x} to 0x{val:#x}"
            ),
            VcpuSetVtimerMask => write!(f, "Error setting HVF vCPU vtimer mask"),
            VcpuSetVtimerOffset => write!(f, "Error setting HVF vCPU vtimer offset"),
            VcpuGetVtimerOffset => write!(f, "Error getting HVF vCPU vtimer offset"),
            GicStateCreate => write!(f, "Error creating HVF GIC state object"),
            GicStateSize => write!(f, "Error obtaining HVF GIC state size"),
            GicStateRead => write!(f, "Error reading HVF GIC state data"),
            GicStateRestore => write!(f, "Error restoring HVF GIC state data"),
            VmCreate => write!(f, "Error creating HVF VM instance"),
        }
    }
}

pub fn save_gic_state() -> Result<Vec<u8>, Error> {
    let state = unsafe { hv_gic_state_create() };
    if state.is_null() {
        return Err(Error::GicStateCreate);
    }

    let mut size: usize = 0;
    let size_ret = unsafe { hv_gic_state_get_size(state, &mut size as *mut usize) };
    if size_ret != HV_SUCCESS {
        unsafe { os_release(state as *mut c_void) };
        return Err(Error::GicStateSize);
    }

    let mut data = vec![0u8; size];
    let data_ret = unsafe { hv_gic_state_get_data(state, data.as_mut_ptr() as *mut c_void) };
    unsafe { os_release(state as *mut c_void) };

    if data_ret != HV_SUCCESS {
        return Err(Error::GicStateRead);
    }

    Ok(data)
}

pub fn restore_gic_state(data: &[u8]) -> Result<(), Error> {
    let ret = unsafe { hv_gic_set_state(data.as_ptr() as *const c_void, data.len()) };
    if ret != HV_SUCCESS {
        return Err(Error::GicStateRestore);
    }
    Ok(())
}

pub enum InterruptType {
    Irq,
    Fiq,
}

pub trait Vcpus {
    fn set_vtimer_irq(&self, vcpuid: u64);
    fn should_wait(&self, vcpuid: u64) -> bool;
    fn has_pending_irq(&self, vcpuid: u64) -> bool;
    fn get_pending_irq(&self, vcpuid: u64) -> u32;
    fn handle_sysreg_read(&self, vcpuid: u64, reg: u32) -> Option<u64>;
    fn handle_sysreg_write(&self, vcpuid: u64, reg: u32, val: u64) -> bool;
    /// Get the virtual timer offset (CNTVOFF_EL2) for cross-timestamping.
    /// Returns the offset that converts host counter to guest counter:
    /// guest_counter = host_counter - vtimer_offset
    fn get_vtimer_offset(&self, vcpuid: u64) -> Option<u64>;
}

pub fn vcpu_request_exit(vcpuid: u64) -> Result<(), Error> {
    let mut vcpu: u64 = vcpuid;
    let ret = unsafe { hv_vcpus_exit(&mut vcpu, 1) };

    if ret != HV_SUCCESS {
        Err(Error::VcpuRequestExit)
    } else {
        Ok(())
    }
}

pub fn vcpu_set_pending_irq(
    vcpuid: u64,
    irq_type: InterruptType,
    pending: bool,
) -> Result<(), Error> {
    let _type = match irq_type {
        InterruptType::Irq => hv_interrupt_type_t_HV_INTERRUPT_TYPE_IRQ,
        InterruptType::Fiq => hv_interrupt_type_t_HV_INTERRUPT_TYPE_FIQ,
    };

    let ret = unsafe { hv_vcpu_set_pending_interrupt(vcpuid, _type, pending) };

    if ret != HV_SUCCESS {
        Err(Error::VcpuSetPendingIrq)
    } else {
        Ok(())
    }
}

pub fn vcpu_set_vtimer_mask(vcpuid: u64, masked: bool) -> Result<(), Error> {
    let ret = unsafe { hv_vcpu_set_vtimer_mask(vcpuid, masked) };

    if ret != HV_SUCCESS {
        Err(Error::VcpuSetVtimerMask)
    } else {
        Ok(())
    }
}

/// Set the virtual timer offset (CNTVOFF_EL2) for a vCPU.
/// This controls the value the guest sees when reading CNTVCT_EL0:
/// guest_cntvct = host_cntvct - vtimer_offset
pub fn vcpu_set_vtimer_offset(vcpuid: u64, offset: u64) -> Result<(), Error> {
    let ret = unsafe { hv_vcpu_set_vtimer_offset(vcpuid, offset) };

    if ret != HV_SUCCESS {
        Err(Error::VcpuSetVtimerOffset)
    } else {
        Ok(())
    }
}

/// Get the virtual timer offset (CNTVOFF_EL2) for a vCPU.
pub fn vcpu_get_vtimer_offset(vcpuid: u64) -> Result<u64, Error> {
    let mut offset: u64 = 0;
    let ret = unsafe { hv_vcpu_get_vtimer_offset(vcpuid, &mut offset) };

    if ret != HV_SUCCESS {
        Err(Error::VcpuGetVtimerOffset)
    } else {
        Ok(offset)
    }
}

/// Checks if Nested Virtualization is supported on the current system. Only
/// M3 or newer chips on macOS 15+ will satisfy the requirements.
pub fn check_nested_virt() -> Result<bool, Error> {
    type GetEL2Supported =
        libloading::Symbol<'static, unsafe extern "C" fn(*mut bool) -> hv_return_t>;

    let get_el2_supported: Result<GetEL2Supported, libloading::Error> =
        unsafe { HVF.get(b"hv_vm_config_get_el2_supported") };
    if get_el2_supported.is_err() {
        info!("cannot find hv_vm_config_get_el2_supported symbol");
        return Ok(false);
    }

    let mut el2_supported: bool = false;
    let ret = unsafe { (get_el2_supported.unwrap())(&mut el2_supported) };
    if ret != HV_SUCCESS {
        error!("hv_vm_config_get_el2_supported failed: {ret:?}");
        return Err(Error::NestedCheck);
    }

    Ok(el2_supported)
}

pub struct HvfVm {}

static HVF: LazyLock<libloading::Library> = LazyLock::new(|| unsafe {
    libloading::Library::new(
        "/System/Library/Frameworks/Hypervisor.framework/Versions/A/Hypervisor",
    )
    .unwrap()
});

impl HvfVm {
    pub fn new(nested_enabled: bool) -> Result<Self, Error> {
        let config = unsafe { hv_vm_config_create() };
        if nested_enabled {
            let set_el2_enabled: libloading::Symbol<
                'static,
                unsafe extern "C" fn(hv_vm_config_t, bool) -> hv_return_t,
            > = unsafe {
                HVF.get(b"hv_vm_config_set_el2_enabled")
                    .map_err(Error::FindSymbol)?
            };

            let ret = unsafe { (set_el2_enabled)(config, true) };
            if ret != HV_SUCCESS {
                return Err(Error::EnableEL2);
            }
        }

        let ret = unsafe { hv_vm_create(config) };

        if ret != HV_SUCCESS {
            Err(Error::VmCreate)
        } else {
            Ok(Self {})
        }
    }

    pub fn map_memory(
        &self,
        host_start_addr: u64,
        guest_start_addr: u64,
        size: u64,
    ) -> Result<(), Error> {
        let ret = unsafe {
            hv_vm_map(
                host_start_addr as *mut core::ffi::c_void,
                guest_start_addr,
                size.try_into().unwrap(),
                (HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC).into(),
            )
        };
        if ret != HV_SUCCESS {
            Err(Error::MemoryMap)
        } else {
            Ok(())
        }
    }

    pub fn unmap_memory(&self, guest_start_addr: u64, size: u64) -> Result<(), Error> {
        let ret = unsafe { hv_vm_unmap(guest_start_addr, size.try_into().unwrap()) };
        if ret != HV_SUCCESS {
            Err(Error::MemoryUnmap)
        } else {
            Ok(())
        }
    }

    /// Change memory protection flags for a guest memory region.
    pub fn protect_memory(
        guest_addr: u64,
        size: u64,
        read: bool,
        write: bool,
        exec: bool,
    ) -> Result<(), Error> {
        let mut flags: u64 = 0;
        if read {
            flags |= HV_MEMORY_READ as u64;
        }
        if write {
            flags |= HV_MEMORY_WRITE as u64;
        }
        if exec {
            flags |= HV_MEMORY_EXEC as u64;
        }
        let ret = unsafe { hv_vm_protect(guest_addr, size.try_into().unwrap(), flags) };
        if ret != HV_SUCCESS {
            Err(Error::MemoryProtect)
        } else {
            Ok(())
        }
    }
}

/// System registers that should be saved/restored for vCPU snapshot.
/// These cover EL1 core regs, thread regs, timer regs, PAC keys, and debug regs.
pub const SAVEABLE_SYS_REGS: &[u16] = &[
    // EL1 core registers
    hv_sys_reg_t_HV_SYS_REG_SCTLR_EL1,
    hv_sys_reg_t_HV_SYS_REG_ACTLR_EL1,
    hv_sys_reg_t_HV_SYS_REG_CPACR_EL1,
    hv_sys_reg_t_HV_SYS_REG_TTBR0_EL1,
    hv_sys_reg_t_HV_SYS_REG_TTBR1_EL1,
    hv_sys_reg_t_HV_SYS_REG_TCR_EL1,
    hv_sys_reg_t_HV_SYS_REG_SPSR_EL1,
    hv_sys_reg_t_HV_SYS_REG_ELR_EL1,
    hv_sys_reg_t_HV_SYS_REG_SP_EL0,
    hv_sys_reg_t_HV_SYS_REG_SP_EL1,
    hv_sys_reg_t_HV_SYS_REG_AFSR0_EL1,
    hv_sys_reg_t_HV_SYS_REG_AFSR1_EL1,
    hv_sys_reg_t_HV_SYS_REG_ESR_EL1,
    hv_sys_reg_t_HV_SYS_REG_FAR_EL1,
    hv_sys_reg_t_HV_SYS_REG_PAR_EL1,
    hv_sys_reg_t_HV_SYS_REG_MAIR_EL1,
    hv_sys_reg_t_HV_SYS_REG_AMAIR_EL1,
    hv_sys_reg_t_HV_SYS_REG_VBAR_EL1,
    hv_sys_reg_t_HV_SYS_REG_CONTEXTIDR_EL1,
    hv_sys_reg_t_HV_SYS_REG_CSSELR_EL1,
    hv_sys_reg_t_HV_SYS_REG_CNTKCTL_EL1,
    // Thread registers
    hv_sys_reg_t_HV_SYS_REG_TPIDR_EL0,
    hv_sys_reg_t_HV_SYS_REG_TPIDRRO_EL0,
    hv_sys_reg_t_HV_SYS_REG_TPIDR_EL1,
    // Timer registers
    hv_sys_reg_t_HV_SYS_REG_CNTV_CTL_EL0,
    hv_sys_reg_t_HV_SYS_REG_CNTV_CVAL_EL0,
    hv_sys_reg_t_HV_SYS_REG_CNTP_CTL_EL0,
    hv_sys_reg_t_HV_SYS_REG_CNTP_CVAL_EL0,
    hv_sys_reg_t_HV_SYS_REG_CNTP_TVAL_EL0,
    // PAC keys
    hv_sys_reg_t_HV_SYS_REG_APIAKEYLO_EL1,
    hv_sys_reg_t_HV_SYS_REG_APIAKEYHI_EL1,
    hv_sys_reg_t_HV_SYS_REG_APIBKEYLO_EL1,
    hv_sys_reg_t_HV_SYS_REG_APIBKEYHI_EL1,
    hv_sys_reg_t_HV_SYS_REG_APDAKEYLO_EL1,
    hv_sys_reg_t_HV_SYS_REG_APDAKEYHI_EL1,
    hv_sys_reg_t_HV_SYS_REG_APDBKEYLO_EL1,
    hv_sys_reg_t_HV_SYS_REG_APDBKEYHI_EL1,
    hv_sys_reg_t_HV_SYS_REG_APGAKEYLO_EL1,
    hv_sys_reg_t_HV_SYS_REG_APGAKEYHI_EL1,
    // Debug registers
    hv_sys_reg_t_HV_SYS_REG_MDCCINT_EL1,
    hv_sys_reg_t_HV_SYS_REG_MDSCR_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBVR0_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBCR0_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWVR0_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWCR0_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBVR1_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBCR1_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWVR1_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWCR1_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBVR2_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBCR2_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWVR2_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWCR2_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBVR3_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBCR3_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWVR3_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWCR3_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBVR4_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBCR4_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWVR4_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWCR4_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBVR5_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBCR5_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWVR5_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWCR5_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBVR6_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGBCR6_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWVR6_EL1,
    hv_sys_reg_t_HV_SYS_REG_DBGWCR6_EL1,
];

/// Additional EL2 system registers to save/restore when nested virtualization is enabled.
pub const SAVEABLE_SYS_REGS_EL2: &[u16] = &[
    hv_sys_reg_t_HV_SYS_REG_HCR_EL2,
    hv_sys_reg_t_HV_SYS_REG_SCTLR_EL2,
    hv_sys_reg_t_HV_SYS_REG_CPTR_EL2,
    hv_sys_reg_t_HV_SYS_REG_TTBR0_EL2,
    hv_sys_reg_t_HV_SYS_REG_TTBR1_EL2,
    hv_sys_reg_t_HV_SYS_REG_TCR_EL2,
    hv_sys_reg_t_HV_SYS_REG_VTTBR_EL2,
    hv_sys_reg_t_HV_SYS_REG_VTCR_EL2,
    hv_sys_reg_t_HV_SYS_REG_SPSR_EL2,
    hv_sys_reg_t_HV_SYS_REG_ELR_EL2,
    hv_sys_reg_t_HV_SYS_REG_SP_EL2,
    hv_sys_reg_t_HV_SYS_REG_ESR_EL2,
    hv_sys_reg_t_HV_SYS_REG_FAR_EL2,
    hv_sys_reg_t_HV_SYS_REG_HPFAR_EL2,
    hv_sys_reg_t_HV_SYS_REG_MAIR_EL2,
    hv_sys_reg_t_HV_SYS_REG_VBAR_EL2,
    hv_sys_reg_t_HV_SYS_REG_MDCR_EL2,
    hv_sys_reg_t_HV_SYS_REG_TPIDR_EL2,
    hv_sys_reg_t_HV_SYS_REG_VMPIDR_EL2,
    hv_sys_reg_t_HV_SYS_REG_VPIDR_EL2,
    hv_sys_reg_t_HV_SYS_REG_CNTHCTL_EL2,
    hv_sys_reg_t_HV_SYS_REG_CNTHP_CTL_EL2,
    hv_sys_reg_t_HV_SYS_REG_CNTHP_CVAL_EL2,
    hv_sys_reg_t_HV_SYS_REG_CNTHP_TVAL_EL2,
    hv_sys_reg_t_HV_SYS_REG_CNTVOFF_EL2,
];

/// Complete vCPU state for snapshot/restore.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "snapshot", derive(Serialize, Deserialize))]
pub struct Aarch64VcpuState {
    /// X0-X30, PC, FPCR, FPSR, CPSR (35 registers total, indexed by HV_REG_* constants)
    #[cfg_attr(feature = "snapshot", serde(with = "serde_array_u64_35"))]
    pub gp_regs: [u64; 35],
    /// Q0-Q31 SIMD/FP registers
    pub simd_fp_regs: [u128; 32],
    /// System registers as (reg_id, value) pairs
    pub sys_regs: Vec<(u16, u64)>,
    /// Virtual timer offset
    pub vtimer_offset: u64,
    /// Whether the virtual timer interrupt was masked
    pub vtimer_masked: bool,
    /// Whether a PC advance was pending at the time of save
    pub pending_advance_pc: bool,
}

#[derive(Debug)]
pub enum VcpuExit<'a> {
    Breakpoint,
    Canceled,
    CpuOn(u64, u64, u64),
    /// A write fault on a write-protected RAM page (dirty tracking).
    /// Contains the faulting guest physical address.
    DirtyPageFault(u64),
    HypervisorCall,
    MmioRead(u64, &'a mut [u8]),
    MmioWrite(u64, &'a [u8]),
    PsciHandled,
    SecureMonitorCall,
    Shutdown,
    SystemRegister,
    VtimerActivated,
    WaitForEvent,
    WaitForEventExpired,
    WaitForEventTimeout(Duration),
}

struct MmioRead {
    addr: u64,
    len: usize,
    srt: u32,
}

/// Callback type for dirty page tracking. Takes the faulting guest physical address.
pub type DirtyCallback = Box<dyn Fn(u64) + Send>;

pub struct HvfVcpu<'a> {
    vcpuid: hv_vcpu_t,
    vcpu_exit: &'a hv_vcpu_exit_t,
    cntfrq: u64,
    mmio_buf: [u8; 8],
    pending_mmio_read: Option<MmioRead>,
    pending_advance_pc: bool,
    vtimer_masked: bool,
    nested_enabled: bool,
    /// When true, RAM write faults are treated as dirty page faults
    /// rather than MMIO accesses.
    pub dirty_tracking_enabled: bool,
    /// Guest physical address ranges that are RAM: (start, size) pairs.
    /// Used to distinguish RAM faults from MMIO faults when dirty tracking is on.
    pub ram_regions: Vec<(u64, u64)>,
    /// Callback invoked when a dirty page fault occurs.
    pub dirty_callback: Option<DirtyCallback>,
}

impl HvfVcpu<'_> {
    pub fn new(mpidr: u64, nested_enabled: bool) -> Result<Self, Error> {
        let mut vcpuid: hv_vcpu_t = 0;
        let vcpu_exit_ptr: *mut hv_vcpu_exit_t = std::ptr::null_mut();

        #[cfg(target_arch = "aarch64")]
        let cntfrq = {
            let cntfrq: u64;
            unsafe { asm!("mrs {}, cntfrq_el0", out(reg) cntfrq) };
            cntfrq
        };
        #[cfg(target_arch = "x86_64")]
        let cntfrq = 0u64;
        #[cfg(target_arch = "riscv64")]
        let cntfrq = 0u64;

        let ret = unsafe {
            hv_vcpu_create(
                &mut vcpuid,
                &vcpu_exit_ptr as *const _ as *mut *mut _,
                std::ptr::null_mut(),
            )
        };
        if ret != HV_SUCCESS {
            return Err(Error::VcpuCreate);
        }

        // We write vcpuid to Aff1 as otherwise it won't match the redistributor ID
        // when using HVF in-kernel GICv3.
        let ret = unsafe { hv_vcpu_set_sys_reg(vcpuid, hv_sys_reg_t_HV_SYS_REG_MPIDR_EL1, mpidr) };
        if ret != HV_SUCCESS {
            return Err(Error::VcpuCreate);
        }

        let vcpu_exit: &hv_vcpu_exit_t = unsafe { vcpu_exit_ptr.as_mut().unwrap() };

        Ok(Self {
            vcpuid,
            vcpu_exit,
            cntfrq,
            mmio_buf: [0; 8],
            pending_mmio_read: None,
            pending_advance_pc: false,
            vtimer_masked: false,
            nested_enabled,
            dirty_tracking_enabled: false,
            ram_regions: Vec::new(),
            dirty_callback: None,
        })
    }

    pub fn set_initial_state(&self, entry_addr: u64, fdt_addr: u64) -> Result<(), Error> {
        if self.nested_enabled {
            let ret = unsafe {
                hv_vcpu_set_reg(self.vcpuid, hv_reg_t_HV_REG_CPSR, PSTATE_EL2_FAULT_BITS_64)
            };
            if ret != HV_SUCCESS {
                return Err(Error::VcpuInitialRegisters);
            }

            let ret = unsafe {
                hv_vcpu_set_sys_reg(self.vcpuid, hv_sys_reg_t_HV_SYS_REG_HCR_EL2, HCR_EL2_BITS)
            };
            if ret != HV_SUCCESS {
                return Err(Error::VcpuInitialRegisters);
            }

            let ret = unsafe {
                hv_vcpu_set_sys_reg(
                    self.vcpuid,
                    hv_sys_reg_t_HV_SYS_REG_CNTHCTL_EL2,
                    CNTHCTL_EL2_BITS,
                )
            };
            if ret != HV_SUCCESS {
                return Err(Error::VcpuInitialRegisters);
            }

            // Enable EL2 and GICv3 in ID_AA64PFR0_EL1
            let val: u64 = 0;
            let ret = unsafe {
                hv_vcpu_get_sys_reg(
                    self.vcpuid,
                    hv_sys_reg_t_HV_SYS_REG_ID_AA64PFR0_EL1,
                    &val as *const _ as *mut _,
                )
            };
            if ret != HV_SUCCESS {
                return Err(Error::VcpuInitialRegisters);
            }
            let ret = unsafe {
                hv_vcpu_set_sys_reg(
                    self.vcpuid,
                    hv_sys_reg_t_HV_SYS_REG_ID_AA64PFR0_EL1,
                    val | AA64PFR0_EL1_EL2EN | AA64PFR0_EL1_GIC3EN,
                )
            };
            if ret != HV_SUCCESS {
                return Err(Error::VcpuInitialRegisters);
            }

            // If SME is enabled in ID_AA64PFR1_EL1 in the VM, the guest will
            // break after enabling the MMU. Mask it out.
            let val: u64 = 0;
            let ret = unsafe {
                hv_vcpu_get_sys_reg(
                    self.vcpuid,
                    hv_sys_reg_t_HV_SYS_REG_ID_AA64PFR1_EL1,
                    &val as *const _ as *mut _,
                )
            };
            if ret != HV_SUCCESS {
                return Err(Error::VcpuInitialRegisters);
            }
            let ret = unsafe {
                hv_vcpu_set_sys_reg(
                    self.vcpuid,
                    hv_sys_reg_t_HV_SYS_REG_ID_AA64PFR1_EL1,
                    val & !AA64PFR1_EL1_SMEMASK,
                )
            };
            if ret != HV_SUCCESS {
                return Err(Error::VcpuInitialRegisters);
            }
        } else {
            let ret = unsafe {
                hv_vcpu_set_reg(self.vcpuid, hv_reg_t_HV_REG_CPSR, PSTATE_EL1_FAULT_BITS_64)
            };
            if ret != HV_SUCCESS {
                return Err(Error::VcpuInitialRegisters);
            }
        }

        let ret = unsafe { hv_vcpu_set_reg(self.vcpuid, hv_reg_t_HV_REG_PC, entry_addr) };
        if ret != HV_SUCCESS {
            return Err(Error::VcpuInitialRegisters);
        }

        let ret = unsafe { hv_vcpu_set_reg(self.vcpuid, hv_reg_t_HV_REG_X0, fdt_addr) };
        if ret != HV_SUCCESS {
            return Err(Error::VcpuInitialRegisters);
        }

        Ok(())
    }

    pub fn id(&self) -> u64 {
        self.vcpuid
    }

    pub fn pending_advance_pc(&self) -> bool {
        self.pending_advance_pc
    }

    pub fn vtimer_masked(&self) -> bool {
        self.vtimer_masked
    }

    pub fn read_reg(&self, reg: u32) -> Result<u64, Error> {
        let val: u64 = 0;
        let ret = unsafe { hv_vcpu_get_reg(self.vcpuid, reg, &val as *const _ as *mut _) };
        if ret != HV_SUCCESS {
            Err(Error::VcpuReadRegister)
        } else {
            Ok(val)
        }
    }

    pub fn write_reg(&self, rt: u32, val: u64) -> Result<(), Error> {
        let ret = unsafe { hv_vcpu_set_reg(self.vcpuid, rt, val) };
        if ret != HV_SUCCESS {
            Err(Error::VcpuSetRegister)
        } else {
            Ok(())
        }
    }

    pub fn read_sys_reg(&self, reg: u16) -> Result<u64, Error> {
        let val: u64 = 0;
        let ret = unsafe { hv_vcpu_get_sys_reg(self.vcpuid, reg, &val as *const _ as *mut _) };
        if ret != HV_SUCCESS {
            Err(Error::VcpuReadSystemRegister)
        } else {
            Ok(val)
        }
    }

    pub fn write_sys_reg(&self, reg: u16, val: u64) -> Result<(), Error> {
        let ret = unsafe { hv_vcpu_set_sys_reg(self.vcpuid, reg, val) };
        if ret != HV_SUCCESS {
            Err(Error::VcpuSetSystemRegister(reg, val))
        } else {
            Ok(())
        }
    }

    /// Read a SIMD/FP register (Q0-Q31). Returns a 128-bit value.
    pub fn read_simd_fp_reg(&self, reg: u32) -> Result<u128, Error> {
        let val: u128 = 0;
        let ret = unsafe { hv_vcpu_get_simd_fp_reg(self.vcpuid, reg, &val as *const _ as *mut _) };
        if ret != HV_SUCCESS {
            Err(Error::VcpuReadSimdFpRegister)
        } else {
            Ok(val)
        }
    }

    /// Write a SIMD/FP register (Q0-Q31) with a 128-bit value.
    pub fn write_simd_fp_reg(&self, reg: u32, val: u128) -> Result<(), Error> {
        let ret = unsafe { hv_vcpu_set_simd_fp_reg(self.vcpuid, reg, val) };
        if ret != HV_SUCCESS {
            Err(Error::VcpuSetSimdFpRegister)
        } else {
            Ok(())
        }
    }

    /// Save the complete vCPU state. The vCPU must be paused (not running) when this is called.
    pub fn save_state(&self) -> Result<Aarch64VcpuState, Error> {
        assert!(
            self.pending_mmio_read.is_none(),
            "Cannot save state with pending MMIO read"
        );

        // Save GP registers: X0-X30, PC, FPCR, FPSR, CPSR
        let mut gp_regs = [0u64; 35];
        for i in 0..35u32 {
            gp_regs[i as usize] = self.read_reg(i)?;
        }

        // Save SIMD/FP registers: Q0-Q31
        let mut simd_fp_regs = [0u128; 32];
        for i in 0..32u32 {
            simd_fp_regs[i as usize] = self.read_simd_fp_reg(i)?;
        }

        // Save system registers
        let mut sys_regs = Vec::with_capacity(
            SAVEABLE_SYS_REGS.len()
                + if self.nested_enabled {
                    SAVEABLE_SYS_REGS_EL2.len()
                } else {
                    0
                },
        );
        for &reg in SAVEABLE_SYS_REGS {
            match self.read_sys_reg(reg) {
                Ok(val) => sys_regs.push((reg, val)),
                Err(Error::VcpuReadSystemRegister) => {
                    debug!("Skipping unreadable system register during snapshot save: 0x{reg:04x}");
                }
                Err(err) => return Err(err),
            }
        }
        if self.nested_enabled {
            for &reg in SAVEABLE_SYS_REGS_EL2 {
                match self.read_sys_reg(reg) {
                    Ok(val) => sys_regs.push((reg, val)),
                    Err(Error::VcpuReadSystemRegister) => {
                        debug!(
                            "Skipping unreadable EL2 system register during snapshot save: 0x{reg:04x}"
                        );
                    }
                    Err(err) => return Err(err),
                }
            }
        }

        // Save vtimer offset
        let vtimer_offset = vcpu_get_vtimer_offset(self.vcpuid)?;

        Ok(Aarch64VcpuState {
            gp_regs,
            simd_fp_regs,
            sys_regs,
            vtimer_offset,
            vtimer_masked: self.vtimer_masked,
            pending_advance_pc: self.pending_advance_pc,
        })
    }

    /// Restore vCPU state from a snapshot. The vCPU must be paused (not running).
    pub fn restore_state(&mut self, state: &Aarch64VcpuState) -> Result<(), Error> {
        // Restore GP registers
        for i in 0..35u32 {
            self.write_reg(i, state.gp_regs[i as usize])?;
        }

        // Restore SIMD/FP registers
        for i in 0..32u32 {
            self.write_simd_fp_reg(i, state.simd_fp_regs[i as usize])?;
        }

        // Restore system registers
        for &(reg, val) in &state.sys_regs {
            match self.write_sys_reg(reg, val) {
                Ok(()) => {}
                Err(Error::VcpuSetSystemRegister(_, _)) => {
                    debug!(
                        "Skipping unwritable system register during snapshot restore: 0x{reg:04x}"
                    );
                }
                Err(err) => return Err(err),
            }
        }

        // Restore vtimer offset
        vcpu_set_vtimer_offset(self.vcpuid, state.vtimer_offset)?;

        // Restore vtimer mask state
        if state.vtimer_masked {
            vcpu_set_vtimer_mask(self.vcpuid, true)?;
        }
        self.vtimer_masked = state.vtimer_masked;
        self.pending_advance_pc = state.pending_advance_pc;

        Ok(())
    }

    /// Check if a guest physical address falls within a RAM region.
    fn is_ram_address(&self, pa: u64) -> bool {
        self.ram_regions
            .iter()
            .any(|&(start, size)| pa >= start && pa < start + size)
    }

    fn hvf_sync_vtimer(&mut self, vcpu_list: Arc<dyn Vcpus>) {
        if !self.vtimer_masked {
            return;
        }

        let ctl = self
            .read_sys_reg(hv_sys_reg_t_HV_SYS_REG_CNTV_CTL_EL0)
            .unwrap();
        let irq_state = (ctl & (TMR_CTL_ENABLE | TMR_CTL_IMASK | TMR_CTL_ISTATUS))
            == (TMR_CTL_ENABLE | TMR_CTL_ISTATUS);
        vcpu_list.set_vtimer_irq(self.vcpuid);
        if !irq_state {
            vcpu_set_vtimer_mask(self.vcpuid, false).unwrap();
            self.vtimer_masked = false;
        }
    }

    fn handle_psci_request(&self) -> Result<VcpuExit<'_>, Error> {
        match self.read_reg(hv_reg_t_HV_REG_X0)? {
            0x8400_0000 /* QEMU_PSCI_0_2_FN_PSCI_VERSION */ => {
                self.write_reg(hv_reg_t_HV_REG_X0, 2)?;
                Ok(VcpuExit::PsciHandled)
            },
            0x8400_0006 /* QEMU_PSCI_0_2_FN_MIGRATE_INFO_TYPE */ => {
                self.write_reg(hv_reg_t_HV_REG_X0, 2)?;
                Ok(VcpuExit::PsciHandled)
            },
            0x8400_0008 /* QEMU_PSCI_0_2_FN_SYSTEM_OFF */ => {
                Ok(VcpuExit::Shutdown)
            },
            0x8400_0009 /* QEMU_PSCI_0_2_FN_SYSTEM_RESET */ => {
                Ok(VcpuExit::Shutdown)
            },
            0xc400_0003 /* QEMU_PSCI_0_2_FN64_CPU_ON */ => {
                let mpidr = self.read_reg(hv_reg_t_HV_REG_X1)?;
                let entry = self.read_reg(hv_reg_t_HV_REG_X2)?;
                let context_id = self.read_reg(hv_reg_t_HV_REG_X3)?;
                self.write_reg(hv_reg_t_HV_REG_X0, 0)?;
                Ok(VcpuExit::CpuOn(mpidr, entry, context_id))
            }
            val => panic!("Unexpected val={val}")
        }
    }

    pub fn run(&mut self, vcpu_list: Arc<dyn Vcpus>) -> Result<VcpuExit<'_>, Error> {
        let pending_irq = vcpu_list.has_pending_irq(self.vcpuid);

        if let Some(mmio_read) = self.pending_mmio_read.take() {
            if mmio_read.srt < 31 {
                let val = match mmio_read.len {
                    1 => u8::from_le_bytes(self.mmio_buf[0..1].try_into().unwrap()) as u64,
                    2 => u16::from_le_bytes(self.mmio_buf[0..2].try_into().unwrap()) as u64,
                    4 => u32::from_le_bytes(self.mmio_buf[0..4].try_into().unwrap()) as u64,
                    8 => u64::from_le_bytes(self.mmio_buf[0..8].try_into().unwrap()),
                    _ => panic!(
                        "unsupported mmio pa={} len={}",
                        mmio_read.addr, mmio_read.len
                    ),
                };

                self.write_reg(mmio_read.srt, val)?;
            }
        }

        if self.pending_advance_pc {
            let pc = self.read_reg(hv_reg_t_HV_REG_PC)?;
            self.write_reg(hv_reg_t_HV_REG_PC, pc + 4)?;
            self.pending_advance_pc = false;
        }

        if pending_irq {
            vcpu_set_pending_irq(self.vcpuid, InterruptType::Irq, true)?;
        }

        let ret = unsafe { hv_vcpu_run(self.vcpuid) };
        if ret != HV_SUCCESS {
            return Err(Error::VcpuRun);
        }

        match self.vcpu_exit.reason {
            HV_EXIT_REASON_EXCEPTION => { /* This is the main one, handle below. */ }
            HV_EXIT_REASON_VTIMER_ACTIVATED => {
                self.vtimer_masked = true;
                return Ok(VcpuExit::VtimerActivated);
            }
            HV_EXIT_REASON_CANCELED => return Ok(VcpuExit::Canceled),
            _ => {
                let pc = self.read_reg(hv_reg_t_HV_REG_PC)?;
                panic!(
                    "unexpected exit reason: vcpuid={} 0x{:x} at pc=0x{:x}",
                    self.id(),
                    self.vcpu_exit.reason,
                    pc
                );
            }
        }

        self.hvf_sync_vtimer(vcpu_list.clone());

        let syndrome = self.vcpu_exit.exception.syndrome;
        let ec = (syndrome >> 26) & 0x3f;
        match ec {
            EC_AA64_BKPT => {
                debug!("vcpu[{}]: BRK exit", self.vcpuid);
                Ok(VcpuExit::Breakpoint)
            }
            EC_DATAABORT => {
                let pa = self.vcpu_exit.exception.physical_address;

                // When dirty tracking is enabled, check if this is a write fault
                // to RAM (permission fault from write-protected pages) vs a true MMIO access.
                if self.dirty_tracking_enabled && self.is_ram_address(pa) {
                    // This is a RAM write fault from dirty tracking.
                    // Mark the page dirty via callback.
                    let page_start = pa & !(PAGE_SIZE_16K - 1);
                    if let Some(ref callback) = self.dirty_callback {
                        callback(page_start);
                    }
                    // Re-enable writes on this page so the instruction can retry.
                    let _ = HvfVm::protect_memory(
                        page_start,
                        PAGE_SIZE_16K,
                        true, // read
                        true, // write
                        true, // exec
                    );
                    // DON'T set pending_advance_pc — we want to retry the instruction.
                    return Ok(VcpuExit::DirtyPageFault(pa));
                }

                let isv: bool = (syndrome & (1 << 24)) != 0;
                let iswrite: bool = ((syndrome >> 6) & 1) != 0;
                let s1ptw: bool = ((syndrome >> 7) & 1) != 0;
                let sas: u32 = ((syndrome >> 22) & 3) as u32;
                let len: usize = (1 << sas) as usize;
                let srt: u32 = ((syndrome >> 16) & 0x1f) as u32;
                let cm: u32 = ((syndrome >> 8) & 0x1) as u32;

                debug!(
                    "EC_DATAABORT {} {} {} {} {} {} {} {}",
                    syndrome, isv as u8, iswrite as u8, s1ptw as u8, sas, len, srt, cm
                );

                self.pending_advance_pc = true;

                if iswrite {
                    let val = if srt < 31 {
                        self.read_reg(hv_reg_t_HV_REG_X0 + srt)?
                    } else {
                        0
                    };

                    match len {
                        1 => self.mmio_buf[0..1].copy_from_slice(&(val as u8).to_le_bytes()),
                        4 => self.mmio_buf[0..4].copy_from_slice(&(val as u32).to_le_bytes()),
                        8 => self.mmio_buf[0..8].copy_from_slice(&val.to_le_bytes()),
                        _ => panic!("unsupported mmio len={len}"),
                    };

                    Ok(VcpuExit::MmioWrite(pa, &self.mmio_buf[0..len]))
                } else {
                    self.pending_mmio_read = Some(MmioRead { addr: pa, srt, len });
                    Ok(VcpuExit::MmioRead(pa, &mut self.mmio_buf[0..len]))
                }
            }
            #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
            EC_SYSTEMREGISTERTRAP => {
                let isread: bool = (syndrome & 1) != 0;
                let rt: u32 = ((syndrome >> 5) & 0x1f) as u32;
                let reg: u32 = syndrome as u32 & SYSREG_MASK;
                debug!(
                    "EC_SYSTEMREGISTERTRAP isread={}, syndrome={}, rt={}, reg={}, reg_name={}",
                    isread as u32,
                    syndrome,
                    rt,
                    reg,
                    sys_reg_name(reg).unwrap_or("unknown sysreg")
                );

                self.pending_advance_pc = true;

                if isread {
                    assert!(rt < 32);

                    // See https://developer.arm.com/documentation/dui0801/l/Overview-of-AArch64-state/Registers-in-AArch64-state
                    if rt == 31 {
                        return Ok(VcpuExit::SystemRegister);
                    }

                    match vcpu_list.handle_sysreg_read(self.vcpuid, reg) {
                        Some(val) => {
                            self.write_reg(rt, val)?;
                            Ok(VcpuExit::SystemRegister)
                        }
                        None => panic!(
                            "UNKNOWN rt={}, reg={} name={}",
                            rt,
                            reg,
                            sys_reg_name(reg).unwrap_or("unknown sysreg")
                        ),
                    }
                } else {
                    assert!(rt < 32);

                    // See https://developer.arm.com/documentation/dui0801/l/Overview-of-AArch64-state/Registers-in-AArch64-state
                    let val = if rt == 31 { 0u64 } else { self.read_reg(rt)? };

                    if vcpu_list.handle_sysreg_write(self.vcpuid, reg, val) {
                        Ok(VcpuExit::SystemRegister)
                    } else {
                        panic!(
                            "unexpected write: {} name={}",
                            reg,
                            sys_reg_name(reg).unwrap_or("unknown sysreg")
                        );
                    }
                }
            }
            EC_WFX_TRAP => {
                let ctl = self.read_sys_reg(hv_sys_reg_t_HV_SYS_REG_CNTV_CTL_EL0)?;

                self.pending_advance_pc = true;
                if ((ctl & 1) == 0) || (ctl & 2) != 0 {
                    return Ok(VcpuExit::WaitForEvent);
                }

                // Also CNTV_CVAL & CNTV_CVAL_EL0
                let cval = self.read_sys_reg(hv_sys_reg_t_HV_SYS_REG_CNTV_CVAL_EL0)?;
                let now = unsafe { mach_absolute_time() };
                if now > cval {
                    return Ok(VcpuExit::WaitForEventExpired);
                }

                let timeout = Duration::from_nanos((cval - now) * (1_000_000_000 / self.cntfrq));
                Ok(VcpuExit::WaitForEventTimeout(timeout))
            }
            EC_AA64_HVC => self.handle_psci_request(),
            EC_AA64_SMC => {
                self.pending_advance_pc = true;
                self.handle_psci_request()
            }
            _ => panic!("unexpected exception: 0x{ec:x}"),
        }
    }
}
