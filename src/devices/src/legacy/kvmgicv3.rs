// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;

use crate::bus::BusDevice;
use crate::legacy::gic::GICDevice;
use crate::legacy::irqchip::IrqChipT;
use crate::Error as DeviceError;

use kvm_ioctls::{DeviceFd, Error, VmFd};
use utils::eventfd::EventFd;

const KVM_VGIC_V3_BASE_SIZE: u64 = 0x0001_0000;

// Device trees specific constants
const ARCH_GIC_V3_MAINT_IRQ: u32 = 9;

// GIC distributor register offsets
#[cfg(feature = "snapshot")]
const GICD_CTLR: u64 = 0x0000;
#[cfg(feature = "snapshot")]
const GICD_IGROUPR: u64 = 0x0080;
#[cfg(feature = "snapshot")]
const GICD_ISENABLER: u64 = 0x0100;
#[cfg(feature = "snapshot")]
const GICD_ISPENDR: u64 = 0x0200;
#[cfg(feature = "snapshot")]
const GICD_ISACTIVER: u64 = 0x0300;
#[cfg(feature = "snapshot")]
const GICD_IPRIORITYR: u64 = 0x0400;
#[cfg(feature = "snapshot")]
const GICD_ICFGR: u64 = 0x0C00;
#[cfg(feature = "snapshot")]
const GICD_IROUTER: u64 = 0x6000;

// GIC distributor clear registers (write-1-to-clear counterparts of IS* registers)
#[cfg(feature = "snapshot")]
const GICD_ICENABLER: u64 = 0x0180;
#[cfg(feature = "snapshot")]
const GICD_ICPENDR: u64 = 0x0280;
#[cfg(feature = "snapshot")]
const GICD_ICACTIVER: u64 = 0x0380;

// GIC redistributor register offsets (SGI region, per-vCPU)
#[cfg(feature = "snapshot")]
const GICR_IGROUPR0: u64 = 0x0080;
#[cfg(feature = "snapshot")]
const GICR_ISENABLER0: u64 = 0x0100;
#[cfg(feature = "snapshot")]
const GICR_ICENABLER0: u64 = 0x0180;
#[cfg(feature = "snapshot")]
const GICR_ISPENDR0: u64 = 0x0200;
#[cfg(feature = "snapshot")]
const GICR_ICPENDR0: u64 = 0x0280;
#[cfg(feature = "snapshot")]
const GICR_ISACTIVER0: u64 = 0x0300;
#[cfg(feature = "snapshot")]
const GICR_ICACTIVER0: u64 = 0x0380;
#[cfg(feature = "snapshot")]
const GICR_IPRIORITYR: u64 = 0x0400;
#[cfg(feature = "snapshot")]
const GICR_ICFGR0: u64 = 0x0C00;

pub struct KvmGicV3 {
    device_fd: DeviceFd,

    /// GIC device properties, to be used for setting up the fdt entry
    properties: [u64; 4],

    /// Number of CPUs handled by the device
    vcpu_count: u64,
}

#[cfg(feature = "snapshot")]
#[derive(serde::Serialize, serde::Deserialize)]
struct GicV3State {
    /// Distributor registers: (offset, value)
    dist_regs: Vec<(u64, u32)>,
    /// Per-vCPU redistributor registers: Vec<(offset, value)>
    redist_regs: Vec<Vec<(u64, u32)>>,
}

impl KvmGicV3 {
    pub fn new(vm: &VmFd, vcpu_count: u64) -> Result<Self, Error> {
        let dist_size = KVM_VGIC_V3_BASE_SIZE;
        let dist_addr = arch::MMIO_MEM_START - dist_size;
        let redist_size = 2 * dist_size;
        let redists_size = redist_size * vcpu_count;
        let redists_addr = dist_addr - redists_size;

        let mut gic_device = kvm_bindings::kvm_create_device {
            type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
            fd: 0,
            flags: 0,
        };
        let device_fd = vm.create_device(&mut gic_device)?;

        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            attr: u64::from(kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_DIST),
            addr: &dist_addr as *const u64 as u64,
            flags: 0,
        };
        device_fd.set_device_attr(&attr)?;

        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            attr: u64::from(kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_REDIST),
            addr: &redists_addr as *const u64 as u64,
            flags: 0,
        };
        device_fd.set_device_attr(&attr)?;

        let nr_irqs: u32 = arch::aarch64::layout::IRQ_MAX - arch::aarch64::layout::IRQ_BASE + 1;
        let nr_irqs_ptr = &nr_irqs as *const u32;
        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
            attr: 0,
            addr: nr_irqs_ptr as u64,
            flags: 0,
        };
        device_fd.set_device_attr(&attr)?;

        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            attr: u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_CTRL_INIT),
            addr: 0,
            flags: 0,
        };
        device_fd.set_device_attr(&attr)?;

        Ok(Self {
            device_fd,
            properties: [dist_addr, dist_size, redists_addr, redists_size],
            vcpu_count,
        })
    }

    /// Get a distributor register value.
    #[cfg(feature = "snapshot")]
    fn get_dist_reg(&self, offset: u64) -> Result<u32, Error> {
        let mut val: u32 = 0;
        let mut attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_DIST_REGS,
            attr: offset,
            addr: &mut val as *mut u32 as u64,
            flags: 0,
        };
        unsafe {
            self.device_fd.get_device_attr(&mut attr)?;
        }
        Ok(val)
    }

    /// Set a distributor register value.
    #[cfg(feature = "snapshot")]
    fn set_dist_reg(&self, offset: u64, val: u32) -> Result<(), Error> {
        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_DIST_REGS,
            attr: offset,
            addr: &val as *const u32 as u64,
            flags: 0,
        };
        self.device_fd.set_device_attr(&attr)
    }

    /// Get a redistributor register value for a specific vCPU.
    /// The attr encoding packs the vCPU index and the register offset:
    /// attr = (mpidr << 32) | offset
    /// For simplicity we use the vCPU index as the mpidr value (KVM accepts this).
    #[cfg(feature = "snapshot")]
    fn get_redist_reg(&self, vcpu_index: u64, offset: u64) -> Result<u32, Error> {
        let mut val: u32 = 0;
        let mut attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_REDIST_REGS,
            attr: (vcpu_index << 32) | offset,
            addr: &mut val as *mut u32 as u64,
            flags: 0,
        };
        unsafe {
            self.device_fd.get_device_attr(&mut attr)?;
        }
        Ok(val)
    }

    /// Set a redistributor register value for a specific vCPU.
    #[cfg(feature = "snapshot")]
    fn set_redist_reg(&self, vcpu_index: u64, offset: u64, val: u32) -> Result<(), Error> {
        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_REDIST_REGS,
            attr: (vcpu_index << 32) | offset,
            addr: &val as *const u32 as u64,
            flags: 0,
        };
        self.device_fd.set_device_attr(&attr)
    }

    /// Flush pending interrupt state to memory before saving.
    #[cfg(feature = "snapshot")]
    fn save_pending_tables(&self) -> Result<(), Error> {
        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            attr: u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_SAVE_PENDING_TABLES),
            addr: 0,
            flags: 0,
        };
        self.device_fd.set_device_attr(&attr)
    }

    /// Save all GIC register state.
    #[cfg(feature = "snapshot")]
    fn save_gic_state(&self) -> Result<GicV3State, Error> {
        self.save_pending_tables()?;

        let nr_irqs =
            (arch::aarch64::layout::IRQ_MAX - arch::aarch64::layout::IRQ_BASE + 1) as u64;
        // Number of SPI (Shared Peripheral Interrupt) registers
        // SPIs start at IRQ 32, each register covers 32 IRQs
        let nr_spis = nr_irqs.saturating_sub(32);
        let nr_spi_regs = (nr_spis + 31) / 32;

        let mut dist_regs = Vec::new();

        // GICD_CTLR
        dist_regs.push((GICD_CTLR, self.get_dist_reg(GICD_CTLR)?));

        // GICD_IGROUPR (one bit per IRQ, 32 IRQs per register, starting at SPI 32)
        for i in 1..=nr_spi_regs {
            let offset = GICD_IGROUPR + i * 4;
            dist_regs.push((offset, self.get_dist_reg(offset)?));
        }

        // GICD_ISENABLER
        for i in 1..=nr_spi_regs {
            let offset = GICD_ISENABLER + i * 4;
            dist_regs.push((offset, self.get_dist_reg(offset)?));
        }

        // GICD_ISPENDR
        for i in 1..=nr_spi_regs {
            let offset = GICD_ISPENDR + i * 4;
            dist_regs.push((offset, self.get_dist_reg(offset)?));
        }

        // GICD_ISACTIVER
        for i in 1..=nr_spi_regs {
            let offset = GICD_ISACTIVER + i * 4;
            dist_regs.push((offset, self.get_dist_reg(offset)?));
        }

        // GICD_IPRIORITYR (one byte per IRQ, 4 IRQs per 32-bit register, starting at SPI 32)
        // Register index 8 is the first SPI priority register (IRQs 32-35)
        let nr_spi_prio_regs = (nr_spis + 3) / 4;
        for i in 8..(8 + nr_spi_prio_regs) {
            let offset = GICD_IPRIORITYR + i * 4;
            dist_regs.push((offset, self.get_dist_reg(offset)?));
        }

        // GICD_ICFGR (2 bits per IRQ, 16 IRQs per register, starting at SPI 32)
        let nr_spi_cfg_regs = (nr_spis + 15) / 16;
        for i in 2..(2 + nr_spi_cfg_regs) {
            let offset = GICD_ICFGR + i * 4;
            dist_regs.push((offset, self.get_dist_reg(offset)?));
        }

        // GICD_IROUTER (64-bit per SPI, but we access as 32-bit pairs)
        for i in 0..nr_spis {
            let offset = GICD_IROUTER + (i + 32) * 8;
            dist_regs.push((offset, self.get_dist_reg(offset)?));
            dist_regs.push((offset + 4, self.get_dist_reg(offset + 4)?));
        }

        // Per-vCPU redistributor registers
        let mut redist_regs = Vec::new();
        for vcpu in 0..self.vcpu_count {
            let mut vcpu_regs = Vec::new();

            // GICR_IGROUPR0
            vcpu_regs.push((
                GICR_IGROUPR0,
                self.get_redist_reg(vcpu, GICR_IGROUPR0)?,
            ));

            // GICR_ISENABLER0
            vcpu_regs.push((
                GICR_ISENABLER0,
                self.get_redist_reg(vcpu, GICR_ISENABLER0)?,
            ));

            // GICR_ISPENDR0
            vcpu_regs.push((
                GICR_ISPENDR0,
                self.get_redist_reg(vcpu, GICR_ISPENDR0)?,
            ));

            // GICR_ISACTIVER0
            vcpu_regs.push((
                GICR_ISACTIVER0,
                self.get_redist_reg(vcpu, GICR_ISACTIVER0)?,
            ));

            // GICR_IPRIORITYR (8 registers for 32 SGI/PPI IRQs)
            for i in 0..8u64 {
                let offset = GICR_IPRIORITYR + i * 4;
                vcpu_regs.push((offset, self.get_redist_reg(vcpu, offset)?));
            }

            // GICR_ICFGR0 (and ICFGR1 for PPIs)
            vcpu_regs.push((GICR_ICFGR0, self.get_redist_reg(vcpu, GICR_ICFGR0)?));
            vcpu_regs.push((
                GICR_ICFGR0 + 4,
                self.get_redist_reg(vcpu, GICR_ICFGR0 + 4)?,
            ));

            redist_regs.push(vcpu_regs);
        }

        Ok(GicV3State {
            dist_regs,
            redist_regs,
        })
    }

    /// Restore all GIC register state.
    ///
    /// The IS* registers (ISENABLER, ISPENDR, ISACTIVER) are write-1-to-set,
    /// so they can only add bits. To get an exact restore, we first write
    /// all-ones to the corresponding IC* (clear) registers to zero everything
    /// out, then write the saved IS* values to set the correct bits.
    #[cfg(feature = "snapshot")]
    fn restore_gic_state(&self, state: &GicV3State) -> Result<(), Error> {
        let nr_irqs =
            (arch::aarch64::layout::IRQ_MAX - arch::aarch64::layout::IRQ_BASE + 1) as u64;
        let nr_spis = nr_irqs.saturating_sub(32);
        let nr_spi_regs = (nr_spis + 31) / 32;

        // Clear all SPI enable/pending/active bits before restoring
        for i in 1..=nr_spi_regs {
            self.set_dist_reg(GICD_ICENABLER + i * 4, 0xFFFF_FFFF)?;
            self.set_dist_reg(GICD_ICPENDR + i * 4, 0xFFFF_FFFF)?;
            self.set_dist_reg(GICD_ICACTIVER + i * 4, 0xFFFF_FFFF)?;
        }

        // Restore distributor registers (CTLR, IGROUPR, ISENABLER, etc.)
        for &(offset, val) in &state.dist_regs {
            self.set_dist_reg(offset, val)?;
        }

        // Clear and restore per-vCPU redistributor registers
        for (vcpu, vcpu_regs) in state.redist_regs.iter().enumerate() {
            let vcpu_idx = vcpu as u64;
            // Clear SGI/PPI enable/pending/active bits
            self.set_redist_reg(vcpu_idx, GICR_ICENABLER0, 0xFFFF_FFFF)?;
            self.set_redist_reg(vcpu_idx, GICR_ICPENDR0, 0xFFFF_FFFF)?;
            self.set_redist_reg(vcpu_idx, GICR_ICACTIVER0, 0xFFFF_FFFF)?;

            for &(offset, val) in vcpu_regs {
                self.set_redist_reg(vcpu_idx, offset, val)?;
            }
        }

        Ok(())
    }
}

impl IrqChipT for KvmGicV3 {
    fn get_mmio_addr(&self) -> u64 {
        0
    }

    fn get_mmio_size(&self) -> u64 {
        0
    }

    fn set_irq(
        &self,
        _irq_line: Option<u32>,
        interrupt_evt: Option<&EventFd>,
    ) -> Result<(), DeviceError> {
        if let Some(interrupt_evt) = interrupt_evt {
            if let Err(e) = interrupt_evt.write(1) {
                error!("Failed to signal used queue: {e:?}");
                return Err(DeviceError::FailedSignalingUsedQueue(e));
            }
        } else {
            error!("EventFd not set up for irq line");
            return Err(DeviceError::FailedSignalingUsedQueue(io::Error::new(
                io::ErrorKind::NotFound,
                "EventFd not set up for irq line".to_string(),
            )));
        }
        Ok(())
    }

    #[cfg(feature = "snapshot")]
    fn save_snapshot_state(&self) -> Option<Vec<u8>> {
        match self.save_gic_state() {
            Ok(state) => match bincode::serialize(&state) {
                Ok(data) => Some(data),
                Err(e) => {
                    error!("Failed to serialize GIC state: {e}");
                    None
                }
            },
            Err(e) => {
                error!("Failed to save GIC state: {e}");
                None
            }
        }
    }

    #[cfg(feature = "snapshot")]
    fn restore_snapshot_state(&mut self, data: &[u8]) {
        match bincode::deserialize::<GicV3State>(data) {
            Ok(state) => {
                if let Err(e) = self.restore_gic_state(&state) {
                    error!("Failed to restore GIC state: {e}");
                }
            }
            Err(e) => {
                error!("Failed to deserialize GIC state: {e}");
            }
        }
    }
}

impl BusDevice for KvmGicV3 {
    fn read(&mut self, _vcpuid: u64, _offset: u64, _data: &mut [u8]) {
        unreachable!("MMIO operations are managed in-kernel");
    }

    fn write(&mut self, _vcpuid: u64, _offset: u64, _data: &[u8]) {
        unreachable!("MMIO operations are managed in-kernel");
    }
}

impl GICDevice for KvmGicV3 {
    fn device_properties(&self) -> Vec<u64> {
        self.properties.to_vec()
    }

    fn vcpu_count(&self) -> u64 {
        self.vcpu_count
    }

    fn fdt_compatibility(&self) -> String {
        "arm,gic-v3".to_string()
    }

    fn fdt_maint_irq(&self) -> u32 {
        ARCH_GIC_V3_MAINT_IRQ
    }

    fn version(&self) -> u32 {
        kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3
    }
}
