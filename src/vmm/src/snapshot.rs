// Copyright 2024 The libkrun Authors.
// SPDX-License-Identifier: Apache-2.0

//! VM snapshot and restore support.
//!
//! Provides full and incremental snapshot capabilities for macOS/HVF VMs.

use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

use hvf::Aarch64VcpuState;

pub const SNAPSHOT_MAGIC: u32 = 0x4B52_534E; // "KRSN"
pub const SNAPSHOT_VERSION: u32 = 1;

/// Timeout for quiescing async device workers during snapshot operations.
pub const SNAPSHOT_QUIESCE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);

#[derive(Debug)]
pub enum SnapshotError {
    Io(io::Error),
    Serialize(String),
    Deserialize(String),
    InvalidMagic,
    InvalidVersion(u32),
    MemorySizeMismatch {
        expected: u64,
        got: u64,
    },
    MemoryLayoutMismatch {
        expected: Vec<(u64, u64)>,
        got: Vec<(u64, u64)>,
    },
    VcpuCountMismatch {
        expected: usize,
        got: usize,
    },
}

impl Display for SnapshotError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            SnapshotError::Io(e) => write!(f, "Snapshot I/O error: {e}"),
            SnapshotError::Serialize(e) => write!(f, "Snapshot serialization error: {e}"),
            SnapshotError::Deserialize(e) => write!(f, "Snapshot deserialization error: {e}"),
            SnapshotError::InvalidMagic => write!(f, "Invalid snapshot magic number"),
            SnapshotError::InvalidVersion(v) => write!(f, "Unsupported snapshot version: {v}"),
            SnapshotError::MemorySizeMismatch { expected, got } => {
                write!(
                    f,
                    "Memory size mismatch: expected {expected} bytes, got {got}"
                )
            }
            SnapshotError::MemoryLayoutMismatch { expected, got } => {
                write!(f, "RAM layout mismatch: expected {expected:?}, got {got:?}")
            }
            SnapshotError::VcpuCountMismatch { expected, got } => {
                write!(f, "vCPU count mismatch: expected {expected}, got {got}")
            }
        }
    }
}

impl From<io::Error> for SnapshotError {
    fn from(e: io::Error) -> Self {
        SnapshotError::Io(e)
    }
}

fn validate_magic_and_version(header: &SnapshotHeader) -> Result<(), SnapshotError> {
    if header.magic != SNAPSHOT_MAGIC {
        return Err(SnapshotError::InvalidMagic);
    }
    if header.version != SNAPSHOT_VERSION {
        return Err(SnapshotError::InvalidVersion(header.version));
    }
    Ok(())
}

pub fn validate_header_for_vm(
    header: &SnapshotHeader,
    guest_memory: &GuestMemoryMmap,
    expected_vcpu_count: usize,
) -> Result<(), SnapshotError> {
    validate_magic_and_version(header)?;

    let expected_layout = ram_layout(guest_memory);
    if header.ram_regions != expected_layout {
        return Err(SnapshotError::MemoryLayoutMismatch {
            expected: expected_layout,
            got: header.ram_regions.clone(),
        });
    }

    if header.vcpu_count as usize != expected_vcpu_count {
        return Err(SnapshotError::VcpuCountMismatch {
            expected: expected_vcpu_count,
            got: header.vcpu_count as usize,
        });
    }

    Ok(())
}

/// Header for the snapshot file.
#[cfg_attr(feature = "snapshot", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone)]
pub struct SnapshotHeader {
    pub magic: u32,
    pub version: u32,
    pub vcpu_count: u32,
    /// (guest_addr, size) pairs describing the RAM layout
    pub ram_regions: Vec<(u64, u64)>,
    pub nested_enabled: bool,
}

/// Complete VM snapshot (metadata, excluding raw memory).
#[cfg_attr(feature = "snapshot", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone)]
pub struct VmSnapshot {
    pub header: SnapshotHeader,
    pub vcpu_states: Vec<Aarch64VcpuState>,
    /// Device states as (device_id, serialized_bytes) pairs.
    pub device_states: Vec<(String, Vec<u8>)>,
    #[cfg_attr(feature = "snapshot", serde(default))]
    pub gic_state: Option<Vec<u8>>,
}

/// Dump guest memory to a file.
pub fn dump_memory(guest_memory: &GuestMemoryMmap, path: &Path) -> Result<(), SnapshotError> {
    let mut file = File::create(path)?;
    for region in guest_memory.iter() {
        let host_addr = guest_memory
            .get_host_address(region.start_addr())
            .map_err(|e| SnapshotError::Serialize(format!("Invalid guest address: {e}")))?;
        let len = region.len() as usize;
        let slice = unsafe { std::slice::from_raw_parts(host_addr, len) };
        file.write_all(slice)?;
    }
    file.sync_all()?;
    Ok(())
}

/// Load guest memory from a file.
pub fn load_memory(guest_memory: &GuestMemoryMmap, path: &Path) -> Result<(), SnapshotError> {
    let mut file = File::open(path)?;
    let expected_size = total_ram_size(guest_memory);
    let actual_size = file.metadata()?.len();
    if actual_size != expected_size {
        return Err(SnapshotError::MemorySizeMismatch {
            expected: expected_size,
            got: actual_size,
        });
    }

    for region in guest_memory.iter() {
        let host_addr = guest_memory
            .get_host_address(region.start_addr())
            .map_err(|e| SnapshotError::Deserialize(format!("Invalid guest address: {e}")))?;
        let len = region.len() as usize;
        let slice = unsafe { std::slice::from_raw_parts_mut(host_addr as *mut u8, len) };
        file.read_exact(slice)?;
    }
    Ok(())
}

/// Compute total RAM size from guest memory regions.
pub fn total_ram_size(guest_memory: &GuestMemoryMmap) -> u64 {
    guest_memory.iter().map(|r| r.len()).sum()
}

/// Get the RAM layout as (guest_addr, size) pairs.
pub fn ram_layout(guest_memory: &GuestMemoryMmap) -> Vec<(u64, u64)> {
    guest_memory
        .iter()
        .map(|r| (r.start_addr().raw_value(), r.len()))
        .collect()
}

/// Save VM snapshot metadata to a file (vmstate).
#[cfg(feature = "snapshot")]
pub fn save_vmstate(snapshot: &VmSnapshot, path: &Path) -> Result<(), SnapshotError> {
    let data = bincode::serialize(snapshot).map_err(|e| SnapshotError::Serialize(e.to_string()))?;
    let mut file = File::create(path)?;
    file.write_all(&data)?;
    file.sync_all()?;
    Ok(())
}

/// Load VM snapshot metadata from a file (vmstate).
#[cfg(feature = "snapshot")]
pub fn load_vmstate(path: &Path) -> Result<VmSnapshot, SnapshotError> {
    let mut file = File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    let snapshot: VmSnapshot =
        bincode::deserialize(&data).map_err(|e| SnapshotError::Deserialize(e.to_string()))?;
    validate_magic_and_version(&snapshot.header)?;
    if snapshot.vcpu_states.len() != snapshot.header.vcpu_count as usize {
        return Err(SnapshotError::VcpuCountMismatch {
            expected: snapshot.header.vcpu_count as usize,
            got: snapshot.vcpu_states.len(),
        });
    }
    Ok(snapshot)
}

/// Create a full VM snapshot to a directory.
///
/// The directory will contain:
/// - `vmstate`: serialized VmSnapshot (header + vcpu states + device states)
/// - `memory`: raw guest RAM dump
#[cfg(feature = "snapshot")]
pub fn create_full_snapshot(
    path: &Path,
    guest_memory: &GuestMemoryMmap,
    vcpu_states: Vec<Aarch64VcpuState>,
    device_states: Vec<(String, Vec<u8>)>,
    gic_state: Option<Vec<u8>>,
    nested_enabled: bool,
) -> Result<(), SnapshotError> {
    std::fs::create_dir_all(path)?;

    let snapshot = VmSnapshot {
        header: SnapshotHeader {
            magic: SNAPSHOT_MAGIC,
            version: SNAPSHOT_VERSION,
            vcpu_count: vcpu_states.len() as u32,
            ram_regions: ram_layout(guest_memory),
            nested_enabled,
        },
        vcpu_states,
        device_states,
        gic_state,
    };

    save_vmstate(&snapshot, &path.join("vmstate"))?;
    dump_memory(guest_memory, &path.join("memory"))?;

    Ok(())
}

/// Page size on Apple Silicon (16KB).
pub const PAGE_SIZE: u64 = 16384;

/// An incremental memory diff entry.
#[cfg_attr(feature = "snapshot", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone)]
pub struct DirtyPage {
    pub guest_addr: u64,
    pub data: Vec<u8>,
}

/// Incremental snapshot: vm state + dirty pages only.
#[cfg_attr(feature = "snapshot", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone)]
pub struct IncrementalSnapshot {
    pub header: SnapshotHeader,
    pub vcpu_states: Vec<Aarch64VcpuState>,
    pub device_states: Vec<(String, Vec<u8>)>,
    pub dirty_pages: Vec<DirtyPage>,
    #[cfg_attr(feature = "snapshot", serde(default))]
    pub gic_state: Option<Vec<u8>>,
}

/// Combined interrupt controller snapshot: pending IRQs + GIC register state.
#[cfg(feature = "snapshot")]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct InterruptControllerSnapshot {
    pub pending_irqs: Vec<Vec<u32>>,
    pub gic_registers: Option<Vec<u8>>,
}

/// Save an incremental snapshot.
#[cfg(feature = "snapshot")]
pub fn save_incremental_snapshot(
    snapshot: &IncrementalSnapshot,
    path: &Path,
) -> Result<(), SnapshotError> {
    let data = bincode::serialize(snapshot).map_err(|e| SnapshotError::Serialize(e.to_string()))?;
    let mut file = File::create(path)?;
    file.write_all(&data)?;
    file.sync_all()?;
    Ok(())
}

/// Load an incremental snapshot.
#[cfg(feature = "snapshot")]
pub fn load_incremental_snapshot(path: &Path) -> Result<IncrementalSnapshot, SnapshotError> {
    let mut file = File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    let snapshot: IncrementalSnapshot =
        bincode::deserialize(&data).map_err(|e| SnapshotError::Deserialize(e.to_string()))?;
    validate_magic_and_version(&snapshot.header)?;
    if snapshot.vcpu_states.len() != snapshot.header.vcpu_count as usize {
        return Err(SnapshotError::VcpuCountMismatch {
            expected: snapshot.header.vcpu_count as usize,
            got: snapshot.vcpu_states.len(),
        });
    }
    Ok(snapshot)
}

/// Apply incremental snapshot dirty pages on top of existing guest memory.
pub fn apply_dirty_pages(
    guest_memory: &GuestMemoryMmap,
    dirty_pages: &[DirtyPage],
) -> Result<(), SnapshotError> {
    for page in dirty_pages {
        if page.data.len() != PAGE_SIZE as usize {
            return Err(SnapshotError::Deserialize(format!(
                "Dirty page at 0x{:x} has {} bytes (expected {})",
                page.guest_addr,
                page.data.len(),
                PAGE_SIZE
            )));
        }

        guest_memory
            .write_slice(&page.data, GuestAddress(page.guest_addr))
            .map_err(|e| {
                SnapshotError::Deserialize(format!(
                    "Failed writing dirty page at 0x{:x}: {e}",
                    page.guest_addr
                ))
            })?;
    }
    Ok(())
}
