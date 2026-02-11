// Copyright 2024 The libkrun Authors.
// SPDX-License-Identifier: Apache-2.0

//! Snapshot trait for devices that support save/restore.

use std::fmt;

/// Errors that can occur during device snapshot operations.
#[derive(Debug)]
pub enum SnapshotError {
    /// Serialization failed.
    Serialize(String),
    /// Deserialization failed.
    Deserialize(String),
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SnapshotError::Serialize(e) => write!(f, "Device snapshot serialize error: {e}"),
            SnapshotError::Deserialize(e) => write!(f, "Device snapshot deserialize error: {e}"),
        }
    }
}

impl std::error::Error for SnapshotError {}

/// Trait for devices that support snapshot save/restore.
///
/// Each device serializes its own state to opaque bytes. The snapshot layer
/// stores these as `(device_id, Vec<u8>)` pairs.
pub trait Snapshottable {
    /// A unique identifier for this device instance (e.g. "virtio-blk-0").
    fn snapshot_id(&self) -> &str;

    /// Serialize the device's current state to bytes.
    fn save_state(&self) -> Result<Vec<u8>, SnapshotError>;

    /// Restore the device's state from bytes previously returned by `save_state`.
    fn restore_state(&mut self, data: &[u8]) -> Result<(), SnapshotError>;
}
