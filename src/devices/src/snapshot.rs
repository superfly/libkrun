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
    /// Device quiesce did not complete within the configured deadline.
    QuiesceTimeout {
        device_id: String,
        timeout_ms: u64,
        detail: Option<String>,
    },
    /// Device restore resync did not complete within the configured deadline.
    ResyncTimeout {
        device_id: String,
        timeout_ms: u64,
        detail: Option<String>,
    },
    /// Device quiesce failed before snapshot save.
    QuiesceFailure {
        device_id: String,
        detail: Option<String>,
    },
    /// Device restore resync failed.
    ResyncFailure {
        device_id: String,
        detail: Option<String>,
    },
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SnapshotError::Serialize(e) => write!(f, "Device snapshot serialize error: {e}"),
            SnapshotError::Deserialize(e) => write!(f, "Device snapshot deserialize error: {e}"),
            SnapshotError::QuiesceTimeout {
                device_id,
                timeout_ms,
                detail,
            } => {
                if let Some(detail) = detail {
                    write!(
                        f,
                        "Device snapshot quiesce timeout for '{device_id}' after {timeout_ms}ms: {detail}"
                    )
                } else {
                    write!(
                        f,
                        "Device snapshot quiesce timeout for '{device_id}' after {timeout_ms}ms"
                    )
                }
            }
            SnapshotError::ResyncTimeout {
                device_id,
                timeout_ms,
                detail,
            } => {
                if let Some(detail) = detail {
                    write!(
                        f,
                        "Device snapshot restore resync timeout for '{device_id}' after {timeout_ms}ms: {detail}"
                    )
                } else {
                    write!(
                        f,
                        "Device snapshot restore resync timeout for '{device_id}' after {timeout_ms}ms"
                    )
                }
            }
            SnapshotError::QuiesceFailure { device_id, detail } => {
                if let Some(detail) = detail {
                    write!(
                        f,
                        "Device snapshot quiesce failure for '{device_id}': {detail}"
                    )
                } else {
                    write!(f, "Device snapshot quiesce failure for '{device_id}'")
                }
            }
            SnapshotError::ResyncFailure { device_id, detail } => {
                if let Some(detail) = detail {
                    write!(
                        f,
                        "Device snapshot restore resync failure for '{device_id}': {detail}"
                    )
                } else {
                    write!(
                        f,
                        "Device snapshot restore resync failure for '{device_id}'"
                    )
                }
            }
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
