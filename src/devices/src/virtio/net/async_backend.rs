// Copyright 2024 Anthropic. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Async network backend traits for virtio-net devices.
//!
//! This module defines the traits for implementing async network backends
//! that can be used with the `AsyncNetWorker`. The design prioritizes:
//!
//! - **Zero-copy where possible**: TX path passes borrowed slices
//! - **No locking**: All methods take `&mut self`
//! - **Async-friendly**: Separated channel for RX to avoid borrow conflicts
//!
//! # Implementing a Backend
//!
//! To create a custom network backend:
//!
//! 1. Implement `AsyncNetBackendFactory` to create your backend
//! 2. Implement `AsyncNetBackend` for packet handling
//! 3. Pass the factory to libkrun via `VirtioNetBackend::CustomAsyncFactory`
//!
//! See the `examples/smoltcp-proxy` for a complete implementation using smoltcp.

use bytes::Bytes;
use std::io;
use std::time::Duration;
use tokio::sync::mpsc;

/// A boxed future type for async operations.
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + 'a>>;

/// A Send-able boxed future for factory creation (crosses thread boundary).
pub type SendBoxFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Handle returned by the backend factory.
///
/// Separates the synchronous backend from the async RX channel to avoid
/// borrow conflicts in the worker's select loop.
pub struct NetBackendHandle {
    /// The backend for synchronous operations
    pub backend: Box<dyn AsyncNetBackend>,
    /// Receiver for packets destined for the guest (backend holds the sender)
    pub to_guest_rx: mpsc::Receiver<Bytes>,
    /// Optional receiver for wake notifications from background tasks.
    ///
    /// When background tasks (like host socket handlers) have data ready,
    /// they send a unit `()` on this channel to wake the worker's poll loop.
    /// This avoids the need for aggressive timer-based polling.
    ///
    /// Set to `None` if the backend doesn't use background tasks.
    pub wake_rx: Option<mpsc::Receiver<()>>,
}

/// Network backend trait optimized for minimal copying.
///
/// All methods are synchronous and take `&mut self`, eliminating the need
/// for interior mutability. The backend communicates packets to the guest
/// via the channel returned in `NetBackendHandle`.
///
/// # TX Path (Guest -> Backend)
///
/// `handle_guest_tx` receives a borrowed slice. The backend can:
/// - Process inline with zero copies (e.g., feed directly to a TCP/IP stack)
/// - Copy only when needed for async operations (e.g., host socket sends)
///
/// # RX Path (Backend -> Guest)
///
/// The backend sends packets via the `mpsc::Sender<Bytes>` it receives
/// during creation. The worker awaits on the corresponding receiver.
pub trait AsyncNetBackend: 'static {
    /// Handle a packet from the guest.
    ///
    /// Called synchronously from the worker's event loop. The packet data
    /// is borrowed - the backend must copy if it needs to retain the data
    /// beyond this call (e.g., for async host socket operations).
    fn handle_guest_tx(&mut self, packet: &[u8]);

    /// Run internal state machine processing.
    ///
    /// Called after handling guest packets and when timers expire.
    /// Backends should process internal queues, check host socket
    /// readiness, etc.
    fn poll(&mut self);

    /// Hint for how long until the backend needs polling.
    ///
    /// Used for timer-driven operations (TCP retransmits, keepalives, etc.).
    /// Returns `None` if no timer-based polling is needed.
    fn poll_delay(&mut self) -> Option<Duration> {
        None
    }

    /// Called when the worker is shutting down.
    fn on_exit(&mut self);
}

/// Factory trait for creating async network backends.
///
/// The factory pattern allows the backend to initialize async resources
/// inside the worker's tokio runtime, which is necessary for backends
/// that spawn tasks or use async I/O.
///
/// # Usage
///
/// 1. Create a factory on the main thread with configuration
/// 2. Pass the factory to the VMM via `VirtioNetBackend::CustomAsyncFactory`
/// 3. The async worker calls `create()` inside its own runtime
/// 4. Backend async resources are properly initialized on the correct runtime
pub trait AsyncNetBackendFactory: Send + 'static {
    /// Create the backend and return a handle for communication.
    ///
    /// Called inside the worker's tokio runtime on a `LocalSet`, so the
    /// backend can spawn `!Send` tasks if needed.
    ///
    /// The backend should store the `mpsc::Sender<Bytes>` internally
    /// for sending packets to the guest.
    fn create(self: Box<Self>) -> SendBoxFuture<'static, io::Result<NetBackendHandle>>;
}
