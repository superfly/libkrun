// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Simplified exit reason for scheduler decision-making.
/// Abstracts over platform-specific exit types (HVF VcpuExit, KVM exit, etc.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VcpuExitReason {
    Mmio,
    SystemRegister,
    TimerActivated,
    WaitForEvent,
    Shutdown,
    Other,
}

/// Trait for controlling vCPU scheduling in the VMM run loop.
///
/// Implementations control which vCPU runs at any given time via a barrier-based
/// model: each vCPU thread calls `request_run_permission` before entering
/// `hv_vcpu_run()`, and the scheduler decides when to yield via `on_exit`.
///
/// All methods take `&self` — implementations use interior mutability (Mutex/Condvar).
pub trait VcpuScheduler: Send + Sync {
    /// Blocks until this vCPU is allowed to execute.
    /// Called before each hv_vcpu_run(). Returns immediately if this vCPU
    /// already holds the run permission (i.e., on_exit returned false).
    fn request_run_permission(&self, vcpu_id: usize);

    /// Called after each hv_vcpu_run exit. Returns true if vCPU should yield
    /// its time slice (caller must then call release_run_permission).
    fn on_exit(&self, vcpu_id: usize, exit_reason: VcpuExitReason) -> bool;

    /// Signals this vCPU has yielded. Unblocks the next scheduled vCPU.
    /// Only call after on_exit returned true.
    fn release_run_permission(&self, vcpu_id: usize);

    /// Returns synthetic timer counter value when guest reads CNTVCT_EL0.
    /// Only called when wants_timer_trapping() returns true.
    fn timer_counter(&self, vcpu_id: usize) -> u64;

    /// Whether timer counter trapping should be enabled for this scheduler.
    fn wants_timer_trapping(&self) -> bool;

    /// Called when active vCPU switches from one to another.
    /// Used for timer offset adjustments on hardware without FEAT_ECV.
    fn on_vcpu_switch(&self, _from_vcpu: usize, _to_vcpu: usize) {}

    /// Serialize scheduler state for VM snapshot.
    fn save_state(&self) -> Vec<u8>;

    /// Restore scheduler state from VM snapshot.
    fn restore_state(&self, state: &[u8]);
}

/// No-op scheduler — all vCPUs run concurrently with zero overhead.
/// This is the default when no scheduling injection is configured.
pub struct PassthroughScheduler;

impl VcpuScheduler for PassthroughScheduler {
    fn request_run_permission(&self, _vcpu_id: usize) {}

    fn on_exit(&self, _vcpu_id: usize, _exit_reason: VcpuExitReason) -> bool {
        false // Never yield
    }

    fn release_run_permission(&self, _vcpu_id: usize) {}

    fn timer_counter(&self, _vcpu_id: usize) -> u64 {
        0 // Should never be called (wants_timer_trapping is false)
    }

    fn wants_timer_trapping(&self) -> bool {
        false
    }

    fn save_state(&self) -> Vec<u8> {
        Vec::new()
    }

    fn restore_state(&self, _state: &[u8]) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passthrough_scheduler_request_permission() {
        let scheduler = PassthroughScheduler;
        // Should return without blocking
        scheduler.request_run_permission(0);
        scheduler.request_run_permission(1);
    }

    #[test]
    fn test_passthrough_scheduler_on_exit_returns_false() {
        let scheduler = PassthroughScheduler;
        // on_exit should always return false (never yield)
        assert!(!scheduler.on_exit(0, VcpuExitReason::Mmio));
        assert!(!scheduler.on_exit(0, VcpuExitReason::SystemRegister));
        assert!(!scheduler.on_exit(0, VcpuExitReason::TimerActivated));
        assert!(!scheduler.on_exit(0, VcpuExitReason::WaitForEvent));
        assert!(!scheduler.on_exit(0, VcpuExitReason::Shutdown));
        assert!(!scheduler.on_exit(0, VcpuExitReason::Other));
        assert!(!scheduler.on_exit(1, VcpuExitReason::Mmio));
    }

    #[test]
    fn test_passthrough_scheduler_release_permission() {
        let scheduler = PassthroughScheduler;
        // Should return without blocking
        scheduler.release_run_permission(0);
        scheduler.release_run_permission(1);
    }

    #[test]
    fn test_passthrough_scheduler_timer_counter() {
        let scheduler = PassthroughScheduler;
        assert_eq!(scheduler.timer_counter(0), 0);
        assert_eq!(scheduler.timer_counter(1), 0);
    }

    #[test]
    fn test_passthrough_scheduler_wants_timer_trapping() {
        let scheduler = PassthroughScheduler;
        // Should never want timer trapping (zero overhead)
        assert!(!scheduler.wants_timer_trapping());
    }

    #[test]
    fn test_passthrough_scheduler_on_vcpu_switch() {
        let scheduler = PassthroughScheduler;
        // Should not panic
        scheduler.on_vcpu_switch(0, 1);
        scheduler.on_vcpu_switch(1, 0);
    }

    #[test]
    fn test_passthrough_scheduler_save_state() {
        let scheduler = PassthroughScheduler;
        let state = scheduler.save_state();
        assert!(state.is_empty());
    }

    #[test]
    fn test_passthrough_scheduler_restore_state() {
        let scheduler = PassthroughScheduler;
        // Should not panic on empty state
        scheduler.restore_state(&[]);
        // Should not panic on non-empty state
        scheduler.restore_state(&[1, 2, 3]);
    }

    #[test]
    fn test_passthrough_scheduler_zero_overhead() {
        let scheduler = PassthroughScheduler;
        // Verify that all methods return immediately without blocking
        // This is a functional test — actual performance benchmarking is out of scope
        for vcpu_id in 0..4 {
            scheduler.request_run_permission(vcpu_id);
            assert!(!scheduler.on_exit(vcpu_id, VcpuExitReason::Mmio));
            scheduler.release_run_permission(vcpu_id);
        }
    }
}
