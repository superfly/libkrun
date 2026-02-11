// Copyright 2024 The libkrun Authors.
// SPDX-License-Identifier: Apache-2.0

//! Lock-free dirty page bitmap for tracking guest memory writes.
//!
//! Uses atomic operations so vCPU fault handlers can mark pages dirty
//! without acquiring a lock.

use std::sync::atomic::{AtomicU64, Ordering};

/// Page size on Apple Silicon (16KB).
pub const PAGE_SIZE: u64 = 16384;

/// A bitmap tracking dirty (written-to) guest memory pages.
///
/// Thread-safe: `mark_dirty` uses atomic OR operations and can be called
/// from vCPU data abort handlers without locking.
pub struct DirtyBitmap {
    /// Guest physical address of the start of the tracked region.
    base_addr: u64,
    /// Number of pages tracked.
    num_pages: usize,
    /// Bitmap stored as AtomicU64 words (each covers 64 pages).
    bitmap: Vec<AtomicU64>,
}

impl DirtyBitmap {
    /// Create a new dirty bitmap covering the given address range.
    pub fn new(base_addr: u64, size: u64) -> Self {
        let num_pages = ((size + PAGE_SIZE - 1) / PAGE_SIZE) as usize;
        let num_words = (num_pages + 63) / 64;
        let bitmap: Vec<AtomicU64> = (0..num_words).map(|_| AtomicU64::new(0)).collect();

        DirtyBitmap {
            base_addr,
            num_pages,
            bitmap,
        }
    }

    /// Check whether a guest address falls within this bitmap's range.
    pub fn contains(&self, guest_addr: u64) -> bool {
        guest_addr >= self.base_addr
            && guest_addr < self.base_addr + (self.num_pages as u64 * PAGE_SIZE)
    }

    /// Mark the page containing `guest_addr` as dirty.
    /// This is lock-free and safe to call from vCPU fault handlers.
    pub fn mark_dirty(&self, guest_addr: u64) {
        debug_assert!(self.contains(guest_addr));
        let page_idx = ((guest_addr - self.base_addr) / PAGE_SIZE) as usize;
        let word_idx = page_idx / 64;
        let bit_idx = page_idx % 64;
        self.bitmap[word_idx].fetch_or(1u64 << bit_idx, Ordering::Relaxed);
    }

    /// Check whether the page at the given index is dirty.
    pub fn is_dirty(&self, page_idx: usize) -> bool {
        if page_idx >= self.num_pages {
            return false;
        }
        let word_idx = page_idx / 64;
        let bit_idx = page_idx % 64;
        (self.bitmap[word_idx].load(Ordering::Relaxed) >> bit_idx) & 1 != 0
    }

    /// Reset the bitmap, returning the old state as a Vec of u64 words.
    /// Each bit that was set represents a dirty page.
    pub fn reset(&self) -> Vec<u64> {
        self.bitmap
            .iter()
            .map(|word| word.swap(0, Ordering::AcqRel))
            .collect()
    }

    /// Get the base address of this bitmap's tracked region.
    pub fn base_addr(&self) -> u64 {
        self.base_addr
    }

    /// Get the number of pages tracked.
    pub fn num_pages(&self) -> usize {
        self.num_pages
    }

    /// Iterate over dirty page indices and return their guest addresses.
    /// Resets the bitmap in the process.
    pub fn drain_dirty_pages(&self) -> Vec<u64> {
        let old_bitmap = self.reset();
        let mut dirty = Vec::new();
        for (word_idx, &word) in old_bitmap.iter().enumerate() {
            if word == 0 {
                continue;
            }
            for bit_idx in 0..64 {
                if (word >> bit_idx) & 1 != 0 {
                    let page_idx = word_idx * 64 + bit_idx;
                    if page_idx < self.num_pages {
                        dirty.push(self.base_addr + (page_idx as u64 * PAGE_SIZE));
                    }
                }
            }
        }
        dirty
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_dirty_tracking() {
        let bitmap = DirtyBitmap::new(0x8000_0000, 4 * PAGE_SIZE);
        assert_eq!(bitmap.num_pages(), 4);

        // Initially nothing is dirty
        assert!(!bitmap.is_dirty(0));
        assert!(!bitmap.is_dirty(1));

        // Mark page 1 dirty
        bitmap.mark_dirty(0x8000_0000 + PAGE_SIZE);
        assert!(!bitmap.is_dirty(0));
        assert!(bitmap.is_dirty(1));

        // Contains check
        assert!(bitmap.contains(0x8000_0000));
        assert!(bitmap.contains(0x8000_0000 + 3 * PAGE_SIZE));
        assert!(!bitmap.contains(0x8000_0000 + 4 * PAGE_SIZE));
        assert!(!bitmap.contains(0x7FFF_FFFF));
    }

    #[test]
    fn test_drain_dirty_pages() {
        let bitmap = DirtyBitmap::new(0x8000_0000, 4 * PAGE_SIZE);

        bitmap.mark_dirty(0x8000_0000);
        bitmap.mark_dirty(0x8000_0000 + 2 * PAGE_SIZE);

        let dirty = bitmap.drain_dirty_pages();
        assert_eq!(dirty.len(), 2);
        assert_eq!(dirty[0], 0x8000_0000);
        assert_eq!(dirty[1], 0x8000_0000 + 2 * PAGE_SIZE);

        // After drain, bitmap should be clear
        assert!(!bitmap.is_dirty(0));
        assert!(!bitmap.is_dirty(2));
    }
}
