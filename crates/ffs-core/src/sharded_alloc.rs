//! Per-group allocator lock decomposition (bd-bhh0i step 5), **default-OFF**.
//!
//! This is the production primitive matching the Loom-verified decomposition
//! (`tests/bd_bhh0i_lock_decomposition_model.rs`): the single whole-state
//! `RwLock<Ext4AllocState>` that serializes every ext4 mutation is replaced by
//! per-group locks, so disjoint-group creates proceed concurrently. Immutable
//! geometry is NOT held here — it is derived lock-free from the superblock
//! (`FsGeometry::from_superblock`), so this structure holds ONLY the per-group
//! mutable allocation records.
//!
//! Gated behind the `bhh0i_sharded_alloc` feature (default off). With the
//! feature off this module is not compiled and production keeps the single lock,
//! so the sharded path is byte-identical-absent by construction; the mandatory
//! e2fsck-clean cutover gate (step 7) is only reached once this path is wired in
//! and enabled. Building the primitive first lets it be Loom/bench/cargo-verified
//! entirely remote-only before any cutover.

#![allow(dead_code)] // wired into the alloc path in a later bd-bhh0i slice.

use ffs_alloc::GroupStats;
use parking_lot::{Mutex, MutexGuard};

/// One block group's mutable allocation record behind its own lock, cache-line
/// aligned to avoid false sharing between adjacent groups. The
/// `ext4_group_lock_layout` bench measured `#[repr(align(64))]` (Padded) beating
/// the unpadded layout under disjoint-group concurrent writes.
#[repr(align(64))]
struct GroupLock {
    stats: Mutex<GroupStats>,
}

/// Sharded per-group ext4 allocation records: one independently lockable record
/// per block group. A mutation locks only its target group's record, so
/// disjoint-group mutations never contend. A multi-group allocation scan
/// (goal → neighbors → full fallback) acquires group locks one at a time along
/// the scan and never holds two group locks at once, matching the
/// `groups(sorted)` acquisition order the Loom writer projection proves
/// deadlock-free and linearizable.
pub(crate) struct PerGroupAlloc {
    groups: Vec<GroupLock>,
}

impl PerGroupAlloc {
    /// Build the sharded records from the same `Vec<GroupStats>` the single-lock
    /// `Ext4AllocState` holds, moving each group's stats behind its own lock
    /// (no clone; identical initial state).
    pub(crate) fn from_group_stats(groups: Vec<GroupStats>) -> Self {
        Self {
            groups: groups
                .into_iter()
                .map(|stats| GroupLock {
                    stats: Mutex::new(stats),
                })
                .collect(),
        }
    }

    pub(crate) fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Lock a single group's record. Callers acquire at most one group lock at a
    /// time during a scan (see the struct doc); acquiring in ascending group
    /// order when more than one is ever needed preserves the sorted-acquisition
    /// invariant the Loom model relies on.
    pub(crate) fn lock_group(&self, group: usize) -> MutexGuard<'_, GroupStats> {
        self.groups[group].stats.lock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_types::{BlockNumber, GroupNumber};
    use std::sync::Arc;

    fn sample_group(n: u32, free_blocks: u32, free_inodes: u32) -> GroupStats {
        GroupStats {
            group: GroupNumber(n),
            free_blocks,
            block_largest_free_run: None,
            free_inodes,
            inode_search_start: 0,
            used_dirs: 0,
            block_bitmap_block: BlockNumber(u64::from(n) * 100 + 1),
            inode_bitmap_block: BlockNumber(u64::from(n) * 100 + 2),
            inode_table_block: BlockNumber(u64::from(n) * 100 + 3),
            flags: 0,
            block_bitmap_csum: 0,
            inode_bitmap_csum: 0,
            reserved_cache: std::sync::OnceLock::new(),
            reserved_confirmed: std::sync::OnceLock::new(),
        }
    }

    #[test]
    fn from_group_stats_round_trips_every_group() {
        let stats: Vec<GroupStats> = (0..4).map(|g| sample_group(g, 100 + g, 50 + g)).collect();
        let sharded = PerGroupAlloc::from_group_stats(stats);
        assert_eq!(sharded.group_count(), 4);
        for g in 0..4u32 {
            let rec = sharded.lock_group(g as usize);
            assert_eq!(rec.group, GroupNumber(g));
            assert_eq!(rec.free_blocks, 100 + g);
            assert_eq!(rec.free_inodes, 50 + g);
            assert_eq!(rec.inode_table_block, BlockNumber(u64::from(g) * 100 + 3));
        }
    }

    #[test]
    fn disjoint_groups_mutate_concurrently_without_lost_updates() {
        let stats: Vec<GroupStats> = (0..8).map(|g| sample_group(g, 1_000, 1_000)).collect();
        let sharded = Arc::new(PerGroupAlloc::from_group_stats(stats));
        // Each thread owns a distinct group and decrements its free counts; with
        // per-group locks these never contend, and no update is lost.
        let handles: Vec<_> = (0..8u32)
            .map(|g| {
                let sharded = Arc::clone(&sharded);
                std::thread::spawn(move || {
                    for _ in 0..1_000 {
                        let mut rec = sharded.lock_group(g as usize);
                        rec.free_blocks -= 1;
                        rec.free_inodes -= 1;
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread panicked");
        }
        for g in 0..8u32 {
            let rec = sharded.lock_group(g as usize);
            assert_eq!(rec.free_blocks, 0, "group {g} lost a block update");
            assert_eq!(rec.free_inodes, 0, "group {g} lost an inode update");
        }
    }
}
