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

    /// The Part-A multi-group allocation scan. Walks `order` (the goal group →
    /// ±neighbors → full-fallback sequence produced by
    /// `ffs_alloc::allocation_group_order`), locking each candidate group ONE AT
    /// A TIME, and returns the first group where `try_in_group` succeeds. The
    /// group lock is released before advancing, so at most one group lock is held
    /// at any instant — exactly the single-acquisition discipline the Loom writer
    /// projection proves deadlock-free (no two-lock cycle) and linearizable, and
    /// the resolution for the "a request that can't fit in the goal group mutates
    /// a different group" hazard that made naive fixed-target locking wrong.
    ///
    /// `try_in_group(group, &mut stats)` performs the real in-group allocation
    /// (bitmap read/set + count decrement, e.g. via `ffs_alloc::try_alloc_safe`
    /// with the device + geometry captured), returning `Some(result)` on success
    /// (leaving that group mutated) or `None` to fall through to the next group.
    /// Out-of-range group indices in `order` are skipped.
    pub(crate) fn alloc_in_scan_order<T>(
        &self,
        order: impl IntoIterator<Item = usize>,
        mut try_in_group: impl FnMut(usize, &mut GroupStats) -> Option<T>,
    ) -> Option<T> {
        for group in order {
            if group >= self.groups.len() {
                continue;
            }
            let mut stats = self.groups[group].stats.lock();
            if let Some(result) = try_in_group(group, &mut stats) {
                return Some(result);
            }
            // `stats` (the group lock) is dropped here, before the next group —
            // never two group locks at once.
        }
        None
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

    /// Try to allocate `want` blocks from a group: succeed (decrement) iff it has
    /// enough, returning the group index; a stand-in for `try_alloc_safe`.
    fn try_take(want: u32) -> impl FnMut(usize, &mut GroupStats) -> Option<usize> {
        move |g, stats| {
            if stats.free_blocks >= want {
                stats.free_blocks -= want;
                Some(g)
            } else {
                None
            }
        }
    }

    #[test]
    fn scan_stops_at_first_satisfying_group_and_mutates_only_it() {
        let stats: Vec<GroupStats> = [0u32, 0, 5, 10]
            .into_iter()
            .enumerate()
            .map(|(g, fb)| sample_group(g as u32, fb, 0))
            .collect();
        let sharded = PerGroupAlloc::from_group_stats(stats);
        // Order 0,1,2,3: groups 0,1 have 0 free (fail), group 2 has 5 >= 3 -> take.
        let hit = sharded.alloc_in_scan_order(0..4, try_take(3));
        assert_eq!(hit, Some(2));
        assert_eq!(sharded.lock_group(0).free_blocks, 0);
        assert_eq!(sharded.lock_group(1).free_blocks, 0);
        assert_eq!(sharded.lock_group(2).free_blocks, 2, "group 2 should be debited");
        assert_eq!(sharded.lock_group(3).free_blocks, 10, "group 3 untouched (scan stopped)");
    }

    #[test]
    fn scan_honors_order_goal_group_first() {
        let stats: Vec<GroupStats> = [4u32, 4, 4, 4]
            .into_iter()
            .enumerate()
            .map(|(g, fb)| sample_group(g as u32, fb, 0))
            .collect();
        let sharded = PerGroupAlloc::from_group_stats(stats);
        // Goal group 2 first: it satisfies, so it (not group 0) is debited.
        let hit = sharded.alloc_in_scan_order([2usize, 0, 1, 3], try_take(3));
        assert_eq!(hit, Some(2));
        assert_eq!(sharded.lock_group(2).free_blocks, 1);
        assert_eq!(sharded.lock_group(0).free_blocks, 4, "goal group won; others untouched");
    }

    #[test]
    fn scan_returns_none_and_mutates_nothing_when_no_group_fits() {
        let stats: Vec<GroupStats> = [2u32, 1, 2]
            .into_iter()
            .enumerate()
            .map(|(g, fb)| sample_group(g as u32, fb, 0))
            .collect();
        let sharded = PerGroupAlloc::from_group_stats(stats);
        let hit = sharded.alloc_in_scan_order(0..3, try_take(3));
        assert_eq!(hit, None);
        for g in 0..3usize {
            let expect = [2u32, 1, 2][g];
            assert_eq!(sharded.lock_group(g).free_blocks, expect, "group {g} must be unchanged");
        }
    }

    #[test]
    fn scan_skips_out_of_range_group_indices() {
        let stats: Vec<GroupStats> = [0u32, 5]
            .into_iter()
            .enumerate()
            .map(|(g, fb)| sample_group(g as u32, fb, 0))
            .collect();
        let sharded = PerGroupAlloc::from_group_stats(stats);
        // 99 is out of range (skipped), 0 fails, 1 satisfies.
        let hit = sharded.alloc_in_scan_order([99usize, 0, 1], try_take(3));
        assert_eq!(hit, Some(1));
        assert_eq!(sharded.lock_group(1).free_blocks, 2);
    }
}
