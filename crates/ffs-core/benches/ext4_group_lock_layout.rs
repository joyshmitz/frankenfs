#![forbid(unsafe_code)]

//! False-sharing guard for the bd-bhh0i per-group allocator refactor.
//!
//! The production gap is the global `RwLock<Ext4AllocState>::write` convoy.
//! Prior evidence says the real fix is per-group ownership. This benchmark
//! measures one design detail for that future layout: if the per-group hot lock
//! words and counters are stored adjacently, disjoint groups can still bounce the
//! same cache lines. Cache-line padding should remove that residual convoy.

use criterion::{Criterion, criterion_group, criterion_main};
use parking_lot::Mutex;
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

const GROUPS: usize = 8;
const THREADS: usize = GROUPS;
const OPS_PER_THREAD: usize = 50_000;

#[derive(Clone)]
struct GroupHotStats {
    free_blocks: u32,
    free_inodes: u32,
    used_dirs: u32,
    cursor: u64,
}

impl GroupHotStats {
    fn new(group: usize) -> Self {
        Self {
            free_blocks: 1_000_000,
            free_inodes: 1_000_000 - group as u32,
            used_dirs: group as u32,
            cursor: (group as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15),
        }
    }

    fn account_create(&mut self, op: usize) -> u64 {
        self.free_inodes = self.free_inodes.wrapping_sub(1);
        self.free_blocks = self.free_blocks.wrapping_sub((op & 1) as u32);
        self.used_dirs = self.used_dirs.wrapping_add((op & 3 == 0) as u32);
        self.cursor = self
            .cursor
            .wrapping_add(u64::from(self.free_inodes))
            .rotate_left((op as u32) & 31)
            ^ u64::from(self.free_blocks);
        self.cursor ^ u64::from(self.used_dirs)
    }
}

struct PlainGroup {
    stats: Mutex<GroupHotStats>,
}

#[repr(align(64))]
struct PaddedGroup {
    stats: Mutex<GroupHotStats>,
}

fn make_plain_groups() -> Arc<Vec<PlainGroup>> {
    Arc::new(
        (0..GROUPS)
            .map(|group| PlainGroup {
                stats: Mutex::new(GroupHotStats::new(group)),
            })
            .collect(),
    )
}

fn make_padded_groups() -> Arc<Vec<PaddedGroup>> {
    Arc::new(
        (0..GROUPS)
            .map(|group| PaddedGroup {
                stats: Mutex::new(GroupHotStats::new(group)),
            })
            .collect(),
    )
}

fn run_plain_groups(groups: &Arc<Vec<PlainGroup>>) -> u64 {
    let start = Arc::new(Barrier::new(THREADS));
    let total = Arc::new(AtomicU64::new(0));
    std::thread::scope(|scope| {
        for group in 0..GROUPS {
            let groups = Arc::clone(groups);
            let start = Arc::clone(&start);
            let total = Arc::clone(&total);
            scope.spawn(move || {
                start.wait();
                let mut local = 0_u64;
                for op in 0..OPS_PER_THREAD {
                    let mut stats = groups[group].stats.lock();
                    local = local.wrapping_add(stats.account_create(op));
                }
                total.fetch_add(local, Ordering::Relaxed);
            });
        }
    });
    total.load(Ordering::Relaxed)
}

fn run_padded_groups(groups: &Arc<Vec<PaddedGroup>>) -> u64 {
    let start = Arc::new(Barrier::new(THREADS));
    let total = Arc::new(AtomicU64::new(0));
    std::thread::scope(|scope| {
        for group in 0..GROUPS {
            let groups = Arc::clone(groups);
            let start = Arc::clone(&start);
            let total = Arc::clone(&total);
            scope.spawn(move || {
                start.wait();
                let mut local = 0_u64;
                for op in 0..OPS_PER_THREAD {
                    let mut stats = groups[group].stats.lock();
                    local = local.wrapping_add(stats.account_create(op));
                }
                total.fetch_add(local, Ordering::Relaxed);
            });
        }
    });
    total.load(Ordering::Relaxed)
}

fn bench_ext4_group_lock_layout(c: &mut Criterion) {
    let expected = run_plain_groups(&make_plain_groups());
    assert_eq!(
        expected,
        run_padded_groups(&make_padded_groups()),
        "padding changed the synthetic accounting result"
    );

    let plain_groups = make_plain_groups();
    let padded_groups = make_padded_groups();

    let mut group = c.benchmark_group("ext4_group_lock_layout_8t");
    group.bench_function("plain_adjacent_group_locks", |b| {
        b.iter(|| black_box(run_plain_groups(black_box(&plain_groups))));
    });
    group.bench_function("cacheline_padded_group_locks", |b| {
        b.iter(|| black_box(run_padded_groups(black_box(&padded_groups))));
    });
    group.finish();
}

criterion_group!(benches, bench_ext4_group_lock_layout);
criterion_main!(benches);
