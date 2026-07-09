#![forbid(unsafe_code)]

//! Benchmarks for mount runtime mode dispatch infrastructure.
//!
//! Measures the overhead of per-core routing, work-stealing decisions,
//! aggregate metrics collection, backpressure decisions, and atomic
//! metrics recording. These operate without actual FUSE mounts.

use asupersync::Cx;
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_core::{FsOps, InodeAttr, ReaddirPage, RequestOp, RequestScope};
use ffs_error::FfsError;
use ffs_fuse::per_core::{PerCoreConfig, PerCoreDispatcher, inode_to_core};
use ffs_fuse::{AtomicMetrics, FrankenFuse, MountOptions, WritebackCacheMode};
use ffs_types::{CommitSeq, InodeNumber};
use std::ffi::OsStr;
use std::hint::black_box;
use std::sync::atomic::Ordering;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::Duration;

fn legacy_inode_to_core(ino: u64, num_cores: u32) -> u32 {
    if num_cores == 0 {
        return 0;
    }
    let mixed = ino.wrapping_mul(0x517c_c1b7_2722_0a95);
    #[expect(clippy::cast_possible_truncation)] // intentional 64->32 fold
    let folded = (mixed ^ (mixed >> 32)) as u32;
    folded % num_cores
}

fn bench_per_core_route_hash_ab(c: &mut Criterion) {
    let num_cores = 8_u32;
    let mut group = c.benchmark_group("mount_runtime_per_core_route_hash_ab");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(1));

    group.bench_function("legacy_modulo", |b| {
        let mut ino = 2_u64;
        b.iter(|| {
            let core = legacy_inode_to_core(black_box(ino), black_box(num_cores));
            ino = ino.wrapping_add(1);
            black_box(core);
        });
    });

    group.bench_function("power2_mask", |b| {
        let mut ino = 2_u64;
        b.iter(|| {
            let core = inode_to_core(black_box(ino), black_box(num_cores));
            ino = ino.wrapping_add(1);
            black_box(core);
        });
    });
    group.finish();
}

fn bench_per_core_route_inode(c: &mut Criterion) {
    let dispatcher = PerCoreDispatcher::new(PerCoreConfig {
        num_cores: 8,
        ..PerCoreConfig::default()
    });

    c.bench_function("mount_runtime_per_core_route_inode", |b| {
        let mut ino = 2_u64;
        b.iter(|| {
            let core = dispatcher.route_inode(black_box(ino));
            ino = ino.wrapping_add(1);
            black_box(core);
        });
    });
}

fn bench_per_core_route_lookup(c: &mut Criterion) {
    let dispatcher = PerCoreDispatcher::new(PerCoreConfig {
        num_cores: 8,
        ..PerCoreConfig::default()
    });

    c.bench_function("mount_runtime_per_core_route_lookup", |b| {
        let mut parent_ino = 2_u64;
        b.iter(|| {
            let core = dispatcher.route_lookup(black_box(parent_ino));
            parent_ino = parent_ino.wrapping_add(1);
            black_box(core);
        });
    });
}

fn bench_per_core_should_steal(c: &mut Criterion) {
    let dispatcher = PerCoreDispatcher::new(PerCoreConfig {
        num_cores: 8,
        ..PerCoreConfig::default()
    });

    // Create imbalanced load: core 0 gets all requests, others idle.
    if let Some(m) = dispatcher.core_metrics(0) {
        for _ in 0..10_000 {
            m.begin_request();
        }
    }

    c.bench_function("mount_runtime_per_core_should_steal", |b| {
        b.iter(|| {
            // Check if core 1 (idle) should steal from others.
            black_box(dispatcher.should_steal(black_box(1)));
        });
    });
}

fn bench_per_core_aggregate_metrics(c: &mut Criterion) {
    let dispatcher = PerCoreDispatcher::new(PerCoreConfig {
        num_cores: 8,
        ..PerCoreConfig::default()
    });

    // Populate some realistic metrics.
    for core_id in 0..8_u32 {
        if let Some(m) = dispatcher.core_metrics(core_id) {
            for _ in 0..(1000 * (core_id as usize + 1)) {
                m.record_request();
                m.record_hit();
            }
            for _ in 0..(100 * (core_id as usize + 1)) {
                m.record_miss();
            }
        }
    }

    c.bench_function("mount_runtime_per_core_aggregate_metrics", |b| {
        b.iter(|| {
            black_box(dispatcher.aggregate_metrics());
        });
    });
}

fn bench_metrics_record_throughput(c: &mut Criterion) {
    let metrics = AtomicMetrics::new();

    c.bench_function("mount_runtime_metrics_record_throughput", |b| {
        b.iter(|| {
            metrics.requests_total.0.fetch_add(1, Ordering::Relaxed);
            metrics.requests_ok.0.fetch_add(1, Ordering::Relaxed);
            black_box(&metrics);
        });
    });
}

fn bench_backpressure_normal(c: &mut Criterion) {
    use asupersync::SystemPressure;
    use ffs_core::{BackpressureGate, DegradationFsm, RequestOp};
    use std::sync::Arc;

    let pressure = Arc::new(SystemPressure::new());
    let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
    let gate = BackpressureGate::new(fsm);

    c.bench_function("mount_runtime_backpressure_normal", |b| {
        b.iter(|| {
            black_box(gate.check(black_box(RequestOp::Read)));
        });
    });
}

fn bench_backpressure_degraded(c: &mut Criterion) {
    use asupersync::SystemPressure;
    use ffs_core::{BackpressureGate, DegradationFsm, RequestOp};
    use std::sync::Arc;

    // headroom=0.2 → degraded after tick
    let pressure = Arc::new(SystemPressure::with_headroom(0.2));
    let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
    fsm.tick();
    let gate = BackpressureGate::new(fsm);

    c.bench_function("mount_runtime_backpressure_degraded", |b| {
        b.iter(|| {
            // Read ops proceed even under degraded state (no throttle delay).
            black_box(gate.check(black_box(RequestOp::Read)));
        });
    });
}

fn bench_backpressure_emergency(c: &mut Criterion) {
    use asupersync::SystemPressure;
    use ffs_core::{BackpressureGate, DegradationFsm, RequestOp};
    use std::sync::Arc;

    // headroom=0.02 → emergency after tick
    let pressure = Arc::new(SystemPressure::with_headroom(0.02));
    let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
    fsm.tick();
    let gate = BackpressureGate::new(fsm);

    c.bench_function("mount_runtime_backpressure_emergency", |b| {
        b.iter(|| {
            // Write ops get shed under emergency — measures decision latency only.
            black_box(gate.check(black_box(RequestOp::Write)));
        });
    });
}

struct WritebackBenchFs {
    writes: AtomicU64,
    commits: AtomicU64,
    commit_work: u64,
}

impl WritebackBenchFs {
    fn new(commit_work: u64) -> Self {
        Self {
            writes: AtomicU64::new(0),
            commits: AtomicU64::new(0),
            commit_work,
        }
    }
}

impl FsOps for WritebackBenchFs {
    fn getattr(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<InodeAttr> {
        Err(FfsError::UnsupportedFeature(
            "writeback bench does not model getattr".to_owned(),
        ))
    }

    fn lookup(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _parent: InodeNumber,
        _name: &OsStr,
    ) -> ffs_error::Result<InodeAttr> {
        Err(FfsError::UnsupportedFeature(
            "writeback bench does not model lookup".to_owned(),
        ))
    }

    fn readdir(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _offset: u64,
    ) -> ffs_error::Result<ReaddirPage> {
        Err(FfsError::UnsupportedFeature(
            "writeback bench does not model readdir".to_owned(),
        ))
    }

    fn read(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _offset: u64,
        size: u32,
    ) -> ffs_error::Result<Vec<u8>> {
        Ok(vec![0; usize::try_from(size).unwrap_or(usize::MAX)])
    }

    fn readlink(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "writeback bench does not model readlink".to_owned(),
        ))
    }

    fn write(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _offset: u64,
        data: &[u8],
    ) -> ffs_error::Result<u32> {
        self.writes.fetch_add(1, AtomicOrdering::Relaxed);
        Ok(u32::try_from(data.len()).unwrap_or(u32::MAX))
    }

    fn begin_request_scope(&self, _cx: &Cx, _op: RequestOp) -> ffs_error::Result<RequestScope> {
        Ok(RequestScope::empty())
    }

    fn commit_request_scope(&self, _scope: &mut RequestScope) -> ffs_error::Result<CommitSeq> {
        let mut state = self.commits.load(AtomicOrdering::Relaxed);
        for n in 0..self.commit_work {
            state = state.wrapping_add(n.rotate_left(7)).rotate_left(13) ^ 0x9E37_79B9_7F4A_7C15;
        }
        black_box(state);
        let seq = self.commits.fetch_add(1, AtomicOrdering::Relaxed) + 1;
        Ok(CommitSeq(seq))
    }

    fn end_request_scope(
        &self,
        _cx: &Cx,
        _op: RequestOp,
        _scope: RequestScope,
    ) -> ffs_error::Result<()> {
        Ok(())
    }

    fn fsync(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _fh: u64,
        _datasync: bool,
    ) -> ffs_error::Result<()> {
        Ok(())
    }
}

fn run_writeback_batch(writeback_cache: bool, writes: usize, payload: &[u8], commit_work: u64) {
    let options = MountOptions {
        read_only: false,
        writeback_cache: WritebackCacheMode::from_enabled(writeback_cache),
        ..MountOptions::default()
    };
    let fuse = FrankenFuse::with_options(Box::new(WritebackBenchFs::new(commit_work)), &options);
    for index in 0..writes {
        let offset = i64::try_from(index.saturating_mul(payload.len())).unwrap_or(i64::MAX);
        let written = fuse
            .write_for_fuzzing(44, offset, payload)
            .expect("bench write succeeds");
        assert_eq!(written as usize, payload.len());
    }
    if writeback_cache {
        fuse.flush_for_fuzzing(44, 0, 0)
            .expect("bench flush commits deferred writeback");
    }
}

fn bench_writeback_cache_batching(c: &mut Criterion) {
    let payload = vec![0x5A_u8; 32 * 1024];
    let writes = 32_usize;
    let commit_work = 512_u64;
    let mut group = c.benchmark_group("mount_runtime_writeback");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(1));

    group.bench_function("per_write_commit_32x32k", |b| {
        b.iter(|| run_writeback_batch(false, writes, black_box(&payload), commit_work));
    });

    group.bench_function("deferred_flush_32x32k", |b| {
        b.iter(|| run_writeback_batch(true, writes, black_box(&payload), commit_work));
    });
    group.finish();
}

criterion_group!(
    mount_runtime,
    bench_per_core_route_hash_ab,
    bench_per_core_route_inode,
    bench_per_core_route_lookup,
    bench_per_core_should_steal,
    bench_per_core_aggregate_metrics,
    bench_metrics_record_throughput,
    bench_backpressure_normal,
    bench_backpressure_degraded,
    bench_backpressure_emergency,
    bench_writeback_cache_batching,
);
criterion_main!(mount_runtime);
