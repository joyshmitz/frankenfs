#![forbid(unsafe_code)]

//! Benchmarks for mount runtime mode dispatch infrastructure.
//!
//! Measures the overhead of per-core routing, work-stealing decisions,
//! aggregate metrics collection, backpressure decisions, and atomic
//! metrics recording. These operate without actual FUSE mounts.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_fuse::AtomicMetrics;
use ffs_fuse::per_core::{PerCoreConfig, PerCoreDispatcher};
use std::hint::black_box;
use std::sync::atomic::Ordering;

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

criterion_group!(
    mount_runtime,
    bench_per_core_route_inode,
    bench_per_core_route_lookup,
    bench_per_core_should_steal,
    bench_per_core_aggregate_metrics,
    bench_metrics_record_throughput,
    bench_backpressure_normal,
    bench_backpressure_degraded,
    bench_backpressure_emergency,
);
criterion_main!(mount_runtime);
