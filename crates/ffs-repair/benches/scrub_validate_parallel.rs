#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for parallelizing the per-block validation in
//! `Scrubber::scrub_range`.
//!
//! `scrub_range` reads a batch of blocks contiguously (one vectored device
//! read), then validates each block in the batch SERIALLY via
//! `BlockValidator::validate`. For an integrity scrub the validator computes a
//! per-block checksum (crc32c over the whole block) — pure, independent CPU
//! work. A whole-device scrub runs this over every block on the device (TB
//! scale), so the serial validation loop is the rank-1 CPU cost once the reads
//! are cached / fast.
//!
//! `validate(&self, block, data)` takes no `cx` and the validator is
//! `Send + Sync`, so the batch's validations are embarrassingly parallel.
//! Collecting the verdicts in block order keeps the findings list and the
//! corrupt/clean counters byte-identical to the serial loop — only the order
//! the (pure) checksums are computed in changes.
//!
//! This bench isolates that validation fan-out at a decoupled validate window
//! (512 blocks — larger than the 64-block contiguous read batch, to amortize
//! the rayon fan-out): build the window, validate it serially vs. via
//! `into_par_iter`, asserting identical verdict tags.
//!
//! Measured (rch CI remote, ~2 effective cores): 64-block window = 1.81x,
//! 512-block window = 2.00x median. CPU-bound parallelism is core-limited on
//! this host; the lever scales toward core count on real multi-core hardware
//! where TB-scale scrubs actually run. Tracked as bd-tyym4 (ship + confirm the
//! production decoupled-window restructure on a real multi-core host).

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_block::BlockBuf;
use ffs_repair::scrub::{BlockValidator, BlockVerdict, CorruptionKind, Severity};
use ffs_types::BlockNumber;
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use std::hint::black_box;

const BATCH: usize = 512; // parallel-validate window (decoupled from 64-block read batch)
const BS: usize = 4096; // block size

/// Deterministic pseudo-random byte (no `Math.random` in benches).
fn prng(seed: u64) -> u8 {
    let x = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (x >> 33) as u8
}

/// Representative integrity validator: checksums every block (crc32c over the
/// whole block) and flags blocks whose checksum has its low bit set. The crc is
/// data-dependent so it cannot be elided, and the verdict is deterministic.
struct Crc32cValidator;

impl BlockValidator for Crc32cValidator {
    fn validate(&self, block: BlockNumber, data: &BlockBuf) -> BlockVerdict {
        let crc = crc32c::crc32c(data.as_slice());
        if crc & 1 == 0 {
            BlockVerdict::Clean
        } else {
            BlockVerdict::Corrupt(vec![(
                CorruptionKind::StructuralInvariant,
                Severity::Error,
                format!("synthetic odd-crc finding for block {}", block.0),
            )])
        }
    }
}

fn build_batch() -> Vec<BlockBuf> {
    (0..BATCH)
        .map(|b| {
            let bytes: Vec<u8> = (0..BS).map(|i| prng((b as u64) << 20 ^ i as u64)).collect();
            BlockBuf::new(bytes)
        })
        .collect()
}

/// Tag a verdict so the two arms can be compared without `PartialEq`.
fn tag(v: &BlockVerdict) -> u8 {
    match v {
        BlockVerdict::Clean => 0,
        BlockVerdict::Corrupt(_) => 1,
        BlockVerdict::Skip => 2,
    }
}

/// Pre-lever: validate each block in the batch serially.
fn serial_validate(validator: &Crc32cValidator, bufs: &[BlockBuf]) -> Vec<u8> {
    bufs.iter()
        .enumerate()
        .map(|(i, buf)| tag(&validator.validate(BlockNumber(i as u64), buf)))
        .collect()
}

/// Lever: validate the batch's blocks in parallel, collecting verdicts in
/// block order (identical findings/counters as the serial loop).
fn parallel_validate(validator: &Crc32cValidator, bufs: &[BlockBuf]) -> Vec<u8> {
    (0..bufs.len())
        .into_par_iter()
        .map(|i| tag(&validator.validate(BlockNumber(i as u64), &bufs[i])))
        .collect()
}

fn bench_scrub_validate_parallel(c: &mut Criterion) {
    let validator = Crc32cValidator;
    let bufs = build_batch();

    // Isomorphism: identical verdict-tag sequence regardless of order.
    assert_eq!(
        serial_validate(&validator, &bufs),
        parallel_validate(&validator, &bufs),
        "parallel scrub validation diverged from serial"
    );

    let mut group = c.benchmark_group("scrub_validate_window");
    group.bench_function("serial_validate", |b| {
        b.iter(|| black_box(serial_validate(black_box(&validator), black_box(&bufs))));
    });
    group.bench_function("parallel_validate", |b| {
        b.iter(|| black_box(parallel_validate(black_box(&validator), black_box(&bufs))));
    });
    group.finish();
}

criterion_group!(benches, bench_scrub_validate_parallel);
criterion_main!(benches);
