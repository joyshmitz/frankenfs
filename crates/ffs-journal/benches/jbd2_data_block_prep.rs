#![forbid(unsafe_code)]

//! A/B benchmark for the JBD2 data-block padding buffer prep in the per-commit
//! journal write path (`Jbd2Writer::commit_transaction`).
//!
//! Each journaled block write builds a `bs`-sized buffer. The old code did
//! `vec![0u8; bs]` (a full-block zero-init) then `copy_from_slice(payload)`; for
//! the common full-block payload the zero-init is entirely overwritten. The new
//! code copies the payload directly (`payload[..bs].to_vec()`) for full blocks
//! and only zero-pads short payloads. This measures whether skipping the
//! redundant zero-init is a real saving. Both produce byte-identical buffers.

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const BS: usize = 4096;
/// One descriptor group's worth of data blocks, so per-iteration harness
/// overhead is amortized across a realistic commit chunk.
const BLOCKS: usize = 256;

/// Old strategy: zero-init the block, then copy the payload over it.
fn prep_zero_init(payload: &[u8]) -> Vec<u8> {
    let mut padded = vec![0_u8; BS];
    let copy_len = payload.len().min(BS);
    padded[..copy_len].copy_from_slice(&payload[..copy_len]);
    padded
}

/// New strategy: full-block payloads copy directly (no zero-init); short
/// payloads still zero-pad to the block size.
fn prep_skip_zero_init(payload: &[u8]) -> Vec<u8> {
    let copy_len = payload.len().min(BS);
    if copy_len == BS {
        payload[..BS].to_vec()
    } else {
        let mut p = vec![0_u8; BS];
        p[..copy_len].copy_from_slice(&payload[..copy_len]);
        p
    }
}

fn prep_chunk<F: Fn(&[u8]) -> Vec<u8>>(payload: &[u8], prep: F) -> u64 {
    let mut acc = 0_u64;
    for _ in 0..BLOCKS {
        let padded = prep(black_box(payload));
        // Touch first + last byte so the buffer build cannot be elided.
        acc = acc
            .wrapping_add(u64::from(padded[0]))
            .wrapping_add(u64::from(padded[BS - 1]));
    }
    acc
}

fn bench_jbd2_data_block_prep(c: &mut Criterion) {
    let full = vec![0xAB_u8; BS];
    let short = vec![0xCD_u8; 100];

    // Byte-identity: both strategies produce the same buffer for full and short
    // payloads (the padded tail zeros are what the short arm preserves).
    assert_eq!(
        prep_zero_init(&full),
        prep_skip_zero_init(&full),
        "full-block prep diverged"
    );
    assert_eq!(
        prep_zero_init(&short),
        prep_skip_zero_init(&short),
        "short-payload prep diverged"
    );

    let mut group = c.benchmark_group("jbd2_data_block_prep_256x4096");
    group.bench_function("zero_init_then_copy_a", |b| {
        b.iter(|| black_box(prep_chunk(black_box(&full), prep_zero_init)));
    });
    group.bench_function("zero_init_then_copy_b", |b| {
        b.iter(|| black_box(prep_chunk(black_box(&full), prep_zero_init)));
    });
    group.bench_function("skip_zero_init", |b| {
        b.iter(|| black_box(prep_chunk(black_box(&full), prep_skip_zero_init)));
    });
    group.finish();
}

criterion_group!(benches, bench_jbd2_data_block_prep);
criterion_main!(benches);
