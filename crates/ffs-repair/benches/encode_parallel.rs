#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for parallelizing the RaptorQ encode GF combine (bd-blr6r).
//!
//! `encode_group` builds R repair symbols, each an independent GF256 linear
//! combination of K source symbols into a fresh block. The old loop ran the R
//! combines serially; the new code runs them in parallel across cores (rayon).
//! This bench isolates that GF combine: build K random source blocks + R random
//! coefficient rows, then compute the R repair blocks serially vs. via
//! `into_par_iter`. Both produce the identical repair blocks (asserted).

use asupersync::raptorq::gf256::{Gf256, gf256_addmul_slice};
use criterion::{Criterion, criterion_group, criterion_main};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use std::hint::black_box;

const K: usize = 64; // source symbols per group
const R: usize = 16; // repair symbols (parallelized across)
const BLOCK: usize = 4096; // symbol size (bytes)

/// Deterministic pseudo-random byte (no Math.random in benches).
fn prng(seed: u64) -> u8 {
    let x = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (x >> 33) as u8
}

fn build_sources() -> Vec<Vec<u8>> {
    (0..K)
        .map(|s| {
            (0..BLOCK)
                .map(|b| prng((s as u64) << 20 ^ b as u64))
                .collect()
        })
        .collect()
}

/// R coefficient rows, each K non-trivial GF256 coefficients.
fn build_coeffs() -> Vec<Vec<u8>> {
    (0..R)
        .map(|r| {
            (0..K)
                .map(|s| prng(0x00C0_FFEE ^ (r as u64) << 16 ^ s as u64) | 1)
                .collect()
        })
        .collect()
}

fn combine_one(coeffs: &[u8], sources: &[Vec<u8>]) -> Vec<u8> {
    let mut data = vec![0_u8; BLOCK];
    for (&c, src) in coeffs.iter().zip(sources) {
        let coeff = Gf256::new(c);
        if coeff.is_zero() {
            continue;
        }
        gf256_addmul_slice(&mut data, src, coeff);
    }
    data
}

fn encode_serial(coeff_rows: &[Vec<u8>], sources: &[Vec<u8>]) -> Vec<Vec<u8>> {
    coeff_rows
        .iter()
        .map(|row| combine_one(row, sources))
        .collect()
}

fn encode_parallel(coeff_rows: &[Vec<u8>], sources: &[Vec<u8>]) -> Vec<Vec<u8>> {
    (0..coeff_rows.len())
        .into_par_iter()
        .map(|r| combine_one(&coeff_rows[r], sources))
        .collect()
}

fn bench_encode(c: &mut Criterion) {
    let sources = build_sources();
    let coeff_rows = build_coeffs();

    // Isomorphism: parallel produces the identical repair blocks, same order.
    assert_eq!(
        encode_serial(&coeff_rows, &sources),
        encode_parallel(&coeff_rows, &sources),
        "parallel encode diverged from serial"
    );

    let mut group = c.benchmark_group("raptorq_encode_combine_k64_r16_4k");
    group.bench_function("serial", |b| {
        b.iter(|| black_box(encode_serial(black_box(&coeff_rows), black_box(&sources))));
    });
    group.bench_function("parallel_rayon", |b| {
        b.iter(|| black_box(encode_parallel(black_box(&coeff_rows), black_box(&sources))));
    });
    group.finish();
}

criterion_group!(benches, bench_encode);
criterion_main!(benches);
