#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for parallelizing the PoR prover response loop,
//! `por::respond_to_challenges` (bd-eei3y).
//!
//! Answering a Proof-of-Retrievability audit reads the challenged block and
//! BLAKE3-hashes it, once per challenge (~460 challenges for 2^-128 security).
//! Both the block read (I/O latency) and the full-block hash (CPU) are
//! independent per challenge, so the serial loop pays ~460 read latencies plus
//! ~460 hashes back to back.
//!
//! The lever answers the challenges across the rayon pool: a blocking read parks
//! its worker so the read latencies overlap up to the pool size, and the BLAKE3
//! hashes run across cores. `filter_map` has no early-return (a failed read
//! drops the challenge via `None`) and rayon's `collect` preserves the relative
//! order of the surviving responses, so the result is byte-identical.
//!
//! This bench isolates the response loop: a latency-injecting `Fn` closure
//! (sleep + return pre-built bytes, the production read cost shape) feeds the
//! serial vs parallel response builders, both running real BLAKE3. Both produce
//! the identical response sequence (asserted), so this measures the read overlap
//! plus hash parallelism.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;

const BS: usize = 4096; // challenged block size (bytes)
/// Per-block read access latency. Models a real-disk / SSD-queue round trip.
const READ_LATENCY: Duration = Duration::from_micros(250);

/// Deterministic pseudo-random byte (no `Math.random` in benches).
fn prng(seed: u64) -> u8 {
    let x = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (x >> 33) as u8
}

fn block_bytes(idx: u64) -> Vec<u8> {
    (0..BS).map(|i| prng(idx << 20 ^ i as u64)).collect()
}

#[derive(Clone, Copy)]
struct Challenge {
    index: u64,
    table_offset: u32,
}

#[derive(PartialEq, Eq, Debug)]
struct Response {
    index: u64,
    block_hash: [u8; 32],
    authenticator: [u8; 32],
}

/// OLD: serial read + hash loop.
fn respond_serial<F>(challenges: &[Challenge], auth: &[[u8; 32]], read_block: F) -> Vec<Response>
where
    F: Fn(u64) -> Option<Vec<u8>>,
{
    challenges
        .iter()
        .filter_map(|ch| {
            let data = read_block(ch.index)?;
            let block_hash = *blake3::hash(&data).as_bytes();
            let authenticator = *auth.get(ch.table_offset as usize)?;
            Some(Response {
                index: ch.index,
                block_hash,
                authenticator,
            })
        })
        .collect()
}

/// NEW: parallel read + hash across the rayon pool, order preserved by collect.
fn respond_parallel<F>(challenges: &[Challenge], auth: &[[u8; 32]], read_block: F) -> Vec<Response>
where
    F: Fn(u64) -> Option<Vec<u8>> + Sync + Send,
{
    use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
    challenges
        .par_iter()
        .filter_map(|ch| {
            let data = read_block(ch.index)?;
            let block_hash = *blake3::hash(&data).as_bytes();
            let authenticator = *auth.get(ch.table_offset as usize)?;
            Some(Response {
                index: ch.index,
                block_hash,
                authenticator,
            })
        })
        .collect()
}

fn bench_respond(c: &mut Criterion) {
    let mut group = c.benchmark_group("por_respond_io_overlap");
    for &n in &[64_usize, 256, 460] {
        let challenges: Vec<Challenge> = (0..n as u64)
            .map(|i| Challenge {
                index: i,
                table_offset: i as u32,
            })
            .collect();
        let auth: Vec<[u8; 32]> = (0..n).map(|i| [(i & 0xff) as u8; 32]).collect();
        let read_block = |idx: u64| -> Option<Vec<u8>> {
            std::thread::sleep(READ_LATENCY);
            Some(block_bytes(idx))
        };

        // Isomorphism: parallel responses == serial responses, same order.
        assert_eq!(
            respond_serial(&challenges, &auth, read_block),
            respond_parallel(&challenges, &auth, read_block),
            "parallel respond diverged from serial (n={n})"
        );

        group.bench_with_input(BenchmarkId::new("serial", n), &n, |b, _| {
            b.iter(|| black_box(respond_serial(black_box(&challenges), black_box(&auth), read_block)));
        });
        group.bench_with_input(BenchmarkId::new("parallel_rayon", n), &n, |b, _| {
            b.iter(|| {
                black_box(respond_parallel(
                    black_box(&challenges),
                    black_box(&auth),
                    read_block,
                ))
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_respond);
criterion_main!(benches);
