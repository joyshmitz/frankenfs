#![forbid(unsafe_code)]

//! Per-crate A/Bs for indirect-truncate scans: the empty-block check and the
//! cutoff-prefix selector used before visiting pointers in an indirect block.
//!
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc \
//!   rch exec -- cargo bench --profile release-perf -p ffs-inode --bench indirect_zero_scan

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn byte_all_zero(data: &[u8]) -> bool {
    data.iter().all(|&b| b == 0)
}

fn unrolled4_all_zero(data: &[u8]) -> bool {
    let mut chunks = data.chunks_exact(32);
    for block in &mut chunks {
        let w0 = u64::from_ne_bytes(block[0..8].try_into().unwrap());
        let w1 = u64::from_ne_bytes(block[8..16].try_into().unwrap());
        let w2 = u64::from_ne_bytes(block[16..24].try_into().unwrap());
        let w3 = u64::from_ne_bytes(block[24..32].try_into().unwrap());
        if (w0 | w1 | w2 | w3) != 0 {
            return false;
        }
    }
    let mut tail = chunks.remainder().chunks_exact(8);
    tail.all(|c| u64::from_ne_bytes(c.try_into().unwrap()) == 0)
        && tail.remainder().iter().all(|&b| b == 0)
}

#[inline(never)]
fn linear_cutoff_scan(pointers: &[u32], base: u64, cutoff: u64, entry_span: u64) -> (u64, u64) {
    let ppb = pointers.len() as u64;
    let mut visited = 0u64;
    let mut digest = 0u64;
    for i in 0..ppb {
        let child_base = base.saturating_add(i.saturating_mul(entry_span));
        if child_base.saturating_add(entry_span) <= cutoff {
            continue;
        }
        let pointer = pointers[i as usize];
        if pointer == 0 {
            continue;
        }
        visited += 1;
        digest = digest
            .wrapping_mul(0x9e37_79b1_85eb_ca87)
            .wrapping_add(i.rotate_left(17) ^ u64::from(pointer));
    }
    (visited, digest)
}

#[inline(never)]
fn bounded_cutoff_scan(pointers: &[u32], base: u64, cutoff: u64, entry_span: u64) -> (u64, u64) {
    let ppb = pointers.len() as u64;
    let first_entry = if entry_span == 0 {
        if base <= cutoff { ppb } else { 0 }
    } else if cutoff == u64::MAX {
        ppb
    } else {
        (cutoff.saturating_sub(base) / entry_span).min(ppb)
    };
    let mut visited = 0u64;
    let mut digest = 0u64;
    for i in first_entry..ppb {
        let child_base = base.saturating_add(i.saturating_mul(entry_span));
        if child_base.saturating_add(entry_span) <= cutoff {
            continue;
        }
        let pointer = pointers[i as usize];
        if pointer == 0 {
            continue;
        }
        visited += 1;
        digest = digest
            .wrapping_mul(0x9e37_79b1_85eb_ca87)
            .wrapping_add(i.rotate_left(17) ^ u64::from(pointer));
    }
    (visited, digest)
}

fn bench(c: &mut Criterion) {
    let zero = vec![0u8; 4096];
    let mut early = vec![0u8; 4096];
    early[0] = 1;
    for (name, block) in [("empty", &zero), ("nonempty_early", &early)] {
        assert_eq!(byte_all_zero(block), unrolled4_all_zero(block));
        let mut g = c.benchmark_group(format!("indirect_all_zero_{name}"));
        g.bench_function("byte", |b| {
            b.iter(|| black_box(byte_all_zero(black_box(block))))
        });
        g.bench_function("unrolled4", |b| {
            b.iter(|| black_box(unrolled4_all_zero(black_box(block))))
        });
        g.finish();
    }

    let pointers: Vec<u32> = (0..1024)
        .map(|i| if i % 11 == 0 { 0 } else { i + 1 })
        .collect();
    let base = 12u64;
    let cutoff = base + 900;
    let entry_span = 1u64;
    for &(case_base, case_cutoff, case_span) in &[
        (base, base - 1, 1),
        (base, base, 1),
        (base, base + 1, 1),
        (base, cutoff, 1),
        (base, base + pointers.len() as u64, 1),
        (base, u64::MAX, 1),
        (u64::MAX - 3, u64::MAX - 2, 2),
        (base, base - 1, 0),
        (base, base, 0),
    ] {
        assert_eq!(
            linear_cutoff_scan(&pointers, case_base, case_cutoff, case_span),
            bounded_cutoff_scan(&pointers, case_base, case_cutoff, case_span)
        );
    }

    let mut g = c.benchmark_group("indirect_truncate_prefix_ab");
    g.bench_function("linear_a", |b| {
        b.iter(|| {
            black_box(linear_cutoff_scan(
                black_box(&pointers),
                black_box(base),
                black_box(cutoff),
                black_box(entry_span),
            ))
        })
    });
    g.bench_function("linear_b", |b| {
        b.iter(|| {
            black_box(linear_cutoff_scan(
                black_box(&pointers),
                black_box(base),
                black_box(cutoff),
                black_box(entry_span),
            ))
        })
    });
    g.bench_function("bounded", |b| {
        b.iter(|| {
            black_box(bounded_cutoff_scan(
                black_box(&pointers),
                black_box(base),
                black_box(cutoff),
                black_box(entry_span),
            ))
        })
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
