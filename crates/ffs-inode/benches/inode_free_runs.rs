#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for batching contiguous data-block frees in the indirect
//! delete/truncate path (bd-wgv6x).
//!
//! `free_indirect_chain` / `free_indirect_blocks` freed each data block of a
//! legacy indirect-mapped inode with its own `free_blocks_persist(block, 1)`
//! call. `free_blocks_persist(start, count)` already does a single bitmap-block
//! read-modify-write per group for the whole range, so freeing a contiguous run
//! of L blocks individually costs L bitmap RMWs (L block reads + L writes) while
//! freeing the run as one ranged call costs ONE. The lever gathers each leaf's
//! data-block pointers and frees them in maximal contiguous runs — O(blocks) ->
//! O(runs) bitmap RMWs, a large win for sequentially-allocated files.
//!
//! This bench isolates the call-count reduction: a `free_op(start, len)` models
//! one bitmap-block read-modify-write by parking for a fixed latency once per
//! call (the real cost is the bitmap block read + write), then recording the
//! freed blocks. The serial arm calls it once per block; the batched arm once
//! per contiguous run. Both free the identical set of blocks (asserted), so this
//! measures only the eliminated bitmap RMWs.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;

/// Per-call bitmap-block read-modify-write latency (one block read + write).
const RMW_LATENCY: Duration = Duration::from_micros(120);

/// Model of `free_blocks_persist(start, len)`: one bitmap RMW (latency) plus
/// recording the freed range. Returns the freed blocks so both arms can be
/// compared.
fn free_op(start: u32, len: u32, sink: &mut Vec<u32>) {
    std::thread::sleep(RMW_LATENCY);
    for b in start..start + len {
        sink.push(b);
    }
}

/// OLD: one `free_op` per block.
fn free_per_block(blocks: &[u32]) -> Vec<u32> {
    let mut freed = Vec::with_capacity(blocks.len());
    for &b in blocks {
        free_op(b, 1, &mut freed);
    }
    freed
}

/// NEW: gather maximal contiguous runs, one `free_op` per run.
fn free_in_runs(blocks: &[u32]) -> Vec<u32> {
    let mut freed = Vec::with_capacity(blocks.len());
    let mut idx = 0;
    while idx < blocks.len() {
        let start = blocks[idx];
        let mut len = 1u32;
        while idx + (len as usize) < blocks.len()
            && start.checked_add(len) == Some(blocks[idx + len as usize])
        {
            len += 1;
        }
        free_op(start, len, &mut freed);
        idx += len as usize;
    }
    freed
}

fn bench_free(c: &mut Criterion) {
    let n = 1024_u32; // one full leaf indirect block (ppb = block_size/4)

    // Fully contiguous (sequentially allocated file): 1024 blocks -> 1 run.
    let contiguous: Vec<u32> = (1000..1000 + n).collect();
    // Fragmented (every other block present): 512 blocks -> 512 singleton runs.
    let fragmented: Vec<u32> = (0..n).filter(|i| i % 2 == 0).map(|i| 1000 + i * 2).collect();

    for (label, blocks) in [("contiguous_1024", &contiguous), ("fragmented_512", &fragmented)] {
        assert_eq!(
            free_per_block(blocks),
            free_in_runs(blocks),
            "run-batched free diverged from per-block ({label})"
        );

        let mut group = c.benchmark_group("inode_free_runs");
        group.bench_with_input(BenchmarkId::new("per_block", label), blocks, |b, blk| {
            b.iter(|| black_box(free_per_block(black_box(blk))));
        });
        group.bench_with_input(BenchmarkId::new("run_batched", label), blocks, |b, blk| {
            b.iter(|| black_box(free_in_runs(black_box(blk))));
        });
        group.finish();
    }
}

criterion_group!(benches, bench_free);
criterion_main!(benches);
