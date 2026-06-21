#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for overlapping the per-cluster block reads in
//! `decompress_e2compr_cluster` (bd-giyxr), completing the ext4 read-family
//! I/O-overlap set (extent bd-yg6tk, indirect bd-r9c10, extent-tree bd-8nrzh).
//!
//! Decompressing an e2compr cluster reads each present cluster block and appends
//! it to the raw buffer before decompression. The reads serialized one device
//! access latency per block. The lever resolves the present block pointers
//! serially, reads them in a rayon `par_iter` (latencies overlap), then appends
//! in block order. This bench isolates that read fan-out on a `LatencyBlockDevice`
//! at realistic small cluster sizes; both arms assemble identical bytes.
//!
//! The second group isolates bd-xmh5g.415: the e2compr read loop resolves the
//! same indirect pointer block for the cluster-end sentinel probe and then again
//! for each present cluster block. A one-slot-per-depth memo is byte-identical
//! but collapses repeated pointer-block reads during the serial PLAN pass.

use asupersync::Cx;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result};
use ffs_types::BlockNumber;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use std::hint::black_box;
use std::time::Duration;

const BS: usize = 4096;
const READ_LATENCY: Duration = Duration::from_micros(250);

fn prng(seed: u64) -> u8 {
    let x = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (x >> 33) as u8
}

struct LatencyBlockDevice {
    blocks: Vec<BlockBuf>,
    read_latency: Duration,
}

impl LatencyBlockDevice {
    fn new(block_count: u64, read_latency: Duration) -> Self {
        let blocks = (0..block_count)
            .map(|blk| BlockBuf::new((0..BS).map(|i| prng(blk << 20 ^ i as u64)).collect()))
            .collect();
        Self {
            blocks,
            read_latency,
        }
    }

    fn from_blocks(blocks: Vec<BlockBuf>, read_latency: Duration) -> Self {
        Self {
            blocks,
            read_latency,
        }
    }
}

impl BlockDevice for LatencyBlockDevice {
    fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        std::thread::sleep(self.read_latency);
        let idx = usize::try_from(block.0)
            .map_err(|_| FfsError::Format("bench block index overflow".into()))?;
        self.blocks
            .get(idx)
            .map(BlockBuf::clone_ref)
            .ok_or_else(|| FfsError::Format(format!("bench block out of range: {}", block.0)))
    }

    fn supports_contiguous_reads(&self) -> bool {
        false
    }

    fn read_contiguous_blocks(
        &self,
        cx: &Cx,
        start: BlockNumber,
        bufs: &mut [BlockBuf],
    ) -> Result<()> {
        for (i, buf) in bufs.iter_mut().enumerate() {
            *buf = self.read_block(cx, BlockNumber(start.0 + i as u64))?;
        }
        Ok(())
    }

    fn write_block(&self, _cx: &Cx, _block: BlockNumber, _data: &[u8]) -> Result<()> {
        Err(FfsError::ReadOnly)
    }

    fn block_size(&self) -> u32 {
        BS as u32
    }

    fn block_count(&self) -> u64 {
        self.blocks.len() as u64
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Ok(())
    }
}

/// OLD: read each cluster block serially, append in order.
fn cluster_serial(cx: &Cx, dev: &LatencyBlockDevice, ptrs: &[u64]) -> Result<Vec<u8>> {
    let mut raw = Vec::with_capacity(ptrs.len() * BS);
    for &ptr in ptrs {
        let data = dev.read_block(cx, BlockNumber(ptr))?;
        raw.extend_from_slice(data.as_slice());
    }
    Ok(raw)
}

/// NEW: read cluster blocks in parallel, append in order.
fn cluster_parallel(cx: &Cx, dev: &LatencyBlockDevice, ptrs: &[u64]) -> Result<Vec<u8>> {
    let reads: Vec<Result<BlockBuf>> = ptrs
        .par_iter()
        .map(|&ptr| dev.read_block(cx, BlockNumber(ptr)))
        .collect();
    let mut raw = Vec::with_capacity(ptrs.len() * BS);
    for read in reads {
        raw.extend_from_slice(read?.as_slice());
    }
    Ok(raw)
}

fn set_u32_ptr(block: &mut [u8], idx: usize, value: u32) {
    let off = idx * 4;
    block[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

fn get_u32_ptr(block: &[u8], idx: usize) -> u64 {
    let off = idx * 4;
    if off + 4 <= block.len() {
        u64::from(u32::from_le_bytes([
            block[off],
            block[off + 1],
            block[off + 2],
            block[off + 3],
        ]))
    } else {
        0
    }
}

fn build_double_indirect_device(nblocks: usize) -> (LatencyBlockDevice, Vec<u32>) {
    const DIND_BLOCK: u32 = 1;
    const IND_BLOCK: u32 = 2;
    const DATA_BASE: u32 = 64;
    const PTRS_PER_BLOCK: u32 = (BS / 4) as u32;

    let mut blocks = vec![BlockBuf::new(vec![0_u8; BS]); 3];
    let mut dind = vec![0_u8; BS];
    let mut ind = vec![0_u8; BS];
    set_u32_ptr(&mut dind, 0, IND_BLOCK);
    for idx in 0..nblocks {
        set_u32_ptr(&mut ind, idx, DATA_BASE + idx as u32);
    }
    blocks[DIND_BLOCK as usize] = BlockBuf::new(dind);
    blocks[IND_BLOCK as usize] = BlockBuf::new(ind);

    let logical_start = 12 + PTRS_PER_BLOCK;
    let logicals = (0..nblocks).map(|idx| logical_start + idx as u32).collect();
    (
        LatencyBlockDevice::from_blocks(blocks, READ_LATENCY),
        logicals,
    )
}

fn read_indirect_ptr_raw(cx: &Cx, dev: &LatencyBlockDevice, phys: u64, idx: usize) -> Result<u64> {
    let block = dev.read_block(cx, BlockNumber(phys))?;
    Ok(get_u32_ptr(block.as_slice(), idx))
}

fn read_indirect_ptr_memo(
    cx: &Cx,
    dev: &LatencyBlockDevice,
    phys: u64,
    idx: usize,
    depth: usize,
    memo: &mut [Option<(u64, Vec<u8>)>; 3],
) -> Result<u64> {
    let slot = &mut memo[depth];
    if slot.as_ref().map(|(cached_phys, _)| *cached_phys) != Some(phys) {
        let block = dev.read_block(cx, BlockNumber(phys))?;
        *slot = Some((phys, block.as_slice().to_vec()));
    }
    Ok(get_u32_ptr(
        &slot.as_ref().expect("memo slot populated").1,
        idx,
    ))
}

fn resolve_double_indirect_old(
    cx: &Cx,
    dev: &LatencyBlockDevice,
    logical_block: u32,
) -> Result<Option<u64>> {
    const DIND_BLOCK: u64 = 1;
    const PTRS_PER_BLOCK: u32 = (BS / 4) as u32;

    let lb_dind = logical_block - 12 - PTRS_PER_BLOCK;
    let idx1 = (lb_dind / PTRS_PER_BLOCK) as usize;
    let ind_block = read_indirect_ptr_raw(cx, dev, DIND_BLOCK, idx1)?;
    if ind_block == 0 {
        return Ok(None);
    }
    let idx2 = (lb_dind % PTRS_PER_BLOCK) as usize;
    let phys = read_indirect_ptr_raw(cx, dev, ind_block, idx2)?;
    Ok(if phys == 0 { None } else { Some(phys) })
}

fn resolve_double_indirect_memo(
    cx: &Cx,
    dev: &LatencyBlockDevice,
    logical_block: u32,
    memo: &mut [Option<(u64, Vec<u8>)>; 3],
) -> Result<Option<u64>> {
    const DIND_BLOCK: u64 = 1;
    const PTRS_PER_BLOCK: u32 = (BS / 4) as u32;

    let lb_dind = logical_block - 12 - PTRS_PER_BLOCK;
    let idx1 = (lb_dind / PTRS_PER_BLOCK) as usize;
    let ind_block = read_indirect_ptr_memo(cx, dev, DIND_BLOCK, idx1, 1, memo)?;
    if ind_block == 0 {
        return Ok(None);
    }
    let idx2 = (lb_dind % PTRS_PER_BLOCK) as usize;
    let phys = read_indirect_ptr_memo(cx, dev, ind_block, idx2, 0, memo)?;
    Ok(if phys == 0 { None } else { Some(phys) })
}

fn resolve_cluster_old(
    cx: &Cx,
    dev: &LatencyBlockDevice,
    logicals: &[u32],
) -> Result<Vec<Option<u64>>> {
    logicals
        .iter()
        .map(|&logical| resolve_double_indirect_old(cx, dev, logical))
        .collect()
}

fn resolve_cluster_memo(
    cx: &Cx,
    dev: &LatencyBlockDevice,
    logicals: &[u32],
) -> Result<Vec<Option<u64>>> {
    let mut memo: [Option<(u64, Vec<u8>)>; 3] = [None, None, None];
    logicals
        .iter()
        .map(|&logical| resolve_double_indirect_memo(cx, dev, logical, &mut memo))
        .collect()
}

fn bench_cluster(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let mut group = c.benchmark_group("e2compr_cluster_read_overlap");
    for &nblocks in &[4_usize, 16, 32] {
        let dev = LatencyBlockDevice::new(nblocks as u64, READ_LATENCY);
        let ptrs: Vec<u64> = (0..nblocks as u64).collect();

        assert_eq!(
            cluster_serial(&cx, &dev, &ptrs).expect("serial"),
            cluster_parallel(&cx, &dev, &ptrs).expect("parallel"),
            "parallel cluster read diverged from serial (nblocks={nblocks})"
        );

        group.bench_with_input(BenchmarkId::new("serial", nblocks), &nblocks, |b, _| {
            b.iter(|| black_box(cluster_serial(&cx, &dev, black_box(&ptrs))));
        });
        group.bench_with_input(
            BenchmarkId::new("parallel_rayon", nblocks),
            &nblocks,
            |b, _| {
                b.iter(|| black_box(cluster_parallel(&cx, &dev, black_box(&ptrs))));
            },
        );
    }
    group.finish();
}

fn bench_indirect_pointer_memo(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let mut group = c.benchmark_group("e2compr_indirect_pointer_memo");
    group.sample_size(20);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(2));

    for &nblocks in &[4_usize, 16, 32] {
        let (dev, logicals) = build_double_indirect_device(nblocks);

        assert_eq!(
            resolve_cluster_old(&cx, &dev, &logicals).expect("old pointer resolution"),
            resolve_cluster_memo(&cx, &dev, &logicals).expect("memo pointer resolution"),
            "memoized e2compr pointer resolution diverged from old path (nblocks={nblocks})"
        );

        group.bench_with_input(BenchmarkId::new("old_reread", nblocks), &nblocks, |b, _| {
            b.iter(|| black_box(resolve_cluster_old(&cx, &dev, black_box(&logicals))));
        });
        group.bench_with_input(BenchmarkId::new("memo", nblocks), &nblocks, |b, _| {
            b.iter(|| black_box(resolve_cluster_memo(&cx, &dev, black_box(&logicals))));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_cluster, bench_indirect_pointer_memo);
criterion_main!(benches);
