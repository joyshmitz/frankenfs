#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-machine A/B for the zero-copy ranged-read lever (bd-dy41g).
//!
//! The file-data read path coalesces a contiguous physical block run into one
//! device read. Two ways to land that run in the caller's contiguous output
//! buffer:
//!
//! * `read_contiguous_blocks_then_copy` — the pre-bd-dy41g shape: allocate one
//!   `BlockBuf::zeroed` per block into a `Vec<BlockBuf>`, do the ranged read
//!   into those scattered buffers, then memcpy each buffer into `out`. For an
//!   N-block run that is N allocations + N zero-fills + a `Vec` + N copies on
//!   top of the single read.
//! * `read_contiguous_into` — the post-bd-dy41g shape: one ranged read straight
//!   into `out`. No per-block allocation and no post-read copy.
//!
//! Both deposit byte-identical data into `out`; the delta isolates exactly the
//! eliminated allocation + copy traffic. Running both in one binary keeps the
//! comparison on a single CPU.

use asupersync::Cx;
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_block::{BlockBuf, BlockDevice, ByteBlockDevice, ByteDevice};
use ffs_error::Result;
use ffs_types::{BlockNumber, ByteOffset};
use std::hint::black_box;
use std::io::IoSliceMut;
use std::sync::Mutex;

const BLOCK_SIZE: u32 = 4096;
const BLOCKS: usize = 256; // a 1 MiB contiguous run
const SPAN: usize = BLOCK_SIZE as usize * BLOCKS;

/// Minimal in-memory `ByteDevice` for the bench (mirrors the arc_cache helper).
struct MemByteDevice {
    bytes: Mutex<Vec<u8>>,
}

impl MemByteDevice {
    fn new(size: usize) -> Self {
        Self {
            bytes: Mutex::new(vec![0u8; size]),
        }
    }
}

#[allow(clippy::cast_possible_truncation)]
impl ByteDevice for MemByteDevice {
    fn len_bytes(&self) -> u64 {
        self.bytes.lock().unwrap().len() as u64
    }

    fn supports_vectored_reads(&self) -> bool {
        // Match a real file device: the old path issues ONE vectored read into
        // the per-block buffers, so the A/B isolates the alloc + copy traffic
        // (not a scalar-vs-vectored syscall-count difference).
        true
    }

    fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        let off = offset.0 as usize;
        let guard = self.bytes.lock().unwrap();
        buf.copy_from_slice(&guard[off..off + buf.len()]);
        Ok(())
    }

    fn read_vectored_exact_at(
        &self,
        _cx: &Cx,
        offset: ByteOffset,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Result<()> {
        let mut off = offset.0 as usize;
        let guard = self.bytes.lock().unwrap();
        for buf in bufs {
            let len = buf.len();
            buf.copy_from_slice(&guard[off..off + len]);
            off += len;
        }
        Ok(())
    }

    fn write_all_at(&self, _cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        let off = offset.0 as usize;
        let mut guard = self.bytes.lock().unwrap();
        guard[off..off + buf.len()].copy_from_slice(buf);
        Ok(())
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Ok(())
    }
}

fn make_device() -> ByteBlockDevice<MemByteDevice> {
    let byte_len = BLOCK_SIZE as usize * (BLOCKS + 1);
    let mem = MemByteDevice::new(byte_len);
    ByteBlockDevice::new(mem, BLOCK_SIZE).expect("device")
}

fn bench_read_contiguous(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let dev = make_device();
    let bs = BLOCK_SIZE as usize;

    // Isomorphism: both paths fill `out` with identical bytes.
    let mut out_old = vec![0_u8; SPAN];
    let mut bufs: Vec<BlockBuf> = (0..BLOCKS).map(|_| BlockBuf::zeroed(bs)).collect();
    dev.read_contiguous_blocks(&cx, BlockNumber(0), &mut bufs)
        .expect("contiguous blocks");
    for (idx, buf) in bufs.iter().enumerate() {
        out_old[idx * bs..(idx + 1) * bs].copy_from_slice(buf.as_slice());
    }
    let mut out_new = vec![0_u8; SPAN];
    dev.read_contiguous_into(&cx, BlockNumber(0), &mut out_new)
        .expect("contiguous into");
    assert_eq!(
        out_old, out_new,
        "read_contiguous_into must match blocks+copy"
    );

    let mut group = c.benchmark_group("read_contiguous_1mib");
    // Old: Vec<BlockBuf> (alloc + zero per block) + ranged read + per-block copy.
    group.bench_function("read_contiguous_blocks_then_copy", |b| {
        b.iter(|| {
            let mut out = vec![0_u8; SPAN];
            let mut bufs: Vec<BlockBuf> = (0..BLOCKS).map(|_| BlockBuf::zeroed(bs)).collect();
            dev.read_contiguous_blocks(black_box(&cx), BlockNumber(0), &mut bufs)
                .unwrap();
            for (idx, buf) in bufs.iter().enumerate() {
                out[idx * bs..(idx + 1) * bs].copy_from_slice(buf.as_slice());
            }
            black_box(out)
        });
    });
    // Old ext4 shape (bd-xfdjk): read_contiguous_blocks_with_scope returned a
    // Vec<Vec<u8>> — one BlockBuf per block, then a `to_vec` into a SECOND
    // per-block allocation, then the caller copies each Vec into `out`. Two
    // allocations + two copies per block on top of the ranged read.
    group.bench_function("ext4_blocks_then_vec_then_copy", |b| {
        b.iter(|| {
            let mut out = vec![0_u8; SPAN];
            let mut bufs: Vec<BlockBuf> = (0..BLOCKS).map(|_| BlockBuf::zeroed(bs)).collect();
            dev.read_contiguous_blocks(black_box(&cx), BlockNumber(0), &mut bufs)
                .unwrap();
            let datas: Vec<Vec<u8>> = bufs.iter().map(|b| b.as_slice().to_vec()).collect();
            for (idx, data) in datas.iter().enumerate() {
                out[idx * bs..(idx + 1) * bs].copy_from_slice(&data[..bs]);
            }
            black_box(out)
        });
    });
    // New: one ranged read straight into out — no per-block alloc/copy.
    group.bench_function("read_contiguous_into", |b| {
        b.iter(|| {
            let mut out = vec![0_u8; SPAN];
            dev.read_contiguous_into(black_box(&cx), BlockNumber(0), &mut out)
                .unwrap();
            black_box(out)
        });
    });
    group.finish();
}

criterion_group!(read_contiguous, bench_read_contiguous);
criterion_main!(read_contiguous);
