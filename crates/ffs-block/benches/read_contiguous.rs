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
//! * `read_contiguous_into_trusted_direct` — the post-bd-xmh5g.351 shape for
//!   byte devices that already preserve read destinations on error: skip the
//!   outer safety staging buffer and let the device fill `out` directly.
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
    preserves_read_destination_on_error: bool,
}

impl MemByteDevice {
    fn new(size: usize, preserves_read_destination_on_error: bool) -> Self {
        Self {
            bytes: Mutex::new(vec![0u8; size]),
            preserves_read_destination_on_error,
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

    fn preserves_read_exact_at_destination_on_error(&self) -> bool {
        self.preserves_read_destination_on_error
    }

    fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        let off = offset.0 as usize;
        {
            let guard = self.bytes.lock().unwrap();
            buf.copy_from_slice(&guard[off..off + buf.len()]);
        }
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
        drop(guard);
        Ok(())
    }

    fn write_all_at(&self, _cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        let off = offset.0 as usize;
        {
            let mut guard = self.bytes.lock().unwrap();
            guard[off..off + buf.len()].copy_from_slice(buf);
        }
        Ok(())
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Ok(())
    }
}

fn make_device(preserves_read_destination_on_error: bool) -> ByteBlockDevice<MemByteDevice> {
    let byte_len = BLOCK_SIZE as usize * (BLOCKS + 1);
    let mem = MemByteDevice::new(byte_len, preserves_read_destination_on_error);
    ByteBlockDevice::new(mem, BLOCK_SIZE).expect("device")
}

fn bench_read_contiguous(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let staged_dev = make_device(false);
    let trusted_dev = make_device(true);
    let bs = BLOCK_SIZE as usize;

    // Isomorphism: both paths fill `out` with identical bytes.
    let mut out_old = vec![0_u8; SPAN];
    let mut bufs: Vec<BlockBuf> = (0..BLOCKS).map(|_| BlockBuf::zeroed(bs)).collect();
    staged_dev
        .read_contiguous_blocks(&cx, BlockNumber(0), &mut bufs)
        .expect("contiguous blocks");
    for (idx, buf) in bufs.iter().enumerate() {
        out_old[idx * bs..(idx + 1) * bs].copy_from_slice(buf.as_slice());
    }
    let mut out_staged = vec![0_u8; SPAN];
    staged_dev
        .read_contiguous_into(&cx, BlockNumber(0), &mut out_staged)
        .expect("staged contiguous into");
    let mut out_direct = vec![0_u8; SPAN];
    trusted_dev
        .read_contiguous_into(&cx, BlockNumber(0), &mut out_direct)
        .expect("trusted contiguous into");
    assert_eq!(
        out_old, out_staged,
        "staged read_contiguous_into must match blocks+copy"
    );
    assert_eq!(
        out_old, out_direct,
        "trusted direct read_contiguous_into must match blocks+copy"
    );

    let mut group = c.benchmark_group("read_contiguous_1mib");
    // Old: Vec<BlockBuf> (alloc + zero per block) + ranged read + per-block copy.
    group.bench_function("read_contiguous_blocks_then_copy", |b| {
        b.iter(|| {
            let mut out = vec![0_u8; SPAN];
            let mut bufs: Vec<BlockBuf> = (0..BLOCKS).map(|_| BlockBuf::zeroed(bs)).collect();
            staged_dev
                .read_contiguous_blocks(black_box(&cx), BlockNumber(0), &mut bufs)
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
            staged_dev
                .read_contiguous_blocks(black_box(&cx), BlockNumber(0), &mut bufs)
                .unwrap();
            let datas: Vec<Vec<u8>> = bufs.iter().map(|b| b.as_slice().to_vec()).collect();
            for (idx, data) in datas.iter().enumerate() {
                out[idx * bs..(idx + 1) * bs].copy_from_slice(&data[..bs]);
            }
            black_box(out)
        });
    });
    // Conservative all-device path: one ranged read into an outer staging buffer,
    // then one final copy into out, preserving out on devices that may dirty
    // their destination before returning Err.
    group.bench_function("read_contiguous_into_outer_staged", |b| {
        b.iter(|| {
            let mut out = vec![0_u8; SPAN];
            staged_dev
                .read_contiguous_into(black_box(&cx), BlockNumber(0), &mut out)
                .unwrap();
            black_box(out)
        });
    });
    // Trusted all-or-nothing path: the byte device itself preserves out on Err,
    // so ByteBlockDevice can skip the outer staging Vec and final memcpy.
    group.bench_function("read_contiguous_into_trusted_direct", |b| {
        b.iter(|| {
            let mut out = vec![0_u8; SPAN];
            trusted_dev
                .read_contiguous_into(black_box(&cx), BlockNumber(0), &mut out)
                .unwrap();
            black_box(out)
        });
    });
    group.finish();
}

criterion_group!(read_contiguous, bench_read_contiguous);
criterion_main!(read_contiguous);
