#![forbid(unsafe_code)]
//! Cold-read A/B harness for the `posix_fadvise` read-ahead lever (bd-5v3mh).
//!
//! Warm tmpfs benches cannot see read-ahead — the data is already page-cache
//! resident, so the kernel's prefetch window is irrelevant. This harness reads a
//! file on a REAL disk (e.g. /data ext4) through `FileByteDevice`, the exact
//! device the FS read path uses, so a `drop_caches` between runs exposes the
//! cold gap the warm path hides. The `FFS_READ_FADVISE` env var (read by
//! `FileByteDevice::open`) selects the advice; run the same binary twice with
//! different values, dropping caches before each, to A/B the lever.
//!
//! Usage:
//!   FFS_READ_FADVISE=sequential cargo run --release --example cold_read -- <path> [chunk_kib] [threads]
//!
//! Reads the whole file in `chunk_kib`-sized `read_exact_at` calls (default
//! 1024), optionally split across `threads` contiguous ranges (default 1, to
//! mirror the parallel chunk read of the real path). Prints elapsed + MiB/s and
//! a checksum byte so the read cannot be optimized away.
//!
//! ## Do NOT use `cat` as the kernel baseline (2026-07-09)
//!
//! On this box `cat` is an alias for `bat`, and `/usr/bin/cat` is uutils
//! coreutils — **both issue 832-byte `read()` calls**, so they measure syscall
//! overhead, not the kernel's cold read path. Measured on an 800 MiB dense
//! fixture on /data ext4 with `drop_caches=3` before every run: `cat` 2932 ms
//! (273 MiB/s) versus 513 ms (1558 MiB/s) for a plain 1 MiB-read loop over the
//! same file. Any "vs kernel `cat`" cold ratio taken here is off by ~6x.
//!
//! Use a pure read loop at the SAME chunk size instead — no output write, so it
//! is apples-to-apples with this harness (`dd ... of=/dev/null` also pays a
//! `write()` per block and reads ~20% slow):
//!
//! ```text
//! python3 -c 'import os,sys,time
//! fd=os.open(sys.argv[1],os.O_RDONLY); s=time.perf_counter()
//! while os.read(fd,1<<20): pass
//! print(f"{(time.perf_counter()-s)*1000:.1f} ms")' <path>
//! ```
//!
//! Box load dominates single reps (kernel arm cv≈19% at load 30); take min-of-N.

use asupersync::Cx;
use ffs_block::{ByteDevice, FileByteDevice};
use ffs_types::ByteOffset;
use std::sync::Arc;
use std::time::Instant;

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: cold_read <path> [chunk_kib] [threads]");
    let chunk: usize = args
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1024)
        * 1024;
    let threads: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(1);
    // 4th arg: access pattern — "seq" (default) sweeps each thread's contiguous
    // range; "rand" does `len/chunk` reads at random chunk-aligned offsets across
    // the whole file (the random-read workload). The random arm answers whether
    // the default `POSIX_FADV_SEQUENTIAL` hint regresses random access (read
    // amplification) vs `none`/`random`.
    let pattern = args.next().unwrap_or_else(|| "seq".into());

    let dev = Arc::new(FileByteDevice::open(&path).expect("open device"));
    let len = dev.len_bytes();
    let mode = std::env::var("FFS_READ_FADVISE").unwrap_or_else(|_| "sequential(default)".into());

    let start = Instant::now();
    let per = len / threads as u64;
    let nchunks = len / chunk as u64; // chunk-aligned slots in the file
    let rand = pattern == "rand";
    let mut handles = Vec::new();
    for t in 0..threads {
        let dev = Arc::clone(&dev);
        let begin = per * t as u64;
        let end = if t + 1 == threads { len } else { per * (t as u64 + 1) };
        let pat_rand = rand;
        handles.push(std::thread::spawn(move || {
            let cx = Cx::for_testing();
            let mut buf = vec![0_u8; chunk];
            let mut sum: u64 = 0;
            if pat_rand {
                // Per-thread LCG (deterministic, no rand dep); each thread issues
                // `nchunks/threads` reads at random chunk-aligned offsets.
                let mut state: u64 = 0x9E37_79B9_7F4A_7C15 ^ (t as u64).wrapping_mul(0x1234_5);
                let reads = (nchunks / threads as u64).max(1);
                for _ in 0..reads {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    let slot = if nchunks == 0 { 0 } else { (state >> 33) % nchunks };
                    let off = slot * chunk as u64;
                    let n = std::cmp::min(chunk as u64, len - off) as usize;
                    dev.read_exact_at(&cx, ByteOffset(off), &mut buf[..n])
                        .expect("read");
                    let mut i = 0;
                    while i < n {
                        sum = sum.wrapping_add(u64::from(buf[i]));
                        i += 4096;
                    }
                }
                return sum;
            }
            let mut off = begin;
            while off < end {
                let n = std::cmp::min(chunk as u64, end - off) as usize;
                dev.read_exact_at(&cx, ByteOffset(off), &mut buf[..n])
                    .expect("read");
                // Touch one byte per page so the read is not elided and pages fault.
                let mut i = 0;
                while i < n {
                    sum = sum.wrapping_add(u64::from(buf[i]));
                    i += 4096;
                }
                off += n as u64;
            }
            sum
        }));
    }
    let mut sum: u64 = 0;
    for h in handles {
        sum = sum.wrapping_add(h.join().expect("join"));
    }
    let elapsed = start.elapsed();
    let mib = len as f64 / (1024.0 * 1024.0);
    let secs = elapsed.as_secs_f64();
    println!(
        "fadvise={mode} pattern={pattern} threads={threads} chunk_kib={} bytes={len} elapsed_ms={:.2} MiB_s={:.1} cksum={sum}",
        chunk / 1024,
        secs * 1000.0,
        mib / secs,
    );
}
