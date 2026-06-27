#![forbid(unsafe_code)]
//! crc32c throughput probe — is the checksum path (btrfs verifies crc32c on every
//! tree/data block read; ext4 metadata too) hardware-accelerated or a software
//! bottleneck worth a lever? The `crc32c` crate auto-detects SSE4.2 at runtime;
//! this confirms empirically. Hardware (SSE4.2 `crc32` instruction) sustains
//! ~10-25 GB/s; a software table fallback is ~0.3-1 GB/s. At a ~2 GB/s btrfs read,
//! a software crc would dominate (verify slower than the read); hardware makes it
//! a few percent. Run: `cargo run --release --example crc_throughput`.

use ffs_types::crc32c;
use std::time::Instant;

fn main() {
    // 64 MiB buffer, non-trivial content so the crc actually churns.
    let n = 64 * 1024 * 1024;
    let buf: Vec<u8> = (0..n).map(|i| (i * 1103515245 + 12345) as u8).collect();
    // Warm.
    let _ = std::hint::black_box(crc32c(&buf[..1024]));

    let iters = 20;
    let start = Instant::now();
    let mut acc = 0u32;
    for _ in 0..iters {
        acc = acc.wrapping_add(crc32c(std::hint::black_box(&buf)));
    }
    std::hint::black_box(acc);
    let secs = start.elapsed().as_secs_f64();
    let gib = (n as f64 * iters as f64) / (1024.0 * 1024.0 * 1024.0);
    let gbps = gib / secs;
    println!(
        "crc32c: {gib:.2} GiB in {:.3}s = {gbps:.2} GiB/s  ({})",
        secs,
        if gbps > 4.0 { "HARDWARE (SSE4.2) — no lever" } else { "SOFTWARE fallback — possible lever" }
    );
}
