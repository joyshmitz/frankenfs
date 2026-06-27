#![forbid(unsafe_code)]
//! Parallel `BlockBuf` allocation convoy probe (bd-bhh0i follow-up).
//!
//! IvoryBirch's bd-bhh0i profile flags a "malloc-arena convoy" on parallel
//! metadata writes and proposes thread-local block-buffer pooling. `BlockBuf`
//! (the buffer that path allocates) lives in ffs-block, so this probes the
//! hypothesis directly and in isolation: each thread allocates+zeros+touches+
//! drops `BlockBuf::zeroed(4096)` in a tight loop. If glibc's per-thread arenas
//! absorb these sub-mmap-threshold allocations, the per-thread alloc rate holds
//! flat from 1 to N threads (NO convoy → pooling lever is inert). If a shared
//! arena lock serializes them, the per-thread rate collapses with N (convoy →
//! pooling would help). Reports per-thread ns/alloc so the scaling is read
//! directly, robust to absolute-time jitter under box load (relative across N).
//!
//! Usage: cargo run --release --example alloc_convoy -- [allocs_per_thread] [threads...]

use ffs_block::BlockBuf;
use std::time::Instant;

fn run(threads: usize, per: usize) -> f64 {
    let start = Instant::now();
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            std::thread::spawn(move || {
                let mut acc: u64 = 0;
                for i in 0..per {
                    let mut b = BlockBuf::zeroed(4096);
                    // Touch a byte so the alloc+zero can't be optimized away.
                    let s = b.make_mut();
                    s[i & 4095] = (i as u8).wrapping_add(1);
                    acc = acc.wrapping_add(u64::from(s[i & 4095]));
                    std::hint::black_box(&b);
                }
                acc
            })
        })
        .collect();
    let mut acc = 0u64;
    for h in handles {
        acc = acc.wrapping_add(h.join().expect("join"));
    }
    std::hint::black_box(acc);
    let elapsed = start.elapsed().as_secs_f64();
    let total = (threads * per) as f64;
    elapsed * 1e9 / total // ns per alloc (wall, aggregate)
}

fn main() {
    let mut args = std::env::args().skip(1);
    let per: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(2_000_000);
    let thread_set: Vec<usize> = {
        let rest: Vec<usize> = args.filter_map(|s| s.parse().ok()).collect();
        if rest.is_empty() { vec![1, 2, 4, 8, 16] } else { rest }
    };
    // Warm up allocator arenas.
    let _ = run(1, per / 20);
    let base = run(1, per);
    println!("threads=1  ns/alloc(per-thread)={base:.1}  (baseline)");
    for &t in thread_set.iter().filter(|&&t| t != 1) {
        let ns = run(t, per);
        // Aggregate ns/alloc already normalizes by total allocs; if there is NO
        // convoy it stays ~flat vs the 1-thread baseline (each thread on its own
        // core/arena). A convoy makes it climb toward t*baseline.
        println!(
            "threads={t:<2} ns/alloc(per-thread)={ns:.1}  scaling={:.2}x vs 1t (1.0=perfect, ->{t} = full convoy)",
            ns / base
        );
    }
}
