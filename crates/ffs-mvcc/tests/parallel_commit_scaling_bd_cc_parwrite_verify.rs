//! Parallel commit scaling: does the (built-but-unwired) `ShardedMvccStore`
//! actually let concurrent writers to DISJOINT blocks commit in parallel, vs the
//! single `MvccStore` behind a `Mutex` (the current production FS shape, which
//! serializes every commit on one exclusive lock)?
//!
//! This is the independent proof for the parallel-write lever the parwrite WIP is
//! wiring: the campaign measured FS-level parallel create/metadata NEGATIVE-scaling
//! (3.5-5.9x slower than kernel at 8t) and root-caused it to the single MVCC commit
//! lock. If `ShardedMvccStore` here scales positively while the Mutex-wrapped single
//! store stays flat/negative, the wiring is worth it (and quantifies the gain).
//!
//! `#[ignore]` (timing measurement, not a correctness gate). Run with:
//!   cargo test -p ffs-mvcc --test parallel_commit_scaling_bd_cc_parwrite_verify \
//!     -- --ignored --nocapture

use ffs_mvcc::MvccStore;
use ffs_mvcc::sharded::ShardedMvccStore;
use ffs_types::BlockNumber;
use parking_lot::Mutex;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

const PER_THREAD: u64 = 4000;
const BS: usize = 4096;

fn data() -> Vec<u8> {
    vec![0xAB_u8; BS]
}

// Disjoint, widely-spaced block range per thread => no FCW conflicts, and (for
// the sharded store) different shards => genuinely concurrent installs.
fn base_for(thread: usize) -> u64 {
    (thread as u64) * PER_THREAD * 16
}

fn run_sharded(threads: usize, d: &[u8]) {
    let store = Arc::new(ShardedMvccStore::for_host_parallelism());
    let mut handles = Vec::with_capacity(threads);
    for t in 0..threads {
        let store = Arc::clone(&store);
        let d = d.to_vec();
        handles.push(thread::spawn(move || {
            let base = base_for(t);
            for i in 0..PER_THREAD {
                let mut txn = store.begin();
                txn.stage_write(BlockNumber(base + i), d.clone());
                let _ = store.commit(txn);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

fn run_single_locked(threads: usize, d: &[u8]) {
    let store = Arc::new(Mutex::new(MvccStore::new()));
    let mut handles = Vec::with_capacity(threads);
    for t in 0..threads {
        let store = Arc::clone(&store);
        let d = d.to_vec();
        handles.push(thread::spawn(move || {
            let base = base_for(t);
            for i in 0..PER_THREAD {
                let mut guard = store.lock();
                let mut txn = guard.begin();
                txn.stage_write(BlockNumber(base + i), d.clone());
                let _ = guard.commit(txn);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

fn throughput(threads: usize, d: &[u8], f: impl Fn(usize, &[u8])) -> f64 {
    // one warm pass, then timed
    f(threads, d);
    let total = (threads as u64) * PER_THREAD;
    let start = Instant::now();
    f(threads, d);
    let secs = start.elapsed().as_secs_f64();
    (total as f64) / secs
}

#[test]
#[ignore = "timing measurement; run with --ignored --nocapture"]
fn parallel_commit_scaling_sharded_vs_single_locked() {
    let d = data();
    eprintln!(
        "\n=== MVCC parallel commit scaling: ShardedMvccStore vs Mutex<MvccStore> ({} commits/thread) ===",
        PER_THREAD
    );
    eprintln!("threads |   sharded c/s |    single c/s | sharded/single");
    let mut sharded_1t = 0.0_f64;
    let mut sharded_nt = 0.0_f64;
    for &t in &[1_usize, 4, 8] {
        let sharded = throughput(t, &d, run_sharded);
        let single = throughput(t, &d, run_single_locked);
        if t == 1 {
            sharded_1t = sharded;
        }
        sharded_nt = sharded;
        eprintln!(
            "{t:7} | {sharded:13.0} | {single:13.0} | {:.2}x",
            sharded / single
        );
    }
    eprintln!(
        "sharded self-scaling 8t/1t = {:.2}x (single store cannot scale: one exclusive commit lock)\n",
        sharded_nt / sharded_1t
    );
}
