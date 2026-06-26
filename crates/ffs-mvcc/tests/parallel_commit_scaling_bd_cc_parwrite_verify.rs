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

/// Correctness gate (NOT ignored — runs in normal test): the `ShardedMvccStore`'s
/// `CommitPublicationGate` makes out-of-order concurrent commits become in-order
/// visible. Stress it: N threads each blind-commit DISTINCT data to DISJOINT blocks
/// concurrently, then verify EVERY committed block reads back its exact value at the
/// final snapshot. A lost/torn/mis-ordered commit (a gate or shard-install bug) fails
/// here — catching it BEFORE the parwrite wiring lands a broken transaction core.
#[test]
fn sharded_parallel_commit_is_correct_bd_cc_parwrite_verify() {
    use ffs_mvcc::sharded::ShardedMvccStore;

    const THREADS: usize = 8;
    const PER_THREAD: u64 = 1500;

    // block b's payload: first 8 bytes = b.to_le_bytes(), rest a b-derived fill.
    fn payload(block: u64) -> Vec<u8> {
        let mut v = vec![(block as u8) ^ 0x5A; BS];
        v[..8].copy_from_slice(&block.to_le_bytes());
        v
    }

    let store = Arc::new(ShardedMvccStore::for_host_parallelism());
    let mut handles = Vec::with_capacity(THREADS);
    for t in 0..THREADS {
        let store = Arc::clone(&store);
        handles.push(thread::spawn(move || {
            let base = base_for(t);
            for i in 0..PER_THREAD {
                let block = base + i;
                let mut txn = store.begin();
                txn.stage_write(BlockNumber(block), payload(block));
                // disjoint blocks => no FCW conflict => every commit must succeed
                store
                    .commit(txn)
                    .unwrap_or_else(|(e, _)| panic!("commit of block {block} failed: {e:?}"));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    // After all writers joined, every committed block must be visible with its exact
    // payload at the latest snapshot.
    let snapshot = store.current_snapshot();
    let mut verified = 0_u64;
    for t in 0..THREADS {
        let base = base_for(t);
        for i in 0..PER_THREAD {
            let block = base + i;
            let got = store
                .read_visible(BlockNumber(block), snapshot)
                .unwrap_or_else(|| panic!("block {block} not visible after parallel commit"));
            assert_eq!(
                got,
                payload(block),
                "block {block} read back wrong bytes (gate/install corruption)"
            );
            verified += 1;
        }
    }
    assert_eq!(verified, THREADS as u64 * PER_THREAD);
    eprintln!("sharded parallel-commit correctness: {verified} blocks verified byte-exact");
}

/// FCW-under-concurrency gate: the serializability guarantee. N threads all begin at
/// the SAME snapshot (synced by a barrier so no commit lands before any begin), then
/// all blind-commit the SAME block concurrently. First-committer-wins means EXACTLY
/// ONE must succeed and the other N-1 must be rejected as conflicts — never two
/// winners (that would be lost-update corruption of the transaction core the parwrite
/// effort is wiring). Repeated over several rounds to shake out races.
#[test]
fn sharded_concurrent_same_block_fcw_exactly_one_winner_bd_cc_parwrite_verify() {
    use ffs_mvcc::sharded::ShardedMvccStore;
    use std::sync::Barrier;

    const THREADS: usize = 8;
    const ROUNDS: u64 = 200;

    let store = Arc::new(ShardedMvccStore::for_host_parallelism());
    let contended = BlockNumber(777);

    for round in 0..ROUNDS {
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut handles = Vec::with_capacity(THREADS);
        for t in 0..THREADS {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                // All begin at the same snapshot (no commit has landed this round yet).
                let mut txn = store.begin();
                let mut payload = vec![0xC3_u8; BS];
                payload[..8].copy_from_slice(&((round << 8) | t as u64).to_le_bytes());
                txn.stage_write(contended, payload);
                barrier.wait(); // every thread has begun before any commits
                store.commit(txn).is_ok()
            }));
        }
        let winners: usize = handles.into_iter().map(|h| h.join().unwrap() as usize).sum();
        assert_eq!(
            winners, 1,
            "round {round}: FCW broke under concurrency — {winners} winners (expected exactly 1; >1 = lost-update corruption)"
        );
    }
    eprintln!(
        "sharded FCW-under-concurrency: {ROUNDS} rounds x {THREADS} threads on one block, exactly 1 winner each — serializability holds"
    );
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

/// bd-cc-shardread: verify the read-interface gap methods added to ShardedMvccStore
/// (read_visible_block_buf, read_visible_physical) — completing the store's read
/// interface toward the FS wiring. block_buf must equal read_visible's bytes;
/// physical is logical-identity for a committed block (the no-COW ext4 fallback)
/// and None for an uncommitted block.
#[test]
fn sharded_read_gap_methods_match_bd_cc_shardread() {
    use ffs_mvcc::sharded::ShardedMvccStore;
    use ffs_types::BlockNumber as BN;

    let store = ShardedMvccStore::for_host_parallelism();
    let block = BN(42);
    let snap0 = store.current_snapshot();
    assert!(store.read_visible_block_buf(block, snap0).is_none());
    assert!(store.read_visible_physical(block, snap0).is_none());

    let mut txn = store.begin();
    let data = vec![0x7E_u8; 4096];
    txn.stage_write(block, data.clone());
    store.commit(txn).map_err(|(e, _)| e).expect("commit");

    let snap = store.current_snapshot();
    let bytes = store.read_visible(block, snap).expect("visible bytes");
    let buf = store.read_visible_block_buf(block, snap).expect("visible buf");
    assert_eq!(buf.as_slice(), bytes.as_slice(), "block_buf must match read_visible bytes");
    assert_eq!(bytes, data);
    assert_eq!(store.read_visible_physical(block, snap), Some(block));
    assert!(store.read_visible_physical(BN(99), snap).is_none());
    eprintln!("sharded read-gap methods verified byte-exact + physical identity");
}
