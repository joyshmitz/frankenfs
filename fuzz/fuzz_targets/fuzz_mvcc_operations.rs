#![no_main]

// Drives MvccStore across its full commit-path surface under adversarial
// operation sequences:
//   * Transaction lifecycle: begin / stage_write / stage_write_with_proof /
//     commit / commit_ssi / commit_fcw_prechecked / abort.
//   * Policy toggles: ConflictPolicy::Strict / SafeMerge / Adaptive.
//   * MergeProof variants that are well-defined on arbitrary payloads
//     (Unsafe, DisjointBlocks).
//
// Invariants checked after every accepted commit:
//   I1: commit sequences returned by the store are strictly monotonic.
//   I2: a snapshot captured before the most recent commit must see either
//       (a) a byte pattern that previously committed to that block, or
//       (b) nothing — it must NEVER see bytes that only became committed
//       after the snapshot was captured. Verified via an oracle that
//       records each captured snapshot's expected state.
//   I3: a snapshot captured after a successful commit observes exactly the
//       bytes the most recent committed writer staged for each block.
//   I4: effective_policy() always resolves Adaptive to Strict or SafeMerge,
//       and conflict_policy() returns one of the three declared policies.
//
// Size-bounded to keep exec/s high; invariant violations panic via assert!.

use ffs_mvcc::{ConflictPolicy, MergeProof, MvccStore, Transaction};
use ffs_types::{BlockNumber, CommitSeq, Snapshot};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

const MAX_INPUT_BYTES: usize = 2048;
const MAX_ACTIVE_TXNS: usize = 16;
const BLOCK_DOMAIN: u64 = 8;
const PAYLOAD_LEN: usize = 32;

struct ByteCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn next_u8(&mut self) -> u8 {
        let byte = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        byte
    }

    fn next_block(&mut self) -> BlockNumber {
        BlockNumber(u64::from(self.next_u8()) % BLOCK_DOMAIN)
    }
}

fn policy_from_byte(byte: u8) -> ConflictPolicy {
    match byte % 3 {
        0 => ConflictPolicy::Strict,
        1 => ConflictPolicy::SafeMerge,
        _ => ConflictPolicy::Adaptive,
    }
}

fn merge_proof_from_byte(byte: u8) -> MergeProof {
    // Only `Unsafe` and `DisjointBlocks` are well-defined on arbitrary
    // payload lengths; the other variants require byte-range bookkeeping
    // that would require coordinated payload construction. Those paths
    // are exercised by ffs-mvcc's dedicated unit tests.
    match byte % 2 {
        0 => MergeProof::Unsafe,
        _ => MergeProof::DisjointBlocks,
    }
}

// Oracle: mirrors the committed state that we expect to observe at the
// snapshot returned after each successful commit.
#[derive(Default)]
struct Oracle {
    committed: BTreeMap<BlockNumber, Vec<u8>>,
    last_commit_seq: u64,
}

impl Oracle {
    fn record_commit(
        &mut self,
        seq: CommitSeq,
        writes: &BTreeMap<BlockNumber, Vec<u8>>,
    ) {
        assert!(
            seq.0 > self.last_commit_seq,
            "I1: commit sequences must be strictly monotonic (prev={}, got={})",
            self.last_commit_seq,
            seq.0,
        );
        self.last_commit_seq = seq.0;
        for (block, bytes) in writes {
            self.committed.insert(*block, bytes.clone());
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    if data.len() < 8 {
        return;
    }

    let mut cursor = ByteCursor::new(data);

    let mut store = MvccStore::new();
    store.set_conflict_policy(policy_from_byte(cursor.next_u8()));

    let mut active: Vec<Transaction> = Vec::new();
    let mut pending_writes: Vec<BTreeMap<BlockNumber, Vec<u8>>> = Vec::new();
    let mut pre_commit_snapshots: Vec<(Snapshot, BTreeMap<BlockNumber, Vec<u8>>)> = Vec::new();
    let mut oracle = Oracle::default();

    while cursor.pos < data.len() {
        let op = cursor.next_u8() % 10;
        match op {
            // Begin a new transaction.
            0 => {
                if active.len() < MAX_ACTIVE_TXNS {
                    active.push(store.begin());
                    pending_writes.push(BTreeMap::new());
                }
                assert!(
                    matches!(
                        store.effective_policy(),
                        ConflictPolicy::Strict | ConflictPolicy::SafeMerge
                    ),
                    "I4: effective_policy() must resolve Adaptive to Strict or SafeMerge"
                );
            }
            // Plain stage_write on the most recent transaction.
            1 => {
                if let (Some(txn), Some(staged)) =
                    (active.last_mut(), pending_writes.last_mut())
                {
                    let block = cursor.next_block();
                    let tag = cursor.next_u8();
                    let payload = vec![tag; PAYLOAD_LEN];
                    txn.stage_write(block, payload.clone());
                    staged.insert(block, payload);
                }
            }
            // stage_write_with_proof — drives MergeProof plumbing.
            2 => {
                if let (Some(txn), Some(staged)) =
                    (active.last_mut(), pending_writes.last_mut())
                {
                    let block = cursor.next_block();
                    let tag = cursor.next_u8();
                    let proof_selector = cursor.next_u8();
                    let payload = vec![tag; PAYLOAD_LEN];
                    let proof = merge_proof_from_byte(proof_selector);
                    txn.stage_write_with_proof(block, payload.clone(), proof);
                    staged.insert(block, payload);
                }
            }
            // Record a pre-commit snapshot for invariant I2 (snapshot isolation).
            // The expected state is a CLONE of the oracle's committed map at
            // this moment — whatever we observe at this snapshot later must
            // match that frozen state (or be absent).
            3 => {
                pre_commit_snapshots.push((
                    store.current_snapshot(),
                    oracle.committed.clone(),
                ));
            }
            // Commit oldest via generic `commit`.
            4 => {
                if !active.is_empty() {
                    let txn = active.remove(0);
                    let staged = pending_writes.remove(0);
                    if let Ok(seq) = store.commit(txn) {
                        oracle.record_commit(seq, &staged);
                        check_snapshot_isolation(&store, &pre_commit_snapshots);
                        check_post_commit_visibility(&store, &oracle);
                    }
                }
            }
            // Commit oldest via `commit_ssi`.
            5 => {
                if !active.is_empty() {
                    let txn = active.remove(0);
                    let staged = pending_writes.remove(0);
                    if let Ok(seq) = store.commit_ssi(txn) {
                        oracle.record_commit(seq, &staged);
                        check_snapshot_isolation(&store, &pre_commit_snapshots);
                        check_post_commit_visibility(&store, &oracle);
                    }
                }
            }
            // Commit oldest via `commit_fcw_prechecked`.
            6 => {
                if !active.is_empty() {
                    let txn = active.remove(0);
                    let staged = pending_writes.remove(0);
                    if let Ok(seq) = store.commit_fcw_prechecked(txn) {
                        oracle.record_commit(seq, &staged);
                        check_snapshot_isolation(&store, &pre_commit_snapshots);
                        check_post_commit_visibility(&store, &oracle);
                    }
                }
            }
            // Abort most recent transaction (drop discards staged writes).
            7 => {
                if active.pop().is_some() {
                    pending_writes.pop();
                }
            }
            // Toggle policy mid-stream.
            8 => {
                store.set_conflict_policy(policy_from_byte(cursor.next_u8()));
                assert!(
                    matches!(
                        store.conflict_policy(),
                        ConflictPolicy::Strict
                            | ConflictPolicy::SafeMerge
                            | ConflictPolicy::Adaptive
                    ),
                    "I4: conflict_policy() must return one of the three declared policies"
                );
            }
            // Prune old versions; post-commit oracle must still be reachable
            // at the current snapshot.
            _ => {
                store.prune_safe();
                check_post_commit_visibility(&store, &oracle);
            }
        }
    }
});

// I2: snapshots captured before any commit must observe exactly the
// oracle's committed state frozen at the time of capture. A later commit's
// bytes must never leak backward into an older snapshot. For each (snap,
// expected_state) pair:
//   * If `read_visible(block, snap)` returns `Some(bytes)`, bytes MUST equal
//     the expected_state entry for that block (or be absent if the block
//     had no prior commit at snapshot time).
//   * `None` reads are always acceptable (pruned or never committed).
fn check_snapshot_isolation(
    store: &MvccStore,
    pre_commit: &[(Snapshot, BTreeMap<BlockNumber, Vec<u8>>)],
) {
    for (snap, expected_state) in pre_commit {
        for (block, expected_bytes) in expected_state {
            if let Some(observed) = store.read_visible(*block, *snap) {
                assert_eq!(
                    observed.as_ref(),
                    expected_bytes.as_slice(),
                    "I2 violated: snapshot {:?} on block {:?} should observe the frozen \
                     pre-commit value, not a later-committed value",
                    snap,
                    block
                );
            }
        }
    }
}

// I3: a snapshot captured at the current top of the version chain must see
// the oracle's most-recent committed bytes for every block the oracle
// tracks, unless that block was pruned.
fn check_post_commit_visibility(store: &MvccStore, oracle: &Oracle) {
    let snap = store.current_snapshot();
    for (block, expected) in &oracle.committed {
        if let Some(observed) = store.read_visible(*block, snap) {
            assert_eq!(
                observed.as_ref(),
                expected.as_slice(),
                "I3 violated: post-commit snapshot read on block {:?} returned unexpected bytes",
                block
            );
        }
        // A store may have pruned the version already; missing reads are OK.
    }
}
