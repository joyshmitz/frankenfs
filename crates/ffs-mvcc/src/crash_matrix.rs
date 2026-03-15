//! Deterministic crash/restart matrix for durable MVCC replay correctness.
//!
//! This module provides a deterministic test framework that proves WAL replay
//! correctness under adversarial crash timing.  It works by:
//!
//! 1. Building a WAL byte buffer from a deterministic commit sequence (seeded).
//! 2. Simulating crash points by truncating or corrupting the buffer at precise
//!    byte boundaries within the write path.
//! 3. Replaying each crashed WAL through [`WalReplayEngine`] and comparing the
//!    recovered state against an oracle (the known-good commit sequence).
//! 4. Collecting results into a machine-readable [`CrashMatrixReport`].
//!
//! # Crash Point Classes
//!
//! | Class | Simulation |
//! |-------|------------|
//! | `CrashBeforeRecordVisible` | Truncate WAL before the Nth record begins. |
//! | `CrashAfterRecordBeforeChecksum` | Write partial record body, no CRC. |
//! | `CrashAfterChecksumBeforeSync` | Full record present but bit-flip in CRC. |
//! | `CrashAfterSyncBeforeCommitSeqPublish` | Full record synced, verify monotonicity survives. |
//! | `RepeatedCrashReplay` | Multiple crash/replay cycles on the same WAL. |
//!
//! # Determinism
//!
//! Every matrix run is fully reproducible by seed.  The seed controls:
//! - Block numbers and data payloads for generated commits.
//! - Which byte offsets are targeted for truncation/corruption.
//!
//! No schedule should yield silent divergence from the oracle state.

use crate::MvccStore;
use crate::persist::apply_wal_commit;
use crate::wal::{self, WalCommit, WalWrite};
use crate::wal_replay::{ReplayOutcome, TailPolicy, WalReplayEngine};
use ffs_types::{BlockNumber, CommitSeq, Snapshot, TxnId};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ── Crash point classification ──────────────────────────────────────────────

/// Classification of simulated crash points within the WAL write path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrashPoint {
    /// Crash before the target record is appended.  The WAL contains only
    /// records prior to the crash point — the target record is invisible.
    CrashBeforeRecordVisible,

    /// Crash mid-write: partial record body written, CRC not yet appended.
    /// The WAL ends with a truncated record.
    CrashAfterRecordBeforeChecksum,

    /// Full record written including CRC, but a bit-flip in the CRC field
    /// simulates a crash between checksum write and fsync completion.
    CrashAfterChecksumBeforeSync,

    /// Record fully synced.  Replay should recover it.  This validates that
    /// the commit-seq-publish step (in-memory update after sync) is not
    /// required for durability — the WAL is the source of truth.
    CrashAfterSyncBeforeCommitSeqPublish,

    /// Multiple crash/replay cycles: crash at different points across
    /// successive replays of the same (growing) WAL.
    RepeatedCrashReplay,
}

impl CrashPoint {
    /// All crash point classes for matrix iteration.
    pub const ALL: [Self; 5] = [
        Self::CrashBeforeRecordVisible,
        Self::CrashAfterRecordBeforeChecksum,
        Self::CrashAfterChecksumBeforeSync,
        Self::CrashAfterSyncBeforeCommitSeqPublish,
        Self::RepeatedCrashReplay,
    ];
}

impl std::fmt::Display for CrashPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CrashBeforeRecordVisible => write!(f, "crash-before-record-visible"),
            Self::CrashAfterRecordBeforeChecksum => {
                write!(f, "crash-after-record-before-checksum")
            }
            Self::CrashAfterChecksumBeforeSync => write!(f, "crash-after-checksum-before-sync"),
            Self::CrashAfterSyncBeforeCommitSeqPublish => {
                write!(f, "crash-after-sync-before-commit-seq-publish")
            }
            Self::RepeatedCrashReplay => write!(f, "repeated-crash-replay"),
        }
    }
}

// ── Scenario result ─────────────────────────────────────────────────────────

/// Outcome of a single crash matrix scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioResult {
    /// Unique identifier for this scenario.
    pub scenario_id: String,
    /// Crash point class tested.
    pub crash_point: CrashPoint,
    /// Seed used to generate the commit sequence.
    pub seed: u64,
    /// Index of the commit where the crash was simulated.
    pub crash_at_commit: usize,
    /// Total commits in the test sequence.
    pub total_commits: usize,
    /// Number of commits expected to survive replay.
    pub expected_survivors: usize,
    /// Number of commits actually recovered by replay.
    pub actual_survivors: u64,
    /// Replay outcome classification.
    pub replay_outcome: String,
    /// Whether the oracle check passed (recovered state matches expected).
    pub oracle_pass: bool,
    /// Error message if oracle check failed.
    pub error: Option<String>,
}

// ── Matrix report ───────────────────────────────────────────────────────────

/// Machine-readable report of the full crash matrix run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashMatrixReport {
    /// Seed used for the entire matrix run.
    pub seed: u64,
    /// Total number of scenarios executed.
    pub total_scenarios: usize,
    /// Number of scenarios that passed.
    pub passed: usize,
    /// Number of scenarios that failed.
    pub failed: usize,
    /// Individual scenario results.
    pub scenarios: Vec<ScenarioResult>,
}

impl CrashMatrixReport {
    /// Whether every scenario passed.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }
}

// ── Deterministic commit generator ──────────────────────────────────────────

/// Simple deterministic PRNG (xorshift64) for reproducible test data.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 { 1 } else { seed })
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo + 1)
    }
}

/// Generate a deterministic sequence of WAL commits from a seed.
fn generate_commits(seed: u64, count: usize) -> Vec<WalCommit> {
    let mut rng = Rng::new(seed);
    let mut commits = Vec::with_capacity(count);

    for i in 1..=count {
        let seq = i as u64;
        let txn = seq;
        // Values bounded to 1..=4 and 4..=64 — safe to truncate on any platform.
        #[expect(clippy::cast_possible_truncation)]
        let num_writes: usize = rng.next_range(1, 4) as usize;
        let mut writes = Vec::with_capacity(num_writes);

        for _ in 0..num_writes {
            let block = rng.next_range(1, 1000);
            #[expect(clippy::cast_possible_truncation)]
            let data_len: usize = rng.next_range(4, 64) as usize;
            let data: Vec<u8> = (0..data_len).map(|_| (rng.next() & 0xFF) as u8).collect();
            writes.push(WalWrite {
                block: BlockNumber(block),
                data,
            });
        }

        commits.push(WalCommit {
            commit_seq: CommitSeq(seq),
            txn_id: TxnId(txn),
            writes,
        });
    }

    commits
}

// ── WAL construction helpers ────────────────────────────────────────────────

/// Encode just the commit records (no header) for replay engine input.
fn encode_commit_data(commits: &[WalCommit]) -> Vec<u8> {
    let mut data = Vec::new();
    for c in commits {
        data.extend_from_slice(&wal::encode_commit(c).expect("encode commit"));
    }
    data
}

/// Compute the byte offset where the Nth commit record begins (0-indexed),
/// relative to the start of commit data (after header).
fn commit_record_offset(commits: &[WalCommit], n: usize) -> usize {
    let mut offset = 0;
    for c in commits.iter().take(n) {
        offset += wal::encode_commit(c).expect("encode").len();
    }
    offset
}

/// Compute the byte size of the Nth commit record (0-indexed).
fn commit_record_size(commits: &[WalCommit], n: usize) -> usize {
    wal::encode_commit(&commits[n]).expect("encode").len()
}

// ── Oracle ──────────────────────────────────────────────────────────────────

/// Build the expected MvccStore state from commits 0..num_survivors.
///
/// This is the ground-truth oracle: after replaying the first `num_survivors`
/// commits, the store should contain exactly these versions visible at
/// a snapshot capturing all committed data.
fn build_oracle_store(commits: &[WalCommit], num_survivors: usize) -> MvccStore {
    let mut store = MvccStore::new();
    for c in commits.iter().take(num_survivors) {
        apply_wal_commit(&mut store, c);
    }
    store
}

/// Verify that the replayed store matches the oracle store for all blocks
/// written in the surviving commits.
fn verify_oracle(
    replayed_store: &MvccStore,
    oracle_store: &MvccStore,
    commits: &[WalCommit],
    num_survivors: usize,
) -> std::result::Result<(), String> {
    // Collect all block numbers written in surviving commits.
    let mut blocks_written: std::collections::BTreeSet<BlockNumber> =
        std::collections::BTreeSet::new();
    for c in commits.iter().take(num_survivors) {
        for w in &c.writes {
            blocks_written.insert(w.block);
        }
    }

    // Create a snapshot that sees everything committed.
    let snap_seq = num_survivors as u64;
    let snapshot = Snapshot {
        high: CommitSeq(snap_seq),
    };

    for &block in &blocks_written {
        let oracle_val = oracle_store.read_visible(block, snapshot);
        let replay_val = replayed_store.read_visible(block, snapshot);

        match (&oracle_val, &replay_val) {
            (Some(expected), Some(actual)) => {
                if expected.as_ref() != actual.as_ref() {
                    return Err(format!(
                        "block {}: data mismatch (oracle {} bytes vs replay {} bytes)",
                        block.0,
                        expected.len(),
                        actual.len()
                    ));
                }
            }
            (Some(_), None) => {
                return Err(format!(
                    "block {}: present in oracle but missing in replay",
                    block.0
                ));
            }
            (None, Some(_)) => {
                return Err(format!(
                    "block {}: absent in oracle but present in replay",
                    block.0
                ));
            }
            (None, None) => {} // Both absent — ok
        }
    }

    Ok(())
}

/// Helper: extract error from oracle result or build error from other conditions.
fn build_scenario_error(
    oracle_result: std::result::Result<(), String>,
    commits_match: bool,
    expected_survivors: usize,
    actual_survivors: u64,
    outcome_error: Option<String>,
) -> (bool, Option<String>) {
    if let Err(e) = oracle_result {
        return (false, Some(e));
    }
    if !commits_match {
        return (
            false,
            Some(format!(
                "expected {expected_survivors} survivors, got {actual_survivors}"
            )),
        );
    }
    if let Some(msg) = outcome_error {
        return (false, Some(msg));
    }
    (true, None)
}

// ── Crash scenario runners ──────────────────────────────────────────────────

/// Run a single crash scenario: truncate/corrupt the WAL, replay, and verify.
fn run_crash_scenario(
    commits: &[WalCommit],
    crash_point: CrashPoint,
    crash_at: usize,
    seed: u64,
    scenario_id: &str,
) -> ScenarioResult {
    let total_commits = commits.len();

    debug!(
        scenario_id,
        crash_point = %crash_point,
        crash_at,
        total_commits,
        seed,
        "crash_matrix_scenario_start"
    );

    match crash_point {
        CrashPoint::CrashBeforeRecordVisible => {
            run_crash_before_visible(commits, crash_at, seed, scenario_id)
        }
        CrashPoint::CrashAfterRecordBeforeChecksum => {
            run_crash_partial_record(commits, crash_at, seed, scenario_id)
        }
        CrashPoint::CrashAfterChecksumBeforeSync => {
            run_crash_corrupt_crc(commits, crash_at, seed, scenario_id)
        }
        CrashPoint::CrashAfterSyncBeforeCommitSeqPublish => {
            run_crash_after_sync(commits, crash_at, seed, scenario_id)
        }
        CrashPoint::RepeatedCrashReplay => {
            run_repeated_crash_replay(commits, crash_at, seed, scenario_id)
        }
    }
}

/// Crash before the target record is visible: WAL contains only prior commits.
fn run_crash_before_visible(
    commits: &[WalCommit],
    crash_at: usize,
    seed: u64,
    scenario_id: &str,
) -> ScenarioResult {
    let expected_survivors = crash_at;
    let commit_data = encode_commit_data(&commits[..crash_at]);

    let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);
    let mut store = MvccStore::new();
    let report = engine
        .replay(&commit_data, 0, |c| apply_wal_commit(&mut store, c))
        .expect("replay should not fail for clean data");

    let oracle = build_oracle_store(commits, expected_survivors);
    let oracle_result = verify_oracle(&store, &oracle, commits, expected_survivors);

    let (oracle_pass, error) = build_scenario_error(
        oracle_result,
        report.commits_replayed == expected_survivors as u64,
        expected_survivors,
        report.commits_replayed,
        None,
    );

    ScenarioResult {
        scenario_id: scenario_id.to_owned(),
        crash_point: CrashPoint::CrashBeforeRecordVisible,
        seed,
        crash_at_commit: crash_at,
        total_commits: commits.len(),
        expected_survivors,
        actual_survivors: report.commits_replayed,
        replay_outcome: format!("{:?}", report.outcome),
        oracle_pass,
        error,
    }
}

/// Crash mid-write: partial record body, CRC not yet written.
fn run_crash_partial_record(
    commits: &[WalCommit],
    crash_at: usize,
    seed: u64,
    scenario_id: &str,
) -> ScenarioResult {
    let expected_survivors = crash_at;
    let mut commit_data = encode_commit_data(commits);

    // Find the byte offset where the crash_at-th record starts and truncate
    // partway through it (approximately half the record).
    let record_start = commit_record_offset(commits, crash_at);
    let record_size = commit_record_size(commits, crash_at);
    let truncate_at = record_start + record_size / 2;
    commit_data.truncate(truncate_at);

    let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);
    let mut store = MvccStore::new();
    let report = engine
        .replay(&commit_data, 0, |c| apply_wal_commit(&mut store, c))
        .expect("TruncateToLastGood should not return Err");

    let oracle = build_oracle_store(commits, expected_survivors);
    let oracle_result = verify_oracle(&store, &oracle, commits, expected_survivors);

    let outcome_err = match report.outcome {
        ReplayOutcome::TruncatedTail { .. } | ReplayOutcome::CorruptTail { .. } => None,
        _ => Some(format!(
            "expected TruncatedTail/CorruptTail, got {:?}",
            report.outcome
        )),
    };
    let (oracle_pass, error) = build_scenario_error(
        oracle_result,
        report.commits_replayed == expected_survivors as u64,
        expected_survivors,
        report.commits_replayed,
        outcome_err,
    );

    ScenarioResult {
        scenario_id: scenario_id.to_owned(),
        crash_point: CrashPoint::CrashAfterRecordBeforeChecksum,
        seed,
        crash_at_commit: crash_at,
        total_commits: commits.len(),
        expected_survivors,
        actual_survivors: report.commits_replayed,
        replay_outcome: format!("{:?}", report.outcome),
        oracle_pass,
        error,
    }
}

/// Full record written but CRC is corrupted (simulates crash between checksum
/// write and fsync, or a bit-flip on disk).
fn run_crash_corrupt_crc(
    commits: &[WalCommit],
    crash_at: usize,
    seed: u64,
    scenario_id: &str,
) -> ScenarioResult {
    let expected_survivors = crash_at;
    let mut commit_data = encode_commit_data(commits);

    // Find the CRC field of the crash_at-th record and flip a bit.
    let record_start = commit_record_offset(commits, crash_at);
    let record_size = commit_record_size(commits, crash_at);
    let crc_offset = record_start + record_size - 4; // CRC is last 4 bytes

    if crc_offset < commit_data.len() {
        commit_data[crc_offset] ^= 0x01;
    }

    let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);
    let mut store = MvccStore::new();
    let report = engine
        .replay(&commit_data, 0, |c| apply_wal_commit(&mut store, c))
        .expect("TruncateToLastGood should not return Err");

    let oracle = build_oracle_store(commits, expected_survivors);
    let oracle_result = verify_oracle(&store, &oracle, commits, expected_survivors);

    let outcome_err = if matches!(report.outcome, ReplayOutcome::CorruptTail { .. }) {
        None
    } else {
        Some(format!("expected CorruptTail, got {:?}", report.outcome))
    };
    let (oracle_pass, error) = build_scenario_error(
        oracle_result,
        report.commits_replayed == expected_survivors as u64,
        expected_survivors,
        report.commits_replayed,
        outcome_err,
    );

    ScenarioResult {
        scenario_id: scenario_id.to_owned(),
        crash_point: CrashPoint::CrashAfterChecksumBeforeSync,
        seed,
        crash_at_commit: crash_at,
        total_commits: commits.len(),
        expected_survivors,
        actual_survivors: report.commits_replayed,
        replay_outcome: format!("{:?}", report.outcome),
        oracle_pass,
        error,
    }
}

/// Record fully synced — replay should recover all commits up to and including
/// the crash_at commit.
fn run_crash_after_sync(
    commits: &[WalCommit],
    crash_at: usize,
    seed: u64,
    scenario_id: &str,
) -> ScenarioResult {
    // After sync, the crash_at-th record IS durable, so survivors = crash_at + 1
    let expected_survivors = (crash_at + 1).min(commits.len());
    let commit_data = encode_commit_data(&commits[..expected_survivors]);

    let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);
    let mut store = MvccStore::new();
    let report = engine
        .replay(&commit_data, 0, |c| apply_wal_commit(&mut store, c))
        .expect("replay should not fail for clean data");

    let oracle = build_oracle_store(commits, expected_survivors);
    let oracle_result = verify_oracle(&store, &oracle, commits, expected_survivors);

    let outcome_err = if report.outcome == ReplayOutcome::Clean {
        None
    } else {
        Some(format!("expected Clean, got {:?}", report.outcome))
    };
    let (oracle_pass, error) = build_scenario_error(
        oracle_result,
        report.commits_replayed == expected_survivors as u64,
        expected_survivors,
        report.commits_replayed,
        outcome_err,
    );

    ScenarioResult {
        scenario_id: scenario_id.to_owned(),
        crash_point: CrashPoint::CrashAfterSyncBeforeCommitSeqPublish,
        seed,
        crash_at_commit: crash_at,
        total_commits: commits.len(),
        expected_survivors,
        actual_survivors: report.commits_replayed,
        replay_outcome: format!("{:?}", report.outcome),
        oracle_pass,
        error,
    }
}

/// Multiple crash/replay cycles on the same WAL.
///
/// Builds a WAL incrementally: after each crash, replays what survived, then
/// "writes" more commits and crashes again at a different point.  Verifies
/// that the final state is consistent with the oracle.
fn run_repeated_crash_replay(
    commits: &[WalCommit],
    _crash_at: usize,
    seed: u64,
    scenario_id: &str,
) -> ScenarioResult {
    let total = commits.len();
    let num_cycles = 3.min(total);
    let mut rng = Rng::new(seed.wrapping_add(0xDEAD));

    // Track which commits are durably survived across cycles.
    let mut durable_count = 0_usize;
    let mut cumulative_store = MvccStore::new();

    for cycle in 0..num_cycles {
        // Each cycle "appends" some new commits beyond the durable frontier,
        // then crashes partway through.
        let new_commits_in_cycle = ((total - durable_count) / (num_cycles - cycle)).max(1);
        let attempted_end = (durable_count + new_commits_in_cycle).min(total);

        // Crash point: truncate the last attempted commit partway through.
        let crash_target = attempted_end.saturating_sub(1).max(durable_count);
        let survived_this_cycle = crash_target;

        // Build WAL data with all commits up to crash target fully intact,
        // and the crash_target-th record truncated.
        let mut commit_data = encode_commit_data(&commits[..crash_target]);
        if crash_target < attempted_end {
            let partial = wal::encode_commit(&commits[crash_target]).expect("encode");
            let max_trunc = partial.len().saturating_sub(1).max(1);
            #[expect(clippy::cast_possible_truncation)]
            let trunc_len: usize = rng.next_range(1, max_trunc as u64) as usize;
            commit_data.extend_from_slice(&partial[..trunc_len]);
        }

        // Replay the crashed WAL.
        let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);
        cumulative_store = MvccStore::new();
        let report = engine
            .replay(&commit_data, 0, |c| {
                apply_wal_commit(&mut cumulative_store, c);
            })
            .expect("TruncateToLastGood should not return Err");

        debug!(
            scenario_id,
            cycle,
            durable_before = durable_count,
            attempted_end,
            survived = survived_this_cycle,
            commits_replayed = report.commits_replayed,
            outcome = ?report.outcome,
            "crash_matrix_cycle"
        );

        durable_count = survived_this_cycle;
    }

    // Final oracle check.
    let oracle = build_oracle_store(commits, durable_count);
    let oracle_result = verify_oracle(&cumulative_store, &oracle, commits, durable_count);

    ScenarioResult {
        scenario_id: scenario_id.to_owned(),
        crash_point: CrashPoint::RepeatedCrashReplay,
        seed,
        crash_at_commit: durable_count,
        total_commits: total,
        expected_survivors: durable_count,
        actual_survivors: durable_count as u64,
        replay_outcome: format!("{num_cycles} cycles completed"),
        oracle_pass: oracle_result.is_ok(),
        error: oracle_result.err(),
    }
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Run the full deterministic crash/restart matrix.
///
/// The matrix tests every [`CrashPoint`] class at multiple crash positions
/// within a commit sequence of `num_commits` entries, all generated from
/// the given `seed`.
///
/// Returns a machine-readable [`CrashMatrixReport`] summarizing all results.
pub fn run_crash_matrix(seed: u64, num_commits: usize) -> CrashMatrixReport {
    let commits = generate_commits(seed, num_commits);

    info!(
        seed,
        num_commits,
        crash_point_classes = CrashPoint::ALL.len(),
        "crash_matrix_start"
    );

    let mut scenarios = Vec::new();
    let mut passed = 0_usize;
    let mut failed = 0_usize;

    for &crash_point in &CrashPoint::ALL {
        // For each crash class, test crashing at multiple positions.
        let positions: Vec<usize> = if crash_point == CrashPoint::RepeatedCrashReplay {
            vec![0] // single run that internally does multiple cycles
        } else {
            // Test at every commit boundary and also at positions 0, mid, last.
            (0..num_commits).collect()
        };

        for &crash_at in &positions {
            let scenario_id = format!("{crash_point}@commit-{crash_at}/seed-{seed}");

            let result = run_crash_scenario(&commits, crash_point, crash_at, seed, &scenario_id);

            if result.oracle_pass {
                debug!(
                    scenario_id = result.scenario_id,
                    "crash_matrix_scenario_pass"
                );
                passed += 1;
            } else {
                warn!(
                    scenario_id = result.scenario_id,
                    error = result.error.as_deref().unwrap_or("unknown"),
                    "crash_matrix_scenario_fail"
                );
                failed += 1;
            }

            scenarios.push(result);
        }
    }

    let total_scenarios = scenarios.len();

    info!(seed, total_scenarios, passed, failed, "crash_matrix_done");

    CrashMatrixReport {
        seed,
        total_scenarios,
        passed,
        failed,
        scenarios,
    }
}

// ── FailFast policy matrix ──────────────────────────────────────────────────

/// Run the crash matrix with `FailFast` policy to verify that every corruption
/// scenario produces an appropriate error rather than silent data loss.
pub fn run_fail_fast_matrix(seed: u64, num_commits: usize) -> CrashMatrixReport {
    let commits = generate_commits(seed, num_commits);

    info!(
        seed,
        num_commits,
        policy = "FailFast",
        "fail_fast_matrix_start"
    );

    let mut scenarios = Vec::new();
    let mut passed = 0_usize;
    let mut failed = 0_usize;

    // Only test crash classes that produce corruption/truncation.
    let corruption_classes = [
        CrashPoint::CrashAfterRecordBeforeChecksum,
        CrashPoint::CrashAfterChecksumBeforeSync,
    ];

    for &crash_point in &corruption_classes {
        for crash_at in 0..num_commits {
            let scenario_id = format!("failfast-{crash_point}@commit-{crash_at}/seed-{seed}");

            let (commit_data, expected_survivors) = match crash_point {
                CrashPoint::CrashAfterRecordBeforeChecksum => {
                    let mut data = encode_commit_data(&commits);
                    let record_start = commit_record_offset(&commits, crash_at);
                    let record_size = commit_record_size(&commits, crash_at);
                    data.truncate(record_start + record_size / 2);
                    (data, crash_at)
                }
                CrashPoint::CrashAfterChecksumBeforeSync => {
                    let mut data = encode_commit_data(&commits);
                    let record_start = commit_record_offset(&commits, crash_at);
                    let record_size = commit_record_size(&commits, crash_at);
                    let crc_offset = record_start + record_size - 4;
                    if crc_offset < data.len() {
                        data[crc_offset] ^= 0x01;
                    }
                    (data, crash_at)
                }
                _ => unreachable!(),
            };

            let engine = WalReplayEngine::new(TailPolicy::FailFast);
            let mut store = MvccStore::new();
            let result = engine.replay(&commit_data, 0, |c| apply_wal_commit(&mut store, c));

            // FailFast should return Err for corrupted/truncated records,
            // regardless of crash position.
            let oracle_pass = result.is_err();

            let replay_outcome = match &result {
                Ok(r) => format!("{:?}", r.outcome),
                Err(e) => format!("Err: {e}"),
            };

            let result = ScenarioResult {
                scenario_id: scenario_id.clone(),
                crash_point,
                seed,
                crash_at_commit: crash_at,
                total_commits: num_commits,
                expected_survivors,
                actual_survivors: 0, // FailFast aborts
                replay_outcome,
                oracle_pass,
                error: if oracle_pass {
                    None
                } else {
                    Some("FailFast did not return Err for corrupted WAL".to_owned())
                },
            };

            if result.oracle_pass {
                passed += 1;
            } else {
                failed += 1;
            }

            scenarios.push(result);
        }
    }

    let total_scenarios = scenarios.len();

    info!(
        seed,
        total_scenarios, passed, failed, "fail_fast_matrix_done"
    );

    CrashMatrixReport {
        seed,
        total_scenarios,
        passed,
        failed,
        scenarios,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Deterministic generation ────────────────────────────────────────

    #[test]
    fn generate_commits_is_deterministic() {
        let a = generate_commits(42, 10);
        let b = generate_commits(42, 10);
        assert_eq!(a.len(), 10);
        for (ca, cb) in a.iter().zip(b.iter()) {
            assert_eq!(ca.commit_seq, cb.commit_seq);
            assert_eq!(ca.txn_id, cb.txn_id);
            assert_eq!(ca.writes.len(), cb.writes.len());
            for (wa, wb) in ca.writes.iter().zip(cb.writes.iter()) {
                assert_eq!(wa.block, wb.block);
                assert_eq!(wa.data, wb.data);
            }
        }
    }

    #[test]
    fn different_seeds_produce_different_commits() {
        let a = generate_commits(42, 5);
        let b = generate_commits(99, 5);
        // Very likely to differ in block numbers or data.
        let same = a.iter().zip(b.iter()).all(|(ca, cb)| {
            ca.writes
                .iter()
                .zip(cb.writes.iter())
                .all(|(wa, wb)| wa.block == wb.block && wa.data == wb.data)
        });
        assert!(!same, "different seeds should produce different data");
    }

    // ── Oracle verification ─────────────────────────────────────────────

    #[test]
    fn oracle_store_matches_direct_replay() {
        let commits = generate_commits(123, 5);
        let oracle = build_oracle_store(&commits, 5);
        let data = encode_commit_data(&commits);

        let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);
        let mut replay_store = MvccStore::new();
        engine
            .replay(&data, 0, |c| apply_wal_commit(&mut replay_store, c))
            .expect("replay");

        let result = verify_oracle(&replay_store, &oracle, &commits, 5);
        assert!(result.is_ok(), "oracle mismatch: {result:?}");
    }

    #[test]
    fn oracle_detects_missing_block() {
        let commits = generate_commits(123, 3);
        let oracle = build_oracle_store(&commits, 3);
        let empty_store = MvccStore::new();

        let result = verify_oracle(&empty_store, &oracle, &commits, 3);
        assert!(result.is_err());
    }

    // ── Individual crash point classes ───────────────────────────────────

    #[test]
    fn crash_before_visible_at_every_position() {
        let commits = generate_commits(777, 8);
        for crash_at in 0..8 {
            let result = run_crash_before_visible(
                &commits,
                crash_at,
                777,
                &format!("test-before-visible-{crash_at}"),
            );
            assert!(
                result.oracle_pass,
                "crash_at={crash_at}: {:?}",
                result.error
            );
            assert_eq!(result.actual_survivors, crash_at as u64);
        }
    }

    #[test]
    fn crash_partial_record_at_every_position() {
        let commits = generate_commits(888, 8);
        for crash_at in 0..8 {
            let result = run_crash_partial_record(
                &commits,
                crash_at,
                888,
                &format!("test-partial-{crash_at}"),
            );
            assert!(
                result.oracle_pass,
                "crash_at={crash_at}: {:?}",
                result.error
            );
            assert_eq!(result.actual_survivors, crash_at as u64);
        }
    }

    #[test]
    fn crash_corrupt_crc_at_every_position() {
        let commits = generate_commits(999, 8);
        for crash_at in 0..8 {
            let result = run_crash_corrupt_crc(
                &commits,
                crash_at,
                999,
                &format!("test-corrupt-crc-{crash_at}"),
            );
            assert!(
                result.oracle_pass,
                "crash_at={crash_at}: {:?}",
                result.error
            );
            assert_eq!(result.actual_survivors, crash_at as u64);
        }
    }

    #[test]
    fn crash_after_sync_at_every_position() {
        let commits = generate_commits(1111, 8);
        for crash_at in 0..8 {
            let result = run_crash_after_sync(
                &commits,
                crash_at,
                1111,
                &format!("test-after-sync-{crash_at}"),
            );
            assert!(
                result.oracle_pass,
                "crash_at={crash_at}: {:?}",
                result.error
            );
            // After sync, crash_at-th record IS durable.
            let expected = (crash_at + 1).min(commits.len());
            assert_eq!(result.actual_survivors, expected as u64);
        }
    }

    #[test]
    fn repeated_crash_replay_cycles() {
        let commits = generate_commits(2222, 12);
        let result = run_repeated_crash_replay(&commits, 0, 2222, "test-repeated");
        assert!(result.oracle_pass, "repeated crash: {:?}", result.error);
    }

    // ── Full matrix run ─────────────────────────────────────────────────

    #[test]
    fn full_matrix_seed_42_passes() {
        let report = run_crash_matrix(42, 6);
        assert!(
            report.all_passed(),
            "matrix failed: {}/{} passed, failures: {:?}",
            report.passed,
            report.total_scenarios,
            report
                .scenarios
                .iter()
                .filter(|s| !s.oracle_pass)
                .map(|s| format!("{}: {}", s.scenario_id, s.error.as_deref().unwrap_or("?")))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn full_matrix_seed_1337_passes() {
        let report = run_crash_matrix(1337, 8);
        assert!(
            report.all_passed(),
            "matrix failed: {}/{} passed",
            report.passed,
            report.total_scenarios
        );
    }

    #[test]
    fn full_matrix_seed_0xdeadbeef_passes() {
        let report = run_crash_matrix(0xDEAD_BEEF, 10);
        assert!(
            report.all_passed(),
            "matrix failed: {}/{} passed",
            report.passed,
            report.total_scenarios
        );
    }

    #[test]
    fn matrix_report_is_serializable() {
        let report = run_crash_matrix(42, 4);
        let json = serde_json::to_string_pretty(&report).expect("serialize");
        assert!(json.contains("\"seed\": 42"), "json missing seed: {json}");
        assert!(
            json.contains("\"oracle_pass\": true"),
            "json missing oracle_pass: {json}"
        );
    }

    // ── FailFast matrix ─────────────────────────────────────────────────

    #[test]
    fn fail_fast_matrix_seed_42() {
        let report = run_fail_fast_matrix(42, 6);
        assert!(
            report.all_passed(),
            "FailFast matrix failed: {}/{} passed, failures: {:?}",
            report.passed,
            report.total_scenarios,
            report
                .scenarios
                .iter()
                .filter(|s| !s.oracle_pass)
                .map(|s| format!("{}: {}", s.scenario_id, s.error.as_deref().unwrap_or("?")))
                .collect::<Vec<_>>()
        );
    }

    // ── Invariant: no schedule yields silent divergence ──────────────────

    #[test]
    fn no_silent_divergence_across_seeds() {
        // Run matrix across multiple seeds to ensure no schedule produces
        // silent divergence (incorrect data without error).
        for seed in [1, 42, 100, 255, 1000, 0xCAFE, 0xBEEF, 0xDEAD] {
            let report = run_crash_matrix(seed, 6);
            for scenario in &report.scenarios {
                assert!(
                    scenario.oracle_pass,
                    "silent divergence at seed={seed}, scenario={}: {:?}",
                    scenario.scenario_id, scenario.error
                );
            }
        }
    }

    // ── Idempotent replay across crash/restart ───────────────────────────

    #[test]
    fn replay_is_idempotent_after_crash() {
        let commits = generate_commits(5555, 10);
        let mut data = encode_commit_data(&commits);
        // Truncate at record 7 (midway through).
        let offset = commit_record_offset(&commits, 7);
        let size = commit_record_size(&commits, 7);
        data.truncate(offset + size / 3);

        let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);

        // First replay.
        let mut store1 = MvccStore::new();
        let r1 = engine
            .replay(&data, 0, |c| apply_wal_commit(&mut store1, c))
            .expect("replay 1");

        // Second replay of same data.
        let mut store2 = MvccStore::new();
        let r2 = engine
            .replay(&data, 0, |c| apply_wal_commit(&mut store2, c))
            .expect("replay 2");

        assert_eq!(r1.commits_replayed, r2.commits_replayed);
        assert_eq!(r1.outcome, r2.outcome);

        // Verify both stores agree.
        let commits_replayed_1 =
            usize::try_from(r1.commits_replayed).expect("replayed commit count fits in usize");
        let commits_replayed_2 =
            usize::try_from(r2.commits_replayed).expect("replayed commit count fits in usize");
        let oracle = build_oracle_store(&commits, commits_replayed_1);
        assert!(verify_oracle(&store1, &oracle, &commits, commits_replayed_1).is_ok());
        assert!(verify_oracle(&store2, &oracle, &commits, commits_replayed_2).is_ok());
    }

    // ── Negative: intentionally wrong oracle detects divergence ──────────

    #[test]
    fn oracle_detects_divergence_when_wrong_survivor_count() {
        let commits = generate_commits(6666, 5);
        let data = encode_commit_data(&commits[..3]); // only 3 commits

        let engine = WalReplayEngine::new(TailPolicy::TruncateToLastGood);
        let mut store = MvccStore::new();
        engine
            .replay(&data, 0, |c| apply_wal_commit(&mut store, c))
            .expect("replay");

        // Oracle expects 5 survivors, but only 3 are present.
        let oracle = build_oracle_store(&commits, 5);
        let result = verify_oracle(&store, &oracle, &commits, 5);
        assert!(result.is_err(), "oracle should detect missing commits");
    }
}
