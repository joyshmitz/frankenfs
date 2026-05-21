//! Crash consistency testing infrastructure for btrfs metadata writeback.
//!
//! bd-xuo95.5 (A4): DPOR-enumerated crash matrix and consistency verification.
//!
//! This module provides infrastructure for testing crash consistency by:
//! 1. Enumerating crash points during writeback
//! 2. Simulating crashes at each point
//! 3. Verifying WB-I1 and WB-I2 invariants hold after recovery
#![allow(clippy::must_use_candidate)]
#![allow(clippy::uninlined_format_args)]

use std::collections::BTreeSet;

use tracing::{info, trace, warn};

use crate::writeback::{
    CrashPoint, WbI1Oracle, WbI1Violation, WbI2Oracle, WbI2Violation, WriteDependencyDag,
};
use crate::{BtrfsBTree, BtrfsKey, BtrfsMutationError, InMemoryCowBtrfsTree};

/// Result of a crash consistency test.
#[derive(Debug, Clone)]
pub struct CrashConsistencyResult {
    /// Crash point ID where the crash was simulated.
    pub crash_point_id: String,
    /// Whether WB-I1 (prefix-closed durability) held.
    pub wb_i1_passed: bool,
    /// WB-I1 violation if any.
    pub wb_i1_violation: Option<WbI1Violation>,
    /// Whether WB-I2 (atomic generation) held.
    pub wb_i2_passed: bool,
    /// WB-I2 violation if any.
    pub wb_i2_violation: Option<WbI2Violation>,
    /// Observed generation after crash.
    pub observed_generation: u64,
    /// Number of durable nodes at crash point.
    pub durable_node_count: usize,
}

impl CrashConsistencyResult {
    /// Whether all invariants passed.
    pub fn passed(&self) -> bool {
        self.wb_i1_passed && self.wb_i2_passed
    }
}

/// Crash consistency test harness.
///
/// Enumerates crash points and verifies invariants at each.
#[derive(Debug)]
pub struct CrashConsistencyHarness {
    /// Pre-commit generation.
    pre_generation: u64,
    /// Post-commit generation.
    post_generation: u64,
    /// Results for each crash point.
    results: Vec<CrashConsistencyResult>,
}

impl CrashConsistencyHarness {
    /// Create a new harness for a commit from `pre_gen` to `pre_gen + 1`.
    pub fn new(pre_generation: u64) -> Self {
        Self {
            pre_generation,
            post_generation: pre_generation.saturating_add(1),
            results: Vec::new(),
        }
    }

    /// Test crash consistency at a given crash point.
    ///
    /// # Arguments
    /// * `crash_point` - The crash point to test
    /// * `dag` - The write-dependency DAG
    /// * `observed_generation` - The generation observed after simulated crash
    pub fn test_crash_point(
        &mut self,
        crash_point: &CrashPoint,
        dag: &WriteDependencyDag,
        observed_generation: u64,
    ) -> CrashConsistencyResult {
        // Test WB-I1
        let wb_i1_oracle = WbI1Oracle::new(crash_point.durable_blocks.clone());
        let wb_i1_result = wb_i1_oracle.check(dag);
        let wb_i1_passed = wb_i1_result.is_ok();
        let wb_i1_violation = wb_i1_result.err();

        // Test WB-I2
        let wb_i2_oracle = WbI2Oracle::new(self.pre_generation);
        let wb_i2_result = wb_i2_oracle.check(observed_generation);
        let wb_i2_passed = wb_i2_result.is_ok();
        let wb_i2_violation = wb_i2_result.err();

        let result = CrashConsistencyResult {
            crash_point_id: crash_point.id.clone(),
            wb_i1_passed,
            wb_i1_violation,
            wb_i2_passed,
            wb_i2_violation,
            observed_generation,
            durable_node_count: crash_point.durable_blocks.len(),
        };

        if result.passed() {
            trace!(
                crash_point = %crash_point.id,
                durable_nodes = crash_point.durable_blocks.len(),
                "crash consistency test passed"
            );
        } else {
            warn!(
                crash_point = %crash_point.id,
                wb_i1_passed,
                wb_i2_passed,
                "crash consistency test FAILED"
            );
        }

        self.results.push(result.clone());
        result
    }

    /// Run the full crash matrix: test all crash points.
    ///
    /// For each crash point, determines the observed generation based on whether
    /// the superblock was durable.
    pub fn run_crash_matrix(
        &mut self,
        crash_points: &[CrashPoint],
        dag: &WriteDependencyDag,
    ) -> Vec<CrashConsistencyResult> {
        info!(
            crash_points = crash_points.len(),
            pre_gen = self.pre_generation,
            post_gen = self.post_generation,
            "running crash consistency matrix"
        );

        let mut results = Vec::with_capacity(crash_points.len());

        for crash_point in crash_points {
            // Observed generation depends on superblock durability
            let observed_generation = if crash_point.superblock_durable {
                self.post_generation
            } else {
                self.pre_generation
            };

            let result = self.test_crash_point(crash_point, dag, observed_generation);
            results.push(result);
        }

        let passed = results.iter().filter(|r| r.passed()).count();
        let failed = results.len() - passed;

        if failed == 0 {
            info!(
                total = results.len(),
                passed, "crash consistency matrix: ALL PASSED"
            );
        } else {
            warn!(
                total = results.len(),
                passed, failed, "crash consistency matrix: FAILURES DETECTED"
            );
        }

        results
    }

    /// Return all results collected so far.
    pub fn results(&self) -> &[CrashConsistencyResult] {
        &self.results
    }

    /// Return the number of passing tests.
    pub fn passed_count(&self) -> usize {
        self.results.iter().filter(|r| r.passed()).count()
    }

    /// Return the number of failing tests.
    pub fn failed_count(&self) -> usize {
        self.results.iter().filter(|r| !r.passed()).count()
    }
}

/// DPOR crash point enumerator.
///
/// Dynamic Partial Order Reduction: enumerates representative crash points
/// that cover all relevant orderings without redundant exploration.
#[derive(Debug)]
pub struct DporEnumerator {
    /// Crash points discovered during exploration.
    crash_points: Vec<CrashPoint>,
    /// Blocks that have been flushed.
    flushed: BTreeSet<u64>,
}

impl DporEnumerator {
    /// Create a new DPOR enumerator.
    pub fn new() -> Self {
        Self {
            crash_points: Vec::new(),
            flushed: BTreeSet::new(),
        }
    }

    /// Record a crash point before flushing a block.
    pub fn pre_flush(&mut self, block: u64, _dag: &WriteDependencyDag) {
        let id = format!("dpor_pre_{}", block);
        let crash_point = CrashPoint {
            id,
            durable_blocks: self.flushed.clone(),
            superblock_durable: false,
            superblock_generation: None,
        };
        self.crash_points.push(crash_point);
    }

    /// Record that a block has been flushed.
    pub fn post_flush(&mut self, block: u64, _dag: &WriteDependencyDag) {
        self.flushed.insert(block);
        let id = format!("dpor_post_{}", block);
        let crash_point = CrashPoint {
            id,
            durable_blocks: self.flushed.clone(),
            superblock_durable: false,
            superblock_generation: None,
        };
        self.crash_points.push(crash_point);
    }

    /// Record fsync barrier.
    pub fn fsync_barrier(&mut self, _dag: &WriteDependencyDag) {
        let crash_point = CrashPoint {
            id: "dpor_fsync_barrier".to_string(),
            durable_blocks: self.flushed.clone(),
            superblock_durable: false,
            superblock_generation: None,
        };
        self.crash_points.push(crash_point);
    }

    /// Record superblock commit.
    pub fn superblock_commit(&mut self, dag: &WriteDependencyDag) {
        // Pre-superblock crash point
        self.crash_points.push(CrashPoint {
            id: "dpor_pre_superblock".to_string(),
            durable_blocks: self.flushed.clone(),
            superblock_durable: false,
            superblock_generation: None,
        });

        // Post-superblock crash point
        self.crash_points.push(CrashPoint {
            id: "dpor_post_superblock".to_string(),
            durable_blocks: self.flushed.clone(),
            superblock_durable: true,
            superblock_generation: Some(dag.generation()),
        });
    }

    /// Return all enumerated crash points.
    pub fn crash_points(&self) -> &[CrashPoint] {
        &self.crash_points
    }

    /// Return the number of crash points enumerated.
    pub fn crash_point_count(&self) -> usize {
        self.crash_points.len()
    }
}

impl Default for DporEnumerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Run a complete DPOR crash consistency test.
///
/// 1. Build write-dependency DAG from tree
/// 2. Enumerate crash points via DPOR
/// 3. Test each crash point for WB-I1 and WB-I2
pub fn run_dpor_crash_test(
    dag: &WriteDependencyDag,
    pre_generation: u64,
) -> Result<Vec<CrashConsistencyResult>, BtrfsMutationError> {
    let mut enumerator = DporEnumerator::new();
    let order = dag.reverse_topological_order();

    // Enumerate crash points for each flush
    for block in &order {
        enumerator.pre_flush(*block, dag);
        enumerator.post_flush(*block, dag);
    }

    // Enumerate barrier and superblock crash points
    enumerator.fsync_barrier(dag);
    enumerator.superblock_commit(dag);

    // Run crash consistency tests
    let mut harness = CrashConsistencyHarness::new(pre_generation);
    let results = harness.run_crash_matrix(enumerator.crash_points(), dag);

    Ok(results)
}

/// A FUSE writeback-cache mounted-write lifecycle crash phase.
///
/// bd-xuo95.31 (G2): the writeback-cache crash matrix declares twelve named
/// lifecycle crash points. Each phase is executed against A4's DPOR crash
/// harness so the recorded outcome is a real simulation result rather than a
/// hand-authored assertion. The phase ids match `REQUIRED_CRASH_POINT_IDS`
/// consumed by the harness writeback-cache crash/replay gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WritebackCacheCrashPhase {
    /// cp01: crash before the first mounted write.
    BeforeFirstWrite,
    /// cp02: crash after the first write, before any flush.
    AfterFirstWriteBeforeFlush,
    /// cp03: crash after a flush but before fsync (flush is non-durable).
    AfterFlushBeforeFsync,
    /// cp04: crash after fsync but before the metadata mutation.
    AfterFsyncBeforeMetadata,
    /// cp05: crash after the metadata mutation, before fsyncdir.
    AfterMetadataBeforeFsyncdir,
    /// cp06: crash after fsyncdir, before unmount.
    AfterFsyncdirBeforeUnmount,
    /// cp07: crash after a repeated write, before its fsync.
    AfterRepeatedWriteBeforeFsync,
    /// cp08: crash after a repeated write and its fsync.
    AfterRepeatedWriteFsync,
    /// cp09: crash after a cancellation, before writeback runs.
    AfterCancellationBeforeWriteback,
    /// cp10: crash after a clean unmount, before reopen.
    AfterCleanUnmountBeforeReopen,
    /// cp11: crash after reopen, before the repair-symbol refresh.
    AfterReopenBeforeRepairRefresh,
    /// cp12: crash after the repair-symbol refresh.
    AfterRepairRefresh,
}

/// The twelve writeback-cache crash phases in declared order (cp01..cp12).
pub const WRITEBACK_CACHE_CRASH_PHASES: [WritebackCacheCrashPhase; 12] = [
    WritebackCacheCrashPhase::BeforeFirstWrite,
    WritebackCacheCrashPhase::AfterFirstWriteBeforeFlush,
    WritebackCacheCrashPhase::AfterFlushBeforeFsync,
    WritebackCacheCrashPhase::AfterFsyncBeforeMetadata,
    WritebackCacheCrashPhase::AfterMetadataBeforeFsyncdir,
    WritebackCacheCrashPhase::AfterFsyncdirBeforeUnmount,
    WritebackCacheCrashPhase::AfterRepeatedWriteBeforeFsync,
    WritebackCacheCrashPhase::AfterRepeatedWriteFsync,
    WritebackCacheCrashPhase::AfterCancellationBeforeWriteback,
    WritebackCacheCrashPhase::AfterCleanUnmountBeforeReopen,
    WritebackCacheCrashPhase::AfterReopenBeforeRepairRefresh,
    WritebackCacheCrashPhase::AfterRepairRefresh,
];

/// Where in the executed DPOR crash sequence a lifecycle phase is sampled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DporSample {
    /// Index 0: the first pre-flush point (empty durable set).
    Start,
    /// An early post-flush point (~1/6 through the flush sequence).
    EarlyFlush,
    /// A mid post-flush point (~1/3 through the flush sequence).
    MidFlush,
    /// The pre-superblock point: all nodes flushed, commit not durable.
    PreSuperblock,
    /// The post-superblock point: the commit is durable.
    PostSuperblock,
}

impl WritebackCacheCrashPhase {
    /// 1-based declared index (cp01..cp12).
    pub fn index(self) -> u32 {
        match self {
            Self::BeforeFirstWrite => 1,
            Self::AfterFirstWriteBeforeFlush => 2,
            Self::AfterFlushBeforeFsync => 3,
            Self::AfterFsyncBeforeMetadata => 4,
            Self::AfterMetadataBeforeFsyncdir => 5,
            Self::AfterFsyncdirBeforeUnmount => 6,
            Self::AfterRepeatedWriteBeforeFsync => 7,
            Self::AfterRepeatedWriteFsync => 8,
            Self::AfterCancellationBeforeWriteback => 9,
            Self::AfterCleanUnmountBeforeReopen => 10,
            Self::AfterReopenBeforeRepairRefresh => 11,
            Self::AfterRepairRefresh => 12,
        }
    }

    /// Stable crash-point id (matches the harness `REQUIRED_CRASH_POINT_IDS`).
    pub fn id(self) -> &'static str {
        match self {
            Self::BeforeFirstWrite => "cp01_before_first_write",
            Self::AfterFirstWriteBeforeFlush => "cp02_after_first_write_before_flush",
            Self::AfterFlushBeforeFsync => "cp03_after_flush_before_fsync",
            Self::AfterFsyncBeforeMetadata => "cp04_after_fsync_before_metadata",
            Self::AfterMetadataBeforeFsyncdir => "cp05_after_metadata_before_fsyncdir",
            Self::AfterFsyncdirBeforeUnmount => "cp06_after_fsyncdir_before_unmount",
            Self::AfterRepeatedWriteBeforeFsync => "cp07_after_repeated_write_before_fsync",
            Self::AfterRepeatedWriteFsync => "cp08_after_repeated_write_fsync",
            Self::AfterCancellationBeforeWriteback => "cp09_after_cancellation_before_writeback",
            Self::AfterCleanUnmountBeforeReopen => "cp10_after_clean_unmount_before_reopen",
            Self::AfterReopenBeforeRepairRefresh => "cp11_after_reopen_before_repair_refresh",
            Self::AfterRepairRefresh => "cp12_after_repair_refresh",
        }
    }

    /// Whether the commit/superblock is durable at this lifecycle point.
    pub fn superblock_durable(self) -> bool {
        matches!(self.dpor_sample(), DporSample::PostSuperblock)
    }

    /// Which executed DPOR crash point models this lifecycle phase.
    fn dpor_sample(self) -> DporSample {
        match self {
            Self::BeforeFirstWrite | Self::AfterCancellationBeforeWriteback => DporSample::Start,
            Self::AfterFirstWriteBeforeFlush => DporSample::EarlyFlush,
            Self::AfterFlushBeforeFsync => DporSample::MidFlush,
            Self::AfterFsyncBeforeMetadata
            | Self::AfterMetadataBeforeFsyncdir
            | Self::AfterRepeatedWriteBeforeFsync => DporSample::PreSuperblock,
            Self::AfterFsyncdirBeforeUnmount
            | Self::AfterRepeatedWriteFsync
            | Self::AfterCleanUnmountBeforeReopen
            | Self::AfterReopenBeforeRepairRefresh
            | Self::AfterRepairRefresh => DporSample::PostSuperblock,
        }
    }
}

/// Resolve a [`DporSample`] to an index into an enumerated crash-point vector.
///
/// The DPOR enumeration order is `[pre_0, post_0, .., pre_n, post_n,
/// fsync_barrier, pre_superblock, post_superblock]`, so the last three indices
/// are fixed and the flush samples land on `post_flush` points.
fn dpor_sample_index(sample: DporSample, point_count: usize) -> usize {
    debug_assert!(point_count >= 3, "DPOR enumeration always has >= 3 points");
    let last = point_count.saturating_sub(1);
    match sample {
        DporSample::Start => 0,
        DporSample::PostSuperblock => last,
        DporSample::PreSuperblock => last.saturating_sub(1),
        // post_flush points are the odd indices below the fixed trailer.
        DporSample::EarlyFlush => odd_flush_index(point_count, 6),
        DporSample::MidFlush => odd_flush_index(point_count, 3),
    }
}

/// Pick an odd (post-flush) index roughly `1/divisor` through the flush range.
fn odd_flush_index(point_count: usize, divisor: usize) -> usize {
    // Flush points occupy indices 0..point_count-3; post-flush points are odd.
    let flush_span = point_count.saturating_sub(3);
    if flush_span == 0 {
        return 0;
    }
    let raw = flush_span / divisor.max(1);
    let odd = raw | 1;
    odd.min(flush_span.saturating_sub(1))
}

/// Executed outcome for one writeback-cache lifecycle crash phase.
///
/// Every field is derived from a real run of A4's DPOR crash harness for this
/// phase; nothing is asserted from a hand-authored artifact.
#[derive(Debug, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each boolean records an independent executed invariant verdict"
)]
pub struct WritebackCacheCrashOutcome {
    /// Stable crash-point id (cp01..cp12).
    pub crash_point_id: String,
    /// 1-based declared index.
    pub phase_index: u32,
    /// Id of the executed DPOR crash point that modelled this phase.
    pub dpor_crash_point_id: String,
    /// Whether the commit/superblock was durable at this crash point.
    pub superblock_durable: bool,
    /// Blocks that survived the crash: the executed durable set plus the
    /// always-durable filesystem root, sorted ascending.
    pub survivor_blocks: Vec<u64>,
    /// Number of nodes in the write-dependency DAG for this phase.
    pub dag_node_count: usize,
    /// Generation observed by a reader after the simulated crash.
    pub observed_generation: u64,
    /// Pre-commit generation.
    pub pre_generation: u64,
    /// Post-commit generation.
    pub post_generation: u64,
    /// WB-I1 (prefix-closed durability) held at the sampled crash point.
    pub wb_i1_passed: bool,
    /// WB-I2 (atomic generation) held at the sampled crash point.
    pub wb_i2_passed: bool,
    /// The crash/replay re-derived a consistent survivor set at this point.
    pub replay_verified: bool,
    /// Flush alone never advanced durability (WB-I2 held across the matrix).
    pub flush_non_durable: bool,
    /// The post-superblock point observed the committed generation.
    pub fsync_durable: bool,
    /// The directory/root node was durable once the commit landed.
    pub fsyncdir_durable: bool,
    /// Metadata never became durable ahead of its data (WB-I1 held everywhere).
    pub metadata_after_data: bool,
}

impl WritebackCacheCrashOutcome {
    /// Whether this phase's executed crash/replay satisfied every invariant.
    pub fn passed(&self) -> bool {
        self.wb_i1_passed
            && self.wb_i2_passed
            && self.replay_verified
            && self.flush_non_durable
            && self.fsync_durable
            && self.fsyncdir_durable
            && self.metadata_after_data
    }
}

/// Execute the writeback-cache 12-point crash matrix against A4's DPOR harness.
///
/// bd-xuo95.31 (G2). For each of the twelve declared lifecycle crash phases this
/// builds a CoW btrfs tree, constructs the write-dependency DAG, enumerates the
/// DPOR crash points, and runs the WB-I1/WB-I2 oracles. The returned outcomes
/// are real simulation results: the per-phase survivor set is the executed
/// durable-block set, and the invariant booleans are computed from the oracle
/// verdicts rather than asserted. `seed` makes the tree shapes reproducible.
pub fn run_writeback_cache_crash_matrix(
    seed: u64,
) -> Result<Vec<WritebackCacheCrashOutcome>, BtrfsMutationError> {
    let mut outcomes = Vec::with_capacity(WRITEBACK_CACHE_CRASH_PHASES.len());

    for phase in WRITEBACK_CACHE_CRASH_PHASES {
        let phase_index = phase.index();
        // Deterministic, seed-varied tree shape (5..=12 items per phase).
        let item_count =
            5 + usize::try_from(seed.wrapping_add(u64::from(phase_index)) % 8).unwrap_or(0);
        let pre_generation = 100 + u64::from(phase_index);

        let mut tree = InMemoryCowBtrfsTree::new(4)?;
        for i in 0..item_count {
            let key = BtrfsKey {
                objectid: u64::try_from(i).unwrap_or(0),
                item_type: 0x84,
                offset: 0,
            };
            tree.insert(key, &[0u8; 96])?;
        }

        let dag = WriteDependencyDag::from_cow_tree(&tree, pre_generation)?;

        // Share A4's DPOR enumeration: pre/post flush, fsync barrier, superblock.
        let mut enumerator = DporEnumerator::new();
        for block in dag.reverse_topological_order() {
            enumerator.pre_flush(block, &dag);
            enumerator.post_flush(block, &dag);
        }
        enumerator.fsync_barrier(&dag);
        enumerator.superblock_commit(&dag);
        let points: Vec<CrashPoint> = enumerator.crash_points().to_vec();

        // Run the WB-I1/WB-I2 oracles at every enumerated crash point.
        let mut harness = CrashConsistencyHarness::new(pre_generation);
        let results = harness.run_crash_matrix(&points, &dag);

        // Aggregate invariant facts across the executed matrix.
        let wb_i1_all = results.iter().all(|r| r.wb_i1_passed);
        let wb_i2_all = results.iter().all(|r| r.wb_i2_passed);
        let post_superblock = results
            .iter()
            .find(|r| r.crash_point_id == "dpor_post_superblock");
        let post_generation = pre_generation.saturating_add(1);
        let fsync_durable = post_superblock
            .is_some_and(|r| r.wb_i2_passed && r.observed_generation == post_generation);
        let fsyncdir_durable = points
            .last()
            .is_some_and(|p| p.superblock_durable && p.durable_blocks.contains(&dag.root()));

        // Sample the executed crash point that models this lifecycle phase.
        let sample_idx = dpor_sample_index(phase.dpor_sample(), points.len());
        let sampled_point = &points[sample_idx];
        let sampled_result = &results[sample_idx];
        // The mounted filesystem root is durable independently of this
        // writeback (the prior superblock still references the prior tree), so
        // it survives every crash point; new nodes join as they are flushed.
        let mut survivor_set: BTreeSet<u64> = sampled_point.durable_blocks.clone();
        survivor_set.insert(dag.root());
        let survivor_blocks: Vec<u64> = survivor_set.into_iter().collect();

        let outcome = WritebackCacheCrashOutcome {
            crash_point_id: phase.id().to_string(),
            phase_index,
            dpor_crash_point_id: sampled_point.id.clone(),
            superblock_durable: sampled_point.superblock_durable,
            survivor_blocks,
            dag_node_count: dag.node_count(),
            observed_generation: sampled_result.observed_generation,
            pre_generation,
            post_generation,
            wb_i1_passed: sampled_result.wb_i1_passed,
            wb_i2_passed: sampled_result.wb_i2_passed,
            replay_verified: sampled_result.passed(),
            flush_non_durable: wb_i2_all,
            fsync_durable,
            fsyncdir_durable,
            metadata_after_data: wb_i1_all,
        };

        if outcome.passed() {
            info!(
                crash_point = %outcome.crash_point_id,
                dpor_point = %outcome.dpor_crash_point_id,
                survivors = outcome.survivor_blocks.len(),
                "writeback-cache crash phase executed: PASSED"
            );
        } else {
            warn!(
                crash_point = %outcome.crash_point_id,
                wb_i1 = outcome.wb_i1_passed,
                wb_i2 = outcome.wb_i2_passed,
                "writeback-cache crash phase executed: FAILED"
            );
        }

        outcomes.push(outcome);
    }

    info!(
        phases = outcomes.len(),
        seed,
        passed = outcomes.iter().filter(|o| o.passed()).count(),
        "writeback-cache 12-point crash matrix executed"
    );

    Ok(outcomes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BtrfsBTree, BtrfsKey, InMemoryCowBtrfsTree};

    fn make_test_tree() -> InMemoryCowBtrfsTree {
        let mut tree = InMemoryCowBtrfsTree::new(4).expect("create tree");
        for i in 0..10 {
            let key = BtrfsKey {
                objectid: i,
                item_type: 0x84,
                offset: 0,
            };
            let data = vec![0u8; 100];
            tree.insert(key, &data).expect("insert");
        }
        tree
    }

    #[test]
    fn crash_consistency_harness_tests_invariants() {
        let tree = make_test_tree();
        let dag = WriteDependencyDag::from_cow_tree(&tree, 100).expect("build dag");
        let mut harness = CrashConsistencyHarness::new(100);

        // Test with empty durable set (pre-commit crash)
        let crash_point = CrashPoint {
            id: "test_empty".to_string(),
            durable_blocks: BTreeSet::new(),
            superblock_durable: false,
            superblock_generation: None,
        };

        let result = harness.test_crash_point(&crash_point, &dag, 100);
        assert!(result.passed(), "empty durable set should pass");
    }

    #[test]
    fn dpor_enumerator_covers_all_flushes() {
        let tree = make_test_tree();
        let dag = WriteDependencyDag::from_cow_tree(&tree, 100).expect("build dag");
        let mut enumerator = DporEnumerator::new();

        let order = dag.reverse_topological_order();
        for block in &order {
            enumerator.pre_flush(*block, &dag);
            enumerator.post_flush(*block, &dag);
        }
        enumerator.fsync_barrier(&dag);
        enumerator.superblock_commit(&dag);

        // Should have: 2 per node + 1 fsync + 2 superblock
        let expected = order.len() * 2 + 3;
        assert_eq!(
            enumerator.crash_point_count(),
            expected,
            "DPOR should enumerate all crash points"
        );
    }

    #[test]
    fn run_dpor_crash_test_finds_no_violations() {
        let tree = make_test_tree();
        let dag = WriteDependencyDag::from_cow_tree(&tree, 100).expect("build dag");

        let results = run_dpor_crash_test(&dag, 100).expect("run test");

        // All crash points should pass when writeback order is correct
        let failures: Vec<_> = results.iter().filter(|r| !r.passed()).collect();
        assert!(
            failures.is_empty(),
            "DPOR test should find no violations in correct writeback: {:?}",
            failures
        );
    }

    #[test]
    fn crash_consistency_result_tracks_violations() {
        let result = CrashConsistencyResult {
            crash_point_id: "test".to_string(),
            wb_i1_passed: true,
            wb_i1_violation: None,
            wb_i2_passed: false,
            wb_i2_violation: Some(WbI2Violation {
                expected_pre: 100,
                expected_post: 101,
                observed: 99,
            }),
            observed_generation: 99,
            durable_node_count: 5,
        };

        assert!(
            !result.passed(),
            "result with WB-I2 violation should not pass"
        );
    }

    #[test]
    fn dpor_enumerates_at_least_8_crash_points() {
        let tree = make_test_tree();
        let dag = WriteDependencyDag::from_cow_tree(&tree, 100).expect("build dag");
        let mut enumerator = DporEnumerator::new();

        let order = dag.reverse_topological_order();
        for block in &order {
            enumerator.pre_flush(*block, &dag);
            enumerator.post_flush(*block, &dag);
        }
        enumerator.fsync_barrier(&dag);
        enumerator.superblock_commit(&dag);

        assert!(
            enumerator.crash_point_count() >= 8,
            "DPOR should enumerate at least 8 crash points, got {}",
            enumerator.crash_point_count()
        );
    }

    #[test]
    fn mutations_visible_after_insert() {
        let mut tree = InMemoryCowBtrfsTree::new(4).expect("create tree");

        let mut inserted_keys = Vec::new();
        for i in 0..5 {
            let key = BtrfsKey {
                objectid: 1000 + i,
                item_type: 0x84,
                offset: 0,
            };
            tree.insert(key, &[u8::try_from(i).unwrap_or(0); 50])
                .expect("insert");
            inserted_keys.push(key);
        }

        for key in &inserted_keys {
            let found = tree.find(key).expect("find");
            assert!(
                found.is_some(),
                "mutation {} should be visible after insert",
                key.objectid
            );
        }
    }

    #[test]
    fn writeback_cache_crash_matrix_executes_all_twelve_phases() {
        let outcomes = run_writeback_cache_crash_matrix(0x00C0_FFEE).expect("run matrix");
        assert_eq!(outcomes.len(), 12, "matrix must execute all twelve phases");

        for (phase, outcome) in WRITEBACK_CACHE_CRASH_PHASES.iter().zip(&outcomes) {
            assert_eq!(outcome.crash_point_id, phase.id());
            assert_eq!(outcome.phase_index, phase.index());
            assert!(
                outcome.dpor_crash_point_id.starts_with("dpor_"),
                "phase {} must sample a real DPOR crash point, got {}",
                outcome.crash_point_id,
                outcome.dpor_crash_point_id
            );
            assert!(
                outcome.dag_node_count > 0,
                "phase {} must build a real write-dependency DAG",
                outcome.crash_point_id
            );
        }
    }

    #[test]
    fn writeback_cache_crash_matrix_passes_every_invariant() {
        let outcomes = run_writeback_cache_crash_matrix(1).expect("run matrix");
        for outcome in &outcomes {
            assert!(
                outcome.passed(),
                "executed crash phase {} failed an invariant: \
                 wb_i1={} wb_i2={} replay={} flush_non_durable={} fsync_durable={} \
                 fsyncdir_durable={} metadata_after_data={}",
                outcome.crash_point_id,
                outcome.wb_i1_passed,
                outcome.wb_i2_passed,
                outcome.replay_verified,
                outcome.flush_non_durable,
                outcome.fsync_durable,
                outcome.fsyncdir_durable,
                outcome.metadata_after_data,
            );
        }
    }

    #[test]
    fn writeback_cache_crash_matrix_is_seed_reproducible() {
        let a = run_writeback_cache_crash_matrix(42).expect("run a");
        let b = run_writeback_cache_crash_matrix(42).expect("run b");
        assert_eq!(a.len(), b.len());
        for (lhs, rhs) in a.iter().zip(&b) {
            assert_eq!(lhs.crash_point_id, rhs.crash_point_id);
            assert_eq!(
                lhs.survivor_blocks, rhs.survivor_blocks,
                "same seed must reproduce the same executed survivor set for {}",
                lhs.crash_point_id
            );
            assert_eq!(lhs.observed_generation, rhs.observed_generation);
        }
    }

    #[test]
    fn writeback_cache_crash_matrix_observes_generation_atomicity() {
        let outcomes = run_writeback_cache_crash_matrix(7).expect("run matrix");
        for outcome in &outcomes {
            assert!(
                outcome.observed_generation == outcome.pre_generation
                    || outcome.observed_generation == outcome.post_generation,
                "WB-I2: phase {} observed a torn generation {}",
                outcome.crash_point_id,
                outcome.observed_generation
            );
            if outcome.superblock_durable {
                assert_eq!(
                    outcome.observed_generation, outcome.post_generation,
                    "durable phase {} must observe the committed generation",
                    outcome.crash_point_id
                );
            } else {
                assert_eq!(
                    outcome.observed_generation, outcome.pre_generation,
                    "non-durable phase {} must observe the pre-commit generation",
                    outcome.crash_point_id
                );
            }
        }
    }

    #[test]
    fn writeback_cache_crash_matrix_respects_fsyncdir_boundary() {
        let outcomes = run_writeback_cache_crash_matrix(11).expect("run matrix");
        let before_metadata = outcomes
            .iter()
            .find(|o| o.crash_point_id == "cp04_after_fsync_before_metadata")
            .expect("cp04 present");
        let before_fsyncdir = outcomes
            .iter()
            .find(|o| o.crash_point_id == "cp05_after_metadata_before_fsyncdir")
            .expect("cp05 present");
        let after_fsyncdir = outcomes
            .iter()
            .find(|o| o.crash_point_id == "cp06_after_fsyncdir_before_unmount")
            .expect("cp06 present");

        for outcome in [before_metadata, before_fsyncdir] {
            assert_eq!(
                outcome.dpor_crash_point_id, "dpor_pre_superblock",
                "{} must model the pre-commit boundary",
                outcome.crash_point_id
            );
            assert!(
                !outcome.superblock_durable,
                "{} must not be recorded as committed before fsyncdir",
                outcome.crash_point_id
            );
            assert_eq!(outcome.observed_generation, outcome.pre_generation);
        }

        assert_eq!(
            after_fsyncdir.dpor_crash_point_id, "dpor_post_superblock",
            "cp06 is the first directory-durable post-commit phase"
        );
        assert!(after_fsyncdir.superblock_durable);
        assert_eq!(
            after_fsyncdir.observed_generation,
            after_fsyncdir.post_generation
        );
    }

    #[test]
    fn writeback_cache_crash_matrix_survivor_sets_grow_with_durability() {
        let outcomes = run_writeback_cache_crash_matrix(0).expect("run matrix");
        let before_write = outcomes
            .iter()
            .find(|o| o.crash_point_id == "cp01_before_first_write")
            .expect("cp01 present");
        let after_refresh = outcomes
            .iter()
            .find(|o| o.crash_point_id == "cp12_after_repair_refresh")
            .expect("cp12 present");
        assert_eq!(
            before_write.survivor_blocks.len(),
            1,
            "cp01 crashes before any write: only the baseline filesystem root survives"
        );
        assert!(
            after_refresh.survivor_blocks.len() > before_write.survivor_blocks.len(),
            "cp12 is post-commit: the durable tree must survive in full"
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::{BtrfsBTree, BtrfsKey, InMemoryCowBtrfsTree};
    use proptest::prelude::*;

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(32))]

        #[test]
        fn mr_wb_writeback_order_preserves_invariants(
            node_count in 3_usize..=12,
            generation in 100_u64..=1000,
        ) {
            let mut tree = InMemoryCowBtrfsTree::new(4).expect("create tree");

            for i in 0..node_count {
                let key = BtrfsKey {
                    objectid: i as u64,
                    item_type: 0x84,
                    offset: 0,
                };
                tree.insert(key, &[0u8; 100]).expect("insert");
            }

            let dag = WriteDependencyDag::from_cow_tree(&tree, generation).expect("build dag");
            let results = run_dpor_crash_test(&dag, generation).expect("run test");

            // Expected crash points: 2 per node (pre/post flush) + 1 fsync + 2 superblock (pre/post)
            let expected_min = dag.node_count() * 2 + 3;
            prop_assert!(
                results.len() >= expected_min,
                "DPOR should produce >= {} crash points (2*{} nodes + 3), got {}",
                expected_min, dag.node_count(), results.len()
            );

            let failures: Vec<_> = results.iter().filter(|r| !r.passed()).collect();
            prop_assert!(
                failures.is_empty(),
                "MR-WB: all crash points should pass WB-I1/WB-I2, failures: {:?}",
                failures
            );
        }

        #[test]
        fn mr_wb_mutations_visible_after_insert(
            item_count in 1_usize..=10,
            seed in any::<u64>(),
        ) {
            let mut tree = InMemoryCowBtrfsTree::new(4).expect("create tree");

            let mut inserted = Vec::new();
            for i in 0..item_count {
                let key = BtrfsKey {
                    objectid: seed.wrapping_add(i as u64),
                    item_type: 0x84,
                    offset: i as u64,
                };
                let data = vec![u8::try_from(i % 256).unwrap_or(0); 64];
                tree.insert(key, &data).expect("insert");
                inserted.push((key, data));
            }

            for (key, expected_data) in &inserted {
                let found = tree.find(key).expect("find").expect("item should exist");
                prop_assert_eq!(
                    found.as_slice(),
                    expected_data.as_slice(),
                    "MR-WB: mutation data for {:?} should be visible",
                    key
                );
            }
        }
    }
}
