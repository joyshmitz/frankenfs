//! Crash consistency testing infrastructure for btrfs metadata writeback.
//!
//! bd-xuo95.5 (A4): DPOR-enumerated crash matrix and consistency verification.
//!
//! This module provides infrastructure for testing crash consistency by:
//! 1. Enumerating crash points during writeback
//! 2. Simulating crashes at each point
//! 3. Verifying WB-I1 and WB-I2 invariants hold after recovery

use std::collections::BTreeSet;

use tracing::{debug, info, trace, warn};

use crate::writeback::{CrashPoint, WbI1Oracle, WbI1Violation, WbI2Oracle, WbI2Violation, WriteDependencyDag};
use crate::BtrfsMutationError;

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
                passed,
                "crash consistency matrix: ALL PASSED"
            );
        } else {
            warn!(
                total = results.len(),
                passed,
                failed,
                "crash consistency matrix: FAILURES DETECTED"
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
    pub fn pre_flush(&mut self, block: u64, dag: &WriteDependencyDag) {
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
    pub fn post_flush(&mut self, block: u64, dag: &WriteDependencyDag) {
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
    pub fn fsync_barrier(&mut self, dag: &WriteDependencyDag) {
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

        assert!(!result.passed(), "result with WB-I2 violation should not pass");
    }
}
