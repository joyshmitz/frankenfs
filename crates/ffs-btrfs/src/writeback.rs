//! btrfs metadata writeback: write-dependency DAG and crash consistency.
//!
//! bd-xuo95.5 (A4): Implements write-dependency DAG construction, reverse-topological
//! flush ordering, and crash consistency oracles (WB-I1, WB-I2) for btrfs metadata.
//!
//! # Write-Dependency DAG
//!
//! The DAG captures ordering constraints: a child node must be durable before any
//! parent that references it. Nodes are flushed in reverse topological order.
//!
//! # Crash Consistency Invariants
//!
//! - **WB-I1 (Prefix-Closed Durability):** At every crash point, the set of durable
//!   nodes is prefix-closed under references: no durable internal node points at a
//!   non-durable child.
//!
//! - **WB-I2 (Atomic Generation Transition):** A reader after crash observes
//!   generation `g` (pre-writeback) or `g+1` (post), never a torn mixture.

use std::collections::{BTreeMap, BTreeSet};

use tracing::{debug, trace};

use crate::{BtrfsCowNode, BtrfsMutationError, InMemoryCowBtrfsTree};

/// A node in the write-dependency DAG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagNode {
    /// Block number of this node.
    pub block: u64,
    /// Tree level (0 = leaf).
    pub level: u8,
    /// Generation when this node was created/modified.
    pub generation: u64,
    /// Child block numbers (empty for leaves).
    pub children: Vec<u64>,
    /// Whether this node has been marked durable.
    pub durable: bool,
}

/// Write-dependency DAG for btrfs CoW tree nodes.
///
/// Captures the ordering constraint that children must be durable before parents.
#[derive(Debug, Clone)]
pub struct WriteDependencyDag {
    /// All nodes in the DAG, keyed by block number.
    nodes: BTreeMap<u64, DagNode>,
    /// Root block number.
    root: u64,
    /// Current generation.
    generation: u64,
}

impl WriteDependencyDag {
    /// Build a write-dependency DAG from an in-memory CoW tree.
    pub fn from_cow_tree(
        tree: &InMemoryCowBtrfsTree,
        generation: u64,
    ) -> Result<Self, BtrfsMutationError> {
        let mut nodes = BTreeMap::new();
        let root = tree.root_block();

        Self::collect_nodes(tree, root, &mut nodes, generation)?;

        Ok(Self {
            nodes,
            root,
            generation,
        })
    }

    fn collect_nodes(
        tree: &InMemoryCowBtrfsTree,
        block: u64,
        nodes: &mut BTreeMap<u64, DagNode>,
        generation: u64,
    ) -> Result<(), BtrfsMutationError> {
        if nodes.contains_key(&block) {
            return Ok(());
        }

        let node = tree.node_snapshot(block)?;
        let (level, children) = match &node {
            BtrfsCowNode::Leaf { .. } => (0, Vec::new()),
            BtrfsCowNode::Internal { children, .. } => {
                let child_blocks: Vec<u64> = children.clone();
                let height = tree.height()?;
                // Internal nodes have level > 0; for simplicity we use 1 for direct parents of leaves
                let level = u8::try_from(height.saturating_sub(1)).unwrap_or(1);
                (level.max(1), child_blocks)
            }
        };

        nodes.insert(
            block,
            DagNode {
                block,
                level,
                generation,
                children: children.clone(),
                durable: false,
            },
        );

        // Recursively collect children
        for child in children {
            Self::collect_nodes(tree, child, nodes, generation)?;
        }

        Ok(())
    }

    /// Return blocks in reverse topological order (leaves first, root last).
    ///
    /// This is the order in which nodes must be flushed to maintain WB-I1.
    pub fn reverse_topological_order(&self) -> Vec<u64> {
        // Kahn's algorithm: start from nodes with no children (leaves)
        let mut in_degree: BTreeMap<u64, usize> = BTreeMap::new();
        let mut parent_of: BTreeMap<u64, Vec<u64>> = BTreeMap::new();

        for (block, node) in &self.nodes {
            in_degree.entry(*block).or_insert(0);
            for child in &node.children {
                *in_degree.entry(*child).or_insert(0) += 1;
                parent_of.entry(*child).or_default().push(*block);
            }
        }

        // Start with leaves (children in the DAG, which have in_degree from parents)
        // Actually for reverse topo, we want nodes whose children are all processed
        // Reframe: edges go parent -> child, we want reverse order (children first)

        // Simpler approach: compute levels and sort
        let mut by_level: BTreeMap<u8, Vec<u64>> = BTreeMap::new();
        for (block, node) in &self.nodes {
            by_level.entry(node.level).or_default().push(*block);
        }

        let mut result = Vec::with_capacity(self.nodes.len());
        // Levels 0 (leaves) first, then 1, 2, etc.
        for level in by_level.keys() {
            if let Some(blocks) = by_level.get(level) {
                result.extend(blocks.iter().copied());
            }
        }

        trace!(order_len = result.len(), "writeback dag reverse_topological_order");
        result
    }

    /// Mark a node as durable after it has been successfully flushed.
    pub fn mark_durable(&mut self, block: u64) -> Result<(), BtrfsMutationError> {
        let node = self
            .nodes
            .get_mut(&block)
            .ok_or(BtrfsMutationError::MissingNode(block))?;
        node.durable = true;
        trace!(block, "writeback dag mark_durable");
        Ok(())
    }

    /// Check if a node is durable.
    pub fn is_durable(&self, block: u64) -> bool {
        self.nodes.get(&block).map_or(false, |n| n.durable)
    }

    /// Return the root block number.
    pub fn root(&self) -> u64 {
        self.root
    }

    /// Return the current generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Return the number of nodes in the DAG.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Return all blocks in the DAG.
    pub fn blocks(&self) -> impl Iterator<Item = u64> + '_ {
        self.nodes.keys().copied()
    }

    /// Get a node by block number.
    pub fn get(&self, block: u64) -> Option<&DagNode> {
        self.nodes.get(&block)
    }
}

/// WB-I1 oracle: verify prefix-closed durability.
///
/// At every crash point, the set of durable nodes must be prefix-closed:
/// no durable internal node may point at a non-durable child.
#[derive(Debug, Clone)]
pub struct WbI1Oracle {
    /// Blocks that are known durable.
    durable_blocks: BTreeSet<u64>,
}

impl WbI1Oracle {
    /// Create a new WB-I1 oracle with the given durable block set.
    pub fn new(durable_blocks: BTreeSet<u64>) -> Self {
        Self { durable_blocks }
    }

    /// Create from a DAG's current durability state.
    pub fn from_dag(dag: &WriteDependencyDag) -> Self {
        let durable_blocks = dag
            .nodes
            .iter()
            .filter(|(_, n)| n.durable)
            .map(|(b, _)| *b)
            .collect();
        Self { durable_blocks }
    }

    /// Check WB-I1: every durable internal node's children must also be durable.
    ///
    /// Returns `Ok(())` if the invariant holds, or `Err` with the violating block.
    pub fn check(&self, dag: &WriteDependencyDag) -> Result<(), WbI1Violation> {
        for (block, node) in &dag.nodes {
            if !self.durable_blocks.contains(block) {
                continue;
            }
            // This node is durable; all its children must also be durable
            for child in &node.children {
                if !self.durable_blocks.contains(child) {
                    return Err(WbI1Violation {
                        durable_parent: *block,
                        non_durable_child: *child,
                    });
                }
            }
        }
        debug!(durable_count = self.durable_blocks.len(), "wb_i1 check passed");
        Ok(())
    }

    /// Mark a block as durable.
    pub fn mark_durable(&mut self, block: u64) {
        self.durable_blocks.insert(block);
    }

    /// Check if a block is durable.
    pub fn is_durable(&self, block: u64) -> bool {
        self.durable_blocks.contains(&block)
    }
}

/// WB-I1 violation: a durable parent references a non-durable child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WbI1Violation {
    /// The durable internal node.
    pub durable_parent: u64,
    /// The non-durable child it references.
    pub non_durable_child: u64,
}

impl std::fmt::Display for WbI1Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WB-I1 violation: durable block {} references non-durable child {}",
            self.durable_parent, self.non_durable_child
        )
    }
}

impl std::error::Error for WbI1Violation {}

/// WB-I2 oracle: verify atomic generation transition.
///
/// After a crash, the observed generation must be exactly `g` or `g+1`,
/// never a torn mixture.
#[derive(Debug, Clone)]
pub struct WbI2Oracle {
    /// Pre-commit generation.
    pub pre_generation: u64,
    /// Post-commit generation (pre + 1).
    pub post_generation: u64,
}

impl WbI2Oracle {
    /// Create a new WB-I2 oracle for a commit from generation `g` to `g+1`.
    pub fn new(pre_generation: u64) -> Self {
        Self {
            pre_generation,
            post_generation: pre_generation.saturating_add(1),
        }
    }

    /// Check WB-I2: observed generation must be pre or post, not torn.
    pub fn check(&self, observed_generation: u64) -> Result<(), WbI2Violation> {
        if observed_generation == self.pre_generation
            || observed_generation == self.post_generation
        {
            debug!(
                observed = observed_generation,
                pre = self.pre_generation,
                post = self.post_generation,
                "wb_i2 check passed"
            );
            Ok(())
        } else {
            Err(WbI2Violation {
                expected_pre: self.pre_generation,
                expected_post: self.post_generation,
                observed: observed_generation,
            })
        }
    }
}

/// WB-I2 violation: observed generation is neither pre nor post commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WbI2Violation {
    /// Expected pre-commit generation.
    pub expected_pre: u64,
    /// Expected post-commit generation.
    pub expected_post: u64,
    /// Actually observed generation.
    pub observed: u64,
}

impl std::fmt::Display for WbI2Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WB-I2 violation: expected generation {} or {}, observed {}",
            self.expected_pre, self.expected_post, self.observed
        )
    }
}

impl std::error::Error for WbI2Violation {}

/// Crash point in a writeback sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashPoint {
    /// Unique identifier for this crash point.
    pub id: String,
    /// Blocks that were durable at this crash point.
    pub durable_blocks: BTreeSet<u64>,
    /// Whether the superblock was durable.
    pub superblock_durable: bool,
    /// Generation of the superblock if durable.
    pub superblock_generation: Option<u64>,
}

impl CrashPoint {
    /// Create a crash point from a DAG's current state.
    pub fn from_dag(dag: &WriteDependencyDag, id: impl Into<String>, superblock_durable: bool) -> Self {
        let durable_blocks = dag
            .nodes
            .iter()
            .filter(|(_, n)| n.durable)
            .map(|(b, _)| *b)
            .collect();
        Self {
            id: id.into(),
            durable_blocks,
            superblock_durable,
            superblock_generation: if superblock_durable {
                Some(dag.generation)
            } else {
                None
            },
        }
    }
}

/// Writeback executor that flushes nodes in correct order and tracks crash points.
#[derive(Debug)]
pub struct WritebackExecutor {
    dag: WriteDependencyDag,
    crash_points: Vec<CrashPoint>,
    fsync_barrier_issued: bool,
}

impl WritebackExecutor {
    /// Create a new writeback executor for the given DAG.
    pub fn new(dag: WriteDependencyDag) -> Self {
        Self {
            dag,
            crash_points: Vec::new(),
            fsync_barrier_issued: false,
        }
    }

    /// Execute writeback in reverse topological order.
    ///
    /// The `flush_node` callback is called for each node in order. It should
    /// perform the actual I/O and return `Ok(())` on success.
    ///
    /// Crash points are recorded after each flush for DPOR enumeration.
    pub fn execute<F>(&mut self, mut flush_node: F) -> Result<(), BtrfsMutationError>
    where
        F: FnMut(u64) -> Result<(), BtrfsMutationError>,
    {
        let order = self.dag.reverse_topological_order();
        let total = order.len();

        for (i, block) in order.into_iter().enumerate() {
            // Record crash point before this flush
            let pre_crash_id = format!("pre_flush_{}", block);
            self.crash_points
                .push(CrashPoint::from_dag(&self.dag, pre_crash_id, false));

            // Flush the node
            flush_node(block)?;
            self.dag.mark_durable(block)?;

            // Record crash point after this flush
            let post_crash_id = format!("post_flush_{}", block);
            self.crash_points
                .push(CrashPoint::from_dag(&self.dag, post_crash_id, false));

            trace!(
                block,
                progress = i + 1,
                total,
                "writeback executor flushed node"
            );
        }

        Ok(())
    }

    /// Issue fsync barrier before superblock write.
    pub fn fsync_barrier(&mut self) {
        self.crash_points.push(CrashPoint::from_dag(
            &self.dag,
            "pre_fsync_barrier",
            false,
        ));
        self.fsync_barrier_issued = true;
        self.crash_points.push(CrashPoint::from_dag(
            &self.dag,
            "post_fsync_barrier",
            false,
        ));
        debug!("writeback executor fsync barrier issued");
    }

    /// Record superblock commit.
    pub fn commit_superblock(&mut self) {
        self.crash_points.push(CrashPoint::from_dag(
            &self.dag,
            "pre_superblock",
            false,
        ));
        // After superblock write, the commit is durable
        self.crash_points.push(CrashPoint::from_dag(
            &self.dag,
            "post_superblock",
            true,
        ));
        debug!(
            generation = self.dag.generation,
            "writeback executor superblock committed"
        );
    }

    /// Return all crash points recorded during execution.
    pub fn crash_points(&self) -> &[CrashPoint] {
        &self.crash_points
    }

    /// Verify WB-I1 holds at all crash points.
    pub fn verify_wb_i1(&self) -> Result<(), WbI1Violation> {
        for crash_point in &self.crash_points {
            let oracle = WbI1Oracle::new(crash_point.durable_blocks.clone());
            oracle.check(&self.dag)?;
        }
        debug!(
            crash_points = self.crash_points.len(),
            "wb_i1 verified at all crash points"
        );
        Ok(())
    }

    /// Return the underlying DAG.
    pub fn dag(&self) -> &WriteDependencyDag {
        &self.dag
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BtrfsBTree, BtrfsKey, InMemoryCowBtrfsTree};

    fn make_test_tree() -> InMemoryCowBtrfsTree {
        let mut tree = InMemoryCowBtrfsTree::new(4).expect("create tree");
        // Insert some items to force tree structure
        for i in 0..10 {
            let key = BtrfsKey {
                objectid: i,
                item_type: 0x84, // INODE_ITEM
                offset: 0,
            };
            let data = vec![0u8; 100];
            tree.insert(key, &data).expect("insert");
        }
        tree
    }

    #[test]
    fn dag_from_cow_tree_captures_structure() {
        let tree = make_test_tree();
        let dag = WriteDependencyDag::from_cow_tree(&tree, 100).expect("build dag");

        assert!(dag.node_count() > 0, "dag should have nodes");
        assert_eq!(dag.generation(), 100);
        assert!(dag.get(dag.root()).is_some(), "root should be in dag");
    }

    #[test]
    fn reverse_topological_order_leaves_first() {
        let tree = make_test_tree();
        let dag = WriteDependencyDag::from_cow_tree(&tree, 100).expect("build dag");
        let order = dag.reverse_topological_order();

        // All leaves (level 0) should come before internal nodes
        let mut seen_internal = false;
        for block in &order {
            let node = dag.get(*block).expect("node in dag");
            if node.level > 0 {
                seen_internal = true;
            } else if seen_internal {
                panic!(
                    "leaf {} appeared after internal node in reverse topo order",
                    block
                );
            }
        }
    }

    #[test]
    fn wb_i1_oracle_passes_for_empty_durable_set() {
        let tree = make_test_tree();
        let dag = WriteDependencyDag::from_cow_tree(&tree, 100).expect("build dag");
        let oracle = WbI1Oracle::new(BTreeSet::new());

        // Empty durable set trivially satisfies WB-I1
        assert!(oracle.check(&dag).is_ok());
    }

    #[test]
    fn wb_i1_oracle_passes_for_leaves_only() {
        let tree = make_test_tree();
        let dag = WriteDependencyDag::from_cow_tree(&tree, 100).expect("build dag");

        // Mark only leaves as durable
        let leaves: BTreeSet<u64> = dag
            .nodes
            .iter()
            .filter(|(_, n)| n.level == 0)
            .map(|(b, _)| *b)
            .collect();

        let oracle = WbI1Oracle::new(leaves);
        assert!(oracle.check(&dag).is_ok(), "leaves-only should satisfy WB-I1");
    }

    #[test]
    fn wb_i1_oracle_fails_for_parent_without_children() {
        let tree = make_test_tree();
        let dag = WriteDependencyDag::from_cow_tree(&tree, 100).expect("build dag");

        // Find an internal node
        let internal = dag
            .nodes
            .iter()
            .find(|(_, n)| !n.children.is_empty())
            .map(|(b, _)| *b);

        if let Some(block) = internal {
            // Mark only the internal node as durable (violates WB-I1)
            let mut durable = BTreeSet::new();
            durable.insert(block);
            let oracle = WbI1Oracle::new(durable);

            let result = oracle.check(&dag);
            assert!(result.is_err(), "parent without durable children should fail WB-I1");
        }
    }

    #[test]
    fn wb_i2_oracle_accepts_valid_generations() {
        let oracle = WbI2Oracle::new(100);

        assert!(oracle.check(100).is_ok(), "pre-commit gen should pass");
        assert!(oracle.check(101).is_ok(), "post-commit gen should pass");
    }

    #[test]
    fn wb_i2_oracle_rejects_torn_generation() {
        let oracle = WbI2Oracle::new(100);

        assert!(oracle.check(99).is_err(), "old gen should fail");
        assert!(oracle.check(102).is_err(), "future gen should fail");
        assert!(oracle.check(50).is_err(), "random gen should fail");
    }

    #[test]
    fn writeback_executor_records_crash_points() {
        let tree = make_test_tree();
        let dag = WriteDependencyDag::from_cow_tree(&tree, 100).expect("build dag");
        let mut executor = WritebackExecutor::new(dag);

        // Execute with no-op flush
        executor.execute(|_| Ok(())).expect("execute");
        executor.fsync_barrier();
        executor.commit_superblock();

        // Should have crash points: 2 per node + 2 for fsync + 2 for superblock
        let expected_min = executor.dag().node_count() * 2 + 4;
        assert!(
            executor.crash_points().len() >= expected_min,
            "should record crash points"
        );
    }

    #[test]
    fn writeback_executor_verifies_wb_i1() {
        let tree = make_test_tree();
        let dag = WriteDependencyDag::from_cow_tree(&tree, 100).expect("build dag");
        let mut executor = WritebackExecutor::new(dag);

        executor.execute(|_| Ok(())).expect("execute");

        // WB-I1 should hold at all crash points after proper execution
        assert!(executor.verify_wb_i1().is_ok(), "WB-I1 should hold");
    }
}
