#![forbid(unsafe_code)]

//! A/B benchmark for btrfs writeback DAG scheduling and construction
//! (`bd-f759f`, `bd-xmh5g.400`).
//!
//! `WriteDependencyDag::reverse_topological_order` runs before every metadata
//! writeback and during crash-consistency enumeration. The flush order is
//! determined by child-vector postorder plus the DAG's `BTreeMap` key order for
//! disconnected components; the visited set only answers membership. This
//! compares the old `BTreeSet` membership model against the production
//! HashSet-backed scheduler while asserting exact order and WB-I1 prefix
//! equivalence. The construction group compares the old child-vector
//! double-clone model against the moved-child production shape.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_btrfs::writeback::{WbI1Oracle, WriteDependencyDag};
use ffs_btrfs::{BtrfsBTree, BtrfsCowNode, BtrfsKey, BtrfsMutationError, InMemoryCowBtrfsTree};
use std::collections::{BTreeMap, BTreeSet};
use std::hint::black_box;

const ITEMS: u64 = 2048;
const MAX_ITEMS: usize = 8;
const GENERATION: u64 = 123;

#[derive(Debug, Clone, PartialEq, Eq)]
struct BenchDagNode {
    level: u8,
    children: Vec<u64>,
}

type BenchDag = BTreeMap<u64, BenchDagNode>;

fn build_tree() -> InMemoryCowBtrfsTree {
    let mut tree = InMemoryCowBtrfsTree::new(MAX_ITEMS).expect("create tree");
    for i in 0..ITEMS {
        let key = BtrfsKey {
            objectid: i,
            item_type: 0x84,
            offset: i * 4096,
        };
        tree.insert(key, &i.to_le_bytes()).expect("insert");
    }
    tree
}

fn build_dag() -> WriteDependencyDag {
    let tree = build_tree();
    WriteDependencyDag::from_cow_tree(&tree, GENERATION).expect("build dag")
}

fn collect_double_clone_model(
    tree: &InMemoryCowBtrfsTree,
    block: u64,
    nodes: &mut BenchDag,
    level: u8,
) -> Result<(), BtrfsMutationError> {
    if nodes.contains_key(&block) {
        return Ok(());
    }

    let node = tree.node_snapshot(block)?;
    let (node_level, children) = match &node {
        BtrfsCowNode::Leaf { .. } => (0, Vec::new()),
        BtrfsCowNode::Internal { children, .. } => (level, children.clone()),
    };

    nodes.insert(
        block,
        BenchDagNode {
            level: node_level,
            children: children.clone(),
        },
    );

    let child_level = level.saturating_sub(1);
    for child in children {
        collect_double_clone_model(tree, child, nodes, child_level)?;
    }

    Ok(())
}

fn collect_single_clone_model(
    tree: &InMemoryCowBtrfsTree,
    block: u64,
    nodes: &mut BenchDag,
    level: u8,
) -> Result<(), BtrfsMutationError> {
    if nodes.contains_key(&block) {
        return Ok(());
    }

    let node = tree.node_snapshot(block)?;
    let (node_level, children) = match node {
        BtrfsCowNode::Leaf { .. } => (0, Vec::new()),
        BtrfsCowNode::Internal { children, .. } => (level, children),
    };
    let recursion_children = children.clone();

    nodes.insert(
        block,
        BenchDagNode {
            level: node_level,
            children,
        },
    );

    let child_level = level.saturating_sub(1);
    for child in recursion_children {
        collect_single_clone_model(tree, child, nodes, child_level)?;
    }

    Ok(())
}

fn double_clone_model(tree: &InMemoryCowBtrfsTree) -> BenchDag {
    let mut nodes = BTreeMap::new();
    collect_double_clone_model(tree, tree.root_block(), &mut nodes, tree.root_level())
        .expect("old double-clone model");
    nodes
}

fn single_clone_model(tree: &InMemoryCowBtrfsTree) -> BenchDag {
    let mut nodes = BTreeMap::new();
    collect_single_clone_model(tree, tree.root_block(), &mut nodes, tree.root_level())
        .expect("single-clone model");
    nodes
}

fn dag_shape_digest(dag: &BenchDag) -> u64 {
    dag.iter()
        .fold(0xcbf2_9ce4_8422_2325_u64, |acc, (block, node)| {
            let mut digest = acc
                .wrapping_mul(0x100_0000_01b3)
                .wrapping_add(*block)
                .wrapping_add(u64::from(node.level));
            for child in &node.children {
                digest = digest.wrapping_mul(0x100_0000_01b3).wrapping_add(*child);
            }
            digest
        })
}

fn assert_build_isomorphic(tree: &InMemoryCowBtrfsTree) {
    let old = double_clone_model(tree);
    let new = single_clone_model(tree);
    assert_eq!(old, new, "single-clone model changed DAG shape");

    let production = WriteDependencyDag::from_cow_tree(tree, GENERATION).expect("production dag");
    assert_eq!(
        production.node_count(),
        old.len(),
        "production node count changed"
    );
    for (block, old_node) in &old {
        let production_node = production.get(*block).expect("production node");
        assert_eq!(production_node.level, old_node.level, "node level changed");
        assert_eq!(
            production_node.children, old_node.children,
            "node children changed"
        );
    }
}

fn btree_push_postorder(
    dag: &WriteDependencyDag,
    block: u64,
    visited: &mut BTreeSet<u64>,
    result: &mut Vec<u64>,
) {
    if !visited.insert(block) {
        return;
    }

    let Some(node) = dag.get(block) else {
        return;
    };

    for child in &node.children {
        btree_push_postorder(dag, *child, visited, result);
    }

    result.push(block);
}

fn btree_visited_order(dag: &WriteDependencyDag) -> Vec<u64> {
    let mut result = Vec::with_capacity(dag.node_count());
    let mut visited = BTreeSet::new();
    btree_push_postorder(dag, dag.root(), &mut visited, &mut result);
    for block in dag.blocks() {
        btree_push_postorder(dag, block, &mut visited, &mut result);
    }
    result
}

fn order_digest(order: &[u64]) -> u64 {
    order.iter().fold(0xcbf2_9ce4_8422_2325_u64, |acc, block| {
        acc.wrapping_mul(0x100_0000_01b3).wrapping_add(*block)
    })
}

fn assert_isomorphic(dag: &WriteDependencyDag) {
    let old = btree_visited_order(dag);
    let new = dag.reverse_topological_order();
    assert_eq!(
        old, new,
        "HashSet membership changed deterministic DAG flush order"
    );

    for end in 0..=new.len() {
        let durable = new[..end].iter().copied().collect();
        WbI1Oracle::new(durable)
            .check(dag)
            .expect("every flush-order prefix must satisfy WB-I1");
    }
}

fn bench_writeback_dag_order(c: &mut Criterion) {
    let dag = build_dag();
    assert_isomorphic(&dag);

    let mut group = c.benchmark_group("writeback_dag_order_hashset_ab");
    group.bench_function("old_btreeset_visited", |b| {
        b.iter(|| {
            let order = btree_visited_order(black_box(&dag));
            black_box(order_digest(&order))
        });
    });
    group.bench_function("production_hashset_visited", |b| {
        b.iter(|| {
            let order = black_box(&dag).reverse_topological_order();
            black_box(order_digest(&order))
        });
    });
    group.finish();
}

fn bench_writeback_dag_build(c: &mut Criterion) {
    let tree = build_tree();
    assert_build_isomorphic(&tree);

    let mut group = c.benchmark_group("writeback_dag_build_child_vector_ab");
    group.bench_function("old_double_clone_model", |b| {
        b.iter(|| {
            let dag = double_clone_model(black_box(&tree));
            black_box(dag_shape_digest(&dag))
        });
    });
    group.bench_function("single_clone_model", |b| {
        b.iter(|| {
            let dag = single_clone_model(black_box(&tree));
            black_box(dag_shape_digest(&dag))
        });
    });
    group.bench_function("production_from_cow_tree", |b| {
        b.iter(|| {
            let dag = WriteDependencyDag::from_cow_tree(black_box(&tree), GENERATION)
                .expect("build production dag");
            black_box(dag.node_count())
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_writeback_dag_order,
    bench_writeback_dag_build
);
criterion_main!(benches);
