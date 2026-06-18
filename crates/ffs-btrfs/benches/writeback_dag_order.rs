#![forbid(unsafe_code)]

//! A/B benchmark for btrfs writeback DAG scheduling (bd-f759f).
//!
//! `WriteDependencyDag::reverse_topological_order` runs before every metadata
//! writeback and during crash-consistency enumeration. The flush order is
//! determined by child-vector postorder plus the DAG's `BTreeMap` key order for
//! disconnected components; the visited set only answers membership. This
//! compares the old `BTreeSet` membership model against the production
//! HashSet-backed scheduler while asserting exact order and WB-I1 prefix
//! equivalence.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_btrfs::writeback::{WbI1Oracle, WriteDependencyDag};
use ffs_btrfs::{BtrfsBTree, BtrfsKey, InMemoryCowBtrfsTree};
use std::collections::BTreeSet;
use std::hint::black_box;

const ITEMS: u64 = 2048;
const MAX_ITEMS: usize = 8;
const GENERATION: u64 = 123;

fn build_dag() -> WriteDependencyDag {
    let mut tree = InMemoryCowBtrfsTree::new(MAX_ITEMS).expect("create tree");
    for i in 0..ITEMS {
        let key = BtrfsKey {
            objectid: i,
            item_type: 0x84,
            offset: i * 4096,
        };
        tree.insert(key, &i.to_le_bytes()).expect("insert");
    }
    WriteDependencyDag::from_cow_tree(&tree, GENERATION).expect("build dag")
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

criterion_group!(benches, bench_writeback_dag_order);
criterion_main!(benches);
