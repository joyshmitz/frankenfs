#![forbid(unsafe_code)]

//! Same-process A/B for the `setxattr` Create/Replace existence check
//! (bd-dwiti).
//!
//! `ext4_setxattr` only needs to know whether an attribute is *present* to
//! honor `XATTR_CREATE`/`XATTR_REPLACE`. The old path called
//! `get_xattr_for_access`, which materialized *every* inline + external entry
//! (a name+value `Vec` allocation each) just to take `is_some()`. The new
//! `xattr_exists_for_access` routes through the by-name early-exit finders
//! (bd-abu3z) and allocates only for the one matched value — O(N) allocations
//! down to O(1).
//!
//! Benches the worst case for the old path: an **absent** name over a full
//! external block of N attributes, where the materialize-all scan allocates a
//! name+value `Vec` for every entry before concluding "not found", while the
//! early-exit finder walks the same entries allocating nothing. Both return the
//! same answer (asserted for present + absent names).

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ffs_ondisk::{Ext4Inode, Ext4Xattr};
use ffs_types::all_zero_bytes;
use ffs_xattr::{XattrReadAccess, XattrWriteAccess, get_xattr_for_access, xattr_exists_for_access};
use std::hint::black_box;

const N: usize = 96; // attributes packed into the external block
const BLOCK_SIZE: usize = 4096;

fn blank_inode(ibody_len: usize) -> Ext4Inode {
    Ext4Inode {
        mode: 0,
        uid: 0,
        gid: 0,
        size: 0,
        links_count: 0,
        blocks: 0,
        flags: 0,
        version: 0,
        generation: 0,
        file_acl: 0,
        atime: 0,
        ctime: 0,
        mtime: 0,
        dtime: 0,
        atime_extra: 0,
        ctime_extra: 0,
        mtime_extra: 0,
        crtime: 0,
        crtime_extra: 0,
        extra_isize: 32,
        checksum: 0,
        version_hi: 0,
        projid: 0,
        extent_bytes: vec![0; 60].into(),
        xattr_ibody: vec![0; ibody_len],
        number: 0,
    }
}

/// Build an inode (tiny ibody so attributes spill to the external block) plus a
/// 4 KiB external block packed with N `user.*` attributes.
fn build_populated() -> (Ext4Inode, Vec<u8>) {
    let mut inode = blank_inode(4);
    // file_acl non-zero so get_xattr_for_access treats the external block as the
    // authoritative store (matches the real ext4_setxattr inode state).
    inode.file_acl = 1;
    let mut block = vec![0_u8; BLOCK_SIZE];
    let access = XattrWriteAccess {
        is_owner: true,
        has_cap_fowner: true,
        has_cap_sys_admin: true,
    };
    for i in 0..N {
        let name = format!("user.attr{i:04}");
        ffs_xattr::set_xattr(&mut inode, Some(&mut block), &name, b"v", access)
            .expect("populate external xattr block");
    }
    (inode, block)
}

fn read_access() -> XattrReadAccess {
    XattrReadAccess {
        has_cap_sys_admin: true,
    }
}

fn scalar_all_zero(block: &[u8]) -> bool {
    block.iter().all(|byte| *byte == 0)
}

fn frozen_clone_inline_candidate(
    entries: &[Ext4Xattr],
    name_index: u8,
    name: &[u8],
    value: &[u8],
) -> Vec<Ext4Xattr> {
    let mut candidate = entries.to_vec();
    candidate.push(Ext4Xattr {
        name_index,
        name: name.to_vec(),
        value: value.to_vec(),
    });
    candidate
}

fn moved_inline_candidate(
    mut entries: Vec<Ext4Xattr>,
    name_index: u8,
    name: Vec<u8>,
    value: &[u8],
) -> Vec<Ext4Xattr> {
    entries.push(Ext4Xattr {
        name_index,
        name,
        value: value.to_vec(),
    });
    entries
}

fn clear_external_block_old(block: &mut [u8]) {
    let new_block = vec![0_u8; block.len()];
    block.copy_from_slice(&new_block);
}

fn clear_external_block_in_place(block: &mut [u8]) {
    block.fill(0);
}

fn allocate_external_value_replace(old: Vec<u8>, value: &[u8]) -> Vec<u8> {
    let replacement = value.to_vec();
    drop(old);
    replacement
}

fn reuse_external_value_replace(mut old: Vec<u8>, value: &[u8]) -> Vec<u8> {
    old.clear();
    old.extend_from_slice(value);
    old
}

fn bench_exists_probe(c: &mut Criterion) {
    let (inode, block) = build_populated();
    let access = read_access();

    // Isomorphism: the early-exit existence answer matches
    // get_xattr_for_access(..).is_some() for present and absent names.
    let present = format!("user.attr{:04}", N - 1); // last entry: full scan to hit
    let absent = "user.missing".to_owned();
    for name in [present.as_str(), absent.as_str(), "user.attr0000"] {
        let old = get_xattr_for_access(&inode, Some(&block), name, access)
            .expect("old probe")
            .is_some();
        let new = xattr_exists_for_access(&inode, Some(&block), name, access).expect("new probe");
        assert_eq!(old, new, "existence diverged for {name}");
    }

    let mut group = c.benchmark_group("xattr_exists_probe_absent_over_96ext");
    group.bench_function("materialize_all_is_some", |b| {
        b.iter(|| {
            black_box(
                get_xattr_for_access(
                    black_box(&inode),
                    Some(black_box(&block)),
                    black_box(absent.as_str()),
                    access,
                )
                .expect("old probe")
                .is_some(),
            )
        });
    });
    group.bench_function("early_exit_exists", |b| {
        b.iter(|| {
            black_box(
                xattr_exists_for_access(
                    black_box(&inode),
                    Some(black_box(&block)),
                    black_box(absent.as_str()),
                    access,
                )
                .expect("new probe"),
            )
        });
    });
    group.finish();
}

fn bench_zero_initialized_external_block(c: &mut Criterion) {
    let zero_block = vec![0_u8; BLOCK_SIZE];
    let mut late_nonzero = zero_block.clone();
    *late_nonzero.last_mut().expect("block is non-empty") = 1;

    assert_eq!(
        scalar_all_zero(&zero_block),
        all_zero_bytes(&zero_block),
        "zero block verdict diverged"
    );
    assert_eq!(
        scalar_all_zero(&late_nonzero),
        all_zero_bytes(&late_nonzero),
        "late-nonzero block verdict diverged"
    );

    let mut group = c.benchmark_group("xattr_zero_initialized_external_block");
    group.bench_function("scalar_zero_scan_4k", |b| {
        b.iter(|| black_box(scalar_all_zero(black_box(&zero_block))));
    });
    group.bench_function("chunked_all_zero_4k", |b| {
        b.iter(|| black_box(all_zero_bytes(black_box(&zero_block))));
    });
    group.bench_function("scalar_late_nonzero_4k", |b| {
        b.iter(|| black_box(scalar_all_zero(black_box(&late_nonzero))));
    });
    group.bench_function("chunked_late_nonzero_4k", |b| {
        b.iter(|| black_box(all_zero_bytes(black_box(&late_nonzero))));
    });
    group.finish();
}

fn bench_new_inline_candidate(c: &mut Criterion) {
    let entries = (0..2)
        .map(|i| Ext4Xattr {
            name_index: 1,
            name: format!("attr{i:02}").into_bytes(),
            value: vec![u8::try_from(i).expect("small fixture index"); 24],
        })
        .collect::<Vec<_>>();
    let name = b"fresh_attribute".to_vec();
    let value = vec![0x5a; 32];

    let old = frozen_clone_inline_candidate(&entries, 1, &name, &value);
    let new = moved_inline_candidate(entries.clone(), 1, name.clone(), &value);
    assert_eq!(old, new, "inline candidate bytes diverged");

    let mut group = c.benchmark_group("xattr_new_inline_candidate_2");
    for control in ["deep_clone_a", "deep_clone_b"] {
        group.bench_function(control, |b| {
            b.iter_batched(
                || (entries.clone(), name.clone()),
                |(parsed, parsed_name)| {
                    black_box(frozen_clone_inline_candidate(
                        black_box(&parsed),
                        1,
                        black_box(&parsed_name),
                        black_box(&value),
                    ))
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.bench_function("move_owned_candidate", |b| {
        b.iter_batched(
            || (entries.clone(), name.clone()),
            |(parsed, parsed_name)| {
                black_box(moved_inline_candidate(
                    black_box(parsed),
                    1,
                    black_box(parsed_name),
                    black_box(&value),
                ))
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_external_empty_clear(c: &mut Criterion) {
    let populated = vec![0xa5_u8; BLOCK_SIZE];
    let mut old = populated.clone();
    let mut new = populated.clone();
    clear_external_block_old(&mut old);
    clear_external_block_in_place(&mut new);
    assert_eq!(old, new, "external block clear bytes diverged");

    let mut group = c.benchmark_group("xattr_external_empty_clear_4k");
    for control in ["allocate_zero_copy_a", "allocate_zero_copy_b"] {
        group.bench_function(control, |b| {
            b.iter_batched(
                || populated.clone(),
                |mut block| {
                    clear_external_block_old(black_box(&mut block));
                    black_box(block)
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.bench_function("fill_owned_block", |b| {
        b.iter_batched(
            || populated.clone(),
            |mut block| {
                clear_external_block_in_place(black_box(&mut block));
                black_box(block)
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_external_value_replace(c: &mut Criterion) {
    const VALUE_SIZE: usize = 1024;

    for (old_len, new_len) in [
        (0, 0),
        (VALUE_SIZE, 0),
        (VALUE_SIZE, VALUE_SIZE),
        (32, 2048),
    ] {
        let old = vec![0x3c; old_len];
        let value = vec![0xa5; new_len];
        assert_eq!(
            allocate_external_value_replace(old.clone(), &value),
            reuse_external_value_replace(old, &value),
            "external value replacement diverged for {old_len} -> {new_len} bytes"
        );
    }

    let value = vec![0xa5; VALUE_SIZE];
    let mut group = c.benchmark_group("xattr_external_value_replace_1k");
    for control in ["allocate_replacement_a", "allocate_replacement_b"] {
        group.bench_function(control, |b| {
            b.iter_batched(
                || vec![0x3c; VALUE_SIZE],
                |old| {
                    black_box(allocate_external_value_replace(
                        black_box(old),
                        black_box(&value),
                    ))
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.bench_function("reuse_parsed_value", |b| {
        b.iter_batched(
            || vec![0x3c; VALUE_SIZE],
            |old| {
                black_box(reuse_external_value_replace(
                    black_box(old),
                    black_box(&value),
                ))
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_exists_probe,
    bench_zero_initialized_external_block,
    bench_new_inline_candidate,
    bench_external_empty_clear,
    bench_external_value_replace
);
criterion_main!(benches);
