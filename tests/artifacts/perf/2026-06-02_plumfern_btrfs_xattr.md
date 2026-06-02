# bd-b0u6s - ffs-btrfs xattr item parser optimization

Date: 2026-06-02
Agent: PlumFern

## Profile target

Command:

```bash
RCH_FORCE_REMOTE=true rch exec -- cargo bench --profile release-perf -p ffs-harness --bench ondisk_parse -- btrfs --noplot
```

The broad Btrfs criterion pass selected `ffs_btrfs::parse_xattr_items` as the
highest `ffs-btrfs` item-parser target not already covered by the prior
`ffs-ondisk` parser campaign.

| Rank | Benchmark | Mean |
|---:|---|---:|
| 1 | `btrfs_parse_xattr_items` | 31.902 ns |
| 2 | `btrfs_parse_inode_refs` | 25.263 ns |
| 3 | `btrfs_parse_dir_items` | 24.333 ns |
| 4 | `btrfs_inode_item_to_bytes` | 22.565 ns |

## Lever

After `parse_xattr_items` proves `cur + HEADER <= data.len()`, the
`data_len` and `name_len` fields at fixed offsets `+25` and `+27` are
already in bounds. The change replaces two generic checked `read_u16` helper
calls with direct `u16::from_le_bytes` loads for those two fields only.

## Benchmark result

After command:

```bash
RCH_FORCE_REMOTE=true timeout 1600 rch exec -- cargo bench --profile release-perf -p ffs-harness --bench ondisk_parse -- btrfs --noplot
```

| Benchmark | Before mean | After mean | Delta |
|---|---:|---:|---:|
| `btrfs_parse_xattr_items` | 31.902 ns | 29.658 ns | -7.03% |

Score: `Impact 3 x Confidence 3 / Effort 1 = 9.0`, keep.

## Behavior proof

Commands:

```bash
RCH_FORCE_REMOTE=true timeout 1000 rch exec -- bash -lc 'set -euo pipefail; cargo test -p ffs-btrfs --lib xattr_items -- --nocapture 2>&1 | sed -E "s/finished in [0-9.]+s/finished in <elapsed>/g" | tee /tmp/ffs_btrfs_xattr_items_tests_normalized.txt; printf "normalized_sha256  "; sha256sum /tmp/ffs_btrfs_xattr_items_tests_normalized.txt'
RCH_FORCE_REMOTE=true timeout 1000 rch exec -- cargo check -p ffs-btrfs --all-targets
RCH_FORCE_REMOTE=true timeout 1200 rch exec -- cargo clippy -p ffs-btrfs --all-targets -- -D warnings
RCH_FORCE_REMOTE=true timeout 600 rch exec -- cargo fmt -p ffs-btrfs --check
```

Golden-output sha256:

```text
beef9fce4217e1477fc8ef7346405b55b646ca357820489d46a7dc6cc6ae33fa  /tmp/ffs_btrfs_xattr_items_tests_normalized.txt
```

The `xattr_items` test filter ran:

- `parse_xattr_items_kernel_offsets_match_btrfs_tree_h`
- `proptest_xattr_items_truncation_rejection`
- `proptest_xattr_items_determinism`
- `proptest_xattr_items_payload_round_trip`

## Isomorphism proof

- Ordering preserved: yes. The loop cursor update and `out.push` order are unchanged.
- Tie-breaking unchanged: N/A. The parser has no comparisons or tie resolution.
- Floating-point identical: N/A. The parser has no floating-point operations.
- RNG seeds unchanged: unchanged. The code change has no RNG; proptest behavior proof remained green.
- Error behavior unchanged: yes for this lever. The existing `cur + HEADER > data.len()` guard still emits the only possible insufficient-header error before these fields are read. After that guard, both two-byte fields are necessarily in bounds, so removing the helper cannot remove a reachable error.
- Allocation behavior unchanged: yes. Name and value slices are still copied into `Vec<u8>` exactly once per item.
