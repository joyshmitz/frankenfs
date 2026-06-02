# bd-a80jk - ffs-btrfs inode-ref fixed-header decode attempt

Date: 2026-06-02
Agent: PlumFern

## Profile target

Profile source: `tests/artifacts/perf/2026-06-02_plumfern_btrfs_xattr.md`
ranked the broad btrfs item-parser Criterion pass. After the closed
`bd-b0u6s` xattr parser pass, the next parser target was
`btrfs_parse_inode_refs`.

Fresh baseline command:

```bash
RCH_FORCE_REMOTE=true timeout 1600 rch exec -- cargo bench --profile release-perf -p ffs-harness --bench ondisk_parse -- btrfs_parse_inode_refs --noplot
```

Baseline worker: `vmi1153651`.

| Benchmark | Before mean | Before interval |
|---|---:|---:|
| `btrfs_parse_inode_refs` | 47.389 ns | [46.032 ns, 48.951 ns] |

## Lever Attempted

After `parse_inode_refs` proves `cur + 10 <= data.len()`, the `index`
and `name_len` fields are already in bounds at fixed offsets `cur..cur+8`
and `cur+8..cur+10`. The candidate replaced the generic checked
`read_u64` and `read_u16` helper calls with direct little-endian fixed-offset
loads.

No code was kept.

## Benchmark Result

After command:

```bash
RCH_FORCE_REMOTE=true TMPDIR=/data/tmp timeout 1600 rch exec -- cargo bench --profile release-perf -p ffs-harness --bench ondisk_parse -- btrfs_parse_inode_refs --noplot
```

After worker: `vmi1153651`.

| Benchmark | Before mean | After mean | Delta |
|---|---:|---:|---:|
| `btrfs_parse_inode_refs` | 47.389 ns | 46.571 ns | -1.73% |

After interval: [45.225 ns, 48.394 ns].

The confidence intervals overlap heavily, so the result is not a reliable
win. Score: `Impact 1 x Confidence 1 / Effort 1 = 1.0`. Reject.

## Behavior Proof

Focused remote proof:

```bash
RCH_FORCE_REMOTE=true TMPDIR=/data/tmp timeout 1000 rch exec -- cargo test -p ffs-btrfs --lib inode_ref -- --nocapture
```

Remote worker: `vmi1149989`. Result: 9 passed, 0 failed.

Golden-output sha256 manifests:

```bash
(cd conformance/golden && sha256sum -c checksums.sha256)
(cd tests/fixtures/golden && sha256sum -c checksums.txt)
```

Both checksum manifests passed.

Formatting:

```bash
cargo fmt -p ffs-btrfs --check
```

Passed.

## Isomorphism Proof

- Ordering preserved: yes. Candidate did not change loop cursor update or
  `out.push` order.
- Tie-breaking unchanged: N/A. The parser has no comparisons or tie resolution.
- Floating-point identical: N/A. The parser has no floating-point operations.
- RNG seeds unchanged: unchanged. The parser has no RNG and the proptest-backed
  focused proof remained green.
- Error behavior unchanged: yes for the attempted lever. The existing
  `cur + 10 > data.len()` guard still emitted the insufficient-header error
  before the fixed fields were read, and the zero-name/truncation tests passed.
- Final tree: no parser code changes kept.
