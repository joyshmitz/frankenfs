# bd-xmh5g.8 - ByteBlockDevice contiguous-read buffer reuse

## Target

`ffs_block::ByteBlockDevice::read_contiguous_blocks` rebuilt each output
`BlockBuf` with `BlockBuf::zeroed(block_size)` before calling
`ByteDevice::read_vectored_exact_at`. For successful exact reads those bytes are
immediately overwritten; on error the method returns `Err` and callers must not
consume the partially-filled buffers.

This is the `ffs-cli fsck -f` scrub path: `build_fsck_output` constructs
`ffs_block::ByteBlockDevice`, so this is the actual exact-read adapter used by
the CLI scrub loop.

## Baseline and re-benchmark

Command:

```text
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary timeout 900 rch exec -- cargo bench --profile release-perf -p ffs-repair --bench scrub_codec -- scrub_buffer_prep --warm-up-time 1 --measurement-time 2 --sample-size 20 --noplot
```

Worker: `vmi1153651`

Same-binary A/B rows:

```text
scrub_buffer_prep/old_zero_per_batch  [711.67 us 756.73 us 805.68 us]
scrub_buffer_prep/new_reuse_pool       [46.658 us 47.766 us 48.783 us]
```

Delta: `756.73 / 47.766 = 15.84x` faster for the isolated buffer-prep work.

Integrated after sanity row:

```text
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary timeout 700 rch exec -- cargo bench --profile release-perf -p ffs-repair --bench scrub_codec -- scrub_clean_256blocks --warm-up-time 1 --measurement-time 2 --sample-size 20 --noplot

scrub_clean_256blocks [141.58 us 146.41 us 152.08 us]
```

## Alien primitive

Candidate: cache-local buffer reuse / redundant memset elimination before exact
overwrite.

Recommendation score: `Impact 4 * Confidence 4 / Effort 1 = 16.0`.

Fallback: allocate+zero every output buffer before the exact read. Revert the
single guard in `ByteBlockDevice::read_contiguous_blocks` if a byte-for-byte
overwrite proof fails.

## Isomorphism proof

- Ordering preserved: yes. `read_contiguous_blocks` still builds `IoSliceMut`
  in caller buffer order and reads from the same contiguous byte offset.
- Tie-breaking unchanged: N/A.
- Floating-point: N/A.
- RNG seeds: N/A.
- Error classes unchanged: yes. Range validation is unchanged. Exact read errors
  still return the same `Err`; callers do not consume buffers after `Err`.
- Byte output unchanged: yes. On success, `read_vectored_exact_at` fills every
  slice byte. Focused test starts from dirty `0xAA`/`0xBB` buffers and verifies
  the requested block bytes replace them.
- Golden output sha256: `sha256sum -c -` passed for:
  - `266a75f96df99a397f78bff54632acc9b5b025577392366d2cd90ee3f5ad4b42  crates/ffs-repair/src/snapshots/ffs_repair__scrub__tests__scrub_report_human_output.snap`
  - `de759acfd4c676daa8694e23ad7c0e95cc2180969da2ea6aaab6b0ae44093d9c  conformance/golden/checksums.sha256`

## Validation

```text
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary timeout 500 rch exec -- cargo test -p ffs-block byte_block_device_reuses_sized_contiguous_buffers -- --nocapture
# vmi1227854: 1 passed

RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary timeout 500 rch exec -- cargo check -p ffs-block --all-targets
# vmi1153651: passed

RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary timeout 500 rch exec -- cargo clippy -p ffs-block --all-targets -- -D warnings
# vmi1153651: passed

cargo fmt --package ffs-block --check
git diff --check -- .beads/issues.jsonl crates/ffs-block/src/lib.rs
br dep cycles --json
```

## Verdict

Keep. Score is above the `>=2.0` threshold and behavior is byte-for-byte
preserved for successful exact reads.
