# bd-xmh5g.3 - ffs-alloc succinct select0 broadword block scan

Agent: PlumFern
Date: 2026-06-02
Crate: ffs-alloc
Lever: replace only the final in-block `select0` bit scan with safe broadword zero-mask selection over 64-bit words.

## Profile-Backed Target

Baseline command:

```bash
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary timeout 700 rch exec -- \
  cargo bench --profile release-perf -p ffs-alloc --bench bitmap_ops -- \
  succinct_select0 --warm-up-time 1 --measurement-time 2 --sample-size 20 --noplot
```

Baseline worker: `vmi1227854`

Baseline result:

```text
succinct_select0
  time: [182.14 ns 197.58 ns 218.21 ns]
  outliers: 2 high mild
```

Profile interpretation: the succinct index already narrows the search to a
superblock and a 256-bit local block. The remaining hot step scans that final
block bit by bit with `get_bit`.

## Alien Recommendation Card

Source: `/data/projects/alien_cs_graveyard/alien_cs_graveyard.md` section 7.1,
succinct rank/select bitvectors and broadword select. The relevant primitive is
word-at-a-time rank/select over compact bitvectors using popcount and bit
selection rather than pointer-heavy or per-bit scans.

Candidate: within the located 256-bit block, form `zero_mask = !word`, mask the
tail word by bitmap length, skip whole words by `count_ones`, and select the
k-th zero with `trailing_zeros` plus `word &= word - 1`.

EV score: 12.0 = Impact 4 x Confidence 3 / Effort 1.

Fallback: keep the old per-bit scan if any ordering, tail masking, `None`
behavior, proptest, golden-output hash, or rch benchmark proof fails.

## After Benchmark

After command:

```bash
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary timeout 700 rch exec -- \
  cargo bench --profile release-perf -p ffs-alloc --bench bitmap_ops -- \
  succinct_select0 --warm-up-time 1 --measurement-time 2 --sample-size 20 --noplot
```

After worker: `vmi1149989`

After result:

```text
succinct_select0
  time: [26.083 ns 26.965 ns 27.978 ns]
  outliers: 1 high severe
```

Delta by Criterion mean: 197.58 ns -> 26.965 ns = -86.35%.

## Same-Binary Lever A/B

Command:

```bash
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary timeout 700 rch exec -- \
  cargo bench --profile release-perf -p ffs-alloc --bench bitmap_ops -- \
  select0_in_block --warm-up-time 1 --measurement-time 2 --sample-size 20 --noplot
```

Worker: `vmi1149989`

Result:

```text
select0_in_block/old_bit_scan
  time: [26.467 ns 27.592 ns 29.173 ns]
select0_in_block/new_broadword
  time: [9.9555 ns 10.331 ns 10.630 ns]
```

Same-binary delta by mean: 27.592 ns -> 10.331 ns = -62.56%.

## Isomorphism Proof

Ordering preserved: yes. The old scan visits positions in increasing bit order.
The new scan visits words in increasing word-base order, then uses
`trailing_zeros` and repeated `word &= word - 1` to select set bits in increasing
bit order inside the zero mask.

Tie-breaking unchanged: yes. `select0(k)` has a unique k-th zero bit. Whole-word
skips occur only when `remaining >= zeros_in_word`, exactly matching the old
loop's decrement count for that word.

Tail masking unchanged: yes. The new helper computes
`block_end = min(block_start + BLOCK_BITS, self.len)` and masks the final partial
word with `(1 << bits_in_word) - 1`, so zero bits past `len` are unobservable.

`None` behavior unchanged: yes. Existing `k >= count_zeros()` rejection remains
before block search. Inside the block helper, failure to find enough zero bits
returns `None`, matching the old exhausted loop.

Floating-point: N/A.

RNG seeds: N/A.

Golden output hash: `426fa627e301f712e5f0fc4577a1e7a944321e93e2cdf6bb994483e298cd8fb3`.
Verified for the tab-delimited rows emitted by `select0_golden_report`.

Golden rows:

```text
SUCCINCT_SELECT0_GOLDEN	0	0
SUCCINCT_SELECT0_GOLDEN	1	3
SUCCINCT_SELECT0_GOLDEN	2	8
SUCCINCT_SELECT0_GOLDEN	3	63
SUCCINCT_SELECT0_GOLDEN	4	64
SUCCINCT_SELECT0_GOLDEN	5	65
SUCCINCT_SELECT0_GOLDEN	6	127
SUCCINCT_SELECT0_GOLDEN	7	128
SUCCINCT_SELECT0_GOLDEN	8	190
SUCCINCT_SELECT0_GOLDEN	9	191
SUCCINCT_SELECT0_GOLDEN	10	192
SUCCINCT_SELECT0_GOLDEN	11	250
SUCCINCT_SELECT0_GOLDEN	12	255
SUCCINCT_SELECT0_GOLDEN	13	256
SUCCINCT_SELECT0_GOLDEN	14	257
SUCCINCT_SELECT0_GOLDEN	15	258
SUCCINCT_SELECT0_GOLDEN	16	300
SUCCINCT_SELECT0_GOLDEN	17	301
SUCCINCT_SELECT0_GOLDEN	18	302
SUCCINCT_SELECT0_GOLDEN	19	303
SUCCINCT_SELECT0_GOLDEN	20	304
SUCCINCT_SELECT0_GOLDEN	21	None
```

## Behavior Gates

```bash
RCH_FORCE_REMOTE=true timeout 700 rch exec -- \
  cargo test -p ffs-alloc select0 -- --nocapture
```

Passed on `vmi1227854`: 3 tests, 0 failed.

```bash
RCH_FORCE_REMOTE=true timeout 700 rch exec -- \
  cargo test -p ffs-alloc proptest_succinct_find_free_matches_linear -- --nocapture
```

Passed on `vmi1149989`: 1 test, 0 failed.

```bash
RCH_FORCE_REMOTE=true timeout 900 rch exec -- \
  cargo check -p ffs-alloc --all-targets
```

Passed on `vmi1149989`.

```bash
RCH_FORCE_REMOTE=true timeout 900 rch exec -- \
  cargo clippy -p ffs-alloc --all-targets -- -D warnings
```

Passed on `vmi1149989`.

```bash
cargo fmt --package ffs-alloc --check
```

Passed locally; `rch exec cargo fmt` only prints the formatter warning and does
not execute `rustfmt`.
