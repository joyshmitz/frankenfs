# bd-p7555 — portable-SIMD GF(256) global-parity multiply: REJECTED (0.51×, regression)

**Date:** 2026-06-02 · **Crate:** `ffs-repair` · **Outcome:** SIMD lever reverted; golden test retained.

## Target

`encode_global` (LRC global parity) is the rank-1 ffs-repair Criterion hotspot
(`lrc_encode_global_64blocks_8parity` ≈ 532 µs, PlumFern 2026-06-02) — a GF(256) dense
matrix-vector multiply. The directive calls for an in-house safe-Rust SIMD kernel.

## Lever attempted

Replace the scalar inner loop of `gf256_mul_xor_into` (one 256-entry static-table lookup
per byte: `dst[i] ^= MUL[coeff][src[i]]`) with a portable-SIMD nibble-split multiply:
build per-coefficient low/high 16-entry tables and use `u8x16::swizzle_dyn`
(PSHUFB/TBL-style, safe Rust) to process 16 bytes per op. Behind
`#![feature(portable_simd)]` (nightly, already required).

## Isomorphism — held

The nibble-split is exact: `x == (x & 0xF0) ^ (x & 0x0F)` (disjoint bits) and GF mult
distributes over XOR, so `gf_mul(c,x) == gf_mul(c, x&0x0F) ^ gf_mul(c, x&0xF0)`. Verified:
the A/B harness asserted `scalar_encode_global == encode_global` (SIMD) byte-for-byte; all
45 lrc + 8 gf256 lib tests passed including PlumFern's `lrc_global_parity_golden_report`.
Golden output sha256 `d12208add085574d1db8a0fca6546aeec6028161ee6ff67b0edb87630f46afd0`
(`lrc_global_parity_golden.txt`).

## Performance — REGRESSION

Same-binary A/B (`scrub_codec` `lrc_gf_kernel`, 64 data × 8 parity × 4096 B):

| Arm | Path | Median |
|-----|------|--------|
| `old_scalar_gf` | per-byte log/exp replica | **1.581 ms** |
| `new_simd_gf` | encode_global → SIMD nibble-split | **3.097 ms** |

**Score ≈ 1.581 / 3.097 ≈ 0.51× — 2× SLOWER.** And the bench's scalar arm is *slower* than
the production scalar path (it uses a branchy `log/exp` multiply, not the production's
single `MUL[coeff][s]` static-table load), so the real incumbent beats the SIMD by even more.

## Why the incumbent already wins

The production scalar `gf256_mul_xor_into` indexes a **64 KiB static `MUL` table** that is
L1-resident across the 8 distinct parity coefficients — one load per byte, no per-call
setup. The SIMD attempt pays a per-call cost (rebuild low/high tables for each of the
8×64 = 512 `(i,j)` pairs) and `swizzle_dyn` does not outrun an L1 table load on this
workload/target. The classic PSHUFB GF win assumes a *gather-free* scalar baseline; here
the baseline is already a fast cached lookup.

## Decision

Per `/extreme-software-optimization` ("Score ≥ 2.0 … otherwise revert"), the SIMD lever +
`#![feature(portable_simd)]` were **reverted**. PlumFern's `lrc_global_parity_golden_report`
test is **retained** as durable encode_global regression coverage. `encode_global` is at
its safe-Rust optimum for the table-lookup approach; a cache-friendly loop reorder
(data-outer/parity-inner register blocking) remains the only untried angle but is expected
to be latency-bound (<2×). `#![forbid(unsafe_code)]` intact; clippy/fmt clean.
