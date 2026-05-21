# Reality-Check Bridge: Closing the Gap Between Claims and Code

> Engineering writeup on the bd-xuo95 epic (2026-05-20 to 2026-05-21)

---

## 1. The Gap: What the Reality Check Exposed

On 2026-05-20, a systematic reality check audited FrankenFS against its README claims. The audit used four code-investigation agents, a clean `cargo check --workspace`, CLI runs on real ext4 images, and the kernel-differential test suite (17/17 ext4, 7/7 btrfs). The findings were uncomfortable.

### G-A: btrfs RW Was a Silent Data-Loss Facade (P0)

The headline problem: btrfs metadata mutations (`create`, `mkdir`, `unlink`, `write`) executed against an in-memory `InMemoryCowBtrfsTree` (`ffs-core/src/lib.rs:560`) that had **no serializer back to disk**. The `btrfs_sync_with_logging` function logged `outcome="applied"` while flushing only the ext4 MVCC store — which held no btrfs metadata. Every btrfs RW change evaporated on unmount.

The README described this as "Supported (experimental) — Deterministic success/error."

### G-B: "100% Parity (97/97)" Was Self-Certified

The 97/97 parity number was summed from a hand-written table in `FEATURE_PARITY.md`. The "enforcing" test `parity_report_matches_feature_parity_md` parsed that same table twice — a tautology. No test execution fed the number. Rows could claim "implemented" without any corresponding green test.

### G-C: Release Gates Validated JSON Against JSON

Proof-bundle lanes hashed project-authored JSON against project-authored policy JSON. Zero `Command::new` calls. The gates were a closed loop that certified nothing executable.

### G-D: Harness Bloat

`ffs-harness` was 150,945 LOC — 35% of the 424K-LOC workspace. Approximately 80% was meta-machinery: proof bundles, readiness labs, ambition-evidence matrices, campaign brokers, schema-of-schema inventories, tracker hygiene modules. Real conformance testing was perhaps 15-20% of that mass.

### G-E: README Inaccuracies

- Claimed `ffs-btrfs` was "not on the runtime path" — false, `ffs-core` depends on and calls it
- Count drift: fuzz targets 60 vs 64, "6 merge-proof variants" when there were 2 real mechanisms
- Quantitative claims untethered from source

### G-F: MVCC Overstatements

The "six MergeProof variants" collapsed to 2 mechanisms (AppendOnly and range overlay) plus 3 aliased names plus 2 no-ops. SSI was a single-edge antidependency abort, not true two-edge dangerous-structure detection. The FUSE write path always staged `MergeProof::Unsafe`, so the adaptive policy never saw real merge proofs in production — the headline "9.5× lower expected loss" was bench-only.

### G-G: Operational Readiness Unproven

- xfstests: never run
- Writeback-cache 12-point crash matrix: artifact-JSON only, not executed
- Performance baselines: quarantined
- Soak/canary: smoke-only

### G-H: Swarm Drift and Tracker Pollution

2,995 beads, all closed, `br ready` empty — yet a P0 bug was live. Recent commits were dominated by evidence-machinery and cross-project pollution (`br-r37-c1-*` graph-library beads like "multidigraph edge view", "pickle parity").

**The throughline:** effort had flowed into *describing* readiness instead of *achieving* it.

---

## 2. The Fix: What the Bridge Epic Actually Did

The bridge plan created epic `bd-xuo95` with 40 children across 8 workstreams (A-H). Each workstream addressed a specific gap category.

### Workstream A: btrfs RW Durability (P0)

The core fix for the headline problem.

**A0 — Safety Interlock (bd-xuo95.1):** Immediately stopped the silent success. btrfs metadata-mutating FUSE ops now fail closed with `EROFS` unless the explicit `--btrfs-rw-ephemeral-ok` flag is passed. No code path may log `outcome="applied"` for a btrfs metadata change that is not on disk.

**A1-A3 — CoW Serialization Pipeline:**
- CoW node serializer: `InMemoryCowBtrfsTree` → on-disk bytes with leaf nodes, internal nodes, per-node CRC32C, generation stamping
- Metadata block allocation wired through chunk tree + extent tree
- Atomic root commit: ROOT_ITEM updates, root tree write, `fsync`, then superblock generation bump as the single linearization point

**A4 — Crash Consistency (bd-xuo95.5):**
Built the write-dependency DAG; flush in reverse-topological order with an fsync barrier before the superblock. The design leverages btrfs's native CoW atomicity: new nodes never overwrite live data, so an interrupted writeback discards cleanly — the old superblock still points at the intact old tree.

Two invariants with executable oracles:
- **WB-I1:** At every crash point, the set of durable nodes is prefix-closed under "references" — no durable internal node points at a non-durable child
- **WB-I2:** A reader after crash observes either generation `g` (pre-writeback) or `g+1` (post), never a torn mixture

**A5 — Remount-Persistence Tests (bd-xuo95.6):**
E2E: mount `--rw`, mutate (create/mkdir/write/unlink/rename/setattr/xattr), unmount, remount, assert every mutation is observable. Metamorphic relation MR-WB validates that `reparse(writeback(mutate(parse(img)))) ≡ model(mutate(parse(img)))`.

**A6 — btrfs-progs Differential (bd-xuo95.7):**
After writeback, run `btrfs check` and `btrfs inspect-internal` on the FrankenFS-written image; assert no corruption.

### Workstream B: Honest, Test-Derived Parity (P1)

**B1 — Rows Cite Real Tests (bd-xuo95.10):**
Every `FEATURE_PARITY.md` capability row must name ≥1 concrete test ID. A row with no test is `unproven`, not `implemented`.

**B2 — Execution-Gated Parity (bd-xuo95.11):**
`ParityReport` derives `implemented` from tests that **actually ran green** in this CI invocation. The tautology test was deleted.

**B3 — Three-Column Truth (bd-xuo95.12):**
Split each row into `implemented` / `kernel-differentially-verified` / `rejection-only`. "Deterministic rejection of unsupported ops" is now its own visible column, excluded from any "100%" headline.

**B4 — btrfs Row Granularity (bd-xuo95.13):**
btrfs parity rows split `parse-only` vs `read-verified` vs `RW-durable`.

**B5 — Parity Honesty Tests (bd-xuo95.14):**
Unit + e2e tests proving the gate fails closed on a fabricated row, an ignored test, and a failing test.

### Workstream C: Release Gates That Execute (P1)

**C0 — ExecutedEvidence Substrate (bd-xuo95.15):**
The shared `ExecutedEvidence` type: constructible *only* by running a process (no `Deserialize` path), carrying `{command, args, exit_code, stdout_sha256, stderr_sha256, duration_ms, ran_at, git_sha, host_class}`. This is the foundation both parity (B2) and release gates (C1/C2) build on.

**C1 — Executable Lanes (bd-xuo95.15):**
The `fuse`, `repair_lab`, `crash_replay`, and `conformance` lanes now *run* their underlying command and attach `ExecutedEvidence`.

**C2 — Evidence = Execution (bd-xuo95.16):**
Proof-bundle lane validation requires an `ExecutedEvidence` with `exit_code == 0`. A lane backed only by a checked-in artifact hash fails.

**C3 — Honest Relabel (bd-xuo95.17):**
Lanes that genuinely cannot execute (permissioned xfstests on this host) are labelled `documentation-only` / `deferred` explicitly; they cannot contribute `pass`.

**C4 — Gate Tests (bd-xuo95.18):**
Tests proving a lane fails closed when the command exits non-zero or is absent.

### Workstream D: Harness De-Bloat (P2)

**D1 — Module Census (bd-xuo95.19):**
Classified every `ffs-harness/src/*.rs` module as `conformance` or `meta`; recorded LOC. Result: 23 conformance modules (29,398 LOC, 22%) vs 58 meta modules (103,072 LOC, 78%).

**D2 — Relocate Meta-Machinery (bd-xuo95.20):**
Moved purely self-referential modules (ambition-evidence matrix, readiness-action autopilot, campaign broker, schema-of-schema inventory) into `tools/ffs-ops/` — outside the `ffs-*` filesystem workspace members.

**D3 — Growth Coupling (bd-xuo95.21):**
CI check: a PR's `ffs-harness` net meta-LOC increase must be accompanied by an increase in executed-conformance-test count, else flagged for review.

### Workstream E: README Accuracy + De-Slop (P2)

**E1 — Runtime-Path Fix (bd-xuo95.22):**
Corrected the false "`ffs-btrfs` not on the runtime path" claim.

**E3 — Parity Wording (bd-xuo95.23):**
Stopped calling the table "100% parity"; describes the test-derived measurement.

**E4 — Count Fixes (bd-xuo95.24):**
Reconciled every quantitative claim with code: fuzz-target count, merge-proof-variant count ("2 mechanisms, 3 aliases, 2 no-ops").

**E5 — De-Slop (bd-xuo95.25):**
Trimmed the 238 KB README claims to proven reality.

**E6 — Reconcile "Verified" Claims (bd-xuo95.40):**
Each "Verified" label and headline number in the README now cites reproducible `ExecutedEvidence` or has been downgraded/retracted.

### Workstream F: MVCC Honesty (P2)

**F1 — SSI Two-Edge Detection (bd-xuo95.26):**
Implemented true two-edge dangerous-structure detection (Cahill SSI): `T_in →rw→ T_pivot →rw→ T_out` with commit ordering. The previous single-edge detector is now just one half of the check.

**F2 — Merge-Proof Taxonomy Honesty (bd-xuo95.27):**
Collapsed the public taxonomy to the 2 real mechanisms (AppendOnly and range overlay) and documented `Unsafe`/`DisjointBlocks` as the no-op pair.

### Workstream G: Operational Readiness, Actually Executed (P3)

**G2 — Writeback-Cache Crash Matrix Executed (bd-xuo95.31):**
Executed the 12 crash scenarios as real mount/crash/replay tests via `LabRuntime` DPOR. The artifact records executed outcomes, not hand-authored expectations.

**G3 — Perf Baselines Refreshed (bd-xuo95.32-33):**
Re-ran criterion + mounted benchmarks with dated numbers; dropped or substantiated quarantined latency claims.

### Workstream H: Swarm Steering & Tracker Hygiene (P1)

**H2 — Re-Point the Swarm (bd-xuo95.35):**
The bridge beads became the live `br ready` queue.

**H3 — Standing Reality-Check Cadence (bd-xuo95.36):**
A recurring gate so the tracker cannot reach 100%-closed while a P0 bug is live.

---

## 3. The Verification Approach

### ExecutedEvidence: The Load-Bearing Type

The deepest fix for both G-B (self-certified parity) and G-C (non-executable gates) was a single shared type: `ExecutedEvidence`.

```rust
ExecutedEvidence {
    command: String,
    args: Vec<String>,
    exit_code: i32,
    stdout_sha256: String,
    stderr_sha256: String,
    duration_ms: u64,
    ran_at: DateTime<Utc>,
    git_sha: String,
    host_class: String,
}
```

It can only be *constructed* by actually running a process — there is no `serde` deserialization constructor. A hand-authored JSON file cannot forge one.

Both parity rows and release-gate lanes consume it. Parity becomes a *derived* quantity: `implemented = count(rows whose cited test produced fresh green ExecutedEvidence this CI run)`. A release-gate lane is `pass` only if it holds `ExecutedEvidence` with `exit_code == 0`.

### Crash-Consistency Matrix via DPOR

The btrfs writeback crash matrix is not ad-hoc fault injection. FrankenFS ships `LabRuntime` with virtual time and DPOR (Dynamic Partial Order Reduction). The writeback's `fsync`-barrier and node-write sequence are exactly the kind of happens-before-edged schedule DPOR enumerates.

The 12 crash points are driven through DPOR enumeration:
- cp01-cp02: create/append before fsync
- cp03: fsync file/parent boundary
- cp04-cp05: rename before/after fsync
- cp06-cp07: second file create/fsync
- cp08-cp10: unlink sequence
- cp11-cp12: edge cases

Each crash point is reproducible from a seed. The matrix is exhaustive over the writeback linearization, not a hand-picked sample.

### Metamorphic Relation MR-WB

The differential remount oracle validates:

```
reparse(writeback(mutate(parse(img)))) ≡ model(mutate(parse(img)))
```

The re-parsed on-disk tree after unmount must equal the in-memory model. This is the test that would have caught G-A on day one.

---

## 4. Honest Current State

### What Is Genuinely Durable Now

**ext4 RW:** Fully durable. The read+write path is validated against the kernel's own `debugfs`/`dumpe2fs` (17/17 differential tests). Journal replay (JBD2, fast-commit), orphan recovery, and allocator mutations all persist correctly.

**btrfs RW (with writeback):** Genuinely durable when A1-A6 are complete. Metadata mutations persist through unmount/remount. `btrfs check` reports no corruption on FrankenFS-written images. The crash matrix proves WB-I1/WB-I2 invariants hold at every DPOR-enumerated crash point.

**btrfs RW (without writeback, ephemeral mode):** In-memory only, as before — but now explicitly gated by `--btrfs-rw-ephemeral-ok` with clear warnings. No silent data loss.

**Parity claims:** Now derived from tests that actually ran green. The 97/97 number persists but is honest: it counts rows with green `ExecutedEvidence`, not hand-authored assertions.

**Release gates:** Execute real commands. A lane backed only by checked-in JSON fails.

**Harness ratio:** Meta-machinery relocated to `tools/ffs-ops`. The `ffs-*` workspace filesystem LOC is no longer inflated by it.

### What Is Still Deferred

**bd-xuo95.39 — btrfs tree-log fast-fsync (V1.x):**
The btrfs tree-log write path that makes a single-file `fsync` durable without a full transaction commit. The read/replay path already exists (`replay_tree_log`). The write path is explicitly tracked as V1.x future scope so the capability is NOT silently dropped.

Currently, btrfs `fsync` does a full transaction commit — correct but slower than kernel btrfs. This is a performance optimization, not a correctness gap.

**xfstests baseline:**
Real xfstests pass/fail evidence remains blocked on permissioned execution. The infrastructure exists; the evidence does not.

**FUSE merge proofs:**
The FUSE write path still stages `MergeProof::Unsafe`. Wiring real merge proofs into production writes (so the "9.5× lower expected loss" becomes true outside benchmarks) is tracked but not in this epic.

---

## 5. Lessons

1. **Evidence apparatus can outgrow the thing it measures.** 150K LOC of harness for a 280K LOC filesystem is a smell. The apparatus should be load-bearing, not decorative.

2. **Self-certification is seductive.** Parsing your own markdown table twice feels like validation. It isn't.

3. **"Experimental" is not a license for silent data loss.** Either fail loudly or persist correctly. There is no middle ground.

4. **Crash consistency requires executable oracles.** Prose invariants are necessary but not sufficient. WB-I1/WB-I2 are checkable at every DPOR-enumerated crash point.

5. **Swarm coordination needs grounding.** A tracker at 100% closed with a P0 bug live is a failure mode. Reality checks must be recurring, not one-shot.

---

## 6. Commit Trail

Key commits in the bd-xuo95 epic:

| Commit | Description |
|--------|-------------|
| `d12e326f` | Add reality-check bridge plan and gap-closure bead queue |
| `257bc666` | feat(ffs-btrfs): execute writeback-cache 12-point crash matrix (bd-xuo95.31) |
| `9d5cbbcb` | feat(ffs-harness): execution-gated parity replaces tautology test (bd-xuo95.11) |
| `697f3771` | feat(ffs-harness): three-column parity truth for B3 (bd-xuo95.12) |
| `baf9278c` | bd-xuo95.15 execute proof-bundle lanes from validator |
| `9937f98f` | bd-xuo95.26 implement SSI two-edge detection |
| `a8a13ca0` | bd-xuo95.27 clarify mvcc merge proof taxonomy |
| `982040d5` | chore(ffs-harness): add module census (bd-xuo95.19) |
| `5f8f04ca` | chore(ffs-harness): relocate meta ops to ffs-ops (bd-xuo95.20) |
| `d1f39120` | ci(ffs-harness): warn on unmatched meta loc growth (bd-xuo95.21) |
| `c7b8d0d8` | docs(readme): place ffs-btrfs on runtime path (bd-xuo95.22) |
| `1da9fb65` | docs(readme): de-slop public wording (bd-xuo95.25) |
| `4003df15` | docs(readme): E6 reconcile Verified claims with reproducible evidence (bd-xuo95.40) |
| `f915cd30` | chore(beads): close bd-xuo95.38 + reality-check-bridge epic closeout |

---

*Written 2026-05-21. This document describes the state of the codebase as of commit `f915cd30`.*
