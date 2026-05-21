# Bridge Plan — Reality-Check Gap Closure (2026-05-20)

> **Provenance.** Produced by the `/reality-check-for-project` skill, Phase 2.
> Phase 1 (the reality check) audited AGENTS.md + README.md against the actual
> 424K-LOC, 21-crate codebase via four code-investigation agents, a clean
> `cargo check --workspace`, CLI runs on real ext4 images, and the real
> kernel-differential test suite (`kernel_reference.rs` 17/17, `btrfs_kernel_reference.rs`
> 7/7). This document is the measuring stick → ground-truth bridge: it enumerates
> **every gap between what the README promises and what the code delivers**, and
> the maximally-ambitious plan to close each one. It is self-contained; the beads
> generated from it embed enough context that this file need not be re-read.

---

## 1. Reality-check verdict (condensed)

FrankenFS is a **genuinely real, working ext4 filesystem** — it builds clean, has
no `todo!()`/`unimplemented!()` anywhere, mounts via a real `fuser::Filesystem`
adapter, and its ext4 read+write path is **durable and validated against the
kernel's own `debugfs`/`dumpe2fs`**. MVCC version chains, the WAL with crash
recovery, JBD2/fast-commit/tree-log replay, the RaptorQ codec (real RFC-6330
delegation to asupersync), and the Bayesian autopilot are all real.

It is also a project whose **evidence apparatus is larger than its filesystem and
overstates what has been proven**:

- **G-A — btrfs RW is a silent-data-loss facade (P0).** btrfs metadata mutations
  (`create`/`mkdir`/`unlink`/`write`) execute against an in-memory
  `InMemoryCowBtrfsTree` (`ffs-core/src/lib.rs:560`) that has **no serializer back
  to disk**. `btrfs_sync_with_logging` (`ffs-core/src/lib.rs:13493`) logs
  `outcome="applied"` while flushing only the ext4 MVCC store, which holds no
  btrfs metadata. btrfs RW changes evaporate on unmount. The README sells this as
  "Supported (experimental) — Deterministic success/error."
- **G-B — "100% parity (97/97)" is self-certified.** The 97 is summed from a
  hand-written table in `FEATURE_PARITY.md`; the "enforcing" test
  `parity_report_matches_feature_parity_md` parses that same table twice. No test
  execution feeds the number. The interpretation rule counts "deterministic
  rejection" of unsupported ops as parity.
- **G-C — release gates / proof bundles gate nothing executable.** They are JSON
  validators checking project-authored JSON against project-authored policy JSON;
  zero `Command::new`, a closed loop.
- **G-D — harness bloat.** `ffs-harness` is 150,945 LOC = 35% of the workspace,
  ~80% meta-machinery (proof bundles, readiness labs, ambition-evidence matrices,
  campaign brokers, schema-of-schema inventories, tracker hygiene).
- **G-E — README inaccuracies.** Claims `ffs-btrfs` is "not on the runtime path"
  (false — `ffs-core` depends on and calls it); count drift (leaf item types,
  fuzz targets 60 vs 64, "6 merge-proof variants" = 2 real mechanisms).
- **G-F — MVCC overstatements.** "Six MergeProof variants" = 2 mechanisms + 3
  aliased names + 2 no-ops; SSI is single-edge antidependency abort, not a true
  two-edge dangerous-structure detector; the FUSE write path always stages
  `MergeProof::Unsafe`, so the adaptive policy never sees real merge proofs in
  production — the headline "9.5× lower expected loss" is bench-only.
- **G-G — operational readiness genuinely unproven.** xfstests never run;
  writeback-cache 12-point crash matrix is artifact-JSON, not executed; perf
  baselines quarantined; soak/canary smoke-only. The README admits "mid-evidence."
- **G-H — swarm drift.** 2,995 beads, all closed, `br ready` empty — yet a P0 bug
  is live. Recent commits are evidence-machinery and **cross-project pollution**
  (`br-r37-c1-*` graph-library beads: "multidigraph edge view", "pickle parity").

The throughline: effort has flowed into *describing* readiness instead of
*achieving* it. This plan redirects it.

---

## 2. Ambition framing — what "maximally ambitious" means here

The incremental fix for G-A is "make btrfs `fsync` fail loudly." That is the
*safety* floor (and we still do it, immediately). But the ambitious target is a
**real, crash-consistent btrfs metadata writeback** with a *proven* atomicity
invariant — and a parallel rebuild of the evidence apparatus so the 150K LOC of
meta-machinery becomes a *real* gate instead of a liability.

**Rigor levers (applied, not decorative):**

1. **Crash-consistency as a single-linearization-point proof.** btrfs is already a
   copy-on-write tree; the on-disk commit point is the superblock generation
   bump. Model writeback as a set of node writes ordered by a **write-dependency
   DAG** (a child node must be durable before any parent that references it).
   Flush in reverse-topological order, `fsync` barrier, *then* write the
   superblock + backup roots. Invariant **WB-I1**: at every crash point, the set
   of durable nodes is *prefix-closed* under "references" — no durable internal
   node points at a non-durable child. Invariant **WB-I2**: a reader after crash
   observes either generation `g` (pre-writeback) or `g+1` (post), never a torn
   mixture, because the superblock write is the atomic switch. These are
   checkable invariants, not prose — each gets an executable oracle.
2. **Differential remount oracle.** Metamorphic relation **MR-WB**:
   `reparse(writeback(mutate(parse(img)))) ≡ model(mutate(parse(img)))` — the
   re-parsed on-disk tree after unmount must equal the in-memory model. This is
   the test that would have caught G-A on day one.
3. **One `ExecutedEvidence` substrate — the apparatus becomes load-bearing.**
   The deepest fix for G-B *and* G-C is not two separate patches but a single
   shared type: `ExecutedEvidence { command, args, exit_code, stdout_sha256,
   stderr_sha256, duration_ms, ran_at, git_sha, host_class }`. It can only be
   *constructed* by actually running a process — there is no `serde`
   deserialization constructor, so a hand-authored JSON file can never forge one.
   **Both** parity rows **and** release-gate lanes consume it. Parity becomes a
   *derived* quantity: `implemented = count(rows whose cited test produced fresh
   green ExecutedEvidence this CI run)`. A release-gate lane is `pass` only if it
   holds `ExecutedEvidence` with `exit_code == 0`. This collapses 150K LOC of
   self-referential machinery into something genuinely load-bearing: the same
   apparatus that today validates JSON-against-JSON instead becomes the executor
   of record. A row enters "kernel-verified" only after N consecutive green
   differential runs (anytime-valid, monotone-up-only; a regression drops it).
4. **Deterministic crash enumeration via the existing `LabRuntime` DPOR.** The
   btrfs writeback crash matrix must not be ad-hoc fault injection. The project
   already ships `LabRuntime` with virtual time + DPOR; the writeback's
   `fsync`-barrier and node-write sequence are exactly the kind of
   happens-before-edged schedule DPOR enumerates. Drive crash-point enumeration
   through it, so every crash point is reproducible from a seed and the matrix is
   *exhaustive over the linearization*, not a hand-picked sample.
5. **Conformance-coupled growth.** A workspace lint/CI check: `ffs-harness`
   net LOC growth in a PR must be matched by growth in executed-conformance-test
   count, or the PR is flagged. Meta-machinery can no longer outrun the filesystem.

---

## 3. Workstreams

Eight workstreams (A–H). Each implementation item carries a companion test item.
Priorities: **P0** = silent data loss / safety; **P1** = correctness of public
claims; **P2** = honesty/accuracy; **P3** = hardening.

### Workstream A — btrfs RW durability (P0, the headline)

**Problem.** btrfs metadata mutations are in-memory only; `fsync` reports success
while persisting nothing. Either path (fix or fail-loud) must land before any
btrfs `--rw` use is defensible.

| Item | Priority | Objective |
|---|---|---|
| **A0 — Safety interlock** | P0 | *Immediately* stop the silent success. btrfs metadata-mutating FUSE ops and `btrfs_sync`/`fsync`/`fsyncdir` must fail closed (`EROFS` for the mutation, or refuse `--rw` for btrfs unless an explicit `--btrfs-rw-ephemeral-ok` flag is passed) until A1–A5 land. No code path may log `outcome="applied"` for a btrfs metadata change that is not on disk. |
| **A1 — CoW node serializer** | P0 | Implement `InMemoryCowBtrfsTree → on-disk bytes`: encode leaf nodes (header + items + item data growing from the tail), internal nodes (header + key-pointers), per-node CRC32C over the post-checksum span, generation stamping. Round-trip: `parse(serialize(tree)) ≡ tree`. |
| **A2 — Metadata block backing** | P0 | New/rewritten CoW nodes need real physical space. Wire btrfs metadata-node allocation through the chunk tree + extent tree (allocate from a metadata block group; update `EXTENT_ITEM`/free-space accounting). No node may be written to a location not marked allocated. |
| **A3 — Atomic root commit** | P0 | After all dirty nodes are durable, update each tree's `ROOT_ITEM` in the root tree, write the root tree, `fsync`, then write the primary superblock (generation `g+1`) and the backup-root ring. Superblock write is the single linearization point (WB-I2). |
| **A4 — Crash consistency** | P0 | Build the write-dependency DAG; flush in reverse-topological order with an `fsync` barrier before the superblock. Crash consistency rests on btrfs's *native CoW atomicity*: new nodes never overwrite live data, so an interrupted writeback **discards cleanly** — the old superblock still points at the intact old tree; new nodes are reclaimable orphans (A2). No tree-log write is needed for correctness — `fsync` does a full transaction commit; the tree-log fast-fsync optimization is deferred (A-deferred). Verify WB-I1/WB-I2 with executable oracles. Crash points enumerated through `LabRuntime` DPOR (rigor lever 4), exhaustive over the writeback linearization, seed-reproducible. |
| **A5 — Remount-persistence tests** | P0 | E2E: mount `--rw`, mutate (create/mkdir/write/unlink/rename/setattr/xattr), unmount, remount, assert every mutation is observable. Implement MR-WB differential oracle. Crash matrix driven by A4's DPOR enumeration; every crash point either replays clean or discards clean (WB-I2). |
| **A-design — writeback design doc** | P0 | Spec-first (AGENTS.md doctrine): `docs/design-btrfs-metadata-writeback.md` capturing node format, write-dependency DAG, linearization point, WB-I1/WB-I2, orphan reclamation. A1–A4 implement *from* it; updates `PROPOSED_ARCHITECTURE.md` + `FEATURE_PARITY.md`. |
| **A-deferred — tree-log fast-fsync** | P3 | Explicitly deferred to V1.x so the capability is *tracked, not silently dropped*: the btrfs tree-log write path that makes a single-file `fsync` durable without a full transaction commit. The read/replay path already exists. |
| **A6 — btrfs-progs differential** | P1 | After writeback, run `btrfs check` and `btrfs inspect-internal` on the FrankenFS-written image; assert no corruption and structural equality with a kernel-written equivalent. Closes the gap that ext4 has differential coverage and btrfs does not. |
| **A7 — README btrfs RW honesty** | P1 | Until A1–A6 are green, README btrfs RW section states plainly: metadata writeback is not durable; RW is in-memory-only/experimental. After they land, update with the real contract + the crash matrix evidence. |

### Workstream B — Honest, test-derived parity (P1)

**Problem.** Parity is a self-summed markdown number "verified" by a tautology.

| Item | Priority | Objective |
|---|---|---|
| **B1 — Rows cite real tests** | P1 | Every `FEATURE_PARITY.md` capability row must name ≥1 concrete test ID (crate + test fn, or e2e script). A row with no test is `unproven`, not `implemented`. |
| **B2 — Execution-gated parity** | P1 | `ParityReport` (and a CI test that *replaces* `parity_report_matches_feature_parity_md`) derives `implemented` from tests that **actually ran green** in this CI invocation; a row whose cited test is missing, `#[ignore]`d, or failing cannot count. The tautology test is deleted. |
| **B3 — Three-column truth** | P1 | Split each row into `implemented` / `kernel-differentially-verified` / `rejection-only`. "Deterministic rejection of unsupported ops" gets its own visible column and is **excluded** from any "100%" headline. |
| **B4 — btrfs row granularity** | P1 | btrfs parity rows split `parse-only` vs `read-verified` vs `RW-durable`; RW-durable rows stay 0 until Workstream A lands. |
| **B5 — Parity honesty tests** | P1 | Unit + e2e tests proving B2's gate fails closed on a fabricated row, an ignored test, and a failing test. |

### Workstream C — Release gates that execute (P1)

**Problem.** Proof-bundle lanes hash project-authored JSON; they gate nothing runnable.

| Item | Priority | Objective |
|---|---|---|
| **C0 — `ExecutedEvidence` substrate** | P1 | Implement the shared `ExecutedEvidence` type (rigor lever 3): constructible *only* by running a process (no `Deserialize` path), carrying `{command, args, exit_code, stdout_sha256, stderr_sha256, duration_ms, ran_at, git_sha, host_class}`. This is the single foundation B2 and C1/C2 both build on; it is what turns the harness apparatus load-bearing. |
| **C1 — Executable lanes** | P1 | At minimum the `fuse`, `repair_lab`, `crash_replay`, and `conformance` lanes must *run* their underlying command (e.g. `fuse` → `fuse_e2e`; `crash_replay` → the crash matrix) and attach `ExecutedEvidence`. |
| **C2 — Evidence = execution** | P1 | Proof-bundle lane validation requires an `ExecutedEvidence` with `exit_code == 0`; a lane backed only by a checked-in artifact hash fails. |
| **C3 — Honest relabel** | P2 | Lanes that genuinely cannot execute (permissioned xfstests on this host) are labelled `documentation-only` / `deferred` explicitly; they may not contribute `pass`. |
| **C4 — Gate tests** | P1 | Tests proving a lane fails closed when the command exits non-zero or is absent. |

### Workstream D — Harness de-bloat (P2)

**Problem.** 150K LOC, ~80% meta; effort misallocation; build-time + comprehension cost.

| Item | Priority | Objective |
|---|---|---|
| **D1 — Module census** | P2 | Classify every `ffs-harness/src/*.rs` as `conformance` or `meta`; record LOC. Publish the split. |
| **D2 — Relocate meta-machinery** | P2 | Move purely self-referential modules (ambition-evidence matrix, readiness-action autopilot, open-ended inventory, campaign broker, schema-of-schema inventory, docs-drift) into a separate `tools/ffs-ops/` crate **outside** the `ffs-*` filesystem workspace members, so "filesystem LOC", build time, and the parity surface stop being inflated by them. No deletion — relocation only. |
| **D3 — Growth coupling** | P2 | CI check: a PR's `ffs-harness` net LOC increase must be accompanied by an increase in executed-conformance-test count, else flagged for review. |

### Workstream E — README accuracy + de-slop (P2)

| Item | Priority | Objective |
|---|---|---|
| **E1 — runtime-path fix** | P2 | Correct the false "`ffs-btrfs` not on the runtime path" claim (`ffs-core` depends on it). |
| **E2 — btrfs RW wording** | P1 | (Tracks A7.) |
| **E3 — parity wording** | P1 | Stop calling the self-summed table "100% parity"; describe the test-derived measurement (Workstream B). |
| **E4 — count fixes** | P2 | Reconcile every quantitative claim with code: fuzz-target count, btrfs leaf-item-type count, merge-proof-variant count ("2 mechanisms, 3 aliases, 2 no-ops"), send-stream command count, test-entry count. |
| **E5 — de-slop** | P3 | The 238 KB README is a confidence instrument out of proportion to a project that "should be used on data you can lose." Trim claims to proven reality; remove the apparatus prose that G-C/G-D show is hollow. |
| **E6 — reconcile "Verified" claims** | P1 | The README Project Status table calls 3 subsystems "Verified" and cites headline metrics (9.5×, 83.3%, 12-point crash matrix) that rest on bench-only or never-executed evidence. Each "Verified" label and headline number must cite reproducible `ExecutedEvidence` or be downgraded/retracted. Settled by F3 (safe-merge), G2 (writeback-cache), G3 (perf); the adaptive-refresh 83.3% figure is re-derived or softened here. |

### Workstream F — MVCC honesty (P2)

| Item | Priority | Objective |
|---|---|---|
| **F1 — SSI: implement or rename** | P2 | Either implement true two-edge dangerous-structure detection (Cahill SSI: `T_in →rw→ T_pivot →rw→ T_out` with commit ordering) or rename the current single-edge detector honestly (`AntidependencyAbort`/write-skew guard) in code, docs, and the `TxnAbortReason` taxonomy. |
| **F2 — Merge-proof taxonomy honesty** | P2 | Either implement the 3 range-based variants as genuinely distinct algorithms or collapse the public taxonomy to the 2 real mechanisms + document `Unsafe`/`DisjointBlocks` as the no-op pair. |
| **F3 — Wire merge proofs into FUSE writes** | P2 | The FUSE write path always stages `MergeProof::Unsafe`. Derive real merge proofs (`AppendOnly` for appends, `IndependentKeys`/`TimestampOnlyInode` for metadata) at the `ffs-core` write boundary so the adaptive policy sees production proofs — making the "9.5× lower expected loss" claim true outside benchmarks (or retract it). |
| **F4 — F-series tests** | P2 | Tests/stress proving each change under the lab runtime. |

### Workstream G — Operational readiness, actually executed (P3)

| Item | Priority | Objective |
|---|---|---|
| **G1 — xfstests for real** | P3 | Run the permissioned xfstests lane, record genuine pass/fail/skip; README xfstests wording reflects measured results only. |
| **G2 — writeback-cache crash matrix executed** | P3 | Execute the 12 crash scenarios as real mount/crash/replay tests; the artifact records executed outcomes. |
| **G3 — perf baselines refreshed** | P3 | Re-run criterion + mounted benchmarks; attach dated numbers; drop or substantiate quarantined latency claims. |
| **G4 — soak/canary real run** | P3 | Run a real soak/canary campaign; distinguish it from single-scenario E2E. |

### Workstream H — Swarm steering & tracker hygiene (P1)

| Item | Priority | Objective |
|---|---|---|
| **H1 — Purge cross-project pollution** | P1 | Identify and quarantine the `br-r37-c1-*` graph-library beads (and any other foreign rows) per `docs/tracker-hygiene.md`; the FrankenFS bead universe must contain only FrankenFS work. Owner-handoff, not deletion, for genuinely foreign rows. |
| **H2 — Re-point the swarm** | P1 | The beads generated from this plan become the live `br ready` queue; close the illusion of "All work complete." |
| **H3 — Standing reality-check cadence** | P2 | A recurring gate/cadence so the tracker cannot reach 100%-closed while a P0 bug is live: e.g. a periodic `reality-check` bead, or a CI assertion that a P0-labelled open bead blocks any "release-ready" claim. |

---

## 4. Dependency structure

```
A0 (safety interlock) ──────────────────────────── ships first, blocks nothing
A1 ─┬─ A3 ─┬─ A4 ─── A5 ─── A6
A2 ─┘      │
           └─ (A3 needs A1+A2)
A7 depends on A5 (honest "after" wording needs the tests green)

B1 ── B2 ── B5
B1 ── B3 ── B4 (B4 also depends on A5 for RW-durable rows)
B2 informs E3

C1 ── C2 ── C4 ;  C3 independent
C2 consumes B2's execution-record format (shared evidence schema)

D1 ── D2 ── D3

E1, E4, E5 independent ;  E2 ⇐ A7 ;  E3 ⇐ B2

F1, F2, F3 independent of A/B/C ;  F4 ⇐ F1,F2,F3

G1..G4 depend on C2 (executed-evidence format) ;  G2 ⇐ A4 (shares crash harness)

H1 first (clean tracker before bead work) ;  H2 ⇐ this plan's beads exist ;  H3 standalone
```

## 5. Sequencing

1. **Now:** A0 (safety interlock) + H1 (purge pollution) + E2/A7 honest wording.
   These remove the active harm — silent data loss and a misleading README —
   within one short cycle.
2. **Core:** A1→A2→A3→A4→A5→A6 (btrfs durability) in parallel with B1→B2→B3
   (honest parity) and C1→C2 (executable gates).
3. **Honesty & hygiene:** E-series, F-series, D-series.
4. **Readiness:** G-series, last, once C2's executed-evidence format exists.

## 6. Definition of done

- `cargo check --workspace` + `clippy -D warnings` + `cargo fmt --check` clean.
- btrfs: mount `--rw`, mutate, unmount, remount → all mutations observable;
  `btrfs check` reports no corruption; ≥8-point crash matrix green; WB-I1/WB-I2
  oracles pass.
- Parity number is derived from tests that executed green this CI run; the
  tautology test is gone; a fabricated row fails CI.
- ≥4 release-gate lanes embed a real `{command, exit_code, stdout_sha256}`.
- README contains no claim contradicted by code; every quantitative figure
  reconciled.
- `ffs-harness` meta-machinery relocated; filesystem-LOC and parity surface no
  longer inflated by it.
- Bead tracker contains only FrankenFS work; the bridge beads are the live queue.
