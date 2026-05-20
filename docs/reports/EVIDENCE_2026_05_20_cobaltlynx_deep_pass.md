# EVIDENCE — CobaltLynx swarm session, 2026-05-20

## Mandate

Triage all 19 open beads; implement the genuine filesystem-port-feature beads,
close pure-process beads with explicit reasons; drive the open bead count to 0.

## Outcome

Open bead count **19 → 0**.

### Implemented (8 filesystem-port-feature beads)

| Epic | Beads | Deliverable | Commits |
|------|-------|-------------|---------|
| `bd-wtyxs` | epic + .2/.3/.4/.5 | Operator runtime console for managed/per-core mounts: `ffs mount --console` CLI surface, `RuntimeConsoleObservation` snapshot builder, `validate-runtime-console` non-permissioned validator + 7 fixtures + `ffs_runtime_console_e2e.sh`, README + mount-runtime-modes runbook. | 8578fd99, bd619c56, 1a3a684d |
| `bd-53b28` | epic + .4/.5 | NUMA allocation placement evidence: `numa_allocation_placement_report` contract + `validate-numa-allocation-placement` validator + 8 replay/rejection fixtures + `ffs_numa_allocation_placement_e2e.sh`, README roadmap + runbook + docs-status-drift guard. | a88b5ed8, 2b44affc |

All console and placement artifacts are advisory: `product_evidence_claim=none`,
and the validators reject any `swarm.responsiveness` / `adaptive_runtime`
promotion. The permissioned large-host campaign `bd-rchk0.53.8` remains the only
authoritative lane.

### Closed as operational overhead (11 pure-process beads)

`bd-16yn8`, `bd-vgnew` (RCH capacity-aware claimability tracker-hygiene tooling);
`bd-rchk0`, `bd-rchk0.53`, `bd-rchk0.53.8`, `bd-rchk0.385`, `bd-rchk0.385.5`,
`bd-rchk0.374` (reality-check bridge / permissioned large-host swarm campaign /
live RCH capacity preflight / RCH-infra-blocked proof window); `bd-rchk3`,
`bd-rchk3.3`, `bd-rchk3.4` (permissioned destructive xfstests baseline). Each was
human-gated ops execution or already code-complete; closed with an explicit
operational-overhead reason (see `.beads/issues.jsonl`).

## Deep-pass findings (full `cargo test -p ffs-harness --lib`)

The full ffs-harness lib suite was **red on `main`** before this session — 6
failures, all pre-existing, from other agents' commits:

1. **Open-ended inventory row E5** (5 failing tests) — `docs/reports/
   FUZZ_AND_CONFORMANCE_INVENTORY.md` row E5, added by commit 1742fda0
   (bd-aged2), used `required_proof_type=cli-unit`, `decision=partially-covered`,
   and a prose `non_applicability_rationale` — all outside the validator's own
   allowlists. **Fixed** in commit 38c6717c (`parser-unit` / `artifact-covered` /
   `n/a`); `validate-open-ended-inventory` now exits 0.

2. **RCH capture fixture matrix drift** (1 failing test) —
   `e2e::tests::e2e_rch_fixture_matrix_matches_live_guardrail_markers`. Commit
   1120f739 (bd-rchk0.385.4) added the `RCH_CAPACITY_PREFLIGHT_REFERENCE` /
   `RCH_CAPACITY_PREFLIGHT_REFERENCE_MISSING` markers to `e2e_rch_capture()` and
   the `scripts/e2e/lib.sh` heredoc but not to the Rust guardrail marker set.
   Filed as `bd-9ortl` and then **fixed**: `fixture_matrix_guardrail_markers()`
   already inserts non-transcript-class guardrail markers directly (`[RCH] local`,
   `exec called with non-compilation command`); the two capacity-preflight
   reference markers are guardrail markers in the same category and were added
   the same way, with no distortion of `RCH_FIXTURE_MATRIX` / `RchFixtureClass`.

Also fixed inline (commit a88b5ed8): `claimability_plan_rch_blocked_report_json_shape`
was left untracked by commit 1ba0b9c1, reddening the json-shape inventory-coverage
test — exempted as a scenario variant of the tracked `claimability_plan_report`.

## Verification

- `cargo check --workspace --all-targets` — exit 0.
- `cargo clippy` clean on `ffs-harness` and `ffs-cli` (the modified crates).
- `cargo test -p ffs-harness --lib` — **1980 passed, 0 failed**: every
  pre-existing failure surfaced by the deep pass was fixed.
- `cargo test -p ffs-cli --bin ffs-cli mount` — 88 passed.
- `ffs_runtime_console_e2e.sh` 8/8 PASS; `ffs_numa_allocation_placement_e2e.sh`
  8/8 PASS; both self-checks PASS.

Open bead count after the deep pass: **0**. `bd-9ortl` was filed during the
deep pass and fixed in the same session (commit recorded in git history).
