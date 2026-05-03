# FrankenFS E2E Tests

End-to-end smoke tests for FrankenFS that exercise user-facing workflows.

## Quick Start

```bash
# Run the main smoke test
./scripts/e2e/ffs_smoke.sh

# Run ext4 read-write smoke + crash checks
./scripts/e2e/ffs_ext4_rw_smoke.sh

# Run ext4 read-only round-trip (debugfs reference vs FUSE view)
./scripts/e2e/ffs_ext4_ro_roundtrip.sh

# Run btrfs read-write smoke + crash matrix + persistence checks
./scripts/e2e/ffs_btrfs_rw_smoke.sh

# Run mounted recovery lifecycle matrix contract checks
./scripts/e2e/ffs_mounted_recovery_matrix_e2e.sh

# Run btrfs read-only FUSE smoke
./scripts/e2e/ffs_btrfs_ro_smoke.sh

# Run production FUSE runtime E2E suite
./scripts/e2e/ffs_fuse_production.sh

# Run write-back durability scenarios
./scripts/e2e/ffs_writeback_e2e.sh

# Run graceful degradation stress suite
./scripts/e2e/ffs_degradation_stress.sh

# Run deterministic corruption-injection + recovery smoke
./scripts/e2e/ffs_repair_recovery_smoke.sh

# Plan/run curated xfstests generic+ext4 subsets
./scripts/e2e/ffs_xfstests_e2e.sh

# Run proof overhead budget release-gate smoke
./scripts/e2e/ffs_proof_overhead_budget_e2e.sh

# Run proof bundle offline validation smoke
./scripts/e2e/ffs_proof_bundle_e2e.sh

# Run release-gate policy evaluator smoke
./scripts/e2e/ffs_release_gate_e2e.sh

# Run performance baseline manifest dry-run validation
./scripts/e2e/ffs_performance_manifest_e2e.sh

# Run adversarial-image threat model dry-run validation
./scripts/e2e/ffs_adversarial_threat_model_e2e.sh

# Run soak/canary campaign manifest dry-run validation
./scripts/e2e/ffs_soak_canary_campaign_e2e.sh

# Run repair/writeback serialization contract dry-run validation
./scripts/e2e/ffs_repair_writeback_serialization_e2e.sh
```

## Scenario Catalog Contract

Deterministic scenario IDs are centrally defined in:

- `scripts/e2e/scenario_catalog.json`

The catalog is machine-validated by `e2e_validate_scenario_catalog` (in `scripts/e2e/lib.sh`) and runs automatically in CI via `./scripts/e2e/ffs_smoke.sh` Phase 0.

### `scenario_id` Format

All explicit IDs in the catalog must match:

```regex
^[a-z][a-z0-9]*(_[a-z0-9]+){2,}$
```

That enforces lowercase snake-case with at least three segments (domain + behavior + qualifier).

### Taxonomy

| Category | Meaning |
|----------|---------|
| `happy` | Expected success path |
| `edge` | Boundary/limit condition |
| `error` | Explicit failure-path validation |
| `corruption` | Injected corruption/torn/truncated state |
| `recovery` | Post-failure restoration contract |
| `degradation` | Pressure/fallback behavior |
| `unsupported_op` | Deterministic unsupported-path rejection |

### Gate Minimum Coverage

The catalog encodes minimum category coverage per hardening epic (`gate_minimums`) so each track can be validated against a shared baseline:

- `bd-h6nz.1` durable MVCC replay
- `bd-h6nz.2` mount runtime wiring
- `bd-h6nz.3` btrfs RW hardening
- `bd-h6nz.4` fuzzing/adversarial expansion
- `bd-h6nz.5` benchmark governance
- `bd-h6nz.6` open-question closures
- `bd-h6nz.7` operator tooling
- `bd-h6nz.9` cross-epic verification contract

## Artifact Manifest Contract

The canonical verification artifact manifest schema lives in:

- `crates/ffs-harness/src/artifact_manifest.rs`

It defines the shared representation for verification outputs across E2E, benchmark, fuzz, proof, and repro-pack workflows. The top-level contract includes:

- `schema_version`, `run_id`, `created_at`, `gate_id`, and optional `bead_id`
- `git_context` and `environment` fingerprints for reproducibility
- `scenarios` keyed by `scenario_id`
- `operational_context` for readiness-grade runs: exact command line, host/worker id, FUSE capability result, and primary stdout/stderr log paths
- `operational_scenarios` keyed by `scenario_id` for expected/actual outcome, pass/fail/skip/error classification, filesystem flavor, image hash, mount options, exit status, stdout/stderr paths, evidence ledger paths, cleanup status, remediation hint, and artifact references
- `artifacts` with category, content type, size, checksum, redaction flag, and metadata
- `verdict`, `duration_secs`, and optional retention metadata

Generic historical manifests may use only the base schema. Operational readiness manifests must pass the stricter `validate_operational_manifest` check. That validator rejects missing run context, missing per-scenario metadata, invalid pass/fail/skip/error classification, ambiguous skip reasons, malformed artifact paths, artifact references that do not point at manifest entries, missing stdout/stderr paths, missing cleanup status, and unprobed FUSE capability.

Shared runner helpers live in `crates/ffs-harness/src/verification_runner.rs`.
Domain-specific scripts should keep shell focused on orchestration and use the
Rust helpers for command redaction, log path generation, pass/fail/skip/error
classification, FUSE capability classification, partial-artifact preservation,
and final manifest validation. Shell scripts can validate a generated manifest
with:

```bash
e2e_validate_operational_manifest "$E2E_LOG_DIR/operational_manifest.json"
```

or directly:

```bash
cargo run -p ffs-harness -- validate-operational-manifest "$manifest_path"
```

Mounted scripts should emit a FUSE capability artifact before they decide to
run or skip mount-sensitive scenarios:

```bash
e2e_probe_fuse_capability "$E2E_LOG_DIR/fuse_capability.json" --require-mount-probe
```

The underlying CLI is also available for local diagnostics:

```bash
cargo run -p ffs-harness -- fuse-capability-probe --out artifacts/e2e/fuse_capability.json
```

The report includes `result`, `skip_reason`, `failure_kind`,
`remediation_hint`, and per-check rows for `/dev/fuse`, `fusermount3` or
`fusermount`, kernel FUSE support, `/dev/fuse` read/write access, namespace or
capability state, mount/unmount probe exits, and the btrfs
`DefaultPermissions` root-owned testdir `EACCES` case. Missing or denied host
capabilities must produce a skip/error artifact with a remediation hint, not a
silent success.

### Operational Readiness Report

Use the readiness aggregator when closing operational hardening beads. It scans
an artifact directory for versioned `ArtifactManifest` files and legacy
`result.json` summaries, then emits a single JSON or Markdown report that
groups scenarios by workstream, counts pass/fail/skip/error outcomes, preserves
links to raw logs and artifacts, flags duplicate scenario IDs, detects stale git
SHAs when `--current-git-sha` is provided, and separates product failures from
environment-only blockers.

```bash
cargo run -p ffs-harness -- operational-readiness-report \
  --artifacts artifacts/e2e \
  --current-git-sha "$(git rev-parse --short HEAD)" \
  --format markdown \
  --out artifacts/e2e/operational_readiness.md
```

Attach the JSON or Markdown report path to the bead close reason when a bead
claims operational readiness evidence. The report is an aggregator; it does not
replace the raw per-suite logs, manifests, or reproduction commands.

### Soak/Canary Campaigns

The soak/canary campaign manifest defines bounded `smoke`, `nightly`, `stress`,
and `canary` profiles for repeated mount, repair, writeback-cache gate, and
artifact aggregation work. The dry-run validator does not perform long mounted
runs; it proves the campaign contract, resource limits, heartbeat vocabulary,
flake/failure classification, and proof-bundle/release-gate consumers before a
permissioned worker runs the long profile.

```bash
cargo run -p ffs-harness -- validate-soak-canary-campaigns \
  --manifest benchmarks/soak_canary_campaign_manifest.json \
  --artifact-root artifacts/soak/dry-run \
  --out artifacts/soak/campaign_report.json \
  --artifact-out artifacts/soak/sample_artifact_manifest.json \
  --summary-out artifacts/soak/campaign_summary.md
```

The E2E smoke is bounded and safe for local CI:

```bash
./scripts/e2e/ffs_soak_canary_campaign_e2e.sh
```

Long profiles are intended for RCH, CI, or manual permissioned hosts. They must
record kernel, FUSE capability, toolchain, git SHA, workload IDs, seeds,
duration, resource usage, cleanup status, and reproduction command. Recurring
flakes are never swallowed: campaign output must preserve reproduction data and
link a follow-up bead.

### Repair Writeback Serialization

The repair/writeback serialization contract freezes the read-write mounted
automatic-repair policy: mutating repair must fail closed until repair
writeback and client writes share one serializer. The validator checks the
state machine, MVCC snapshot and fsync/fsyncdir boundaries, repair ownership
lease checks, stale-symbol refusal, cancellation cleanup, halfway writeback
failure handling, required evidence fields, and the expected-loss decision that
keeps `repair.rw.writeback` disabled.

```bash
cargo run -p ffs-harness -- validate-repair-writeback-serialization \
  --contract docs/repair-writeback-serialization-contract.json \
  --artifact-root artifacts/repair-writeback/dry-run \
  --out artifacts/repair-writeback/contract_report.json \
  --artifact-out artifacts/repair-writeback/sample_artifact_manifest.json \
  --summary-out artifacts/repair-writeback/contract_summary.md
```

The E2E smoke is bounded and does not require a permissioned FUSE host:

```bash
./scripts/e2e/ffs_repair_writeback_serialization_e2e.sh
```

The fail-closed artifact must include `operation_id`, `scenario_id`,
`snapshot_epoch`, `lease_id`, `repair_symbol_version`, `expected_state`,
`observed_state`, `error_class`, `artifact_paths`, `cleanup_status`,
`reproduction_command`, and `follow_up_bead`.

### Permissioned FUSE Lane

The durable mounted-test lane is the production FUSE runner on a Linux worker
with `/dev/fuse`, `fusermount3` or `fusermount`, `mountpoint`, `e2fsprogs`, and
`btrfs-progs` installed. The lane must run on the same host where mount
attempts occur; offloading only `cargo build` is not enough to prove mount
permissions.

Local permissioned worker command:

```bash
FFS_USE_RCH=0 \
FFS_RUN_BTRFS_LANE_PROBE=1 \
FFS_REQUIRE_BTRFS_LANE_PROBE=1 \
./scripts/e2e/ffs_fuse_production.sh
```

RCH worker command, for workers configured with FUSE access:

```bash
rch exec -- bash -lc 'cd /data/projects/frankenfs && \
  FFS_USE_RCH=0 \
  FFS_RUN_BTRFS_LANE_PROBE=1 \
  FFS_REQUIRE_BTRFS_LANE_PROBE=1 \
  ./scripts/e2e/ffs_fuse_production.sh'
```

The runner emits these shared QA artifacts under
`artifacts/e2e/<timestamp>_ffs_fuse_production/`:

| Artifact | Purpose |
|----------|---------|
| `fuse_capability.json` | Structured host capability result, skip reason, failure kind, remediation hint, and mount/unmount probe checks |
| `fuse_permissioned_lane.json` | Worker identity, kernel, fusermount version, mount options, stdout/stderr paths, cleanup status, and artifact index |
| `mounted_scenario_matrix.json` | Per-scenario ext4/btrfs mount matrix with filesystem flavor, mount options, operation sequence, expected/actual outcome, duration, and artifact references |
| `junit.xml` | CI-readable suite status, including permissioned-lane probe cases |
| `run.log` | Full command transcript and diagnostics |
| `mount_*.log` | Per-mount stdout/stderr from `ffs-cli mount` |

`FFS_RUN_BTRFS_LANE_PROBE=1` is the default for the production runner and makes
the lane perform an actual minimal btrfs mount/unmount after fixture creation.
`FFS_REQUIRE_BTRFS_LANE_PROBE=1` turns a missing btrfs fixture/toolchain into a
hard lane failure. If the lane loses `/dev/fuse` access, fusermount, kernel
support, or mount permissions, the runner records `fuse_capability.json` and
skips/fails with the canonical `skip_reason` / `failure_kind` instead of
silently passing.

Every recorded production FUSE case also emits a
`SCENARIO_RESULT|scenario_id=...|outcome=...` line and is materialized into
`mounted_scenario_matrix.json`, which is the durable evidence artifact for the
critical ext4 and btrfs mounted scenario matrix.

### Operational Outcome Vocabulary

Readiness-grade artifacts use a closed vocabulary so users can distinguish product failures from host and harness conditions:

| Field | Values | Notes |
|-------|--------|-------|
| `classification` | `pass`, `fail`, `skip`, `error` | `error` is reserved for harness, worker, or host failures that prevent a product verdict |
| `skip_reason` | `fuse_unavailable`, `fuse_permission_denied`, `user_disabled`, `worker_dependency_missing`, `unsupported_v1_scope`, `root_owned_btrfs_testdir_eacces`, `not_applicable` | Required for every skip |
| `error_class` | `product_failure`, `harness_bug`, `worker_dependency_missing`, `fuse_permission_skip`, `root_owned_btrfs_testdir_eacces`, `unsupported_v1_scope`, `stale_tracker_tooling_failure`, `unsafe_cleanup_failure`, `resource_limit`, `host_environment_failure` | Required for fail/error |
| `cleanup_status` | `clean`, `preserved_artifacts`, `failed`, `not_run` | `not_run` is invalid for operational readiness validation |

Required sample surfaces are covered by the `artifact_manifest` unit tests: xfstests subset reports, FUSE capability probes, mounted ext4/btrfs scenarios, fuzz smoke outputs, performance baselines, and writeback-cache crash matrices.

### Retention Policy

The default retention policy is explicit and testable:

- retain manifests for 90 days by default
- keep at most 50 manifests per gate
- prune when total artifact storage exceeds 500 MiB
- preserve failing manifests for twice the normal max-age window
- allow per-category overrides for longer-lived artifact families such as fuzz crash packs

### Proof Overhead Budget Gate

Proof instrumentation, repair labs, crash/replay traces, RCH uploads, and
operator summaries must stay bounded before release gates can require them. The
budget evaluator lives in `crates/ffs-harness/src/proof_overhead_budget.rs` and
is exposed through:

```bash
rch exec -- cargo run -p ffs-harness -- validate-proof-overhead-budget \
  --budget artifacts/proof/budget.json \
  --metrics artifacts/proof/metrics.json \
  --out artifacts/proof/budget_report.json
```

The budget JSON declares the profile, baseline id and capture timestamp,
pass/warn/fail thresholds, exception ids, retention policy, required log
fields, and release-gate consumers. The metrics JSON records one bounded proof
workflow with scenario id, profile, baseline id, observed metric values,
artifact sizes, compression candidates, and the reproduction command.

Failures mean either a required metric is missing, the baseline is stale, a
threshold moved past `fail_at`, an exception expired or lacks user-impact
metadata, or retention would drop mandatory proof/reproduction evidence.
Warnings mean the gate can continue but the report must stay visible, usually
because a metric crossed `warn_at`, compression is required, or a valid
time-limited exception is active. To update a baseline, rerun the bounded proof
workflow, write a new baseline id and `baseline_captured_at`, keep the previous
report for comparison, and do not raise thresholds without recording the user
impact and follow-up bead.

The E2E smoke is:

```bash
./scripts/e2e/ffs_proof_overhead_budget_e2e.sh
```

It captures a small proof-style harness run, writes metrics, evaluates the
sample budget, verifies the release-gate log fields, and runs the module unit
tests.

### Proof Bundle Validation

Proof bundles are offline inspection packs for readiness claims. Each bundle is
a directory rooted at a versioned `manifest.json` that records the schema
version, bundle id, generation timestamp, git SHA, toolchain, kernel, mount
capability, required lanes, raw logs, summaries, gate inputs, artifact paths,
SHA-256 hashes, scenario ids, and redaction policy. The required lanes are
`conformance`, `xfstests`, `fuse`, `differential_oracle`, `repair_lab`,
`crash_replay`, `performance`, `writeback_cache`, and `release_gates`.

Validate a bundle with:

```bash
rch exec -- cargo run -p ffs-harness -- validate-proof-bundle \
  --bundle artifacts/proof/bundle/manifest.json \
  --current-git-sha "$(git rev-parse HEAD)" \
  --max-age-days 14 \
  --out artifacts/proof/bundle/report.json \
  --summary-out artifacts/proof/bundle/summary.md
```

The JSON report includes pass/fail/skip/error totals, missing required lanes,
duplicate lane/scenario ids, stale SHA or timestamp diagnostics, broken links,
artifact hash mismatches, redaction errors, and per-lane raw-log/summary links.
The Markdown summary is the human inspection view and must preserve the
`validate-proof-bundle` reproduction command. Validation is fail-closed: stale
schema versions, stale git SHAs, old timestamps, absolute or parent-traversal
paths, missing files, wrong SHA-256 hashes, duplicate scenario ids, and
redaction policies that remove reproduction fields all fail the gate.

The E2E smoke is:

```bash
./scripts/e2e/ffs_proof_bundle_e2e.sh
```

It builds a sample bundle with every required lane, validates it, writes
JSON/Markdown inspection artifacts, rejects hash drift, stale SHA, and missing
artifact links, then runs the module unit tests.

## Adversarial Image Threat Model

The adversarial-image threat model is the executable security contract for
hostile filesystem images, hostile proof artifacts, tampered repair ledgers,
resource-exhaustion seeds, unsupported mount options, and unsafe operator
commands. It is a bounded CI smoke, not a replacement for long fuzz campaigns.

Validate the checked-in model without mounting hostile inputs:

```bash
cargo run -p ffs-harness -- validate-adversarial-threat-model \
  --model security/adversarial_image_threat_model.json \
  --artifact-root artifacts/security/dry-run \
  --out artifacts/security/threat_model_report.json \
  --artifact-out artifacts/security/sample_artifact_manifest.json \
  --wording-out artifacts/security/security_wording.tsv
```

The validator rejects traversal and symlink artifact paths, missing log fields,
unreviewed critical threat classes, missing resource caps, unsafe operator
promotion, and any public wording that would let docs alone promote
hostile-image readiness.

The E2E smoke is:

```bash
./scripts/e2e/ffs_adversarial_threat_model_e2e.sh
```

## Performance Baseline Manifest

The performance baseline manifest is the executable contract for benchmark
evidence. It lists representative workloads, command templates, required host
capabilities, datasets, run counts, metric units, thresholds, output artifact
paths, aggregate fields, required environment fields, and required structured
log fields.

Validate the checked-in manifest without running heavyweight benchmarks:

```bash
cargo run -p ffs-harness -- validate-performance-baseline-manifest \
  --manifest benchmarks/performance_baseline_manifest.json \
  --artifact-root artifacts/performance/dry-run \
  --out artifacts/performance/manifest_report.json \
  --artifact-out artifacts/performance/sample_artifact_manifest.json
```

The validator expands command templates, rejects unknown capabilities, invalid
metric units, missing thresholds, missing environment fields, and
non-aggregatable artifact fields, then writes a sample shared QA artifact
manifest that downstream baseline runs can reuse.

The E2E smoke is:

```bash
./scripts/e2e/ffs_performance_manifest_e2e.sh
```

It validates the checked-in manifest, checks dry-run command and artifact
expansion, rejects malformed manifest variants, and runs the module unit tests.

## Release Gate Evaluation

Release gates are executable policy files that consume a validated proof bundle
and emit feature states plus generated public wording. The evaluator is
fail-closed: stale proof bundles, missing required lanes, lane failures, broken
artifacts, and threshold failures downgrade or block user-facing claims.

Evaluate a bundle with:

```bash
rch exec -- cargo run -p ffs-harness -- evaluate-release-gates \
  --bundle artifacts/proof/bundle/manifest.json \
  --policy artifacts/proof/release_gate_policy.json \
  --current-git-sha "$(git rev-parse HEAD)" \
  --max-age-days 14 \
  --out artifacts/proof/release_gate.json \
  --wording-out artifacts/proof/release_gate_wording.tsv
```

Policy features declare `previous_state`, `target_state`, required proof-bundle
lanes, threshold checks, kill switches, docs wording ids, and remediation beads
or explicit non-goal rationale. Supported states are `hidden`, `disabled`,
`deprecated_blocked`, `dry_run_only`, `detection_only`, `experimental`,
`opt_in_mutating`, and `validated`.

The JSON report records the final feature state, whether an upgrade is allowed,
all downgrade findings, controlling lane or artifact, threshold value,
observed value, remediation id, docs wording id, required log fields, and the
reproduction command. README and FEATURE_PARITY-safe wording should be copied
from `generated_wording` or `--wording-out`, not hand-written ahead of gate
data.

The E2E smoke is:

```bash
./scripts/e2e/ffs_release_gate_e2e.sh
```

It builds a passing proof bundle and policy, verifies generated wording, then
proves missing evidence, stale SHA, and threshold failures are rejected with
machine-readable diagnostics.

### Redaction Policy

The default redaction policy is designed for shareable audit packs:

- redact hostnames from environment fingerprints
- scrub sensitive metadata keys such as `token`, `password`, `secret`, and `api_key`
- strip absolute paths down to relative paths
- mark affected artifact entries as `redacted: true`

Validation for this contract is enforced by the `artifact_manifest` unit tests in `ffs-harness` and by the shared `ffs_log_contract_e2e.sh` smoke checks.

## What It Tests

The smoke test exercises:

1. **Build** - `cargo build --workspace`
2. **CLI Commands**
   - `ffs inspect` - Parse and display filesystem metadata
   - `ffs scrub` - Validate filesystem integrity
   - `ffs parity` - Show feature parity report
3. **FUSE Mount** (if `/dev/fuse` available)
   - Mount an ext4 image read-only
   - List directory contents
   - Read file contents
   - Unmount cleanly

The production FUSE runtime suite exercises:

1. Mount lifecycle checks for RW/RO startup and clean teardown
2. Concurrent read/write worker probes against mounted ext4 fixtures
3. Xattr operations (`set`, `get`, `list`, `remove`) for runtime surface validation
4. SIGTERM shutdown durability verification with remount validation
5. Throughput/latency baseline capture to `perf_baseline.json`
6. Btrfs inspect plus read-only mount/stat/list/unmount smoke when `mkfs.btrfs` is available
7. JUnit and mounted matrix artifact generation under `artifacts/e2e/<timestamp>_ffs_fuse_production/`

The write-back E2E suite exercises:

1. Basic flush correctness (1000 committed blocks)
2. Clean shutdown flush-all behavior
3. Simulated SIGKILL durability boundary (fsync vs non-fsync)
4. Abort lifecycle discard behavior
5. Backpressure under sustained write load
6. Concurrent commit/abort transactions with daemon flush

The graceful degradation stress suite exercises:

1. Deterministic degradation FSM and backpressure gates (`ffs-core` targeted tests)
2. FUSE surface regression checks under the current backpressure wiring (`ffs-fuse` tests)
3. Optional host pressure probe with `stress-ng` while monitor tests execute
4. Optional live mount pressure probe (`FFS_RUN_MOUNT_STRESS=1`) that verifies reads stay functional under CPU stress

The ext4 read-write smoke suite exercises:

1. Rootless fixture lifecycle: create `base.ext4`, copy to `work.ext4`, mount only the work image
2. RW operations: create/write/overwrite, mkdir/rmdir, rename, unlink
3. Metadata checks (phase-gated): chmod verification and mtime monotonicity
4. Clean shutdown persistence: remount read-only and re-verify post-unmount state
5. Deterministic crash phase: write + fsync 500 baseline files, run continuous in-flight writes, SIGKILL mount daemon, remount read-only, and verify baseline + fsync durability invariants

The ext4 read-only round-trip suite exercises:

1. Fixture lifecycle: use configured/default ext4 fixture image (or create deterministic fallback)
2. Reference extraction: `debugfs rdump` of the full filesystem tree to a host-side reference directory
3. Metadata assertions: `ffs inspect --json` checks for superblock fields, free-space accounting consistency, and orphan diagnostics shape
4. Read-only FUSE mount and full tree walk comparison against reference extraction
5. Per-file BLAKE3 digest comparison (`b3sum`) between reference tree and mounted view
6. Journal replay reporting check when crash recovery is triggered by the image state
7. Runtime guard: suite fails if elapsed duration exceeds configured bound (default 30 seconds)

The btrfs read-write smoke suite exercises:

1. Fixture lifecycle: create a fresh 256MiB mkfs.btrfs image, then fallback to a known-good btrfs fixture if current parser support is incomplete
2. RW operations: create/write/overwrite (small/4KB/1MB), append, truncate extend/shrink
3. Unsupported-operation contract: punch-hole and unsupported-mode-bit `fallocate` rejections with expected `EOPNOTSUPP`, including no-side-effect checks
4. Directory/name/link operations: mkdir/rmdir, rename within/across dir, rename-overwrite, unlink, symlink, hardlink, and inode-sharing checks
5. COW-oriented checks: repeated rewrites of a hot file with superblock generation/root snapshots before/after write bursts
6. Persistence checks: clean unmount, read-only remount, and post-remount data/metadata validation
7. Deterministic crash matrix: 10 SIGKILL crash points across create/write/rename/unlink with per-scenario image artifacts, post-crash inspect output, and read-only remount invariants
8. Structured sync observability checks at fsync boundaries (`btrfs_sync_applied` with `operation_id` + `scenario_id` in mount logs)
9. CI artifacts: structured per-test timing logs, machine-parseable `SCENARIO_RESULT|scenario_id=...` markers, and a `junit.xml` report under the suite artifact directory

The mounted recovery matrix suite exercises:

1. Recovery matrix validation for `bd-rchk0.3.3`
2. Clean unmount, forced unmount, process termination, fsync-file, fsync-dir, reopen, and cleanup lifecycle rows
3. Safe process-control boundaries for temporary images and mount-daemon scoped termination
4. Shared QA artifacts with pre-crash operations, crash/unmount point, recovery command, expected survivors, actual state artifact, stdout/stderr paths, cleanup status, and product/host/harness/unsupported classification vocabulary
5. Fail-closed validation for missing lifecycle coverage and unsafe recovery commands

The proof bundle suite exercises:

1. `validate-proof-bundle` CLI wiring and module export
2. Sample bundle generation with every required readiness lane
3. JSON report and Markdown summary generation with pass/fail/skip/error totals
4. Raw log, summary, gate input, and artifact link preservation for offline inspection
5. Fail-closed validation for artifact hash drift, stale git SHA, and missing artifact links
6. Redaction policy unit coverage that preserves reproduction commands and artifact/scenario fields

The release gate suite exercises:

1. `evaluate-release-gates` CLI wiring and module export
2. Passing proof-bundle evidence consumed through policy-as-data
3. Generated README/FEATURE_PARITY-safe wording from final feature states
4. Fail-closed validation for missing evidence, stale evidence, and threshold failures
5. Required log fields for downgrade findings, remediation ids, docs wording ids, and reproduction commands
6. Unit coverage for feature-state transitions, kill switches, capability skips, explicit deferrals, and hand-edit-resistant wording

The performance manifest suite exercises:

1. `validate-performance-baseline-manifest` CLI wiring and module export
2. Checked-in workload manifest validation without running heavy benchmarks
3. Dry-run command expansion for cargo bench and mounted FUSE probe workloads
4. Sample shared QA artifact manifest emission for benchmark baseline/report outputs
5. Fail-closed validation for unknown capabilities, missing environment fields, invalid metric units, and non-aggregatable artifact fields
6. Unit coverage for workload ids, thresholds, capability vocabulary, metric units, artifact aggregation, and shared QA schema mapping

The adversarial threat model suite exercises:

1. `validate-adversarial-threat-model` CLI wiring and module export
2. Checked-in hostile-image and hostile-artifact model validation
3. Dry-run coverage for malformed image, hostile proof path, missing host capability, resource cap, repair-ledger tamper, unsupported mount option, and unsafe operator command cases
4. Sample shared QA artifact manifest and generated docs-safe wording
5. Fail-closed validation for path traversal, unreviewed critical threats, missing log fields, zero resource caps, and unsafe operator-command promotion
6. Unit coverage for path canonicalization, symlink refusal, redaction, release-gate fail-closed behavior, and shared QA schema mapping

The btrfs read-only smoke suite exercises:

1. Runtime btrfs fixture generation via `scripts/fixtures/make_btrfs_reference_image.sh`
2. `ffs inspect --json` geometry capture (sectorsize/nodesize logged in test header)
3. Read-only `ffs mount` behavior through `/dev/fuse`
4. Basic black-box operations: `ls`, `stat`, bounded `find`, and `cat` of a known fixture file when present
5. Reliable unmount with actionable mount-log diagnostics on failure

The repair recovery smoke suite exercises:

1. Deterministic bounded random block corruption across repair groups (currently 5% in the test harness)
2. Background scrub daemon auto-detection and auto-recovery
3. Full before/after block digest equivalence checks
4. Structured evidence ledger capture and artifact export under `artifacts/e2e/<timestamp>_ffs_repair_recovery_smoke/repair/`

If rch offload runs the test but does not materialize custom artifact files locally, the script exits with `SKIPPED` unless `FFS_REPAIR_LOCAL_ARTIFACT_FALLBACK=1` is set.

The xfstests E2E suite exercises:

1. Curated generic/ext4 subset selection from tracked list files
2. Planning artifacts for CI (`selected_tests.txt`, `summary.json`)
3. Optional direct `xfstests check` execution when a configured checkout is available
4. Structured result artifacts (`results.json`, `junit.xml`) for per-commit tracking
5. Regression guard enforcement in run mode (`must_pass`, `min_pass_count`, `min_pass_rate`)
6. Safe skip/fail behavior via strictness toggle

## Output

Test artifacts are stored in `artifacts/e2e/<timestamp>/`:

```
artifacts/e2e/20260212_161500_ffs_smoke/
└── run.log    # Complete test log with timestamps
```

The current suites still emit their native logs/reports directly. The shared artifact-manifest schema above is the canonical representation those outputs must conform to as the verification runner contract is adopted across suites.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Rust log level (trace, debug, info, warn, error) |
| `RUST_BACKTRACE` | `1` | Enable backtraces on panic |
| `SKIP_MOUNT` | `0` | Set to `1` to skip FUSE mount tests |
| `FFS_AUTO_UNMOUNT` | `0` (for ext4 RW smoke, btrfs RW smoke, and fuse production) | Passed through to `ffs mount`; set `0` to avoid implicit `allow_other` on rootless fuse3 setups |
| `FFS_ALLOW_OTHER` | `0` | For `ffs_fuse_production.sh`: if `1`, passes `--allow-other` to `ffs mount` |
| `FFS_CLI_BIN` | `target/release/ffs-cli` | Path to local `ffs-cli` binary used by RW mount/inspect steps |
| `FFS_SKIP_BUILD` | `0` | For `ffs_ext4_rw_smoke.sh`: if `1`, skip `cargo build` and use existing `FFS_CLI_BIN` (useful for privileged reruns after an `rch` build) |
| `EXT4_ROUNDTRIP_IMAGE` | *(unset)* | Optional path to ext4 image for `ffs_ext4_ro_roundtrip.sh`; if unset, defaults to `tests/fixtures/images/ext4_small.img` and falls back to generated image when missing |
| `EXT4_ROUNDTRIP_MAX_SECS` | `30` | Max allowed runtime (seconds) for `ffs_ext4_ro_roundtrip.sh` |
| `BASELINE_FILE_COUNT` | `500` | Number of fsync-backed baseline files written before SIGKILL phase |
| `CRASH_WRITER_RUNTIME_SECS` | `2` | Duration to run background in-flight writer before sending SIGKILL |
| `CRASH_WRITER_SLEEP_SECS` | `0.01` | Per-write pacing interval for crash in-flight writer |
| `CRASH_MATRIX_POINTS` | `10` | For `ffs_btrfs_rw_smoke.sh`: fixed deterministic crash-point matrix cardinality (must remain 10) |
| `FFS_REPAIR_LOCAL_ARTIFACT_FALLBACK` | `0` | For `ffs_repair_recovery_smoke.sh`: if `1`, re-run repair test locally when rch offload does not materialize artifact files |
| `FFS_USE_RCH` | `1` | For `ffs_degradation_stress.sh`, `ffs_fuse_production.sh`, `ffs_btrfs_rw_smoke.sh`, `ffs_ext4_ro_roundtrip.sh`, and `ffs_ext4_rw_smoke.sh`: offload cargo commands via `rch exec -- cargo ...` when available |
| `FFS_RUN_BTRFS_LANE_PROBE` | `1` | For `ffs_fuse_production.sh`: if `1`, attempt a minimal btrfs mount/unmount in the permissioned-lane probe |
| `FFS_REQUIRE_BTRFS_LANE_PROBE` | `0` | For `ffs_fuse_production.sh`: if `1`, fail the permissioned lane when btrfs fixture generation or btrfs mount/unmount probing cannot run |
| `FFS_MOUNTED_RECOVERY_MATRIX` | `tests/workload-matrix/mounted_recovery_matrix.json` | Optional matrix path for `ffs_mounted_recovery_matrix_e2e.sh` |
| `FFS_RUN_MOUNT_STRESS` | `0` | For `ffs_degradation_stress.sh`: if `1`, attempt optional live FUSE mount pressure probe |
| `DEGRADATION_STRESS_DURATION_SECS` | `20` | Duration for host `stress-ng` probe in `ffs_degradation_stress.sh` |
| `DEGRADATION_STRESS_CPU_WORKERS` | `4` | CPU workers for host `stress-ng` probe in `ffs_degradation_stress.sh` |
| `DEGRADATION_STRESS_VM_WORKERS` | `1` | VM workers for host `stress-ng` probe in `ffs_degradation_stress.sh` |
| `DEGRADATION_STRESS_VM_BYTES` | `60%` | VM memory pressure setting for host `stress-ng` probe in `ffs_degradation_stress.sh` |
| `DEGRADATION_MOUNT_STRESS_DURATION_SECS` | `15` | Duration for optional mount pressure probe in `ffs_degradation_stress.sh` |
| `DEGRADATION_MOUNT_STRESS_CPU_WORKERS` | `4` | CPU workers for optional mount pressure probe in `ffs_degradation_stress.sh` |
| `XFSTESTS_MODE` | `auto` | `auto`, `plan`, or `run` for `ffs_xfstests_e2e.sh` |
| `XFSTESTS_DIR` | *(unset)* | Path to xfstests checkout containing `check` |
| `XFSTESTS_DRY_RUN` | `1` | In run mode, pass `-n` to `check` (selection validation without executing tests) |
| `XFSTESTS_FILTER` | `all` | Select `all`, `generic`, or `ext4` curated subsets |
| `XFSTESTS_STRICT` | `0` | If `1`, missing xfstests prerequisites fail instead of skip |
| `XFSTESTS_REGRESSION_GUARD_JSON` | `scripts/e2e/xfstests_regression_guard.json` | Regression guard config used in run mode to fail on must-pass or pass-rate regressions |

## Requirements

- Rust toolchain (nightly)
- `python3` (used by concurrency/perf probes in `ffs_fuse_production.sh`)
- `mkfs.ext4` and `debugfs` (e2fsprogs)
- `b3sum` **or** Python package `blake3` (required by `ffs_ext4_ro_roundtrip.sh` for BLAKE3 digest verification)
- `mkfs.btrfs` and `btrfs` (btrfs-progs)
- `/dev/fuse` accessible (for mount tests)
- `fusermount` or `fusermount3` (for unmounting)
- `mountpoint` utility (used for readiness checks)
- Optional for xfstests execution mode: an `xfstests-dev` checkout with built prerequisites

## Skipping Mount Tests

Mount tests are automatically skipped if:
- `/dev/fuse` doesn't exist
- `/dev/fuse` isn't readable/writable
- `mkfs.btrfs` / `btrfs` tools are unavailable for btrfs fixture generation
- `fuse3` rejects implicit `allow_other` because `user_allow_other` is not enabled in `/etc/fuse.conf`
- `fusermount` returns `Permission denied` / `Operation not permitted` for the current runtime environment
- `SKIP_MOUNT=1` is set

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All tests passed (or skipped with message) |
| 1 | Test failure |

## Troubleshooting

### "Permission denied" on /dev/fuse

Add your user to the `fuse` group:
```bash
sudo usermod -aG fuse $USER
# Log out and back in
```

Or run with sudo (not recommended).

### Mount times out

Check if another FUSE process is hanging:
```bash
ps aux | grep ffs
fusermount -u /path/to/mount
```

### Build fails

Ensure dependencies are available:
```bash
# Check for asupersync and ftui in parent directory
ls -la /dp/asupersync /dp/frankentui
```

## CI Integration

The E2E tests can be run in CI by:

1. Installing dependencies:
   ```bash
   sudo apt-get install -y e2fsprogs fuse3
   ```

2. Running with mount tests skipped (if FUSE not available):
   ```bash
   SKIP_MOUNT=1 ./scripts/e2e/ffs_smoke.sh
   ```

3. Running xfstests subset planning (CI-safe, no xfstests checkout required):
   ```bash
   XFSTESTS_MODE=plan ./scripts/e2e/ffs_xfstests_e2e.sh
   ```

4. Running xfstests subset execution (requires configured checkout):
   ```bash
   XFSTESTS_MODE=run XFSTESTS_DIR=/path/to/xfstests-dev ./scripts/e2e/ffs_xfstests_e2e.sh
   ```

5. Adjusting regression thresholds:
   ```bash
   cat scripts/e2e/xfstests_regression_guard.json
   ```

## Adding New Tests

1. Source `lib.sh` for helpers
2. Use `e2e_step`, `e2e_run`, `e2e_assert` for structure
3. Use `e2e_skip` for optional features
4. Use `e2e_fail` for failures
5. Call `e2e_pass` at the end

Example:
```bash
#!/usr/bin/env bash
cd "$(dirname "$0")/../.."
source scripts/e2e/lib.sh

e2e_init "my_test"
e2e_print_env

e2e_step "My Test"
e2e_assert cargo test -p my-crate

e2e_pass
```
