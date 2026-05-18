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

# Verify the write-back wrapper RCH capture contract without running cargo
FFS_E2E_DISABLE_TEMP_CLEANUP=1 FFS_WRITEBACK_SELF_CHECK=1 ./scripts/e2e/ffs_writeback_e2e.sh

# Run graceful degradation stress suite
./scripts/e2e/ffs_degradation_stress.sh

# Run deterministic corruption-injection + recovery smoke
./scripts/e2e/ffs_repair_recovery_smoke.sh

# Verify the repair recovery smoke RCH capture and artifact contract without running cargo
FFS_E2E_DISABLE_TEMP_CLEANUP=1 FFS_REPAIR_RECOVERY_SMOKE_SELF_CHECK=1 ./scripts/e2e/ffs_repair_recovery_smoke.sh

# Verify the repair exchange loopback RCH capture contract without running cargo
FFS_E2E_DISABLE_TEMP_CLEANUP=1 FFS_REPAIR_EXCHANGE_LOOPBACK_SELF_CHECK=1 ./scripts/e2e/ffs_repair_exchange_loopback_e2e.sh

# Plan/run curated xfstests generic+ext4 subsets
./scripts/e2e/ffs_xfstests_e2e.sh

# Run hermetic xfstests prerequisite preflight self-test
# (current host plus missing-tool, permission, dpkg-lock, worker, and unsupported-local fixtures)
./scripts/e2e/ffs_xfstests_preflight_e2e.sh --self-test

# Run proof overhead budget release-gate smoke
./scripts/e2e/ffs_proof_overhead_budget_e2e.sh

# Run proof bundle offline validation smoke
./scripts/e2e/ffs_proof_bundle_e2e.sh

# Run release-gate policy evaluator smoke
./scripts/e2e/ffs_release_gate_e2e.sh

# Run the V1.2 program gate rollup and emit the release recommendation manifest
./scripts/e2e/ffs_v12_program_gate_e2e.sh

# Run invariant-oracle replay/minimization and consumer-validation smoke
./scripts/e2e/ffs_invariant_oracle_e2e.sh

# Run mounted differential oracle allowlist/host-skip validation smoke
./scripts/e2e/ffs_mounted_differential_oracle_e2e.sh

# Run cross-oracle disagreement arbitration validation smoke
./scripts/e2e/ffs_cross_oracle_arbitration_e2e.sh

# Verify the OQ decision integration RCH capture contract without running cargo
FFS_E2E_DISABLE_TEMP_CLEANUP=1 FFS_OQ_DECISION_INTEGRATION_SELF_CHECK=1 ./scripts/e2e/ffs_oq_decision_integration_e2e.sh

# Run P1 workload corpus schema and proof-consumer coverage smoke
./scripts/e2e/ffs_workload_corpus_e2e.sh

# Run swarm tail-latency decomposition ledger validation
./scripts/e2e/ffs_swarm_tail_latency_e2e.sh

# Run NUMA-aware swarm workload harness dry-run validation
./scripts/e2e/ffs_swarm_workload_harness_e2e.sh

# Verify the MVCC lifecycle RCH capture contract without running cargo
FFS_E2E_DISABLE_TEMP_CLEANUP=1 FFS_MVCC_LIFECYCLE_SELF_CHECK=1 ./scripts/e2e/ffs_mvcc_lifecycle_e2e.sh

# Verify the self-healing demo RCH capture contract without running cargo
FFS_E2E_DISABLE_TEMP_CLEANUP=1 FFS_SELF_HEALING_DEMO_SELF_CHECK=1 ./scripts/e2e/ffs_self_healing_demo.sh

# Verify the repair 5pct RCH capture and artifact contract without running cargo
FFS_E2E_DISABLE_TEMP_CLEANUP=1 FFS_REPAIR_5PCT_SELF_CHECK=1 ./scripts/e2e/ffs_repair_5pct_e2e.sh

# Verify the readiness action autopilot RCH capture contract without running cargo
FFS_E2E_DISABLE_TEMP_CLEANUP=1 FFS_READINESS_ACTION_AUTOPILOT_SELF_CHECK=1 ./scripts/e2e/ffs_readiness_action_autopilot_e2e.sh

# Verify the btrfs capability drift RCH capture contract without running cargo
FFS_E2E_DISABLE_TEMP_CLEANUP=1 FFS_BTRFS_CAPABILITY_DRIFT_SELF_CHECK=1 ./scripts/e2e/ffs_btrfs_capability_drift_e2e.sh

# Verify the version-store format RCH capture contract without running cargo
FFS_E2E_DISABLE_TEMP_CLEANUP=1 FFS_VERSION_STORE_FORMAT_SELF_CHECK=1 ./scripts/e2e/ffs_version_store_format_e2e.sh

# Verify the fuzz dashboard RCH capture contract without running cargo
FFS_E2E_DISABLE_TEMP_CLEANUP=1 FFS_FUZZ_DASHBOARD_SELF_CHECK=1 ./scripts/e2e/ffs_fuzz_dashboard_e2e.sh

# Verify the perf comparison RCH capture contract without running cargo
FFS_E2E_DISABLE_TEMP_CLEANUP=1 FFS_PERF_COMPARISON_SELF_CHECK=1 ./scripts/e2e/ffs_perf_comparison_e2e.sh

# Verify the benchmark taxonomy RCH capture contract without running cargo
FFS_E2E_DISABLE_TEMP_CLEANUP=1 FFS_BENCHMARK_TAXONOMY_SELF_CHECK=1 ./scripts/e2e/ffs_benchmark_taxonomy_e2e.sh

# Verify the artifact schema fixture RCH capture contract without running cargo
FFS_E2E_DISABLE_TEMP_CLEANUP=1 FFS_ARTIFACT_SCHEMA_FIXTURES_SELF_CHECK=1 ./scripts/e2e/ffs_artifact_schema_fixtures_e2e.sh

# Verify the evidence presets RCH capture contract without running cargo
FFS_E2E_DISABLE_TEMP_CLEANUP=1 FFS_EVIDENCE_PRESETS_SELF_CHECK=1 ./scripts/e2e/ffs_evidence_presets_e2e.sh

# Verify the evidence metrics presets RCH capture contract without running cargo
FFS_E2E_DISABLE_TEMP_CLEANUP=1 FFS_EVIDENCE_METRICS_PRESETS_SELF_CHECK=1 ./scripts/e2e/ffs_evidence_metrics_presets_e2e.sh

# Verify the operator tooling gate RCH capture contract without running cargo
FFS_E2E_DISABLE_TEMP_CLEANUP=1 FFS_OPERATOR_TOOLING_GATE_SELF_CHECK=1 ./scripts/e2e/ffs_operator_tooling_gate_e2e.sh

# Verify the tabletop drill RCH capture contract without running cargo
FFS_E2E_DISABLE_TEMP_CLEANUP=1 FFS_TABLETOP_DRILL_SELF_CHECK=1 ./scripts/e2e/ffs_tabletop_drill_e2e.sh

# Verify the error taxonomy RCH capture contract without running cargo
FFS_E2E_DISABLE_TEMP_CLEANUP=1 FFS_ERROR_TAXONOMY_SELF_CHECK=1 ./scripts/e2e/ffs_error_taxonomy_e2e.sh

# Verify the health consistency RCH capture contract without running cargo
FFS_E2E_DISABLE_TEMP_CLEANUP=1 FFS_HEALTH_CONSISTENCY_SELF_CHECK=1 ./scripts/e2e/ffs_health_consistency_e2e.sh

# Verify the log contract RCH capture contract without running cargo
FFS_E2E_DISABLE_TEMP_CLEANUP=1 FFS_LOG_CONTRACT_SELF_CHECK=1 ./scripts/e2e/ffs_log_contract_e2e.sh

# Run performance baseline manifest dry-run validation
./scripts/e2e/ffs_performance_manifest_e2e.sh

# Run adversarial-image threat model dry-run validation
./scripts/e2e/ffs_adversarial_threat_model_e2e.sh

# Run soak/canary campaign manifest dry-run validation
./scripts/e2e/ffs_soak_canary_campaign_e2e.sh

# Run docs status wording drift validation
./scripts/e2e/ffs_docs_status_drift_e2e.sh

# Run open-ended inventory and source-scope scanner validation
./scripts/e2e/ffs_open_ended_inventory_scanner_e2e.sh

# Run repair confidence mutation-safety threshold validation
./scripts/e2e/ffs_repair_confidence_lab_e2e.sh

# Run repair/writeback serialization contract dry-run validation
./scripts/e2e/ffs_repair_writeback_serialization_e2e.sh

# Run repair/writeback mounted route smoke
./scripts/e2e/ffs_repair_writeback_route_e2e.sh
```

## Preserving Temp Artifacts

Scripts that source `scripts/e2e/lib.sh` remove their registered temp
directories on exit during ordinary CI runs. Set
`FFS_E2E_DISABLE_TEMP_CLEANUP=1` for operator inspection, no-delete agent
sessions, or debugging runs that must preserve temp directories and direct
`mktemp` logs.

## Source-Scope Scanner Policy

`./scripts/e2e/ffs_open_ended_inventory_scanner_e2e.sh` validates the
open-ended note scanner and the source-scope manifest. The direct source-scope
command for agent runs is:

```bash
rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenfs_source_scope \
  cargo run --quiet -p ffs-harness -- validate-source-scope-manifest \
  --manifest tests/source-scope-manifest/source_scope_manifest.json \
  --workspace-root . \
  --out artifacts/source-scope/source_scope_manifest.json
```

Read source-scope reports with this split in mind:

- `matched_paths` and `file_or_directory_hash` are canonical only for tracked
  inputs, or for an explicit non-git fallback that the report names.
- `untracked_matched_path_count` and `untracked_matched_paths` are dirty
  workspace diagnostics. They identify local output that matched a glob but was
  excluded from canonical hashes.
- Untracked E2E output becomes closeout evidence only when the output itself is
  deliberately checked in or a checked-in artifact/ledger records its path and
  hash. Otherwise it is local diagnostic context.
- Do not delete local artifacts to silence dirty diagnostics, do not close
  readiness gaps from untracked-only evidence, and do not mutate foreign tracker
  rows while handling source-scope cleanup.

## Fuzz Smoke QA Artifact Wrapper

`./scripts/e2e/ffs_fuzz_smoke_e2e.sh` runs the deterministic fuzz-smoke harness
through `rch` and wraps the harness JSON into a shared QA artifact. When RCH
capacity is unavailable, use the local wrapper self-check instead of local
cargo:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_FUZZ_SMOKE_SELF_CHECK=1 \
./scripts/e2e/ffs_fuzz_smoke_e2e.sh
```

The self-check uses a stubbed `rch` binary to prove valid harness JSON produces
a valid QA artifact, unowned failing seeds are rejected, and local fallback
emits the shared `RCH_LOCAL_FALLBACK_REJECTED` marker. It does not run cargo.

## xfstests Failure Triage Artifacts

`./scripts/e2e/ffs_xfstests_e2e.sh` emits a baseline manifest plus derived
failure-triage artifacts under the run's `xfstests/` artifact directory:

- `baseline_manifest.json` and `baseline_report.md` preserve the selected
  subset, immutable raw artifact hashes, partial-run checkpoint, cleanup status,
  and reproduction command.
- `failure_triage.json` and `failure_triage.md` consume only that immutable
  baseline manifest. Product-actionable failures are grouped by duplicate key
  into dry-run proposed beads; host, harness, unsupported, skipped, interrupted,
  resumed, passed, and not-run rows are listed as explicit exclusions.

The triage step is intentionally dry-run only. It records `DRY_RUN br create`
commands for operator review and never creates live Beads entries from an E2E
run.

## V1.2 Program Gate

`./scripts/e2e/ffs_v12_program_gate_e2e.sh` rolls the V1.2 child verification
gates, workspace gates, CLI ergonomics check, and structured logging check into
a single release manifest. Any cargo-bearing command is routed through `rch`.

Artifacts are written to `artifacts/release_gate/v12/`:

- `program_gate_manifest.json` gives the final `PROCEED`, `NO-PROCEED`, or
  `PASS-WITH-WAIVERS` recommendation.
- `scenarios/scenario_<n>.jsonl` contains one structured JSON record per
  scenario run.
- `command_transcript.tsv` records commands, stdout/stderr paths, and exit
  status for replay.

Use `FFS_V12_PROGRAM_GATE_SCENARIO_TIMEOUT_SECS=<seconds>` to adjust the
per-scenario budget. Use `FFS_V12_PROGRAM_GATE_SMOKE=1` for the two-scenario
synthetic smoke path that validates manifest and exit-code semantics without
running the full gate. Release notes and waiver handling are documented in
`docs/release/V1.2_release_notes.md` and `docs/release/V1.2_test_waivers.md`.

## Scenario Catalog Contract

Deterministic scenario IDs are centrally defined in:

- `scripts/e2e/scenario_catalog.json`

The catalog is machine-validated by `e2e_validate_scenario_catalog` (in `scripts/e2e/lib.sh`) and runs automatically in CI via `./scripts/e2e/ffs_smoke.sh` Phase 0. The validator treats every `scripts/e2e/ffs_*.sh` runner, including legacy names that do not end in `_e2e.sh`, as catalog-required.

### `scenario_id` Format

All explicit IDs in the catalog must match:

```regex
^[a-z][a-z0-9]*(_[a-z0-9]+){2,}$
```

That enforces lowercase snake-case with at least three segments (domain + behavior + qualifier).

Active scenario rows must define exactly one of:

- `id` for a literal scenario emitted by the runner.
- `id_pattern` for a bounded family of runner-emitted scenario IDs.

Every active `id_pattern` must be anchored with `^` and `$`, must be valid Bash
ERE, and must be compatible with `scenario_id_regex`. The validator derives a
representative sample from supported pattern atoms (`[a-z0-9]`, `[a-z0-9_]`,
`[0-9]`, plus literal lowercase/digit/underscore text and fixed counts like
`{2}`), then requires that sample to match both the declared pattern and the
canonical scenario ID regex. Literal anchored patterns such as
`^v12_program_gate_1$` are checked as literal IDs. A verification-runner
fail-closed fixture keeps malformed wildcard patterns, such as uppercase-only
samples, from silently entering the catalog.

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

## Workload Corpus Contract

The P1 user-risk workload corpus lives in:

- `tests/workload-corpus/p1_workload_corpus.json`

Validate it with:

```bash
cargo run -p ffs-harness -- validate-workload-corpus \
  --corpus tests/workload-corpus/p1_workload_corpus.json \
  --out artifacts/workload_corpus/report.json \
  --summary-out artifacts/workload_corpus/summary.md
```

When RCH capacity is unavailable, use the no-worker wrapper self-check rather
than a local cargo fallback:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_WORKLOAD_CORPUS_SELF_CHECK=1 \
./scripts/e2e/ffs_workload_corpus_e2e.sh
```

The self-check uses a stubbed `rch` binary to prove the wrapper extracts JSON
validator output, preserves selected-scenario and proof-coverage checks,
verifies invalid-variant unit output and docs, and preserves the shared
`RCH_LOCAL_FALLBACK_REJECTED` marker. It does not run cargo, mounted lanes,
xfstests, fuzz/performance campaigns, or permissioned campaigns.

Every new corpus scenario must include:

- `scenario_id`: stable lowercase snake-case with at least three segments.
- `user_risk`: one of the corpus risk classes, such as `data_loss`, `tail_latency`, `permission_boundary`, or `host_capability_ambiguity`.
- `operation_class`: the workload family, such as `editor_save`, `package_extract`, `metadata_tree_churn`, `append_truncate`, `repair_corruption`, or `host_skip`.
- `supported_filesystems`: explicit filesystem flavors, never implied from the title.
- `required_capabilities`: host and product prerequisites such as `fuse_mount`, `host_capability_probe`, `default_permissions`, `repair_symbol_decode`, or `performance_dry_run`.
- `expected_artifacts` and `expected_logs`: enough evidence for a proof runner to validate the scenario without rerunning immediately.
- `linked_proof_consumers`: at least two consumers, commonly `invariant_oracle`, `mounted_differential_oracle`, `repair_lab`, `crash_replay_lab`, `proof_bundle`, `release_gate`, `operational_readiness_report`, or `performance_baseline`.
- `reproduction_command`: an exact command template that preserves the workload identity in logs.

Unsupported behavior must use `status: "unsupported"` with `unsupported_reason` plus either `follow_up_bead` or `non_goal_reason`. Host-only blockers must use `status: "host_skip"` with `host_skip_reason`; the required capabilities must include a host or FUSE capability so the skip cannot be mistaken for product success. The initial corpus intentionally includes the btrfs DefaultPermissions root-owned image-ownership diagnostic and a generic missing-FUSE host skip so mounted proof consumers keep host limitations separate from FrankenFS failures.

## Metamorphic Workload Seed Catalog Contract

The metamorphic workload seed catalog lives in:

- `tests/metamorphic-workload-seeds/metamorphic_workload_seed_catalog.json`

Validate it with:

```bash
cargo run -p ffs-harness -- validate-metamorphic-workload-seeds \
  --catalog tests/metamorphic-workload-seeds/metamorphic_workload_seed_catalog.json \
  --out artifacts/metamorphic-workload-seeds/report.json \
  --summary-out artifacts/metamorphic-workload-seeds/summary.md
```

When RCH capacity is unavailable, use the no-worker wrapper self-check rather
than a local cargo fallback:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_METAMORPHIC_WORKLOAD_SEED_CATALOG_SELF_CHECK=1 \
./scripts/e2e/ffs_metamorphic_workload_seed_catalog_e2e.sh
```

The self-check uses a stubbed `rch` binary to prove the wrapper extracts JSON
and Markdown validator output, preserves relation/source coverage and
permissioned ACK metadata, rejects invalid variants, verifies focused unit-test
output, and preserves the shared `RCH_LOCAL_FALLBACK_REJECTED` marker. It does
not run cargo, mounted lanes, xfstests, fuzz/performance campaigns, or
permissioned campaigns.

## Btrfs Send/Receive Corpus Contract

The btrfs send/receive parity corpus lives in:

- `tests/btrfs-send-receive-corpus/btrfs_send_receive_corpus.json`

Validate it with:

```bash
cargo run -p ffs-harness -- validate-btrfs-send-receive-corpus \
  --corpus tests/btrfs-send-receive-corpus/btrfs_send_receive_corpus.json \
  --out artifacts/btrfs-send-receive/report.json \
  --summary-out artifacts/btrfs-send-receive/summary.md
```

When RCH capacity is unavailable, use the no-worker wrapper self-check rather
than a local cargo fallback:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_BTRFS_SEND_RECEIVE_CORPUS_SELF_CHECK=1 \
./scripts/e2e/ffs_btrfs_send_receive_corpus_e2e.sh
```

The self-check uses a stubbed `rch` binary to prove the wrapper extracts JSON
validator output, preserves support-state and refusal coverage checks, rejects
invalid corpus input, verifies Markdown/docs and focused unit-test output, and
preserves the shared `RCH_LOCAL_FALLBACK_REJECTED` marker. It does not run
cargo, mounted lanes, xfstests, fuzz/performance campaigns, or permissioned
campaigns.

This corpus is a support-envelope contract, not permission to claim full
send/receive parity. It must keep `parse_only`, `export_only`,
`receive_only`, `roundtrip_supported`, and `unsupported` rows visible, and it
must include refusal cases for unsupported stream records and incremental
parent mismatches. Rows that require loop devices, `btrfs-progs`, long
campaigns, or host-specific behavior remain metadata-only until a permissioned
lane records authoritative artifacts.

## Btrfs Multi-Device Corpus Contract

The btrfs multi-device RAID corpus lives in:

- `tests/btrfs-multidevice-corpus/btrfs_multidevice_corpus.json`

Validate it with:

```bash
cargo run -p ffs-harness -- validate-btrfs-multidevice-corpus \
  --corpus tests/btrfs-multidevice-corpus/btrfs_multidevice_corpus.json \
  --out artifacts/btrfs-multidevice/report.json \
  --summary-out artifacts/btrfs-multidevice/summary.md
```

When RCH capacity is unavailable, use the no-worker wrapper self-check rather
than a local cargo fallback:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_BTRFS_MULTIDEVICE_CORPUS_SELF_CHECK=1 \
./scripts/e2e/ffs_btrfs_multidevice_corpus_e2e.sh
```

The self-check uses a stubbed `rch` binary to prove the wrapper extracts JSON
validator output, preserves scenario-kind and profile coverage checks, rejects
invalid corpus input, verifies Markdown/docs and focused unit-test output, and
preserves the shared `RCH_LOCAL_FALLBACK_REJECTED` marker. It does not run
cargo, mounted lanes, xfstests, fuzz/performance campaigns, or permissioned
campaigns.

This corpus is a support-envelope contract, not permission to claim full btrfs
RAID parity. It must keep healthy assembly, device-order permutation, missing
device, duplicate-device-id, stale-superblock, and unsupported-profile rows
visible, and it must preserve explicit `raid1` and `raid5` profile coverage.
Rows that require real multi-image assembly, mounted writes, scrub/repair, or
host-specific btrfs behavior remain metadata-only until a permissioned lane
records authoritative artifacts.

## Ext4 Casefold Corpus Contract

The ext4 casefold corpus lives in:

- `tests/casefold-corpus/casefold_corpus.json`

Validate it with:

```bash
cargo run -p ffs-harness -- validate-casefold-corpus \
  --corpus tests/casefold-corpus/casefold_corpus.json \
  --out artifacts/casefold/report.json \
  --summary-out artifacts/casefold/summary.md
```

When RCH capacity is unavailable, use the no-worker wrapper self-check rather
than a local cargo fallback:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_CASEFOLD_CORPUS_SELF_CHECK=1 \
./scripts/e2e/ffs_casefold_corpus_e2e.sh
```

The self-check uses a stubbed `rch` binary to prove the wrapper extracts JSON
validator output, preserves operation/outcome coverage checks, rejects invalid
corpus input, verifies Markdown/docs and focused unit-test output, and preserves
the shared `RCH_LOCAL_FALLBACK_REJECTED` marker. It does not run cargo, mounted
lanes, xfstests, fuzz/performance campaigns, or permissioned campaigns.

This corpus is a support-envelope contract, not permission to claim mounted
casefold parity. It must keep lookup, create, rename, cross-directory rename,
and mount-feature validation rows visible, and it must preserve explicit
collision-refusal, invalid-encoding-refusal, and mount-feature-accepted
outcomes. Rows that require real ext4 images, mounted writes, kernel feature
negotiation, or host-specific unicode behavior remain metadata-only until a
permissioned lane records authoritative artifacts.

## Fault Injection Corpus Contract

The deterministic fault-injection corpus lives in:

- `tests/fault-injection-corpus/fault_injection_corpus.json`

Validate it with:

```bash
cargo run -p ffs-harness -- validate-fault-injection-corpus \
  --corpus tests/fault-injection-corpus/fault_injection_corpus.json \
  --out artifacts/fault-injection/report.json \
  --summary-out artifacts/fault-injection/summary.md
```

This corpus is a support-envelope contract for repair-confidence evidence, not
permission to mutate mounted images or claim automatic repair success. It must
keep bit-flip, block-erasure, reordered-block, truncated-metadata,
mismatched-symbol-set, and adversarial-seed rows visible, and it must preserve
clean-repair, partial-repair, detection-only, false-positive, and
unsafe-to-repair classifications. Adversarial and unsafe-to-repair rows must
stay explicit until a permissioned calibration lane records authoritative
recovery evidence.

When RCH capacity is unavailable, use the no-worker wrapper self-check rather
than a local cargo fallback:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_FAULT_INJECTION_CORPUS_SELF_CHECK=1 \
./scripts/e2e/ffs_fault_injection_corpus_e2e.sh
```

The self-check uses a stubbed `rch` binary to prove the wrapper parses valid
JSON and Markdown validator output, rejects the invalid-corpus diagnostic, and
preserves the shared `RCH_LOCAL_FALLBACK_REJECTED` marker. It does not run
cargo, mounted lanes, xfstests, repair mutation, or permissioned campaigns.

## Repair Corpus Contract

The repair chain-of-custody corpus lives in:

- `tests/repair-corpus/repair_corpus.json`

Validate it with:

```bash
cargo run -p ffs-harness -- validate-repair-corpus \
  --corpus tests/repair-corpus/repair_corpus.json \
  --out artifacts/repair-corpus/report.json \
  --summary-out artifacts/repair-corpus/summary.md
```

When RCH capacity is unavailable, use the no-worker wrapper self-check rather
than a local cargo fallback:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_REPAIR_CORPUS_SELF_CHECK=1 \
./scripts/e2e/ffs_repair_corpus_e2e.sh
```

The self-check uses a stubbed `rch` binary to prove the wrapper extracts JSON
validator output, preserves outcome and refusal coverage checks, rejects
invalid corpus input, verifies Markdown/docs and focused unit-test output, and
preserves the shared `RCH_LOCAL_FALLBACK_REJECTED` marker. It does not run
cargo, mounted lanes, xfstests, repair mutation, fuzz/performance campaigns,
or permissioned campaigns.

This corpus is a support-envelope contract for repair refusal and
chain-of-custody evidence, not permission to mutate mounted images or claim
automatic repair success. It must keep recovered, wrong-image-ledger,
stale-ledger, truncated-ledger, and post-repair-refresh-mismatch rows visible,
and it must preserve ledger binding, repair-symbol budget, verification, and
artifact hash fields. Refusal rows remain metadata-only until a permissioned
repair lane records authoritative artifacts for the same image, ledger, and
symbol generation.

## Mounted Checkpoint Survivor Contract

The mounted crash/unmount/reopen survivor matrix lives in:

- `tests/mounted-checkpoint-survivor/mounted_checkpoint_survivor.json`

Validate it with:

```bash
cargo run -p ffs-harness -- validate-mounted-checkpoint-survivor \
  --matrix tests/mounted-checkpoint-survivor/mounted_checkpoint_survivor.json \
  --out artifacts/mounted-checkpoint-survivor/report.json \
  --summary-out artifacts/mounted-checkpoint-survivor/summary.md
```

When RCH capacity is unavailable, use the no-worker wrapper self-check rather
than a local cargo fallback:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_MOUNTED_CHECKPOINT_SURVIVOR_SELF_CHECK=1 \
./scripts/e2e/ffs_mounted_checkpoint_survivor_e2e.sh
```

The self-check uses a stubbed `rch` binary to prove the wrapper extracts JSON
validator output, preserves lifecycle and partial-artifact coverage checks,
rejects invalid matrix input, verifies Markdown/docs and focused unit-test
output, and preserves the shared `RCH_LOCAL_FALLBACK_REJECTED` marker. It does
not run cargo, mounted lanes, process termination, xfstests, fuzz/performance
campaigns, or permissioned campaigns.

This matrix is a support-envelope contract for mounted lifecycle evidence, not
permission to kill mounted writers or claim crash-recovery parity. It must keep
clean unmount, pre-fsync termination, post-fsync termination, fsyncdir
boundary, forced-unmount, and reopen-after-write rows visible, and it must
preserve checkpoint ids, image hashes, operation traces, crash/unmount points,
expected survivor sets, recovery commands, partial artifact paths, cleanup
policies, and unsafe process-control refusals. Rows that require real FUSE
mounts or process termination remain metadata-only until a permissioned lane
records authoritative survivor artifacts.

## Mounted Repair Mutation Boundary Contract

The mounted repair mutation-boundary matrix lives in:

- `tests/mounted-repair-mutation-boundary/mounted_repair_mutation_boundary.json`

Validate it with:

```bash
cargo run -p ffs-harness -- validate-mounted-repair-mutation-boundary \
  --matrix tests/mounted-repair-mutation-boundary/mounted_repair_mutation_boundary.json \
  --out artifacts/mounted-repair-mutation-boundary/report.json \
  --summary-out artifacts/mounted-repair-mutation-boundary/summary.md
```

When remote RCH capacity is unavailable, the deterministic wrapper self-check
proves JSON report extraction, coverage assertions, invalid matrix diagnostics,
Markdown/docs wording, focused unit-output checks, and RCH fallback guardrails
without running cargo:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_MOUNTED_REPAIR_MUTATION_BOUNDARY_SELF_CHECK=1 \
./scripts/e2e/ffs_mounted_repair_mutation_boundary_e2e.sh
```

This matrix is a support-envelope contract for repair mutation scope, not
permission to repair mounted images or claim writeback repair readiness. It
must keep default read-only detection, read-only repair-with-ledger,
read-write refusal, missing/stale ledger refusal, and host-capability skip rows
visible. It also preserves before/after image hashes, expected mutation scope,
ledger row counts, visible namespace expectations, host paths touched, cleanup
status, artifact paths, reproduction commands, follow-up beads for refusals,
and explicit host-skip rationale. Rows that require real mounted mutation
remain metadata-only until a permissioned lane records authoritative artifacts.

## Low-Privilege Demo Contract

The low-privilege demo manifest lives in:

- `tests/low-privilege-demo/low_privilege_demo_manifest.json`

Validate it with:

```bash
cargo run -p ffs-harness -- validate-low-privilege-demo \
  --manifest tests/low-privilege-demo/low_privilege_demo_manifest.json \
  --out artifacts/low-privilege-demo/report.json \
  --summary-out artifacts/low-privilege-demo/summary.md
```

This manifest is the original non-permissioned demo contract. It must keep
parser-unit, invariant-oracle, repair-dry-run, release-gate-eval, and
mounted-smoke-host-skipped lanes visible without claiming FUSE readiness on
hosts that cannot mount. It also preserves capability requirements,
capability-check commands, expected artifact paths, fixture hashes,
reproduction commands, cleanup status, and explicit host-skip reasons. The
checked-in manifest command line must point at `validate-low-privilege-demo`
so the artifact can be reproduced directly from its own metadata.

When RCH capacity is unavailable, use the no-worker wrapper self-check rather
than a local cargo fallback:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_LOW_PRIVILEGE_DEMO_SELF_CHECK=1 \
./scripts/e2e/ffs_low_privilege_demo_e2e.sh
```

The self-check uses a stubbed `rch` binary to prove the wrapper parses valid
JSON and Markdown validator output, rejects the invalid-manifest diagnostic,
and preserves the shared `RCH_LOCAL_FALLBACK_REJECTED` marker. It does not run
cargo, mounted lanes, xfstests, or permissioned campaigns.

## Low-Privilege Demo Sandbox Contract

The low-privilege demo sandbox manifest lives in:

- `tests/low-privilege-demo-sandbox/low_privilege_demo_sandbox.json`

Validate it with:

```bash
cargo run -p ffs-harness -- validate-low-privilege-demo-sandbox \
  --manifest tests/low-privilege-demo-sandbox/low_privilege_demo_sandbox.json \
  --out artifacts/low-privilege-demo-sandbox/report.json \
  --summary-out artifacts/low-privilege-demo-sandbox/summary.md
```

This manifest is a support-envelope contract for safe local demonstration
lanes, not permission to mutate host filesystems, load kernel modules, make
network egress claims, or claim mounted readiness. It must keep parser,
invariant-oracle, repair-dry-run, and mounted-smoke-host-skipped lanes visible,
and it must preserve fixture provenance, immutable committed fixtures,
allowed-workspace-root sandboxing, required forbidden side effects, proof-bundle
schema ids, README wording ids, cleanup policy, and explicit host-skip reasons.
Rows that require real FUSE mounts remain host-skipped until a permissioned
lane records authoritative mounted artifacts.

When RCH capacity is unavailable, use the no-worker wrapper self-check rather
than a local cargo fallback:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_LOW_PRIVILEGE_DEMO_SANDBOX_SELF_CHECK=1 \
./scripts/e2e/ffs_low_privilege_demo_sandbox_e2e.sh
```

The self-check uses a stubbed `rch` binary to prove the wrapper parses valid
JSON and Markdown validator output, rejects the invalid-manifest diagnostic,
and preserves the shared `RCH_LOCAL_FALLBACK_REJECTED` marker. It does not run
cargo, mounted lanes, xfstests, or permissioned campaigns.

## Remediation Catalog Contract

The user-facing remediation catalog lives in:

- `tests/remediation-catalog/remediation_catalog.json`

Validate it with:

```bash
cargo run -p ffs-harness -- validate-remediation-catalog \
  --catalog tests/remediation-catalog/remediation_catalog.json \
  --out artifacts/remediation/catalog_report.json \
  --summary-out artifacts/remediation/catalog_summary.md
```

When RCH capacity is unavailable, use the no-worker wrapper self-check rather
than a local cargo fallback:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_REMEDIATION_CATALOG_SELF_CHECK=1 \
./scripts/e2e/ffs_remediation_catalog_e2e.sh
```

The self-check uses a stubbed `rch` binary to prove the wrapper parses valid
JSON and Markdown validator output, rejects the invalid-catalog diagnostic, and
preserves the shared `RCH_LOCAL_FALLBACK_REJECTED` marker. It does not run
cargo, mounted lanes, xfstests, recovery, mutation, or permissioned campaigns.

This catalog is an operator action contract for proof failures and readiness
blockers, not evidence that any repair, rollback, or host remediation command
has been executed. It must keep product failures, host-capability skips,
unsupported operations, stale artifacts, security refusals, unsafe repair
refusals, and passing-with-caveat outcomes visible, with user summary,
technical cause, immediate action, safe retry policy, reproduction command,
artifact links, owning bead, escalation path, and docs target for every entry.
The CLI must emit JSON reports for machines and Markdown summaries for human
handoffs through `--format markdown` and `--summary-out`.

## Remediation Severity Gate Contract

The remediation severity gate lives in:

- `tests/remediation-severity-gate/remediation_severity_gate.json`

Validate it with:

```bash
cargo run -p ffs-harness -- validate-remediation-severity-gate \
  --gate tests/remediation-severity-gate/remediation_severity_gate.json \
  --out artifacts/remediation/severity_gate_report.json \
  --summary-out artifacts/remediation/severity_gate_summary.md
```

When RCH capacity is unavailable, use the no-worker wrapper self-check rather
than a local cargo fallback:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_REMEDIATION_SEVERITY_GATE_SELF_CHECK=1 \
./scripts/e2e/ffs_remediation_severity_gate_e2e.sh
```

The self-check uses a stubbed `rch` binary to prove the wrapper parses valid
JSON and Markdown validator output, rejects the invalid-gate diagnostic, and
preserves the shared `RCH_LOCAL_FALLBACK_REJECTED` marker. It does not run
cargo, mounted lanes, xfstests, recovery, mutation, or permissioned campaigns.

This gate is a release-blocking remediation outcome contract, not evidence that
any repair, rollback, or host remediation command has been executed. It must
keep product failures, host-capability skips, unsafe repair refusals,
low-confidence repair, missing proof lanes, inconclusive oracle conflicts, and
experimental pass caveats visible, with data-safety severity, mutation status,
safe retry policy, escalation path, owning bead, docs target, artifact
requirements, release-gate effect, and exactly one immediate action or explicit
non-goal rationale for every entry. Rows with unrecoverable data loss must
block release, while host-capability skips and experimental caveats must not
masquerade as product failures.

## Inventory Closeout Gate Contract

The inventory closeout gate lives in:

- `tests/inventory-closeout-gate/inventory_closeout_gate.json`

Validate it with:

```bash
cargo run -p ffs-harness -- validate-inventory-closeout-gate \
  --gate tests/inventory-closeout-gate/inventory_closeout_gate.json \
  --out artifacts/inventory-closeout/gate_report.json \
  --summary-out artifacts/inventory-closeout/gate_summary.md
```

This gate is a closeout contract for stale fuzz/conformance inventory notes,
not proof that any mounted, xfstests, repair, fuzz, or performance campaign has
run. It must keep parser, mounted-path, repair, fuzz, golden, xfstests,
performance, and README/feature-parity risk surfaces visible. Every row must
carry source provenance, a snippet hash, a supported state, and the state-owned
evidence needed to prevent vague high-risk notes from being silently treated as
done. Stale-allowed rows require a future expiry, owner, user-risk rationale,
and linked bead or non-goal artifact; duplicates must point at another row.

When RCH capacity is unavailable, use the no-worker wrapper self-check rather
than a local cargo fallback:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_INVENTORY_CLOSEOUT_GATE_SELF_CHECK=1 \
./scripts/e2e/ffs_inventory_closeout_gate_e2e.sh
```

The self-check uses a stubbed `rch` binary to prove the wrapper parses valid
JSON and Markdown validator output, rejects the invalid-gate diagnostic, and
preserves the shared `RCH_LOCAL_FALLBACK_REJECTED` marker. It does not run
cargo, mounted lanes, xfstests, fuzz/performance campaigns, or permissioned
campaigns.

## Report Schema Inventory Gate

The report schema inventory gate is built from the in-code
`ffs_harness::report_schema_inventory` table.

Validate it with:

```bash
cargo run -p ffs-harness -- validate-report-schema-inventory \
  --out artifacts/report-schema-inventory/report.json \
  --summary-out artifacts/report-schema-inventory/report.md
```

The E2E wrapper is:

```bash
./scripts/e2e/ffs_report_schema_inventory_e2e.sh
```

When RCH capacity is unavailable, use the no-worker wrapper self-check rather
than a local cargo fallback:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_REPORT_SCHEMA_INVENTORY_SELF_CHECK=1 \
./scripts/e2e/ffs_report_schema_inventory_e2e.sh
```

The self-check uses a stubbed `rch` binary to prove the wrapper extracts JSON
and Markdown validator output, preserves row-level product-claim semantics,
resolves evidence-test references, and preserves the shared
`RCH_LOCAL_FALLBACK_REJECTED` marker. It does not run cargo, mounted lanes,
xfstests, large-host campaigns, proof-bundle passes, or permissioned
campaigns.

This gate is a read-only coverage inventory for durable `ffs-harness` JSON
report contracts, not proof that any mounted mutation, xfstests, large-host
swarm campaign, or proof-bundle pass has executed. The JSON report and Markdown
summary must keep `product_evidence_claim=none`, list any uncovered required
report IDs, preserve row-level missing-evidence diagnostics, and include a
reproduction command so future agents can turn missing required rows into
narrow beads instead of another ad hoc JSON-shape scan.

## Chaos Replay Lab Contract

The chaos replay lab lives in:

- `tests/chaos-replay-lab/chaos_replay_lab.json`

Validate it with:

```bash
cargo run -p ffs-harness -- validate-chaos-replay-lab \
  --lab tests/chaos-replay-lab/chaos_replay_lab.json \
  --out artifacts/chaos-replay/lab_report.json \
  --summary-out artifacts/chaos-replay/lab_summary.md
```

This lab is a non-permissioned crash/replay schedule contract, not proof that a
mounted daemon, destructive replay, or permissioned host lane has executed. It
must keep required crash taxonomies, deterministic seeds, replay commands, raw
log paths, survivor expectations, repair policy, minimization status, and
host-skip rationale visible. Replay commands are recorded as RCH cargo-test
commands for reproducibility; permissioned mounted mutation remains outside
this gate until an explicit operator-approved lane produces real artifacts.

When RCH capacity is unavailable, use the no-worker wrapper self-check rather
than a local cargo fallback:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_CHAOS_REPLAY_LAB_SELF_CHECK=1 \
./scripts/e2e/ffs_chaos_replay_lab_e2e.sh
```

The self-check uses a stubbed `rch` binary to prove the wrapper parses valid
JSON and Markdown validator output, rejects the invalid-lab diagnostic, and
preserves the shared `RCH_LOCAL_FALLBACK_REJECTED` marker. It does not run
cargo, mounted lanes, xfstests, crash mutation, or permissioned campaigns.

## Swarm Workload Harness Contract

The 64-core/256GB swarm workload harness plan lives in:

- `benchmarks/swarm_workload_harness_manifest.json`

Validate it with:

```bash
cargo run -p ffs-harness -- validate-swarm-workload-harness \
  --manifest benchmarks/swarm_workload_harness_manifest.json \
  --out artifacts/performance/swarm_workload_harness.json \
  --summary-out artifacts/performance/swarm_workload_harness.md
```

The manifest is a dry-run proof contract, not a real workload execution grant. It must include a host fingerprint, CPU/RAM/NUMA visibility, storage class, FUSE capability, kernel, RCH/local lane, worker isolation notes, exact command plan, resource caps, queue/backpressure counters, cleanup policy, expected artifacts, raw logs, and release-claim state. Local hosts or lanes without enough CPU, RAM, or NUMA visibility must use `capability_skip` or `small_host_smoke`; they cannot produce a 64-core/256GB pass claim.

The local runner emits `small_host_smoke` or blocked/downgraded artifacts only.
To produce evidence that can strengthen the public `swarm.responsiveness`
claim, use a permissioned large-host runner and preserve a validated
`swarm_workload_harness` proof-bundle lane with `host_class`,
`manifest_hash`, `freshness`, `release_claim`, `validator_report`, raw logs,
and artifact paths. `release_claim=authoritative_large_host` is the only
workload-harness release-claim state that may upgrade public wording;
`release_claim=small_host_smoke` and
`release_claim=capability_downgraded_smoke` cannot upgrade `swarm.responsiveness`.
Stale, missing, unsupported, or small-host-only swarm evidence remains
downgrade/blocker evidence.

## Swarm Operator Report Contract

The swarm operator decision report lives in:

- `benchmarks/swarm_operator_report.json`

Validate it with:

```bash
cargo run -p ffs-harness -- validate-swarm-operator-report \
  --report benchmarks/swarm_operator_report.json \
  --out artifacts/performance/swarm_operator_report.json \
  --summary-out artifacts/performance/swarm_operator_report.md
```

When RCH capacity is unavailable, use the no-worker wrapper self-check rather
than a local cargo fallback:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_SWARM_OPERATOR_REPORT_SELF_CHECK=1 \
./scripts/e2e/ffs_swarm_operator_report_e2e.sh
```

The self-check uses a stubbed `rch` binary to prove the wrapper extracts JSON
validator output, preserves operator-card coverage checks, rejects unlinked
evidence beads, verifies Markdown/docs and focused unit-test output, and
preserves the shared `RCH_LOCAL_FALLBACK_REJECTED` marker. It does not run
cargo, mounted lanes, xfstests, fuzz/performance campaigns, or permissioned
campaigns.

This report is an operator decision contract for the swarm-performance
workstream, not an authoritative large-host measurement. It must keep the tail
latency decomposition, NUMA/shard harness, RCU/QSBR metadata path, parallel WAL
group-commit gate, cache budget controller, and scrub/repair scheduler cards
visible. Every card must preserve invariants, evidence rows, expected-loss
policy, fallback behavior, validation commands, release-claim state, and linked
beads. Non-permissioned reports must not upgrade to
`measured_authoritative`; that state requires a separate permissioned
large-host lane with fresh raw artifacts and proof-bundle/release-gate
consumers.

## Swarm Tail-Latency Ledger Contract

The 64-core/256GB swarm tail-latency decomposition ledger lives in:

- `benchmarks/swarm_tail_latency_ledger.json`

Validate it with:

```bash
cargo run -p ffs-harness -- validate-swarm-tail-latency \
  --ledger benchmarks/swarm_tail_latency_ledger.json \
  --out artifacts/performance/swarm_tail_latency.json \
  --summary-out artifacts/performance/swarm_tail_latency.md
```

The ledger decomposes p99 latency into queueing, service, I/O, retries, synchronization, allocator, repair backlog, cache pressure, WAL fsync, and FUSE wrapper components. Rows must carry host fingerprint, core/RAM profile, queue depth, backpressure state, reference state, release-claim state, reproduction command, raw logs, and artifact paths. Missing references, incomplete host fingerprints, or missing component attribution force experimental or missing-reference wording; they cannot produce measured large-host claims.

The tail-latency proof-bundle lane is `swarm_tail_latency`. It must carry the
same host-class and release-claim metadata as the workload lane, plus an
artifact with role `p99_attribution_ledger` that points at the validated p99
decomposition ledger. The release gate for `swarm.responsiveness` stays hidden
or disabled when the p99 ledger is stale, missing, unsupported, small-host-only,
or disconnected from the proof bundle.

When RCH capacity is unavailable, use the no-worker wrapper self-check rather
than a local cargo fallback:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_SWARM_TAIL_LATENCY_SELF_CHECK=1 \
./scripts/e2e/ffs_swarm_tail_latency_e2e.sh
```

The self-check uses a stubbed `rch` binary to prove the wrapper extracts JSON
and Markdown validator output, preserves classification and dominance
accounting, rejects mutated ledger variants, verifies focused unit-test output,
and preserves the shared `RCH_LOCAL_FALLBACK_REJECTED` marker. It does not run
cargo, mounted lanes, xfstests, fuzz/performance campaigns, or permissioned
campaigns.

## Repair Confidence Lab Contract

The repair confidence mutation-safety contract lives in:

- `docs/repair-confidence-mutation-safety.json`

Validate it with:

```bash
cargo run -p ffs-harness -- validate-repair-confidence-lab \
  --spec docs/repair-confidence-mutation-safety.json \
  --out artifacts/repair-confidence/lab_report.json \
  --summary-out artifacts/repair-confidence/lab_summary.md
```

Every scenario must declare the corruption class, repair-symbol budget, evidence-ledger state, candidate repair plan, pre/post image hashes where applicable, threshold id, verification verdict, artifact paths, structured log fields, and reproduction command. The validator requires coverage for detection-only scrub, successful dry-run, verified opt-in mutation, unsafe-to-repair refusal, and failed-verification refusal.

Public wording must keep these states distinct:

- automatic mutating repair: only when dry-run, rollback, ledger integrity, repair-symbol coverage, confidence score, residual-risk threshold, and final verification all pass.
- detection-only scrub: corruption was found or classified, but no image mutation is proposed.
- unsupported corruption classes: the lab must refuse or mark detection-only, link a follow-up measurement bead when thresholds are experimental, and preserve reproduction artifacts.

Thresholds chosen without enough evidence must be marked `experimental: true` and must link a follow-up bead. Non-experimental mutation thresholds require an evidence artifact and fail closed when any precondition is missing.

## Operator Recovery Drill Contract

The operator recovery drill contract lives in:

- `docs/operator-recovery-drill.json`

Validate it with:

```bash
cargo run -p ffs-harness -- validate-operator-recovery-drill \
  --spec docs/operator-recovery-drill.json \
  --out artifacts/operator-recovery/drill_report.json \
  --summary-out artifacts/operator-recovery/drill_summary.md
```

When RCH capacity is unavailable, use the no-worker wrapper self-check rather
than a local cargo fallback:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_OPERATOR_RECOVERY_DRILL_SELF_CHECK=1 \
./scripts/e2e/ffs_operator_recovery_drill_e2e.sh
```

The self-check uses a stubbed `rch` binary to prove the wrapper extracts JSON
and Markdown validator output, preserves drill decision/outcome coverage
checks, rejects invalid drill variants, verifies docs and focused unit-test
output, and preserves the shared `RCH_LOCAL_FALLBACK_REJECTED` marker. It does
not run cargo, mounted lanes, xfstests, fuzz/performance campaigns, or
permissioned campaigns.

Every drill scenario must preserve exact commands, image hashes, corruption
manifest, confidence threshold, repair plan, operator warnings, post-repair
verification, rollback or refusal outcome, cleanup status, proof-bundle lane,
and reproduction command. The validator requires coverage for a detection-only
drill, a successful dry-run drill, a verified opt-in mutating drill, and a
refused unsafe drill.

The `operator_recovery_drill` proof-bundle lane is the user-facing workflow
evidence. It does not replace the repair confidence lab; it consumes that style
of threshold evidence and proves the operator path fails closed before image
mutation when any preflight, confidence, rollback, or verification requirement
is missing.

## Crash Replay Refinement Contract

The crash replay refinement smoke is:

```bash
./scripts/e2e/ffs_crash_replay_refinement_e2e.sh
```

Every crash replay case artifact must include lane type, crash classification, schedule id, seed, crash point, expected survivors, observed survivors, cleanup status, raw structured log marker, minimized operation count, and a minimized reproduction command. Per-schedule artifacts must preserve the full operation trace. Core deterministic schedules must compare survivor sets after replay, while mounted-smoke and repair-interruption lanes must be represented in the taxonomy and use structured host capability skips when the lane cannot run.

The safe default does not attempt mounted crash replay. If
`FFS_ENABLE_PERMISSIONED_CRASH_REPLAY=1` is set, the smoke first emits a
structured permissioned capability blocker unless the host has `/dev/fuse`,
`fusermount3` or `fusermount`, and the separate real-run acknowledgement:

```bash
FFS_PERMISSIONED_CRASH_REPLAY_REAL_RUN_ACK=permissioned-crash-replay-may-mount-kill-daemon-and-mutate-images
```

The blocker artifact records `permissioned_execution_attempted=false`, the
host probe result, missing prerequisites, the required acknowledgement, and a
rerun command. When those host and acknowledgement prerequisites are present,
real execution is delegated to `FFS_PERMISSIONED_CRASH_REPLAY_RUNNER`. The
runner receives `FFS_CRASH_REPLAY_SCENARIO_ID`,
`FFS_CRASH_REPLAY_SCENARIO_LANE`, `FFS_CRASH_REPLAY_CLASSIFICATION`,
`FFS_CRASH_REPLAY_ARTIFACT_OUT`, `FFS_CRASH_REPLAY_STDOUT_OUT`,
`FFS_CRASH_REPLAY_STDERR_OUT`, and `FFS_CRASH_REPLAY_LOG_DIR`. If the runner is
missing, unresolved on `PATH`, or not executable, the smoke emits the same
structured capability blocker instead of reporting an unimplemented-lane
failure. A configured runner must write a mounted crash replay artifact at
`FFS_CRASH_REPLAY_ARTIFACT_OUT` with `lane_type=mounted_e2e`,
`permissioned_context`, image hashes, mountpoint, daemon when applicable,
operation trace with an explicit crash point, expected and observed survivor
sets, ledger for repair interruption, stdout/stderr, cleanup, and reproduction
fields before the smoke will count the permissioned scenario as authoritative
evidence. A failing permissioned verdict must also include follow-up bead data
and `follow_up_dry_run_br_create` text or JSON containing a
`br create --dry-run` payload with the scenario id, expected vs. observed
survivor data, suspected crate boundary, reproduction command, and raw artifact
hashes.

For low-privilege verification of the blocker contract without running the
core cargo replay or any permissioned mount action:

```bash
FFS_CRASH_REPLAY_PERMISSIONED_PROBE_ONLY=1 \
FFS_ENABLE_PERMISSIONED_CRASH_REPLAY=1 \
./scripts/e2e/ffs_crash_replay_refinement_e2e.sh
```

Unreduced failing schedules must link a follow-up bead with raw logs and the full operation trace. Passing schedules still emit minimized reproduction commands so a future regression can be rerun from the artifact bundle without re-searching the corpus.

## Artifact Manifest Contract

The canonical verification artifact manifest schema lives in:

- `crates/ffs-harness/src/artifact_manifest.rs`

It defines the shared representation for verification outputs across E2E, benchmark, fuzz, proof, and repro-pack workflows. The top-level contract includes:

- `schema_version`, `run_id`, `created_at`, `gate_id`, and optional `bead_id`
- `git_context` and `environment` fingerprints for reproducibility
- `scenarios` keyed by `scenario_id`
- `operational_context` for readiness-grade runs: exact command line, host/worker id, FUSE capability result, and primary stdout/stderr log paths
- `operational_scenarios` keyed by `scenario_id` for expected/actual outcome, pass/fail/skip/error classification, filesystem flavor, image hash, mount options, exit status, stdout/stderr paths, evidence ledger paths, cleanup status, remediation hint, and artifact references
- `readiness_events` for the versioned cross-lane event envelope: event id, report id, run id, lane id, scenario id or aggregate marker, controlling artifact id, parent correlation id, classification, severity, timestamp, git SHA, host/capability fingerprint, raw-log references, controlling evidence, remediation id, and reproduction command
- `artifacts` with category, content type, size, checksum, redaction flag, and metadata
- `verdict`, `duration_secs`, and optional retention metadata

Generic historical manifests may use only the base schema. Operational readiness manifests must pass the stricter `validate_operational_manifest` check. That validator rejects missing run context, missing per-scenario metadata, invalid pass/fail/skip/error classification, ambiguous skip reasons, malformed artifact paths, artifact references that do not point at manifest entries, missing stdout/stderr paths, missing cleanup status, missing or malformed readiness event envelopes, and unprobed FUSE capability.

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

Mounted differential oracle artifacts are validated with:

```bash
cargo run -p ffs-harness -- validate-mounted-differential-oracle \
  --report artifacts/e2e/mounted_differential_oracle/report.json \
  --out artifacts/e2e/mounted_differential_oracle/validation.json
```

The validator rejects broad or expired allowlists, unresolved kernel-vs-FrankenFS
diffs, missing raw log paths, missing image hashes, missing kernel baseline
provenance, shared kernel/FrankenFS images or mountpoints, unsupported-scope rows
without an owner or non-goal, and host skips that blur `/dev/fuse`,
`fusermount`, kernel mount permission, `mkfs` helper, or btrfs
`DefaultPermissions` setup failures into product failures.

Cross-oracle arbitration artifacts are validated with:

```bash
cargo run -p ffs-harness -- validate-cross-oracle-arbitration \
  --report artifacts/e2e/cross_oracle_arbitration/report.json \
  --out artifacts/e2e/cross_oracle_arbitration/validation.json
```

The validator rejects stale or missing oracle evidence under product-bug
classifications, missing controlling artifacts, missing arbitration log fields,
and unresolved conflicts that affect mounted writes, mutating repair,
writeback-cache, background scrub mutation, or data-integrity claims without a
fail-closed release-gate impact.

### Operational Readiness Report

Use the readiness aggregator when closing operational hardening beads. It scans
an artifact directory for versioned `ArtifactManifest` files and legacy
`result.json` summaries, then emits a single JSON or Markdown report that
groups scenarios by workstream, counts pass/fail/skip/error outcomes, preserves
links to raw logs and artifacts, flags duplicate scenario IDs, detects stale git
SHAs when `--current-git-sha` is provided, enforces artifact recency when
`--max-age-days` is provided, and separates product failures from
environment-only blockers. Each scenario row also carries stale-artifact and
artifact-age fields plus a stable `taxonomy_class`, controlling artifact,
reproduction command, cleanup status, manifest schema version, host
fingerprint, readiness event ids, parent correlation ids, event artifact ids,
and event severities so report consumers can distinguish
`product_failure`, `host_capability_skip`, `authoritative_lane_unavailable`,
`harness_failure`, `unsupported_by_scope`, `stale_artifact`,
`missing_artifact`, `noisy_measurement`, `security_refusal`,
`unsafe_repair_refusal`, and `pass_with_experimental_caveat` without parsing
free-form logs.

```bash
cargo run -p ffs-harness -- operational-readiness-report \
  --artifacts artifacts/e2e \
  --current-git-sha "$(git rev-parse --short HEAD)" \
  --max-age-days 14 \
  --format markdown \
  --out artifacts/e2e/operational_readiness.md
```

Attach the JSON or Markdown report path to the bead close reason when a bead
claims operational readiness evidence. The report is an aggregator; it does not
replace the raw per-suite logs, manifests, or reproduction commands.
Required readiness workstreams are fail-closed in the JSON contract through
`required_workstreams_missing` and `contract_failed`; stale git SHAs and missing
logs also set `contract_failed`. When `--max-age-days` is set, stale, missing,
or malformed `created_at` timestamps set `contract_failed` through the
`stale_artifacts` and `invalid_artifact_timestamps` diagnostics so docs and
parity claims cannot upgrade from an incomplete or outdated aggregate.

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

When remote RCH capacity is unavailable, the deterministic wrapper self-check
proves report/artifact/Markdown parsing and local-fallback rejection without
running cargo:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_SOAK_CANARY_CAMPAIGN_SELF_CHECK=1 \
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

When remote RCH capacity is unavailable, the deterministic wrapper self-check
proves report/artifact/Markdown/proof-summary parsing and local-fallback
rejection without running cargo:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_REPAIR_WRITEBACK_SERIALIZATION_SELF_CHECK=1 \
./scripts/e2e/ffs_repair_writeback_serialization_e2e.sh
```

The fail-closed artifact must include `operation_id`, `scenario_id`,
`snapshot_epoch`, `lease_id`, `repair_symbol_version`, `expected_state`,
`observed_state`, `error_class`, `artifact_paths`, `cleanup_status`,
`reproduction_command`, and `follow_up_bead`.

### Repair Writeback Route And Race Gate

The route smoke proves the implementation surface behind the contract:
`OpenFs::repair_writeback_blocks_via_mounted_mutation_path` stages recovered
blocks in a mounted MVCC request scope, commits, flushes, and verifies durable
bytes, while `ffs-repair` consumes an explicit recovered-block writeback
authority and fails closed when that authority rejects a stale repair snapshot.
The same smoke also records deterministic interleavings for repair-before-write,
write-before-repair stale rejection, disjoint client/repair writes, cancellation
before staging, stale-symbol refresh suppression, and flush/reopen visibility.
The read-write enablement leg proves `ffs mount --rw --background-repair
--background-scrub-ledger <jsonl>` parses and resolves, missing ledgers reject
before mount, and kernel FUSE writeback-cache mode stays disabled.

```bash
./scripts/e2e/ffs_repair_writeback_route_e2e.sh
```

When remote RCH capacity is unavailable, the deterministic wrapper self-check
proves captured focused-test output, route artifact generation, and
local-fallback rejection without running cargo:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_REPAIR_WRITEBACK_ROUTE_SELF_CHECK=1 \
./scripts/e2e/ffs_repair_writeback_route_e2e.sh
```

The generated artifact records operation and scenario IDs, expected and
observed states, interleaving schedule IDs, operation traces, ledger event
classes, visible data before/after repair, stdout/stderr log paths, cleanup
status, writeback-cache state, read-write background repair guard state, and
the reproduction command.

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

FUSE-capable worker shell command:

```bash
cd /data/projects/frankenfs
FFS_USE_RCH=0 \
FFS_RUN_BTRFS_LANE_PROBE=1 \
FFS_REQUIRE_BTRFS_LANE_PROBE=1 \
./scripts/e2e/ffs_fuse_production.sh
```

Run that command in a shell that is already on the FUSE-capable worker. Do not
use RCH to launch a shell wrapper around the whole mounted lane; RCH command
classification is for the runner's internal cargo commands, and the FUSE probe
must execute on the host that owns `/dev/fuse`.

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
fields, and release-gate consumers. The retention policy is class-specific:
each artifact class declares retention duration, retention count, maximum size,
compression mode, redaction policy/version, and mandatory fields that cannot be
dropped before remediation, cross-lane correlation, tamper validation, and
reproduction consumers finish. The metrics JSON records one bounded proof
workflow with scenario id, profile, baseline id, observed metric values,
artifact sizes, compression candidates, redaction/sampling decisions, validator
results, cleanup status, and the reproduction command.

Failures mean either a required metric is missing, the baseline is stale, a
threshold moved past `fail_at`, an exception expired or lacks user-impact
metadata, compression is corrupt or disabled for a compressed class, cleanup
failed, redaction used the wrong policy version, or retention would drop
mandatory proof/reproduction evidence. Warnings mean the gate can continue but
the report must stay visible, usually because a metric crossed `warn_at`,
compression is required, sampling/redaction changed optional diagnostics, or a
valid time-limited exception is active. To update a baseline, rerun the bounded
proof workflow, write a new baseline id and `baseline_captured_at`, keep the
previous report for comparison, and do not raise thresholds without recording
the user impact and follow-up bead.

The E2E smoke is:

```bash
./scripts/e2e/ffs_proof_overhead_budget_e2e.sh
```

It captures a small proof-style harness run, writes metrics, evaluates the
sample budget, verifies the release-gate log fields, checks that retention and
redaction preserved mandatory reproduction fields plus raw diagnostics, and
runs the module unit tests.

### Proof Bundle Validation

Proof bundles are offline inspection packs for readiness claims. Each bundle is
a directory rooted at a versioned `manifest.json` that records the schema
version, bundle id, generation timestamp, git SHA, toolchain, kernel, mount
capability, required lanes, raw logs, summaries, gate inputs, artifact paths,
SHA-256 hashes, scenario ids, redaction policy, and optional artifact
hash-chain integrity fields. The required lanes are `conformance`, `xfstests`,
`fuse`, `differential_oracle`, `repair_lab`, `crash_replay`, `performance`,
`writeback_cache`, `scrub_repair_status`, `known_deferrals`, and
`release_gates`.

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
artifact hash mismatches, artifact path/hash rows, hash-chain diagnostics,
redaction errors, redaction leaks, and per-lane raw-log/summary links. The
Markdown summary is the human inspection view and must preserve the
`validate-proof-bundle` reproduction command plus hash-chain status. Validation
is fail-closed: stale schema versions, stale git SHAs, old timestamps, absolute
or parent-traversal paths, missing files, wrong SHA-256 hashes, duplicate
scenario ids, hash-chain mismatches, redaction policies that remove
reproduction fields, configured sensitive marker leaks, and redacted artifacts
that lack required placeholders all fail the gate.

The E2E smoke is:

```bash
./scripts/e2e/ffs_proof_bundle_e2e.sh
```

It builds a sample bundle with every required lane, validates it, writes
JSON/Markdown inspection artifacts, rejects hash drift, stale SHA, missing
artifact links, hash-chain tampering, redaction leaks, and missing redaction
placeholders, then runs the module unit tests.

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

When remote RCH capacity is unavailable, the deterministic wrapper self-check
proves the JSON/artifact/wording parsing path and local-fallback rejection
without running cargo:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_ADVERSARIAL_THREAT_MODEL_SELF_CHECK=1 \
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
When remote RCH capacity is unavailable, the deterministic wrapper self-check
proves the JSON/artifact parsing path and local-fallback rejection without
running cargo:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_PERFORMANCE_MANIFEST_SELF_CHECK=1 \
./scripts/e2e/ffs_performance_manifest_e2e.sh
```

## Support-State Accounting

Support-state accounting separates implementation inventory from readiness
claims. It keeps the `FEATURE_PARITY.md` count table parseable while requiring
every user-facing claim to name a tier such as `validated`, `experimental`,
`detection_only`, `dry_run_only`, `parse_only`, `single_device_only`,
`basic_coverage`, `disabled`, `opt_in_mutating`, `unsupported`, `deferred`, or
`host_blocked`.

Validate the checked-in parity wording and Beads ownership links with:

```bash
cargo run -p ffs-harness -- validate-support-state-accounting \
  --issues .beads/issues.jsonl \
  --feature-parity FEATURE_PARITY.md \
  --out artifacts/parity/support_state_accounting.json \
  --summary-out artifacts/parity/support_state_accounting.md
```

The validator rejects unscoped flat 100 percent parity wording, stale/missing
owner beads, missing structured log fields, and any row that does not compose
with the fail-closed release evaluator contract. README and FEATURE_PARITY-safe
wording should consume the support-state rows rather than treating inventory
percentages as readiness percentages.

The E2E smoke is:

```bash
./scripts/e2e/ffs_support_state_accounting_e2e.sh
```

It writes JSON and Markdown reports, checks historical 86/86, 90/90, and 100
percent migration classifications, injects unsafe flat parity wording, injects
missing owner beads, and runs the module unit tests.

## Docs Status Drift

Docs status drift validation consumes support-state accounting plus the ambition
evidence matrix, then checks generated wording snippets for README,
FEATURE_PARITY, required spec documents, CLI/help text, operator docs, and
proof-bundle summaries. It preserves feature claims by downgrading or scoping
wording rather than deleting capability rows.

Validate the current control surface with:

```bash
cargo run -p ffs-harness -- validate-docs-status-drift \
  --issues .beads/issues.jsonl \
  --feature-parity FEATURE_PARITY.md \
  --out artifacts/docs-status/docs_status_drift.json \
  --summary-out artifacts/docs-status/docs_status_drift.md
```

Observed snippet fixtures can be supplied with `--snippets <json>`. The gate
rejects hand-upgraded claims, stale flat-parity wording, missing support-state
or evidence-matrix references, missing remediation beads, and public statuses
stronger than the controlling support-state/gate outputs allow.

The report also carries release-gate wording contracts for `mount.rw.ext4`,
`mount.rw.btrfs`, `repair.rw.writeback`, `writeback_cache`,
`xfstests.baseline`, and `swarm.responsiveness`. Each contract records the exact
docs target, final/target state, controlling lane, missing artifact, and
remediation bead. README and FEATURE_PARITY wording may only strengthen when the
contract's final state is authoritative.

The E2E smoke is:

```bash
./scripts/e2e/ffs_docs_status_drift_e2e.sh
```

When RCH capacity is unavailable, use the no-worker wrapper self-check rather
than a local cargo fallback:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_DOCS_STATUS_DRIFT_SELF_CHECK=1 \
./scripts/e2e/ffs_docs_status_drift_e2e.sh
```

The self-check uses a stubbed `rch` binary to prove the wrapper extracts JSON
and Markdown validator output, preserves status/surface accounting and
structured drift tokens, rejects overclaim snippets, verifies focused unit-test
output, and preserves the shared `RCH_LOCAL_FALLBACK_REJECTED` marker. It does
not run cargo, mounted lanes, xfstests, fuzz/performance campaigns, or
permissioned campaigns.

It checks default generated snippets across all required public surfaces,
injects a hand-upgraded read-write repair claim, injects stale flat parity
wording, injects a release-gate overclaim for xfstests readiness, verifies
structured drift log fields, and runs the module unit tests.

## Tracker Source Hygiene

Tracker source hygiene keeps agent triage from treating foreign-looking Beads
rows as FrankenFS-ready work. The report is non-mutating by default and is safe
to run when `br ready` or `bv --robot-triage` is polluted by cross-project rows.

Run the live report with:

```bash
./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh
```

By default, the live report also runs a guarded deterministic fixture self-check
against `tests/fixtures/tracker_source_hygiene_report.golden.json`, including the
intentional mismatch guard. Set
`TRACKER_SOURCE_HYGIENE_DEFAULT_FIXTURE_SELF_CHECK=0` only when debugging the live
tracker report in isolation.

The E2E wrapper remains the artifact-producing gate. Tooling that only needs the
Rust queue-state classifier can call:

```bash
ffs-harness validate-tracker-source-hygiene --issues .beads/issues.jsonl
```

Run the deterministic fixture check with:

```bash
TRACKER_SOURCE_HYGIENE_ISSUES=tests/fixtures/tracker_source_hygiene.jsonl \
TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_OPEN=5 \
TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_OPEN=27 \
TRACKER_SOURCE_HYGIENE_EXPECT_READY=2 \
TRACKER_SOURCE_HYGIENE_EXPECT_PERMISSION_GATED=1 \
TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_NONCLAIMABLE=3 \
TRACKER_SOURCE_HYGIENE_EXPECT_IN_PROGRESS=2 \
TRACKER_SOURCE_HYGIENE_EXPECT_STALE_IN_PROGRESS=1 \
TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_IN_PROGRESS=2 \
TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_STALE_IN_PROGRESS=1 \
TRACKER_SOURCE_HYGIENE_NOW_EPOCH=2000000000 \
TRACKER_SOURCE_HYGIENE_STALE_IN_PROGRESS_SECONDS=3600 \
TRACKER_SOURCE_HYGIENE_EXPECT_GOLDEN=tests/fixtures/tracker_source_hygiene_report.golden.json \
TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_SAMPLE_COUNT=20 \
TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_GROUP_COUNT=4 \
./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh
```

The report emits `local_open_rows`, `source_aware_ready_rows`,
`source_aware_queue_state`, `local_graph_exports`, `permission_gated_rows`,
`blocked_local_rows`, `local_nonclaimable_rows`, `local_in_progress_rows`,
`stale_in_progress_rows`,
foreign in-progress/stale samples, `excluded_foreign_open_count`,
`excluded_foreign_in_progress_count`, prefix counts, foreign group summaries with
owner hints, sample foreign rows, and exact reproduction commands. It also writes
checksum-validated
`tracker_source_hygiene_local_open.jsonl` and
`tracker_source_hygiene_source_aware_ready.jsonl` artifacts for source-aware
graph/triage consumers, plus
`tracker_source_hygiene_local_nonclaimable.jsonl` for the local open rows that
are not safe to claim. Nonclaimable rows carry a stable `reason` of `epic`,
`permission_gated`, or `blocked`, with permission-gate or dependency details
attached. `source_aware_ready_rows` excludes real xfstests and permissioned
large-host swarm rows until their explicit ACK env vars are present.
`source_aware_queue_state.verdict` gives the safe queue explanation before
agents create fallback work, and its stale in-progress fields identify claimed
local rows that require Agent Mail/worktree verification before any reopen.
Foreign in-progress rows are reported only as excluded diagnostics and do not
affect the local stale-claim verdict. `TRACKER_SOURCE_HYGIENE_EXPECT_GOLDEN`
compares the deterministic
fixture report against the scrubbed committed golden so report-shape drift is a
reviewed diff. `TRACKER_SOURCE_HYGIENE_EXPECT_GOLDEN_MISMATCH=1` proves the
golden guard fails closed by diffing against an artifact-local corrupted golden
copy. Enable `TRACKER_SOURCE_HYGIENE_STRICT=1` only after the criteria in
[docs/tracker-hygiene.md](../../docs/tracker-hygiene.md) are met; strict mode
intentionally fails while foreign-looking open rows exist.

The Rust harness path can emit the same local graph export contract without the
shell wrapper when an export directory is supplied:

```bash
ffs-harness validate-tracker-source-hygiene \
  --issues .beads/issues.jsonl \
  --export-dir artifacts/tracker/source_hygiene \
  --out artifacts/tracker/source_hygiene/report.json
```

This writes `tracker_source_hygiene_local_open.jsonl`,
`tracker_source_hygiene_source_aware_ready.jsonl`,
`tracker_source_hygiene_local_nonclaimable.jsonl`, and matching `.sha256`
files under the export directory while keeping the tracker mutation policy
report-only.

## Claimability Autopilot

The claimability autopilot E2E is a fixture-only gate for agent queue guidance.
It runs `validate-tracker-source-hygiene` and `claimability-plan` through
`rch exec -- cargo run` and rejects transcripts that use local fallback. The
suite writes JSON and Markdown claimability plans under
`artifacts/claimability_autopilot/<run-id>/`, records the tracker report,
reservation snapshot, bv fixture, command transcripts, cleanup policy, and exact
next command hints in `result.json`, and checks that fixture tracker rows were
not mutated.

Run it with:

```bash
./scripts/e2e/ffs_claimability_autopilot_e2e.sh
```

The committed fixtures cover:

- zero-claimable permission-gated queues with parent-epic bv suppression
- one source-aware claimable task
- active peer reservation over the target file surface
- stale in-progress reclaim candidates that still require Agent Mail review
- foreign polluted rows preserved as owner handoff only

The script does not call bare `bv`, does not run local cargo validation, and
does not claim, close, rewrite, or edit tracker rows in fixture mode. Temporary
cleanup is disabled by default for this suite so no files are deleted by agent
runs; set `FFS_E2E_DISABLE_TEMP_CLEANUP=0` only when a human explicitly wants
standard temp cleanup.

For post-close reservation reconciliation, release the current agent's leases
first, then capture a fresh non-mutating reservation snapshot when one is
available. Treat active peer conflicts as handoff blockers, but classify
current-agent leftovers as `self_held` so the next agent can decide whether the
same lease is intentionally being reused or should be reported and released
again. Record the release result and any snapshot path in the Agent Mail thread;
do not force-release peer leases, delete reservation artifacts, or bypass live
`file_reservation_paths` conflicts.

## Release Gate Evaluation

Release gates are executable policy files that consume a validated proof bundle
and emit feature states plus generated public wording. The evaluator is
fail-closed: stale proof bundles, missing required lanes, lane failures, broken
artifacts, and threshold failures downgrade or block user-facing claims.
The canonical checked-in policy is
`tests/release-gates/release_gate_policy_v1.json`; generated or CI policies must
stay compatible with that fixture before they can strengthen README or
FEATURE_PARITY wording.

Evaluate a bundle with:

```bash
rch exec -- cargo run -p ffs-harness -- evaluate-release-gates \
  --bundle artifacts/proof/bundle/manifest.json \
  --policy tests/release-gates/release_gate_policy_v1.json \
  --current-git-sha "$(git rev-parse HEAD)" \
  --max-age-days 14 \
  --out artifacts/proof/release_gate.json \
  --wording-out artifacts/proof/release_gate_wording.tsv
```

Policy features declare `previous_state`, `target_state`, required proof-bundle
lanes, lane `risk_class` values, threshold checks, kill switches, docs wording
ids, and remediation beads or explicit non-goal rationale. Lane risk classes
differentiate generic evidence loss from `security_refused`,
`unsafe_repair_refused`, `noisy_performance`, and `host_capability_skip`
downgrades. Supported states are `hidden`, `disabled`, `deprecated_blocked`,
`dry_run_only`, `detection_only`, `experimental`, `opt_in_mutating`, and
`validated`.

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
proves missing evidence, stale SHA, threshold failures, hostile-image/security
refusal, unsafe repair refusal, noisy performance, and host capability skips
produce machine-readable downgrade diagnostics.

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
6. Explicit scrub/repair status and known-deferral lanes so readiness summaries preserve uncomfortable facts
7. Redaction policy unit coverage that preserves reproduction commands and artifact/scenario fields

The release gate suite exercises:

1. `evaluate-release-gates` CLI wiring and module export
2. Passing proof-bundle evidence consumed through policy-as-data
3. Generated README/FEATURE_PARITY-safe wording from final feature states
4. Fail-closed validation for missing evidence, stale evidence, and threshold failures
5. Required log fields for downgrade findings, remediation ids, docs wording ids, and reproduction commands
6. Unit coverage for feature-state transitions, kill switches, capability skips, explicit deferrals, and hand-edit-resistant wording

The invariant oracle suite exercises:

1. `validate-invariant-oracle` CLI wiring and module export
2. Replayable trace schema validation for create/write/fsync plus the executable model surfaces for nested rename/unlink, extent ownership, snapshot visibility, journal replay idempotence, and mounted repair writeback authority
3. Deterministic replay ids, artifact references, and reproduction commands in the JSON report
4. Consumer validation for model-version compatibility and malformed oracle artifacts
5. Expected invariant failure reporting with failure class, violated invariant, operation index, state hashes, expected/observed invariant result, and minimized trace prefix
6. Fail-closed validation for unexpected production/model mismatches
7. Unit coverage for schema parsing, deterministic replay, false-positive guards, expected failures, minimization, classification, consumer validation, rename/unlink edges, extent overlap rejection, snapshot/journal stability, repair serialization, and Markdown rendering

The cross-oracle arbitration suite exercises:

1. `validate-cross-oracle-arbitration` CLI wiring and module export
2. Fixture conflicts across invariant traces, mounted differential artifacts, repair confidence artifacts, crash replay survivors, and release-gate rows
3. Output preservation for classification, controlling artifact paths, blocked public claims, remediation ids, and reproduction commands
4. Fail-closed validation for unresolved high-risk mounted write, mutating repair, writeback-cache, background scrub mutation, and data-integrity claims
5. Fail-closed validation for stale or missing oracle evidence that is not routed through a gap-aware classification
6. Unit coverage for every disagreement category: model bug, kernel baseline issue, FrankenFS product bug, harness bug, fixture bug, unsupported scope, host capability gap, repair oracle gap, and inconclusive conflict

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
2. Planning artifacts for CI (`selected_tests.txt`, `summary.json`, `policy_plan.json`, `policy_report.md`)
3. Optional direct `xfstests check` execution when a configured checkout is available
4. Structured result artifacts (`results.json`, `junit.xml`) for per-commit tracking
5. Immutable baseline artifacts (`baseline_manifest.json`, `baseline_report.md`) with raw log hashes, checkpoint/resume commands, cleanup status, and per-test dispositions
6. Regression guard enforcement in run mode (`must_pass`, `min_pass_count`, `min_pass_rate`)
7. Safe skip/fail behavior via strictness toggle

The policy plan is a non-destructive planning artifact by default. It records
one row per curated xfstests id with the policy row id, filesystem flavor, V1
scope mapping, required capability, expected operation class, user-risk
category, expected outcome, artifact requirements, owning bead, and
reproduction command. The Markdown report counts product-actionable failures,
environment blockers, harness blockers, expected unsupported rows, not-run rows,
and pass candidates separately; CI and README wording must not compress those
categories into an xfstests pass claim.

The baseline manifest is the only durable input for later xfstests failure
triage. Every row records the subset version, environment manifest id, exact
command, raw artifact refs and SHA256 hashes, status vocabulary, checkpoint id,
resume command, cleanup status, output paths, and reproduction command.
Downstream triage must reject rows whose raw artifacts are missing, mutable, or
hash-drifted unless the row is explicitly `not_run` or `interrupted` with a
remediation/resume command.

Each row also carries a command-plan proof. The plan must name a temp-root
scratch path, temp-root mountpoint, image hash, helper binaries, required
privileges, mutation surface, cleanup action, execution lane, and argv vector.
Default CI planning is non-destructive: broad shell commands, non-temporary
paths, unknown privilege labels, unresolved helper placeholders, and destructive
actions outside the `permissioned_real` lane are rejected before any xfstests
coverage can be counted.

The permissioned campaign broker E2E suite is also non-destructive. It prepares
operator handoff packets for the real xfstests baseline and the large-host
swarm responsiveness run, then proves those packets remain authorization
material rather than executed evidence:

```bash
AGENT_NAME="${AGENT_NAME:-operator}" ./scripts/e2e/ffs_permissioned_campaign_broker_e2e.sh
```

The suite writes
`artifacts/e2e/<timestamp>_ffs_permissioned_campaign_broker/permissioned_campaign_broker/`
with these durable surfaces:

- `manifests/xfstests_ready_manifest.json`
- `manifests/swarm_ready_manifest.json`
- `manifests/swarm_blocker_manifest.json`
- `manifests/swarm_calibration_candidate_manifest.json`
- `manifests/swarm_calibration_blocked_manifest.json`
- `manifests/swarm_calibration_release_gate_bundle.json`
- `manifests/swarm_calibration_release_gate_policy.json`
- `reports/*_report.json` and `reports/*_report.md`
- `packets/*_handoff_packet.json` and `packets/*_handoff_packet.md`
- `blockers/xfstests_missing_inputs.json`
- `blockers/swarm_missing_inputs.json`
- `command_transcript.tsv`
- `non_execution_safety_report.json`

Use the validator and packet generator directly when promoting a generated
manifest into operator handoff material:

```bash
cargo run -p ffs-harness -- validate-permissioned-campaign-broker \
  --manifest artifacts/e2e/<run>/permissioned_campaign_broker/manifests/xfstests_ready_manifest.json \
  --out artifacts/e2e/<run>/permissioned_campaign_broker/reports/xfstests_ready_report.json \
  --summary-out artifacts/e2e/<run>/permissioned_campaign_broker/reports/xfstests_ready_report.md

cargo run -p ffs-harness -- generate-permissioned-campaign-packet \
  --manifest artifacts/e2e/<run>/permissioned_campaign_broker/manifests/xfstests_ready_manifest.json \
  --out artifacts/e2e/<run>/permissioned_campaign_broker/packets/xfstests_handoff_packet.json \
  --summary-out artifacts/e2e/<run>/permissioned_campaign_broker/packets/xfstests_handoff_packet.md

cargo run -p ffs-harness -- validate-swarm-capability-calibration \
  --manifest artifacts/e2e/<run>/permissioned_campaign_broker/manifests/swarm_calibration_candidate_manifest.json \
  --out artifacts/e2e/<run>/permissioned_campaign_broker/reports/swarm_calibration_candidate_report.json \
  --summary-out artifacts/e2e/<run>/permissioned_campaign_broker/reports/swarm_calibration_candidate_report.md
```

The xfstests ACK boundary is exactly
`XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices`; it must be
paired with explicit `XFSTESTS_DIR`, `TEST_DIR`, `SCRATCH_MNT`, and
`RESULT_BASE`. The swarm ACK boundary is exactly
`FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD=1`,
`FFS_SWARM_WORKLOAD_REAL_RUN_ACK=swarm-workload-may-use-permissioned-large-host`,
`FFS_SWARM_WORKLOAD_PERMISSIONED_RUNNER`, and
`FFS_SWARM_WORKLOAD_ARTIFACT_ROOT`. Broker packets and blocker artifacts are
not product pass/fail evidence. Proof bundles may carry them as
`permissioned_campaign_handoff_packet` or `permissioned_campaign_broker_report`
roles only when the lane stays non-pass and the metadata says
`permissioned_campaign_product_evidence_claim=none`.

The swarm capability calibration packet is a pre-run host classifier, not a
campaign result. It records CPU, RAM, NUMA visibility, storage class, FUSE
visibility, RCH worker identity, queue isolation, target-dir isolation, resource
caps, and the exact artifact root. Its classifications are
`authoritative_large_host_candidate`, `small_host_smoke`,
`capability_downgraded_smoke`, and `blocked`; all of them preserve
`product_evidence_claim=none`. The handoff is: use
`authoritative_large_host_candidate` only to decide whether the operator should
authorize `bd-rchk0.53.8`, then run the permissioned campaign to produce raw
workload logs, p99 attribution, proof-bundle swarm lanes, adaptive-runtime
evidence, cleanup status, and release-gate output. The calibration E2E includes
a release-gate fixture proving that calibration-only evidence keeps
`swarm.responsiveness` hidden until those real campaign artifacts exist.

### Adaptive Runtime Manifest Contract

`ffs_adaptive_runtime_manifest_e2e.sh` validates the checked-in adaptive
runtime evidence manifest without mounting FUSE or generating workload load. It
exercises the same `validate-adaptive-runtime-manifest` command that proof
bundles and release gates consume, captures JSON and Markdown reports, and
asserts that `accepted_large_host`, `per_core`, host classification, FUSE
capability, artifact counts, raw-log counts, ACK controls, and reproduction
commands stay explicit.

The suite also checks fail-closed boundaries: a strict `--current-git-sha`
mismatch and a malformed manifest with a missing `run_id` must both reject with
actionable diagnostics. It is a non-permissioned contract gate only; it does not
upgrade `swarm.responsiveness` or replace the permissioned large-host campaign.

When remote RCH capacity is unavailable, the deterministic wrapper self-check
proves JSON report extraction, Markdown/docs wording, fail-closed diagnostics,
focused unit-output checks, and local-fallback rejection without running cargo:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_ADAPTIVE_RUNTIME_MANIFEST_SELF_CHECK=1 \
./scripts/e2e/ffs_adaptive_runtime_manifest_e2e.sh
```

### Operator Readiness Dashboard

The readiness dashboard is a read-only display layer over strict validator
outputs. It consumes proof-bundle validation reports, release-gate reports,
operational evidence indexes, permissioned campaign reports or handoff packets,
readiness-lab advisory reports, and optional `.beads/issues.jsonl` rows. It
does not infer readiness, execute permissioned work, or strengthen
docs/FEATURE_PARITY wording outside those validator outputs.

```bash
rch exec -- cargo run -p ffs-harness -- readiness-dashboard \
  --proof-bundle-report artifacts/proof/bundle/report.json \
  --release-gate-report artifacts/proof/release_gate.json \
  --operational-evidence-index artifacts/e2e/evidence-index.json \
  --permissioned-campaign-report artifacts/e2e/permissioned_campaign_broker/reports/swarm_report.json \
  --readiness-lab-report artifacts/e2e/readiness_lab_contracts/reports/truth_graph.json \
  --readiness-lab-report artifacts/e2e/readiness_lab_contracts/reports/numa_p99_replay.json \
  --beads .beads/issues.jsonl \
  --format markdown
```

Each claim row shows the validator report path, claim state, controlling lane,
freshness, host class, missing artifacts, remediation bead, and next safe
command. Readiness-lab simulated, rehearsal, truth-graph, and replay reports
render as `advisory_only` rows with `product_evidence_claim=none`; they can
drive follow-up recommendations, but never mark the dashboard release-ready.
Each recommendation links back to a validator report or bead id so an operator
can inspect the authoritative source before changing public readiness claims.
The dashboard E2E is non-destructive and uses synthetic reports:

```bash
./scripts/e2e/ffs_readiness_dashboard_e2e.sh
```

### Readiness Action Autopilot Contract

`ffs_readiness_action_autopilot_e2e.sh` exercises the
`recommend-readiness-actions` dry-run CLI without executing any recommended
commands. The gate writes the JSON report, Markdown report, deterministic
stdout log, and deterministic stderr log, then checks that local-safe,
permissioned, stale-evidence, and impossible recommendations stay classified as
planner output rather than executed work.

The dry-run report also accepts advisory claimability-plan and RCH proof-ledger
inputs. These recommendations carry exact bead IDs, Agent Mail thread IDs when
known, reservation/proof artifact paths, and safe next commands, but they remain
operator evidence only: polluted tracker rows stay owner-handoff, permission
gates stay blocked until the exact ACK, raw bv parent-epic suggestions stay
suppressed when claimability has zero safe claims, and proof-capture artifacts
must not improve public readiness scores or parity percentages.

The suite treats malformed planning input as a fail-closed error and verifies
that the deterministic stderr log says permissioned, destructive, and
stale-evidence commands stayed dry-run only. It complements
`docs/runbooks/readiness-action-autopilot.md`; it does not authorize xfstests,
mounted mutation, package installs, or large-host campaigns.

### Non-Permissioned Readiness Lab Contracts

Readiness lab contracts describe advisory artifacts that help agents rehearse
large-host swarm, RCH scheduling, xfstests handoff, evidence graph, and dashboard
flows without producing product pass/fail evidence. The validator requires an
explicit advisory notice and rejects any contract that claims authoritative
product evidence.

```bash
rch exec -- cargo run -p ffs-harness -- validate-readiness-lab-contracts \
  --manifest artifacts/readiness-lab/contracts.json \
  --reference-epoch-days 20001 \
  --format markdown

rch exec -- cargo run -p ffs-harness -- simulate-readiness-lab-hosts \
  --manifest artifacts/readiness-lab/host_matrix.json \
  --reference-epoch-days 20001 \
  --format markdown

rch exec -- cargo run -p ffs-harness -- plan-readiness-lab-rch-lanes \
  --manifest artifacts/readiness-lab/rch_lanes.json \
  --reference-epoch-days 20001 \
  --format markdown

rch exec -- cargo run -p ffs-harness -- build-readiness-lab-truth-graph \
  --manifest artifacts/readiness-lab/truth_graph.json \
  --reference-epoch-days 20001 \
  --format markdown

rch exec -- cargo run -p ffs-harness -- validate-readiness-lab-numa-p99-replay \
  --manifest tests/readiness-lab/numa_p99_replay_fixtures.json \
  --reference-epoch-days 20001 \
  --format markdown
```

These artifacts are allowed to drive preflight, rehearsal, dashboard, and
runbook work. They are not allowed to mark xfstests or swarm responsiveness as
validated; release-gate and proof-bundle promotion still require the real
permissioned evidence lanes. The E2E suite builds synthetic advisory and
forbidden product-claim manifests plus a synthetic large-host matrix that
classifies candidate, small-host, downgraded, and blocked inventories while
preserving `product_evidence_claim=none`. It also emits a dry-run RCH lane
schedule for check, test, clippy, and dashboard commands, proving target-dir
isolation, dependency ordering, duplicate coalescing, and no local cargo
fallback without executing the planned lanes. The truth-graph fixture links
reports, claims, commands, artifacts, beads, host capabilities, freshness
windows, blockers, superseded stale evidence, and permission requirements while
proving every blocker edge points at a validator report path or bead id.
The NUMA/p99 replay fixture suite is a committed advisory manifest covering
balanced NUMA, skewed NUMA, metadata-read hot shards, repair/scrub
interference, RCH worker contention, and memory pressure. Its rollup emits
p50/p95/p99 attribution summaries and fails closed on malformed histograms,
missing p99 buckets, impossible CPU counts, or negative durations while keeping
`product_evidence_claim=none`.

```bash
./scripts/e2e/ffs_readiness_lab_contracts_e2e.sh
```

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
| `XFSTESTS_STRICT` | `0` | If `1`, missing xfstests prerequisites fail instead of skip; the regression gate also fails closed when current results or the baseline are missing, or when current results contain failed rows |
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

Strict regression-gate runs require both current xfstests results and the
baseline file. Non-strict runs still emit an advisory pass report when either
input is missing. When the regression gate launches `ffs_xfstests_e2e.sh`
itself, it only consumes the results path reported by that child invocation;
historical `artifacts/e2e/*/xfstests/results.json` files are not fallback
evidence. In strict mode, a nonzero child exit code is blocking even if the
child emitted partial or derived result artifacts. Strict post-hoc analysis of
`XFSTESTS_RESULTS_JSON` also fails on current `failed` rows even when the
baseline expected that test to be skipped or not run.

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

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_my_test}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR

e2e_init "my_test"
e2e_print_env

e2e_step "My Test"
e2e_rch_capture "$E2E_LOG_DIR/my_test.raw" cargo test -p my-crate

e2e_pass
```

Cargo build, check, test, clippy, bench, and run commands in E2E scripts must
go through `e2e_rch_capture` or a wrapper that delegates to it. The canonical
helper rejects local RCH fallback, non-compilation wrapper output, missing
remote-success evidence, and any `RCH_ARTIFACT_RETRIEVAL_*ACCEPTED` marker.
When RCH reports `Remote command finished: exit=0` but artifact retrieval keeps
the local wrapper alive, the helper may terminate the wrapper after the grace
window and records `RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT` with the
command-tagged raw log path.

The deterministic RCH regression matrix lives in `crates/ffs-harness/src/e2e.rs`
and models local fallback, non-compilation wrapper rejection, remote build
failure, remote test failure, remote success followed by artifact retrieval
hang, timeout before remote exit, and missing remote evidence. It uses transcript
fixtures only; it must never invoke real workers. The no-worker smoke command
below verifies that the fixture marker vocabulary still matches the live helper:

```bash
bash -c 'source scripts/e2e/lib.sh; e2e_rch_capture_fixture_matrix_self_test'
```

To add a new RCH failure class, add one transcript fixture with the expected
marker, remote exit, wrapper exit code, and authority classification, then add
the marker to `e2e_rch_capture_fixture_matrix_markers` only if the live helper
emits or parses a new marker. Do not add any accepted artifact-retrieval marker;
new classes must preserve the existing local-fallback, timeout, missing-evidence,
and artifact-retrieval fail-closed checks.

## RCH Proof Ledger Gate

`ffs_rch_proof_ledger_e2e.sh` is a no-worker fixture gate for operator proof
handoffs. It writes synthetic RCH transcripts plus JSON and Markdown ledgers
covering clean remote success, degraded artifact retrieval, and local fallback
rejection. The fixture lane must not invoke cargo, `rch`, or `e2e_rch_capture`.

Run it with cleanup disabled when preserving artifacts for review:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 ./scripts/e2e/ffs_rch_proof_ledger_e2e.sh
```

For real transcripts, use the harness parser documented in
`docs/runbooks/rch-proof-ledger.md`:

```bash
ffs-harness rch-proof-ledger --transcript artifacts/e2e/run/cargo_check.raw \
  --command-arg cargo --command-arg check --command-arg -p \
  --command-arg ffs-harness --command-arg --all-targets \
  --cwd /data/projects/frankenfs --env CARGO_TARGET_DIR \
  --out artifacts/e2e/run/rch_proof_ledger.json \
  --summary-out artifacts/e2e/run/rch_proof_ledger.md
```

## RCH Capacity Preflight Gate

`ffs_rch_capacity_preflight_e2e.sh` is the live, non-mutating capacity check to
run before expensive remote-only proof lanes when RCH appears degraded. It
captures `rch status --json`, classifies admissible workers, critical pressure,
telemetry gaps, unreachable workers, and operator actions, then writes
`rch_capacity_preflight_report.json` plus a short Markdown summary.
Each default run also executes deterministic fixture self-checks with a stubbed
`rch` binary so the report contract is proven for both an admissible
remote-success case and a fail-closed local-fallback case without depending on
live worker health. Set `FFS_RCH_CAPACITY_PREFLIGHT_SKIP_FIXTURE_SELF_CHECK=1`
only when reproducing a live-only transcript.

The default run does not invoke workers:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 ./scripts/e2e/ffs_rch_capacity_preflight_e2e.sh
```

Set `FFS_RCH_CAPACITY_PREFLIGHT_RUN_PROBE=1` to add a small
`RCH_REQUIRE_REMOTE=1 rch exec -- cargo check -p ffs-error --lib` probe. Any
local fallback is recorded as `RCH_LOCAL_FALLBACK_REJECTED` and remains a
capacity blocker, not validation proof. A probe without an RCH remote/local
summary is rejected as ambiguous:

```bash
FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
FFS_RCH_CAPACITY_PREFLIGHT_RUN_PROBE=1 \
./scripts/e2e/ffs_rch_capacity_preflight_e2e.sh
```

Use the resulting capacity artifact to explain why remote proof is unavailable.
Do not close compiler, clippy, conformance, or mounted-write beads with only a
`no_admissible_workers` or local-fallback preflight result.
