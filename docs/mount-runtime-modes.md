# Mount Runtime Modes — Operator Guide

## Modes

| Mode | Flag | Behavior |
|------|------|----------|
| `standard` | `--runtime-mode standard` (default) | Blocking mount via `fuser::mount2`. Process exits on unmount. |
| `managed` | `--runtime-mode managed` | Background mount with graceful Ctrl+C shutdown and metrics. |
| `per-core` | `--runtime-mode per-core` | Managed mount with thread-per-core dispatch and per-core metrics. |

## Runtime Console Artifact Contract

`ffs mount --console` emits a schema-pinned runtime console artifact when a
managed or per-core mount shuts down. The checked-in contract is
`crates/ffs-harness/src/runtime_console_report.rs`, report ID
`runtime_console_report`, schema version `1`.

### Enabling the console

```bash
# Managed mount: console JSON to the default artifact path
# (artifacts/runtime-console/<operation-id>.json).
ffs mount image.img /mnt/ffs --runtime-mode managed --console

# Per-core mount: explicit JSON + Markdown summary destinations.
ffs mount image.img /mnt/ffs --runtime-mode per-core --rw --console \
  --console-json artifacts/runtime-console/per_core_run.json \
  --console-summary artifacts/runtime-console/per_core_run.md
```

| Flag | Effect |
|------|--------|
| `--console` | Enable the console; on shutdown emit a JSON artifact (default path under `artifacts/runtime-console/`). |
| `--console-json <path>` | Write the console JSON to an explicit path (requires `--console`). |
| `--console-summary <path>` | Also write a Markdown summary (requires `--console`). |

Incompatible combinations fail closed at flag parsing:

- `--console` with `--runtime-mode standard` is rejected — the standard runtime
  has no managed metrics surface to snapshot.
- `--console-json` / `--console-summary` without `--console` are rejected.

A disabled console is a true no-op: no observation is gathered and no artifact
is written. An enabled console always writes a JSON artifact so a run never
leaves a hollow, evidence-free console claim.

### Console field meanings

| Field | Operator meaning |
|-------|------------------|
| `operation_id`, `scenario_id` | Stable identifiers for the mount run and its CLI scenario. |
| `runtime_mode` | `managed` or `per_core`; `managed` always reports `worker_count=1`. |
| `read_write` | Whether the mount was writable. |
| `worker_count` | Per-core worker count (per-core mode) or `1` (managed mode). |
| `started_at`, `shutdown_at` | UTC RFC3339 mount start and shutdown timestamps. |
| `counters.requests_total` | Total FUSE requests dispatched. The runtime does not tag op classes, so the whole count is surfaced under `requests_metadata`. |
| `counters.bytes_read` / `bytes_written` | Bytes served; `bytes_written` is `0` (the FUSE metrics snapshot does not split write bytes). |
| `counters.errors_total` | Requests that completed with an error. |
| `counters.throttled_requests` / `shed_requests` | Requests delayed / rejected by backpressure. |
| `backpressure_decisions` | `pass` / `throttle` / `shed` / `emergency` / `no_signal` tallies summing to `requests_total`. |
| `degradation_level` | `normal`, `degraded`, `throttling`, `shedding`, or `emergency` at shutdown. |
| `per_core_distribution.rows` | Per-core request count and cache hit/miss counts (per-core mode). |
| `per_core_distribution.imbalance_ratio` | Max/min per-core request ratio (`1.0` = perfectly balanced). |
| `cleanup_status` | `clean` on a graceful shutdown; `preserved_artifacts` when the run did not finish cleanly. |
| `reproduction_command` | The exact `ffs mount` command to reproduce the run. |

The artifact is operational observability only:

| Field | Required value |
|-------|----------------|
| `product_evidence_claim` | `none` |
| `release_gate_effect` | `operational_observability_only` |
| `claim_state.swarm_responsiveness` | `not_claimed` |
| `claim_state.adaptive_runtime` | `not_claimed` |

Console persistence is fail-closed unless host paths, mountpoints, and operator
environment values are redacted. Artifact paths recorded in the report are
repository-relative `artifacts/...` paths or redacted FrankenFS temp artifact
roots; a console output path outside `artifacts/` is redacted to
`artifacts/runtime-console/<file_name>` so a persisted report never leaks an
operator host path. Log volume, snapshot count, and interval cadence are bounded
by the harness contract (`16 MiB`, `240` snapshots, and `1s..600s`).

### Forbidden interpretations

| Do not claim from console output | Reason |
|----------------------------------|--------|
| `swarm.responsiveness` validated | Console output is local operational observability. `swarm.responsiveness` requires the permissioned large-host campaign (`bd-rchk0.53.8`) with raw workload logs, p99 attribution, and proof-bundle lanes. |
| `adaptive_runtime` proof-bundle pass | The console never sets `adaptive_runtime` acceptance; the adaptive runtime proof-bundle lane needs its own fresh artifacts. |
| xfstests pass/fail/not-run baseline | The console reports runtime counters, not conformance execution evidence. |
| permissioned large-host evidence | A local console run is not a large-host campaign result on its own. |
| public readiness upgrade | `product_evidence_claim=none` and `release_gate_effect=operational_observability_only`. |

### Validating a console artifact

The non-permissioned validator checks a `runtime_console_report` JSON artifact
against the schema/safety contract without mounting anything:

```bash
ffs-harness validate-runtime-console \
  --report artifacts/runtime-console/per_core_run.json \
  --format json
```

`scripts/e2e/ffs_runtime_console_e2e.sh` is the dry, non-mutating fixture lane
(suite `ffs_runtime_console` in `scripts/e2e/scenario_catalog.json`): it proves
honest console fixtures validate and contract violations fail closed. It does
not mount a filesystem, run xfstests, or run a permissioned campaign.

### Console failure triage

| Symptom | Likely cause | Operator action |
|---------|--------------|-----------------|
| `--console` rejected at flag parsing | Used with `--runtime-mode standard`. | Re-run with `--runtime-mode managed` or `per-core`. |
| `--console-json` rejected | `--console` not set. | Add `--console`, or drop the output-path flag. |
| Console log line `runtime_console_snapshot_skipped` | The runtime observation was internally inconsistent. | Inspect the `reason` field; the mount itself still completed — the console artifact was skipped, not silently dropped. |
| Console log line `runtime_console_report_advisory_only` | The emitted report failed schema validation (for example a per-core mount with an idle, zero-request worker). | The artifact is still written; treat it as advisory and inspect `issue_count`. |
| `validate-runtime-console` reports `stale runtime console report` | The artifact's `shutdown_at` is older than the freshness window. | Pass `--reference-timestamp` for a deterministic fixture check, or regenerate the artifact. |
| `validate-runtime-console` rejects an artifact path | The report references a path outside `artifacts/` or a secret-bearing path. | Re-emit the console under `artifacts/runtime-console/`. |
| Console E2E logs `RCH_LOCAL_FALLBACK_REJECTED` | The cargo build lane could not reach an admissible RCH worker. | Retry once RCH capacity recovers; the validator runs locally once the harness binary is built. |

The permissioned large-host boundary for `swarm.responsiveness` evidence is
`bd-rchk0.53.8`; console output never substitutes for that campaign.

## Topology Runtime Advisor

The topology runtime advisor is a non-permissioned preflight for choosing a
runtime mode before a later permissioned `bd-rchk0.53.8` swarm responsiveness
campaign. It validates and scores `docs/topology-runtime-advisor-manifest.json`,
emits dry-run artifacts, and preserves `advisory_only` plus
`product_evidence_claim=none`. It is not xfstests evidence, not
`swarm.responsiveness` evidence, not an `adaptive_runtime` proof-bundle pass, and
not a public release readiness upgrade.

Run the validation and scoring lanes through RCH when producing repo evidence:

```bash
RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR rch exec -- \
  env CARGO_TARGET_DIR=/data/projects/.cargo-target-frankenfs-topology-advisor \
  cargo run --quiet -p ffs-harness -- validate-topology-runtime-advisor \
    --manifest docs/topology-runtime-advisor-manifest.json \
    --out artifacts/topology-advisor/report.json \
    --summary-out artifacts/topology-advisor/summary.md \
    --structured-log-out artifacts/topology-advisor/structured.jsonl

RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR rch exec -- \
  env CARGO_TARGET_DIR=/data/projects/.cargo-target-frankenfs-topology-advisor \
  cargo run --quiet -p ffs-harness -- score-topology-runtime-advisor \
    --manifest docs/topology-runtime-advisor-manifest.json \
    --out artifacts/topology-advisor/score.json \
    --summary-out artifacts/topology-advisor/score.md \
    --structured-log-out artifacts/topology-advisor/score.jsonl
```

### Manifest Fields

| Field | Operator meaning |
|-------|------------------|
| `manifest_version` | Schema version; current value is `1`. |
| `operation_id`, `scenario_id` | Stable identifiers for the advisory run and workload scenario. |
| `source_bead` | Bead that produced the advisor package; this should remain in the `bd-rchk0.212.*` family. |
| `real_campaign_bead` | Permissioned campaign handoff target; use `bd-rchk0.53.8` for swarm responsiveness. |
| `generated_at`, `expires_at` | Freshness window; stale or future manifests fail closed. |
| `manifest_path`, `artifact_root`, `artifact_paths` | Relative paths for the manifest and emitted artifacts. Use a new artifact root for each run. |
| `host_topology` | CPU count, NUMA visibility, RAM bytes, and storage profile used for candidate scoring. |
| `fuse_capability` | FUSE availability used to reject managed/per-core candidates when `/dev/fuse` is absent or denied. |
| `rch_worker_identity` | Optional worker fingerprint; refresh the manifest if the worker changes before handoff. |
| `resource_caps` | Duration, thread, memory, temp-storage, and queue-depth limits for the later campaign plan. |
| `runtime_candidates` | Candidate modes (`standard`, `managed`, `per_core`) and the operator reason each is allowed. |
| `workload_shapes` | Hot-inode concentration, directory fanout, read/write mix, fsync cadence, dirty bytes, and queue depth. |
| `command_transcript` | Invocation and stdout/stderr/JSON/Markdown/log destinations for reproducibility. |
| `product_evidence_claim` | Must be `none`. |
| `release_gate_effect` | Must be `advisory_only`. |

### Report Interpretation

| Report field | How to use it |
|--------------|---------------|
| `valid` / `outcome` | `true` / `pass` means the advisory input is well-formed and fresh; it still is not product evidence. |
| `host_classification` | `large_host_floor_met` means the manifest describes enough CPU/RAM/NUMA for per-core scoring; it is not a release state. |
| `fuse_capability_state` | `available` keeps managed/per-core candidates eligible; missing or denied FUSE keeps those candidates rejected. |
| `recommendation` | Suggested runtime mode for the later campaign command line. `none` means stay on `standard` or refresh inputs. |
| `confidence_tier` | `high`, `medium`, `low`, or `no_recommendation`; low confidence should trigger another manifest pass before handoff. |
| `candidate_scores` | Ordered candidate scores with rejection reasons and rationale for mode selection. |
| `rejected_candidates` | Count of modes rejected by manifest capability or operator configuration. |
| `loss_risk_ledger` | Expected-loss signals such as `hot_inode_imbalance`, `small_host_downgrade`, and `writeback_backpressure`. |
| `release_claim_state` | Must remain `not_product_evidence` in score output. |

Use the recommendation only to choose the planned `ffs mount --runtime-mode`
value for a real campaign. Prefer `managed` when the ledger shows
`hot_inode_imbalance` or `writeback_backpressure`; prefer `per-core` only when
the host topology floor is visible, FUSE is available, and read-heavy fanout is
the dominant signal. Keep `standard` for low confidence, missing capabilities,
or no recommendation.

### Permissioned Handoff

The handoff target for swarm responsiveness is `bd-rchk0.53.8`. Attach the
advisor validation report, score report, structured logs, manifest hash, and
artifact paths to the permissioned campaign packet. The real campaign still
requires:

```bash
FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD=1
FFS_SWARM_WORKLOAD_REAL_RUN_ACK=swarm-workload-may-use-permissioned-large-host
FFS_SWARM_WORKLOAD_PERMISSIONED_RUNNER=<configured runner>
```

The advisor output must not consume those tokens, run the campaign, or mark
`swarm.responsiveness` complete. xfstests remains under its own explicit
`XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices` contract
and is not affected by topology advisor reports.

### Forbidden Promotions

| Do not claim from advisor output | Required wording |
|----------------------------------|------------------|
| `swarm.responsiveness` validated | `swarm.responsiveness` remains blocked until `bd-rchk0.53.8` produces raw workload logs, p99 attribution, proof-bundle lanes, cleanup status, and release-gate output. |
| xfstests pass/fail/not-run baseline | Topology advisor reports are unrelated to xfstests execution evidence. |
| `adaptive_runtime` proof-bundle pass | Advisor reports can feed planning only; proof-bundle lanes need their own fresh artifacts. |
| accepted large-host release state | Host topology floor visibility is advisory input, not release acceptance. |
| public readiness upgrade | `product_evidence_claim=none` and `release_gate_effect=advisory_only`. |

### NUMA Allocation Topology Contract

`ffs-alloc` owns the executable NUMA placement contract through
`NumaAllocationTopology` and `validate_numa_allocation_topology`. Topology and
adaptive runtime reports may feed this contract, but their evidence claim must
remain `AdvisoryOnly`; attempts to convert advisor replay into product readiness
are rejected before allocator placement can use the input.

| Source | Accepted shape | Allocator meaning |
|--------|----------------|-------------------|
| `Unknown` | Non-empty reason, no node map. | Preserve existing `AllocHint` semantics and fall back to group 0 when no explicit hint exists. |
| `SingleNode` | Host is known to expose one NUMA node. | Map every block group to node 0 and keep this as fallback semantics, not readiness evidence. |
| `Observed` | Fresh bounded evidence with non-overlapping node ranges covering every block group exactly once. | Optional NUMA preference may choose the first group on the preferred node when no explicit allocation hint exists. |

The contract rejects missing observed maps, duplicate group ownership,
uncovered groups, out-of-range group ranges, invalid node ids, stale or
unbounded evidence windows, and missing downstream consumer declarations.
Required consumers are `ffs-alloc`, `ffs-core`,
`topology_adaptive_runtime_reports`, `proof_bundle_release_gate`, and `docs`.

Placement precedence is fixed:

1. `AllocHint.goal_group`
2. `AllocHint.goal_block`
3. Optional preferred NUMA node from a validated advisory plan
4. Legacy fallback group 0

`ffs-core` carries the runtime NUMA allocation policy and propagates validated
preferences into this contract, and topology/adaptive reports may name the
proposed node map, but proof bundles and release gates must keep the wording
advisory until independent release evidence exists.

### Opt-in NUMA Allocation Policy

NUMA-aware allocation placement is **opt-in and off by default**. The runtime
policy lives in `ffs-core` as `NumaAllocationPolicy`:

| Policy | Behavior |
|--------|----------|
| `Disabled` (default) | Legacy allocator hints only; no NUMA preference is attached. The compatibility fallback is `goal_group` → `goal_block` → group 0. |
| `PreferredNode` | Validates `NumaAllocationTopology`, attaches a `NumaAllocationPreference` for `preferred_node`, and carries a `NumaAllocationClaimTier` (`advisory` or `capability_downgraded`). |

When the policy is active, `ffs-core` emits a `numa_allocation_hint` trace
record per allocation decision (`op`, `inode`, `preferred_node`,
`selected_group`, `disposition`, `claim_tier`, `fallback_reason`,
`explicit_goal_group`, `explicit_goal_block`) and a `numa_allocation_hint_fallback`
warning whenever topology validation fails. Explicit `goal_group`/`goal_block`
hints always win over a NUMA preference, so enabling the policy never changes
ext4/btrfs on-disk allocation semantics — it only reorders the candidate group
search when no explicit hint is present.

### NUMA Allocation Placement Evidence

The `numa_allocation_placement_report` contract
(`crates/ffs-harness/src/numa_allocation_placement_report.rs`, report ID
`numa_allocation_placement_report`, schema version `1`) turns the
`numa_allocation_hint` decision logs, the validated group-to-node map, and an
optional p99 latency attribution into a single advisory evidence artifact.

Non-permissioned validation (dry, no mount, no campaign):

```bash
ffs-harness validate-numa-allocation-placement \
  --report artifacts/numa-placement/run.json \
  --reference-unix-secs "$(date +%s)" \
  --format json --summary-out artifacts/numa-placement/run.md
```

`scripts/e2e/ffs_numa_allocation_placement_e2e.sh` is the dry replay lane
(suite `ffs_numa_allocation_placement` in `scripts/e2e/scenario_catalog.json`):
it proves the balanced, skewed-metadata, preferred-node-exhaustion,
cross-node-fallback, repair/scrub-interference, and unknown-topology replay
fixtures validate, and that stale topology and `swarm.responsiveness` promotion
fail closed.

The report fields a support engineer needs:

| Field | Operator meaning |
|-------|------------------|
| `topology_source` | `observed`, `single_node`, or `unknown` — the evidence source backing placement. |
| `node_count` / `group_count` | NUMA nodes and block groups the report covers. |
| `group_node_map` | The validated group-to-node assignment (`observed` topology only). |
| `topology_observed_at_unix_secs` / `topology_max_age_secs` | Freshness window; stale or future observed topology fails closed. |
| `claim_tier` | `advisory` or `capability_downgraded`. |
| `decisions` | `advisory_map_used`, `explicit_hint`, and `fallback_unknown_topology` / `fallback_single_node` / `fallback_validation_error` tallies — the per-decision `fallback_reason` rolled up. |
| `p99` | `baseline_p99_micros`, `observed_p99_micros`, and the `outcome` (`helped`, `hurt`, `neutral`, `not_attributed`). |
| `release_gate_effect` | `advisory_replay_only` (advisory tier) or `small_host_downgrade_only` (capability-downgraded tier). |
| `artifact_paths` / `raw_log_paths` | Repository-relative redacted artifact and raw `numa_allocation_hint` log locations. |
| `reproduction_command` | The exact validator command to reproduce the report. |

The validator rejects any report whose `release_gate_effect` is stronger than
the claim tier allows: even a p99 `helped` outcome stays advisory replay or
small-host downgrade evidence. `product_evidence_claim` must be `none` and
`swarm_responsiveness_claim` must stay `not_claimed`.

### NUMA Readiness Boundary

NUMA placement readiness is separated into four evidence tiers:

| Tier | What it proves | Where it lives |
|------|----------------|----------------|
| Implemented opt-in behavior | The allocator hook, contract, and runtime policy exist and preserve compatibility semantics. | `ffs-alloc`/`ffs-core`; closed beads `bd-53b28.1/.2/.3`. |
| Advisory replay evidence | A `numa_allocation_placement_report` with `claim_tier=advisory` from replay fixtures or a non-permissioned run. | `validate-numa-allocation-placement`; `release_gate_effect=advisory_replay_only`. |
| Small-host downgrade evidence | A placement report from a host that cannot meet the large-host floor. | `claim_tier=capability_downgraded`; `release_gate_effect=small_host_downgrade_only`. |
| Authoritative large-host proof | NUMA placement *measurably* improves `swarm.responsiveness`. | The permissioned campaign **`bd-rchk0.53.8`** only. |

Authoritative large-host evidence requires the same permissioned contract used
elsewhere — a 64+ logical CPU / 256GB+ host with visible NUMA topology and:

```bash
FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD=1
FFS_SWARM_WORKLOAD_REAL_RUN_ACK=swarm-workload-may-use-permissioned-large-host
FFS_SWARM_WORKLOAD_PERMISSIONED_RUNNER=<configured runner>
```

The `numa_allocation_placement_report` advisory artifact must never consume
those tokens, run the campaign, or mark `swarm.responsiveness` complete. The
release-gate wording contract `numa.allocation.placement`
(`crates/ffs-harness/src/docs_status_drift.rs`, controlling lane
`numa_allocation_placement`, remediation bead `bd-rchk0.53.8`) keeps the README
roadmap wording downgraded: `validate-docs-status-drift` fails if docs claim
NUMA allocation readiness without that authoritative large-host evidence.

### NUMA Troubleshooting

| Symptom | Likely cause | Operator action |
|---------|--------------|-----------------|
| `numa_allocation_hint` logs show `fallback_reason=unknown_topology` | The host topology probe produced no trusted node map. | Expected on small/unknown hosts; placement preserves legacy `goal_group` semantics. Not a defect. |
| `fallback_reason=single_node_topology` | The host exposes one NUMA node. | Expected single-node fallback; NUMA preference cannot help and is not used. |
| `numa_allocation_hint_fallback` warnings | `validate_numa_allocation_topology` rejected the input (stale evidence, impossible map, missing consumers). | Refresh the topology evidence; the allocator already fell back safely to legacy hints. |
| `validate-numa-allocation-placement` reports `stale topology evidence` | The report's `topology_observed_at_unix_secs` is older than `topology_max_age_secs`. | Regenerate the placement report from a fresh `numa_allocation_hint` log, or pass `--reference-unix-secs` for a deterministic fixture check. |
| `validate-numa-allocation-placement` reports an `impossible group-to-node map` | A group maps to a node ≥ `node_count`, a group is mapped twice, or coverage is incomplete. | The placement evidence is corrupt — re-derive the group-to-node map from the validated `NumaAllocationTopology`. |
| `p99.outcome does not match baseline/observed p99` | The report's `p99.outcome` was hand-edited or mis-derived. | Recompute the outcome from `baseline_p99_micros`/`observed_p99_micros`; the validator never trusts a stated outcome over the measured delta. |
| Disabled policy, no `numa_allocation_hint` logs | `NumaAllocationPolicy::Disabled` (the default). | Expected; enable `PreferredNode` only with a validated advisory topology and never to make a public readiness claim. |

### Topology Advisor Troubleshooting

| Symptom | Likely cause | Operator action |
|---------|--------------|-----------------|
| High imbalance or `hot_inode_imbalance` | One inode or directory shard dominates request routing. | Plan `managed`, reduce per-core expectations, and capture the hot workload shape for the real campaign. |
| Low NUMA visibility or `small_host_downgrade` | The worker exposes too few CPUs, too little RAM, or fewer than two NUMA nodes. | Refresh the host probe on a capable worker; keep `per_core` rejected until the large-host floor is visible. |
| Missing FUSE capability | `/dev/fuse` is absent, denied, or disabled by operator policy. | Fix host capability before managed/per-core campaign planning; do not treat the advisory skip as mount evidence. |
| Stale RCH worker fingerprint | `generated_at` is too old or `rch_worker_identity` no longer matches the intended worker. | Regenerate the manifest and rerun validation/scoring before handoff. |
| Overloaded artifact root | Multiple runs share the same `artifact_root` or logs are too large to inspect. | Use a unique artifact root for the next run and preserve the previous artifact paths in the packet. |

## Hostile-Image Boundary

Mount runtime mode does not upgrade hostile-image readiness by itself. Malformed
images, hostile proof artifacts, tampered repair ledgers, resource-exhaustion
seeds, unsupported mount options, and unsafe operator command combinations are
controlled by `security/adversarial_image_threat_model.json`.

Operators should distinguish:

| Case | Expected public status |
|------|------------------------|
| Hostile or malformed image containment | Evidence-gated by `validate-adversarial-threat-model` and security E2E artifacts. |
| Ordinary corruption repair | Covered by scrub/repair evidence; does not imply hostile-image containment. |
| Unsupported mount option or unavailable host capability | Deterministic unsupported/skip classification, not readiness. |
| Detection-only scrub | May inspect and log findings but must not mutate the image. |
| Mutating repair | Requires explicit opt-in plus fresh preflight, ledger, backup/rollback, and release-gate evidence. |

## Soak And Canary Campaigns

Single mounted smoke tests do not prove endurance. The campaign contract in
`benchmarks/soak_canary_campaign_manifest.json` defines bounded `smoke`,
`nightly`, `stress`, and `canary` profiles for repeated mount/unmount/reopen,
metadata churn, read/write/verify, repair scrub dry-runs, writeback-cache gate
checks, and artifact aggregation.

The local dry-run validator is:

```bash
cargo run -p ffs-harness -- validate-soak-canary-campaigns \
  --manifest benchmarks/soak_canary_campaign_manifest.json \
  --artifact-root artifacts/soak/dry-run \
  --out artifacts/soak/campaign_report.json \
  --artifact-out artifacts/soak/sample_artifact_manifest.json \
  --summary-out artifacts/soak/campaign_summary.md
```

Long `nightly`, `stress`, and `canary` profiles are for RCH, CI, or manual
permissioned hosts. They must record kernel, FUSE capability, toolchain, git
SHA, workload IDs, seeds, duration, resource usage, cleanup status, and the
reproduction command. Recurring flakes must preserve a repro pack and link a
follow-up bead; they are not allowed to silently soften release gates.

## Read-Write Repair Writeback

Read-write mounted automatic repair is fail-closed until client writes and
repair writeback share one serializer. The executable contract is:

```bash
cargo run -p ffs-harness -- validate-repair-writeback-serialization \
  --contract docs/repair-writeback-serialization-contract.json \
  --artifact-root artifacts/repair-writeback/dry-run \
  --out artifacts/repair-writeback/contract_report.json \
  --artifact-out artifacts/repair-writeback/sample_artifact_manifest.json \
  --summary-out artifacts/repair-writeback/contract_summary.md
```

The contract requires MVCC snapshot epoch evidence, an active repair lease
before mutation, `fsync`/`fsyncdir` as the durability boundary, stale-symbol
refusal, cancellation cleanup, halfway writeback failure handling, and
`rw_repair_serialization_missing` when a read-write mounted repair mutation is
requested before the serializer exists. `flush` is not a durability boundary.

Implementation hook: `OpenFs::repair_writeback_blocks_via_mounted_mutation_path`
stages recovered physical blocks in a `RequestOp::RepairWriteback` MVCC request
scope, first checks that mounted-visible bytes still match the
repair-planning-time `expected_current` bytes, commits through the same mutation
authority as mounted writes, flushes the committed versions to the backing
image, verifies durable bytes, and only then allows repair-symbol refresh
consumers to proceed. Stale repair snapshots fail closed before staging and do
not trigger refresh lifecycle notifications. `ffs-repair` also makes
recovered-block writeback an explicit `RecoveryWriteback` authority; the default
direct-device authority remains scoped to offline repair and client read-only
mount repair.

## Startup Banner

The CLI prints the active runtime mode in the startup banner:
```
Mounting ext4 image (block_size=4096, blocks=131072, ro, runtime=managed) at /mnt/ffs
```

Structured logs also include `runtime_mode` in the `mount_start` and
`mount_runtime_mode_selected` events at target `ffs::cli::mount`.

## Pressure Telemetry

FrankenFS tracks backpressure events in two counters:

| Counter | Meaning |
|---------|---------|
| `requests_throttled` | Requests delayed (but completed) due to degraded state. |
| `requests_shed` | Requests rejected entirely due to critical/emergency state. |

These appear in:
- **Structured logs** at `ffs::cli::mount` on `managed_mount_shutdown_complete`
- **FUSE unmount log** at unmount time

### Interpreting Pressure Events

- **`requests_throttled > 0`**: The filesystem entered `Degraded` state during
  operation. Write operations were delayed by 10ms each. Investigate storage
  I/O latency or CPU contention.

- **`requests_shed > 0`**: The filesystem entered `Critical` or `Emergency`
  state. Metadata writes were rejected (`ENOSPC`-style). This typically
  indicates severe resource exhaustion — check disk space, I/O errors, and
  system load.

- **Both zero**: Normal operation. No backpressure was applied.

## Timeout Configuration

The `--managed-unmount-timeout-secs` flag controls the grace period for
in-flight requests during shutdown (default: 30s). Only valid with `managed`
or `per-core` modes.

If you see "unmount timed out" warnings, increase this value or investigate
why requests are taking longer than expected to complete.

## Per-Core Mode Details

Per-core mode logs additional metrics on shutdown:
- `num_cores`: Number of worker threads used.
- `imbalance_ratio`: Max/min request distribution across cores (1.0 = perfect).
- Per-core cache hit/miss rates (at `debug` level).

High `imbalance_ratio` (>3.0) indicates hot inodes concentrating on one core.
Consider whether your workload is amenable to the inode-based routing strategy.
