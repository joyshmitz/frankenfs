# Soak And Canary Campaigns

Source artifact: `benchmarks/soak_canary_campaign_manifest.json`

Validator:

```bash
cargo run -p ffs-harness -- validate-soak-canary-campaigns \
  --manifest benchmarks/soak_canary_campaign_manifest.json \
  --artifact-root artifacts/soak/dry-run \
  --out artifacts/soak/campaign_report.json \
  --artifact-out artifacts/soak/sample_artifact_manifest.json \
  --summary-out artifacts/soak/campaign_summary.md
```

E2E smoke:

```bash
./scripts/e2e/ffs_soak_canary_campaign_e2e.sh
```

## Contract

The manifest defines four profiles:

| Profile | Purpose |
|---------|---------|
| `smoke` | Bounded local dry-run for CI and developer validation |
| `nightly` | RCH/CI endurance profile for repeated mount, repair, and aggregation checks |
| `stress` | Large-worker profile for 256GB+ RAM and 64+ core hosts |
| `canary` | Manual permissioned pre-release profile feeding readiness wording |

Long profiles must record kernel, FUSE capability, toolchain, git SHA, workload
IDs, seeds, duration, resource usage, cleanup status, and reproduction command.
They are not allowed to turn missing `/dev/fuse`, helper binaries, or mount
permissions into product failures; those cases must be structured host skips.

## Failure Semantics

Campaign output uses five classifications: `pass`, `fail`, `skip`, `error`,
and `flake`.

- `fail` is a product behavior failure and must preserve artifacts.
- `error` is a host, worker, or harness failure that prevents a product verdict.
- `skip` is an expected host capability or V1-scope skip.
- `flake` is only allowed when the workload declares a follow-up bead and a
  reproduction pack.

The validator fails closed when a workload permits flakes without a follow-up,
omits reproduction preservation, exceeds resource caps, loses required log
fields, or drops the proof-bundle/release-gate consumers.

## Downstream Consumers

The sample artifact manifest marks the `soak_canary_campaigns` proof-bundle lane
and `operational.soak_canary` release-gate feature. Public readiness wording
must not cite soak evidence unless the release-gate evaluator has consumed a
fresh campaign artifact with the declared profile, host capability, resource
limits, and cleanup status.
