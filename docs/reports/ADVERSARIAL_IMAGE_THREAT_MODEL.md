# Adversarial Image Threat Model (bd-rchk0.5.11)

The machine-readable source of truth is
[`security/adversarial_image_threat_model.json`](../../security/adversarial_image_threat_model.json).
Validate it without mounting hostile images:

```bash
cargo run -p ffs-harness -- validate-adversarial-threat-model \
  --model security/adversarial_image_threat_model.json \
  --artifact-root artifacts/security/dry-run \
  --out artifacts/security/threat_model_report.json \
  --artifact-out artifacts/security/sample_artifact_manifest.json \
  --wording-out artifacts/security/security_wording.tsv
```

The threat model covers hostile ext4/btrfs images, malformed superblocks,
hostile proof-bundle paths, symlinked artifacts, missing FUSE capability,
resource-exhaustion corpus seeds, tampered repair ledgers, unsupported mount
options, and unsafe operator-command combinations.

Every critical threat class is release-gate controlled. Unreviewed critical
classes fail closed, and public docs cannot promote `security.hostile_image`
from prose alone. A fresh validation artifact must show the expected safe
behavior and shared QA artifact mapping.

## Safety Vocabulary

| Term | Meaning |
|------|---------|
| Hostile-image safety | Malicious or malformed inputs cannot escape the declared parser/mount/repair sandbox, consume unbounded resources, or create misleading readiness evidence. |
| Ordinary corruption repair | Non-malicious media corruption handled by scrub, repair symbols, and explicit repair workflows. This does not imply hostile-image containment. |
| Unsupported format | A deterministic refusal or unsupported classification, not a crash or silent success. |
| Detection-only behavior | The system may inspect and report findings but must not mutate the image or host paths. |
| Mutating repair readiness | The narrow opt-in state where preflight, ledger identity, backup/rollback, and release-gate evidence permit image mutation. |

## Required Logs

Each scenario log must include:

- `threat_scenario_id`
- `input_hash`
- `parser_capability`
- `mount_capability`
- `repair_capability`
- `expected_safe_behavior`
- `observed_classification`
- `resource_limits`
- `cleanup_status`
- `reproduction_command`

## Smoke Coverage

Run the bounded security smoke with:

```bash
./scripts/e2e/ffs_adversarial_threat_model_e2e.sh
```

The smoke validates the checked-in model, emits a shared QA artifact manifest,
writes docs-safe wording, rejects malformed variants, and runs the focused unit
tests. Longer fuzz campaigns and hostile-image containment proofs build on this
contract rather than replacing it.
