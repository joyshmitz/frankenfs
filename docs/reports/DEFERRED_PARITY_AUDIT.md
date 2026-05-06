# Deferred Parity Audit (bd-39lau)

This report is the machine-checkable registry for closed beads whose closure
language scopes, defers, or weakens parity evidence. `ffs-harness
validate-deferred-parity-audit` scans `.beads/issues.jsonl`, README/status
docs, and this registry. A closed bead with risky deferred language must point
to a follow-up bead, an explicit non-goal, or a docs/release-gate downgrade.

## Deferred Closure Audit Registry

| Row | Source bead | Source status | Matched phrase | Gap class | Docs/spec claim checked | Release-gate effect | Decision | Linked follow-up or non-goal | Required logs | Required artifacts | Reproduction command |
|-----|-------------|---------------|----------------|-----------|-------------------------|---------------------|----------|------------------------------|---------------|--------------------|----------------------|
| D1 | bd-nzv3.24 | closed | deferred | deferred | README.md btrfs multi-device wording; FEATURE_PARITY.md btrfs support wording | Multi-device readiness stays downgraded unless current multi-image evidence is fresh | validated-artifact | bd-ch373 | audit_run_id,source_bead_id,source_status,matched_vocabulary_rule,docs_claim_checked,release_gate_effect,artifact_path,reproduction_command | report_json,human_report,source_bead_id,docs_claim_checked,output_report_path | ffs-harness validate-deferred-parity-audit --issues .beads/issues.jsonl --report docs/reports/DEFERRED_PARITY_AUDIT.md --doc README.md --doc FEATURE_PARITY.md |
| D2 | bd-nzv3.15 | closed | full export deferred | deferred | README.md send/receive wording; FEATURE_PARITY.md send/receive support wording | Send/receive readiness stays parse-scoped unless current export/apply evidence is fresh | validated-artifact | bd-naww5 | audit_run_id,source_bead_id,source_status,matched_vocabulary_rule,docs_claim_checked,release_gate_effect,artifact_path,reproduction_command | report_json,human_report,source_bead_id,docs_claim_checked,output_report_path | ffs-harness validate-deferred-parity-audit --issues .beads/issues.jsonl --report docs/reports/DEFERRED_PARITY_AUDIT.md --doc README.md --doc FEATURE_PARITY.md |
| D3 | bd-nzv3.21 | closed | basic coverage | basic-coverage | README.md ext4 casefold wording; FEATURE_PARITY.md casefold support wording | Casefold readiness stays scoped to validated Unicode/mounted evidence tiers | validated-artifact | bd-9er6s | audit_run_id,source_bead_id,source_status,matched_vocabulary_rule,docs_claim_checked,release_gate_effect,artifact_path,reproduction_command | report_json,human_report,source_bead_id,docs_claim_checked,output_report_path | ffs-harness validate-deferred-parity-audit --issues .beads/issues.jsonl --report docs/reports/DEFERRED_PARITY_AUDIT.md --doc README.md --doc FEATURE_PARITY.md |
| D4 | docs:readme-flat-parity | current | 100% | implemented-unvalidated | README.md flat tracked-parity and readiness wording | Release gates consume tiered support-state accounting instead of flat implementation counts | validated-artifact | bd-mpcse | audit_run_id,source_bead_id,source_status,matched_vocabulary_rule,docs_claim_checked,release_gate_effect,artifact_path,reproduction_command | report_json,human_report,source_bead_id,docs_claim_checked,output_report_path | ffs-harness validate-deferred-parity-audit --issues .beads/issues.jsonl --report docs/reports/DEFERRED_PARITY_AUDIT.md --doc README.md --doc FEATURE_PARITY.md |
| D5 | docs:feature-parity-flat-counts | current | 100% | implemented-unvalidated | FEATURE_PARITY.md flat percentage/accounting wording | Tiered accounting separates implementation inventory from readiness claims | validated-artifact | bd-mpcse | audit_run_id,source_bead_id,source_status,matched_vocabulary_rule,docs_claim_checked,release_gate_effect,artifact_path,reproduction_command | report_json,human_report,source_bead_id,docs_claim_checked,output_report_path | ffs-harness validate-deferred-parity-audit --issues .beads/issues.jsonl --report docs/reports/DEFERRED_PARITY_AUDIT.md --doc README.md --doc FEATURE_PARITY.md |

## Resolved Follow-Up Coverage

| Follow-up bead | Closed artifact now owning the audit row |
|----------------|-----------------------------------------|
| bd-ch373 | btrfs multi-device RAID corpus and degraded-mode proof |
| bd-naww5 | btrfs send/receive export/apply parity beyond parse-only |
| bd-9er6s | ext4 casefold Unicode collision and mounted conformance |
| bd-mpcse | tiered support-state accounting to replace flat parity percentages |

The audit preserves the original feature goals. It does not remove parity rows
or historical claims; it requires public wording and release gates to point at
the controlling artifact, follow-up, downgrade, or non-goal when evidence is
partial, deferred, parse-only, single-device-only, experimental, host-blocked,
stale, or non-authoritative.
