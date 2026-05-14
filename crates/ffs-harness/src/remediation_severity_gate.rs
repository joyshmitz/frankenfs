#![forbid(unsafe_code)]

//! Remediation severity gate with dead-end prevention.
//!
//! Tracks bd-t6zqr: refines the remediation catalog so every entry tied to a
//! user-visible failure, skip, security refusal, unsupported feature, stale
//! evidence, or unsafe repair carries a data-safety severity, mutation
//! status, immediate next command (or explicit non-goal rationale), safe
//! retry policy, escalation path, owning bead/subsystem, docs target, and
//! release-gate effect. Release gates fail closed if any user-visible
//! outcome lacks a concrete next action or explicit non-goal rationale.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fs, path::Path};

pub const REMEDIATION_SEVERITY_GATE_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_REMEDIATION_SEVERITY_GATE_PATH: &str =
    "tests/remediation-severity-gate/remediation_severity_gate.json";
const DEFAULT_REMEDIATION_SEVERITY_GATE_JSON: &str =
    include_str!("../../../tests/remediation-severity-gate/remediation_severity_gate.json");

const ALLOWED_OUTCOME_CLASSES: [&str; 11] = [
    "product_failure",
    "host_capability_skip",
    "unsupported_operation",
    "stale_artifact",
    "security_refusal",
    "unsafe_repair_refusal",
    "low_confidence_repair",
    "noisy_performance",
    "missing_proof_lane",
    "inconclusive_oracle_conflict",
    "pass_with_experimental_caveat",
];

const ALLOWED_DATA_SAFETY_SEVERITIES: [&str; 5] = [
    "no_user_data_at_risk",
    "potential_data_loss",
    "data_loss_blocked_by_refusal",
    "data_loss_recoverable",
    "data_loss_unrecoverable",
];

const ALLOWED_MUTATION_STATUSES: [&str; 5] =
    ["none", "dry_run", "applied", "rolled_back", "refused"];

const ALLOWED_RELEASE_GATE_EFFECTS: [&str; 4] = [
    "block_release",
    "downgrade_to_experimental",
    "annotate_caveat",
    "no_effect",
];

const ALLOWED_RETRY_POLICIES: [&str; 5] = [
    "no_retry_until_root_cause",
    "no_retry_until_security_review",
    "manual_dry_run_then_review",
    "regenerate_artifact_then_retry",
    "ok_to_retry",
];

const REQUIRED_OUTCOME_COVERAGE: [&str; 7] = [
    "product_failure",
    "host_capability_skip",
    "unsafe_repair_refusal",
    "low_confidence_repair",
    "missing_proof_lane",
    "inconclusive_oracle_conflict",
    "pass_with_experimental_caveat",
];

const ALLOWED_HARNESS_ACTION_COMMANDS: [&str; 3] = [
    "validate-cross-oracle-arbitration",
    "validate-proof-bundle",
    "validate-remediation-severity-gate",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationSeverityGate {
    pub schema_version: u32,
    pub gate_id: String,
    pub bead_id: String,
    pub entries: Vec<RemediationSeverityEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationSeverityEntry {
    pub remediation_id: String,
    pub outcome_class: String,
    pub data_safety_severity: String,
    pub mutation_status: String,
    pub immediate_action_command: String,
    pub safe_retry_policy: String,
    pub escalation_path: String,
    pub owning_bead: String,
    pub docs_target: String,
    pub artifact_requirements: Vec<String>,
    pub release_gate_effect: String,
    #[serde(default)]
    pub explicit_non_goal_rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationSeverityGateReport {
    pub schema_version: u32,
    pub gate_id: String,
    pub bead_id: String,
    pub entry_count: usize,
    pub outcome_classes_covered: Vec<String>,
    pub block_release_count: usize,
    pub valid: bool,
    pub errors: Vec<String>,
}

pub fn parse_remediation_severity_gate(text: &str) -> Result<RemediationSeverityGate> {
    serde_json::from_str(text)
        .map_err(|err| anyhow::anyhow!("failed to parse remediation severity gate JSON: {err}"))
}

pub fn load_remediation_severity_gate(path: &Path) -> Result<RemediationSeverityGate> {
    let text = fs::read_to_string(path).map_err(|err| {
        anyhow::anyhow!(
            "failed to read remediation severity gate `{}`: {err}",
            path.display()
        )
    })?;
    parse_remediation_severity_gate(&text)
}

pub fn validate_default_remediation_severity_gate() -> Result<RemediationSeverityGateReport> {
    let gate = parse_remediation_severity_gate(DEFAULT_REMEDIATION_SEVERITY_GATE_JSON)?;
    let report = validate_remediation_severity_gate(&gate);
    fail_on_remediation_severity_gate_errors(&report)?;
    Ok(report)
}

pub fn fail_on_remediation_severity_gate_errors(
    report: &RemediationSeverityGateReport,
) -> Result<()> {
    if report.valid {
        return Ok(());
    }
    bail!(
        "remediation severity gate failed with {} error(s): {}",
        report.errors.len(),
        report.errors.join("; ")
    );
}

#[must_use]
pub fn validate_remediation_severity_gate(
    gate: &RemediationSeverityGate,
) -> RemediationSeverityGateReport {
    let mut errors = Vec::new();
    let mut ids = BTreeSet::new();
    let mut classes_seen = BTreeSet::new();
    let mut block_release = 0_usize;

    validate_top_level(gate, &mut errors);
    for entry in &gate.entries {
        validate_entry(
            entry,
            &mut ids,
            &mut classes_seen,
            &mut block_release,
            &mut errors,
        );
    }
    validate_required_outcome_coverage(&classes_seen, &mut errors);

    RemediationSeverityGateReport {
        schema_version: gate.schema_version,
        gate_id: gate.gate_id.clone(),
        bead_id: gate.bead_id.clone(),
        entry_count: gate.entries.len(),
        outcome_classes_covered: classes_seen.into_iter().collect(),
        block_release_count: block_release,
        valid: errors.is_empty(),
        errors,
    }
}

fn validate_top_level(gate: &RemediationSeverityGate, errors: &mut Vec<String>) {
    if gate.schema_version != REMEDIATION_SEVERITY_GATE_SCHEMA_VERSION {
        errors.push(format!(
            "remediation severity gate schema_version must be {REMEDIATION_SEVERITY_GATE_SCHEMA_VERSION}, got {}",
            gate.schema_version
        ));
    }
    if gate.gate_id.trim().is_empty() {
        errors.push("remediation severity gate missing gate_id".to_owned());
    }
    if !gate.bead_id.starts_with("bd-") {
        errors.push(format!(
            "remediation severity gate bead_id must look like bd-..., got `{}`",
            gate.bead_id
        ));
    }
    if gate.entries.is_empty() {
        errors.push("remediation severity gate must declare at least one entry".to_owned());
    }
}

fn validate_entry(
    entry: &RemediationSeverityEntry,
    ids: &mut BTreeSet<String>,
    classes_seen: &mut BTreeSet<String>,
    block_release: &mut usize,
    errors: &mut Vec<String>,
) {
    if !ids.insert(entry.remediation_id.clone()) {
        errors.push(format!(
            "duplicate remediation_id `{}`",
            entry.remediation_id
        ));
    }
    if !entry.remediation_id.starts_with("rem_") {
        errors.push(format!(
            "remediation_id `{}` must start with rem_",
            entry.remediation_id
        ));
    }
    if ALLOWED_OUTCOME_CLASSES.contains(&entry.outcome_class.as_str()) {
        classes_seen.insert(entry.outcome_class.clone());
    } else {
        errors.push(format!(
            "remediation `{}` has unsupported outcome_class `{}`",
            entry.remediation_id, entry.outcome_class
        ));
    }
    if !ALLOWED_DATA_SAFETY_SEVERITIES.contains(&entry.data_safety_severity.as_str()) {
        errors.push(format!(
            "remediation `{}` has unsupported data_safety_severity `{}`",
            entry.remediation_id, entry.data_safety_severity
        ));
    }
    if !ALLOWED_MUTATION_STATUSES.contains(&entry.mutation_status.as_str()) {
        errors.push(format!(
            "remediation `{}` has unsupported mutation_status `{}`",
            entry.remediation_id, entry.mutation_status
        ));
    }
    if !ALLOWED_RELEASE_GATE_EFFECTS.contains(&entry.release_gate_effect.as_str()) {
        errors.push(format!(
            "remediation `{}` has unsupported release_gate_effect `{}`",
            entry.remediation_id, entry.release_gate_effect
        ));
    }
    if entry.release_gate_effect == "block_release" {
        *block_release += 1;
    }
    if !ALLOWED_RETRY_POLICIES.contains(&entry.safe_retry_policy.as_str()) {
        errors.push(format!(
            "remediation `{}` has unsupported safe_retry_policy `{}`",
            entry.remediation_id, entry.safe_retry_policy
        ));
    }
    validate_entry_required_text(entry, errors);
    validate_harness_action_command(entry, errors);
    validate_dead_end_prevention(entry, errors);
    validate_entry_safety_invariants(entry, errors);
}

fn validate_entry_required_text(entry: &RemediationSeverityEntry, errors: &mut Vec<String>) {
    if !entry.owning_bead.starts_with("bd-") {
        errors.push(format!(
            "remediation `{}` owning_bead must look like bd-..., got `{}`",
            entry.remediation_id, entry.owning_bead
        ));
    }
    if entry.escalation_path.trim().is_empty() {
        errors.push(format!(
            "remediation `{}` missing escalation_path",
            entry.remediation_id
        ));
    }
    if entry.docs_target.trim().is_empty() {
        errors.push(format!(
            "remediation `{}` missing docs_target",
            entry.remediation_id
        ));
    }
    if entry.artifact_requirements.is_empty() {
        errors.push(format!(
            "remediation `{}` must declare at least one artifact_requirement",
            entry.remediation_id
        ));
    }
}

fn validate_dead_end_prevention(entry: &RemediationSeverityEntry, errors: &mut Vec<String>) {
    let has_action = !entry.immediate_action_command.trim().is_empty();
    let has_non_goal = !entry.explicit_non_goal_rationale.trim().is_empty();
    if !has_action && !has_non_goal {
        errors.push(format!(
            "remediation `{}` is a dead end: declare immediate_action_command or explicit_non_goal_rationale",
            entry.remediation_id
        ));
    }
    if has_action && has_non_goal {
        errors.push(format!(
            "remediation `{}` cannot have both immediate_action_command and explicit_non_goal_rationale",
            entry.remediation_id
        ));
    }
    if entry.outcome_class == "pass_with_experimental_caveat" && !has_action && !has_non_goal {
        errors.push(format!(
            "remediation `{}` pass_with_experimental_caveat must explain how to graduate or accept the caveat",
            entry.remediation_id
        ));
    }
}

fn validate_entry_safety_invariants(entry: &RemediationSeverityEntry, errors: &mut Vec<String>) {
    let is_refusal =
        entry.outcome_class == "security_refusal" || entry.outcome_class == "unsafe_repair_refusal";
    let claims_no_loss = entry.data_safety_severity == "no_user_data_at_risk"
        || entry.data_safety_severity == "data_loss_blocked_by_refusal";
    if is_refusal && !claims_no_loss {
        errors.push(format!(
            "remediation `{}` refusal outcome must classify data_safety_severity as no_user_data_at_risk or data_loss_blocked_by_refusal",
            entry.remediation_id
        ));
    }
    if entry.mutation_status == "applied"
        && entry.data_safety_severity == "data_loss_unrecoverable"
        && entry.outcome_class != "product_failure"
    {
        errors.push(format!(
            "remediation `{}` applied mutation with unrecoverable loss must classify as product_failure",
            entry.remediation_id
        ));
    }
    if entry.outcome_class == "low_confidence_repair" && entry.mutation_status == "applied" {
        errors.push(format!(
            "remediation `{}` low_confidence_repair must not record applied mutation; mutation requires high confidence",
            entry.remediation_id
        ));
    }
    if entry.data_safety_severity == "data_loss_unrecoverable"
        && entry.release_gate_effect != "block_release"
    {
        errors.push(format!(
            "remediation `{}` data_loss_unrecoverable must use release_gate_effect=block_release",
            entry.remediation_id
        ));
    }
    if entry.outcome_class == "pass_with_experimental_caveat"
        && entry.release_gate_effect == "block_release"
    {
        errors.push(format!(
            "remediation `{}` pass_with_experimental_caveat must not block_release; downgrade or annotate instead",
            entry.remediation_id
        ));
    }
    if entry.outcome_class == "host_capability_skip" && entry.release_gate_effect == "block_release"
    {
        errors.push(format!(
            "remediation `{}` host_capability_skip must not block_release; the host is at fault, not the product",
            entry.remediation_id
        ));
    }
}

fn validate_required_outcome_coverage(seen: &BTreeSet<String>, errors: &mut Vec<String>) {
    for required in REQUIRED_OUTCOME_COVERAGE {
        if !seen.contains(required) {
            errors.push(format!(
                "remediation severity gate missing required outcome_class `{required}`"
            ));
        }
    }
}

fn validate_harness_action_command(entry: &RemediationSeverityEntry, errors: &mut Vec<String>) {
    let Some(command_name) = harness_command_name(&entry.immediate_action_command) else {
        return;
    };
    if !ALLOWED_HARNESS_ACTION_COMMANDS.contains(&command_name) {
        errors.push(format!(
            "remediation `{}` immediate_action_command references unsupported ffs-harness command `{command_name}`; expected one of {}",
            entry.remediation_id,
            ALLOWED_HARNESS_ACTION_COMMANDS.join(", ")
        ));
    }
}

fn harness_command_name(command: &str) -> Option<&str> {
    const MARKERS: [&str; 3] = [
        "cargo run -p ffs-harness -- ",
        "cargo run --quiet -p ffs-harness -- ",
        "ffs-harness ",
    ];
    MARKERS.iter().find_map(|marker| {
        command
            .split_once(marker)
            .and_then(|(_, rest)| rest.split_whitespace().next())
    })
}

#[must_use]
pub fn render_remediation_severity_gate_markdown(report: &RemediationSeverityGateReport) -> String {
    let mut out = String::new();
    out.push_str("# Remediation Severity Gate\n\n");
    out.push_str("- gate: `");
    out.push_str(&report.gate_id);
    out.push_str("`\n");
    out.push_str("- schema version: `");
    out.push_str(&report.schema_version.to_string());
    out.push_str("`\n");
    out.push_str("- bead: `");
    out.push_str(&report.bead_id);
    out.push_str("`\n");
    out.push_str("- valid: `");
    out.push_str(if report.valid { "true" } else { "false" });
    out.push_str("`\n");
    out.push_str("- entries: `");
    out.push_str(&report.entry_count.to_string());
    out.push_str("`\n");
    out.push_str("- block-release entries: `");
    out.push_str(&report.block_release_count.to_string());
    out.push_str("`\n\n");
    out.push_str("## Outcome Classes\n");
    for outcome_class in &report.outcome_classes_covered {
        out.push_str("- `");
        out.push_str(outcome_class);
        out.push_str("`\n");
    }
    if !report.errors.is_empty() {
        out.push_str("\n## Errors\n");
        for error in &report.errors {
            out.push_str("- ");
            out.push_str(error);
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    fn fixture_gate() -> Result<RemediationSeverityGate> {
        parse_remediation_severity_gate(DEFAULT_REMEDIATION_SEVERITY_GATE_JSON)
    }

    fn first_entry_mut(
        gate: &mut RemediationSeverityGate,
    ) -> Result<&mut RemediationSeverityEntry> {
        gate.entries
            .first_mut()
            .context("missing remediation severity gate entry")
    }

    fn first_two_entries_mut(
        gate: &mut RemediationSeverityGate,
    ) -> Result<(&mut RemediationSeverityEntry, &mut RemediationSeverityEntry)> {
        let (first, rest) = gate
            .entries
            .split_first_mut()
            .context("missing first remediation severity gate entry")?;
        let second = rest
            .first_mut()
            .context("missing second remediation severity gate entry")?;
        Ok((first, second))
    }

    fn entry_by_id_mut<'a>(
        gate: &'a mut RemediationSeverityGate,
        remediation_id: &str,
    ) -> Result<&'a mut RemediationSeverityEntry> {
        gate.entries
            .iter_mut()
            .find(|entry| entry.remediation_id == remediation_id)
            .with_context(|| format!("missing remediation severity gate entry {remediation_id}"))
    }

    #[test]
    fn default_gate_validates_required_classes() -> Result<()> {
        let report = validate_default_remediation_severity_gate()?;
        assert_eq!(report.bead_id, "bd-t6zqr");
        for class in REQUIRED_OUTCOME_COVERAGE {
            assert!(
                report.outcome_classes_covered.iter().any(|c| c == class),
                "missing class {class}"
            );
        }
        Ok(())
    }

    #[test]
    fn missing_low_confidence_repair_is_rejected() -> Result<()> {
        let mut gate = fixture_gate()?;
        gate.entries
            .retain(|entry| entry.outcome_class != "low_confidence_repair");
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required outcome_class `low_confidence_repair`"))
        );
        Ok(())
    }

    #[test]
    fn missing_inconclusive_oracle_is_rejected() -> Result<()> {
        let mut gate = fixture_gate()?;
        gate.entries
            .retain(|entry| entry.outcome_class != "inconclusive_oracle_conflict");
        let report = validate_remediation_severity_gate(&gate);
        assert!(report.errors.iter().any(|err| {
            err.contains("missing required outcome_class `inconclusive_oracle_conflict`")
        }));
        Ok(())
    }

    #[test]
    fn duplicate_remediation_id_is_rejected() -> Result<()> {
        let mut gate = fixture_gate()?;
        let (first, second) = first_two_entries_mut(&mut gate)?;
        let dup = first.remediation_id.clone();
        second.remediation_id = dup;
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("duplicate remediation_id"))
        );
        Ok(())
    }

    #[test]
    fn remediation_id_prefix_is_enforced() -> Result<()> {
        let mut gate = fixture_gate()?;
        first_entry_mut(&mut gate)?.remediation_id = "fix_001".to_owned();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must start with rem_"))
        );
        Ok(())
    }

    #[test]
    fn unsupported_data_safety_severity_is_rejected() -> Result<()> {
        let mut gate = fixture_gate()?;
        first_entry_mut(&mut gate)?.data_safety_severity = "kinda_safe".to_owned();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported data_safety_severity"))
        );
        Ok(())
    }

    #[test]
    fn unsupported_release_gate_effect_is_rejected() -> Result<()> {
        let mut gate = fixture_gate()?;
        first_entry_mut(&mut gate)?.release_gate_effect = "pretend_release".to_owned();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported release_gate_effect"))
        );
        Ok(())
    }

    #[test]
    fn unsupported_safe_retry_policy_is_rejected() -> Result<()> {
        let mut gate = fixture_gate()?;
        first_entry_mut(&mut gate)?.safe_retry_policy = "yolo_retry".to_owned();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported safe_retry_policy"))
        );
        Ok(())
    }

    #[test]
    fn dead_end_entry_is_rejected() -> Result<()> {
        let mut gate = fixture_gate()?;
        let entry = first_entry_mut(&mut gate)?;
        entry.immediate_action_command = String::new();
        entry.explicit_non_goal_rationale = String::new();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("is a dead end"))
        );
        Ok(())
    }

    #[test]
    fn unsupported_harness_action_command_is_rejected() -> Result<()> {
        let mut gate = fixture_gate()?;
        first_entry_mut(&mut gate)?.immediate_action_command =
            "cargo run -p ffs-harness -- build-operator-proof-bundle --out bundle.json".to_owned();
        let report = validate_remediation_severity_gate(&gate);

        assert!(report.errors.iter().any(|err| {
            err.contains("immediate_action_command references unsupported ffs-harness command")
                && err.contains("build-operator-proof-bundle")
        }));
        Ok(())
    }

    #[test]
    fn stale_proof_bundle_uses_current_validator() -> Result<()> {
        let mut gate = fixture_gate()?;
        let entry = entry_by_id_mut(&mut gate, "rem_stale_proof_bundle")?;

        assert!(
            entry
                .immediate_action_command
                .contains("validate-proof-bundle"),
            "stale proof bundle remediation must point at validate-proof-bundle"
        );
        assert!(
            !entry
                .immediate_action_command
                .contains("build-operator-proof-bundle"),
            "stale proof bundle remediation must not advertise removed proof-bundle builder"
        );
        Ok(())
    }

    #[test]
    fn inconclusive_oracle_uses_current_arbitration_validator() -> Result<()> {
        let mut gate = fixture_gate()?;
        let entry = entry_by_id_mut(&mut gate, "rem_inconclusive_oracle_conflict")?;

        assert!(
            entry
                .immediate_action_command
                .contains("validate-cross-oracle-arbitration"),
            "oracle conflict remediation must point at the current arbitration validator"
        );
        assert!(
            !entry
                .immediate_action_command
                .contains("arbitrate-cross-oracle"),
            "oracle conflict remediation must not advertise removed arbitration command"
        );
        Ok(())
    }

    #[test]
    fn cannot_have_both_action_and_non_goal_rationale() -> Result<()> {
        let mut gate = fixture_gate()?;
        let entry = gate
            .entries
            .iter_mut()
            .find(|e| !e.immediate_action_command.is_empty())
            .context("entry with action exists")?;
        entry.explicit_non_goal_rationale = "leftover".to_owned();
        let report = validate_remediation_severity_gate(&gate);
        assert!(report.errors.iter().any(|err| err.contains(
            "cannot have both immediate_action_command and explicit_non_goal_rationale"
        )));
        Ok(())
    }

    #[test]
    fn refusal_outcome_must_classify_as_no_loss() -> Result<()> {
        let mut gate = fixture_gate()?;
        let entry = gate
            .entries
            .iter_mut()
            .find(|e| e.outcome_class == "unsafe_repair_refusal")
            .context("refusal entry exists")?;
        entry.data_safety_severity = "data_loss_unrecoverable".to_owned();
        entry.release_gate_effect = "block_release".to_owned();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("refusal outcome must classify data_safety_severity"))
        );
        Ok(())
    }

    #[test]
    fn applied_mutation_with_unrecoverable_loss_must_be_product_failure() -> Result<()> {
        let mut gate = fixture_gate()?;
        let entry = gate
            .entries
            .iter_mut()
            .find(|e| e.outcome_class == "low_confidence_repair")
            .context("low confidence entry exists")?;
        entry.outcome_class = "stale_artifact".to_owned();
        entry.mutation_status = "applied".to_owned();
        entry.data_safety_severity = "data_loss_unrecoverable".to_owned();
        entry.release_gate_effect = "block_release".to_owned();
        let report = validate_remediation_severity_gate(&gate);
        assert!(report.errors.iter().any(|err| err.contains(
            "applied mutation with unrecoverable loss must classify as product_failure"
        )));
        Ok(())
    }

    #[test]
    fn low_confidence_repair_cannot_apply_mutation() -> Result<()> {
        let mut gate = fixture_gate()?;
        let entry = gate
            .entries
            .iter_mut()
            .find(|e| e.outcome_class == "low_confidence_repair")
            .context("low confidence entry exists")?;
        entry.mutation_status = "applied".to_owned();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("low_confidence_repair must not record applied mutation"))
        );
        Ok(())
    }

    #[test]
    fn unrecoverable_loss_must_block_release() -> Result<()> {
        let mut gate = fixture_gate()?;
        let entry = gate
            .entries
            .iter_mut()
            .find(|e| e.outcome_class == "product_failure")
            .context("product failure entry exists")?;
        entry.data_safety_severity = "data_loss_unrecoverable".to_owned();
        entry.release_gate_effect = "annotate_caveat".to_owned();
        let report = validate_remediation_severity_gate(&gate);
        assert!(report.errors.iter().any(|err| {
            err.contains("data_loss_unrecoverable must use release_gate_effect=block_release")
        }));
        Ok(())
    }

    #[test]
    fn pass_with_caveat_cannot_block_release() -> Result<()> {
        let mut gate = fixture_gate()?;
        let entry = gate
            .entries
            .iter_mut()
            .find(|e| e.outcome_class == "pass_with_experimental_caveat")
            .context("caveat entry exists")?;
        entry.release_gate_effect = "block_release".to_owned();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("pass_with_experimental_caveat must not block_release"))
        );
        Ok(())
    }

    #[test]
    fn host_capability_skip_cannot_block_release() -> Result<()> {
        let mut gate = fixture_gate()?;
        let entry = gate
            .entries
            .iter_mut()
            .find(|e| e.outcome_class == "host_capability_skip")
            .context("host skip entry exists")?;
        entry.release_gate_effect = "block_release".to_owned();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("host_capability_skip must not block_release"))
        );
        Ok(())
    }

    #[test]
    fn missing_owning_bead_is_rejected() -> Result<()> {
        let mut gate = fixture_gate()?;
        first_entry_mut(&mut gate)?.owning_bead = "PROJ-99".to_owned();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("owning_bead must look like bd-"))
        );
        Ok(())
    }

    #[test]
    fn missing_escalation_path_is_rejected() -> Result<()> {
        let mut gate = fixture_gate()?;
        first_entry_mut(&mut gate)?.escalation_path = String::new();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing escalation_path"))
        );
        Ok(())
    }

    #[test]
    fn missing_docs_target_is_rejected() -> Result<()> {
        let mut gate = fixture_gate()?;
        first_entry_mut(&mut gate)?.docs_target = String::new();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing docs_target"))
        );
        Ok(())
    }

    #[test]
    fn empty_artifact_requirements_is_rejected() -> Result<()> {
        let mut gate = fixture_gate()?;
        first_entry_mut(&mut gate)?.artifact_requirements.clear();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("at least one artifact_requirement"))
        );
        Ok(())
    }

    #[test]
    fn empty_entries_list_is_rejected() -> Result<()> {
        let mut gate = fixture_gate()?;
        gate.entries.clear();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("at least one entry"))
        );
        Ok(())
    }

    #[test]
    fn block_release_count_is_reported() -> Result<()> {
        let report = validate_default_remediation_severity_gate()?;
        assert!(report.block_release_count >= 1);
        Ok(())
    }

    #[test]
    fn remediation_severity_gate_report_json_shape() -> Result<()> {
        let report = validate_default_remediation_severity_gate()?;

        let json = serde_json::to_string_pretty(&report)?;
        insta::assert_snapshot!("remediation_severity_gate_report_json_shape", json);

        let roundtrip: RemediationSeverityGateReport = serde_json::from_str(&json)?;
        assert_eq!(roundtrip, report);
        Ok(())
    }

    #[test]
    fn render_remediation_severity_gate_markdown_default_gate() -> Result<()> {
        let report = validate_default_remediation_severity_gate()?;
        let markdown = render_remediation_severity_gate_markdown(&report);
        insta::assert_snapshot!(
            "render_remediation_severity_gate_markdown_default_gate",
            markdown
        );
        Ok(())
    }

    #[test]
    fn fail_on_errors_rejects_invalid_report() -> Result<()> {
        let mut gate = fixture_gate()?;
        first_entry_mut(&mut gate)?.release_gate_effect = "annotate_caveat".to_owned();
        let report = validate_remediation_severity_gate(&gate);
        let Err(err) = fail_on_remediation_severity_gate_errors(&report) else {
            anyhow::bail!("invalid report unexpectedly passed");
        };
        assert!(err.to_string().contains("remediation severity gate failed"));
        assert!(
            err.to_string()
                .contains("data_loss_unrecoverable must use release_gate_effect=block_release")
        );
        Ok(())
    }
}
