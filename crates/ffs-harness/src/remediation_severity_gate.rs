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
use std::collections::BTreeSet;

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

pub fn validate_default_remediation_severity_gate() -> Result<RemediationSeverityGateReport> {
    let gate = parse_remediation_severity_gate(DEFAULT_REMEDIATION_SEVERITY_GATE_JSON)?;
    let report = validate_remediation_severity_gate(&gate);
    if !report.valid {
        bail!(
            "remediation severity gate failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        );
    }
    Ok(report)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_gate() -> RemediationSeverityGate {
        parse_remediation_severity_gate(DEFAULT_REMEDIATION_SEVERITY_GATE_JSON)
            .expect("default remediation severity gate parses")
    }

    #[test]
    fn default_gate_validates_required_classes() {
        let report = validate_default_remediation_severity_gate()
            .expect("default remediation severity gate validates");
        assert_eq!(report.bead_id, "bd-t6zqr");
        for class in REQUIRED_OUTCOME_COVERAGE {
            assert!(
                report.outcome_classes_covered.iter().any(|c| c == class),
                "missing class {class}"
            );
        }
    }

    #[test]
    fn missing_low_confidence_repair_is_rejected() {
        let mut gate = fixture_gate();
        gate.entries
            .retain(|entry| entry.outcome_class != "low_confidence_repair");
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required outcome_class `low_confidence_repair`"))
        );
    }

    #[test]
    fn missing_inconclusive_oracle_is_rejected() {
        let mut gate = fixture_gate();
        gate.entries
            .retain(|entry| entry.outcome_class != "inconclusive_oracle_conflict");
        let report = validate_remediation_severity_gate(&gate);
        assert!(report.errors.iter().any(|err| {
            err.contains("missing required outcome_class `inconclusive_oracle_conflict`")
        }));
    }

    #[test]
    fn duplicate_remediation_id_is_rejected() {
        let mut gate = fixture_gate();
        let dup = gate.entries[0].remediation_id.clone();
        gate.entries[1].remediation_id = dup;
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("duplicate remediation_id"))
        );
    }

    #[test]
    fn remediation_id_prefix_is_enforced() {
        let mut gate = fixture_gate();
        gate.entries[0].remediation_id = "fix_001".to_owned();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must start with rem_"))
        );
    }

    #[test]
    fn unsupported_data_safety_severity_is_rejected() {
        let mut gate = fixture_gate();
        gate.entries[0].data_safety_severity = "kinda_safe".to_owned();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported data_safety_severity"))
        );
    }

    #[test]
    fn unsupported_release_gate_effect_is_rejected() {
        let mut gate = fixture_gate();
        gate.entries[0].release_gate_effect = "pretend_release".to_owned();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported release_gate_effect"))
        );
    }

    #[test]
    fn unsupported_safe_retry_policy_is_rejected() {
        let mut gate = fixture_gate();
        gate.entries[0].safe_retry_policy = "yolo_retry".to_owned();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported safe_retry_policy"))
        );
    }

    #[test]
    fn dead_end_entry_is_rejected() {
        let mut gate = fixture_gate();
        gate.entries[0].immediate_action_command = String::new();
        gate.entries[0].explicit_non_goal_rationale = String::new();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("is a dead end"))
        );
    }

    #[test]
    fn cannot_have_both_action_and_non_goal_rationale() {
        let mut gate = fixture_gate();
        let entry = gate
            .entries
            .iter_mut()
            .find(|e| !e.immediate_action_command.is_empty())
            .expect("entry with action exists");
        entry.explicit_non_goal_rationale = "leftover".to_owned();
        let report = validate_remediation_severity_gate(&gate);
        assert!(report.errors.iter().any(|err| err.contains(
            "cannot have both immediate_action_command and explicit_non_goal_rationale"
        )));
    }

    #[test]
    fn refusal_outcome_must_classify_as_no_loss() {
        let mut gate = fixture_gate();
        let entry = gate
            .entries
            .iter_mut()
            .find(|e| e.outcome_class == "unsafe_repair_refusal")
            .expect("refusal entry exists");
        entry.data_safety_severity = "data_loss_unrecoverable".to_owned();
        entry.release_gate_effect = "block_release".to_owned();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("refusal outcome must classify data_safety_severity"))
        );
    }

    #[test]
    fn applied_mutation_with_unrecoverable_loss_must_be_product_failure() {
        let mut gate = fixture_gate();
        let entry = gate
            .entries
            .iter_mut()
            .find(|e| e.outcome_class == "low_confidence_repair")
            .expect("low confidence entry exists");
        entry.outcome_class = "stale_artifact".to_owned();
        entry.mutation_status = "applied".to_owned();
        entry.data_safety_severity = "data_loss_unrecoverable".to_owned();
        entry.release_gate_effect = "block_release".to_owned();
        let report = validate_remediation_severity_gate(&gate);
        assert!(report.errors.iter().any(|err| err.contains(
            "applied mutation with unrecoverable loss must classify as product_failure"
        )));
    }

    #[test]
    fn low_confidence_repair_cannot_apply_mutation() {
        let mut gate = fixture_gate();
        let entry = gate
            .entries
            .iter_mut()
            .find(|e| e.outcome_class == "low_confidence_repair")
            .expect("low confidence entry exists");
        entry.mutation_status = "applied".to_owned();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("low_confidence_repair must not record applied mutation"))
        );
    }

    #[test]
    fn unrecoverable_loss_must_block_release() {
        let mut gate = fixture_gate();
        let entry = gate
            .entries
            .iter_mut()
            .find(|e| e.outcome_class == "product_failure")
            .expect("product failure entry exists");
        entry.data_safety_severity = "data_loss_unrecoverable".to_owned();
        entry.release_gate_effect = "annotate_caveat".to_owned();
        let report = validate_remediation_severity_gate(&gate);
        assert!(report.errors.iter().any(|err| {
            err.contains("data_loss_unrecoverable must use release_gate_effect=block_release")
        }));
    }

    #[test]
    fn pass_with_caveat_cannot_block_release() {
        let mut gate = fixture_gate();
        let entry = gate
            .entries
            .iter_mut()
            .find(|e| e.outcome_class == "pass_with_experimental_caveat")
            .expect("caveat entry exists");
        entry.release_gate_effect = "block_release".to_owned();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("pass_with_experimental_caveat must not block_release"))
        );
    }

    #[test]
    fn host_capability_skip_cannot_block_release() {
        let mut gate = fixture_gate();
        let entry = gate
            .entries
            .iter_mut()
            .find(|e| e.outcome_class == "host_capability_skip")
            .expect("host skip entry exists");
        entry.release_gate_effect = "block_release".to_owned();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("host_capability_skip must not block_release"))
        );
    }

    #[test]
    fn missing_owning_bead_is_rejected() {
        let mut gate = fixture_gate();
        gate.entries[0].owning_bead = "PROJ-99".to_owned();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("owning_bead must look like bd-"))
        );
    }

    #[test]
    fn missing_escalation_path_is_rejected() {
        let mut gate = fixture_gate();
        gate.entries[0].escalation_path = String::new();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing escalation_path"))
        );
    }

    #[test]
    fn missing_docs_target_is_rejected() {
        let mut gate = fixture_gate();
        gate.entries[0].docs_target = String::new();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing docs_target"))
        );
    }

    #[test]
    fn empty_artifact_requirements_is_rejected() {
        let mut gate = fixture_gate();
        gate.entries[0].artifact_requirements.clear();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("at least one artifact_requirement"))
        );
    }

    #[test]
    fn empty_entries_list_is_rejected() {
        let mut gate = fixture_gate();
        gate.entries.clear();
        let report = validate_remediation_severity_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("at least one entry"))
        );
    }

    #[test]
    fn block_release_count_is_reported() {
        let report = validate_default_remediation_severity_gate().expect("default validates");
        assert!(report.block_release_count >= 1);
    }
}
