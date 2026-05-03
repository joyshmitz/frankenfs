#![forbid(unsafe_code)]

//! Ambition evidence matrix control plane for `bd-rchk0.5.10.1` and
//! `bd-vp5v7`.
//!
//! The matrix keeps ambition beads from becoming loose planning text. It turns
//! tracker rows into a versioned evidence-control surface that downstream proof
//! bundles, remediation catalogs, demo lanes, and release gates can consume.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

pub const MATRIX_VERSION: &str = "bd-vp5v7-ambition-evidence-matrix-v2";

const REQUIRED_SOURCE_BEADS: [&str; 5] = [
    "bd-rchk0.5.10.1",
    "bd-rchk0.5.11",
    "bd-rchk0.5.12",
    "bd-rchk0.5.13",
    "bd-rchk0.5.14",
];

const MATRIX_STATUSES: [&str; 6] = [
    "validated",
    "partial",
    "blocked",
    "stale",
    "not-applicable",
    "intentionally-deferred",
];

const ALLOWED_CONSUMERS: [&str; 6] = [
    "proof-bundle",
    "release-gates",
    "remediation-catalog",
    "README/FEATURE_PARITY",
    "follow-up-bead",
    "readiness-report",
];

const REQUIRED_LOG_TOKENS: [&str; 8] = [
    "matrix_version",
    "source_bead_ids",
    "consumer_versions",
    "stale_reference_checks",
    "missing_field_diagnostics",
    "downgrade_decisions",
    "generated_artifact_paths",
    "reproduction_command",
];

const DEFAULT_ARTIFACT_PATH: &str = "artifacts/ambition/evidence_matrix.json";
const REPRODUCTION_COMMAND: &str = "ffs-harness validate-ambition-evidence-matrix --issues .beads/issues.jsonl --out artifacts/ambition/evidence_matrix.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmbitionEvidenceMatrixConfig {
    pub issues_jsonl: PathBuf,
    pub generated_artifact_paths: Vec<String>,
}

impl Default for AmbitionEvidenceMatrixConfig {
    fn default() -> Self {
        Self {
            issues_jsonl: PathBuf::from(".beads/issues.jsonl"),
            generated_artifact_paths: vec![DEFAULT_ARTIFACT_PATH.to_owned()],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmbitionEvidenceMatrixReport {
    pub matrix_version: String,
    pub source_issue_count: usize,
    pub row_count: usize,
    pub source_bead_ids: Vec<String>,
    pub required_source_beads: Vec<String>,
    pub allowed_consumers: Vec<String>,
    pub rows: Vec<AmbitionEvidenceMatrixRow>,
    pub grouped_by_user_risk: BTreeMap<String, Vec<String>>,
    pub grouped_by_security_coverage: BTreeMap<String, Vec<String>>,
    pub grouped_by_remediation_coverage: BTreeMap<String, Vec<String>>,
    pub grouped_by_demo_coverage: BTreeMap<String, Vec<String>>,
    pub grouped_by_budget_status: BTreeMap<String, Vec<String>>,
    pub grouped_by_release_gate_consumer: BTreeMap<String, Vec<String>>,
    pub grouped_by_matrix_status: BTreeMap<String, Vec<String>>,
    pub consumer_contracts: Vec<AmbitionEvidenceConsumerContract>,
    pub consumer_summaries: Vec<AmbitionEvidenceConsumerSummary>,
    pub downgrade_decisions: Vec<AmbitionEvidenceDowngradeDecision>,
    pub stale_reference_checks: Vec<ReferenceCheck>,
    pub required_output_coverage: Vec<RequiredOutputCoverage>,
    pub missing_field_diagnostics: Vec<String>,
    pub generated_artifact_paths: Vec<String>,
    pub required_log_fields: Vec<String>,
    pub errors: Vec<String>,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmbitionEvidenceMatrixRow {
    pub source_bead_id: String,
    pub source_status: String,
    pub title: String,
    pub matrix_status: String,
    pub user_risk: String,
    pub threat_class: String,
    pub threat_model_status: String,
    pub threat_model_follow_up: String,
    pub expected_safe_behavior: String,
    pub hostile_artifact_handling: String,
    pub remediation_status: String,
    pub remediation_id: String,
    pub remediation_follow_up: String,
    pub demo_profile: String,
    pub proof_demo_status: String,
    pub proof_demo_follow_up: String,
    pub low_privilege_proof_status: String,
    pub low_privilege_proof_follow_up: String,
    pub overhead_budget_status: String,
    pub overhead_budget_follow_up: String,
    pub budget_profile: String,
    pub measured_overhead: String,
    pub exception_expiry: String,
    pub non_applicability_rationale: String,
    pub deferred_reason: String,
    pub release_gate_consumer: String,
    pub consumer_contracts: Vec<String>,
    pub release_claim_effect: String,
    pub downgrade_decision: String,
    pub artifact_path: String,
    pub required_logs: String,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmbitionEvidenceConsumerContract {
    pub source_bead_id: String,
    pub consumer_name: String,
    pub consumer_version: String,
    pub matrix_status: String,
    pub required_artifact_path: String,
    pub release_claim_effect: String,
    pub downgrade_decision: String,
    pub follow_up_bead_id: String,
    pub log_fields: Vec<String>,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmbitionEvidenceConsumerSummary {
    pub consumer_name: String,
    pub consumer_version: String,
    pub source_bead_ids: Vec<String>,
    pub validated_count: usize,
    pub partial_count: usize,
    pub blocked_count: usize,
    pub stale_count: usize,
    pub not_applicable_count: usize,
    pub intentionally_deferred_count: usize,
    pub downgrade_count: usize,
    pub generated_artifact_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmbitionEvidenceDowngradeDecision {
    pub source_bead_id: String,
    pub consumer_name: String,
    pub matrix_status: String,
    pub release_claim_effect: String,
    pub downgrade_decision: String,
    pub follow_up_bead_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceCheck {
    pub source_bead_id: String,
    pub referenced_bead_id: String,
    pub field: String,
    pub exists: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequiredOutputCoverage {
    pub source_bead_id: String,
    pub expected_output: String,
    pub matrix_fields: Vec<String>,
    pub release_gate_consumer: String,
    pub represented: bool,
    pub diagnostic: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IssueSummary {
    id: String,
    title: String,
    status: String,
    labels: Vec<String>,
    haystack: String,
    artifact_path_override: Option<String>,
}

pub fn run_ambition_evidence_matrix(
    config: &AmbitionEvidenceMatrixConfig,
) -> Result<AmbitionEvidenceMatrixReport> {
    let issues_jsonl = fs::read_to_string(&config.issues_jsonl)
        .with_context(|| format!("failed to read {}", config.issues_jsonl.display()))?;
    Ok(analyze_ambition_evidence_matrix(
        &issues_jsonl,
        &config.generated_artifact_paths,
    ))
}

#[must_use]
pub fn analyze_ambition_evidence_matrix(
    issues_jsonl: &str,
    generated_artifact_paths: &[String],
) -> AmbitionEvidenceMatrixReport {
    let mut errors = Vec::new();
    let issues = parse_issues(issues_jsonl, &mut errors);
    let rows = build_matrix_rows(&issues, &mut errors);
    let mut missing_field_diagnostics = validate_matrix_rows(&rows);
    let stale_reference_checks = collect_reference_checks(&rows, &issues);
    let required_output_coverage = collect_required_output_coverage(&rows);
    let consumer_contracts = build_consumer_contracts(&rows);
    let consumer_summaries =
        summarize_consumer_contracts(&consumer_contracts, generated_artifact_paths);
    let downgrade_decisions = collect_downgrade_decisions(&consumer_contracts);

    errors.extend(missing_field_diagnostics.iter().cloned());
    errors.extend(
        stale_reference_checks
            .iter()
            .filter(|check| !check.exists)
            .map(|check| {
                format!(
                    "{} stale reference {} in {}",
                    check.source_bead_id, check.referenced_bead_id, check.field
                )
            }),
    );
    errors.extend(
        required_output_coverage
            .iter()
            .filter(|coverage| !coverage.represented)
            .map(|coverage| {
                format!(
                    "{} output {} is not represented: {}",
                    coverage.source_bead_id, coverage.expected_output, coverage.diagnostic
                )
            }),
    );
    errors.extend(validate_generated_artifact_paths(generated_artifact_paths));

    missing_field_diagnostics.sort();
    missing_field_diagnostics.dedup();

    AmbitionEvidenceMatrixReport {
        matrix_version: MATRIX_VERSION.to_owned(),
        source_issue_count: issues_jsonl
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count(),
        row_count: rows.len(),
        source_bead_ids: rows.iter().map(|row| row.source_bead_id.clone()).collect(),
        required_source_beads: REQUIRED_SOURCE_BEADS
            .iter()
            .map(ToString::to_string)
            .collect(),
        allowed_consumers: ALLOWED_CONSUMERS.iter().map(ToString::to_string).collect(),
        rows: rows.clone(),
        grouped_by_user_risk: group_by(&rows, |row| row.user_risk.as_str()),
        grouped_by_security_coverage: group_by(&rows, |row| row.threat_model_status.as_str()),
        grouped_by_remediation_coverage: group_by(&rows, |row| row.remediation_status.as_str()),
        grouped_by_demo_coverage: group_by(&rows, demo_group_key),
        grouped_by_budget_status: group_by(&rows, |row| row.overhead_budget_status.as_str()),
        grouped_by_release_gate_consumer: group_by(&rows, |row| row.release_gate_consumer.as_str()),
        grouped_by_matrix_status: group_by(&rows, |row| row.matrix_status.as_str()),
        consumer_contracts,
        consumer_summaries,
        downgrade_decisions,
        stale_reference_checks,
        required_output_coverage,
        missing_field_diagnostics,
        generated_artifact_paths: generated_artifact_paths.to_vec(),
        required_log_fields: REQUIRED_LOG_TOKENS
            .iter()
            .map(ToString::to_string)
            .collect(),
        errors,
        reproduction_command: REPRODUCTION_COMMAND.to_owned(),
    }
}

fn parse_issues(issues_jsonl: &str, errors: &mut Vec<String>) -> BTreeMap<String, IssueSummary> {
    let mut issues = BTreeMap::new();
    for (line_no, line) in issues_jsonl.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value = match serde_json::from_str::<Value>(line) {
            Ok(value) => value,
            Err(err) => {
                errors.push(format!("invalid issue json at line {}: {err}", line_no + 1));
                continue;
            }
        };
        let issue = issue_from_value(&value);
        if issue.id.is_empty() {
            errors.push(format!("issue at line {} is missing id", line_no + 1));
        } else {
            issues.insert(issue.id.clone(), issue);
        }
    }
    issues
}

fn issue_from_value(value: &Value) -> IssueSummary {
    IssueSummary {
        id: string_field(value, "id"),
        title: string_field(value, "title"),
        status: string_field(value, "status"),
        labels: labels_from_issue(value),
        haystack: issue_haystack(value),
        artifact_path_override: value
            .get("artifact_path")
            .and_then(Value::as_str)
            .map(str::to_owned),
    }
}

fn labels_from_issue(value: &Value) -> Vec<String> {
    value
        .get("labels")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn issue_haystack(value: &Value) -> String {
    let mut text = String::new();
    for field in [
        "title",
        "description",
        "design",
        "acceptance_criteria",
        "notes",
        "close_reason",
    ] {
        if let Some(raw) = value.get(field).and_then(Value::as_str) {
            text.push(' ');
            text.push_str(raw);
        }
    }
    text.to_ascii_lowercase()
}

fn build_matrix_rows(
    issues: &BTreeMap<String, IssueSummary>,
    errors: &mut Vec<String>,
) -> Vec<AmbitionEvidenceMatrixRow> {
    let mut row_ids = BTreeSet::new();
    row_ids.extend(REQUIRED_SOURCE_BEADS.iter().map(|id| (*id).to_owned()));
    row_ids.extend(
        issues
            .values()
            .filter(|issue| issue.labels.iter().any(|label| label == "ambition"))
            .map(|issue| issue.id.clone()),
    );

    let mut rows = Vec::new();
    for id in row_ids {
        if let Some(issue) = issues.get(&id) {
            rows.push(row_from_issue(issue));
        } else {
            errors.push(format!("required ambition source bead {id} is missing"));
        }
    }
    rows
}

fn row_from_issue(issue: &IssueSummary) -> AmbitionEvidenceMatrixRow {
    let security_applies = applies_to_security(issue);
    let remediation_applies = applies_to_remediation(issue);
    let demo_applies = applies_to_demo(issue);
    let budget_applies = applies_to_budget(issue);
    let threat_model_status = status_for(issue, security_applies);
    let remediation_status = status_for(issue, remediation_applies);
    let proof_demo_status = status_for(issue, demo_applies);
    let low_privilege_proof_status = status_for(issue, demo_applies);
    let overhead_budget_status = status_for(issue, budget_applies);
    let status_values = [
        threat_model_status.as_str(),
        remediation_status.as_str(),
        proof_demo_status.as_str(),
        low_privilege_proof_status.as_str(),
        overhead_budget_status.as_str(),
    ];
    let matrix_status = matrix_status_for(issue, &status_values);
    let consumer_contracts = consumers_for_issue(issue, &matrix_status);
    let release_claim_effect = release_claim_effect_for(&matrix_status);
    let downgrade_decision = downgrade_decision_for(&matrix_status);

    AmbitionEvidenceMatrixRow {
        source_bead_id: issue.id.clone(),
        source_status: issue.status.clone(),
        title: issue.title.clone(),
        matrix_status,
        user_risk: classify_user_risk(issue),
        threat_class: classify_threat_class(issue),
        threat_model_status,
        threat_model_follow_up: follow_up_for(security_applies, "bd-rchk0.5.11"),
        expected_safe_behavior:
            "fail closed before release claims strengthen when coverage is missing".to_owned(),
        hostile_artifact_handling: hostile_artifact_handling(security_applies),
        remediation_status,
        remediation_id: if remediation_applies {
            "remediation:ambition-matrix".to_owned()
        } else {
            "bd-rchk0.5.12".to_owned()
        },
        remediation_follow_up: follow_up_for(remediation_applies, "bd-rchk0.5.12"),
        demo_profile: if demo_applies {
            "low-privilege-smoke".to_owned()
        } else {
            "blocked-by-bd-rchk0.5.13".to_owned()
        },
        proof_demo_status,
        proof_demo_follow_up: follow_up_for(demo_applies, "bd-rchk0.5.13"),
        low_privilege_proof_status,
        low_privilege_proof_follow_up: follow_up_for(demo_applies, "bd-rchk0.5.13"),
        overhead_budget_status,
        overhead_budget_follow_up: follow_up_for(budget_applies, "bd-rchk0.5.14"),
        budget_profile: if budget_applies {
            "developer-smoke".to_owned()
        } else {
            "blocked-by-bd-rchk0.5.14".to_owned()
        },
        measured_overhead: if budget_applies {
            "required-before-budget-gate-promotion".to_owned()
        } else {
            "blocked-by-bd-rchk0.5.14".to_owned()
        },
        exception_expiry: "not-applicable: no exception granted".to_owned(),
        non_applicability_rationale:
            "all required dimensions are applicable or blocked by an owning follow-up".to_owned(),
        deferred_reason:
            "deferred fields name their owning follow-up before release-gate consumption".to_owned(),
        release_gate_consumer: classify_release_gate_consumer(issue),
        consumer_contracts,
        release_claim_effect,
        downgrade_decision,
        artifact_path: issue
            .artifact_path_override
            .clone()
            .unwrap_or_else(|| DEFAULT_ARTIFACT_PATH.to_owned()),
        required_logs: REQUIRED_LOG_TOKENS.join(","),
        reproduction_command: REPRODUCTION_COMMAND.to_owned(),
    }
}

fn applies_to_security(issue: &IssueSummary) -> bool {
    has_any_label(issue, &["security", "safety", "threat-model"])
        || issue.haystack.contains("hostile")
        || issue.haystack.contains("threat")
        || issue.id == "bd-rchk0.5.10.1"
}

fn applies_to_remediation(issue: &IssueSummary) -> bool {
    has_any_label(issue, &["remediation", "runbook"]) || issue.id == "bd-rchk0.5.10.1"
}

fn applies_to_demo(issue: &IssueSummary) -> bool {
    has_any_label(issue, &["demo", "proof-bundle"]) || issue.id == "bd-rchk0.5.10.1"
}

fn applies_to_budget(issue: &IssueSummary) -> bool {
    has_any_label(issue, &["metrics", "performance"])
        || issue.haystack.contains("budget")
        || issue.id == "bd-rchk0.5.10.1"
}

fn has_any_label(issue: &IssueSummary, labels: &[&str]) -> bool {
    issue
        .labels
        .iter()
        .any(|label| labels.contains(&label.as_str()))
}

fn status_for(issue: &IssueSummary, applies: bool) -> String {
    match (applies, issue.status.as_str()) {
        (false, _) => "blocked".to_owned(),
        (true, "closed") => "validated".to_owned(),
        (true, "open" | "in_progress" | "claimed") => "partial".to_owned(),
        (true, _) => "stale".to_owned(),
    }
}

fn matrix_status_for(issue: &IssueSummary, status_values: &[&str]) -> String {
    if status_values.contains(&"stale") {
        return "stale".to_owned();
    }
    if status_values
        .iter()
        .all(|status| *status == "not-applicable")
    {
        return "not-applicable".to_owned();
    }
    if status_values
        .iter()
        .all(|status| *status == "intentionally-deferred")
    {
        return "intentionally-deferred".to_owned();
    }
    let validated_count = status_values
        .iter()
        .filter(|status| **status == "validated")
        .count();
    if issue.status == "closed" && validated_count == status_values.len() {
        "validated".to_owned()
    } else if status_values.contains(&"partial") || validated_count > 0 {
        "partial".to_owned()
    } else {
        "blocked".to_owned()
    }
}

fn release_claim_effect_for(matrix_status: &str) -> String {
    match matrix_status {
        "validated" => "allow matrix-backed claim only for declared consumer lanes".to_owned(),
        "partial" => {
            "downgrade public claim until missing consumer evidence is represented".to_owned()
        }
        "blocked" => "block public claim and require owning follow-up bead".to_owned(),
        "stale" => "block public claim until stale reference or artifact is refreshed".to_owned(),
        "not-applicable" => "suppress non-applicable claim with explicit rationale".to_owned(),
        "intentionally-deferred" => {
            "defer public claim and cite explicit non-goal or follow-up".to_owned()
        }
        _ => "block public claim until matrix status is recognized".to_owned(),
    }
}

fn downgrade_decision_for(matrix_status: &str) -> String {
    match matrix_status {
        "validated" => "no downgrade for covered consumer lane".to_owned(),
        "partial" => "downgrade-to-experimental".to_owned(),
        "blocked" => "fail-closed-blocked".to_owned(),
        "stale" => "fail-closed-stale".to_owned(),
        "not-applicable" => "not-applicable-non-goal".to_owned(),
        "intentionally-deferred" => "intentionally-deferred".to_owned(),
        _ => "fail-closed-unknown-status".to_owned(),
    }
}

fn follow_up_for(applies: bool, follow_up: &str) -> String {
    if applies {
        String::new()
    } else {
        follow_up.to_owned()
    }
}

fn classify_user_risk(issue: &IssueSummary) -> String {
    if applies_to_security(issue) {
        "hostile-image or hostile-artifact safety".to_owned()
    } else if applies_to_remediation(issue) {
        "operator recovery after proof failure".to_owned()
    } else if applies_to_demo(issue) {
        "low-privilege trust proof coverage".to_owned()
    } else if applies_to_budget(issue) {
        "proof overhead and artifact cost".to_owned()
    } else {
        "release claim drift".to_owned()
    }
}

fn classify_threat_class(issue: &IssueSummary) -> String {
    if applies_to_security(issue) {
        "hostile-image-or-artifact".to_owned()
    } else if applies_to_budget(issue) {
        "resource-exhaustion".to_owned()
    } else if applies_to_demo(issue) {
        "unproven-demo-claim".to_owned()
    } else {
        "matrix-omission".to_owned()
    }
}

fn hostile_artifact_handling(security_applies: bool) -> String {
    if security_applies {
        "classify hostile artifacts, refuse traversal or tamper, preserve reproduction data"
            .to_owned()
    } else {
        "blocked-by-bd-rchk0.5.11 before security claims can strengthen".to_owned()
    }
}

fn classify_release_gate_consumer(issue: &IssueSummary) -> String {
    if has_any_label(issue, &["release", "release-gates", "gates"]) {
        "release-gates".to_owned()
    } else if has_any_label(issue, &["proof-bundle"]) {
        "proof-bundle".to_owned()
    } else if has_any_label(issue, &["docs", "traceability"]) {
        "README/FEATURE_PARITY".to_owned()
    } else {
        "readiness-report".to_owned()
    }
}

fn consumers_for_issue(issue: &IssueSummary, matrix_status: &str) -> Vec<String> {
    let mut consumers = BTreeSet::new();
    let primary_consumer = classify_release_gate_consumer(issue);
    if ALLOWED_CONSUMERS.contains(&primary_consumer.as_str()) {
        consumers.insert(primary_consumer);
    }
    if has_any_label(issue, &["proof-bundle", "demo"]) {
        consumers.insert("proof-bundle".to_owned());
    }
    if has_any_label(issue, &["release", "release-gates", "gates"]) {
        consumers.insert("release-gates".to_owned());
    }
    if has_any_label(issue, &["remediation", "runbook", "operator"]) {
        consumers.insert("remediation-catalog".to_owned());
    }
    if has_any_label(issue, &["docs", "traceability", "readme", "parity"]) {
        consumers.insert("README/FEATURE_PARITY".to_owned());
    }
    if matrix_status != "validated" {
        consumers.insert("follow-up-bead".to_owned());
    }
    if consumers.is_empty() {
        consumers.insert("release-gates".to_owned());
    }
    consumers.into_iter().collect()
}

fn consumer_version(consumer_name: &str) -> &'static str {
    match consumer_name {
        "proof-bundle" => "proof-bundle-ingestion-v1",
        "release-gates" => "release-gate-evaluator-v1",
        "remediation-catalog" => "remediation-catalog-v1",
        "README/FEATURE_PARITY" => "docs-status-renderer-v1",
        "readiness-report" => "readiness-report-v1",
        "follow-up-bead" => "follow-up-bead-creator-v1",
        _ => "unknown-consumer",
    }
}

fn effective_follow_up(row: &AmbitionEvidenceMatrixRow) -> String {
    for candidate in [
        row.threat_model_follow_up.as_str(),
        row.remediation_follow_up.as_str(),
        row.proof_demo_follow_up.as_str(),
        row.low_privilege_proof_follow_up.as_str(),
        row.overhead_budget_follow_up.as_str(),
    ] {
        if candidate.starts_with("bd-") {
            return candidate.to_owned();
        }
    }
    String::new()
}

fn build_consumer_contracts(
    rows: &[AmbitionEvidenceMatrixRow],
) -> Vec<AmbitionEvidenceConsumerContract> {
    let mut contracts = Vec::new();
    for row in rows {
        let follow_up_bead_id = effective_follow_up(row);
        for consumer_name in &row.consumer_contracts {
            contracts.push(AmbitionEvidenceConsumerContract {
                source_bead_id: row.source_bead_id.clone(),
                consumer_name: consumer_name.clone(),
                consumer_version: consumer_version(consumer_name).to_owned(),
                matrix_status: row.matrix_status.clone(),
                required_artifact_path: row.artifact_path.clone(),
                release_claim_effect: row.release_claim_effect.clone(),
                downgrade_decision: row.downgrade_decision.clone(),
                follow_up_bead_id: follow_up_bead_id.clone(),
                log_fields: REQUIRED_LOG_TOKENS
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                reproduction_command: row.reproduction_command.clone(),
            });
        }
    }
    contracts
}

fn summarize_consumer_contracts(
    contracts: &[AmbitionEvidenceConsumerContract],
    generated_artifact_paths: &[String],
) -> Vec<AmbitionEvidenceConsumerSummary> {
    let mut by_consumer: BTreeMap<String, Vec<&AmbitionEvidenceConsumerContract>> = BTreeMap::new();
    for contract in contracts {
        by_consumer
            .entry(contract.consumer_name.clone())
            .or_default()
            .push(contract);
    }

    by_consumer
        .into_iter()
        .map(|(consumer_name, contracts)| {
            let source_bead_ids = contracts
                .iter()
                .map(|contract| contract.source_bead_id.clone())
                .collect();
            AmbitionEvidenceConsumerSummary {
                consumer_version: consumer_version(&consumer_name).to_owned(),
                consumer_name,
                source_bead_ids,
                validated_count: count_status(&contracts, "validated"),
                partial_count: count_status(&contracts, "partial"),
                blocked_count: count_status(&contracts, "blocked"),
                stale_count: count_status(&contracts, "stale"),
                not_applicable_count: count_status(&contracts, "not-applicable"),
                intentionally_deferred_count: count_status(&contracts, "intentionally-deferred"),
                downgrade_count: contracts
                    .iter()
                    .filter(|contract| {
                        contract.downgrade_decision != "no downgrade for covered consumer lane"
                    })
                    .count(),
                generated_artifact_paths: generated_artifact_paths.to_vec(),
            }
        })
        .collect()
}

fn count_status(contracts: &[&AmbitionEvidenceConsumerContract], status: &str) -> usize {
    contracts
        .iter()
        .filter(|contract| contract.matrix_status == status)
        .count()
}

fn collect_downgrade_decisions(
    contracts: &[AmbitionEvidenceConsumerContract],
) -> Vec<AmbitionEvidenceDowngradeDecision> {
    contracts
        .iter()
        .filter(|contract| contract.downgrade_decision != "no downgrade for covered consumer lane")
        .map(|contract| AmbitionEvidenceDowngradeDecision {
            source_bead_id: contract.source_bead_id.clone(),
            consumer_name: contract.consumer_name.clone(),
            matrix_status: contract.matrix_status.clone(),
            release_claim_effect: contract.release_claim_effect.clone(),
            downgrade_decision: contract.downgrade_decision.clone(),
            follow_up_bead_id: contract.follow_up_bead_id.clone(),
        })
        .collect()
}

fn validate_matrix_rows(rows: &[AmbitionEvidenceMatrixRow]) -> Vec<String> {
    let mut errors = Vec::new();
    let mut seen = BTreeSet::new();
    for row in rows {
        validate_row(row, &mut seen, &mut errors);
    }
    errors
}

fn validate_row(
    row: &AmbitionEvidenceMatrixRow,
    seen: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    if !seen.insert(row.source_bead_id.clone()) {
        errors.push(format!("duplicate matrix row {}", row.source_bead_id));
    }
    require_non_empty(row, "source_bead_id", &row.source_bead_id, errors);
    validate_status(
        row,
        "matrix_status",
        &row.matrix_status,
        &effective_follow_up(row),
        errors,
    );
    require_non_empty(row, "title", &row.title, errors);
    require_non_empty(row, "user_risk", &row.user_risk, errors);
    require_non_empty(row, "threat_class", &row.threat_class, errors);
    require_non_empty(
        row,
        "expected_safe_behavior",
        &row.expected_safe_behavior,
        errors,
    );
    require_non_empty(
        row,
        "hostile_artifact_handling",
        &row.hostile_artifact_handling,
        errors,
    );
    require_non_empty(row, "remediation_id", &row.remediation_id, errors);
    require_non_empty(row, "demo_profile", &row.demo_profile, errors);
    require_non_empty(row, "budget_profile", &row.budget_profile, errors);
    require_non_empty(row, "measured_overhead", &row.measured_overhead, errors);
    require_non_empty(
        row,
        "release_gate_consumer",
        &row.release_gate_consumer,
        errors,
    );
    validate_consumer_contract_fields(row, errors);
    require_non_empty(
        row,
        "release_claim_effect",
        &row.release_claim_effect,
        errors,
    );
    require_non_empty(row, "downgrade_decision", &row.downgrade_decision, errors);
    require_non_empty(row, "artifact_path", &row.artifact_path, errors);
    validate_dimension_statuses(row, errors);
    validate_required_log_contract(row, errors);
    validate_release_claim_semantics(row, errors);
}

fn validate_consumer_contract_fields(row: &AmbitionEvidenceMatrixRow, errors: &mut Vec<String>) {
    if !ALLOWED_CONSUMERS.contains(&row.release_gate_consumer.as_str()) {
        errors.push(format!(
            "{} unknown release_gate_consumer {}",
            row.source_bead_id, row.release_gate_consumer
        ));
    }
    if row.consumer_contracts.is_empty() {
        errors.push(format!("{} missing consumer_contracts", row.source_bead_id));
    }
    for consumer in &row.consumer_contracts {
        if !ALLOWED_CONSUMERS.contains(&consumer.as_str()) {
            errors.push(format!(
                "{} unknown consumer {consumer}",
                row.source_bead_id
            ));
        }
    }
}

fn validate_dimension_statuses(row: &AmbitionEvidenceMatrixRow, errors: &mut Vec<String>) {
    validate_status(
        row,
        "threat_model_status",
        &row.threat_model_status,
        &row.threat_model_follow_up,
        errors,
    );
    validate_status(
        row,
        "remediation_status",
        &row.remediation_status,
        &row.remediation_follow_up,
        errors,
    );
    validate_status(
        row,
        "proof_demo_status",
        &row.proof_demo_status,
        &row.proof_demo_follow_up,
        errors,
    );
    validate_status(
        row,
        "low_privilege_proof_status",
        &row.low_privilege_proof_status,
        &row.low_privilege_proof_follow_up,
        errors,
    );
    validate_status(
        row,
        "overhead_budget_status",
        &row.overhead_budget_status,
        &row.overhead_budget_follow_up,
        errors,
    );
}

fn validate_required_log_contract(row: &AmbitionEvidenceMatrixRow, errors: &mut Vec<String>) {
    for token in REQUIRED_LOG_TOKENS {
        if !row.required_logs.contains(token) {
            errors.push(format!(
                "{} required_logs missing {token}",
                row.source_bead_id
            ));
        }
    }
    if !row
        .reproduction_command
        .contains("ffs-harness validate-ambition-evidence-matrix")
    {
        errors.push(format!(
            "{} missing validate-ambition-evidence-matrix reproduction command",
            row.source_bead_id
        ));
    }
}

fn validate_release_claim_semantics(row: &AmbitionEvidenceMatrixRow, errors: &mut Vec<String>) {
    if row.matrix_status == "validated" && row.source_status != "closed" {
        errors.push(format!(
            "{} matrix_status validated requires closed source bead",
            row.source_bead_id
        ));
    }
    if row.matrix_status != "validated"
        && !row.release_claim_effect.contains("downgrade")
        && !row.release_claim_effect.contains("block")
        && !row.release_claim_effect.contains("defer")
        && !row.release_claim_effect.contains("suppress")
    {
        errors.push(format!(
            "{} non-validated status lacks downgrade semantics",
            row.source_bead_id
        ));
    }
}

fn require_non_empty(
    row: &AmbitionEvidenceMatrixRow,
    field: &str,
    value: &str,
    errors: &mut Vec<String>,
) {
    if value.trim().is_empty() {
        errors.push(format!("{} missing {field}", row.source_bead_id));
    }
}

fn validate_status(
    row: &AmbitionEvidenceMatrixRow,
    field: &str,
    status: &str,
    follow_up: &str,
    errors: &mut Vec<String>,
) {
    if !MATRIX_STATUSES.contains(&status) {
        errors.push(format!("{} invalid {field} {status}", row.source_bead_id));
        return;
    }
    match status {
        "blocked" if !follow_up.starts_with("bd-") => errors.push(format!(
            "{} {field} is blocked without owning follow-up",
            row.source_bead_id
        )),
        "stale" if !follow_up.starts_with("bd-") => errors.push(format!(
            "{} {field} is stale without owning follow-up",
            row.source_bead_id
        )),
        "not-applicable" if row.non_applicability_rationale.trim().is_empty() => {
            errors.push(format!(
                "{} {field} is not-applicable without rationale",
                row.source_bead_id
            ));
        }
        "intentionally-deferred" if row.deferred_reason.trim().is_empty() => errors.push(format!(
            "{} {field} is intentionally-deferred without reason",
            row.source_bead_id
        )),
        _ => {}
    }
}

fn validate_generated_artifact_paths(generated_artifact_paths: &[String]) -> Vec<String> {
    let mut errors = Vec::new();
    if generated_artifact_paths.is_empty() {
        errors.push("generated_artifact_paths is empty".to_owned());
    }
    for (index, path) in generated_artifact_paths.iter().enumerate() {
        if path.trim().is_empty() {
            errors.push(format!("generated_artifact_paths[{index}] is empty"));
        }
    }
    errors
}

fn collect_reference_checks(
    rows: &[AmbitionEvidenceMatrixRow],
    issues: &BTreeMap<String, IssueSummary>,
) -> Vec<ReferenceCheck> {
    let mut checks = Vec::new();
    for required_id in REQUIRED_SOURCE_BEADS {
        checks.push(reference_check(
            "matrix",
            required_id,
            "required_source_beads",
            issues,
        ));
    }

    for row in rows {
        checks.push(reference_check(
            &row.source_bead_id,
            &row.source_bead_id,
            "source_bead_id",
            issues,
        ));
        push_reference_if_bead(
            &mut checks,
            &row.source_bead_id,
            &row.threat_model_follow_up,
            "threat_model_follow_up",
            issues,
        );
        push_reference_if_bead(
            &mut checks,
            &row.source_bead_id,
            &row.remediation_id,
            "remediation_id",
            issues,
        );
        push_reference_if_bead(
            &mut checks,
            &row.source_bead_id,
            &row.remediation_follow_up,
            "remediation_follow_up",
            issues,
        );
        push_reference_if_bead(
            &mut checks,
            &row.source_bead_id,
            &row.proof_demo_follow_up,
            "proof_demo_follow_up",
            issues,
        );
        push_reference_if_bead(
            &mut checks,
            &row.source_bead_id,
            &row.low_privilege_proof_follow_up,
            "low_privilege_proof_follow_up",
            issues,
        );
        push_reference_if_bead(
            &mut checks,
            &row.source_bead_id,
            &row.overhead_budget_follow_up,
            "overhead_budget_follow_up",
            issues,
        );
    }
    checks
}

fn push_reference_if_bead(
    checks: &mut Vec<ReferenceCheck>,
    source_bead_id: &str,
    referenced_bead_id: &str,
    field: &str,
    issues: &BTreeMap<String, IssueSummary>,
) {
    if referenced_bead_id.starts_with("bd-") {
        checks.push(reference_check(
            source_bead_id,
            referenced_bead_id,
            field,
            issues,
        ));
    }
}

fn reference_check(
    source_bead_id: &str,
    referenced_bead_id: &str,
    field: &str,
    issues: &BTreeMap<String, IssueSummary>,
) -> ReferenceCheck {
    ReferenceCheck {
        source_bead_id: source_bead_id.to_owned(),
        referenced_bead_id: referenced_bead_id.to_owned(),
        field: field.to_owned(),
        exists: issues.contains_key(referenced_bead_id),
    }
}

fn collect_required_output_coverage(
    rows: &[AmbitionEvidenceMatrixRow],
) -> Vec<RequiredOutputCoverage> {
    required_output_specs()
        .into_iter()
        .map(|(source_bead_id, expected_output, matrix_fields)| {
            let row = rows
                .iter()
                .find(|candidate| candidate.source_bead_id == source_bead_id);
            let represented =
                row.is_some_and(|row| required_output_is_represented(source_bead_id, row));
            let diagnostic = if represented {
                "required output is represented in matrix row".to_owned()
            } else if row.is_some() {
                "matrix row exists but required fields are incomplete".to_owned()
            } else {
                "required source bead is missing from matrix rows".to_owned()
            };
            RequiredOutputCoverage {
                source_bead_id: source_bead_id.to_owned(),
                expected_output: expected_output.to_owned(),
                matrix_fields: matrix_fields.iter().map(ToString::to_string).collect(),
                release_gate_consumer: row.map_or_else(
                    || "readiness-report".to_owned(),
                    |row| row.release_gate_consumer.clone(),
                ),
                represented,
                diagnostic,
            }
        })
        .collect()
}

fn required_output_specs() -> [(&'static str, &'static str, &'static [&'static str]); 5] {
    [
        (
            "bd-rchk0.5.10.1",
            "versioned ambition evidence matrix control plane",
            &[
                "matrix_version",
                "generated_artifact_paths",
                "reproduction_command",
            ],
        ),
        (
            "bd-rchk0.5.11",
            "adversarial image security and safety threat model",
            &[
                "threat_class",
                "threat_model_status",
                "expected_safe_behavior",
                "hostile_artifact_handling",
            ],
        ),
        (
            "bd-rchk0.5.12",
            "user remediation catalog mapping for proof failures",
            &[
                "remediation_status",
                "remediation_id",
                "remediation_follow_up",
            ],
        ),
        (
            "bd-rchk0.5.13",
            "low-privilege local trust demo proof status",
            &[
                "demo_profile",
                "proof_demo_status",
                "low_privilege_proof_status",
            ],
        ),
        (
            "bd-rchk0.5.14",
            "proof instrumentation overhead budget evidence",
            &[
                "overhead_budget_status",
                "budget_profile",
                "measured_overhead",
            ],
        ),
    ]
}

fn required_output_is_represented(source_bead_id: &str, row: &AmbitionEvidenceMatrixRow) -> bool {
    match source_bead_id {
        "bd-rchk0.5.10.1" => {
            !row.artifact_path.trim().is_empty()
                && row
                    .reproduction_command
                    .contains("validate-ambition-evidence-matrix")
                && REQUIRED_LOG_TOKENS
                    .iter()
                    .all(|token| row.required_logs.contains(token))
        }
        "bd-rchk0.5.11" => {
            !row.threat_class.trim().is_empty()
                && !row.expected_safe_behavior.trim().is_empty()
                && !row.hostile_artifact_handling.trim().is_empty()
                && MATRIX_STATUSES.contains(&row.threat_model_status.as_str())
        }
        "bd-rchk0.5.12" => {
            !row.remediation_id.trim().is_empty()
                && MATRIX_STATUSES.contains(&row.remediation_status.as_str())
        }
        "bd-rchk0.5.13" => {
            !row.demo_profile.trim().is_empty()
                && MATRIX_STATUSES.contains(&row.proof_demo_status.as_str())
                && MATRIX_STATUSES.contains(&row.low_privilege_proof_status.as_str())
        }
        "bd-rchk0.5.14" => {
            !row.budget_profile.trim().is_empty()
                && !row.measured_overhead.trim().is_empty()
                && MATRIX_STATUSES.contains(&row.overhead_budget_status.as_str())
        }
        _ => false,
    }
}

fn group_by<F>(rows: &[AmbitionEvidenceMatrixRow], key_fn: F) -> BTreeMap<String, Vec<String>>
where
    F: Fn(&AmbitionEvidenceMatrixRow) -> &str,
{
    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for row in rows {
        grouped
            .entry(key_fn(row).to_owned())
            .or_default()
            .push(row.source_bead_id.clone());
    }
    grouped
}

fn demo_group_key(row: &AmbitionEvidenceMatrixRow) -> &str {
    if row.proof_demo_status == row.low_privilege_proof_status {
        row.proof_demo_status.as_str()
    } else {
        "mixed"
    }
}

fn string_field(value: &Value, field: &str) -> String {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

pub fn fail_on_ambition_evidence_matrix_errors(
    report: &AmbitionEvidenceMatrixReport,
) -> Result<()> {
    if report.errors.is_empty() {
        Ok(())
    } else {
        bail!(
            "ambition evidence matrix failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type RowMutator = fn(&mut AmbitionEvidenceMatrixRow);

    fn clear_threat_model_status(row: &mut AmbitionEvidenceMatrixRow) {
        row.threat_model_status.clear();
    }

    fn clear_remediation_id(row: &mut AmbitionEvidenceMatrixRow) {
        row.remediation_id.clear();
    }

    fn clear_proof_demo_status(row: &mut AmbitionEvidenceMatrixRow) {
        row.proof_demo_status.clear();
    }

    fn clear_low_privilege_proof_status(row: &mut AmbitionEvidenceMatrixRow) {
        row.low_privilege_proof_status.clear();
    }

    fn clear_overhead_budget_status(row: &mut AmbitionEvidenceMatrixRow) {
        row.overhead_budget_status.clear();
    }

    fn fixture_issue(id: &str, title: &str, labels: &[&str]) -> String {
        fixture_issue_with_status(id, title, "open", labels)
    }

    fn fixture_issue_with_status(id: &str, title: &str, status: &str, labels: &[&str]) -> String {
        let labels_json = match serde_json::to_string(labels) {
            Ok(labels_json) => labels_json,
            Err(err) => format!(r#"["label-serialization-error:{err}"]"#),
        };
        format!(
            r#"{{"id":"{id}","title":"{title}","status":"{status}","labels":{labels_json},"description":"{title}","design":"matrix row","acceptance_criteria":"logs include matrix_version source_bead_ids consumer_versions stale_reference_checks missing_field_diagnostics downgrade_decisions generated_artifact_paths reproduction_command"}}"#
        )
    }

    fn fixture_issues() -> String {
        [
            fixture_issue_with_status(
                "bd-rchk0.5.10.1",
                "Refine ambition evidence matrix for safety remediation demos and budgets",
                "closed",
                &[
                    "ambition",
                    "security",
                    "remediation",
                    "demo",
                    "performance",
                    "release-gates",
                    "docs",
                    "traceability",
                ],
            ),
            fixture_issue(
                "bd-rchk0.5.11",
                "Add adversarial image security and safety threat model for ambition gates",
                &[
                    "ambition",
                    "security",
                    "safety",
                    "threat-model",
                    "release-gates",
                ],
            ),
            fixture_issue(
                "bd-rchk0.5.12",
                "Create user remediation catalog for proof failures and readiness blockers",
                &["ambition", "remediation", "runbook", "proof-bundle"],
            ),
            fixture_issue(
                "bd-rchk0.5.13",
                "Build low-privilege local trust demo and sample proof bundle",
                &["ambition", "demo", "proof-bundle", "docs"],
            ),
            fixture_issue_with_status(
                "bd-rchk0.5.14",
                "Set overhead budgets for proof instrumentation repair and logging",
                "closed",
                &["ambition", "metrics", "performance", "release-gates"],
            ),
            fixture_issue(
                "bd-other",
                "Unrelated implementation task",
                &["implementation"],
            ),
        ]
        .join("\n")
    }

    fn valid_row() -> AmbitionEvidenceMatrixRow {
        let issue = IssueSummary {
            id: "bd-row".to_owned(),
            title: "row".to_owned(),
            status: "open".to_owned(),
            labels: vec![
                "ambition".to_owned(),
                "security".to_owned(),
                "remediation".to_owned(),
                "demo".to_owned(),
                "performance".to_owned(),
            ],
            haystack: "hostile remediation demo budget".to_owned(),
            artifact_path_override: None,
        };
        row_from_issue(&issue)
    }

    #[test]
    fn builds_required_ambition_matrix_without_errors() {
        let report = analyze_ambition_evidence_matrix(
            &fixture_issues(),
            &[DEFAULT_ARTIFACT_PATH.to_owned()],
        );
        assert!(
            report.errors.is_empty(),
            "unexpected errors: {:?}",
            report.errors
        );
        assert_eq!(report.matrix_version, MATRIX_VERSION);
        assert_eq!(report.row_count, 5);
        assert!(
            report
                .rows
                .iter()
                .any(|row| row.source_bead_id == "bd-rchk0.5.14"
                    && row.overhead_budget_status == "validated")
        );
        assert!(
            report
                .allowed_consumers
                .contains(&"release-gates".to_owned())
        );
        assert!(
            report
                .source_bead_ids
                .contains(&"bd-rchk0.5.10.1".to_owned())
        );
    }

    #[test]
    fn groups_rows_by_user_risk_and_evidence_coverage() {
        let report = analyze_ambition_evidence_matrix(
            &fixture_issues(),
            &[DEFAULT_ARTIFACT_PATH.to_owned()],
        );
        assert!(
            report
                .grouped_by_user_risk
                .contains_key("hostile-image or hostile-artifact safety")
        );
        assert!(
            report
                .grouped_by_security_coverage
                .contains_key("validated")
        );
        assert!(
            report
                .grouped_by_remediation_coverage
                .contains_key("blocked")
        );
        assert!(report.grouped_by_demo_coverage.contains_key("blocked"));
        assert!(report.grouped_by_budget_status.contains_key("validated"));
        assert!(report.grouped_by_matrix_status.contains_key("partial"));
        assert!(
            report
                .grouped_by_release_gate_consumer
                .contains_key("release-gates")
        );
    }

    #[test]
    fn schema_rejects_missing_required_matrix_fields() {
        let cases: [(&str, RowMutator); 5] = [
            ("threat_model_status", clear_threat_model_status),
            ("remediation_id", clear_remediation_id),
            ("proof_demo_status", clear_proof_demo_status),
            (
                "low_privilege_proof_status",
                clear_low_privilege_proof_status,
            ),
            ("overhead_budget_status", clear_overhead_budget_status),
        ];

        for (expected, mutate) in cases {
            let mut row = valid_row();
            mutate(&mut row);
            let errors = validate_matrix_rows(&[row]);
            assert!(
                errors.iter().any(|error| error.contains(expected)),
                "expected {expected} error, got {errors:?}"
            );
        }
    }

    #[test]
    fn blocked_status_requires_owning_follow_up() {
        let mut row = valid_row();
        row.threat_model_status = "blocked".to_owned();
        row.threat_model_follow_up.clear();
        let errors = validate_matrix_rows(&[row]);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("owning follow-up")),
            "expected follow-up error, got {errors:?}"
        );
    }

    #[test]
    fn not_applicable_status_requires_rationale() {
        let mut row = valid_row();
        row.threat_model_status = "not-applicable".to_owned();
        row.non_applicability_rationale.clear();
        let errors = validate_matrix_rows(&[row]);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("not-applicable without rationale")),
            "expected not-applicable rationale error, got {errors:?}"
        );
    }

    #[test]
    fn deferred_status_requires_reason() {
        let mut row = valid_row();
        row.proof_demo_status = "intentionally-deferred".to_owned();
        row.deferred_reason.clear();
        let errors = validate_matrix_rows(&[row]);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("intentionally-deferred without reason")),
            "expected intentionally-deferred reason error, got {errors:?}"
        );
    }

    #[test]
    fn schema_rejects_consumer_artifact_and_status_drift() {
        let mut missing_bead = valid_row();
        missing_bead.source_bead_id.clear();
        let mut unknown_consumer = valid_row();
        unknown_consumer.consumer_contracts = vec!["spreadsheet".to_owned()];
        let mut missing_effect = valid_row();
        missing_effect.release_claim_effect.clear();
        let mut missing_artifact = valid_row();
        missing_artifact.artifact_path.clear();
        let mut missing_logs = valid_row();
        missing_logs.required_logs = "matrix_version".to_owned();
        let mut unsupported_status = valid_row();
        unsupported_status.matrix_status = "optimistic".to_owned();

        for (expected, row) in [
            ("source_bead_id", missing_bead),
            ("unknown consumer", unknown_consumer),
            ("release_claim_effect", missing_effect),
            ("artifact_path", missing_artifact),
            ("required_logs missing source_bead_ids", missing_logs),
            ("invalid matrix_status", unsupported_status),
        ] {
            let errors = validate_matrix_rows(&[row]);
            assert!(
                errors.iter().any(|error| error.contains(expected)),
                "expected {expected} error, got {errors:?}"
            );
        }
    }

    #[test]
    fn missing_required_reference_fails_stale_check() {
        let issues = fixture_issues().replace(
            &fixture_issue_with_status(
                "bd-rchk0.5.14",
                "Set overhead budgets for proof instrumentation repair and logging",
                "closed",
                &["ambition", "metrics", "performance", "release-gates"],
            ),
            "",
        );
        let report = analyze_ambition_evidence_matrix(&issues, &[DEFAULT_ARTIFACT_PATH.to_owned()]);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("bd-rchk0.5.14")),
            "expected stale reference error, got {:?}",
            report.errors
        );
    }

    #[test]
    fn required_downstream_outputs_are_explicitly_represented() {
        let report = analyze_ambition_evidence_matrix(
            &fixture_issues(),
            &[DEFAULT_ARTIFACT_PATH.to_owned()],
        );
        assert_eq!(report.required_output_coverage.len(), 5);
        for required_id in [
            "bd-rchk0.5.11",
            "bd-rchk0.5.12",
            "bd-rchk0.5.13",
            "bd-rchk0.5.14",
        ] {
            let coverage = report
                .required_output_coverage
                .iter()
                .find(|coverage| coverage.source_bead_id == required_id);
            assert!(coverage.is_some(), "missing coverage row for {required_id}");
            if let Some(coverage) = coverage {
                assert!(
                    coverage.represented,
                    "expected {required_id} to be represented, got {coverage:?}"
                );
                assert!(
                    !coverage.matrix_fields.is_empty(),
                    "expected field mapping for {required_id}"
                );
            }
        }
    }

    #[test]
    fn emits_consumer_contracts_and_downgrade_decisions() {
        let report = analyze_ambition_evidence_matrix(
            &fixture_issues(),
            &[DEFAULT_ARTIFACT_PATH.to_owned()],
        );
        for consumer in [
            "proof-bundle",
            "release-gates",
            "remediation-catalog",
            "README/FEATURE_PARITY",
            "follow-up-bead",
        ] {
            assert!(
                report
                    .consumer_summaries
                    .iter()
                    .any(|summary| summary.consumer_name == consumer
                        && !summary.consumer_version.is_empty()),
                "missing consumer summary for {consumer}"
            );
            assert!(
                report
                    .consumer_contracts
                    .iter()
                    .any(|contract| contract.consumer_name == consumer
                        && contract
                            .log_fields
                            .contains(&"consumer_versions".to_owned())),
                "missing consumer contract for {consumer}"
            );
        }
        assert!(
            report
                .downgrade_decisions
                .iter()
                .any(|decision| decision.downgrade_decision == "downgrade-to-experimental"),
            "expected partial rows to emit downgrade decisions"
        );
    }
}
