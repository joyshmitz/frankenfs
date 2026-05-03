#![forbid(unsafe_code)]

//! Ambition evidence matrix control plane for `bd-rchk0.5.10.1`.
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

pub const MATRIX_VERSION: &str = "bd-rchk0.5.10.1-ambition-evidence-matrix-v1";

const REQUIRED_SOURCE_BEADS: [&str; 5] = [
    "bd-rchk0.5.10.1",
    "bd-rchk0.5.11",
    "bd-rchk0.5.12",
    "bd-rchk0.5.13",
    "bd-rchk0.5.14",
];

const COVERAGE_STATES: [&str; 4] = ["applicable", "not-applicable", "blocked", "deferred"];

const REQUIRED_LOG_TOKENS: [&str; 6] = [
    "matrix_version",
    "source_bead_ids",
    "stale_reference_checks",
    "missing_field_diagnostics",
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
    pub required_source_beads: Vec<String>,
    pub rows: Vec<AmbitionEvidenceMatrixRow>,
    pub grouped_by_user_risk: BTreeMap<String, Vec<String>>,
    pub grouped_by_security_coverage: BTreeMap<String, Vec<String>>,
    pub grouped_by_remediation_coverage: BTreeMap<String, Vec<String>>,
    pub grouped_by_demo_coverage: BTreeMap<String, Vec<String>>,
    pub grouped_by_budget_status: BTreeMap<String, Vec<String>>,
    pub grouped_by_release_gate_consumer: BTreeMap<String, Vec<String>>,
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
    pub release_claim_effect: String,
    pub artifact_path: String,
    pub required_logs: String,
    pub reproduction_command: String,
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

    missing_field_diagnostics.sort();
    missing_field_diagnostics.dedup();

    AmbitionEvidenceMatrixReport {
        matrix_version: MATRIX_VERSION.to_owned(),
        source_issue_count: issues_jsonl
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count(),
        row_count: rows.len(),
        required_source_beads: REQUIRED_SOURCE_BEADS
            .iter()
            .map(ToString::to_string)
            .collect(),
        rows: rows.clone(),
        grouped_by_user_risk: group_by(&rows, |row| row.user_risk.as_str()),
        grouped_by_security_coverage: group_by(&rows, |row| row.threat_model_status.as_str()),
        grouped_by_remediation_coverage: group_by(&rows, |row| row.remediation_status.as_str()),
        grouped_by_demo_coverage: group_by(&rows, demo_group_key),
        grouped_by_budget_status: group_by(&rows, |row| row.overhead_budget_status.as_str()),
        grouped_by_release_gate_consumer: group_by(&rows, |row| row.release_gate_consumer.as_str()),
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

    AmbitionEvidenceMatrixRow {
        source_bead_id: issue.id.clone(),
        source_status: issue.status.clone(),
        title: issue.title.clone(),
        user_risk: classify_user_risk(issue),
        threat_class: classify_threat_class(issue),
        threat_model_status: status_for(security_applies),
        threat_model_follow_up: follow_up_for(security_applies, "bd-rchk0.5.11"),
        expected_safe_behavior:
            "fail closed before release claims strengthen when coverage is missing".to_owned(),
        hostile_artifact_handling: hostile_artifact_handling(security_applies),
        remediation_status: status_for(remediation_applies),
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
        proof_demo_status: status_for(demo_applies),
        proof_demo_follow_up: follow_up_for(demo_applies, "bd-rchk0.5.13"),
        low_privilege_proof_status: status_for(demo_applies),
        low_privilege_proof_follow_up: follow_up_for(demo_applies, "bd-rchk0.5.13"),
        overhead_budget_status: status_for(budget_applies),
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
        release_claim_effect:
            "downgrade or block ambition-readiness claims when required evidence is absent"
                .to_owned(),
        artifact_path: DEFAULT_ARTIFACT_PATH.to_owned(),
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

fn status_for(applies: bool) -> String {
    if applies {
        "applicable".to_owned()
    } else {
        "blocked".to_owned()
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
    require_non_empty(
        row,
        "release_claim_effect",
        &row.release_claim_effect,
        errors,
    );
    require_non_empty(row, "artifact_path", &row.artifact_path, errors);

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
    if !COVERAGE_STATES.contains(&status) {
        errors.push(format!("{} invalid {field} {status}", row.source_bead_id));
        return;
    }
    match status {
        "blocked" if !follow_up.starts_with("bd-") => errors.push(format!(
            "{} {field} is blocked without owning follow-up",
            row.source_bead_id
        )),
        "not-applicable" if row.non_applicability_rationale.trim().is_empty() => {
            errors.push(format!(
                "{} {field} is not-applicable without rationale",
                row.source_bead_id
            ));
        }
        "deferred" if row.deferred_reason.trim().is_empty() => errors.push(format!(
            "{} {field} is deferred without reason",
            row.source_bead_id
        )),
        _ => {}
    }
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
                && COVERAGE_STATES.contains(&row.threat_model_status.as_str())
        }
        "bd-rchk0.5.12" => {
            !row.remediation_id.trim().is_empty()
                && COVERAGE_STATES.contains(&row.remediation_status.as_str())
        }
        "bd-rchk0.5.13" => {
            !row.demo_profile.trim().is_empty()
                && COVERAGE_STATES.contains(&row.proof_demo_status.as_str())
                && COVERAGE_STATES.contains(&row.low_privilege_proof_status.as_str())
        }
        "bd-rchk0.5.14" => {
            !row.budget_profile.trim().is_empty()
                && !row.measured_overhead.trim().is_empty()
                && COVERAGE_STATES.contains(&row.overhead_budget_status.as_str())
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
        let labels_json = match serde_json::to_string(labels) {
            Ok(labels_json) => labels_json,
            Err(err) => format!(r#"["label-serialization-error:{err}"]"#),
        };
        format!(
            r#"{{"id":"{id}","title":"{title}","status":"open","labels":{labels_json},"description":"{title}","design":"matrix row","acceptance_criteria":"logs include matrix_version source_bead_ids stale_reference_checks missing_field_diagnostics generated_artifact_paths reproduction_command"}}"#
        )
    }

    fn fixture_issues() -> String {
        [
            fixture_issue(
                "bd-rchk0.5.10.1",
                "Refine ambition evidence matrix for safety remediation demos and budgets",
                &["ambition", "security", "remediation", "demo", "performance"],
            ),
            fixture_issue(
                "bd-rchk0.5.11",
                "Add adversarial image security and safety threat model for ambition gates",
                &["ambition", "security", "safety", "threat-model"],
            ),
            fixture_issue(
                "bd-rchk0.5.12",
                "Create user remediation catalog for proof failures and readiness blockers",
                &["ambition", "remediation", "runbook"],
            ),
            fixture_issue(
                "bd-rchk0.5.13",
                "Build low-privilege local trust demo and sample proof bundle",
                &["ambition", "demo", "proof-bundle"],
            ),
            fixture_issue(
                "bd-rchk0.5.14",
                "Set overhead budgets for proof instrumentation repair and logging",
                &["ambition", "metrics", "performance"],
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
                    && row.overhead_budget_status == "applicable")
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
                .contains_key("applicable")
        );
        assert!(
            report
                .grouped_by_remediation_coverage
                .contains_key("blocked")
        );
        assert!(report.grouped_by_demo_coverage.contains_key("blocked"));
        assert!(report.grouped_by_budget_status.contains_key("applicable"));
        assert!(
            report
                .grouped_by_release_gate_consumer
                .contains_key("readiness-report")
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
        row.proof_demo_status = "deferred".to_owned();
        row.deferred_reason.clear();
        let errors = validate_matrix_rows(&[row]);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("deferred without reason")),
            "expected deferred reason error, got {errors:?}"
        );
    }

    #[test]
    fn missing_required_reference_fails_stale_check() {
        let issues = fixture_issues().replace(
            &fixture_issue(
                "bd-rchk0.5.14",
                "Set overhead budgets for proof instrumentation repair and logging",
                &["ambition", "metrics", "performance"],
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
}
