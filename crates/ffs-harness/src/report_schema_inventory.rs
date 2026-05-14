#![forbid(unsafe_code)]

//! Inventory of public serialized report schemas emitted by `ffs-harness`.
//!
//! This module is intentionally read-only. It records which durable JSON report
//! contracts already have typed serde round-trip coverage and JSON-shape
//! snapshots, without running permissioned xfstests, mounted mutation, or
//! large-host campaigns.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Component, Path};

pub const REPORT_SCHEMA_INVENTORY_SCHEMA_VERSION: u32 = 1;
pub const REPORT_SCHEMA_INVENTORY_ID: &str = "ffs_harness_serialized_report_schema_inventory_v1";
pub const REPORT_SCHEMA_INVENTORY_PRODUCT_EVIDENCE_CLAIM: &str = "none";
pub const REPORT_SCHEMA_INVENTORY_REPRODUCTION_COMMAND: &str = "ffs-harness validate-report-schema-inventory --out artifacts/report-schema-inventory/report.json --summary-out artifacts/report-schema-inventory/report.md";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportSchemaInventory {
    pub schema_version: u32,
    pub inventory_id: String,
    pub rows: Vec<ReportSchemaInventoryRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportSchemaInventoryRow {
    pub report_id: String,
    pub module_path: String,
    pub rust_type: String,
    pub producer: String,
    pub downstream_consumer: String,
    pub coverage_requirement: ReportSchemaCoverageRequirement,
    pub coverage_status: ReportSchemaCoverageStatus,
    pub evidence_test: String,
    pub snapshot_path: String,
    pub exclusion_reason: String,
    pub claim_effect: ReportSchemaClaimEffect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportSchemaCoverageRequirement {
    Required,
    AdvisoryOnly,
    PermissionedOnly,
    Excluded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportSchemaCoverageStatus {
    Covered,
    Missing,
    Excluded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportSchemaClaimEffect {
    ProductEvidenceNone,
    AdvisoryOnlyNoPublicReadinessChange,
    ExistingReleaseGateInput,
    InternalOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportSchemaInventoryReport {
    pub schema_version: u32,
    pub inventory_id: String,
    pub product_evidence_claim: String,
    pub reproduction_command: String,
    pub valid: bool,
    pub total_rows: usize,
    pub required_rows: usize,
    pub advisory_only_rows: usize,
    pub permissioned_only_rows: usize,
    pub covered_rows: usize,
    pub missing_rows: usize,
    pub excluded_rows: usize,
    pub report_ids: Vec<String>,
    pub uncovered_required_report_ids: Vec<String>,
    pub row_results: Vec<ReportSchemaInventoryRowResult>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportSchemaInventoryRowResult {
    pub report_id: String,
    pub module_path: String,
    pub rust_type: String,
    pub downstream_consumer: String,
    pub coverage_requirement: ReportSchemaCoverageRequirement,
    pub coverage_status: ReportSchemaCoverageStatus,
    pub evidence_test: String,
    pub snapshot_path: String,
    pub exclusion_reason: String,
    pub claim_effect: ReportSchemaClaimEffect,
    pub missing_evidence: Vec<String>,
    pub errors: Vec<String>,
}

#[must_use]
pub fn current_report_schema_inventory() -> ReportSchemaInventory {
    let mut rows = advisory_report_rows();
    rows.extend(required_report_rows());
    rows.push(permissioned_campaign_reports_row());
    rows.push(readiness_action_dry_run_metadata_row());

    ReportSchemaInventory {
        schema_version: REPORT_SCHEMA_INVENTORY_SCHEMA_VERSION,
        inventory_id: REPORT_SCHEMA_INVENTORY_ID.to_owned(),
        rows,
    }
}

fn advisory_report_rows() -> Vec<ReportSchemaInventoryRow> {
    vec![
        covered_advisory_row(
            "readiness_lab_validation_report",
            "crates/ffs-harness/src/readiness_lab.rs",
            "ReadinessLabValidationReport",
            "validate-readiness-lab-contracts",
            "readiness-lab advisory contracts and dashboard rows",
            "readiness_lab_validation_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__readiness_lab__tests__readiness_lab_validation_report_json_shape.snap",
        ),
        covered_advisory_row(
            "readiness_lab_rch_lane_schedule_report",
            "crates/ffs-harness/src/readiness_lab.rs",
            "ReadinessLabRchLaneScheduleReport",
            "plan-readiness-lab-rch-lanes",
            "readiness-lab RCH dry-run scheduler",
            "readiness_lab_rch_lane_schedule_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__readiness_lab__tests__readiness_lab_rch_lane_schedule_report_json_shape.snap",
        ),
        covered_advisory_row(
            "tracker_source_hygiene_report",
            "crates/ffs-harness/src/tracker_source_hygiene.rs",
            "TrackerSourceHygieneReport",
            "validate-tracker-source-hygiene",
            "source-aware tracker queue state and local graph exports",
            "tracker_source_hygiene_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__tracker_source_hygiene__tests__tracker_source_hygiene_report_json_shape.snap",
        ),
        covered_advisory_row(
            "readiness_lab_numa_p99_replay_report",
            "crates/ffs-harness/src/readiness_lab.rs",
            "ReadinessLabNumaP99ReplayReport",
            "readiness-lab NUMA/p99 replay",
            "large-host swarm responsiveness advisory replay lane",
            "readiness_lab_numa_p99_replay_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__readiness_lab__tests__readiness_lab_numa_p99_replay_report_json_shape.snap",
        ),
        covered_advisory_row(
            "readiness_action_autopilot_source_reports",
            "crates/ffs-harness/src/readiness_action_autopilot.rs",
            "Vec<ReadinessActionAutopilotReport>",
            "readiness-action source fixture planner",
            "readiness-action dry-run planner",
            "readiness_action_autopilot_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__readiness_action_autopilot__tests__readiness_action_autopilot_report_json_shape.snap",
        ),
    ]
}

fn required_report_rows() -> Vec<ReportSchemaInventoryRow> {
    vec![
        covered_required_row(
            "swarm_operator_report",
            "crates/ffs-harness/src/swarm_operator_report.rs",
            "SwarmOperatorReport",
            "swarm operator report renderer",
            "proof-bundle and release-gate operator consumers",
            "swarm_operator_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__swarm_operator_report__tests__swarm_operator_report_json_shape.snap",
            ReportSchemaClaimEffect::ExistingReleaseGateInput,
        ),
        covered_required_row(
            "proof_bundle_validation_report",
            "crates/ffs-harness/src/proof_bundle.rs",
            "ProofBundleValidationReport",
            "validate-proof-bundle",
            "portable release proof bundle inspection",
            "proof_bundle_validation_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__proof_bundle__tests__proof_bundle_validation_report_json_shape.snap",
            ReportSchemaClaimEffect::ExistingReleaseGateInput,
        ),
        covered_required_row(
            "release_gate_evaluation_report",
            "crates/ffs-harness/src/release_gate.rs",
            "ReleaseGateEvaluationReport",
            "release gate policy evaluator",
            "public readiness wording gate",
            "release_gate_evaluation_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__release_gate__tests__release_gate_evaluation_report_json_shape.snap",
            ReportSchemaClaimEffect::ExistingReleaseGateInput,
        ),
        covered_required_row(
            "operational_readiness_report",
            "crates/ffs-harness/src/operational_readiness_report.rs",
            "OperationalReadinessReport",
            "operational readiness report aggregator",
            "readiness proof and runbook consumers",
            "operational_readiness_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__operational_readiness_report__tests__operational_readiness_report_json_shape.snap",
            ReportSchemaClaimEffect::ExistingReleaseGateInput,
        ),
        covered_required_row(
            "readiness_dashboard_report",
            "crates/ffs-harness/src/readiness_dashboard.rs",
            "ReadinessDashboardReport",
            "readiness dashboard renderer",
            "operator dashboard advisory rows",
            "readiness_dashboard_report_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__readiness_dashboard__tests__readiness_dashboard_report_json_shape.snap",
            ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange,
        ),
        covered_required_row(
            "authoritative_lane_decision",
            "crates/ffs-harness/src/authoritative_lane_manifest.rs",
            "AuthoritativeLaneDecision",
            "authoritative lane manifest evaluator",
            "proof-bundle lane promotion and release gates",
            "authoritative_lane_decision_json_shape",
            "crates/ffs-harness/src/snapshots/ffs_harness__authoritative_lane_manifest__tests__authoritative_lane_decision_json_shape.snap",
            ReportSchemaClaimEffect::ExistingReleaseGateInput,
        ),
    ]
}

fn permissioned_campaign_reports_row() -> ReportSchemaInventoryRow {
    covered_permissioned_row(
        "permissioned_campaign_reports",
        "crates/ffs-harness/src/permissioned_campaign_broker.rs",
        "PermissionedCampaignBrokerReport + PermissionedCampaignExecutionLedgerReport + SwarmCapabilityCalibrationReport",
        "permissioned campaign broker validators",
        "operator handoff packets for xfstests and large-host swarm campaigns",
        "permissioned_campaign_reports_json_shape",
        "crates/ffs-harness/src/snapshots/ffs_harness__permissioned_campaign_broker__tests__permissioned_campaign_reports_json_shape.snap",
    )
}

fn readiness_action_dry_run_metadata_row() -> ReportSchemaInventoryRow {
    excluded_row(
        "readiness_action_dry_run_metadata",
        "crates/ffs-harness/src/readiness_action_autopilot.rs",
        "ReadinessActionDryRunMetadata",
        "nested dry-run metadata helper",
        "nested inside ReadinessActionDryRunReport",
        "Nested metadata is not emitted as a standalone durable report; the enclosing dry-run JSON report owns the serialized artifact contract.",
    )
}

#[must_use]
pub fn validate_report_schema_inventory(
    inventory: &ReportSchemaInventory,
) -> ReportSchemaInventoryReport {
    let mut errors = Vec::new();
    let mut report_ids = BTreeSet::new();
    let mut required_rows = 0;
    let mut advisory_only_rows = 0;
    let mut permissioned_only_rows = 0;
    let mut covered_rows = 0;
    let mut missing_rows = 0;
    let mut excluded_rows = 0;
    let mut row_results = Vec::new();

    if inventory.schema_version != REPORT_SCHEMA_INVENTORY_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version must be {REPORT_SCHEMA_INVENTORY_SCHEMA_VERSION}, got {}",
            inventory.schema_version
        ));
    }
    if inventory.inventory_id != REPORT_SCHEMA_INVENTORY_ID {
        errors.push(format!(
            "inventory_id must be `{REPORT_SCHEMA_INVENTORY_ID}`, got `{}`",
            inventory.inventory_id
        ));
    }
    if inventory.rows.is_empty() {
        errors.push("report schema inventory must declare at least one row".to_owned());
    }

    for row in &inventory.rows {
        let row_result = validate_row(
            row,
            &mut report_ids,
            &mut required_rows,
            &mut advisory_only_rows,
            &mut permissioned_only_rows,
            &mut covered_rows,
            &mut missing_rows,
            &mut excluded_rows,
        );
        errors.extend(row_result.errors.iter().cloned());
        row_results.push(row_result);
    }
    row_results.sort_by(|left, right| left.report_id.cmp(&right.report_id));
    errors.sort();
    let uncovered_required_report_ids = row_results
        .iter()
        .filter(|row| {
            row.coverage_requirement == ReportSchemaCoverageRequirement::Required
                && !row.missing_evidence.is_empty()
        })
        .map(|row| row.report_id.clone())
        .collect();

    ReportSchemaInventoryReport {
        schema_version: inventory.schema_version,
        inventory_id: inventory.inventory_id.clone(),
        product_evidence_claim: REPORT_SCHEMA_INVENTORY_PRODUCT_EVIDENCE_CLAIM.to_owned(),
        reproduction_command: REPORT_SCHEMA_INVENTORY_REPRODUCTION_COMMAND.to_owned(),
        valid: errors.is_empty(),
        total_rows: inventory.rows.len(),
        required_rows,
        advisory_only_rows,
        permissioned_only_rows,
        covered_rows,
        missing_rows,
        excluded_rows,
        report_ids: report_ids.into_iter().collect(),
        uncovered_required_report_ids,
        row_results,
        errors,
    }
}

pub fn fail_on_report_schema_inventory_errors(report: &ReportSchemaInventoryReport) -> Result<()> {
    if report.valid {
        return Ok(());
    }
    bail!(
        "report schema inventory failed with {} error(s): {}",
        report.errors.len(),
        report.errors.join("; ")
    );
}

#[must_use]
pub fn render_report_schema_inventory_markdown(report: &ReportSchemaInventoryReport) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "# Report Schema Inventory");
    let _ = writeln!(output);
    let _ = writeln!(output, "- Inventory ID: `{}`", report.inventory_id);
    let _ = writeln!(output, "- Valid: `{}`", report.valid);
    let _ = writeln!(
        output,
        "- Product evidence claim: `{}`",
        report.product_evidence_claim
    );
    let _ = writeln!(
        output,
        "- Reproduction command: `{}`",
        report.reproduction_command
    );
    let _ = writeln!(output);
    let _ = writeln!(output, "## Counts");
    let _ = writeln!(output);
    let _ = writeln!(output, "| Metric | Count |");
    let _ = writeln!(output, "|---|---:|");
    let _ = writeln!(output, "| Total rows | {} |", report.total_rows);
    let _ = writeln!(output, "| Required rows | {} |", report.required_rows);
    let _ = writeln!(
        output,
        "| Advisory-only rows | {} |",
        report.advisory_only_rows
    );
    let _ = writeln!(
        output,
        "| Permissioned-only rows | {} |",
        report.permissioned_only_rows
    );
    let _ = writeln!(output, "| Covered rows | {} |", report.covered_rows);
    let _ = writeln!(output, "| Missing rows | {} |", report.missing_rows);
    let _ = writeln!(output, "| Excluded rows | {} |", report.excluded_rows);
    let _ = writeln!(output);

    let _ = writeln!(output, "## Uncovered Required Reports");
    let _ = writeln!(output);
    if report.uncovered_required_report_ids.is_empty() {
        let _ = writeln!(output, "None.");
    } else {
        for report_id in &report.uncovered_required_report_ids {
            let _ = writeln!(output, "- `{report_id}`");
        }
    }

    let _ = writeln!(output);
    let _ = writeln!(output, "## Row Results");
    let _ = writeln!(output);
    let _ = writeln!(
        output,
        "| Report ID | Requirement | Status | Missing Evidence | Errors |"
    );
    let _ = writeln!(output, "|---|---|---|---|---|");
    for row in &report.row_results {
        let missing = if row.missing_evidence.is_empty() {
            "none".to_owned()
        } else {
            row.missing_evidence.join(", ")
        };
        let errors = if row.errors.is_empty() {
            "none".to_owned()
        } else {
            row.errors.join("; ")
        };
        let _ = writeln!(
            output,
            "| `{}` | `{:?}` | `{:?}` | {} | {} |",
            row.report_id, row.coverage_requirement, row.coverage_status, missing, errors
        );
    }

    output
}

#[allow(clippy::too_many_arguments)]
fn validate_row(
    row: &ReportSchemaInventoryRow,
    report_ids: &mut BTreeSet<String>,
    required_rows: &mut usize,
    advisory_only_rows: &mut usize,
    permissioned_only_rows: &mut usize,
    covered_rows: &mut usize,
    missing_rows: &mut usize,
    excluded_rows: &mut usize,
) -> ReportSchemaInventoryRowResult {
    let mut errors = Vec::new();
    let mut missing_evidence = Vec::new();

    if row.report_id.trim().is_empty() {
        errors.push("report schema row missing report_id".to_owned());
    } else if !report_ids.insert(row.report_id.clone()) {
        errors.push(format!("duplicate report_id `{}`", row.report_id));
    }

    match row.coverage_requirement {
        ReportSchemaCoverageRequirement::Required => *required_rows += 1,
        ReportSchemaCoverageRequirement::AdvisoryOnly => *advisory_only_rows += 1,
        ReportSchemaCoverageRequirement::PermissionedOnly => *permissioned_only_rows += 1,
        ReportSchemaCoverageRequirement::Excluded => *excluded_rows += 1,
    }

    match row.coverage_status {
        ReportSchemaCoverageStatus::Covered => *covered_rows += 1,
        ReportSchemaCoverageStatus::Missing => *missing_rows += 1,
        ReportSchemaCoverageStatus::Excluded => {}
    }

    validate_non_empty(row, "module_path", &row.module_path, &mut errors);
    validate_non_empty(row, "rust_type", &row.rust_type, &mut errors);
    validate_non_empty(row, "producer", &row.producer, &mut errors);
    validate_non_empty(
        row,
        "downstream_consumer",
        &row.downstream_consumer,
        &mut errors,
    );
    validate_safe_relative_path(row, "module_path", &row.module_path, &mut errors);

    if !row.snapshot_path.is_empty() {
        validate_safe_relative_path(row, "snapshot_path", &row.snapshot_path, &mut errors);
    }

    validate_coverage_fields(row, &mut missing_evidence, &mut errors);
    validate_claim_effect(row, &mut missing_evidence, &mut errors);
    missing_evidence.sort();
    missing_evidence.dedup();
    errors.sort();

    ReportSchemaInventoryRowResult {
        report_id: row.report_id.clone(),
        module_path: row.module_path.clone(),
        rust_type: row.rust_type.clone(),
        downstream_consumer: row.downstream_consumer.clone(),
        coverage_requirement: row.coverage_requirement,
        coverage_status: row.coverage_status,
        evidence_test: row.evidence_test.clone(),
        snapshot_path: row.snapshot_path.clone(),
        exclusion_reason: row.exclusion_reason.clone(),
        claim_effect: row.claim_effect,
        missing_evidence,
        errors,
    }
}

fn validate_coverage_fields(
    row: &ReportSchemaInventoryRow,
    missing_evidence: &mut Vec<String>,
    errors: &mut Vec<String>,
) {
    match (row.coverage_requirement, row.coverage_status) {
        (ReportSchemaCoverageRequirement::Excluded, ReportSchemaCoverageStatus::Excluded) => {
            if row.exclusion_reason.trim().is_empty() {
                missing_evidence.push("explicit_exclusion_reason".to_owned());
                errors.push(format!(
                    "row `{}` is excluded but missing exclusion_reason",
                    row.report_id
                ));
            }
        }
        (ReportSchemaCoverageRequirement::Excluded, status) => {
            errors.push(format!(
                "row `{}` has excluded requirement but status {status:?}",
                row.report_id
            ));
        }
        (_, ReportSchemaCoverageStatus::Excluded) => {
            errors.push(format!(
                "row `{}` has non-excluded requirement but excluded status",
                row.report_id
            ));
        }
        (_, ReportSchemaCoverageStatus::Covered) => {
            if row.evidence_test.trim().is_empty() {
                missing_evidence.push("typed_serde_round_trip_evidence".to_owned());
                missing_evidence.push("valid_evidence_test_name".to_owned());
                errors.push(format!(
                    "row `{}` is covered but missing evidence_test",
                    row.report_id
                ));
            } else if !is_valid_rust_test_name(&row.evidence_test) {
                missing_evidence.push("valid_evidence_test_name".to_owned());
                errors.push(format!(
                    "row `{}` evidence_test is not a valid rust test name: `{}`",
                    row.report_id, row.evidence_test
                ));
            }
            if row.snapshot_path.trim().is_empty() {
                missing_evidence.push("compact_json_shape_snapshot".to_owned());
                errors.push(format!(
                    "row `{}` is covered but missing snapshot_path",
                    row.report_id
                ));
            }
            if !row.exclusion_reason.trim().is_empty() {
                errors.push(format!(
                    "row `{}` is covered but has exclusion_reason",
                    row.report_id
                ));
            }
        }
        (_, ReportSchemaCoverageStatus::Missing) => {
            if row.coverage_requirement == ReportSchemaCoverageRequirement::Required {
                missing_evidence.push("typed_serde_round_trip_evidence".to_owned());
                missing_evidence.push("compact_json_shape_snapshot".to_owned());
                errors.push(format!(
                    "row `{}` is a required public report but remains uncovered",
                    row.report_id
                ));
            }
            if !row.evidence_test.trim().is_empty() || !row.snapshot_path.trim().is_empty() {
                errors.push(format!(
                    "row `{}` is missing but already names evidence",
                    row.report_id
                ));
            }
        }
    }
}

fn validate_claim_effect(
    row: &ReportSchemaInventoryRow,
    missing_evidence: &mut Vec<String>,
    errors: &mut Vec<String>,
) {
    match row.coverage_requirement {
        ReportSchemaCoverageRequirement::Required => {
            if matches!(
                row.claim_effect,
                ReportSchemaClaimEffect::ProductEvidenceNone
                    | ReportSchemaClaimEffect::InternalOnly
            ) {
                missing_evidence.push("valid_claim_effect".to_owned());
                errors.push(format!(
                    "row `{}` is required but claim_effect is not public-facing",
                    row.report_id
                ));
            }
        }
        ReportSchemaCoverageRequirement::AdvisoryOnly => {
            if row.claim_effect != ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange {
                missing_evidence.push("valid_claim_effect".to_owned());
                errors.push(format!(
                    "row `{}` is advisory_only but claim_effect is not advisory_only_no_public_readiness_change",
                    row.report_id
                ));
            }
        }
        ReportSchemaCoverageRequirement::PermissionedOnly => {
            if row.claim_effect != ReportSchemaClaimEffect::ProductEvidenceNone {
                missing_evidence.push("valid_claim_effect".to_owned());
                errors.push(format!(
                    "row `{}` is permissioned_only but claim_effect is not product_evidence_none",
                    row.report_id
                ));
            }
        }
        ReportSchemaCoverageRequirement::Excluded => {
            if row.claim_effect != ReportSchemaClaimEffect::InternalOnly {
                missing_evidence.push("valid_claim_effect".to_owned());
                errors.push(format!(
                    "row `{}` is excluded but claim_effect is not internal_only",
                    row.report_id
                ));
            }
        }
    }
}

fn is_valid_rust_test_name(value: &str) -> bool {
    let trimmed = value.trim();
    let Some(first) = trimmed.chars().next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && !trimmed.ends_with('_')
        && !trimmed.contains("__")
        && trimmed.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
}

fn validate_non_empty(
    row: &ReportSchemaInventoryRow,
    field: &str,
    value: &str,
    errors: &mut Vec<String>,
) {
    if value.trim().is_empty() {
        errors.push(format!("row `{}` missing {field}", row.report_id));
    }
}

fn validate_safe_relative_path(
    row: &ReportSchemaInventoryRow,
    field: &str,
    value: &str,
    errors: &mut Vec<String>,
) {
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        errors.push(format!(
            "row `{}` {field} must be a safe relative path, got `{value}`",
            row.report_id
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn covered_required_row(
    report_id: &str,
    module_path: &str,
    rust_type: &str,
    producer: &str,
    downstream_consumer: &str,
    evidence_test: &str,
    snapshot_path: &str,
    claim_effect: ReportSchemaClaimEffect,
) -> ReportSchemaInventoryRow {
    ReportSchemaInventoryRow {
        report_id: report_id.to_owned(),
        module_path: module_path.to_owned(),
        rust_type: rust_type.to_owned(),
        producer: producer.to_owned(),
        downstream_consumer: downstream_consumer.to_owned(),
        coverage_requirement: ReportSchemaCoverageRequirement::Required,
        coverage_status: ReportSchemaCoverageStatus::Covered,
        evidence_test: evidence_test.to_owned(),
        snapshot_path: snapshot_path.to_owned(),
        exclusion_reason: String::new(),
        claim_effect,
    }
}

fn covered_advisory_row(
    report_id: &str,
    module_path: &str,
    rust_type: &str,
    producer: &str,
    downstream_consumer: &str,
    evidence_test: &str,
    snapshot_path: &str,
) -> ReportSchemaInventoryRow {
    ReportSchemaInventoryRow {
        coverage_requirement: ReportSchemaCoverageRequirement::AdvisoryOnly,
        claim_effect: ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange,
        ..covered_required_row(
            report_id,
            module_path,
            rust_type,
            producer,
            downstream_consumer,
            evidence_test,
            snapshot_path,
            ReportSchemaClaimEffect::AdvisoryOnlyNoPublicReadinessChange,
        )
    }
}

fn covered_permissioned_row(
    report_id: &str,
    module_path: &str,
    rust_type: &str,
    producer: &str,
    downstream_consumer: &str,
    evidence_test: &str,
    snapshot_path: &str,
) -> ReportSchemaInventoryRow {
    ReportSchemaInventoryRow {
        coverage_requirement: ReportSchemaCoverageRequirement::PermissionedOnly,
        claim_effect: ReportSchemaClaimEffect::ProductEvidenceNone,
        ..covered_required_row(
            report_id,
            module_path,
            rust_type,
            producer,
            downstream_consumer,
            evidence_test,
            snapshot_path,
            ReportSchemaClaimEffect::ProductEvidenceNone,
        )
    }
}

fn excluded_row(
    report_id: &str,
    module_path: &str,
    rust_type: &str,
    producer: &str,
    downstream_consumer: &str,
    exclusion_reason: &str,
) -> ReportSchemaInventoryRow {
    ReportSchemaInventoryRow {
        report_id: report_id.to_owned(),
        module_path: module_path.to_owned(),
        rust_type: rust_type.to_owned(),
        producer: producer.to_owned(),
        downstream_consumer: downstream_consumer.to_owned(),
        coverage_requirement: ReportSchemaCoverageRequirement::Excluded,
        coverage_status: ReportSchemaCoverageStatus::Excluded,
        evidence_test: String::new(),
        snapshot_path: String::new(),
        exclusion_reason: exclusion_reason.to_owned(),
        claim_effect: ReportSchemaClaimEffect::InternalOnly,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Result, bail};
    use serde_json::json;

    fn row_result<'a>(
        report: &'a ReportSchemaInventoryReport,
        report_id: &str,
    ) -> &'a ReportSchemaInventoryRowResult {
        report
            .row_results
            .iter()
            .find(|row| row.report_id == report_id)
            .expect("row result should exist")
    }

    #[test]
    fn default_report_schema_inventory_is_valid() {
        let inventory = current_report_schema_inventory();
        let report = validate_report_schema_inventory(&inventory);

        assert!(report.valid);
        assert_eq!(
            report.product_evidence_claim,
            REPORT_SCHEMA_INVENTORY_PRODUCT_EVIDENCE_CLAIM
        );
        assert_eq!(
            report.reproduction_command,
            REPORT_SCHEMA_INVENTORY_REPRODUCTION_COMMAND
        );
        assert!(
            report.errors.is_empty(),
            "default inventory should be valid: {:?}",
            report.errors
        );
        assert_eq!(
            report.schema_version,
            REPORT_SCHEMA_INVENTORY_SCHEMA_VERSION
        );
        assert_eq!(report.total_rows, 13);
        assert_eq!(report.required_rows, 6);
        assert_eq!(report.advisory_only_rows, 5);
        assert_eq!(report.permissioned_only_rows, 1);
        assert_eq!(report.excluded_rows, 1);
        assert_eq!(report.covered_rows, 12);
        assert_eq!(report.missing_rows, 0);
        assert!(
            report
                .report_ids
                .contains(&"swarm_operator_report".to_owned())
        );
        assert_eq!(report.row_results.len(), report.total_rows);
        assert_eq!(
            report.row_results[0].report_id,
            "authoritative_lane_decision"
        );
        assert!(report.uncovered_required_report_ids.is_empty());
        assert!(report.row_results.iter().all(|row| row.errors.is_empty()));
    }

    #[test]
    fn duplicate_report_ids_fail() {
        let mut inventory = current_report_schema_inventory();
        inventory.rows[1].report_id = inventory.rows[0].report_id.clone();

        let report = validate_report_schema_inventory(&inventory);

        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("duplicate report_id")),
            "{:?}",
            report.errors
        );
    }

    #[test]
    fn covered_rows_require_snapshot_and_test_evidence() {
        let mut inventory = current_report_schema_inventory();
        inventory.rows[0].evidence_test.clear();
        inventory.rows[0].snapshot_path.clear();
        let report_id = inventory.rows[0].report_id.clone();

        let report = validate_report_schema_inventory(&inventory);
        let result = row_result(&report, &report_id);

        assert!(!report.valid);
        assert!(
            result
                .missing_evidence
                .contains(&"typed_serde_round_trip_evidence".to_owned()),
            "{result:?}"
        );
        assert!(
            result
                .missing_evidence
                .contains(&"compact_json_shape_snapshot".to_owned()),
            "{result:?}"
        );
        assert!(
            result
                .missing_evidence
                .contains(&"valid_evidence_test_name".to_owned()),
            "{result:?}"
        );
    }

    #[test]
    fn invalid_evidence_test_name_fails() {
        let mut inventory = current_report_schema_inventory();
        inventory.rows[0].evidence_test = "Bad-Test-Name".to_owned();
        let report_id = inventory.rows[0].report_id.clone();

        let report = validate_report_schema_inventory(&inventory);
        let result = row_result(&report, &report_id);

        assert!(!report.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains("valid rust test name")),
            "{result:?}"
        );
    }

    #[test]
    fn invalid_claim_effect_fails() {
        let mut inventory = current_report_schema_inventory();
        inventory.rows[0].claim_effect = ReportSchemaClaimEffect::ExistingReleaseGateInput;
        let report_id = inventory.rows[0].report_id.clone();

        let report = validate_report_schema_inventory(&inventory);
        let result = row_result(&report, &report_id);

        assert!(!report.valid);
        assert!(
            result
                .missing_evidence
                .contains(&"valid_claim_effect".to_owned()),
            "{result:?}"
        );
    }

    #[test]
    fn unsafe_snapshot_path_fails() {
        let mut inventory = current_report_schema_inventory();
        inventory.rows[0].snapshot_path = "../outside.snap".to_owned();

        let report = validate_report_schema_inventory(&inventory);

        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("snapshot_path must be a safe relative path")),
            "{:?}",
            report.errors
        );
    }

    #[test]
    fn excluded_rows_require_reason() {
        let mut inventory = current_report_schema_inventory();
        let row = inventory
            .rows
            .iter_mut()
            .find(|row| row.coverage_requirement == ReportSchemaCoverageRequirement::Excluded)
            .expect("fixture includes an excluded helper row");
        row.exclusion_reason.clear();

        let report = validate_report_schema_inventory(&inventory);

        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("missing exclusion_reason")),
            "{:?}",
            report.errors
        );
    }

    #[test]
    fn required_missing_rows_fail_with_row_context() {
        let mut inventory = current_report_schema_inventory();
        let row = inventory
            .rows
            .iter_mut()
            .find(|row| row.coverage_requirement == ReportSchemaCoverageRequirement::Required)
            .expect("fixture includes a required row");
        row.coverage_status = ReportSchemaCoverageStatus::Missing;
        row.evidence_test.clear();
        row.snapshot_path.clear();
        let report_id = row.report_id.clone();

        let report = validate_report_schema_inventory(&inventory);
        let result = row_result(&report, &report_id);

        assert!(!report.valid);
        assert_eq!(report.missing_rows, 1);
        assert_eq!(
            result.module_path,
            "crates/ffs-harness/src/swarm_operator_report.rs"
        );
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains("required public report")),
            "{result:?}"
        );
        assert_eq!(
            report.uncovered_required_report_ids,
            vec!["swarm_operator_report"]
        );
    }

    #[test]
    fn report_results_are_deterministically_ordered() {
        let mut inventory = current_report_schema_inventory();
        inventory.rows.reverse();

        let report = validate_report_schema_inventory(&inventory);
        let row_ids = report
            .row_results
            .iter()
            .map(|row| row.report_id.as_str())
            .collect::<Vec<_>>();
        let mut sorted_ids = row_ids.clone();
        sorted_ids.sort_unstable();

        assert_eq!(row_ids, sorted_ids);
        assert_eq!(report.report_ids, sorted_ids);
    }

    #[test]
    fn report_markdown_summary_names_claim_and_uncovered_rows() {
        let mut inventory = current_report_schema_inventory();
        let row = inventory
            .rows
            .iter_mut()
            .find(|row| row.report_id == "swarm_operator_report")
            .expect("fixture includes swarm operator report row");
        row.coverage_status = ReportSchemaCoverageStatus::Missing;
        row.evidence_test.clear();
        row.snapshot_path.clear();

        let report = validate_report_schema_inventory(&inventory);
        let markdown = render_report_schema_inventory_markdown(&report);

        assert!(markdown.contains("# Report Schema Inventory"));
        assert!(markdown.contains("Product evidence claim: `none`"));
        assert!(markdown.contains("`swarm_operator_report`"));
        assert!(fail_on_report_schema_inventory_errors(&report).is_err());
    }

    #[test]
    fn report_schema_inventory_shape() -> Result<()> {
        let inventory = current_report_schema_inventory();
        let report = validate_report_schema_inventory(&inventory);
        if !report.errors.is_empty() {
            bail!("default inventory has errors: {:?}", report.errors);
        }

        let encoded = serde_json::to_string(&inventory)?;
        let decoded: ReportSchemaInventory = serde_json::from_str(&encoded)?;
        assert_eq!(decoded, inventory);

        let shape = json!({
            "schema_version": inventory.schema_version,
            "inventory_id": inventory.inventory_id,
            "product_evidence_claim": report.product_evidence_claim,
            "reproduction_command": report.reproduction_command,
            "report_valid": report.valid,
            "counts": {
                "total_rows": report.total_rows,
                "required_rows": report.required_rows,
                "advisory_only_rows": report.advisory_only_rows,
                "permissioned_only_rows": report.permissioned_only_rows,
                "covered_rows": report.covered_rows,
                "missing_rows": report.missing_rows,
                "excluded_rows": report.excluded_rows,
            },
            "uncovered_required_report_ids": report.uncovered_required_report_ids,
            "first_row": {
                "report_id": inventory.rows[0].report_id,
                "module_path": inventory.rows[0].module_path,
                "rust_type": inventory.rows[0].rust_type,
                "producer": inventory.rows[0].producer,
                "downstream_consumer": inventory.rows[0].downstream_consumer,
                "coverage_requirement": inventory.rows[0].coverage_requirement,
                "coverage_status": inventory.rows[0].coverage_status,
                "evidence_test": inventory.rows[0].evidence_test,
                "snapshot_path": inventory.rows[0].snapshot_path,
                "claim_effect": inventory.rows[0].claim_effect,
            },
            "first_row_result": {
                "report_id": report.row_results[0].report_id,
                "coverage_requirement": report.row_results[0].coverage_requirement,
                "coverage_status": report.row_results[0].coverage_status,
                "module_path": report.row_results[0].module_path,
                "rust_type": report.row_results[0].rust_type,
                "downstream_consumer": report.row_results[0].downstream_consumer,
                "evidence_test": report.row_results[0].evidence_test,
                "snapshot_path": report.row_results[0].snapshot_path,
                "claim_effect": report.row_results[0].claim_effect,
                "missing_evidence": report.row_results[0].missing_evidence,
                "errors": report.row_results[0].errors,
            },
            "required_report_ids": inventory
                .rows
                .iter()
                .filter(|row| row.coverage_requirement == ReportSchemaCoverageRequirement::Required)
                .map(|row| row.report_id.as_str())
                .collect::<Vec<_>>(),
            "excluded_report_ids": inventory
                .rows
                .iter()
                .filter(|row| row.coverage_status == ReportSchemaCoverageStatus::Excluded)
                .map(|row| row.report_id.as_str())
                .collect::<Vec<_>>(),
            "permissioned_only_report_ids": inventory
                .rows
                .iter()
                .filter(|row| {
                    row.coverage_requirement == ReportSchemaCoverageRequirement::PermissionedOnly
                })
                .map(|row| row.report_id.as_str())
                .collect::<Vec<_>>(),
        });
        let json = serde_json::to_string_pretty(&shape)?;

        insta::assert_snapshot!("report_schema_inventory_shape", json);
        Ok(())
    }
}
