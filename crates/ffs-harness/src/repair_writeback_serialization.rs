#![allow(
    clippy::module_name_repetitions,
    clippy::struct_excessive_bools,
    clippy::too_many_lines
)]
#![forbid(unsafe_code)]

//! Executable repair/writeback serialization contract for `bd-rchk0.1.1`.
//!
//! The live read-write mount path intentionally rejects mutating background
//! repair. This module keeps that policy precise: it validates the state
//! machine, rejection cases, risk decision, evidence fields, and dry-run
//! scenarios that must hold until repair writeback shares one serializer with
//! client writes.

use crate::artifact_manifest::{
    ArtifactCategory, ArtifactEntry, ArtifactManifest, EnvironmentFingerprint, ManifestBuilder,
    ScenarioResult,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub const REPAIR_WRITEBACK_SERIALIZATION_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_REPAIR_WRITEBACK_CONTRACT_PATH: &str =
    "docs/repair-writeback-serialization-contract.json";

const REQUIRED_STATES: [&str; 10] = [
    "detection_only_scrub",
    "repair_planning",
    "repair_lease_held",
    "client_write_in_flight",
    "fsync_boundary",
    "repair_writeback_blocked_rw",
    "repair_writeback_staged",
    "repair_symbol_refresh",
    "writeback_failure",
    "cleanup_complete",
];

const REQUIRED_INVARIANTS: [&str; 8] = [
    "I1_snapshot_epoch_cut",
    "I2_single_writer_serializer",
    "I3_dirty_cache_before_repair",
    "I4_fsync_fsyncdir_boundary",
    "I5_repair_lease_exclusive",
    "I6_repair_symbol_freshness",
    "I7_cancel_cleanup_no_partial_mutation",
    "I8_failure_refuses_symbol_refresh",
];

const REQUIRED_EVIDENCE_FIELDS: [&str; 12] = [
    "operation_id",
    "scenario_id",
    "snapshot_epoch",
    "lease_id",
    "repair_symbol_version",
    "expected_state",
    "observed_state",
    "error_class",
    "artifact_paths",
    "cleanup_status",
    "reproduction_command",
    "follow_up_bead",
];

const REQUIRED_REJECTION_CASES: [&str; 7] = [
    "rw_repair_serializer_missing",
    "client_write_in_flight",
    "dirty_cache_not_fsynced",
    "stale_repair_symbol",
    "lease_expired_or_missing",
    "writeback_failure_no_refresh",
    "cancelled_repair_cleanup",
];

const REQUIRED_COVERAGE_TAGS: [&str; 9] = [
    "fail_closed_rw_repair",
    "mvcc_snapshot_boundary",
    "dirty_cache_flush",
    "fsync_fsyncdir_boundary",
    "repair_lease",
    "stale_repair_symbol",
    "cancellation",
    "writeback_failure",
    "halfway_recovery_failure",
];

const REQUIRED_CONSUMERS: [&str; 4] = [
    "operator_proof_bundle",
    "release_gate_evaluator",
    "operational_readiness_report",
    "mounted_write_matrix",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairWritebackSerializationContract {
    pub schema_version: u32,
    pub contract_id: String,
    pub bead_id: String,
    pub current_policy: CurrentRepairWritebackPolicy,
    pub artifact_consumers: Vec<String>,
    pub required_evidence_fields: Vec<String>,
    pub invariants: Vec<SerializationInvariant>,
    pub states: Vec<SerializationState>,
    pub transitions: Vec<SerializationTransition>,
    pub rejection_cases: Vec<SerializationRejectionCase>,
    pub scenarios: Vec<SerializationScenario>,
    pub risk_decision: SerializationRiskDecision,
    pub follow_up_beads: Vec<SerializationFollowUp>,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurrentRepairWritebackPolicy {
    pub policy_id: String,
    pub read_write_repair_state: String,
    pub mutating_rw_repair_enabled: bool,
    pub serialization_point: String,
    pub fail_closed_error_class: String,
    pub docs_wording_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializationInvariant {
    pub invariant_id: String,
    pub description: String,
    pub required_log_fields: Vec<String>,
    pub failure_error_class: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializationState {
    pub state_id: String,
    pub description: String,
    pub client_writes_allowed: bool,
    pub repair_writeback_allowed: bool,
    pub mutates_image: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializationTransition {
    pub transition_id: String,
    pub from_state: String,
    pub event: String,
    pub to_state: String,
    pub allowed: bool,
    pub mutation_allowed: bool,
    pub error_class: String,
    pub guard: String,
    #[serde(default)]
    pub requires_active_lease: bool,
    #[serde(default)]
    pub requires_fresh_symbol: bool,
    #[serde(default)]
    pub requires_fsync_boundary: bool,
    pub required_evidence_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follow_up_bead: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializationRejectionCase {
    pub case_id: String,
    pub error_class: String,
    pub state: String,
    pub condition: String,
    pub no_mutation_required: bool,
    pub preserves_reproduction_data: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follow_up_bead: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializationScenario {
    pub scenario_id: String,
    pub title: String,
    pub coverage_tags: Vec<String>,
    pub initial_state: String,
    pub events: Vec<String>,
    pub expected_final_state: String,
    pub expected_outcome: String,
    pub expected_error_class: String,
    pub requires_lease: bool,
    pub requires_fsync_boundary: bool,
    pub requires_symbol_freshness: bool,
    pub proves_no_lost_client_write: bool,
    pub preserves_reproduction_data: bool,
    pub artifact_paths: Vec<String>,
    pub reproduction_command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follow_up_bead: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializationRiskDecision {
    pub decision_id: String,
    pub chosen_option: String,
    pub rejected_option: String,
    pub options: Vec<SerializationRiskOption>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializationRiskOption {
    pub option_id: String,
    pub decision: String,
    pub semantic_failure_probability_ppm: u32,
    pub severity_points: u32,
    pub operational_cost_points: u32,
    pub expected_loss_points: u32,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializationFollowUp {
    pub bead_id: String,
    pub reason: String,
    pub required_before_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairWritebackSerializationReport {
    pub schema_version: u32,
    pub contract_id: String,
    pub bead_id: String,
    pub valid: bool,
    pub state_count: usize,
    pub transition_count: usize,
    pub rejection_case_count: usize,
    pub scenario_count: usize,
    pub required_states: Vec<String>,
    pub missing_required_states: Vec<String>,
    pub missing_required_invariants: Vec<String>,
    pub missing_required_evidence_fields: Vec<String>,
    pub missing_required_rejection_cases: Vec<String>,
    pub missing_required_coverage_tags: Vec<String>,
    pub missing_required_consumers: Vec<String>,
    pub duplicate_ids: Vec<String>,
    pub transition_evaluations: Vec<TransitionEvaluation>,
    pub scenario_reports: Vec<SerializationScenarioReport>,
    pub risk_report: SerializationRiskReport,
    pub artifact_root: String,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionEvaluation {
    pub from_state: String,
    pub event: String,
    pub to_state: String,
    pub allowed: bool,
    pub mutation_allowed: bool,
    pub error_class: String,
    pub required_evidence_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follow_up_bead: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializationScenarioReport {
    pub scenario_id: String,
    pub expected_outcome: String,
    pub expected_error_class: String,
    pub final_state: String,
    pub coverage_tags: Vec<String>,
    pub artifact_paths: Vec<String>,
    pub proves_no_lost_client_write: bool,
    pub preserves_reproduction_data: bool,
    pub valid: bool,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializationRiskReport {
    pub decision_id: String,
    pub chosen_option: String,
    pub rejected_option: String,
    pub chosen_expected_loss_points: u32,
    pub rejected_expected_loss_points: u32,
    pub fail_closed_is_lower_loss: bool,
    pub valid: bool,
    pub diagnostics: Vec<String>,
}

pub fn load_repair_writeback_serialization_contract(
    path: &Path,
) -> Result<RepairWritebackSerializationContract> {
    let text = fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read repair/writeback contract {}",
            path.display()
        )
    })?;
    serde_json::from_str(&text)
        .with_context(|| format!("invalid repair/writeback contract JSON {}", path.display()))
}

#[must_use]
pub fn validate_repair_writeback_serialization_contract(
    contract: &RepairWritebackSerializationContract,
    artifact_root: &str,
) -> RepairWritebackSerializationReport {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    validate_top_level(contract, &mut errors);
    let duplicate_ids = collect_duplicate_ids(contract);
    errors.extend(
        duplicate_ids
            .iter()
            .map(|id| format!("duplicate contract id {id}")),
    );

    let state_ids = collect_state_ids(contract);
    let invariant_ids = collect_invariant_ids(contract);
    let rejection_case_ids = collect_rejection_case_ids(contract);
    let coverage_tags = collect_coverage_tags(contract);
    let consumers = collect_strings(&contract.artifact_consumers);
    let evidence_fields = collect_strings(&contract.required_evidence_fields);

    let missing_required_states = missing_required(&state_ids, &REQUIRED_STATES);
    let missing_required_invariants = missing_required(&invariant_ids, &REQUIRED_INVARIANTS);
    let missing_required_evidence_fields =
        missing_required(&evidence_fields, &REQUIRED_EVIDENCE_FIELDS);
    let missing_required_rejection_cases =
        missing_required(&rejection_case_ids, &REQUIRED_REJECTION_CASES);
    let missing_required_coverage_tags = missing_required(&coverage_tags, &REQUIRED_COVERAGE_TAGS);
    let missing_required_consumers = missing_required(&consumers, &REQUIRED_CONSUMERS);

    extend_missing(
        &mut errors,
        "missing required state",
        &missing_required_states,
    );
    extend_missing(
        &mut errors,
        "missing required invariant",
        &missing_required_invariants,
    );
    extend_missing(
        &mut errors,
        "missing required evidence field",
        &missing_required_evidence_fields,
    );
    extend_missing(
        &mut errors,
        "missing required rejection case",
        &missing_required_rejection_cases,
    );
    extend_missing(
        &mut errors,
        "missing required coverage tag",
        &missing_required_coverage_tags,
    );
    extend_missing(
        &mut errors,
        "missing required artifact consumer",
        &missing_required_consumers,
    );

    validate_states(contract, &state_ids, &mut errors);
    validate_transitions(contract, &state_ids, &evidence_fields, &mut errors);
    validate_rejection_cases(contract, &mut errors);

    let scenario_reports = validate_scenarios(contract, &state_ids, artifact_root, &mut errors);
    let risk_report = validate_risk_decision(contract, &mut errors);
    if !risk_report.fail_closed_is_lower_loss {
        warnings
            .push("fail-closed policy is not lower expected loss than rejected path".to_owned());
    }

    let transition_evaluations = required_transition_evaluations(contract);

    RepairWritebackSerializationReport {
        schema_version: contract.schema_version,
        contract_id: contract.contract_id.clone(),
        bead_id: contract.bead_id.clone(),
        valid: errors.is_empty(),
        state_count: contract.states.len(),
        transition_count: contract.transitions.len(),
        rejection_case_count: contract.rejection_cases.len(),
        scenario_count: contract.scenarios.len(),
        required_states: REQUIRED_STATES.iter().map(ToString::to_string).collect(),
        missing_required_states,
        missing_required_invariants,
        missing_required_evidence_fields,
        missing_required_rejection_cases,
        missing_required_coverage_tags,
        missing_required_consumers,
        duplicate_ids,
        transition_evaluations,
        scenario_reports,
        risk_report,
        artifact_root: artifact_root.to_owned(),
        errors,
        warnings,
        reproduction_command: contract.reproduction_command.clone(),
    }
}

#[must_use]
pub fn evaluate_transition(
    contract: &RepairWritebackSerializationContract,
    from_state: &str,
    event: &str,
) -> TransitionEvaluation {
    contract
        .transitions
        .iter()
        .find(|transition| transition.from_state == from_state && transition.event == event)
        .map_or_else(
            || TransitionEvaluation {
                from_state: from_state.to_owned(),
                event: event.to_owned(),
                to_state: from_state.to_owned(),
                allowed: false,
                mutation_allowed: false,
                error_class: "transition_missing".to_owned(),
                required_evidence_fields: REQUIRED_EVIDENCE_FIELDS
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                follow_up_bead: Some("bd-rchk0.1.1.1".to_owned()),
            },
            |transition| TransitionEvaluation {
                from_state: transition.from_state.clone(),
                event: transition.event.clone(),
                to_state: transition.to_state.clone(),
                allowed: transition.allowed,
                mutation_allowed: transition.mutation_allowed,
                error_class: transition.error_class.clone(),
                required_evidence_fields: transition.required_evidence_fields.clone(),
                follow_up_bead: transition.follow_up_bead.clone(),
            },
        )
}

#[must_use]
pub fn render_repair_writeback_serialization_markdown(
    report: &RepairWritebackSerializationReport,
) -> String {
    let mut out = String::new();
    writeln!(&mut out, "# Repair Writeback Serialization Contract").ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "- Contract: `{}`", report.contract_id).ok();
    writeln!(&mut out, "- Bead: `{}`", report.bead_id).ok();
    writeln!(&mut out, "- Valid: `{}`", report.valid).ok();
    writeln!(
        &mut out,
        "- Counts: states={} transitions={} rejection_cases={} scenarios={}",
        report.state_count,
        report.transition_count,
        report.rejection_case_count,
        report.scenario_count
    )
    .ok();
    writeln!(
        &mut out,
        "- Risk decision: `{}` chosen_loss={} rejected_loss={} lower_loss={}",
        report.risk_report.chosen_option,
        report.risk_report.chosen_expected_loss_points,
        report.risk_report.rejected_expected_loss_points,
        report.risk_report.fail_closed_is_lower_loss
    )
    .ok();
    writeln!(&mut out, "- Reproduce: `{}`", report.reproduction_command).ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "## Required Transition Checks").ok();
    for transition in &report.transition_evaluations {
        writeln!(
            &mut out,
            "- `{}` + `{}` -> `{}` allowed={} mutation={} error_class=`{}`",
            transition.from_state,
            transition.event,
            transition.to_state,
            transition.allowed,
            transition.mutation_allowed,
            transition.error_class
        )
        .ok();
    }
    writeln!(&mut out).ok();
    writeln!(&mut out, "## Scenarios").ok();
    for scenario in &report.scenario_reports {
        writeln!(
            &mut out,
            "- `{}` outcome=`{}` error_class=`{}` final_state=`{}` no_lost_write={} repro_preserved={}",
            scenario.scenario_id,
            scenario.expected_outcome,
            scenario.expected_error_class,
            scenario.final_state,
            scenario.proves_no_lost_client_write,
            scenario.preserves_reproduction_data
        )
        .ok();
    }
    if !report.errors.is_empty() {
        writeln!(&mut out).ok();
        writeln!(&mut out, "## Errors").ok();
        for error in &report.errors {
            writeln!(&mut out, "- {error}").ok();
        }
    }
    out
}

#[must_use]
pub fn build_repair_writeback_serialization_sample_artifact_manifest(
    contract: &RepairWritebackSerializationContract,
    artifact_root: &str,
    report: &RepairWritebackSerializationReport,
) -> ArtifactManifest {
    let mut builder = ManifestBuilder::new(
        "bd-rchk0.1.1-repair-writeback-serialization",
        "repair_writeback_serialization",
        "2026-05-03T00:00:00Z",
    )
    .bead_id("bd-rchk0.1.1")
    .git_context("dry-run", "main", true)
    .environment(EnvironmentFingerprint {
        hostname: "dry-run".to_owned(),
        cpu_model: "contract-validator".to_owned(),
        cpu_count: 64,
        memory_gib: 256,
        kernel: "linux-fuse-contract".to_owned(),
        rustc_version: "nightly-rust-2024".to_owned(),
        cargo_version: Some("cargo-2024".to_owned()),
    });

    for scenario in &report.scenario_reports {
        let detail = format!(
            "{}:{}:{}",
            scenario.final_state, scenario.expected_outcome, scenario.expected_error_class
        );
        builder = builder.scenario(
            &scenario.scenario_id,
            if scenario.valid {
                ScenarioResult::Pass
            } else {
                ScenarioResult::Fail
            },
            Some(&detail),
            0.01,
        );
    }

    for path in [
        "repair_writeback_serialization_report.json",
        "repair_writeback_serialization_summary.md",
        "repair_writeback_serialization_repro.log",
    ] {
        let mut metadata = BTreeMap::new();
        metadata.insert("contract_id".to_owned(), contract.contract_id.clone());
        metadata.insert(
            "proof_bundle_lane".to_owned(),
            "repair_rw_writeback".to_owned(),
        );
        metadata.insert(
            "release_gate_feature".to_owned(),
            "repair.rw.writeback".to_owned(),
        );
        let extension = Path::new(path).extension();
        let is_markdown = extension.is_some_and(|ext| ext.eq_ignore_ascii_case("md"));
        let is_log = extension.is_some_and(|ext| ext.eq_ignore_ascii_case("log"));
        builder = builder.artifact(ArtifactEntry {
            path: format!("{artifact_root}/{path}"),
            category: if is_markdown {
                ArtifactCategory::SummaryReport
            } else {
                ArtifactCategory::ProofArtifact
            },
            content_type: Some(if is_markdown {
                "text/markdown".to_owned()
            } else if is_log {
                "text/plain".to_owned()
            } else {
                "application/json".to_owned()
            }),
            size_bytes: 1024,
            sha256: None,
            redacted: false,
            metadata,
        });
    }

    builder.duration_secs(0.5).build()
}

pub fn fail_on_repair_writeback_serialization_errors(
    report: &RepairWritebackSerializationReport,
) -> Result<()> {
    if report.valid {
        Ok(())
    } else {
        for error in &report.errors {
            eprintln!("repair/writeback serialization error: {error}");
        }
        bail!(
            "repair/writeback serialization validation failed with {} error(s)",
            report.errors.len()
        )
    }
}

fn validate_top_level(contract: &RepairWritebackSerializationContract, errors: &mut Vec<String>) {
    if contract.schema_version != REPAIR_WRITEBACK_SERIALIZATION_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version must be {REPAIR_WRITEBACK_SERIALIZATION_SCHEMA_VERSION}, got {}",
            contract.schema_version
        ));
    }
    if contract.bead_id != "bd-rchk0.1.1" {
        errors.push(format!(
            "bead_id must be bd-rchk0.1.1, got {}",
            contract.bead_id
        ));
    }
    if contract.current_policy.mutating_rw_repair_enabled {
        errors.push("mutating read-write repair must remain disabled for this contract".to_owned());
    }
    if contract.current_policy.read_write_repair_state != "fail_closed" {
        errors.push(format!(
            "read_write_repair_state must be fail_closed, got {}",
            contract.current_policy.read_write_repair_state
        ));
    }
    if contract.current_policy.fail_closed_error_class != "rw_repair_serialization_missing" {
        errors.push(format!(
            "fail_closed_error_class must be rw_repair_serialization_missing, got {}",
            contract.current_policy.fail_closed_error_class
        ));
    }
    if contract.reproduction_command.is_empty() {
        errors.push("reproduction_command is required".to_owned());
    }
}

fn validate_states(
    contract: &RepairWritebackSerializationContract,
    state_ids: &BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    for state in &contract.states {
        if state.state_id == "repair_writeback_staged" && !state.repair_writeback_allowed {
            errors.push("repair_writeback_staged must allow repair writeback".to_owned());
        }
        if state.state_id == "repair_writeback_blocked_rw" && state.mutates_image {
            errors.push("repair_writeback_blocked_rw must not mutate the image".to_owned());
        }
    }
    for transition in &contract.transitions {
        if !state_ids.contains(&transition.from_state) {
            errors.push(format!(
                "{} references unknown from_state {}",
                transition.transition_id, transition.from_state
            ));
        }
        if !state_ids.contains(&transition.to_state) {
            errors.push(format!(
                "{} references unknown to_state {}",
                transition.transition_id, transition.to_state
            ));
        }
    }
}

fn validate_transitions(
    contract: &RepairWritebackSerializationContract,
    state_ids: &BTreeSet<String>,
    evidence_fields: &BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    let _ = state_ids;
    for transition in &contract.transitions {
        if !transition.allowed && transition.mutation_allowed {
            errors.push(format!(
                "{} is forbidden but still allows mutation",
                transition.transition_id
            ));
        }
        for field in &transition.required_evidence_fields {
            if !evidence_fields.contains(field) {
                errors.push(format!(
                    "{} requires undeclared evidence field {}",
                    transition.transition_id, field
                ));
            }
        }
        if !transition.allowed
            && transition.error_class == "none"
            && transition.event != "detect_only_scrub"
        {
            errors.push(format!(
                "{} is forbidden but does not name an error class",
                transition.transition_id
            ));
        }
    }

    let rw_block = evaluate_transition(
        contract,
        "client_write_in_flight",
        "repair_writeback_requested",
    );
    if rw_block.allowed
        || rw_block.mutation_allowed
        || rw_block.error_class != "rw_repair_serialization_missing"
        || rw_block.to_state != "repair_writeback_blocked_rw"
    {
        errors.push(
            "client-write plus repair-writeback transition must fail closed without mutation"
                .to_owned(),
        );
    }

    let flush = evaluate_transition(contract, "client_write_in_flight", "flush_observed");
    if flush.allowed || flush.mutation_allowed || flush.error_class != "flush_non_durable" {
        errors.push("flush transition must be non-durable and must not publish repair".to_owned());
    }
}

fn validate_rejection_cases(
    contract: &RepairWritebackSerializationContract,
    errors: &mut Vec<String>,
) {
    for case in &contract.rejection_cases {
        if !case.no_mutation_required {
            errors.push(format!("{} must require no mutation", case.case_id));
        }
        if !case.preserves_reproduction_data {
            errors.push(format!("{} must preserve reproduction data", case.case_id));
        }
        if case.follow_up_bead.is_none() && case.case_id != "rw_repair_serializer_missing" {
            errors.push(format!("{} must link a follow-up bead", case.case_id));
        }
    }
}

fn validate_scenarios(
    contract: &RepairWritebackSerializationContract,
    state_ids: &BTreeSet<String>,
    artifact_root: &str,
    errors: &mut Vec<String>,
) -> Vec<SerializationScenarioReport> {
    let mut reports = Vec::new();
    for scenario in &contract.scenarios {
        let mut diagnostics = Vec::new();
        if !state_ids.contains(&scenario.initial_state) {
            diagnostics.push(format!("unknown initial_state {}", scenario.initial_state));
        }
        if !state_ids.contains(&scenario.expected_final_state) {
            diagnostics.push(format!(
                "unknown expected_final_state {}",
                scenario.expected_final_state
            ));
        }
        if scenario.events.is_empty() {
            diagnostics.push("scenario must include at least one event".to_owned());
        }
        if !matches!(
            scenario.expected_outcome.as_str(),
            "accepted" | "rejected" | "skipped" | "error"
        ) {
            diagnostics.push(format!(
                "invalid expected_outcome {}",
                scenario.expected_outcome
            ));
        }
        if scenario.expected_outcome != "accepted" && scenario.expected_error_class == "none" {
            diagnostics.push("non-accepted scenario must name an error class".to_owned());
        }
        if scenario.expected_outcome == "rejected" && !scenario.proves_no_lost_client_write {
            diagnostics.push("rejected scenario must prove no lost client write".to_owned());
        }
        if (scenario.expected_outcome == "rejected" || scenario.expected_outcome == "error")
            && !scenario.preserves_reproduction_data
        {
            diagnostics.push("failure scenario must preserve reproduction data".to_owned());
        }
        if scenario.artifact_paths.is_empty() {
            diagnostics.push("scenario must list artifact paths".to_owned());
        }
        for path in &scenario.artifact_paths {
            if !is_safe_relative_artifact_path(path) {
                diagnostics.push(format!("unsafe artifact path {path}"));
            }
            if !path.starts_with(artifact_root) {
                diagnostics.push(format!(
                    "artifact path {path} must live under artifact root {artifact_root}"
                ));
            }
        }
        if scenario.reproduction_command.is_empty() {
            diagnostics.push("scenario must include reproduction_command".to_owned());
        }
        if scenario
            .coverage_tags
            .iter()
            .any(|tag| tag == "fail_closed_rw_repair")
            && scenario.follow_up_bead.is_none()
        {
            diagnostics.push(
                "fail-closed RW repair scenario must link the serializer follow-up".to_owned(),
            );
        }

        errors.extend(
            diagnostics
                .iter()
                .map(|diagnostic| format!("{}: {diagnostic}", scenario.scenario_id)),
        );

        reports.push(SerializationScenarioReport {
            scenario_id: scenario.scenario_id.clone(),
            expected_outcome: scenario.expected_outcome.clone(),
            expected_error_class: scenario.expected_error_class.clone(),
            final_state: scenario.expected_final_state.clone(),
            coverage_tags: scenario.coverage_tags.clone(),
            artifact_paths: scenario.artifact_paths.clone(),
            proves_no_lost_client_write: scenario.proves_no_lost_client_write,
            preserves_reproduction_data: scenario.preserves_reproduction_data,
            valid: diagnostics.is_empty(),
            diagnostics,
        });
    }
    reports
}

fn validate_risk_decision(
    contract: &RepairWritebackSerializationContract,
    errors: &mut Vec<String>,
) -> SerializationRiskReport {
    let chosen = contract
        .risk_decision
        .options
        .iter()
        .find(|option| option.option_id == contract.risk_decision.chosen_option);
    let rejected = contract
        .risk_decision
        .options
        .iter()
        .find(|option| option.option_id == contract.risk_decision.rejected_option);

    let mut diagnostics = Vec::new();
    if contract.risk_decision.chosen_option != "fail_closed_until_unified_serializer" {
        diagnostics.push(format!(
            "chosen option must be fail_closed_until_unified_serializer, got {}",
            contract.risk_decision.chosen_option
        ));
    }
    if contract.risk_decision.rejected_option != "enable_rw_repair_without_serializer" {
        diagnostics.push(format!(
            "rejected option must be enable_rw_repair_without_serializer, got {}",
            contract.risk_decision.rejected_option
        ));
    }

    let chosen_loss = chosen.map_or(0, |option| option.expected_loss_points);
    let rejected_loss = rejected.map_or(0, |option| option.expected_loss_points);
    let fail_closed_is_lower_loss = chosen_loss < rejected_loss;
    if chosen.is_none() {
        diagnostics.push("chosen risk option is missing from options".to_owned());
    }
    if rejected.is_none() {
        diagnostics.push("rejected risk option is missing from options".to_owned());
    }
    if !fail_closed_is_lower_loss {
        diagnostics.push(format!(
            "chosen expected loss {chosen_loss} must be lower than rejected {rejected_loss}"
        ));
    }
    for option in &contract.risk_decision.options {
        if option.rationale.is_empty() {
            diagnostics.push(format!("{} is missing rationale", option.option_id));
        }
    }

    errors.extend(diagnostics.iter().cloned());

    SerializationRiskReport {
        decision_id: contract.risk_decision.decision_id.clone(),
        chosen_option: contract.risk_decision.chosen_option.clone(),
        rejected_option: contract.risk_decision.rejected_option.clone(),
        chosen_expected_loss_points: chosen_loss,
        rejected_expected_loss_points: rejected_loss,
        fail_closed_is_lower_loss,
        valid: diagnostics.is_empty(),
        diagnostics,
    }
}

fn required_transition_evaluations(
    contract: &RepairWritebackSerializationContract,
) -> Vec<TransitionEvaluation> {
    [
        ("client_write_in_flight", "repair_writeback_requested"),
        ("client_write_in_flight", "flush_observed"),
        ("repair_lease_held", "repair_symbol_stale"),
        ("repair_lease_held", "fsync_boundary_missing"),
        ("repair_writeback_staged", "writeback_failed"),
        ("repair_writeback_staged", "repair_cancelled"),
    ]
    .into_iter()
    .map(|(from_state, event)| evaluate_transition(contract, from_state, event))
    .collect()
}

fn collect_state_ids(contract: &RepairWritebackSerializationContract) -> BTreeSet<String> {
    contract
        .states
        .iter()
        .map(|state| state.state_id.clone())
        .collect()
}

fn collect_invariant_ids(contract: &RepairWritebackSerializationContract) -> BTreeSet<String> {
    contract
        .invariants
        .iter()
        .map(|invariant| invariant.invariant_id.clone())
        .collect()
}

fn collect_rejection_case_ids(contract: &RepairWritebackSerializationContract) -> BTreeSet<String> {
    contract
        .rejection_cases
        .iter()
        .map(|case| case.case_id.clone())
        .collect()
}

fn collect_coverage_tags(contract: &RepairWritebackSerializationContract) -> BTreeSet<String> {
    contract
        .scenarios
        .iter()
        .flat_map(|scenario| scenario.coverage_tags.iter().cloned())
        .collect()
}

fn collect_strings(values: &[String]) -> BTreeSet<String> {
    values.iter().cloned().collect()
}

fn collect_duplicate_ids(contract: &RepairWritebackSerializationContract) -> Vec<String> {
    let mut duplicates = BTreeSet::new();
    collect_duplicate_namespace(
        contract.states.iter().map(|state| state.state_id.as_str()),
        &mut duplicates,
    );
    collect_duplicate_namespace(
        contract
            .invariants
            .iter()
            .map(|item| item.invariant_id.as_str()),
        &mut duplicates,
    );
    collect_duplicate_namespace(
        contract
            .transitions
            .iter()
            .map(|item| item.transition_id.as_str()),
        &mut duplicates,
    );
    collect_duplicate_namespace(
        contract
            .rejection_cases
            .iter()
            .map(|item| item.case_id.as_str()),
        &mut duplicates,
    );
    collect_duplicate_namespace(
        contract
            .scenarios
            .iter()
            .map(|item| item.scenario_id.as_str()),
        &mut duplicates,
    );
    collect_duplicate_namespace(
        contract
            .follow_up_beads
            .iter()
            .map(|item| item.bead_id.as_str()),
        &mut duplicates,
    );
    duplicates.into_iter().collect()
}

fn collect_duplicate_namespace<'a>(
    ids: impl Iterator<Item = &'a str>,
    duplicates: &mut BTreeSet<String>,
) {
    let mut seen = BTreeSet::new();
    for id in ids {
        if !seen.insert(id.to_owned()) {
            duplicates.insert(id.to_owned());
        }
    }
}

fn missing_required(observed: &BTreeSet<String>, required: &[&str]) -> Vec<String> {
    required
        .iter()
        .filter(|item| !observed.contains(**item))
        .map(|item| (*item).to_owned())
        .collect()
}

fn extend_missing(errors: &mut Vec<String>, prefix: &str, missing: &[String]) {
    errors.extend(missing.iter().map(|item| format!("{prefix}: {item}")));
}

fn is_safe_relative_artifact_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path
            .split('/')
            .any(|component| matches!(component, "" | "." | ".."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_manifest::validate_manifest;

    const CHECKED_IN_CONTRACT: &str =
        include_str!("../../../docs/repair-writeback-serialization-contract.json");
    const ARTIFACT_ROOT: &str = "artifacts/repair-writeback/dry-run";

    fn sample_contract() -> RepairWritebackSerializationContract {
        serde_json::from_str(CHECKED_IN_CONTRACT).expect("checked-in contract parses")
    }

    #[test]
    fn checked_in_contract_validates() {
        let contract = sample_contract();
        let report = validate_repair_writeback_serialization_contract(&contract, ARTIFACT_ROOT);
        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.missing_required_states, Vec::<String>::new());
        assert_eq!(report.missing_required_invariants, Vec::<String>::new());
        assert!(report.risk_report.fail_closed_is_lower_loss);
    }

    #[test]
    fn model_rejects_repair_writeback_during_client_write() {
        let contract = sample_contract();
        let transition = evaluate_transition(
            &contract,
            "client_write_in_flight",
            "repair_writeback_requested",
        );
        assert!(!transition.allowed);
        assert!(!transition.mutation_allowed);
        assert_eq!(transition.to_state, "repair_writeback_blocked_rw");
        assert_eq!(transition.error_class, "rw_repair_serialization_missing");
        assert!(transition.follow_up_bead.is_some());
    }

    #[test]
    fn flush_does_not_create_a_durability_or_repair_boundary() {
        let contract = sample_contract();
        let transition = evaluate_transition(&contract, "client_write_in_flight", "flush_observed");
        assert!(!transition.allowed);
        assert!(!transition.mutation_allowed);
        assert_eq!(transition.error_class, "flush_non_durable");
    }

    #[test]
    fn stale_symbol_is_rejected_before_writeback() {
        let contract = sample_contract();
        let transition = evaluate_transition(&contract, "repair_lease_held", "repair_symbol_stale");
        assert!(!transition.allowed);
        assert!(!transition.mutation_allowed);
        assert_eq!(transition.error_class, "stale_repair_symbol");
    }

    #[test]
    fn fsync_boundary_missing_rejects_repair_mutation() {
        let contract = sample_contract();
        let transition =
            evaluate_transition(&contract, "repair_lease_held", "fsync_boundary_missing");
        assert!(!transition.allowed);
        assert!(!transition.mutation_allowed);
        assert_eq!(transition.error_class, "dirty_cache_not_fsynced");
    }

    #[test]
    fn cancellation_goes_to_cleanup_without_mutation() {
        let contract = sample_contract();
        let transition =
            evaluate_transition(&contract, "repair_writeback_staged", "repair_cancelled");
        assert!(transition.allowed);
        assert!(!transition.mutation_allowed);
        assert_eq!(transition.to_state, "cleanup_complete");
    }

    #[test]
    fn halfway_writeback_failure_blocks_symbol_refresh() {
        let contract = sample_contract();
        let transition =
            evaluate_transition(&contract, "repair_writeback_staged", "writeback_failed");
        assert!(transition.allowed);
        assert!(!transition.mutation_allowed);
        assert_eq!(transition.to_state, "writeback_failure");
        assert_eq!(transition.error_class, "writeback_failure_no_refresh");
    }

    #[test]
    fn invalid_contract_missing_evidence_field_fails() {
        let mut contract = sample_contract();
        contract
            .required_evidence_fields
            .retain(|field| field != "reproduction_command");
        let report = validate_repair_writeback_serialization_contract(&contract, ARTIFACT_ROOT);
        assert!(!report.valid);
        assert!(
            report
                .missing_required_evidence_fields
                .contains(&"reproduction_command".to_owned())
        );
    }

    #[test]
    fn invalid_unsafe_risk_choice_fails() {
        let mut contract = sample_contract();
        contract.risk_decision.chosen_option = "enable_rw_repair_without_serializer".to_owned();
        contract.risk_decision.rejected_option = "fail_closed_until_unified_serializer".to_owned();
        let report = validate_repair_writeback_serialization_contract(&contract, ARTIFACT_ROOT);
        assert!(!report.valid);
        assert!(!report.risk_report.fail_closed_is_lower_loss);
    }

    #[test]
    fn duplicate_state_ids_fail() {
        let mut contract = sample_contract();
        contract.states.push(contract.states[0].clone());
        let report = validate_repair_writeback_serialization_contract(&contract, ARTIFACT_ROOT);
        assert!(!report.valid);
        assert!(report.duplicate_ids.contains(&contract.states[0].state_id));
    }

    #[test]
    fn sample_artifact_manifest_is_valid() {
        let contract = sample_contract();
        let report = validate_repair_writeback_serialization_contract(&contract, ARTIFACT_ROOT);
        let manifest = build_repair_writeback_serialization_sample_artifact_manifest(
            &contract,
            ARTIFACT_ROOT,
            &report,
        );
        let errors = validate_manifest(&manifest);
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(manifest.gate_id, "repair_writeback_serialization");
        assert_eq!(manifest.bead_id.as_deref(), Some("bd-rchk0.1.1"));
    }
}
