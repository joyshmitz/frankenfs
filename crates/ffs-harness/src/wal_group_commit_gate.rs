#![allow(
    clippy::cognitive_complexity,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::struct_field_names,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
#![forbid(unsafe_code)]

//! Parallel WAL and group-commit evidence gate for `bd-p2j3e.4`.
//!
//! The gate is deliberately conservative: it can classify fixture rows as
//! pass/warn/fail/noisy/missing-reference, but public performance wording only
//! advances when replay proof and comparable fsync-tail evidence both pass.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub const DEFAULT_WAL_GROUP_COMMIT_GATE_MANIFEST: &str =
    "benchmarks/wal_group_commit_gate_manifest.json";
pub const WAL_GROUP_COMMIT_GATE_SCHEMA_VERSION: u32 = 1;

const REQUIRED_INVARIANTS: [&str; 7] = [
    "record_order",
    "idempotent_replay",
    "fsync_fdatasync_boundary_semantics",
    "checksum_validation",
    "cancellation",
    "partial_segment_writes",
    "durable_publish_order",
];

const REQUIRED_LOG_FIELDS: [&str; 17] = [
    "scenario_id",
    "host_fingerprint",
    "lane",
    "reference_lane_id",
    "replay_proof_id",
    "candidate_id",
    "batching_depth",
    "group_commit_width",
    "p99_fsync_latency_us",
    "throughput_ops_per_sec",
    "replay_risk_ppm",
    "memory_footprint_mb",
    "durable_publish_lag_us",
    "checksum_outcome",
    "classification",
    "reproduction_command",
    "raw_log_path",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WalGroupCommitGateManifest {
    pub schema_version: u32,
    pub gate_id: String,
    pub generated_at: String,
    pub target_host: WalTargetHost,
    pub reference_policy: WalComparableReferencePolicy,
    pub invariants: Vec<WalInvariant>,
    pub replay_proofs: Vec<WalReplayProofRow>,
    pub scenarios: Vec<WalMeasurementScenario>,
    pub expected_loss: WalExpectedLossController,
    pub public_claims: Vec<WalPublicClaim>,
    #[serde(default)]
    pub required_log_fields: Vec<String>,
    #[serde(default)]
    pub release_gate_consumers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalTargetHost {
    pub min_cpu_cores_logical: u32,
    pub min_ram_total_gb: u32,
    pub min_ram_available_gb: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalComparableReferencePolicy {
    pub require_reference_lane: bool,
    pub min_cpu_cores_logical: u32,
    pub min_ram_total_gb: u32,
    pub min_ram_available_gb: u32,
    pub require_same_storage_class: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalInvariant {
    pub invariant_id: String,
    pub description: String,
    pub enforcement: String,
    pub evidence_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalReplayProofRow {
    pub proof_id: String,
    pub scenario_id: String,
    pub raw_log_path: String,
    pub replay_artifact_path: String,
    pub reproduction_command: String,
    pub validation_command: String,
    pub expected_record_count: u64,
    pub observed_record_count: u64,
    pub checksum_outcome: WalChecksumOutcome,
    pub record_order_verified: bool,
    pub idempotent_replay_verified: bool,
    pub fsync_fdatasync_boundary_verified: bool,
    pub cancellation_verified: bool,
    pub partial_segment_write_verified: bool,
    pub durable_publish_order_verified: bool,
    pub status: WalReplayProofStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalChecksumOutcome {
    Validated,
    MismatchRejected,
    Missing,
}

impl WalChecksumOutcome {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Validated => "validated",
            Self::MismatchRejected => "mismatch_rejected",
            Self::Missing => "missing",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalReplayProofStatus {
    Pass,
    Warn,
    Fail,
}

impl WalReplayProofStatus {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WalMeasurementScenario {
    pub scenario_id: String,
    pub workload_class: WalWorkloadClass,
    pub host: WalHostObservation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<WalReferenceLane>,
    pub replay_proof_id: String,
    pub fsync_tail_slo: WalFsyncTailSlo,
    pub measurements: Vec<WalCandidateMeasurement>,
    pub claim_state: WalClaimState,
    pub reproduction_command: String,
    pub raw_logs: Vec<String>,
    pub artifact_paths: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalWorkloadClass {
    AppendFsync,
    MetadataStorm,
    MixedReadWrite,
    FixtureSmoke,
}

impl WalWorkloadClass {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AppendFsync => "append_fsync",
            Self::MetadataStorm => "metadata_storm",
            Self::MixedReadWrite => "mixed_read_write",
            Self::FixtureSmoke => "fixture_smoke",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WalHostObservation {
    pub host_fingerprint: String,
    pub cpu_cores_logical: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub numa_nodes: Option<u32>,
    pub ram_total_gb: f64,
    pub ram_available_gb: f64,
    pub storage_class: String,
    pub lane: WalEvidenceLane,
}

impl WalHostObservation {
    #[must_use]
    pub fn meets_target(&self, target: &WalTargetHost) -> bool {
        self.cpu_cores_logical >= target.min_cpu_cores_logical
            && self.ram_total_gb >= f64::from(target.min_ram_total_gb)
            && self.ram_available_gb >= f64::from(target.min_ram_available_gb)
    }

    #[must_use]
    pub fn meets_reference_policy(
        &self,
        scenario_host: &Self,
        policy: &WalComparableReferencePolicy,
    ) -> bool {
        self.cpu_cores_logical >= policy.min_cpu_cores_logical
            && self.ram_total_gb >= f64::from(policy.min_ram_total_gb)
            && self.ram_available_gb >= f64::from(policy.min_ram_available_gb)
            && (!policy.require_same_storage_class
                || self.storage_class == scenario_host.storage_class)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WalReferenceLane {
    pub lane_id: String,
    pub host: WalHostObservation,
    pub raw_logs: Vec<String>,
    pub artifact_paths: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalEvidenceLane {
    DeveloperSmoke,
    RchWorker,
    PermissionedLargeHost,
    CiSmoke,
}

impl WalEvidenceLane {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DeveloperSmoke => "developer_smoke",
            Self::RchWorker => "rch_worker",
            Self::PermissionedLargeHost => "permissioned_large_host",
            Self::CiSmoke => "ci_smoke",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WalFsyncTailSlo {
    pub p99_pass_us: f64,
    pub p99_warn_us: f64,
    pub min_throughput_ops_per_sec: f64,
    pub max_replay_risk_ppm: f64,
    pub max_memory_footprint_mb: f64,
    pub max_durable_publish_lag_us: f64,
    pub max_p99_latency_cv: f64,
    pub max_order_violations: u32,
    pub max_checksum_failures: u32,
    pub max_boundary_violations: u32,
    pub max_cancelled_commit_losses: u32,
    pub max_partial_segment_replay_failures: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WalCandidateMeasurement {
    pub candidate_id: String,
    pub batching_depth: u32,
    pub group_commit_width: u32,
    pub p50_fsync_latency_us: f64,
    pub p99_fsync_latency_us: f64,
    pub p99_latency_cv: f64,
    pub throughput_ops_per_sec: f64,
    pub replay_risk_ppm: f64,
    pub memory_footprint_mb: f64,
    pub durable_publish_lag_us: f64,
    pub checksum_failures: u32,
    pub observed_order_violations: u32,
    pub fdatasync_boundary_violations: u32,
    pub cancelled_commit_losses: u32,
    pub partial_segment_replay_failures: u32,
    pub claim_state: WalClaimState,
    pub expected_classification: WalMeasurementClassification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalClaimState {
    Experimental,
    FixtureSmokeOnly,
    MissingReference,
    MeasuredLocal,
    MeasuredAuthoritative,
    Blocked,
}

impl WalClaimState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Experimental => "experimental",
            Self::FixtureSmokeOnly => "fixture_smoke_only",
            Self::MissingReference => "missing_reference",
            Self::MeasuredLocal => "measured_local",
            Self::MeasuredAuthoritative => "measured_authoritative",
            Self::Blocked => "blocked",
        }
    }

    #[must_use]
    pub const fn stronger_than_smoke(self) -> bool {
        matches!(self, Self::MeasuredLocal | Self::MeasuredAuthoritative)
    }

    #[must_use]
    pub const fn authoritative(self) -> bool {
        matches!(self, Self::MeasuredAuthoritative)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalMeasurementClassification {
    Pass,
    Warn,
    Fail,
    Noisy,
    MissingReference,
}

impl WalMeasurementClassification {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::Noisy => "noisy",
            Self::MissingReference => "missing_reference",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WalExpectedLossController {
    pub controller_id: String,
    pub selected_candidate_id: String,
    pub target_throughput_ops_per_sec: f64,
    pub weights: WalExpectedLossWeights,
    pub candidates: Vec<WalExpectedLossCandidate>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WalExpectedLossWeights {
    pub p99_latency: f64,
    pub throughput_shortfall: f64,
    pub replay_risk: f64,
    pub memory_footprint: f64,
    pub durable_publish_lag: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WalExpectedLossCandidate {
    pub candidate_id: String,
    pub scenario_id: String,
    pub batching_depth: u32,
    pub p99_fsync_latency_us: f64,
    pub throughput_ops_per_sec: f64,
    pub replay_risk_ppm: f64,
    pub memory_footprint_mb: f64,
    pub durable_publish_lag_us: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalPublicClaim {
    pub claim_id: String,
    pub candidate_id: String,
    pub scenario_id: String,
    pub replay_proof_id: String,
    pub claim_state: WalClaimState,
    pub wording: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WalGroupCommitGateReport {
    pub schema_version: u32,
    pub gate_id: String,
    pub valid: bool,
    pub invariant_count: usize,
    pub replay_proof_count: usize,
    pub scenario_count: usize,
    pub measurement_count: usize,
    pub missing_reference_count: usize,
    pub public_claim_authoritative_count: usize,
    pub classification_counts: BTreeMap<String, usize>,
    pub expected_loss_selected_candidate_id: String,
    pub expected_loss_best_candidate_id: String,
    pub expected_loss_rows: Vec<WalExpectedLossReportRow>,
    pub rows: Vec<WalGroupCommitGateRow>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WalGroupCommitGateRow {
    pub scenario_id: String,
    pub candidate_id: String,
    pub workload_class: String,
    pub lane: String,
    pub host_meets_target: bool,
    pub comparable_reference_present: bool,
    pub replay_proof_passed: bool,
    pub batching_depth: u32,
    pub group_commit_width: u32,
    pub p99_fsync_latency_us: f64,
    pub throughput_ops_per_sec: f64,
    pub replay_risk_ppm: f64,
    pub memory_footprint_mb: f64,
    pub durable_publish_lag_us: f64,
    pub claim_state: String,
    pub classification: String,
    pub expected_classification: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WalExpectedLossReportRow {
    pub candidate_id: String,
    pub scenario_id: String,
    pub batching_depth: u32,
    pub expected_loss: f64,
    pub p99_fsync_latency_us: f64,
    pub throughput_ops_per_sec: f64,
    pub replay_risk_ppm: f64,
    pub memory_footprint_mb: f64,
    pub durable_publish_lag_us: f64,
}

pub fn load_wal_group_commit_gate_manifest(path: &Path) -> Result<WalGroupCommitGateManifest> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read WAL group-commit gate {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("invalid WAL group-commit gate JSON {}", path.display()))
}

#[must_use]
pub fn validate_wal_group_commit_gate_manifest(
    manifest: &WalGroupCommitGateManifest,
) -> WalGroupCommitGateReport {
    let mut errors = validate_manifest_shape(manifest);
    let invariant_ids = collect_invariant_ids(manifest, &mut errors);
    validate_required_invariants(&invariant_ids, &mut errors);
    let proof_ids = collect_replay_proofs(manifest, &mut errors);
    let expected_loss_rows = build_expected_loss_rows(&manifest.expected_loss, &mut errors);
    let expected_loss_best_candidate_id = best_expected_loss_candidate(&expected_loss_rows);
    validate_expected_loss_selection(
        &manifest.expected_loss,
        &expected_loss_best_candidate_id,
        &mut errors,
    );

    let mut rows = Vec::new();
    for scenario in &manifest.scenarios {
        validate_scenario(manifest, scenario, &proof_ids, &mut errors);
        rows.extend(build_scenario_rows(
            manifest,
            scenario,
            &proof_ids,
            &mut errors,
        ));
    }

    validate_public_claims(manifest, &proof_ids, &rows, &mut errors);
    validate_expected_loss_candidates_covered(manifest, &rows, &mut errors);

    let classification_counts = count_classifications(&rows);
    let missing_reference_count = rows
        .iter()
        .filter(|row| row.classification == WalMeasurementClassification::MissingReference.label())
        .count();
    let measurement_count = manifest
        .scenarios
        .iter()
        .map(|scenario| scenario.measurements.len())
        .sum();
    let public_claim_authoritative_count = manifest
        .public_claims
        .iter()
        .filter(|claim| claim.claim_state.authoritative())
        .count();

    WalGroupCommitGateReport {
        schema_version: WAL_GROUP_COMMIT_GATE_SCHEMA_VERSION,
        gate_id: manifest.gate_id.clone(),
        valid: errors.is_empty(),
        invariant_count: manifest.invariants.len(),
        replay_proof_count: manifest.replay_proofs.len(),
        scenario_count: manifest.scenarios.len(),
        measurement_count,
        missing_reference_count,
        public_claim_authoritative_count,
        classification_counts,
        expected_loss_selected_candidate_id: manifest.expected_loss.selected_candidate_id.clone(),
        expected_loss_best_candidate_id,
        expected_loss_rows,
        rows,
        errors,
    }
}

pub fn fail_on_wal_group_commit_gate_errors(report: &WalGroupCommitGateReport) -> Result<()> {
    if report.valid {
        Ok(())
    } else {
        bail!(
            "WAL group-commit gate invalid: {} error(s)",
            report.errors.len()
        )
    }
}

#[must_use]
pub fn render_wal_group_commit_gate_markdown(report: &WalGroupCommitGateReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# WAL Group-Commit Gate");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Gate: `{}`", report.gate_id);
    let _ = writeln!(out, "- Valid: `{}`", report.valid);
    let _ = writeln!(out, "- Invariants: `{}`", report.invariant_count);
    let _ = writeln!(out, "- Replay proofs: `{}`", report.replay_proof_count);
    let _ = writeln!(out, "- Scenarios: `{}`", report.scenario_count);
    let _ = writeln!(out, "- Measurements: `{}`", report.measurement_count);
    let _ = writeln!(
        out,
        "- Missing-reference rows: `{}`",
        report.missing_reference_count
    );
    let _ = writeln!(
        out,
        "- Authoritative public claims: `{}`",
        report.public_claim_authoritative_count
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Fsync-Tail Classifications");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| Scenario | Candidate | Lane | Reference | p99 fsync | Throughput | Replay risk | Classification |"
    );
    let _ = writeln!(
        out,
        "|----------|-----------|------|-----------|-----------|------------|-------------|----------------|"
    );
    for row in &report.rows {
        let _ = writeln!(
            out,
            "| `{}` | `{}` | `{}` | `{}` | `{:.1}us` | `{:.1}` | `{:.3}ppm` | `{}` |",
            row.scenario_id,
            row.candidate_id,
            row.lane,
            row.comparable_reference_present,
            row.p99_fsync_latency_us,
            row.throughput_ops_per_sec,
            row.replay_risk_ppm,
            row.classification
        );
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "## Expected-Loss Controller");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "- Selected: `{}`",
        report.expected_loss_selected_candidate_id
    );
    let _ = writeln!(
        out,
        "- Best by rule: `{}`",
        report.expected_loss_best_candidate_id
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| Candidate | Scenario | Batch | Loss | p99 | Throughput | Replay risk | Memory | Publish lag |"
    );
    let _ = writeln!(
        out,
        "|-----------|----------|-------|------|-----|------------|-------------|--------|-------------|"
    );
    for row in &report.expected_loss_rows {
        let _ = writeln!(
            out,
            "| `{}` | `{}` | `{}` | `{:.6}` | `{:.1}us` | `{:.1}` | `{:.3}ppm` | `{:.1}MB` | `{:.1}us` |",
            row.candidate_id,
            row.scenario_id,
            row.batching_depth,
            row.expected_loss,
            row.p99_fsync_latency_us,
            row.throughput_ops_per_sec,
            row.replay_risk_ppm,
            row.memory_footprint_mb,
            row.durable_publish_lag_us
        );
    }

    if !report.errors.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "## Errors");
        for error in &report.errors {
            let _ = writeln!(out, "- {error}");
        }
    }

    out
}

fn validate_manifest_shape(manifest: &WalGroupCommitGateManifest) -> Vec<String> {
    let mut errors = Vec::new();
    if manifest.schema_version != WAL_GROUP_COMMIT_GATE_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version must be {}; got {}",
            WAL_GROUP_COMMIT_GATE_SCHEMA_VERSION, manifest.schema_version
        ));
    }
    require_non_empty("gate_id", &manifest.gate_id, &mut errors);
    require_non_empty("generated_at", &manifest.generated_at, &mut errors);
    validate_target_host(&manifest.target_host, &mut errors);
    validate_reference_policy(&manifest.reference_policy, &mut errors);
    validate_required_log_fields(&manifest.required_log_fields, &mut errors);
    if manifest.invariants.is_empty() {
        errors.push("invariants must not be empty".to_owned());
    }
    if manifest.replay_proofs.is_empty() {
        errors.push("replay_proofs must not be empty".to_owned());
    }
    if manifest.scenarios.is_empty() {
        errors.push("scenarios must not be empty".to_owned());
    }
    if manifest.public_claims.is_empty() {
        errors.push("public_claims must not be empty".to_owned());
    }
    if manifest.release_gate_consumers.is_empty() {
        errors.push("release_gate_consumers must include at least one consumer".to_owned());
    }
    errors
}

fn validate_target_host(target: &WalTargetHost, errors: &mut Vec<String>) {
    if target.min_cpu_cores_logical < 64 {
        errors.push("target_host.min_cpu_cores_logical must be at least 64".to_owned());
    }
    if target.min_ram_total_gb < 256 {
        errors.push("target_host.min_ram_total_gb must be at least 256".to_owned());
    }
    if target.min_ram_available_gb == 0 {
        errors.push("target_host.min_ram_available_gb must be positive".to_owned());
    }
}

fn validate_reference_policy(policy: &WalComparableReferencePolicy, errors: &mut Vec<String>) {
    if policy.require_reference_lane && policy.min_cpu_cores_logical < 64 {
        errors.push("reference_policy.min_cpu_cores_logical must be at least 64".to_owned());
    }
    if policy.require_reference_lane && policy.min_ram_total_gb < 256 {
        errors.push("reference_policy.min_ram_total_gb must be at least 256".to_owned());
    }
    if policy.require_reference_lane && policy.min_ram_available_gb == 0 {
        errors.push("reference_policy.min_ram_available_gb must be positive".to_owned());
    }
}

fn collect_invariant_ids(
    manifest: &WalGroupCommitGateManifest,
    errors: &mut Vec<String>,
) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for invariant in &manifest.invariants {
        require_non_empty("invariant.invariant_id", &invariant.invariant_id, errors);
        require_non_empty("invariant.description", &invariant.description, errors);
        require_non_empty("invariant.enforcement", &invariant.enforcement, errors);
        require_non_empty("invariant.evidence_path", &invariant.evidence_path, errors);
        if !ids.insert(invariant.invariant_id.clone()) {
            errors.push(format!("duplicate invariant_id {}", invariant.invariant_id));
        }
    }
    ids
}

fn validate_required_invariants(invariant_ids: &BTreeSet<String>, errors: &mut Vec<String>) {
    for required in REQUIRED_INVARIANTS {
        if !invariant_ids.contains(required) {
            errors.push(format!("invariants missing required {required}"));
        }
    }
}

fn collect_replay_proofs<'a>(
    manifest: &'a WalGroupCommitGateManifest,
    errors: &mut Vec<String>,
) -> BTreeMap<String, &'a WalReplayProofRow> {
    let mut proofs = BTreeMap::new();
    for proof in &manifest.replay_proofs {
        validate_replay_proof(proof, errors);
        if proofs.insert(proof.proof_id.clone(), proof).is_some() {
            errors.push(format!("duplicate replay proof {}", proof.proof_id));
        }
    }
    proofs
}

fn validate_replay_proof(proof: &WalReplayProofRow, errors: &mut Vec<String>) {
    require_non_empty("replay_proof.proof_id", &proof.proof_id, errors);
    require_non_empty("replay_proof.scenario_id", &proof.scenario_id, errors);
    require_non_empty("replay_proof.raw_log_path", &proof.raw_log_path, errors);
    require_non_empty(
        "replay_proof.replay_artifact_path",
        &proof.replay_artifact_path,
        errors,
    );
    require_non_empty(
        "replay_proof.reproduction_command",
        &proof.reproduction_command,
        errors,
    );
    require_non_empty(
        "replay_proof.validation_command",
        &proof.validation_command,
        errors,
    );
    if proof.expected_record_count == 0 {
        errors.push(format!(
            "replay proof {} expected_record_count must be positive",
            proof.proof_id
        ));
    }
    if proof.status == WalReplayProofStatus::Pass {
        if proof.expected_record_count != proof.observed_record_count {
            errors.push(format!(
                "replay proof {} pass status requires expected and observed record counts to match",
                proof.proof_id
            ));
        }
        if proof.checksum_outcome != WalChecksumOutcome::Validated {
            errors.push(format!(
                "replay proof {} pass status requires checksum validation",
                proof.proof_id
            ));
        }
        let verified = proof.record_order_verified
            && proof.idempotent_replay_verified
            && proof.fsync_fdatasync_boundary_verified
            && proof.cancellation_verified
            && proof.partial_segment_write_verified
            && proof.durable_publish_order_verified;
        if !verified {
            errors.push(format!(
                "replay proof {} pass status requires every WAL invariant proof flag",
                proof.proof_id
            ));
        }
    }
}

fn validate_scenario(
    manifest: &WalGroupCommitGateManifest,
    scenario: &WalMeasurementScenario,
    proof_ids: &BTreeMap<String, &WalReplayProofRow>,
    errors: &mut Vec<String>,
) {
    require_non_empty("scenario.scenario_id", &scenario.scenario_id, errors);
    require_non_empty(
        "scenario.replay_proof_id",
        &scenario.replay_proof_id,
        errors,
    );
    require_non_empty(
        "scenario.reproduction_command",
        &scenario.reproduction_command,
        errors,
    );
    validate_non_empty_paths("scenario.raw_logs", &scenario.raw_logs, errors);
    validate_non_empty_paths("scenario.artifact_paths", &scenario.artifact_paths, errors);
    validate_host_observation("scenario.host", &scenario.host, errors);
    validate_fsync_tail_slo(&scenario.scenario_id, &scenario.fsync_tail_slo, errors);
    validate_reference_lane(manifest, scenario, errors);
    validate_measurements(manifest, scenario, errors);

    match proof_ids.get(&scenario.replay_proof_id) {
        Some(proof) if proof.scenario_id != scenario.scenario_id => {
            errors.push(format!(
                "scenario {} replay proof {} belongs to scenario {}",
                scenario.scenario_id, scenario.replay_proof_id, proof.scenario_id
            ));
        }
        Some(_) => {}
        None => errors.push(format!(
            "scenario {} references unknown replay proof {}",
            scenario.scenario_id, scenario.replay_proof_id
        )),
    }
}

fn validate_host_observation(field: &str, host: &WalHostObservation, errors: &mut Vec<String>) {
    require_non_empty(
        &format!("{field}.host_fingerprint"),
        &host.host_fingerprint,
        errors,
    );
    require_non_empty(
        &format!("{field}.storage_class"),
        &host.storage_class,
        errors,
    );
    if host.cpu_cores_logical == 0 {
        errors.push(format!("{field}.cpu_cores_logical must be positive"));
    }
    if let Some(numa_nodes) = host.numa_nodes
        && numa_nodes == 0
    {
        errors.push(format!("{field}.numa_nodes must be positive when present"));
    }
    if !host.ram_total_gb.is_finite() || host.ram_total_gb <= 0.0 {
        errors.push(format!("{field}.ram_total_gb must be finite and positive"));
    }
    if !host.ram_available_gb.is_finite() || host.ram_available_gb <= 0.0 {
        errors.push(format!(
            "{field}.ram_available_gb must be finite and positive"
        ));
    }
    if host.ram_available_gb > host.ram_total_gb {
        errors.push(format!("{field}.ram_available_gb exceeds ram_total_gb"));
    }
}

fn validate_fsync_tail_slo(scenario_id: &str, slo: &WalFsyncTailSlo, errors: &mut Vec<String>) {
    validate_positive_finite(scenario_id, "p99_pass_us", slo.p99_pass_us, errors);
    validate_positive_finite(scenario_id, "p99_warn_us", slo.p99_warn_us, errors);
    validate_positive_finite(
        scenario_id,
        "min_throughput_ops_per_sec",
        slo.min_throughput_ops_per_sec,
        errors,
    );
    validate_non_negative_finite(
        scenario_id,
        "max_replay_risk_ppm",
        slo.max_replay_risk_ppm,
        errors,
    );
    validate_positive_finite(
        scenario_id,
        "max_memory_footprint_mb",
        slo.max_memory_footprint_mb,
        errors,
    );
    validate_positive_finite(
        scenario_id,
        "max_durable_publish_lag_us",
        slo.max_durable_publish_lag_us,
        errors,
    );
    validate_positive_finite(
        scenario_id,
        "max_p99_latency_cv",
        slo.max_p99_latency_cv,
        errors,
    );
    if slo.p99_pass_us >= slo.p99_warn_us {
        errors.push(format!(
            "scenario {scenario_id} p99_pass_us must be below p99_warn_us"
        ));
    }
}

fn validate_reference_lane(
    manifest: &WalGroupCommitGateManifest,
    scenario: &WalMeasurementScenario,
    errors: &mut Vec<String>,
) {
    let Some(reference) = &scenario.reference else {
        return;
    };
    require_non_empty("scenario.reference.lane_id", &reference.lane_id, errors);
    validate_host_observation("scenario.reference.host", &reference.host, errors);
    validate_non_empty_paths("scenario.reference.raw_logs", &reference.raw_logs, errors);
    validate_non_empty_paths(
        "scenario.reference.artifact_paths",
        &reference.artifact_paths,
        errors,
    );
    if !reference
        .host
        .meets_reference_policy(&scenario.host, &manifest.reference_policy)
    {
        errors.push(format!(
            "scenario {} reference lane {} is not comparable to policy",
            scenario.scenario_id, reference.lane_id
        ));
    }
}

fn validate_measurements(
    manifest: &WalGroupCommitGateManifest,
    scenario: &WalMeasurementScenario,
    errors: &mut Vec<String>,
) {
    if scenario.measurements.is_empty() {
        errors.push(format!(
            "scenario {} requires measurements",
            scenario.scenario_id
        ));
        return;
    }

    let mut seen = BTreeSet::new();
    for measurement in &scenario.measurements {
        require_non_empty(
            "measurement.candidate_id",
            &measurement.candidate_id,
            errors,
        );
        if !seen.insert(measurement.candidate_id.clone()) {
            errors.push(format!(
                "scenario {} duplicates candidate {}",
                scenario.scenario_id, measurement.candidate_id
            ));
        }
        if measurement.batching_depth == 0 {
            errors.push(format!(
                "scenario {} candidate {} batching_depth must be positive",
                scenario.scenario_id, measurement.candidate_id
            ));
        }
        if measurement.group_commit_width == 0 {
            errors.push(format!(
                "scenario {} candidate {} group_commit_width must be positive",
                scenario.scenario_id, measurement.candidate_id
            ));
        }
        validate_positive_finite_measurement(
            &scenario.scenario_id,
            &measurement.candidate_id,
            "p50_fsync_latency_us",
            measurement.p50_fsync_latency_us,
            errors,
        );
        validate_positive_finite_measurement(
            &scenario.scenario_id,
            &measurement.candidate_id,
            "p99_fsync_latency_us",
            measurement.p99_fsync_latency_us,
            errors,
        );
        validate_non_negative_finite_measurement(
            &scenario.scenario_id,
            &measurement.candidate_id,
            "p99_latency_cv",
            measurement.p99_latency_cv,
            errors,
        );
        validate_positive_finite_measurement(
            &scenario.scenario_id,
            &measurement.candidate_id,
            "throughput_ops_per_sec",
            measurement.throughput_ops_per_sec,
            errors,
        );
        validate_non_negative_finite_measurement(
            &scenario.scenario_id,
            &measurement.candidate_id,
            "replay_risk_ppm",
            measurement.replay_risk_ppm,
            errors,
        );
        validate_non_negative_finite_measurement(
            &scenario.scenario_id,
            &measurement.candidate_id,
            "memory_footprint_mb",
            measurement.memory_footprint_mb,
            errors,
        );
        validate_non_negative_finite_measurement(
            &scenario.scenario_id,
            &measurement.candidate_id,
            "durable_publish_lag_us",
            measurement.durable_publish_lag_us,
            errors,
        );

        let classification = classify_measurement(manifest, scenario, measurement);
        if classification != measurement.expected_classification {
            errors.push(format!(
                "scenario {} candidate {} expected classification {} but computed {}",
                scenario.scenario_id,
                measurement.candidate_id,
                measurement.expected_classification.label(),
                classification.label()
            ));
        }
        if classification != WalMeasurementClassification::Pass
            && measurement.claim_state.stronger_than_smoke()
        {
            errors.push(format!(
                "scenario {} candidate {} has {} classification but claim state {}",
                scenario.scenario_id,
                measurement.candidate_id,
                classification.label(),
                measurement.claim_state.label()
            ));
        }
        if classification == WalMeasurementClassification::MissingReference
            && measurement.claim_state != WalClaimState::MissingReference
        {
            errors.push(format!(
                "scenario {} candidate {} missing comparable reference but claim state {}",
                scenario.scenario_id,
                measurement.candidate_id,
                measurement.claim_state.label()
            ));
        }
    }
}

fn build_scenario_rows(
    manifest: &WalGroupCommitGateManifest,
    scenario: &WalMeasurementScenario,
    proof_ids: &BTreeMap<String, &WalReplayProofRow>,
    errors: &mut Vec<String>,
) -> Vec<WalGroupCommitGateRow> {
    let proof = proof_ids.get(&scenario.replay_proof_id).copied();
    let replay_proof_passed = proof.is_some_and(replay_proof_passed);
    let comparable_reference_present = scenario_has_comparable_reference(manifest, scenario);
    let host_meets_target = scenario.host.meets_target(&manifest.target_host);
    let mut rows = Vec::new();

    if proof.is_none() {
        errors.push(format!(
            "scenario {} cannot build validation rows without replay proof {}",
            scenario.scenario_id, scenario.replay_proof_id
        ));
    }

    for measurement in &scenario.measurements {
        let classification = classify_measurement(manifest, scenario, measurement);
        rows.push(WalGroupCommitGateRow {
            scenario_id: scenario.scenario_id.clone(),
            candidate_id: measurement.candidate_id.clone(),
            workload_class: scenario.workload_class.label().to_owned(),
            lane: scenario.host.lane.label().to_owned(),
            host_meets_target,
            comparable_reference_present,
            replay_proof_passed,
            batching_depth: measurement.batching_depth,
            group_commit_width: measurement.group_commit_width,
            p99_fsync_latency_us: measurement.p99_fsync_latency_us,
            throughput_ops_per_sec: measurement.throughput_ops_per_sec,
            replay_risk_ppm: measurement.replay_risk_ppm,
            memory_footprint_mb: measurement.memory_footprint_mb,
            durable_publish_lag_us: measurement.durable_publish_lag_us,
            claim_state: measurement.claim_state.label().to_owned(),
            classification: classification.label().to_owned(),
            expected_classification: measurement.expected_classification.label().to_owned(),
        });
    }

    rows
}

fn validate_public_claims(
    manifest: &WalGroupCommitGateManifest,
    proof_ids: &BTreeMap<String, &WalReplayProofRow>,
    rows: &[WalGroupCommitGateRow],
    errors: &mut Vec<String>,
) {
    let scenario_ids = manifest
        .scenarios
        .iter()
        .map(|scenario| scenario.scenario_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut claim_ids = BTreeSet::new();

    for claim in &manifest.public_claims {
        require_non_empty("public_claim.claim_id", &claim.claim_id, errors);
        require_non_empty("public_claim.candidate_id", &claim.candidate_id, errors);
        require_non_empty("public_claim.scenario_id", &claim.scenario_id, errors);
        require_non_empty(
            "public_claim.replay_proof_id",
            &claim.replay_proof_id,
            errors,
        );
        require_non_empty("public_claim.wording", &claim.wording, errors);
        if !claim_ids.insert(claim.claim_id.clone()) {
            errors.push(format!("duplicate public claim {}", claim.claim_id));
        }
        if !scenario_ids.contains(claim.scenario_id.as_str()) {
            errors.push(format!(
                "public claim {} references unknown scenario {}",
                claim.claim_id, claim.scenario_id
            ));
        }

        let proof_passed = proof_ids
            .get(&claim.replay_proof_id)
            .is_some_and(|proof| replay_proof_passed(proof));
        let row = rows.iter().find(|row| {
            row.scenario_id == claim.scenario_id && row.candidate_id == claim.candidate_id
        });
        let Some(row) = row else {
            errors.push(format!(
                "public claim {} references missing candidate {} in scenario {}",
                claim.claim_id, claim.candidate_id, claim.scenario_id
            ));
            continue;
        };

        if claim.claim_state.stronger_than_smoke() {
            if !proof_passed {
                errors.push(format!(
                    "public claim {} cannot improve until replay proof {} passes",
                    claim.claim_id, claim.replay_proof_id
                ));
            }
            if row.classification != WalMeasurementClassification::Pass.label() {
                errors.push(format!(
                    "public claim {} cannot improve while fsync-tail classification is {}",
                    claim.claim_id, row.classification
                ));
            }
            if !row.comparable_reference_present {
                errors.push(format!(
                    "public claim {} cannot improve without comparable reference lane",
                    claim.claim_id
                ));
            }
        }

        if claim.claim_state.authoritative()
            && (!row.host_meets_target
                || row.lane != WalEvidenceLane::PermissionedLargeHost.label())
        {
            errors.push(format!(
                "public claim {} authoritative state requires permissioned large-host evidence",
                claim.claim_id
            ));
        }
    }
}

fn validate_expected_loss_candidates_covered(
    manifest: &WalGroupCommitGateManifest,
    rows: &[WalGroupCommitGateRow],
    errors: &mut Vec<String>,
) {
    for candidate in &manifest.expected_loss.candidates {
        let covered = rows.iter().any(|row| {
            row.scenario_id == candidate.scenario_id && row.candidate_id == candidate.candidate_id
        });
        if !covered {
            errors.push(format!(
                "expected-loss candidate {} references missing measurement in scenario {}",
                candidate.candidate_id, candidate.scenario_id
            ));
        }
    }
}

fn classify_measurement(
    manifest: &WalGroupCommitGateManifest,
    scenario: &WalMeasurementScenario,
    measurement: &WalCandidateMeasurement,
) -> WalMeasurementClassification {
    let slo = &scenario.fsync_tail_slo;

    if manifest.reference_policy.require_reference_lane
        && !scenario_has_comparable_reference(manifest, scenario)
    {
        return WalMeasurementClassification::MissingReference;
    }
    if measurement.p99_latency_cv > slo.max_p99_latency_cv {
        return WalMeasurementClassification::Noisy;
    }
    if measurement.p99_fsync_latency_us > slo.p99_warn_us
        || measurement.throughput_ops_per_sec < slo.min_throughput_ops_per_sec
        || measurement.replay_risk_ppm > slo.max_replay_risk_ppm
        || measurement.memory_footprint_mb > slo.max_memory_footprint_mb
        || measurement.checksum_failures > slo.max_checksum_failures
        || measurement.observed_order_violations > slo.max_order_violations
        || measurement.fdatasync_boundary_violations > slo.max_boundary_violations
        || measurement.cancelled_commit_losses > slo.max_cancelled_commit_losses
        || measurement.partial_segment_replay_failures > slo.max_partial_segment_replay_failures
        || measurement.durable_publish_lag_us > slo.max_durable_publish_lag_us * 2.0
    {
        return WalMeasurementClassification::Fail;
    }
    if measurement.p99_fsync_latency_us > slo.p99_pass_us
        || measurement.durable_publish_lag_us > slo.max_durable_publish_lag_us
    {
        return WalMeasurementClassification::Warn;
    }
    WalMeasurementClassification::Pass
}

fn scenario_has_comparable_reference(
    manifest: &WalGroupCommitGateManifest,
    scenario: &WalMeasurementScenario,
) -> bool {
    scenario.reference.as_ref().is_some_and(|reference| {
        reference
            .host
            .meets_reference_policy(&scenario.host, &manifest.reference_policy)
            && !reference.raw_logs.is_empty()
            && !reference.artifact_paths.is_empty()
    })
}

fn replay_proof_passed(proof: &WalReplayProofRow) -> bool {
    proof.status == WalReplayProofStatus::Pass
        && proof.expected_record_count == proof.observed_record_count
        && proof.checksum_outcome == WalChecksumOutcome::Validated
        && proof.record_order_verified
        && proof.idempotent_replay_verified
        && proof.fsync_fdatasync_boundary_verified
        && proof.cancellation_verified
        && proof.partial_segment_write_verified
        && proof.durable_publish_order_verified
}

fn build_expected_loss_rows(
    controller: &WalExpectedLossController,
    errors: &mut Vec<String>,
) -> Vec<WalExpectedLossReportRow> {
    validate_expected_loss_controller(controller, errors);
    controller
        .candidates
        .iter()
        .map(|candidate| {
            let expected_loss = compute_expected_loss(controller, candidate);
            WalExpectedLossReportRow {
                candidate_id: candidate.candidate_id.clone(),
                scenario_id: candidate.scenario_id.clone(),
                batching_depth: candidate.batching_depth,
                expected_loss,
                p99_fsync_latency_us: candidate.p99_fsync_latency_us,
                throughput_ops_per_sec: candidate.throughput_ops_per_sec,
                replay_risk_ppm: candidate.replay_risk_ppm,
                memory_footprint_mb: candidate.memory_footprint_mb,
                durable_publish_lag_us: candidate.durable_publish_lag_us,
            }
        })
        .collect()
}

fn validate_expected_loss_controller(
    controller: &WalExpectedLossController,
    errors: &mut Vec<String>,
) {
    require_non_empty(
        "expected_loss.controller_id",
        &controller.controller_id,
        errors,
    );
    require_non_empty(
        "expected_loss.selected_candidate_id",
        &controller.selected_candidate_id,
        errors,
    );
    validate_positive_finite(
        "expected_loss",
        "target_throughput_ops_per_sec",
        controller.target_throughput_ops_per_sec,
        errors,
    );
    validate_non_negative_finite(
        "expected_loss",
        "p99_latency",
        controller.weights.p99_latency,
        errors,
    );
    validate_non_negative_finite(
        "expected_loss",
        "throughput_shortfall",
        controller.weights.throughput_shortfall,
        errors,
    );
    validate_non_negative_finite(
        "expected_loss",
        "replay_risk",
        controller.weights.replay_risk,
        errors,
    );
    validate_non_negative_finite(
        "expected_loss",
        "memory_footprint",
        controller.weights.memory_footprint,
        errors,
    );
    validate_non_negative_finite(
        "expected_loss",
        "durable_publish_lag",
        controller.weights.durable_publish_lag,
        errors,
    );
    if controller.candidates.is_empty() {
        errors.push("expected_loss.candidates must not be empty".to_owned());
    }
    for candidate in &controller.candidates {
        validate_expected_loss_candidate(candidate, errors);
    }
}

fn validate_expected_loss_candidate(
    candidate: &WalExpectedLossCandidate,
    errors: &mut Vec<String>,
) {
    require_non_empty(
        "expected_loss.candidate.candidate_id",
        &candidate.candidate_id,
        errors,
    );
    require_non_empty(
        "expected_loss.candidate.scenario_id",
        &candidate.scenario_id,
        errors,
    );
    if candidate.batching_depth == 0 {
        errors.push(format!(
            "expected_loss candidate {} batching_depth must be positive",
            candidate.candidate_id
        ));
    }
    validate_positive_finite_measurement(
        &candidate.scenario_id,
        &candidate.candidate_id,
        "p99_fsync_latency_us",
        candidate.p99_fsync_latency_us,
        errors,
    );
    validate_positive_finite_measurement(
        &candidate.scenario_id,
        &candidate.candidate_id,
        "throughput_ops_per_sec",
        candidate.throughput_ops_per_sec,
        errors,
    );
    validate_non_negative_finite_measurement(
        &candidate.scenario_id,
        &candidate.candidate_id,
        "replay_risk_ppm",
        candidate.replay_risk_ppm,
        errors,
    );
    validate_non_negative_finite_measurement(
        &candidate.scenario_id,
        &candidate.candidate_id,
        "memory_footprint_mb",
        candidate.memory_footprint_mb,
        errors,
    );
    validate_non_negative_finite_measurement(
        &candidate.scenario_id,
        &candidate.candidate_id,
        "durable_publish_lag_us",
        candidate.durable_publish_lag_us,
        errors,
    );
}

fn compute_expected_loss(
    controller: &WalExpectedLossController,
    candidate: &WalExpectedLossCandidate,
) -> f64 {
    let throughput_shortfall =
        (controller.target_throughput_ops_per_sec - candidate.throughput_ops_per_sec).max(0.0)
            / controller.target_throughput_ops_per_sec;
    let weights = &controller.weights;
    weights.durable_publish_lag.mul_add(
        candidate.durable_publish_lag_us / 1_000_000.0,
        weights.memory_footprint.mul_add(
            candidate.memory_footprint_mb / 1024.0,
            weights.replay_risk.mul_add(
                candidate.replay_risk_ppm / 1_000_000.0,
                weights.throughput_shortfall.mul_add(
                    throughput_shortfall,
                    weights.p99_latency * (candidate.p99_fsync_latency_us / 1_000_000.0),
                ),
            ),
        ),
    )
}

fn best_expected_loss_candidate(rows: &[WalExpectedLossReportRow]) -> String {
    rows.iter()
        .min_by(|left, right| left.expected_loss.total_cmp(&right.expected_loss))
        .map(|row| row.candidate_id.clone())
        .unwrap_or_default()
}

fn validate_expected_loss_selection(
    controller: &WalExpectedLossController,
    best_candidate_id: &str,
    errors: &mut Vec<String>,
) {
    if !best_candidate_id.is_empty() && controller.selected_candidate_id != best_candidate_id {
        errors.push(format!(
            "expected_loss selected_candidate_id {} is not minimum-loss candidate {}",
            controller.selected_candidate_id, best_candidate_id
        ));
    }
}

fn count_classifications(rows: &[WalGroupCommitGateRow]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for row in rows {
        *counts.entry(row.classification.clone()).or_insert(0) += 1;
    }
    counts
}

fn validate_required_log_fields(required_log_fields: &[String], errors: &mut Vec<String>) {
    let actual = required_log_fields
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for required in REQUIRED_LOG_FIELDS {
        if !actual.contains(required) {
            errors.push(format!("required_log_fields missing {required}"));
        }
    }
}

fn validate_positive_finite(scenario_id: &str, field: &str, value: f64, errors: &mut Vec<String>) {
    if !value.is_finite() || value <= 0.0 {
        errors.push(format!(
            "scenario {scenario_id} {field} must be finite and positive"
        ));
    }
}

fn validate_non_negative_finite(
    scenario_id: &str,
    field: &str,
    value: f64,
    errors: &mut Vec<String>,
) {
    if !value.is_finite() || value < 0.0 {
        errors.push(format!(
            "scenario {scenario_id} {field} must be finite and non-negative"
        ));
    }
}

fn validate_positive_finite_measurement(
    scenario_id: &str,
    candidate_id: &str,
    field: &str,
    value: f64,
    errors: &mut Vec<String>,
) {
    if !value.is_finite() || value <= 0.0 {
        errors.push(format!(
            "scenario {scenario_id} candidate {candidate_id} {field} must be finite and positive"
        ));
    }
}

fn validate_non_negative_finite_measurement(
    scenario_id: &str,
    candidate_id: &str,
    field: &str,
    value: f64,
    errors: &mut Vec<String>,
) {
    if !value.is_finite() || value < 0.0 {
        errors.push(format!(
            "scenario {scenario_id} candidate {candidate_id} {field} must be finite and non-negative"
        ));
    }
}

fn require_non_empty(field: &str, value: &str, errors: &mut Vec<String>) {
    if value.trim().is_empty() {
        errors.push(format!("{field} must not be empty"));
    }
}

fn validate_non_empty_paths(field: &str, paths: &[String], errors: &mut Vec<String>) {
    if paths.is_empty() {
        errors.push(format!("{field} must not be empty"));
    }
    for path in paths {
        require_non_empty(field, path, errors);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_manifest_accepts_all_required_evidence() {
        let report = validate_wal_group_commit_gate_manifest(&sample_manifest());

        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.invariant_count, REQUIRED_INVARIANTS.len());
        assert_eq!(report.replay_proof_count, 2);
        assert_eq!(report.scenario_count, 2);
        assert_eq!(report.classification_counts["pass"], 1);
        assert_eq!(report.classification_counts["warn"], 1);
        assert_eq!(report.classification_counts["fail"], 2);
        assert_eq!(report.classification_counts["noisy"], 1);
        assert_eq!(report.classification_counts["missing_reference"], 1);
        assert_eq!(
            report.expected_loss_best_candidate_id,
            "parallel_epoch_group_commit"
        );
    }

    #[test]
    fn missing_required_invariant_is_rejected() {
        let mut manifest = sample_manifest();
        manifest
            .invariants
            .retain(|invariant| invariant.invariant_id != "durable_publish_order");

        let report = validate_wal_group_commit_gate_manifest(&manifest);

        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("durable_publish_order"))
        );
    }

    #[test]
    fn missing_raw_logs_are_rejected() {
        let mut manifest = sample_manifest();
        manifest.scenarios[0].raw_logs.clear();
        manifest.replay_proofs[0].raw_log_path.clear();

        let report = validate_wal_group_commit_gate_manifest(&manifest);

        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("raw_logs must not be empty"))
        );
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("raw_log_path must not be empty"))
        );
    }

    #[test]
    fn missing_reference_lane_classifies_conservatively() {
        let mut manifest = sample_manifest();
        manifest.scenarios[0].reference = None;
        manifest.scenarios[0].claim_state = WalClaimState::MissingReference;
        for measurement in &mut manifest.scenarios[0].measurements {
            measurement.claim_state = WalClaimState::MissingReference;
            measurement.expected_classification = WalMeasurementClassification::MissingReference;
        }
        manifest.public_claims[0].claim_state = WalClaimState::MissingReference;

        let report = validate_wal_group_commit_gate_manifest(&manifest);

        assert!(report.valid, "{:?}", report.errors);
        assert!(report.missing_reference_count >= 4);
    }

    #[test]
    fn authoritative_missing_reference_is_rejected() {
        let mut manifest = sample_manifest();
        manifest.scenarios[0].reference = None;

        let report = validate_wal_group_commit_gate_manifest(&manifest);

        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("missing comparable reference"))
        );
    }

    #[test]
    fn expected_loss_selection_must_match_minimum_candidate() {
        let mut manifest = sample_manifest();
        manifest.expected_loss.selected_candidate_id = "wide_batch_noisy".to_owned();

        let report = validate_wal_group_commit_gate_manifest(&manifest);

        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("minimum-loss candidate"))
        );
    }

    #[test]
    fn public_claim_cannot_improve_without_replay_proof() {
        let mut manifest = sample_manifest();
        manifest.replay_proofs[0].durable_publish_order_verified = false;

        let report = validate_wal_group_commit_gate_manifest(&manifest);

        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("cannot improve until replay proof"))
        );
    }

    fn sample_manifest() -> WalGroupCommitGateManifest {
        WalGroupCommitGateManifest {
            schema_version: WAL_GROUP_COMMIT_GATE_SCHEMA_VERSION,
            gate_id: "bd-p2j3e.4-wal-group-commit-gate-v1".to_owned(),
            generated_at: "2026-05-03T23:30:00Z".to_owned(),
            target_host: WalTargetHost {
                min_cpu_cores_logical: 64,
                min_ram_total_gb: 256,
                min_ram_available_gb: 192,
            },
            reference_policy: WalComparableReferencePolicy {
                require_reference_lane: true,
                min_cpu_cores_logical: 64,
                min_ram_total_gb: 256,
                min_ram_available_gb: 192,
                require_same_storage_class: true,
            },
            invariants: REQUIRED_INVARIANTS
                .iter()
                .map(|invariant| WalInvariant {
                    invariant_id: (*invariant).to_owned(),
                    description: format!("{invariant} invariant"),
                    enforcement: "validated by replay proof and fsync-tail gate".to_owned(),
                    evidence_path: format!("artifacts/wal/{invariant}/evidence.json"),
                })
                .collect(),
            replay_proofs: vec![
                replay_proof(
                    "proof_large_pass",
                    "wal_append_256gb_authoritative",
                    WalReplayProofStatus::Pass,
                ),
                replay_proof(
                    "proof_small_smoke",
                    "wal_smoke_missing_reference",
                    WalReplayProofStatus::Pass,
                ),
            ],
            scenarios: vec![large_host_scenario(), missing_reference_scenario()],
            expected_loss: expected_loss_controller(),
            public_claims: vec![WalPublicClaim {
                claim_id: "parallel_wal_authoritative_claim".to_owned(),
                candidate_id: "parallel_epoch_group_commit".to_owned(),
                scenario_id: "wal_append_256gb_authoritative".to_owned(),
                replay_proof_id: "proof_large_pass".to_owned(),
                claim_state: WalClaimState::MeasuredAuthoritative,
                wording:
                    "Parallel WAL group commit is measured only for the referenced large-host lane."
                        .to_owned(),
            }],
            required_log_fields: REQUIRED_LOG_FIELDS
                .iter()
                .map(|field| (*field).to_owned())
                .collect(),
            release_gate_consumers: vec!["bd-p2j3e".to_owned(), "proof-bundle".to_owned()],
        }
    }

    fn replay_proof(
        proof_id: &str,
        scenario_id: &str,
        status: WalReplayProofStatus,
    ) -> WalReplayProofRow {
        WalReplayProofRow {
            proof_id: proof_id.to_owned(),
            scenario_id: scenario_id.to_owned(),
            raw_log_path: format!("artifacts/wal/{scenario_id}/raw.log"),
            replay_artifact_path: format!("artifacts/wal/{scenario_id}/replay.json"),
            reproduction_command:
                "ffs-harness validate-wal-group-commit-gate --manifest benchmarks/wal_group_commit_gate_manifest.json"
                    .to_owned(),
            validation_command:
                "ffs-harness validate-wal-group-commit-gate --format markdown".to_owned(),
            expected_record_count: 128_000,
            observed_record_count: 128_000,
            checksum_outcome: WalChecksumOutcome::Validated,
            record_order_verified: true,
            idempotent_replay_verified: true,
            fsync_fdatasync_boundary_verified: true,
            cancellation_verified: true,
            partial_segment_write_verified: true,
            durable_publish_order_verified: true,
            status,
        }
    }

    fn large_host_scenario() -> WalMeasurementScenario {
        WalMeasurementScenario {
            scenario_id: "wal_append_256gb_authoritative".to_owned(),
            workload_class: WalWorkloadClass::AppendFsync,
            host: large_host("large-host-run"),
            reference: Some(WalReferenceLane {
                lane_id: "large-host-reference".to_owned(),
                host: large_host("large-host-reference"),
                raw_logs: vec!["artifacts/wal/reference/raw.log".to_owned()],
                artifact_paths: vec!["artifacts/wal/reference/report.json".to_owned()],
            }),
            replay_proof_id: "proof_large_pass".to_owned(),
            fsync_tail_slo: fsync_tail_slo(),
            measurements: vec![
                measurement(
                    "current_serial_wal",
                    1,
                    1,
                    4_900.0,
                    18_000.0,
                    0.03,
                    64.0,
                    80.0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    WalClaimState::Blocked,
                    WalMeasurementClassification::Fail,
                ),
                measurement(
                    "parallel_epoch_group_commit",
                    32,
                    16,
                    1_850.0,
                    34_000.0,
                    0.04,
                    512.0,
                    210.0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    WalClaimState::MeasuredAuthoritative,
                    WalMeasurementClassification::Pass,
                ),
                measurement(
                    "wide_batch_warn",
                    96,
                    32,
                    2_650.0,
                    37_000.0,
                    0.04,
                    550.0,
                    430.0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    WalClaimState::FixtureSmokeOnly,
                    WalMeasurementClassification::Warn,
                ),
                measurement(
                    "deep_batch_fail",
                    256,
                    64,
                    6_500.0,
                    41_000.0,
                    0.05,
                    1_500.0,
                    1_900.0,
                    1,
                    0,
                    0,
                    0,
                    1,
                    WalClaimState::Blocked,
                    WalMeasurementClassification::Fail,
                ),
                measurement(
                    "wide_batch_noisy",
                    64,
                    32,
                    2_100.0,
                    35_500.0,
                    0.42,
                    540.0,
                    260.0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    WalClaimState::FixtureSmokeOnly,
                    WalMeasurementClassification::Noisy,
                ),
            ],
            claim_state: WalClaimState::MeasuredAuthoritative,
            reproduction_command:
                "ffs-harness validate-wal-group-commit-gate --manifest benchmarks/wal_group_commit_gate_manifest.json"
                    .to_owned(),
            raw_logs: vec!["artifacts/wal/large-host/raw.log".to_owned()],
            artifact_paths: vec!["artifacts/wal/large-host/report.json".to_owned()],
        }
    }

    fn missing_reference_scenario() -> WalMeasurementScenario {
        WalMeasurementScenario {
            scenario_id: "wal_smoke_missing_reference".to_owned(),
            workload_class: WalWorkloadClass::FixtureSmoke,
            host: WalHostObservation {
                host_fingerprint: "developer-smoke".to_owned(),
                cpu_cores_logical: 16,
                numa_nodes: Some(1),
                ram_total_gb: 64.0,
                ram_available_gb: 40.0,
                storage_class: "nvme".to_owned(),
                lane: WalEvidenceLane::DeveloperSmoke,
            },
            reference: None,
            replay_proof_id: "proof_small_smoke".to_owned(),
            fsync_tail_slo: fsync_tail_slo(),
            measurements: vec![measurement(
                "parallel_epoch_group_commit",
                16,
                8,
                2_900.0,
                12_000.0,
                0.08,
                256.0,
                180.0,
                0,
                0,
                0,
                0,
                0,
                WalClaimState::MissingReference,
                WalMeasurementClassification::MissingReference,
            )],
            claim_state: WalClaimState::MissingReference,
            reproduction_command:
                "ffs-harness validate-wal-group-commit-gate --manifest benchmarks/wal_group_commit_gate_manifest.json"
                    .to_owned(),
            raw_logs: vec!["artifacts/wal/smoke/raw.log".to_owned()],
            artifact_paths: vec!["artifacts/wal/smoke/report.json".to_owned()],
        }
    }

    fn large_host(host_fingerprint: &str) -> WalHostObservation {
        WalHostObservation {
            host_fingerprint: host_fingerprint.to_owned(),
            cpu_cores_logical: 96,
            numa_nodes: Some(2),
            ram_total_gb: 512.0,
            ram_available_gb: 420.0,
            storage_class: "nvme".to_owned(),
            lane: WalEvidenceLane::PermissionedLargeHost,
        }
    }

    fn fsync_tail_slo() -> WalFsyncTailSlo {
        WalFsyncTailSlo {
            p99_pass_us: 2_000.0,
            p99_warn_us: 5_000.0,
            min_throughput_ops_per_sec: 30_000.0,
            max_replay_risk_ppm: 1_000.0,
            max_memory_footprint_mb: 1_024.0,
            max_durable_publish_lag_us: 400.0,
            max_p99_latency_cv: 0.20,
            max_order_violations: 0,
            max_checksum_failures: 0,
            max_boundary_violations: 0,
            max_cancelled_commit_losses: 0,
            max_partial_segment_replay_failures: 0,
        }
    }

    fn measurement(
        candidate_id: &str,
        batching_depth: u32,
        group_commit_width: u32,
        p99_fsync_latency_us: f64,
        throughput_ops_per_sec: f64,
        p99_latency_cv: f64,
        memory_footprint_mb: f64,
        durable_publish_lag_us: f64,
        checksum_failures: u32,
        observed_order_violations: u32,
        fdatasync_boundary_violations: u32,
        cancelled_commit_losses: u32,
        partial_segment_replay_failures: u32,
        claim_state: WalClaimState,
        expected_classification: WalMeasurementClassification,
    ) -> WalCandidateMeasurement {
        WalCandidateMeasurement {
            candidate_id: candidate_id.to_owned(),
            batching_depth,
            group_commit_width,
            p50_fsync_latency_us: p99_fsync_latency_us / 2.0,
            p99_fsync_latency_us,
            p99_latency_cv,
            throughput_ops_per_sec,
            replay_risk_ppm: 15.0,
            memory_footprint_mb,
            durable_publish_lag_us,
            checksum_failures,
            observed_order_violations,
            fdatasync_boundary_violations,
            cancelled_commit_losses,
            partial_segment_replay_failures,
            claim_state,
            expected_classification,
        }
    }

    fn expected_loss_controller() -> WalExpectedLossController {
        WalExpectedLossController {
            controller_id: "wal_expected_loss_v1".to_owned(),
            selected_candidate_id: "parallel_epoch_group_commit".to_owned(),
            target_throughput_ops_per_sec: 30_000.0,
            weights: WalExpectedLossWeights {
                p99_latency: 45.0,
                throughput_shortfall: 20.0,
                replay_risk: 30.0,
                memory_footprint: 0.001,
                durable_publish_lag: 5.0,
            },
            candidates: vec![
                WalExpectedLossCandidate {
                    candidate_id: "current_serial_wal".to_owned(),
                    scenario_id: "wal_append_256gb_authoritative".to_owned(),
                    batching_depth: 1,
                    p99_fsync_latency_us: 4_900.0,
                    throughput_ops_per_sec: 18_000.0,
                    replay_risk_ppm: 5.0,
                    memory_footprint_mb: 64.0,
                    durable_publish_lag_us: 80.0,
                },
                WalExpectedLossCandidate {
                    candidate_id: "parallel_epoch_group_commit".to_owned(),
                    scenario_id: "wal_append_256gb_authoritative".to_owned(),
                    batching_depth: 32,
                    p99_fsync_latency_us: 1_850.0,
                    throughput_ops_per_sec: 34_000.0,
                    replay_risk_ppm: 15.0,
                    memory_footprint_mb: 512.0,
                    durable_publish_lag_us: 210.0,
                },
                WalExpectedLossCandidate {
                    candidate_id: "deep_batch_fail".to_owned(),
                    scenario_id: "wal_append_256gb_authoritative".to_owned(),
                    batching_depth: 256,
                    p99_fsync_latency_us: 6_500.0,
                    throughput_ops_per_sec: 41_000.0,
                    replay_risk_ppm: 1_500.0,
                    memory_footprint_mb: 1_500.0,
                    durable_publish_lag_us: 1_900.0,
                },
            ],
        }
    }
}
