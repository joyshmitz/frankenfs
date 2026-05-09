#![allow(clippy::module_name_repetitions, clippy::too_many_lines)]
#![forbid(unsafe_code)]

//! Non-permissioned readiness-lab artifact contracts.
//!
//! These contracts let future agents rehearse large-host and xfstests evidence
//! flows without producing authoritative product evidence. The validator is
//! intentionally strict about advisory claim boundaries so simulated artifacts
//! cannot be promoted into proof-bundle or release-gate pass evidence.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub const READINESS_LAB_SCHEMA_VERSION: u32 = 1;
pub const READINESS_LAB_REPORT_SCHEMA_VERSION: u32 = 1;
pub const READINESS_LAB_ADVISORY_NOTICE: &str =
    "advisory readiness-lab material only; not product evidence";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessLabValidationConfig {
    pub manifest_path: String,
    pub reference_epoch_days: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabContractBundle {
    pub schema_version: u32,
    pub lab_id: String,
    pub generated_at_epoch_days: u32,
    pub advisory_notice: String,
    pub artifacts: Vec<ReadinessLabArtifactContract>,
    pub lane_plans: Vec<ReadinessLabLanePlan>,
    pub rch_assumptions: Vec<ReadinessLabRchAssumption>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabArtifactContract {
    pub artifact_id: String,
    pub artifact_kind: ReadinessLabArtifactKind,
    pub source_bead: String,
    pub path: String,
    pub product_evidence_claim: ReadinessLabProductEvidenceClaim,
    pub freshness: ReadinessLabFreshnessMetadata,
    pub required_fields: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessLabArtifactKind {
    SimulatedHostCapability,
    PlannedWorkloadLane,
    RchSchedulingPlan,
    EvidenceTruthGraph,
    PermissionedRunRehearsal,
    ReplayFixture,
    DashboardAdvisory,
}

impl ReadinessLabArtifactKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SimulatedHostCapability => "simulated_host_capability",
            Self::PlannedWorkloadLane => "planned_workload_lane",
            Self::RchSchedulingPlan => "rch_scheduling_plan",
            Self::EvidenceTruthGraph => "evidence_truth_graph",
            Self::PermissionedRunRehearsal => "permissioned_run_rehearsal",
            Self::ReplayFixture => "replay_fixture",
            Self::DashboardAdvisory => "dashboard_advisory",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessLabProductEvidenceClaim {
    None,
    AdvisoryOnly,
    ProductPassFail,
}

impl ReadinessLabProductEvidenceClaim {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::AdvisoryOnly => "advisory_only",
            Self::ProductPassFail => "product_pass_fail",
        }
    }

    #[must_use]
    pub const fn is_advisory(self) -> bool {
        matches!(self, Self::None | Self::AdvisoryOnly)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabFreshnessMetadata {
    pub observed_at_epoch_days: u32,
    pub max_age_days: u32,
    pub git_sha: String,
    pub host_class: ReadinessLabHostClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessLabHostClass {
    Synthetic,
    DeveloperSmoke,
    CandidateLargeHost,
    PermissionedLargeHost,
    NotApplicable,
}

impl ReadinessLabHostClass {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Synthetic => "synthetic",
            Self::DeveloperSmoke => "developer_smoke",
            Self::CandidateLargeHost => "candidate_large_host",
            Self::PermissionedLargeHost => "permissioned_large_host",
            Self::NotApplicable => "not_applicable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabLanePlan {
    pub lane_id: String,
    pub lane_kind: ReadinessLabLaneKind,
    pub expected_artifact_ids: Vec<String>,
    pub next_safe_command: String,
    pub permission_boundary: ReadinessLabPermissionBoundary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessLabLaneKind {
    XfstestsRehearsal,
    LargeHostSwarmSimulation,
    RchValidationDryRun,
    EvidenceTruthGraph,
    DashboardAdvisory,
    NumaP99Replay,
}

impl ReadinessLabLaneKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::XfstestsRehearsal => "xfstests_rehearsal",
            Self::LargeHostSwarmSimulation => "large_host_swarm_simulation",
            Self::RchValidationDryRun => "rch_validation_dry_run",
            Self::EvidenceTruthGraph => "evidence_truth_graph",
            Self::DashboardAdvisory => "dashboard_advisory",
            Self::NumaP99Replay => "numa_p99_replay",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessLabPermissionBoundary {
    NoPermissionNeeded,
    RequiresOperatorAck,
    RequiresLargeHostAck,
    RequiresXfstestsAck,
}

impl ReadinessLabPermissionBoundary {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NoPermissionNeeded => "no_permission_needed",
            Self::RequiresOperatorAck => "requires_operator_ack",
            Self::RequiresLargeHostAck => "requires_large_host_ack",
            Self::RequiresXfstestsAck => "requires_xfstests_ack",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabRchAssumption {
    pub assumption_id: String,
    pub command: String,
    pub target_dir: String,
    pub env_allowlist: Vec<String>,
    pub executes_cargo: bool,
    pub local_fallback_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessLabValidationReport {
    pub schema_version: u32,
    pub lab_id: String,
    pub manifest_path: String,
    pub valid: bool,
    pub artifact_count: usize,
    pub lane_count: usize,
    pub rch_assumption_count: usize,
    pub advisory_artifact_count: usize,
    pub stale_artifact_count: usize,
    pub future_artifact_count: usize,
    pub product_claim_violation_count: usize,
    pub missing_required_field_count: usize,
    pub duplicate_id_count: usize,
    pub errors: Vec<ReadinessLabFinding>,
    pub warnings: Vec<ReadinessLabFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessLabFinding {
    pub finding_id: String,
    pub severity: ReadinessLabFindingSeverity,
    pub message: String,
    pub artifact_id: Option<String>,
    pub lane_id: Option<String>,
    pub assumption_id: Option<String>,
    pub field: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessLabFindingSeverity {
    Warning,
    Error,
}

#[must_use]
pub fn validate_readiness_lab_contract_bundle(
    bundle: &ReadinessLabContractBundle,
    config: &ReadinessLabValidationConfig,
) -> ReadinessLabValidationReport {
    let mut validator = ReadinessLabValidator::new(bundle, config);
    validator.validate_bundle();
    validator.finish()
}

pub fn load_readiness_lab_contract_bundle(
    path: impl AsRef<Path>,
) -> Result<ReadinessLabContractBundle> {
    let path = path.as_ref();
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read readiness lab contract {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("failed to parse readiness lab contract {}", path.display()))
}

#[must_use]
pub fn render_readiness_lab_contract_markdown(report: &ReadinessLabValidationReport) -> String {
    let mut out = String::new();
    writeln!(&mut out, "# FrankenFS Readiness Lab Contract Report").ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "- Lab: `{}`", report.lab_id).ok();
    writeln!(&mut out, "- Manifest: `{}`", report.manifest_path).ok();
    writeln!(&mut out, "- Valid: `{}`", report.valid).ok();
    writeln!(&mut out, "- Artifacts: `{}`", report.artifact_count).ok();
    writeln!(&mut out, "- Lanes: `{}`", report.lane_count).ok();
    writeln!(
        &mut out,
        "- RCH assumptions: `{}`",
        report.rch_assumption_count
    )
    .ok();
    writeln!(
        &mut out,
        "- Advisory artifacts: `{}`",
        report.advisory_artifact_count
    )
    .ok();
    writeln!(
        &mut out,
        "- Product-claim violations: `{}`",
        report.product_claim_violation_count
    )
    .ok();
    writeln!(&mut out).ok();

    render_findings(&mut out, "Errors", &report.errors);
    render_findings(&mut out, "Warnings", &report.warnings);
    out
}

pub fn fail_on_readiness_lab_contract_errors(report: &ReadinessLabValidationReport) -> Result<()> {
    if report.valid {
        return Ok(());
    }
    let first = report
        .errors
        .first()
        .map_or("readiness lab contract failed validation", |finding| {
            finding.message.as_str()
        });
    anyhow::bail!(
        "readiness lab contract validation failed with {} error(s): {first}",
        report.errors.len()
    )
}

fn render_findings(out: &mut String, heading: &str, findings: &[ReadinessLabFinding]) {
    writeln!(out, "## {heading}").ok();
    writeln!(out).ok();
    if findings.is_empty() {
        writeln!(out, "- none").ok();
        writeln!(out).ok();
        return;
    }
    for finding in findings {
        let mut scope = Vec::new();
        if let Some(artifact_id) = &finding.artifact_id {
            scope.push(format!("artifact={artifact_id}"));
        }
        if let Some(lane_id) = &finding.lane_id {
            scope.push(format!("lane={lane_id}"));
        }
        if let Some(assumption_id) = &finding.assumption_id {
            scope.push(format!("assumption={assumption_id}"));
        }
        if let Some(field) = &finding.field {
            scope.push(format!("field={field}"));
        }
        if scope.is_empty() {
            writeln!(out, "- `{}`: {}", finding.finding_id, finding.message).ok();
        } else {
            writeln!(
                out,
                "- `{}` [{}]: {}",
                finding.finding_id,
                scope.join(", "),
                finding.message
            )
            .ok();
        }
    }
    writeln!(out).ok();
}

struct ReadinessLabValidator<'a> {
    bundle: &'a ReadinessLabContractBundle,
    config: &'a ReadinessLabValidationConfig,
    errors: Vec<ReadinessLabFinding>,
    warnings: Vec<ReadinessLabFinding>,
    advisory_artifact_count: usize,
    stale_artifact_count: usize,
    future_artifact_count: usize,
    product_claim_violation_count: usize,
    missing_required_field_count: usize,
    duplicate_id_count: usize,
}

impl<'a> ReadinessLabValidator<'a> {
    fn new(
        bundle: &'a ReadinessLabContractBundle,
        config: &'a ReadinessLabValidationConfig,
    ) -> Self {
        Self {
            bundle,
            config,
            errors: Vec::new(),
            warnings: Vec::new(),
            advisory_artifact_count: 0,
            stale_artifact_count: 0,
            future_artifact_count: 0,
            product_claim_violation_count: 0,
            missing_required_field_count: 0,
            duplicate_id_count: 0,
        }
    }

    fn validate_bundle(&mut self) {
        self.check_schema_and_identity();
        self.check_duplicates();
        let artifact_ids = self
            .bundle
            .artifacts
            .iter()
            .map(|artifact| artifact.artifact_id.as_str())
            .collect::<BTreeSet<_>>();
        for artifact in &self.bundle.artifacts {
            self.validate_artifact(artifact);
        }
        for lane in &self.bundle.lane_plans {
            self.validate_lane(lane, &artifact_ids);
        }
        for assumption in &self.bundle.rch_assumptions {
            self.validate_rch_assumption(assumption);
        }
    }

    fn check_schema_and_identity(&mut self) {
        if self.bundle.schema_version != READINESS_LAB_SCHEMA_VERSION {
            self.error(
                "unsupported_schema_version",
                format!(
                    "schema_version must be {READINESS_LAB_SCHEMA_VERSION}, got {}",
                    self.bundle.schema_version
                ),
                FindingScope::default().field("schema_version"),
            );
        }
        if self.bundle.lab_id.trim().is_empty() {
            self.error(
                "missing_lab_id",
                "lab_id must be non-empty",
                FindingScope::default().field("lab_id"),
            );
        }
        if self.bundle.generated_at_epoch_days == 0 {
            self.error(
                "missing_generated_at_epoch_days",
                "generated_at_epoch_days must be non-zero",
                FindingScope::default().field("generated_at_epoch_days"),
            );
        }
        if self.bundle.advisory_notice.trim() != READINESS_LAB_ADVISORY_NOTICE {
            self.error(
                "invalid_advisory_notice",
                format!("advisory_notice must be exactly {READINESS_LAB_ADVISORY_NOTICE:?}"),
                FindingScope::default().field("advisory_notice"),
            );
        }
    }

    fn check_duplicates(&mut self) {
        self.duplicate_id_count += duplicate_count(
            self.bundle
                .artifacts
                .iter()
                .map(|artifact| artifact.artifact_id.as_str()),
        );
        self.duplicate_id_count += duplicate_count(
            self.bundle
                .lane_plans
                .iter()
                .map(|lane| lane.lane_id.as_str()),
        );
        self.duplicate_id_count += duplicate_count(
            self.bundle
                .rch_assumptions
                .iter()
                .map(|assumption| assumption.assumption_id.as_str()),
        );
        if self.duplicate_id_count > 0 {
            self.error(
                "duplicate_ids",
                format!(
                    "readiness lab contract contains {} duplicate id(s)",
                    self.duplicate_id_count
                ),
                FindingScope::default(),
            );
        }
    }

    fn validate_artifact(&mut self, artifact: &ReadinessLabArtifactContract) {
        if artifact.artifact_id.trim().is_empty() {
            self.error(
                "missing_artifact_id",
                "artifact_id must be non-empty",
                FindingScope::default().field("artifact_id"),
            );
        }
        if !artifact.source_bead.starts_with("bd-") {
            self.error(
                "malformed_source_bead",
                "source_bead must look like bd-...",
                FindingScope::artifact(artifact.artifact_id.as_str()).field("source_bead"),
            );
        }
        if artifact.path.trim().is_empty() {
            self.error(
                "missing_artifact_path",
                "artifact path must be non-empty",
                FindingScope::artifact(artifact.artifact_id.as_str()).field("path"),
            );
        }
        if artifact.product_evidence_claim.is_advisory() {
            self.advisory_artifact_count += 1;
        } else {
            self.product_claim_violation_count += 1;
            self.error(
                "product_evidence_claim_violation",
                "readiness lab artifacts must not claim product pass/fail evidence",
                FindingScope::artifact(artifact.artifact_id.as_str())
                    .field("product_evidence_claim"),
            );
        }
        self.validate_required_fields(artifact);
        self.validate_freshness(artifact);
    }

    fn validate_required_fields(&mut self, artifact: &ReadinessLabArtifactContract) {
        if artifact.required_fields.is_empty() {
            self.missing_required_field_count += 1;
            self.error(
                "empty_required_fields",
                "required_fields must list the fields a future validator must inspect",
                FindingScope::artifact(artifact.artifact_id.as_str()).field("required_fields"),
            );
            return;
        }
        for field in &artifact.required_fields {
            if field.trim().is_empty() {
                self.missing_required_field_count += 1;
                self.error(
                    "blank_required_field",
                    "required_fields entries must be non-empty",
                    FindingScope::artifact(artifact.artifact_id.as_str()).field("required_fields"),
                );
            }
        }
    }

    fn validate_freshness(&mut self, artifact: &ReadinessLabArtifactContract) {
        let freshness = &artifact.freshness;
        if freshness.observed_at_epoch_days == 0 {
            self.error(
                "missing_observed_at_epoch_days",
                "freshness.observed_at_epoch_days must be non-zero",
                FindingScope::artifact(artifact.artifact_id.as_str())
                    .field("freshness.observed_at_epoch_days"),
            );
        }
        if freshness.max_age_days == 0 {
            self.error(
                "zero_max_age_days",
                "freshness.max_age_days must be greater than zero",
                FindingScope::artifact(artifact.artifact_id.as_str())
                    .field("freshness.max_age_days"),
            );
        }
        if freshness.git_sha.trim().len() < 7 {
            self.error(
                "missing_git_sha",
                "freshness.git_sha must include at least a short git SHA",
                FindingScope::artifact(artifact.artifact_id.as_str()).field("freshness.git_sha"),
            );
        }

        let Some(reference_epoch_days) = self.config.reference_epoch_days else {
            return;
        };
        if freshness.observed_at_epoch_days > reference_epoch_days {
            self.future_artifact_count += 1;
            self.error(
                "future_artifact_timestamp",
                "readiness lab artifact timestamp is newer than the reference date",
                FindingScope::artifact(artifact.artifact_id.as_str())
                    .field("freshness.observed_at_epoch_days"),
            );
        }
        if freshness
            .observed_at_epoch_days
            .saturating_add(freshness.max_age_days)
            < reference_epoch_days
        {
            self.stale_artifact_count += 1;
            self.error(
                "stale_artifact",
                "readiness lab artifact is older than its max_age_days window",
                FindingScope::artifact(artifact.artifact_id.as_str()).field("freshness"),
            );
        }
    }

    fn validate_lane(&mut self, lane: &ReadinessLabLanePlan, artifact_ids: &BTreeSet<&str>) {
        if lane.lane_id.trim().is_empty() {
            self.error(
                "missing_lane_id",
                "lane_id must be non-empty",
                FindingScope::default().field("lane_id"),
            );
        }
        if lane.next_safe_command.trim().is_empty() {
            self.error(
                "missing_next_safe_command",
                "next_safe_command must be non-empty",
                FindingScope::lane(lane.lane_id.as_str()).field("next_safe_command"),
            );
        }
        if lane.expected_artifact_ids.is_empty() {
            self.error(
                "empty_expected_artifact_ids",
                "lane must reference at least one expected artifact",
                FindingScope::lane(lane.lane_id.as_str()).field("expected_artifact_ids"),
            );
        }
        for artifact_id in &lane.expected_artifact_ids {
            if !artifact_ids.contains(artifact_id.as_str()) {
                self.error(
                    "missing_expected_artifact",
                    format!("lane references unknown artifact_id {artifact_id:?}"),
                    FindingScope::lane(lane.lane_id.as_str()).field("expected_artifact_ids"),
                );
            }
        }
    }

    fn validate_rch_assumption(&mut self, assumption: &ReadinessLabRchAssumption) {
        if assumption.assumption_id.trim().is_empty() {
            self.error(
                "missing_assumption_id",
                "assumption_id must be non-empty",
                FindingScope::default().field("assumption_id"),
            );
        }
        if assumption.command.trim().is_empty() {
            self.error(
                "missing_rch_command",
                "RCH assumption command must be non-empty",
                FindingScope::assumption(assumption.assumption_id.as_str()).field("command"),
            );
        }
        if assumption.target_dir.trim().is_empty() {
            self.error(
                "missing_target_dir",
                "RCH assumption target_dir must be non-empty",
                FindingScope::assumption(assumption.assumption_id.as_str()).field("target_dir"),
            );
        }
        if assumption.local_fallback_allowed {
            self.error(
                "local_fallback_allowed",
                "readiness lab contracts must reject local cargo fallback for heavy lanes",
                FindingScope::assumption(assumption.assumption_id.as_str())
                    .field("local_fallback_allowed"),
            );
        }
        if assumption.executes_cargo {
            if !assumption.command.contains("rch exec") {
                self.error(
                    "cargo_without_rch_exec",
                    "cargo-executing assumptions must route through rch exec",
                    FindingScope::assumption(assumption.assumption_id.as_str()).field("command"),
                );
            }
            if !assumption
                .env_allowlist
                .iter()
                .any(|entry| entry == "CARGO_TARGET_DIR")
            {
                self.error(
                    "missing_cargo_target_dir_allowlist",
                    "cargo-executing assumptions must allowlist CARGO_TARGET_DIR",
                    FindingScope::assumption(assumption.assumption_id.as_str())
                        .field("env_allowlist"),
                );
            }
        }
    }

    fn finish(self) -> ReadinessLabValidationReport {
        ReadinessLabValidationReport {
            schema_version: READINESS_LAB_REPORT_SCHEMA_VERSION,
            lab_id: self.bundle.lab_id.clone(),
            manifest_path: self.config.manifest_path.clone(),
            valid: self.errors.is_empty(),
            artifact_count: self.bundle.artifacts.len(),
            lane_count: self.bundle.lane_plans.len(),
            rch_assumption_count: self.bundle.rch_assumptions.len(),
            advisory_artifact_count: self.advisory_artifact_count,
            stale_artifact_count: self.stale_artifact_count,
            future_artifact_count: self.future_artifact_count,
            product_claim_violation_count: self.product_claim_violation_count,
            missing_required_field_count: self.missing_required_field_count,
            duplicate_id_count: self.duplicate_id_count,
            errors: self.errors,
            warnings: self.warnings,
        }
    }

    fn error(
        &mut self,
        finding_id: impl Into<String>,
        message: impl Into<String>,
        scope: FindingScope,
    ) {
        self.errors.push(scope.into_finding(
            finding_id.into(),
            ReadinessLabFindingSeverity::Error,
            message.into(),
        ));
    }
}

#[derive(Debug, Default)]
struct FindingScope {
    artifact_id: Option<String>,
    lane_id: Option<String>,
    assumption_id: Option<String>,
    field: Option<String>,
}

impl FindingScope {
    fn artifact(artifact_id: &str) -> Self {
        Self {
            artifact_id: Some(artifact_id.to_owned()),
            ..Self::default()
        }
    }

    fn lane(lane_id: &str) -> Self {
        Self {
            lane_id: Some(lane_id.to_owned()),
            ..Self::default()
        }
    }

    fn assumption(assumption_id: &str) -> Self {
        Self {
            assumption_id: Some(assumption_id.to_owned()),
            ..Self::default()
        }
    }

    fn field(mut self, field: &str) -> Self {
        self.field = Some(field.to_owned());
        self
    }

    fn into_finding(
        self,
        finding_id: String,
        severity: ReadinessLabFindingSeverity,
        message: String,
    ) -> ReadinessLabFinding {
        ReadinessLabFinding {
            finding_id,
            severity,
            message,
            artifact_id: self.artifact_id,
            lane_id: self.lane_id,
            assumption_id: self.assumption_id,
            field: self.field,
        }
    }
}

fn duplicate_count<'a>(ids: impl Iterator<Item = &'a str>) -> usize {
    let mut seen = BTreeSet::new();
    let mut duplicates = BTreeSet::new();
    for id in ids {
        if id.trim().is_empty() {
            continue;
        }
        if !seen.insert(id) {
            duplicates.insert(id);
        }
    }
    duplicates.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bundle() -> ReadinessLabContractBundle {
        ReadinessLabContractBundle {
            schema_version: READINESS_LAB_SCHEMA_VERSION,
            lab_id: "readiness-lab-fixture".to_owned(),
            generated_at_epoch_days: 20_000,
            advisory_notice: READINESS_LAB_ADVISORY_NOTICE.to_owned(),
            artifacts: vec![
                ReadinessLabArtifactContract {
                    artifact_id: "host-sim".to_owned(),
                    artifact_kind: ReadinessLabArtifactKind::SimulatedHostCapability,
                    source_bead: "bd-4532j".to_owned(),
                    path: "artifacts/readiness-lab/host-sim.json".to_owned(),
                    product_evidence_claim: ReadinessLabProductEvidenceClaim::None,
                    freshness: sample_freshness(),
                    required_fields: vec![
                        "logical_cpus".to_owned(),
                        "ram_gib".to_owned(),
                        "numa_nodes".to_owned(),
                    ],
                },
                ReadinessLabArtifactContract {
                    artifact_id: "rch-plan".to_owned(),
                    artifact_kind: ReadinessLabArtifactKind::RchSchedulingPlan,
                    source_bead: "bd-hejjl".to_owned(),
                    path: "artifacts/readiness-lab/rch-plan.json".to_owned(),
                    product_evidence_claim: ReadinessLabProductEvidenceClaim::AdvisoryOnly,
                    freshness: sample_freshness(),
                    required_fields: vec![
                        "command".to_owned(),
                        "target_dir".to_owned(),
                        "env_allowlist".to_owned(),
                    ],
                },
            ],
            lane_plans: vec![ReadinessLabLanePlan {
                lane_id: "swarm-simulation".to_owned(),
                lane_kind: ReadinessLabLaneKind::LargeHostSwarmSimulation,
                expected_artifact_ids: vec!["host-sim".to_owned(), "rch-plan".to_owned()],
                next_safe_command:
                    "rch exec -- cargo run -p ffs-harness -- validate-readiness-lab-contracts"
                        .to_owned(),
                permission_boundary: ReadinessLabPermissionBoundary::NoPermissionNeeded,
            }],
            rch_assumptions: vec![ReadinessLabRchAssumption {
                assumption_id: "harness-unit-tests".to_owned(),
                command: "rch exec -- cargo test -p ffs-harness readiness_lab".to_owned(),
                target_dir: "/data/tmp/rch_target_frankenfs_readiness_lab".to_owned(),
                env_allowlist: vec!["CARGO_TARGET_DIR".to_owned()],
                executes_cargo: true,
                local_fallback_allowed: false,
            }],
        }
    }

    fn sample_freshness() -> ReadinessLabFreshnessMetadata {
        ReadinessLabFreshnessMetadata {
            observed_at_epoch_days: 20_000,
            max_age_days: 7,
            git_sha: "1234567".to_owned(),
            host_class: ReadinessLabHostClass::Synthetic,
        }
    }

    fn validate(bundle: &ReadinessLabContractBundle) -> ReadinessLabValidationReport {
        validate_readiness_lab_contract_bundle(
            bundle,
            &ReadinessLabValidationConfig {
                manifest_path: "fixture.json".to_owned(),
                reference_epoch_days: Some(20_001),
            },
        )
    }

    #[test]
    fn valid_contract_bundle_passes_and_renders_markdown() {
        let report = validate(&sample_bundle());

        assert!(report.valid);
        assert_eq!(report.artifact_count, 2);
        assert_eq!(report.advisory_artifact_count, 2);
        assert_eq!(report.product_claim_violation_count, 0);
        let markdown = render_readiness_lab_contract_markdown(&report);
        assert!(markdown.contains("FrankenFS Readiness Lab Contract Report"));
        assert!(markdown.contains("Product-claim violations: `0`"));
    }

    #[test]
    fn serialization_roundtrip_preserves_bundle() -> serde_json::Result<()> {
        let bundle = sample_bundle();
        let encoded = serde_json::to_string_pretty(&bundle)?;
        let decoded = serde_json::from_str::<ReadinessLabContractBundle>(&encoded)?;

        assert_eq!(decoded, bundle);
        Ok(())
    }

    #[test]
    fn product_pass_fail_claim_is_rejected() {
        let mut bundle = sample_bundle();
        bundle.artifacts[0].product_evidence_claim =
            ReadinessLabProductEvidenceClaim::ProductPassFail;

        let report = validate(&bundle);

        assert!(!report.valid);
        assert_eq!(report.product_claim_violation_count, 1);
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.finding_id == "product_evidence_claim_violation")
        );
    }

    #[test]
    fn future_and_stale_artifact_timestamps_fail_closed() {
        let mut bundle = sample_bundle();
        bundle.artifacts[0].freshness.observed_at_epoch_days = 20_010;
        bundle.artifacts[1].freshness.observed_at_epoch_days = 19_900;

        let report = validate(&bundle);

        assert!(!report.valid);
        assert_eq!(report.future_artifact_count, 1);
        assert_eq!(report.stale_artifact_count, 1);
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.finding_id == "future_artifact_timestamp")
        );
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.finding_id == "stale_artifact")
        );
    }

    #[test]
    fn serde_rejects_unknown_manifest_fields() {
        let raw = r#"{
            "schema_version": 1,
            "lab_id": "fixture",
            "generated_at_epoch_days": 20000,
            "advisory_notice": "advisory readiness-lab material only; not product evidence",
            "artifacts": [],
            "lane_plans": [],
            "rch_assumptions": [],
            "unexpected": true
        }"#;

        let err = serde_json::from_str::<ReadinessLabContractBundle>(raw)
            .expect_err("unknown fields must fail closed");

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn duplicate_ids_missing_refs_and_required_fields_are_rejected() {
        let mut bundle = sample_bundle();
        bundle.artifacts[1].artifact_id = "host-sim".to_owned();
        bundle.artifacts[0].required_fields.clear();
        bundle.lane_plans[0]
            .expected_artifact_ids
            .push("missing-artifact".to_owned());

        let report = validate(&bundle);

        assert!(!report.valid);
        assert_eq!(report.duplicate_id_count, 1);
        assert_eq!(report.missing_required_field_count, 1);
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.finding_id == "missing_expected_artifact")
        );
    }

    #[test]
    fn rch_assumptions_reject_local_fallback_and_bare_cargo() {
        let mut bundle = sample_bundle();
        bundle.rch_assumptions[0].command = "cargo test -p ffs-harness readiness_lab".to_owned();
        bundle.rch_assumptions[0].env_allowlist.clear();
        bundle.rch_assumptions[0].local_fallback_allowed = true;

        let report = validate(&bundle);

        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.finding_id == "local_fallback_allowed")
        );
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.finding_id == "cargo_without_rch_exec")
        );
        assert!(
            report
                .errors
                .iter()
                .any(|finding| finding.finding_id == "missing_cargo_target_dir_allowlist")
        );
    }
}
