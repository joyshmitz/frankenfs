#![allow(clippy::module_name_repetitions, clippy::too_many_lines)]
#![forbid(unsafe_code)]

//! Non-permissioned readiness-lab artifact contracts.
//!
//! These contracts let future agents rehearse large-host and xfstests evidence
//! flows without producing authoritative product evidence. The validator is
//! intentionally strict about advisory claim boundaries so simulated artifacts
//! cannot be promoted into proof-bundle or release-gate pass evidence.

use crate::permissioned_campaign_broker::{
    SwarmCapabilityCalibrationArtifactPlan, SwarmCapabilityCalibrationFuse,
    SwarmCapabilityCalibrationFuseState, SwarmCapabilityCalibrationHost,
    SwarmCapabilityCalibrationIsolation, SwarmCapabilityCalibrationManifest,
    SwarmCapabilityCalibrationResourceCaps, SwarmCapabilityCalibrationValidationConfig,
    SwarmCapabilityCalibrationWorker, validate_swarm_capability_calibration_manifest,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub const READINESS_LAB_SCHEMA_VERSION: u32 = 1;
pub const READINESS_LAB_REPORT_SCHEMA_VERSION: u32 = 1;
pub const READINESS_LAB_HOST_SIMULATION_REPORT_SCHEMA_VERSION: u32 = 1;
pub const READINESS_LAB_ADVISORY_NOTICE: &str =
    "advisory readiness-lab material only; not product evidence";
pub const READINESS_LAB_NO_PRODUCT_EVIDENCE_CLAIM: &str = "none";

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessLabHostSimulationConfig {
    pub manifest_path: String,
    pub reference_epoch_days: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessLabHostSimulationManifest {
    pub schema_version: u32,
    pub simulation_id: String,
    pub generated_at_epoch_days: u32,
    pub advisory_notice: String,
    pub source_bead: String,
    pub real_campaign_bead: String,
    pub expected_artifact_root: String,
    pub release_gate_policy_path: String,
    pub hosts: Vec<ReadinessLabSyntheticHostInventory>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ReadinessLabSyntheticHostInventory {
    pub host_id: String,
    pub observed_at_epoch_days: u32,
    pub max_age_days: u32,
    pub logical_cpus: u32,
    pub ram_total_gib: u32,
    pub ram_available_gib: u32,
    pub numa_topology_visible: bool,
    pub numa_nodes: Option<u32>,
    pub storage_class: String,
    pub storage_visible: bool,
    pub fuse_available: bool,
    pub runner_configured: bool,
    pub swarm_ack_configured: bool,
    pub rch_worker_identity: String,
    pub worker_fingerprint: String,
    pub queue_isolation: ReadinessLabSimulationQueueIsolation,
    pub target_dir_isolated: bool,
    pub target_dir: String,
    pub artifact_root: String,
    pub max_threads: u32,
    pub max_memory_gib: u32,
    pub max_temp_storage_gib: u32,
    pub max_queue_depth: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessLabSimulationQueueIsolation {
    Dedicated,
    Shared,
    Unknown,
}

impl ReadinessLabSimulationQueueIsolation {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Dedicated => "dedicated",
            Self::Shared => "shared",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessLabHostSimulationReport {
    pub schema_version: u32,
    pub simulation_id: String,
    pub manifest_path: String,
    pub valid: bool,
    pub product_evidence_claim: String,
    pub release_gate_effect: String,
    pub source_bead: String,
    pub real_campaign_bead: String,
    pub expected_artifact_root: String,
    pub host_count: usize,
    pub candidate_count: usize,
    pub small_host_count: usize,
    pub capability_downgrade_count: usize,
    pub blocked_count: usize,
    pub stale_inventory_count: usize,
    pub future_inventory_count: usize,
    pub rows: Vec<ReadinessLabHostSimulationRow>,
    pub errors: Vec<ReadinessLabFinding>,
    pub warnings: Vec<ReadinessLabFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ReadinessLabHostSimulationRow {
    pub host_id: String,
    pub valid: bool,
    pub classification: String,
    pub candidate_for_authorized_run: bool,
    pub product_evidence_claim: String,
    pub release_gate_effect: String,
    pub logical_cpus: u32,
    pub ram_total_gib: u32,
    pub numa_topology_visible: bool,
    pub numa_nodes: Option<u32>,
    pub storage_visible: bool,
    pub fuse_available: bool,
    pub runner_configured: bool,
    pub swarm_ack_configured: bool,
    pub worker_identity: String,
    pub queue_isolation: String,
    pub target_dir_isolated: bool,
    pub artifact_root: String,
    pub blocker_count: usize,
    pub blockers: Vec<String>,
    pub downgrade_count: usize,
    pub downgrade_reasons: Vec<String>,
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

pub fn load_readiness_lab_host_simulation_manifest(
    path: impl AsRef<Path>,
) -> Result<ReadinessLabHostSimulationManifest> {
    let path = path.as_ref();
    let text = fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read readiness lab host simulation {}",
            path.display()
        )
    })?;
    serde_json::from_str(&text).with_context(|| {
        format!(
            "failed to parse readiness lab host simulation {}",
            path.display()
        )
    })
}

#[must_use]
pub fn simulate_readiness_lab_hosts(
    manifest: &ReadinessLabHostSimulationManifest,
    config: &ReadinessLabHostSimulationConfig,
) -> ReadinessLabHostSimulationReport {
    let mut errors = Vec::new();
    let warnings = Vec::new();
    validate_host_simulation_manifest(manifest, &mut errors);

    let mut seen_hosts = BTreeSet::new();
    for host in &manifest.hosts {
        if !host.host_id.trim().is_empty() && !seen_hosts.insert(host.host_id.as_str()) {
            push_readiness_lab_finding(
                &mut errors,
                "duplicate_host_id",
                "host_id values must be unique",
                FindingScope::artifact(host.host_id.as_str()).field("host_id"),
            );
        }
    }

    let mut rows = Vec::new();
    let mut candidate_count = 0;
    let mut small_host_count = 0;
    let mut capability_downgrade_count = 0;
    let mut blocked_count = 0;
    let mut stale_inventory_count = 0;
    let mut future_inventory_count = 0;

    for host in &manifest.hosts {
        let row = simulate_readiness_lab_host(manifest, host, config);
        if row
            .blockers
            .iter()
            .any(|blocker| blocker.starts_with("stale_inventory"))
        {
            stale_inventory_count += 1;
        }
        if row
            .blockers
            .iter()
            .any(|blocker| blocker.starts_with("future_inventory"))
        {
            future_inventory_count += 1;
        }
        match row.classification.as_str() {
            "authoritative_large_host_candidate" => candidate_count += 1,
            "small_host_smoke" => small_host_count += 1,
            "capability_downgraded_smoke" => capability_downgrade_count += 1,
            "blocked" => blocked_count += 1,
            _ => {}
        }
        rows.push(row);
    }

    ReadinessLabHostSimulationReport {
        schema_version: READINESS_LAB_HOST_SIMULATION_REPORT_SCHEMA_VERSION,
        simulation_id: manifest.simulation_id.clone(),
        manifest_path: config.manifest_path.clone(),
        valid: errors.is_empty(),
        product_evidence_claim: READINESS_LAB_NO_PRODUCT_EVIDENCE_CLAIM.to_owned(),
        release_gate_effect: format!(
            "simulator output is advisory only; swarm.responsiveness remains hidden or blocked until {} records executed large-host proof-bundle lanes and release-gate output",
            manifest.real_campaign_bead
        ),
        source_bead: manifest.source_bead.clone(),
        real_campaign_bead: manifest.real_campaign_bead.clone(),
        expected_artifact_root: manifest.expected_artifact_root.clone(),
        host_count: manifest.hosts.len(),
        candidate_count,
        small_host_count,
        capability_downgrade_count,
        blocked_count,
        stale_inventory_count,
        future_inventory_count,
        rows,
        errors,
        warnings,
    }
}

#[must_use]
pub fn render_readiness_lab_host_simulation_markdown(
    report: &ReadinessLabHostSimulationReport,
) -> String {
    let mut out = String::new();
    writeln!(&mut out, "# FrankenFS Readiness Lab Host Simulation").ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "- Simulation: `{}`", report.simulation_id).ok();
    writeln!(&mut out, "- Manifest: `{}`", report.manifest_path).ok();
    writeln!(&mut out, "- Valid: `{}`", report.valid).ok();
    writeln!(
        &mut out,
        "- Product evidence claim: `{}`",
        report.product_evidence_claim
    )
    .ok();
    writeln!(
        &mut out,
        "- Release-gate effect: {}",
        report.release_gate_effect
    )
    .ok();
    writeln!(&mut out, "- Hosts: `{}`", report.host_count).ok();
    writeln!(&mut out, "- Candidates: `{}`", report.candidate_count).ok();
    writeln!(
        &mut out,
        "- Small-host smoke: `{}`",
        report.small_host_count
    )
    .ok();
    writeln!(
        &mut out,
        "- Capability downgrades: `{}`",
        report.capability_downgrade_count
    )
    .ok();
    writeln!(&mut out, "- Blocked: `{}`", report.blocked_count).ok();
    writeln!(&mut out).ok();
    writeln!(
        &mut out,
        "| host | classification | candidate | cpu | ram_gib | numa | runner | ack | blockers | downgrades |"
    )
    .ok();
    writeln!(&mut out, "|---|---|---:|---:|---:|---|---|---|---:|---:|").ok();
    for row in &report.rows {
        let numa = row.numa_nodes.map_or_else(
            || "missing".to_owned(),
            |nodes| {
                if row.numa_topology_visible {
                    nodes.to_string()
                } else {
                    format!("{nodes} (hidden)")
                }
            },
        );
        writeln!(
            &mut out,
            "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |",
            row.host_id,
            row.classification,
            row.candidate_for_authorized_run,
            row.logical_cpus,
            row.ram_total_gib,
            numa,
            row.runner_configured,
            row.swarm_ack_configured,
            row.blocker_count,
            row.downgrade_count
        )
        .ok();
    }
    writeln!(&mut out).ok();
    render_findings(&mut out, "Errors", &report.errors);
    render_findings(&mut out, "Warnings", &report.warnings);
    out
}

pub fn fail_on_readiness_lab_host_simulation_errors(
    report: &ReadinessLabHostSimulationReport,
) -> Result<()> {
    if report.valid {
        return Ok(());
    }
    let first = report.errors.first().map_or(
        "readiness lab host simulation failed validation",
        |finding| finding.message.as_str(),
    );
    anyhow::bail!(
        "readiness lab host simulation validation failed with {} error(s): {first}",
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

fn validate_host_simulation_manifest(
    manifest: &ReadinessLabHostSimulationManifest,
    errors: &mut Vec<ReadinessLabFinding>,
) {
    if manifest.schema_version != READINESS_LAB_SCHEMA_VERSION {
        push_readiness_lab_finding(
            errors,
            "unsupported_schema_version",
            format!(
                "schema_version must be {READINESS_LAB_SCHEMA_VERSION}, got {}",
                manifest.schema_version
            ),
            FindingScope::default().field("schema_version"),
        );
    }
    if manifest.simulation_id.trim().is_empty() {
        push_readiness_lab_finding(
            errors,
            "missing_simulation_id",
            "simulation_id must be non-empty",
            FindingScope::default().field("simulation_id"),
        );
    }
    if manifest.generated_at_epoch_days == 0 {
        push_readiness_lab_finding(
            errors,
            "missing_generated_at_epoch_days",
            "generated_at_epoch_days must be non-zero",
            FindingScope::default().field("generated_at_epoch_days"),
        );
    }
    if manifest.advisory_notice.trim() != READINESS_LAB_ADVISORY_NOTICE {
        push_readiness_lab_finding(
            errors,
            "invalid_advisory_notice",
            format!("advisory_notice must be exactly {READINESS_LAB_ADVISORY_NOTICE:?}"),
            FindingScope::default().field("advisory_notice"),
        );
    }
    if !manifest.source_bead.starts_with("bd-") {
        push_readiness_lab_finding(
            errors,
            "malformed_source_bead",
            "source_bead must look like bd-...",
            FindingScope::default().field("source_bead"),
        );
    }
    if !manifest.real_campaign_bead.starts_with("bd-") {
        push_readiness_lab_finding(
            errors,
            "malformed_real_campaign_bead",
            "real_campaign_bead must look like bd-...",
            FindingScope::default().field("real_campaign_bead"),
        );
    }
    if manifest.expected_artifact_root.trim().is_empty() {
        push_readiness_lab_finding(
            errors,
            "missing_expected_artifact_root",
            "expected_artifact_root must be non-empty",
            FindingScope::default().field("expected_artifact_root"),
        );
    }
    if manifest.release_gate_policy_path.trim().is_empty() {
        push_readiness_lab_finding(
            errors,
            "missing_release_gate_policy_path",
            "release_gate_policy_path must be non-empty",
            FindingScope::default().field("release_gate_policy_path"),
        );
    }
    if manifest.hosts.is_empty() {
        push_readiness_lab_finding(
            errors,
            "empty_host_matrix",
            "hosts must include at least one synthetic inventory row",
            FindingScope::default().field("hosts"),
        );
    }
    for host in &manifest.hosts {
        validate_synthetic_host_inventory(host, errors);
    }
}

fn validate_synthetic_host_inventory(
    host: &ReadinessLabSyntheticHostInventory,
    errors: &mut Vec<ReadinessLabFinding>,
) {
    let scope = || FindingScope::artifact(host.host_id.as_str());
    if host.host_id.trim().is_empty() {
        push_readiness_lab_finding(
            errors,
            "missing_host_id",
            "host_id must be non-empty",
            FindingScope::default().field("host_id"),
        );
    }
    if host.observed_at_epoch_days == 0 {
        push_readiness_lab_finding(
            errors,
            "missing_observed_at_epoch_days",
            "observed_at_epoch_days must be non-zero",
            scope().field("observed_at_epoch_days"),
        );
    }
    if host.max_age_days == 0 {
        push_readiness_lab_finding(
            errors,
            "zero_max_age_days",
            "max_age_days must be greater than zero",
            scope().field("max_age_days"),
        );
    }
    if host.storage_class.trim().is_empty() {
        push_readiness_lab_finding(
            errors,
            "missing_storage_class",
            "storage_class must be non-empty",
            scope().field("storage_class"),
        );
    }
    if host.rch_worker_identity.trim().is_empty() {
        push_readiness_lab_finding(
            errors,
            "missing_rch_worker_identity",
            "rch_worker_identity must be non-empty",
            scope().field("rch_worker_identity"),
        );
    }
    if host.worker_fingerprint.trim().is_empty() {
        push_readiness_lab_finding(
            errors,
            "missing_worker_fingerprint",
            "worker_fingerprint must be non-empty",
            scope().field("worker_fingerprint"),
        );
    }
    if host.target_dir.trim().is_empty() {
        push_readiness_lab_finding(
            errors,
            "missing_target_dir",
            "target_dir must be non-empty",
            scope().field("target_dir"),
        );
    }
    if host.artifact_root.trim().is_empty() {
        push_readiness_lab_finding(
            errors,
            "missing_artifact_root",
            "artifact_root must be non-empty",
            scope().field("artifact_root"),
        );
    }
    if host.max_threads == 0 {
        push_readiness_lab_finding(
            errors,
            "zero_max_threads",
            "max_threads must be greater than zero",
            scope().field("max_threads"),
        );
    }
    if host.max_memory_gib == 0 {
        push_readiness_lab_finding(
            errors,
            "zero_max_memory_gib",
            "max_memory_gib must be greater than zero",
            scope().field("max_memory_gib"),
        );
    }
    if host.max_temp_storage_gib == 0 {
        push_readiness_lab_finding(
            errors,
            "zero_max_temp_storage_gib",
            "max_temp_storage_gib must be greater than zero",
            scope().field("max_temp_storage_gib"),
        );
    }
    if host.max_queue_depth == 0 {
        push_readiness_lab_finding(
            errors,
            "zero_max_queue_depth",
            "max_queue_depth must be greater than zero",
            scope().field("max_queue_depth"),
        );
    }
}

fn simulate_readiness_lab_host(
    manifest: &ReadinessLabHostSimulationManifest,
    host: &ReadinessLabSyntheticHostInventory,
    config: &ReadinessLabHostSimulationConfig,
) -> ReadinessLabHostSimulationRow {
    let calibration_manifest = calibration_manifest_for_host(manifest, host);
    let calibration_report = validate_swarm_capability_calibration_manifest(
        &calibration_manifest,
        &SwarmCapabilityCalibrationValidationConfig {
            reference_epoch_days: config
                .reference_epoch_days
                .unwrap_or(manifest.generated_at_epoch_days),
        },
    );
    let mut blockers = calibration_report.blockers;
    let mut downgrade_reasons = calibration_report.downgrade_reasons;

    if !host.runner_configured {
        blockers.push("permissioned_runner_configured=false".to_owned());
    }
    if !host.swarm_ack_configured {
        blockers.push("swarm_real_run_ack_configured=false".to_owned());
    }
    if !host.storage_visible {
        downgrade_reasons.push("storage_visible=false".to_owned());
    }
    if let Some(reference_epoch_days) = config.reference_epoch_days {
        if host.observed_at_epoch_days > reference_epoch_days {
            blockers.push(format!(
                "future_inventory observed_at_epoch_days={} reference_epoch_days={reference_epoch_days}",
                host.observed_at_epoch_days
            ));
        }
        if host
            .observed_at_epoch_days
            .saturating_add(host.max_age_days)
            < reference_epoch_days
        {
            blockers.push(format!(
                "stale_inventory observed_at_epoch_days={} max_age_days={} reference_epoch_days={reference_epoch_days}",
                host.observed_at_epoch_days, host.max_age_days
            ));
        }
    }

    let mut classification = calibration_report.classification;
    if !calibration_report.valid || !blockers.is_empty() {
        "blocked".clone_into(&mut classification);
    } else if classification == "authoritative_large_host_candidate"
        && !downgrade_reasons.is_empty()
    {
        "capability_downgraded_smoke".clone_into(&mut classification);
    }
    let candidate_for_authorized_run =
        classification == "authoritative_large_host_candidate" && blockers.is_empty();
    let blocker_count = blockers.len();
    let downgrade_count = downgrade_reasons.len();

    ReadinessLabHostSimulationRow {
        host_id: host.host_id.clone(),
        valid: calibration_report.valid,
        classification,
        candidate_for_authorized_run,
        product_evidence_claim: READINESS_LAB_NO_PRODUCT_EVIDENCE_CLAIM.to_owned(),
        release_gate_effect: calibration_report.release_gate_effect,
        logical_cpus: host.logical_cpus,
        ram_total_gib: host.ram_total_gib,
        numa_topology_visible: host.numa_topology_visible,
        numa_nodes: host.numa_nodes,
        storage_visible: host.storage_visible,
        fuse_available: host.fuse_available,
        runner_configured: host.runner_configured,
        swarm_ack_configured: host.swarm_ack_configured,
        worker_identity: host.rch_worker_identity.clone(),
        queue_isolation: host.queue_isolation.label().to_owned(),
        target_dir_isolated: host.target_dir_isolated,
        artifact_root: host.artifact_root.clone(),
        blocker_count,
        blockers,
        downgrade_count,
        downgrade_reasons,
    }
}

fn calibration_manifest_for_host(
    manifest: &ReadinessLabHostSimulationManifest,
    host: &ReadinessLabSyntheticHostInventory,
) -> SwarmCapabilityCalibrationManifest {
    SwarmCapabilityCalibrationManifest {
        schema_version: READINESS_LAB_SCHEMA_VERSION,
        packet_id: format!("{}-{}", manifest.simulation_id, host.host_id),
        generated_at: manifest.generated_at_epoch_days.to_string(),
        target_beads: vec![
            manifest.source_bead.clone(),
            manifest.real_campaign_bead.clone(),
        ],
        host: SwarmCapabilityCalibrationHost {
            logical_cpus: host.logical_cpus,
            ram_total_gib: f64::from(host.ram_total_gib),
            ram_available_gib: f64::from(host.ram_available_gib),
            numa_topology_visible: host.numa_topology_visible,
            numa_nodes: host.numa_nodes,
            storage_class: host.storage_class.clone(),
            fuse: SwarmCapabilityCalibrationFuse {
                state: if host.fuse_available {
                    SwarmCapabilityCalibrationFuseState::Available
                } else {
                    SwarmCapabilityCalibrationFuseState::Missing
                },
                detail: if host.fuse_available {
                    "synthetic readiness-lab inventory reports FUSE available".to_owned()
                } else {
                    "synthetic readiness-lab inventory reports FUSE missing".to_owned()
                },
            },
        },
        worker: SwarmCapabilityCalibrationWorker {
            rch_worker_identity: host.rch_worker_identity.clone(),
            worker_fingerprint: host.worker_fingerprint.clone(),
            worker_fingerprint_observed_at_epoch_days: host.observed_at_epoch_days,
            worker_fingerprint_max_age_days: host.max_age_days,
            queue_isolation: match host.queue_isolation {
                ReadinessLabSimulationQueueIsolation::Dedicated => {
                    SwarmCapabilityCalibrationIsolation::Dedicated
                }
                ReadinessLabSimulationQueueIsolation::Shared => {
                    SwarmCapabilityCalibrationIsolation::Shared
                }
                ReadinessLabSimulationQueueIsolation::Unknown => {
                    SwarmCapabilityCalibrationIsolation::Unknown
                }
            },
            target_dir_isolated: host.target_dir_isolated,
            target_dir: host.target_dir.clone(),
        },
        artifact_plan: SwarmCapabilityCalibrationArtifactPlan {
            expected_artifact_root: manifest.expected_artifact_root.clone(),
            observed_artifact_root: host.artifact_root.clone(),
        },
        resource_caps: SwarmCapabilityCalibrationResourceCaps {
            max_duration_secs: 1,
            max_threads: host.max_threads,
            max_memory_gib: f64::from(host.max_memory_gib),
            max_temp_storage_gib: f64::from(host.max_temp_storage_gib),
            max_queue_depth: host.max_queue_depth,
        },
        release_gate_policy_path: manifest.release_gate_policy_path.clone(),
        real_campaign_bead: manifest.real_campaign_bead.clone(),
        handoff_summary:
            "readiness-lab host simulation only; run the real campaign for product evidence"
                .to_owned(),
    }
}

fn push_readiness_lab_finding(
    findings: &mut Vec<ReadinessLabFinding>,
    finding_id: impl Into<String>,
    message: impl Into<String>,
    scope: FindingScope,
) {
    findings.push(scope.into_finding(
        finding_id.into(),
        ReadinessLabFindingSeverity::Error,
        message.into(),
    ));
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

    fn sample_host_simulation_manifest() -> ReadinessLabHostSimulationManifest {
        ReadinessLabHostSimulationManifest {
            schema_version: READINESS_LAB_SCHEMA_VERSION,
            simulation_id: "host-matrix".to_owned(),
            generated_at_epoch_days: 20_000,
            advisory_notice: READINESS_LAB_ADVISORY_NOTICE.to_owned(),
            source_bead: "bd-4532j".to_owned(),
            real_campaign_bead: "bd-rchk0.53.8".to_owned(),
            expected_artifact_root: "artifacts/swarm/large-host".to_owned(),
            release_gate_policy_path: "artifacts/swarm/release_gate_policy.json".to_owned(),
            hosts: vec![capable_host("candidate")],
        }
    }

    fn capable_host(host_id: &str) -> ReadinessLabSyntheticHostInventory {
        ReadinessLabSyntheticHostInventory {
            host_id: host_id.to_owned(),
            observed_at_epoch_days: 20_000,
            max_age_days: 7,
            logical_cpus: 64,
            ram_total_gib: 256,
            ram_available_gib: 220,
            numa_topology_visible: true,
            numa_nodes: Some(2),
            storage_class: "local-nvme".to_owned(),
            storage_visible: true,
            fuse_available: true,
            runner_configured: true,
            swarm_ack_configured: true,
            rch_worker_identity: "vmi-sim-64c-256gb".to_owned(),
            worker_fingerprint: "sim-abcdef1".to_owned(),
            queue_isolation: ReadinessLabSimulationQueueIsolation::Dedicated,
            target_dir_isolated: true,
            target_dir: "artifacts/swarm/target".to_owned(),
            artifact_root: "artifacts/swarm/large-host".to_owned(),
            max_threads: 64,
            max_memory_gib: 192,
            max_temp_storage_gib: 256,
            max_queue_depth: 32,
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

    fn simulate_hosts(
        manifest: &ReadinessLabHostSimulationManifest,
    ) -> ReadinessLabHostSimulationReport {
        simulate_readiness_lab_hosts(
            manifest,
            &ReadinessLabHostSimulationConfig {
                manifest_path: "hosts.json".to_owned(),
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

    #[test]
    fn host_simulator_accepts_borderline_large_host_as_advisory_candidate() {
        let report = simulate_hosts(&sample_host_simulation_manifest());

        assert!(report.valid);
        assert_eq!(
            report.product_evidence_claim,
            READINESS_LAB_NO_PRODUCT_EVIDENCE_CLAIM
        );
        assert_eq!(report.candidate_count, 1);
        assert_eq!(
            report.rows[0].classification,
            "authoritative_large_host_candidate"
        );
        assert!(report.rows[0].candidate_for_authorized_run);
        assert!(
            report
                .release_gate_effect
                .contains("swarm.responsiveness remains hidden")
        );
    }

    #[test]
    fn host_simulator_classifies_small_cpu_or_ram_as_smoke_only() {
        let mut manifest = sample_host_simulation_manifest();
        manifest.hosts[0].logical_cpus = 16;
        manifest.hosts[0].ram_total_gib = 128;
        manifest.hosts[0].max_threads = 16;
        manifest.hosts[0].max_memory_gib = 96;

        let report = simulate_hosts(&manifest);

        assert!(report.valid);
        assert_eq!(report.small_host_count, 1);
        assert_eq!(report.rows[0].classification, "small_host_smoke");
        assert!(!report.rows[0].candidate_for_authorized_run);
    }

    #[test]
    fn host_simulator_downgrades_missing_numa_storage_or_fuse() {
        let mut manifest = sample_host_simulation_manifest();
        manifest.hosts[0].numa_topology_visible = false;
        manifest.hosts[0].numa_nodes = None;
        manifest.hosts[0].storage_visible = false;
        manifest.hosts[0].fuse_available = false;

        let report = simulate_hosts(&manifest);

        assert!(report.valid);
        assert_eq!(report.capability_downgrade_count, 1);
        assert_eq!(report.rows[0].classification, "capability_downgraded_smoke");
        assert!(
            report.rows[0]
                .downgrade_reasons
                .iter()
                .any(|reason| reason == "storage_visible=false")
        );
    }

    #[test]
    fn host_simulator_blocks_missing_runner_or_ack() {
        let mut manifest = sample_host_simulation_manifest();
        manifest.hosts[0].runner_configured = false;
        manifest.hosts[0].swarm_ack_configured = false;

        let report = simulate_hosts(&manifest);

        assert!(report.valid);
        assert_eq!(report.blocked_count, 1);
        assert_eq!(report.rows[0].classification, "blocked");
        assert!(
            report.rows[0]
                .blockers
                .iter()
                .any(|blocker| blocker == "permissioned_runner_configured=false")
        );
        assert!(
            report.rows[0]
                .blockers
                .iter()
                .any(|blocker| blocker == "swarm_real_run_ack_configured=false")
        );
    }

    #[test]
    fn host_simulator_blocks_stale_future_and_mismatched_artifact_roots() {
        let mut manifest = sample_host_simulation_manifest();
        manifest.hosts = vec![
            capable_host("stale"),
            capable_host("future"),
            capable_host("root"),
        ];
        manifest.hosts[0].observed_at_epoch_days = 19_900;
        manifest.hosts[1].observed_at_epoch_days = 20_010;
        manifest.hosts[2].artifact_root = "artifacts/swarm/wrong-root".to_owned();

        let report = simulate_hosts(&manifest);

        assert!(report.valid);
        assert_eq!(report.blocked_count, 3);
        assert_eq!(report.stale_inventory_count, 1);
        assert_eq!(report.future_inventory_count, 1);
        assert!(
            report.rows[2]
                .blockers
                .iter()
                .any(|blocker| blocker.contains("artifact_root_mismatch"))
        );
    }

    #[test]
    fn host_simulator_rejects_unknown_manifest_fields() {
        let raw = r#"{
            "schema_version": 1,
            "simulation_id": "host-matrix",
            "generated_at_epoch_days": 20000,
            "advisory_notice": "advisory readiness-lab material only; not product evidence",
            "source_bead": "bd-4532j",
            "real_campaign_bead": "bd-rchk0.53.8",
            "expected_artifact_root": "artifacts/swarm/large-host",
            "release_gate_policy_path": "artifacts/swarm/release_gate_policy.json",
            "hosts": [],
            "unexpected": true
        }"#;

        let err = serde_json::from_str::<ReadinessLabHostSimulationManifest>(raw)
            .expect_err("unknown fields must fail closed");

        assert!(err.to_string().contains("unknown field"));
    }
}
