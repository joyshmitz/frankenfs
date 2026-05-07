#![allow(clippy::too_many_lines)]
#![forbid(unsafe_code)]

//! Non-mutating permission broker packets for destructive evidence campaigns.
//!
//! Broker packets prepare an operator handoff for lanes that need explicit
//! approval, such as real xfstests execution or large-host swarm runs. A valid
//! packet is only authorization material: it must not be treated as product
//! pass/fail evidence.

use crate::artifact_manifest::parse_manifest_timestamp_epoch_days;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::fs;
use std::path::{Component, Path};
use std::time::{SystemTime, UNIX_EPOCH};

pub const PERMISSIONED_CAMPAIGN_BROKER_SCHEMA_VERSION: u32 = 1;
pub const PERMISSIONED_CAMPAIGN_HANDOFF_PACKET_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_PERMISSIONED_CAMPAIGN_BROKER_MANIFEST: &str =
    "docs/permissioned-campaign-broker-manifest.json";
pub const DEFAULT_PERMISSIONED_CAMPAIGN_PREFLIGHT_MAX_AGE_DAYS: u32 = 14;
pub const PERMISSIONED_CAMPAIGN_HANDOFF_NOTICE: &str =
    "authorization handoff material only; not executed evidence and not a product pass/fail claim";
pub const XFSTESTS_REAL_RUN_ACK_ENV: &str = "XFSTESTS_REAL_RUN_ACK";
pub const XFSTESTS_REAL_RUN_ACK_VALUE: &str = "xfstests-may-mutate-test-and-scratch-devices";
pub const SWARM_ENABLE_PERMISSIONED_ENV: &str = "FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD";
pub const SWARM_ENABLE_PERMISSIONED_VALUE: &str = "1";
pub const SWARM_REAL_RUN_ACK_ENV: &str = "FFS_SWARM_WORKLOAD_REAL_RUN_ACK";
pub const SWARM_REAL_RUN_ACK_VALUE: &str = "swarm-workload-may-use-permissioned-large-host";
pub const SWARM_PERMISSIONED_RUNNER_ENV: &str = "FFS_SWARM_WORKLOAD_PERMISSIONED_RUNNER";
pub const SWARM_ARTIFACT_ROOT_ENV: &str = "FFS_SWARM_WORKLOAD_ARTIFACT_ROOT";
pub const SWARM_MIN_LOGICAL_CPUS: u32 = 64;
pub const SWARM_MIN_RAM_GIB: u32 = 256;
pub const SWARM_MIN_NUMA_NODES: u32 = 2;

const ALLOWED_DESTRUCTIVE_OPERATIONS: [&str; 9] = [
    "mount_test_device",
    "mount_scratch_device",
    "mutate_test_device",
    "mutate_scratch_device",
    "format_scratch_device",
    "generate_filesystem_load",
    "spawn_large_host_workers",
    "consume_large_temp_storage",
    "kill_replay_worker",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignBrokerManifest {
    pub schema_version: u32,
    pub campaign_id: String,
    pub lane_kind: PermissionedCampaignLaneKind,
    pub target_beads: Vec<String>,
    pub generated_at: String,
    pub required_ack: PermissionedCampaignAck,
    #[serde(default)]
    pub required_runner_env: Vec<PermissionedCampaignRunnerEnv>,
    #[serde(default)]
    pub host_capability_facts: Vec<PermissionedCampaignHostFact>,
    pub safe_path_roots: Vec<PermissionedCampaignPathRoot>,
    pub destructive_operations: Vec<String>,
    pub expected_artifact_paths: Vec<String>,
    pub cleanup_policy: PermissionedCampaignCleanupPolicy,
    pub claim_boundary: PermissionedCampaignClaimBoundary,
    pub preflight_references: Vec<PermissionedCampaignPreflightReference>,
    pub operator_risks: Vec<String>,
    pub exact_commands: Vec<PermissionedCampaignCommand>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionedCampaignLaneKind {
    XfstestsRealBaseline,
    LargeHostSwarmResponsiveness,
}

impl PermissionedCampaignLaneKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::XfstestsRealBaseline => "xfstests_real_baseline",
            Self::LargeHostSwarmResponsiveness => "large_host_swarm_responsiveness",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignAck {
    pub env_var: String,
    pub exact_value: String,
    pub operator_prompt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignRunnerEnv {
    pub env_var: String,
    pub purpose: String,
    pub expected_shape: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignHostFact {
    pub fact_id: String,
    pub observed_value: String,
    pub required_value: String,
    pub proof_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignPathRoot {
    pub root_id: String,
    pub path: String,
    pub purpose: PermissionedCampaignPathPurpose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionedCampaignPathPurpose {
    TestData,
    Scratch,
    ArtifactRoot,
    RunnerWorkspace,
}

impl PermissionedCampaignPathPurpose {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::TestData => "test_data",
            Self::Scratch => "scratch",
            Self::ArtifactRoot => "artifact_root",
            Self::RunnerWorkspace => "runner_workspace",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignCleanupPolicy {
    pub policy_id: String,
    pub expected_status: PermissionedCampaignCleanupStatus,
    pub partial_artifact_policy: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionedCampaignCleanupStatus {
    Clean,
    PreservedArtifacts,
    ManualCleanupRequired,
}

impl PermissionedCampaignCleanupStatus {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::PreservedArtifacts => "preserved_artifacts",
            Self::ManualCleanupRequired => "manual_cleanup_required",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignClaimBoundary {
    pub packet_status: PermissionedCampaignPacketStatus,
    pub product_evidence_claim: PermissionedCampaignProductEvidenceClaim,
    pub required_executed_evidence: Vec<String>,
    pub claim_text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionedCampaignPacketStatus {
    ReadyForOperatorApproval,
    ExecutedEvidence,
}

impl PermissionedCampaignPacketStatus {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ReadyForOperatorApproval => "ready_for_operator_approval",
            Self::ExecutedEvidence => "executed_evidence",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionedCampaignProductEvidenceClaim {
    None,
    PacketCountsAsPassFail,
    ExecutedEvidenceRecorded,
}

impl PermissionedCampaignProductEvidenceClaim {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::PacketCountsAsPassFail => "packet_counts_as_pass_fail",
            Self::ExecutedEvidenceRecorded => "executed_evidence_recorded",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignPreflightReference {
    pub preflight_id: String,
    pub artifact_path: String,
    pub observed_at_epoch_days: u32,
    pub max_age_days: u32,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignCommand {
    pub command_id: String,
    pub exact_command: String,
    pub command_role: PermissionedCampaignCommandRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionedCampaignCommandRole {
    Preflight,
    PermissionedRun,
    PreserveArtifacts,
    Cleanup,
}

impl PermissionedCampaignCommandRole {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Preflight => "preflight",
            Self::PermissionedRun => "permissioned_run",
            Self::PreserveArtifacts => "preserve_artifacts",
            Self::Cleanup => "cleanup",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionedCampaignBrokerValidationConfig {
    pub reference_epoch_days: u32,
}

impl Default for PermissionedCampaignBrokerValidationConfig {
    fn default() -> Self {
        Self::with_current_reference()
    }
}

impl PermissionedCampaignBrokerValidationConfig {
    #[must_use]
    pub fn with_current_reference() -> Self {
        Self {
            reference_epoch_days: current_epoch_days().unwrap_or(0),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignBrokerReport {
    pub schema_version: u32,
    pub campaign_id: String,
    pub lane_kind: String,
    pub valid: bool,
    pub packet_status: String,
    pub product_evidence_claim: String,
    pub claim_text: String,
    pub required_executed_evidence: Vec<String>,
    pub target_beads: Vec<String>,
    pub ack_env: String,
    pub ack_exact_value: String,
    pub runner_env: Vec<PermissionedCampaignRunnerEnvSummary>,
    pub host_facts: Vec<PermissionedCampaignHostFactSummary>,
    pub safe_path_roots: Vec<PermissionedCampaignPathRootSummary>,
    pub destructive_operations: Vec<String>,
    pub expected_artifact_paths: Vec<String>,
    pub preflight_references: Vec<PermissionedCampaignPreflightSummary>,
    pub operator_risks: Vec<String>,
    pub exact_commands: Vec<PermissionedCampaignCommandSummary>,
    pub issue_count: usize,
    pub issues: Vec<PermissionedCampaignBrokerIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignRunnerEnvSummary {
    pub env_var: String,
    pub purpose: String,
    pub expected_shape: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignHostFactSummary {
    pub fact_id: String,
    pub observed_value: String,
    pub required_value: String,
    pub proof_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignPathRootSummary {
    pub root_id: String,
    pub path: String,
    pub purpose: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignPreflightSummary {
    pub preflight_id: String,
    pub artifact_path: String,
    pub age_days: u32,
    pub max_age_days: u32,
    pub stale: bool,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignCommandSummary {
    pub command_id: String,
    pub command_role: String,
    pub exact_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignBrokerIssue {
    pub path: String,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignHandoffPacket {
    pub packet_schema_version: u32,
    pub packet_id: String,
    pub campaign_id: String,
    pub lane_kind: String,
    pub generation: PermissionedCampaignHandoffGeneration,
    pub authorization_notice: String,
    pub packet_status: String,
    pub product_evidence_claim: String,
    pub claim_text: String,
    pub required_executed_evidence: Vec<String>,
    pub target_beads: Vec<String>,
    pub required_ack: PermissionedCampaignHandoffAck,
    pub runner_env: Vec<PermissionedCampaignRunnerEnvSummary>,
    pub host_capability_facts: Vec<PermissionedCampaignHostFactSummary>,
    pub safe_path_roots: Vec<PermissionedCampaignPathRootSummary>,
    pub destructive_operations: Vec<String>,
    pub expected_artifact_paths: Vec<String>,
    pub cleanup_policy: PermissionedCampaignCleanupSummary,
    pub preflight_references: Vec<PermissionedCampaignPreflightSummary>,
    pub operator_risks: Vec<String>,
    pub exact_commands: Vec<PermissionedCampaignHandoffCommand>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignHandoffGeneration {
    pub generated_at: String,
    pub generated_by: String,
    pub git_sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignHandoffAck {
    pub env_var: String,
    pub exact_value: String,
    pub operator_prompt: String,
    pub export_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignCleanupSummary {
    pub policy_id: String,
    pub expected_status: String,
    pub partial_artifact_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignHandoffCommand {
    pub command_id: String,
    pub command_role: String,
    pub exact_command: String,
    pub transcript_path_template: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedXfstestsBrokerAdapterInput {
    pub campaign_id: String,
    pub generated_at: String,
    pub target_beads: Vec<String>,
    pub selected_subset_id: String,
    pub xfstests_dir: String,
    pub test_dir: String,
    pub scratch_mnt: String,
    pub result_base: String,
    pub preflight_id: String,
    pub preflight_artifact_path: String,
    pub preflight_observed_at_epoch_days: u32,
    pub preflight_max_age_days: u32,
    pub not_run_classification: PermissionedXfstestsNotRunClassification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionedXfstestsNotRunClassification {
    EnvironmentBlockerOnly,
    CountsAsPassingProductSignal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedSwarmBrokerAdapterInput {
    pub campaign_id: String,
    pub generated_at: String,
    pub target_beads: Vec<String>,
    pub permissioned_runner: String,
    pub runner_workspace: String,
    pub artifact_root: String,
    pub workload_manifest_path: String,
    pub adaptive_runtime_manifest_path: String,
    pub resource_caps_path: String,
    pub p99_attribution_ledger_path: String,
    pub proof_bundle_manifest_path: String,
    pub proof_bundle_lane_paths: Vec<String>,
    pub raw_log_path: String,
    pub release_gate_policy_path: String,
    pub release_gate_output_path: String,
    pub host_capability_proof_path: String,
    pub numa_capability_proof_path: String,
    pub preflight_id: String,
    pub preflight_artifact_path: String,
    pub preflight_observed_at_epoch_days: u32,
    pub preflight_max_age_days: u32,
    pub logical_cpu_count: u32,
    pub ram_gib: u32,
    pub numa_node_count: u32,
    pub numa_topology_visible: bool,
    pub release_claim_classification: PermissionedSwarmReleaseClaimClassification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionedSwarmReleaseClaimClassification {
    AuthoritativeLargeHost,
    SmallHostSmoke,
    CapabilityDowngradedSmoke,
}

impl PermissionedSwarmReleaseClaimClassification {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AuthoritativeLargeHost => "authoritative_large_host",
            Self::SmallHostSmoke => "small_host_smoke",
            Self::CapabilityDowngradedSmoke => "capability_downgraded_smoke",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PermissionedSwarmHostCapability {
    ready_for_authoritative_run: bool,
    blockers: Vec<String>,
}

pub fn load_permissioned_campaign_broker_manifest(
    path: &Path,
) -> Result<PermissionedCampaignBrokerManifest> {
    let text = fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read permissioned campaign broker manifest {}",
            path.display()
        )
    })?;
    serde_json::from_str(&text).with_context(|| {
        format!(
            "invalid permissioned campaign broker manifest JSON {}",
            path.display()
        )
    })
}

#[must_use]
pub fn validate_permissioned_campaign_broker_manifest(
    manifest: &PermissionedCampaignBrokerManifest,
    config: &PermissionedCampaignBrokerValidationConfig,
) -> PermissionedCampaignBrokerReport {
    let mut issues = Vec::new();

    validate_top_level(manifest, &mut issues);
    validate_ack(manifest, &mut issues);
    validate_runner_env(manifest, &mut issues);
    validate_host_facts(manifest, &mut issues);
    validate_paths(manifest, &mut issues);
    validate_destructive_operations(manifest, &mut issues);
    validate_cleanup_policy(manifest, &mut issues);
    validate_claim_boundary(manifest, &mut issues);
    validate_preflight_references(manifest, config, &mut issues);
    validate_operator_risks(manifest, &mut issues);
    validate_exact_commands(manifest, &mut issues);

    PermissionedCampaignBrokerReport {
        schema_version: manifest.schema_version,
        campaign_id: manifest.campaign_id.clone(),
        lane_kind: manifest.lane_kind.label().to_owned(),
        valid: issues.is_empty(),
        packet_status: manifest.claim_boundary.packet_status.label().to_owned(),
        product_evidence_claim: manifest
            .claim_boundary
            .product_evidence_claim
            .label()
            .to_owned(),
        claim_text: manifest.claim_boundary.claim_text.clone(),
        required_executed_evidence: manifest.claim_boundary.required_executed_evidence.clone(),
        target_beads: manifest.target_beads.clone(),
        ack_env: manifest.required_ack.env_var.clone(),
        ack_exact_value: manifest.required_ack.exact_value.clone(),
        runner_env: runner_env_summary(manifest),
        host_facts: host_fact_summary(manifest),
        safe_path_roots: path_root_summary(manifest),
        destructive_operations: manifest.destructive_operations.clone(),
        expected_artifact_paths: manifest.expected_artifact_paths.clone(),
        preflight_references: preflight_summary(manifest, config),
        operator_risks: manifest.operator_risks.clone(),
        exact_commands: command_summary(manifest),
        issue_count: issues.len(),
        issues,
    }
}

#[must_use]
pub fn render_permissioned_campaign_broker_markdown(
    report: &PermissionedCampaignBrokerReport,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Permissioned Campaign Broker\n");
    let _ = writeln!(out, "- Campaign: `{}`", report.campaign_id);
    let _ = writeln!(out, "- Lane: `{}`", report.lane_kind);
    let _ = writeln!(out, "- Valid: `{}`", report.valid);
    let _ = writeln!(out, "- Packet status: `{}`", report.packet_status);
    let _ = writeln!(
        out,
        "- Product evidence claim: `{}`",
        report.product_evidence_claim
    );
    let _ = writeln!(
        out,
        "- Claim boundary: {}",
        markdown_cell(&report.claim_text)
    );
    let _ = writeln!(out, "- ACK env: `{}`", report.ack_env);
    let _ = writeln!(out, "- ACK value: `{}`", report.ack_exact_value);

    out.push_str("\n## Required Executed Evidence\n\n");
    for evidence in &report.required_executed_evidence {
        let _ = writeln!(out, "- {}", markdown_cell(evidence));
    }

    out.push_str("\n## Target Beads\n\n");
    for bead in &report.target_beads {
        let _ = writeln!(out, "- `{bead}`");
    }

    out.push_str("\n## Runner Environment\n\n");
    out.push_str("| Env var | Purpose | Expected shape |\n");
    out.push_str("|---|---|---|\n");
    for entry in &report.runner_env {
        let _ = writeln!(
            out,
            "| `{}` | {} | {} |",
            entry.env_var,
            markdown_cell(&entry.purpose),
            markdown_cell(&entry.expected_shape)
        );
    }

    out.push_str("\n## Host Facts\n\n");
    out.push_str("| Fact | Observed | Required | Proof |\n");
    out.push_str("|---|---|---|---|\n");
    for fact in &report.host_facts {
        let _ = writeln!(
            out,
            "| `{}` | `{}` | `{}` | `{}` |",
            fact.fact_id, fact.observed_value, fact.required_value, fact.proof_path
        );
    }

    out.push_str("\n## Safe Path Roots\n\n");
    out.push_str("| Root | Purpose | Path |\n");
    out.push_str("|---|---|---|\n");
    for root in &report.safe_path_roots {
        let _ = writeln!(
            out,
            "| `{}` | `{}` | `{}` |",
            root.root_id, root.purpose, root.path
        );
    }

    out.push_str("\n## Destructive Operations\n\n");
    for operation in &report.destructive_operations {
        let _ = writeln!(out, "- `{operation}`");
    }

    out.push_str("\n## Expected Artifacts\n\n");
    for path in &report.expected_artifact_paths {
        let _ = writeln!(out, "- `{path}`");
    }

    out.push_str("\n## Preflight References\n\n");
    out.push_str("| Preflight | Age days | Max age days | Stale | Artifact |\n");
    out.push_str("|---|---:|---:|---|---|\n");
    for preflight in &report.preflight_references {
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | `{}` | `{}` |",
            preflight.preflight_id,
            preflight.age_days,
            preflight.max_age_days,
            preflight.stale,
            preflight.artifact_path
        );
    }

    out.push_str("\n## Operator Risks\n\n");
    for risk in &report.operator_risks {
        let _ = writeln!(out, "- {}", markdown_cell(risk));
    }

    out.push_str("\n## Exact Commands\n\n");
    out.push_str("| Command | Role | Exact command |\n");
    out.push_str("|---|---|---|\n");
    for command in &report.exact_commands {
        let _ = writeln!(
            out,
            "| `{}` | `{}` | `{}` |",
            command.command_id,
            command.command_role,
            command.exact_command.replace('`', "'")
        );
    }

    if report.issues.is_empty() {
        out.push_str("\n## Issues\n\nnone\n");
    } else {
        out.push_str("\n## Issues\n\n");
        for issue in &report.issues {
            let _ = writeln!(
                out,
                "- `{}` `{}`: {}",
                issue.path, issue.code, issue.message
            );
        }
    }

    out
}

pub fn fail_on_permissioned_campaign_broker_errors(
    report: &PermissionedCampaignBrokerReport,
) -> Result<()> {
    if report.valid {
        Ok(())
    } else {
        bail!(
            "permissioned campaign broker validation failed: issues={}",
            report.issue_count
        )
    }
}

pub fn generate_permissioned_campaign_handoff_packet(
    manifest: &PermissionedCampaignBrokerManifest,
    config: &PermissionedCampaignBrokerValidationConfig,
    generation: PermissionedCampaignHandoffGeneration,
) -> Result<PermissionedCampaignHandoffPacket> {
    let report = validate_permissioned_campaign_broker_manifest(manifest, config);
    fail_on_permissioned_campaign_broker_errors(&report)?;

    Ok(PermissionedCampaignHandoffPacket {
        packet_schema_version: PERMISSIONED_CAMPAIGN_HANDOFF_PACKET_SCHEMA_VERSION,
        packet_id: format!("{}-operator-handoff", manifest.campaign_id),
        campaign_id: manifest.campaign_id.clone(),
        lane_kind: manifest.lane_kind.label().to_owned(),
        generation,
        authorization_notice: PERMISSIONED_CAMPAIGN_HANDOFF_NOTICE.to_owned(),
        packet_status: manifest.claim_boundary.packet_status.label().to_owned(),
        product_evidence_claim: manifest
            .claim_boundary
            .product_evidence_claim
            .label()
            .to_owned(),
        claim_text: manifest.claim_boundary.claim_text.clone(),
        required_executed_evidence: manifest.claim_boundary.required_executed_evidence.clone(),
        target_beads: manifest.target_beads.clone(),
        required_ack: PermissionedCampaignHandoffAck {
            env_var: manifest.required_ack.env_var.clone(),
            exact_value: manifest.required_ack.exact_value.clone(),
            operator_prompt: manifest.required_ack.operator_prompt.clone(),
            export_command: format!(
                "{}={}",
                manifest.required_ack.env_var, manifest.required_ack.exact_value
            ),
        },
        runner_env: runner_env_summary(manifest),
        host_capability_facts: host_fact_summary(manifest),
        safe_path_roots: path_root_summary(manifest),
        destructive_operations: manifest.destructive_operations.clone(),
        expected_artifact_paths: manifest.expected_artifact_paths.clone(),
        cleanup_policy: PermissionedCampaignCleanupSummary {
            policy_id: manifest.cleanup_policy.policy_id.clone(),
            expected_status: manifest.cleanup_policy.expected_status.label().to_owned(),
            partial_artifact_policy: manifest.cleanup_policy.partial_artifact_policy.clone(),
        },
        preflight_references: preflight_summary(manifest, config),
        operator_risks: manifest.operator_risks.clone(),
        exact_commands: handoff_command_summary(manifest),
    })
}

pub fn build_xfstests_broker_manifest(
    input: &PermissionedXfstestsBrokerAdapterInput,
) -> Result<PermissionedCampaignBrokerManifest> {
    validate_xfstests_adapter_input(input)?;
    Ok(PermissionedCampaignBrokerManifest {
        schema_version: PERMISSIONED_CAMPAIGN_BROKER_SCHEMA_VERSION,
        campaign_id: input.campaign_id.clone(),
        lane_kind: PermissionedCampaignLaneKind::XfstestsRealBaseline,
        target_beads: input.target_beads.clone(),
        generated_at: input.generated_at.clone(),
        required_ack: PermissionedCampaignAck {
            env_var: XFSTESTS_REAL_RUN_ACK_ENV.to_owned(),
            exact_value: XFSTESTS_REAL_RUN_ACK_VALUE.to_owned(),
            operator_prompt:
                "Approve real xfstests execution against scoped TEST_DIR and SCRATCH_MNT"
                    .to_owned(),
        },
        required_runner_env: vec![
            PermissionedCampaignRunnerEnv {
                env_var: "XFSTESTS_DIR".to_owned(),
                purpose: "xfstests source tree with built helper binaries".to_owned(),
                expected_shape: input.xfstests_dir.clone(),
            },
            PermissionedCampaignRunnerEnv {
                env_var: "TEST_DIR".to_owned(),
                purpose: "explicit scoped xfstests test mount root".to_owned(),
                expected_shape: input.test_dir.clone(),
            },
            PermissionedCampaignRunnerEnv {
                env_var: "SCRATCH_MNT".to_owned(),
                purpose: "explicit scoped xfstests scratch mount root".to_owned(),
                expected_shape: input.scratch_mnt.clone(),
            },
            PermissionedCampaignRunnerEnv {
                env_var: "RESULT_BASE".to_owned(),
                purpose: "artifact root for xfstests raw logs and summaries".to_owned(),
                expected_shape: input.result_base.clone(),
            },
        ],
        host_capability_facts: vec![
            PermissionedCampaignHostFact {
                fact_id: "xfstests_helpers".to_owned(),
                observed_value: "present".to_owned(),
                required_value: "present".to_owned(),
                proof_path: input.preflight_artifact_path.clone(),
            },
            PermissionedCampaignHostFact {
                fact_id: "explicit_test_and_scratch_paths".to_owned(),
                observed_value: "provided".to_owned(),
                required_value: "provided".to_owned(),
                proof_path: input.preflight_artifact_path.clone(),
            },
        ],
        safe_path_roots: vec![
            PermissionedCampaignPathRoot {
                root_id: "test_dir".to_owned(),
                path: input.test_dir.clone(),
                purpose: PermissionedCampaignPathPurpose::TestData,
            },
            PermissionedCampaignPathRoot {
                root_id: "scratch_mnt".to_owned(),
                path: input.scratch_mnt.clone(),
                purpose: PermissionedCampaignPathPurpose::Scratch,
            },
            PermissionedCampaignPathRoot {
                root_id: "result_base".to_owned(),
                path: input.result_base.clone(),
                purpose: PermissionedCampaignPathPurpose::ArtifactRoot,
            },
        ],
        destructive_operations: vec![
            "mount_test_device".to_owned(),
            "mount_scratch_device".to_owned(),
            "mutate_test_device".to_owned(),
            "mutate_scratch_device".to_owned(),
        ],
        expected_artifact_paths: xfstests_expected_artifact_paths(&input.result_base),
        cleanup_policy: PermissionedCampaignCleanupPolicy {
            policy_id: "xfstests_preserve_partial_artifacts".to_owned(),
            expected_status: PermissionedCampaignCleanupStatus::PreservedArtifacts,
            partial_artifact_policy:
                "preserve raw logs, command transcript, stdout, stderr, and parsed not-run rows"
                    .to_owned(),
        },
        claim_boundary: PermissionedCampaignClaimBoundary {
            packet_status: PermissionedCampaignPacketStatus::ReadyForOperatorApproval,
            product_evidence_claim: PermissionedCampaignProductEvidenceClaim::None,
            required_executed_evidence: vec![
                "raw xfstests logs".to_owned(),
                "pass/fail/not-run summary".to_owned(),
                "failure-to-bead extraction report".to_owned(),
            ],
            claim_text:
                "operator approval material only; not-run rows are blockers, never passing product behavior"
                    .to_owned(),
        },
        preflight_references: vec![PermissionedCampaignPreflightReference {
            preflight_id: input.preflight_id.clone(),
            artifact_path: input.preflight_artifact_path.clone(),
            observed_at_epoch_days: input.preflight_observed_at_epoch_days,
            max_age_days: input.preflight_max_age_days,
            summary: format!(
                "{} selected subset ready for explicit-path permission review",
                input.selected_subset_id
            ),
        }],
        operator_risks: vec![
            "xfstests may mutate the scoped TEST_DIR and SCRATCH_MNT devices".to_owned(),
            "partial runs must preserve raw logs before any cleanup".to_owned(),
            "not-run rows must remain blocker evidence and cannot be counted as passing behavior"
                .to_owned(),
        ],
        exact_commands: vec![
            PermissionedCampaignCommand {
                command_id: "xfstests_preflight".to_owned(),
                exact_command: format!(
                    "XFSTESTS_DIR={} TEST_DIR={} SCRATCH_MNT={} RESULT_BASE={} scripts/e2e/ffs_xfstests_e2e.sh --dry-run",
                    shell_single_quote(&input.xfstests_dir),
                    shell_single_quote(&input.test_dir),
                    shell_single_quote(&input.scratch_mnt),
                    shell_single_quote(&input.result_base)
                ),
                command_role: PermissionedCampaignCommandRole::Preflight,
            },
            PermissionedCampaignCommand {
                command_id: "xfstests_permissioned_run".to_owned(),
                exact_command: format!(
                    "{XFSTESTS_REAL_RUN_ACK_ENV}={XFSTESTS_REAL_RUN_ACK_VALUE} XFSTESTS_DIR={} TEST_DIR={} SCRATCH_MNT={} RESULT_BASE={} scripts/e2e/ffs_xfstests_e2e.sh",
                    shell_single_quote(&input.xfstests_dir),
                    shell_single_quote(&input.test_dir),
                    shell_single_quote(&input.scratch_mnt),
                    shell_single_quote(&input.result_base)
                ),
                command_role: PermissionedCampaignCommandRole::PermissionedRun,
            },
        ],
    })
}

pub fn generate_xfstests_handoff_packet(
    input: &PermissionedXfstestsBrokerAdapterInput,
    validation_config: &PermissionedCampaignBrokerValidationConfig,
    generation: PermissionedCampaignHandoffGeneration,
) -> Result<PermissionedCampaignHandoffPacket> {
    let manifest = build_xfstests_broker_manifest(input)?;
    generate_permissioned_campaign_handoff_packet(&manifest, validation_config, generation)
}

pub fn build_swarm_broker_manifest(
    input: &PermissionedSwarmBrokerAdapterInput,
) -> Result<PermissionedCampaignBrokerManifest> {
    validate_swarm_adapter_input(input)?;
    let capability = swarm_host_capability(input);
    let claim_text = swarm_claim_text(&capability);
    let preflight_summary = swarm_preflight_summary(&capability);

    Ok(PermissionedCampaignBrokerManifest {
        schema_version: PERMISSIONED_CAMPAIGN_BROKER_SCHEMA_VERSION,
        campaign_id: input.campaign_id.clone(),
        lane_kind: PermissionedCampaignLaneKind::LargeHostSwarmResponsiveness,
        target_beads: input.target_beads.clone(),
        generated_at: input.generated_at.clone(),
        required_ack: PermissionedCampaignAck {
            env_var: SWARM_REAL_RUN_ACK_ENV.to_owned(),
            exact_value: SWARM_REAL_RUN_ACK_VALUE.to_owned(),
            operator_prompt:
                "Approve permissioned large-host swarm workload execution after host proof review"
                    .to_owned(),
        },
        required_runner_env: vec![
            PermissionedCampaignRunnerEnv {
                env_var: SWARM_ENABLE_PERMISSIONED_ENV.to_owned(),
                purpose: "default-off opt-in that allows the permissioned swarm runner gate"
                    .to_owned(),
                expected_shape: SWARM_ENABLE_PERMISSIONED_VALUE.to_owned(),
            },
            PermissionedCampaignRunnerEnv {
                env_var: SWARM_PERMISSIONED_RUNNER_ENV.to_owned(),
                purpose: "operator-provided runner that writes authoritative large-host artifacts"
                    .to_owned(),
                expected_shape: input.permissioned_runner.clone(),
            },
            PermissionedCampaignRunnerEnv {
                env_var: SWARM_ARTIFACT_ROOT_ENV.to_owned(),
                purpose:
                    "artifact root for workload reports, p99 attribution, proof-bundle lanes, and logs"
                        .to_owned(),
                expected_shape: input.artifact_root.clone(),
            },
        ],
        host_capability_facts: vec![
            PermissionedCampaignHostFact {
                fact_id: "logical_cpus".to_owned(),
                observed_value: input.logical_cpu_count.to_string(),
                required_value: format!(">={SWARM_MIN_LOGICAL_CPUS}"),
                proof_path: input.host_capability_proof_path.clone(),
            },
            PermissionedCampaignHostFact {
                fact_id: "ram_gib".to_owned(),
                observed_value: input.ram_gib.to_string(),
                required_value: format!(">={SWARM_MIN_RAM_GIB}"),
                proof_path: input.host_capability_proof_path.clone(),
            },
            PermissionedCampaignHostFact {
                fact_id: "numa_topology_visible".to_owned(),
                observed_value: input.numa_topology_visible.to_string(),
                required_value: "true".to_owned(),
                proof_path: input.numa_capability_proof_path.clone(),
            },
            PermissionedCampaignHostFact {
                fact_id: "numa_nodes".to_owned(),
                observed_value: input.numa_node_count.to_string(),
                required_value: format!(">={SWARM_MIN_NUMA_NODES}"),
                proof_path: input.numa_capability_proof_path.clone(),
            },
            PermissionedCampaignHostFact {
                fact_id: "release_claim_classification".to_owned(),
                observed_value: input.release_claim_classification.label().to_owned(),
                required_value: "authoritative_large_host".to_owned(),
                proof_path: input.preflight_artifact_path.clone(),
            },
        ],
        safe_path_roots: vec![
            PermissionedCampaignPathRoot {
                root_id: "runner_workspace".to_owned(),
                path: input.runner_workspace.clone(),
                purpose: PermissionedCampaignPathPurpose::RunnerWorkspace,
            },
            PermissionedCampaignPathRoot {
                root_id: "swarm_artifacts".to_owned(),
                path: input.artifact_root.clone(),
                purpose: PermissionedCampaignPathPurpose::ArtifactRoot,
            },
        ],
        destructive_operations: vec![
            "generate_filesystem_load".to_owned(),
            "spawn_large_host_workers".to_owned(),
            "consume_large_temp_storage".to_owned(),
            "kill_replay_worker".to_owned(),
        ],
        expected_artifact_paths: swarm_expected_artifact_paths(input),
        cleanup_policy: PermissionedCampaignCleanupPolicy {
            policy_id: "swarm_preserve_permissioned_artifacts".to_owned(),
            expected_status: PermissionedCampaignCleanupStatus::PreservedArtifacts,
            partial_artifact_policy:
                "preserve resource caps, p99 attribution, proof-bundle lanes, raw logs, release-gate output, stdout, and stderr"
                    .to_owned(),
        },
        claim_boundary: PermissionedCampaignClaimBoundary {
            packet_status: PermissionedCampaignPacketStatus::ReadyForOperatorApproval,
            product_evidence_claim: PermissionedCampaignProductEvidenceClaim::None,
            required_executed_evidence: vec![
                "swarm workload harness report with measured_authoritative permissioned_large_host row"
                    .to_owned(),
                "p99 attribution ledger for swarm_tail_latency".to_owned(),
                "proof-bundle lanes: swarm_workload_harness, swarm_tail_latency, adaptive_runtime"
                    .to_owned(),
                "release-gate output preserving the swarm.responsiveness decision".to_owned(),
                "raw command transcript, stdout, and stderr logs".to_owned(),
            ],
            claim_text,
        },
        preflight_references: vec![PermissionedCampaignPreflightReference {
            preflight_id: input.preflight_id.clone(),
            artifact_path: input.preflight_artifact_path.clone(),
            observed_at_epoch_days: input.preflight_observed_at_epoch_days,
            max_age_days: input.preflight_max_age_days,
            summary: preflight_summary,
        }],
        operator_risks: vec![
            "permissioned swarm execution may consume >=64 CPUs and large temporary storage"
                .to_owned(),
            "raw logs, p99 attribution, proof-bundle lanes, and release-gate output must be preserved before cleanup"
                .to_owned(),
            "small_host_smoke and capability_downgraded_smoke are blocker evidence and cannot upgrade swarm.responsiveness"
                .to_owned(),
        ],
        exact_commands: swarm_exact_commands(input),
    })
}

pub fn generate_swarm_handoff_packet(
    input: &PermissionedSwarmBrokerAdapterInput,
    validation_config: &PermissionedCampaignBrokerValidationConfig,
    generation: PermissionedCampaignHandoffGeneration,
) -> Result<PermissionedCampaignHandoffPacket> {
    let manifest = build_swarm_broker_manifest(input)?;
    generate_permissioned_campaign_handoff_packet(&manifest, validation_config, generation)
}

#[must_use]
pub fn render_permissioned_campaign_handoff_markdown(
    packet: &PermissionedCampaignHandoffPacket,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Permissioned Campaign Handoff\n");
    let _ = writeln!(out, "- Packet: `{}`", packet.packet_id);
    let _ = writeln!(out, "- Campaign: `{}`", packet.campaign_id);
    let _ = writeln!(out, "- Lane: `{}`", packet.lane_kind);
    let _ = writeln!(
        out,
        "- Generated: `{}` by `{}` at `{}`",
        packet.generation.generated_at, packet.generation.generated_by, packet.generation.git_sha
    );
    let _ = writeln!(
        out,
        "- Notice: {}",
        markdown_cell(&packet.authorization_notice)
    );
    let _ = writeln!(out, "- Packet status: `{}`", packet.packet_status);
    let _ = writeln!(
        out,
        "- Product evidence claim: `{}`",
        packet.product_evidence_claim
    );
    let _ = writeln!(
        out,
        "- Claim boundary: {}",
        markdown_cell(&packet.claim_text)
    );

    out.push_str("\n## Required ACK\n\n");
    let _ = writeln!(out, "- Env var: `{}`", packet.required_ack.env_var);
    let _ = writeln!(out, "- Exact value: `{}`", packet.required_ack.exact_value);
    let _ = writeln!(out, "- Export: `{}`", packet.required_ack.export_command);
    let _ = writeln!(
        out,
        "- Operator prompt: {}",
        markdown_cell(&packet.required_ack.operator_prompt)
    );

    out.push_str("\n## Target Beads\n\n");
    for bead in &packet.target_beads {
        let _ = writeln!(out, "- `{bead}`");
    }

    out.push_str("\n## Required Executed Evidence After Approval\n\n");
    for evidence in &packet.required_executed_evidence {
        let _ = writeln!(out, "- {}", markdown_cell(evidence));
    }

    out.push_str("\n## Runner Environment\n\n");
    out.push_str("| Env var | Purpose | Expected shape |\n");
    out.push_str("|---|---|---|\n");
    for entry in &packet.runner_env {
        let _ = writeln!(
            out,
            "| `{}` | {} | {} |",
            entry.env_var,
            markdown_cell(&entry.purpose),
            markdown_cell(&entry.expected_shape)
        );
    }

    out.push_str("\n## Host Capability Requirements\n\n");
    out.push_str("| Fact | Observed | Required | Proof |\n");
    out.push_str("|---|---|---|---|\n");
    for fact in &packet.host_capability_facts {
        let _ = writeln!(
            out,
            "| `{}` | `{}` | `{}` | `{}` |",
            fact.fact_id, fact.observed_value, fact.required_value, fact.proof_path
        );
    }

    out.push_str("\n## Path Effects\n\n");
    out.push_str("| Root | Purpose | Path |\n");
    out.push_str("|---|---|---|\n");
    for root in &packet.safe_path_roots {
        let _ = writeln!(
            out,
            "| `{}` | `{}` | `{}` |",
            root.root_id, root.purpose, root.path
        );
    }

    out.push_str("\n## Destructive Operations Requiring Approval\n\n");
    for operation in &packet.destructive_operations {
        let _ = writeln!(out, "- `{operation}`");
    }

    out.push_str("\n## Expected Artifact Destinations\n\n");
    for path in &packet.expected_artifact_paths {
        let _ = writeln!(out, "- `{path}`");
    }

    out.push_str("\n## Cleanup Expectations\n\n");
    let _ = writeln!(out, "- Policy: `{}`", packet.cleanup_policy.policy_id);
    let _ = writeln!(
        out,
        "- Expected status: `{}`",
        packet.cleanup_policy.expected_status
    );
    let _ = writeln!(
        out,
        "- Partial artifact policy: {}",
        markdown_cell(&packet.cleanup_policy.partial_artifact_policy)
    );

    out.push_str("\n## Preflight References\n\n");
    out.push_str("| Preflight | Age days | Max age days | Stale | Artifact | Summary |\n");
    out.push_str("|---|---:|---:|---|---|---|\n");
    for preflight in &packet.preflight_references {
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | `{}` | `{}` | {} |",
            preflight.preflight_id,
            preflight.age_days,
            preflight.max_age_days,
            preflight.stale,
            preflight.artifact_path,
            markdown_cell(&preflight.summary)
        );
    }

    out.push_str("\n## Operator Risks\n\n");
    for risk in &packet.operator_risks {
        let _ = writeln!(out, "- {}", markdown_cell(risk));
    }

    out.push_str("\n## Command Transcript Template\n\n");
    out.push_str("| Command | Role | Transcript path | Exact command |\n");
    out.push_str("|---|---|---|---|\n");
    for command in &packet.exact_commands {
        let _ = writeln!(
            out,
            "| `{}` | `{}` | `{}` | `{}` |",
            command.command_id,
            command.command_role,
            command.transcript_path_template,
            command.exact_command.replace('`', "'")
        );
    }

    out
}

fn validate_xfstests_adapter_input(input: &PermissionedXfstestsBrokerAdapterInput) -> Result<()> {
    validate_adapter_non_empty("campaign_id", &input.campaign_id)?;
    validate_adapter_non_empty("generated_at", &input.generated_at)?;
    validate_adapter_non_empty("selected_subset_id", &input.selected_subset_id)?;
    validate_adapter_non_empty("preflight_id", &input.preflight_id)?;
    if input.target_beads.is_empty() {
        bail!("target_beads must include bd-rchk3.3 or an equivalent xfstests bead");
    }
    for (index, bead) in input.target_beads.iter().enumerate() {
        if !bead.starts_with("bd-") {
            bail!("target_beads[{index}] must start with bd-");
        }
    }
    validate_adapter_safe_path("xfstests_dir", &input.xfstests_dir)?;
    validate_adapter_safe_path("test_dir", &input.test_dir)?;
    validate_adapter_safe_path("scratch_mnt", &input.scratch_mnt)?;
    validate_adapter_safe_path("result_base", &input.result_base)?;
    validate_adapter_safe_path("preflight_artifact_path", &input.preflight_artifact_path)?;
    if input.preflight_max_age_days == 0 {
        bail!("preflight_max_age_days must be positive");
    }
    if input.not_run_classification
        == PermissionedXfstestsNotRunClassification::CountsAsPassingProductSignal
    {
        bail!("xfstests not-run rows must be blocker evidence, not passing product signal");
    }
    Ok(())
}

fn validate_swarm_adapter_input(input: &PermissionedSwarmBrokerAdapterInput) -> Result<()> {
    validate_adapter_non_empty("campaign_id", &input.campaign_id)?;
    validate_adapter_non_empty("generated_at", &input.generated_at)?;
    validate_adapter_non_empty("preflight_id", &input.preflight_id)?;
    if input.target_beads.is_empty() {
        bail!("target_beads must include bd-rchk0.53.8 or an equivalent swarm bead");
    }
    for (index, bead) in input.target_beads.iter().enumerate() {
        if !bead.starts_with("bd-") {
            bail!("target_beads[{index}] must start with bd-");
        }
    }
    validate_adapter_non_empty("permissioned_runner", &input.permissioned_runner)?;
    validate_adapter_safe_path("runner_workspace", &input.runner_workspace)?;
    validate_adapter_safe_path("artifact_root", &input.artifact_root)?;
    validate_adapter_safe_path("workload_manifest_path", &input.workload_manifest_path)?;
    validate_adapter_safe_path(
        "adaptive_runtime_manifest_path",
        &input.adaptive_runtime_manifest_path,
    )?;
    validate_adapter_safe_path("resource_caps_path", &input.resource_caps_path)?;
    validate_adapter_safe_path(
        "p99_attribution_ledger_path",
        &input.p99_attribution_ledger_path,
    )?;
    validate_adapter_safe_path(
        "proof_bundle_manifest_path",
        &input.proof_bundle_manifest_path,
    )?;
    if input.proof_bundle_lane_paths.is_empty() {
        bail!("proof_bundle_lane_paths must include the swarm proof-bundle lanes");
    }
    for (index, path) in input.proof_bundle_lane_paths.iter().enumerate() {
        validate_adapter_safe_path(&format!("proof_bundle_lane_paths[{index}]"), path)?;
    }
    validate_adapter_safe_path("raw_log_path", &input.raw_log_path)?;
    validate_adapter_safe_path("release_gate_policy_path", &input.release_gate_policy_path)?;
    validate_adapter_safe_path("release_gate_output_path", &input.release_gate_output_path)?;
    validate_adapter_safe_path(
        "host_capability_proof_path",
        &input.host_capability_proof_path,
    )?;
    validate_adapter_safe_path(
        "numa_capability_proof_path",
        &input.numa_capability_proof_path,
    )?;
    validate_adapter_safe_path("preflight_artifact_path", &input.preflight_artifact_path)?;
    if input.preflight_max_age_days == 0 {
        bail!("preflight_max_age_days must be positive");
    }
    if input.release_claim_classification
        != PermissionedSwarmReleaseClaimClassification::AuthoritativeLargeHost
    {
        bail!(
            "{} cannot be used as an authoritative swarm.responsiveness broker claim",
            input.release_claim_classification.label()
        );
    }
    Ok(())
}

fn validate_adapter_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{field} must not be empty");
    }
    Ok(())
}

fn validate_adapter_safe_path(field: &str, value: &str) -> Result<()> {
    validate_adapter_non_empty(field, value)?;
    if !is_safe_relative_path(value) {
        bail!("{field} must be a safe relative artifact-scoped path");
    }
    Ok(())
}

fn xfstests_expected_artifact_paths(result_base: &str) -> Vec<String> {
    [
        "report.json",
        "stdout.log",
        "stderr.log",
        "raw-results",
        "failure_to_beads.json",
    ]
    .into_iter()
    .map(|suffix| format!("{result_base}/{suffix}"))
    .collect()
}

fn swarm_host_capability(
    input: &PermissionedSwarmBrokerAdapterInput,
) -> PermissionedSwarmHostCapability {
    let mut blockers = Vec::new();
    if input.logical_cpu_count < SWARM_MIN_LOGICAL_CPUS {
        blockers.push(format!(
            "logical_cpus={} below required >={SWARM_MIN_LOGICAL_CPUS}",
            input.logical_cpu_count
        ));
    }
    if input.ram_gib < SWARM_MIN_RAM_GIB {
        blockers.push(format!(
            "ram_gib={} below required >={SWARM_MIN_RAM_GIB}",
            input.ram_gib
        ));
    }
    if !input.numa_topology_visible {
        blockers.push("numa_topology_visible=false".to_owned());
    }
    if input.numa_node_count < SWARM_MIN_NUMA_NODES {
        blockers.push(format!(
            "numa_nodes={} below required >={SWARM_MIN_NUMA_NODES}",
            input.numa_node_count
        ));
    }

    PermissionedSwarmHostCapability {
        ready_for_authoritative_run: blockers.is_empty(),
        blockers,
    }
}

fn swarm_claim_text(capability: &PermissionedSwarmHostCapability) -> String {
    if capability.ready_for_authoritative_run {
        "operator approval material only; cannot upgrade swarm.responsiveness until executed large-host evidence, p99 attribution, proof-bundle lanes, and release-gate output are recorded"
            .to_owned()
    } else {
        format!(
            "capability blocker: {}; cannot upgrade swarm.responsiveness from this broker packet",
            capability.blockers.join("; ")
        )
    }
}

fn swarm_preflight_summary(capability: &PermissionedSwarmHostCapability) -> String {
    if capability.ready_for_authoritative_run {
        "large-host preflight satisfies CPU, RAM, and NUMA visibility floors; permissioned execution not started"
            .to_owned()
    } else {
        format!(
            "large-host preflight is blocked: {}; permissioned execution must not be treated as authoritative",
            capability.blockers.join("; ")
        )
    }
}

fn swarm_expected_artifact_paths(input: &PermissionedSwarmBrokerAdapterInput) -> Vec<String> {
    let mut paths = vec![
        input.resource_caps_path.clone(),
        input.p99_attribution_ledger_path.clone(),
        input.proof_bundle_manifest_path.clone(),
        input.raw_log_path.clone(),
        input.release_gate_output_path.clone(),
    ];
    paths.extend(input.proof_bundle_lane_paths.iter().cloned());
    paths
}

fn swarm_exact_commands(
    input: &PermissionedSwarmBrokerAdapterInput,
) -> Vec<PermissionedCampaignCommand> {
    vec![
        PermissionedCampaignCommand {
            command_id: "swarm_workload_preflight".to_owned(),
            exact_command: format!(
                "cargo run -p ffs-harness -- validate-swarm-workload-harness --manifest {}",
                shell_single_quote(&input.workload_manifest_path)
            ),
            command_role: PermissionedCampaignCommandRole::Preflight,
        },
        PermissionedCampaignCommand {
            command_id: "swarm_tail_latency_preflight".to_owned(),
            exact_command: format!(
                "cargo run -p ffs-harness -- validate-swarm-tail-latency --ledger {}",
                shell_single_quote(&input.p99_attribution_ledger_path)
            ),
            command_role: PermissionedCampaignCommandRole::Preflight,
        },
        PermissionedCampaignCommand {
            command_id: "adaptive_runtime_preflight".to_owned(),
            exact_command: format!(
                "cargo run -p ffs-harness -- validate-adaptive-runtime-manifest --manifest {}",
                shell_single_quote(&input.adaptive_runtime_manifest_path)
            ),
            command_role: PermissionedCampaignCommandRole::Preflight,
        },
        PermissionedCampaignCommand {
            command_id: "proof_bundle_preflight".to_owned(),
            exact_command: format!(
                "cargo run -p ffs-harness -- validate-proof-bundle --bundle {}",
                shell_single_quote(&input.proof_bundle_manifest_path)
            ),
            command_role: PermissionedCampaignCommandRole::Preflight,
        },
        PermissionedCampaignCommand {
            command_id: "release_gate_preflight".to_owned(),
            exact_command: format!(
                "cargo run -p ffs-harness -- evaluate-release-gates --bundle {} --policy {} --out {}",
                shell_single_quote(&input.proof_bundle_manifest_path),
                shell_single_quote(&input.release_gate_policy_path),
                shell_single_quote(&input.release_gate_output_path)
            ),
            command_role: PermissionedCampaignCommandRole::Preflight,
        },
        PermissionedCampaignCommand {
            command_id: "swarm_permissioned_run".to_owned(),
            exact_command: format!(
                "{SWARM_ENABLE_PERMISSIONED_ENV}={SWARM_ENABLE_PERMISSIONED_VALUE} {SWARM_REAL_RUN_ACK_ENV}={SWARM_REAL_RUN_ACK_VALUE} {SWARM_PERMISSIONED_RUNNER_ENV}={} {SWARM_ARTIFACT_ROOT_ENV}={} scripts/e2e/ffs_swarm_workload_harness_e2e.sh",
                shell_single_quote(&input.permissioned_runner),
                shell_single_quote(&input.artifact_root)
            ),
            command_role: PermissionedCampaignCommandRole::PermissionedRun,
        },
    ]
}

fn shell_single_quote(value: &str) -> String {
    let mut quoted = String::from("'");
    for ch in value.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

fn validate_top_level(
    manifest: &PermissionedCampaignBrokerManifest,
    issues: &mut Vec<PermissionedCampaignBrokerIssue>,
) {
    if manifest.schema_version != PERMISSIONED_CAMPAIGN_BROKER_SCHEMA_VERSION {
        push_issue(
            issues,
            "schema_version",
            "unsupported_schema_version",
            "schema_version must match the current permissioned campaign broker schema",
        );
    }
    validate_non_empty(issues, "campaign_id", &manifest.campaign_id);
    validate_non_empty(issues, "generated_at", &manifest.generated_at);
    if manifest.target_beads.is_empty() {
        push_issue(
            issues,
            "target_beads",
            "missing_target_beads",
            "target_beads must include at least one bead id",
        );
    }
    for (index, bead) in manifest.target_beads.iter().enumerate() {
        if !bead.starts_with("bd-") {
            push_issue(
                issues,
                &format!("target_beads[{index}]"),
                "malformed_target_bead",
                "target bead ids must start with bd-",
            );
        }
    }
}

fn validate_ack(
    manifest: &PermissionedCampaignBrokerManifest,
    issues: &mut Vec<PermissionedCampaignBrokerIssue>,
) {
    validate_non_empty(
        issues,
        "required_ack.env_var",
        &manifest.required_ack.env_var,
    );
    validate_non_empty(
        issues,
        "required_ack.exact_value",
        &manifest.required_ack.exact_value,
    );
    validate_non_empty(
        issues,
        "required_ack.operator_prompt",
        &manifest.required_ack.operator_prompt,
    );
    if ack_value_is_ambiguous(&manifest.required_ack.exact_value) {
        push_issue(
            issues,
            "required_ack.exact_value",
            "ambiguous_ack_value",
            "ACK value must be a single exact token, not a wildcard, placeholder, or phrase",
        );
    }
}

fn validate_runner_env(
    manifest: &PermissionedCampaignBrokerManifest,
    issues: &mut Vec<PermissionedCampaignBrokerIssue>,
) {
    if manifest.required_runner_env.is_empty() {
        push_issue(
            issues,
            "required_runner_env",
            "missing_runner_env",
            "required_runner_env must declare the runner/path variables an operator must provide",
        );
    }
    for (index, entry) in manifest.required_runner_env.iter().enumerate() {
        validate_non_empty(
            issues,
            &format!("required_runner_env[{index}].env_var"),
            &entry.env_var,
        );
        validate_non_empty(
            issues,
            &format!("required_runner_env[{index}].purpose"),
            &entry.purpose,
        );
        validate_non_empty(
            issues,
            &format!("required_runner_env[{index}].expected_shape"),
            &entry.expected_shape,
        );
    }
}

fn validate_host_facts(
    manifest: &PermissionedCampaignBrokerManifest,
    issues: &mut Vec<PermissionedCampaignBrokerIssue>,
) {
    if manifest.host_capability_facts.is_empty() {
        push_issue(
            issues,
            "host_capability_facts",
            "missing_host_capability_facts",
            "host_capability_facts must preserve the proof needed before operator approval",
        );
    }
    for (index, fact) in manifest.host_capability_facts.iter().enumerate() {
        validate_non_empty(
            issues,
            &format!("host_capability_facts[{index}].fact_id"),
            &fact.fact_id,
        );
        validate_non_empty(
            issues,
            &format!("host_capability_facts[{index}].observed_value"),
            &fact.observed_value,
        );
        validate_non_empty(
            issues,
            &format!("host_capability_facts[{index}].required_value"),
            &fact.required_value,
        );
        validate_non_empty(
            issues,
            &format!("host_capability_facts[{index}].proof_path"),
            &fact.proof_path,
        );
        validate_safe_path(
            issues,
            &format!("host_capability_facts[{index}].proof_path"),
            &fact.proof_path,
        );
    }
}

fn validate_paths(
    manifest: &PermissionedCampaignBrokerManifest,
    issues: &mut Vec<PermissionedCampaignBrokerIssue>,
) {
    if manifest.safe_path_roots.is_empty() {
        push_issue(
            issues,
            "safe_path_roots",
            "missing_safe_path_roots",
            "safe_path_roots must include at least one artifact root and the approved mutation roots",
        );
    }
    if !manifest
        .safe_path_roots
        .iter()
        .any(|root| root.purpose == PermissionedCampaignPathPurpose::ArtifactRoot)
    {
        push_issue(
            issues,
            "safe_path_roots",
            "missing_artifact_root",
            "safe_path_roots must include a root with purpose artifact_root",
        );
    }
    for (index, root) in manifest.safe_path_roots.iter().enumerate() {
        validate_non_empty(
            issues,
            &format!("safe_path_roots[{index}].root_id"),
            &root.root_id,
        );
        validate_safe_path(
            issues,
            &format!("safe_path_roots[{index}].path"),
            &root.path,
        );
    }
    if manifest.expected_artifact_paths.is_empty() {
        push_issue(
            issues,
            "expected_artifact_paths",
            "missing_expected_artifact_paths",
            "expected_artifact_paths must identify where approval and run artifacts will be written",
        );
    }
    for (index, artifact_path) in manifest.expected_artifact_paths.iter().enumerate() {
        validate_safe_path(
            issues,
            &format!("expected_artifact_paths[{index}]"),
            artifact_path,
        );
        if !path_under_safe_root(artifact_path, &manifest.safe_path_roots) {
            push_issue(
                issues,
                &format!("expected_artifact_paths[{index}]"),
                "artifact_outside_safe_roots",
                "expected artifact path must live under one of the declared safe roots",
            );
        }
    }
}

fn validate_destructive_operations(
    manifest: &PermissionedCampaignBrokerManifest,
    issues: &mut Vec<PermissionedCampaignBrokerIssue>,
) {
    if manifest.destructive_operations.is_empty() {
        push_issue(
            issues,
            "destructive_operations",
            "missing_destructive_operations",
            "destructive_operations must enumerate the operator-approved mutation surface",
        );
    }
    for (index, operation) in manifest.destructive_operations.iter().enumerate() {
        if !ALLOWED_DESTRUCTIVE_OPERATIONS.contains(&operation.as_str()) {
            push_issue(
                issues,
                &format!("destructive_operations[{index}]"),
                "unknown_destructive_operation",
                "destructive operation is outside the broker vocabulary",
            );
        }
    }
}

fn validate_cleanup_policy(
    manifest: &PermissionedCampaignBrokerManifest,
    issues: &mut Vec<PermissionedCampaignBrokerIssue>,
) {
    validate_non_empty(
        issues,
        "cleanup_policy.policy_id",
        &manifest.cleanup_policy.policy_id,
    );
    validate_non_empty(
        issues,
        "cleanup_policy.partial_artifact_policy",
        &manifest.cleanup_policy.partial_artifact_policy,
    );
}

fn validate_claim_boundary(
    manifest: &PermissionedCampaignBrokerManifest,
    issues: &mut Vec<PermissionedCampaignBrokerIssue>,
) {
    if manifest.claim_boundary.packet_status
        != PermissionedCampaignPacketStatus::ReadyForOperatorApproval
    {
        push_issue(
            issues,
            "claim_boundary.packet_status",
            "broker_packet_not_executed_evidence",
            "broker packets must stay ready_for_operator_approval until a separate run records executed evidence",
        );
    }
    if manifest.claim_boundary.product_evidence_claim
        != PermissionedCampaignProductEvidenceClaim::None
    {
        push_issue(
            issues,
            "claim_boundary.product_evidence_claim",
            "packet_cannot_count_as_product_evidence",
            "broker packets cannot count as pass/fail product evidence",
        );
    }
    if manifest
        .claim_boundary
        .required_executed_evidence
        .is_empty()
    {
        push_issue(
            issues,
            "claim_boundary.required_executed_evidence",
            "missing_required_executed_evidence",
            "claim boundary must name the executed evidence required after operator approval",
        );
    }
    validate_non_empty(
        issues,
        "claim_boundary.claim_text",
        &manifest.claim_boundary.claim_text,
    );
}

fn validate_preflight_references(
    manifest: &PermissionedCampaignBrokerManifest,
    config: &PermissionedCampaignBrokerValidationConfig,
    issues: &mut Vec<PermissionedCampaignBrokerIssue>,
) {
    if manifest.preflight_references.is_empty() {
        push_issue(
            issues,
            "preflight_references",
            "missing_preflight_references",
            "preflight_references must preserve current readiness evidence for operator review",
        );
    }
    for (index, reference) in manifest.preflight_references.iter().enumerate() {
        validate_non_empty(
            issues,
            &format!("preflight_references[{index}].preflight_id"),
            &reference.preflight_id,
        );
        validate_non_empty(
            issues,
            &format!("preflight_references[{index}].artifact_path"),
            &reference.artifact_path,
        );
        validate_safe_path(
            issues,
            &format!("preflight_references[{index}].artifact_path"),
            &reference.artifact_path,
        );
        validate_non_empty(
            issues,
            &format!("preflight_references[{index}].summary"),
            &reference.summary,
        );
        if reference.max_age_days == 0 {
            push_issue(
                issues,
                &format!("preflight_references[{index}].max_age_days"),
                "zero_preflight_max_age",
                "preflight references must define a positive freshness window",
            );
        }
        let age_days = config
            .reference_epoch_days
            .saturating_sub(reference.observed_at_epoch_days);
        if age_days > reference.max_age_days {
            push_issue(
                issues,
                &format!("preflight_references[{index}].observed_at_epoch_days"),
                "stale_preflight_reference",
                "preflight reference is too old for an operator handoff packet",
            );
        }
    }
}

fn validate_operator_risks(
    manifest: &PermissionedCampaignBrokerManifest,
    issues: &mut Vec<PermissionedCampaignBrokerIssue>,
) {
    if manifest.operator_risks.is_empty() {
        push_issue(
            issues,
            "operator_risks",
            "missing_operator_risk_text",
            "operator_risks must describe the destructive or high-resource risk before approval",
        );
    }
    for (index, risk) in manifest.operator_risks.iter().enumerate() {
        validate_non_empty(issues, &format!("operator_risks[{index}]"), risk);
    }
}

fn validate_exact_commands(
    manifest: &PermissionedCampaignBrokerManifest,
    issues: &mut Vec<PermissionedCampaignBrokerIssue>,
) {
    if manifest.exact_commands.is_empty() {
        push_issue(
            issues,
            "exact_commands",
            "missing_exact_commands",
            "exact_commands must include the handoff commands an operator may approve",
        );
    }
    for (index, command) in manifest.exact_commands.iter().enumerate() {
        validate_non_empty(
            issues,
            &format!("exact_commands[{index}].command_id"),
            &command.command_id,
        );
        validate_non_empty(
            issues,
            &format!("exact_commands[{index}].exact_command"),
            &command.exact_command,
        );
    }
}

fn validate_non_empty(issues: &mut Vec<PermissionedCampaignBrokerIssue>, path: &str, value: &str) {
    if value.trim().is_empty() {
        push_issue(
            issues,
            path,
            "missing_required_field",
            "required field must not be empty",
        );
    }
}

fn validate_safe_path(
    issues: &mut Vec<PermissionedCampaignBrokerIssue>,
    field_path: &str,
    raw_path: &str,
) {
    if !is_safe_relative_path(raw_path) {
        push_issue(
            issues,
            field_path,
            "unsafe_path",
            "path must be a non-empty relative path without parent traversal",
        );
    }
}

#[must_use]
pub fn is_safe_relative_path(raw_path: &str) -> bool {
    let trimmed = raw_path.trim();
    if trimmed.is_empty() {
        return false;
    }
    let path = Path::new(trimmed);
    !path.is_absolute()
        && !is_repo_control_path(path)
        && path.components().all(|component| {
            !matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
}

fn current_epoch_days() -> Option<u32> {
    let unix_epoch_days = parse_manifest_timestamp_epoch_days("1970-01-01T00:00:00Z")?;
    let elapsed_days = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() / 86_400;
    let total_days = u64::from(unix_epoch_days).checked_add(elapsed_days)?;
    u32::try_from(total_days).ok()
}

fn ack_value_is_ambiguous(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.split_whitespace().count() != 1
        || trimmed.contains('*')
        || trimmed.contains('?')
        || trimmed.contains('<')
        || trimmed.contains('>')
        || trimmed.contains("${")
}

fn is_repo_control_path(path: &Path) -> bool {
    let Some(Component::Normal(first)) = path.components().next() else {
        return true;
    };
    matches!(
        first.to_str(),
        Some(".git" | ".beads" | "crates" | "src" | "target" | "Cargo.toml" | "Cargo.lock")
    )
}

fn runner_env_summary(
    manifest: &PermissionedCampaignBrokerManifest,
) -> Vec<PermissionedCampaignRunnerEnvSummary> {
    manifest
        .required_runner_env
        .iter()
        .map(|entry| PermissionedCampaignRunnerEnvSummary {
            env_var: entry.env_var.clone(),
            purpose: entry.purpose.clone(),
            expected_shape: entry.expected_shape.clone(),
        })
        .collect()
}

fn host_fact_summary(
    manifest: &PermissionedCampaignBrokerManifest,
) -> Vec<PermissionedCampaignHostFactSummary> {
    manifest
        .host_capability_facts
        .iter()
        .map(|fact| PermissionedCampaignHostFactSummary {
            fact_id: fact.fact_id.clone(),
            observed_value: fact.observed_value.clone(),
            required_value: fact.required_value.clone(),
            proof_path: fact.proof_path.clone(),
        })
        .collect()
}

fn path_root_summary(
    manifest: &PermissionedCampaignBrokerManifest,
) -> Vec<PermissionedCampaignPathRootSummary> {
    manifest
        .safe_path_roots
        .iter()
        .map(|root| PermissionedCampaignPathRootSummary {
            root_id: root.root_id.clone(),
            path: root.path.clone(),
            purpose: root.purpose.label().to_owned(),
        })
        .collect()
}

fn preflight_summary(
    manifest: &PermissionedCampaignBrokerManifest,
    config: &PermissionedCampaignBrokerValidationConfig,
) -> Vec<PermissionedCampaignPreflightSummary> {
    manifest
        .preflight_references
        .iter()
        .map(|reference| {
            let age_days = config
                .reference_epoch_days
                .saturating_sub(reference.observed_at_epoch_days);
            PermissionedCampaignPreflightSummary {
                preflight_id: reference.preflight_id.clone(),
                artifact_path: reference.artifact_path.clone(),
                age_days,
                max_age_days: reference.max_age_days,
                stale: age_days > reference.max_age_days,
                summary: reference.summary.clone(),
            }
        })
        .collect()
}

fn command_summary(
    manifest: &PermissionedCampaignBrokerManifest,
) -> Vec<PermissionedCampaignCommandSummary> {
    manifest
        .exact_commands
        .iter()
        .map(|command| PermissionedCampaignCommandSummary {
            command_id: command.command_id.clone(),
            command_role: command.command_role.label().to_owned(),
            exact_command: command.exact_command.clone(),
        })
        .collect()
}

fn handoff_command_summary(
    manifest: &PermissionedCampaignBrokerManifest,
) -> Vec<PermissionedCampaignHandoffCommand> {
    let campaign_component = sanitize_packet_component(&manifest.campaign_id);
    manifest
        .exact_commands
        .iter()
        .map(|command| {
            let command_component = sanitize_packet_component(&command.command_id);
            PermissionedCampaignHandoffCommand {
                command_id: command.command_id.clone(),
                command_role: command.command_role.label().to_owned(),
                exact_command: command.exact_command.clone(),
                transcript_path_template: format!(
                    "artifacts/permissioned/{campaign_component}/commands/{command_component}.log"
                ),
            }
        })
        .collect()
}

fn sanitize_packet_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

fn markdown_cell(value: &str) -> String {
    value.replace('|', "/")
}

fn path_under_safe_root(path: &str, roots: &[PermissionedCampaignPathRoot]) -> bool {
    roots.iter().any(|root| {
        path == root.path
            || path
                .strip_prefix(&root.path)
                .is_some_and(|tail| tail.starts_with('/'))
    })
}

fn push_issue(
    issues: &mut Vec<PermissionedCampaignBrokerIssue>,
    path: &str,
    code: &str,
    message: &str,
) {
    issues.push(PermissionedCampaignBrokerIssue {
        path: path.to_owned(),
        code: code.to_owned(),
        message: message.to_owned(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_manifest::parse_manifest_timestamp_epoch_days;

    const REFERENCE_TIMESTAMP: &str = "2026-05-07T00:00:00Z";

    #[test]
    fn valid_xfstests_manifest_round_trips() -> Result<(), serde_json::Error> {
        let manifest = valid_xfstests_manifest();
        let json = serde_json::to_string_pretty(&manifest)?;
        let decoded: PermissionedCampaignBrokerManifest = serde_json::from_str(&json)?;
        assert_eq!(decoded, manifest);
        assert_valid(&decoded);
        Ok(())
    }

    #[test]
    fn valid_swarm_manifest_round_trips() -> Result<(), serde_json::Error> {
        let manifest = valid_swarm_manifest();
        let json = serde_json::to_string_pretty(&manifest)?;
        let decoded: PermissionedCampaignBrokerManifest = serde_json::from_str(&json)?;
        assert_eq!(decoded, manifest);
        assert_valid(&decoded);
        Ok(())
    }

    #[test]
    fn missing_ack_text_is_rejected() {
        let mut manifest = valid_xfstests_manifest();
        manifest.required_ack.exact_value.clear();
        assert_issue(&manifest, "missing_required_field");
    }

    #[test]
    fn missing_artifact_root_is_rejected() {
        let mut manifest = valid_xfstests_manifest();
        manifest
            .safe_path_roots
            .retain(|root| root.purpose != PermissionedCampaignPathPurpose::ArtifactRoot);
        assert_issue(&manifest, "missing_artifact_root");
    }

    #[test]
    fn unsafe_path_is_rejected() {
        let mut manifest = valid_xfstests_manifest();
        if let Some(path) = manifest.expected_artifact_paths.get_mut(0) {
            *path = "../escape/report.json".to_owned();
        }
        assert_issue(&manifest, "unsafe_path");
    }

    #[test]
    fn stale_preflight_timestamp_is_rejected() {
        let mut manifest = valid_xfstests_manifest();
        if let Some(reference) = manifest.preflight_references.get_mut(0) {
            reference.observed_at_epoch_days = reference_epoch_days() - 30;
        }
        assert_issue(&manifest, "stale_preflight_reference");
    }

    #[test]
    fn absent_claim_boundary_is_rejected() {
        let mut manifest = valid_xfstests_manifest();
        manifest.claim_boundary.required_executed_evidence.clear();
        manifest.claim_boundary.claim_text.clear();
        assert_issue(&manifest, "missing_required_executed_evidence");
        assert_issue(&manifest, "missing_required_field");
    }

    #[test]
    fn unknown_destructive_operation_is_rejected() {
        let mut manifest = valid_xfstests_manifest();
        manifest
            .destructive_operations
            .push("rewrite_real_home_directory".to_owned());
        assert_issue(&manifest, "unknown_destructive_operation");
    }

    #[test]
    fn ambiguous_ack_value_is_rejected() {
        let mut manifest = valid_xfstests_manifest();
        manifest.required_ack.exact_value = "xfstests * maybe".to_owned();
        assert_issue(&manifest, "ambiguous_ack_value");
    }

    #[test]
    fn repo_control_path_is_rejected() {
        let mut manifest = valid_xfstests_manifest();
        manifest.safe_path_roots.push(path_root(
            "repo_source",
            "crates/ffs-harness",
            PermissionedCampaignPathPurpose::RunnerWorkspace,
        ));
        assert_issue(&manifest, "unsafe_path");
    }

    #[test]
    fn broker_packets_cannot_claim_executed_product_evidence() {
        let mut manifest = valid_swarm_manifest();
        manifest.claim_boundary.packet_status = PermissionedCampaignPacketStatus::ExecutedEvidence;
        manifest.claim_boundary.product_evidence_claim =
            PermissionedCampaignProductEvidenceClaim::PacketCountsAsPassFail;
        let report = validate_permissioned_campaign_broker_manifest(&manifest, &config());
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.code == "broker_packet_not_executed_evidence")
        );
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.code == "packet_cannot_count_as_product_evidence")
        );
    }

    #[test]
    fn markdown_summary_includes_ack_and_ready_boundary() {
        let report =
            validate_permissioned_campaign_broker_manifest(&valid_xfstests_manifest(), &config());
        let markdown = render_permissioned_campaign_broker_markdown(&report);
        assert!(markdown.contains("XFSTESTS_REAL_RUN_ACK"));
        assert!(markdown.contains("ready_for_operator_approval"));
        assert!(markdown.contains("operator approval material"));
    }

    #[test]
    fn invalid_report_fails_close_gate() {
        let mut manifest = valid_swarm_manifest();
        manifest.required_ack.exact_value.clear();
        let report = validate_permissioned_campaign_broker_manifest(&manifest, &config());
        assert!(fail_on_permissioned_campaign_broker_errors(&report).is_err());
    }

    #[test]
    fn xfstests_handoff_packet_matches_golden_fields() -> Result<()> {
        let packet = generate_permissioned_campaign_handoff_packet(
            &valid_xfstests_manifest(),
            &config(),
            generation(),
        )?;
        assert_eq!(packet.packet_schema_version, 1);
        assert_eq!(
            packet.required_ack.export_command,
            "XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices"
        );
        assert_eq!(packet.product_evidence_claim, "none");
        assert_eq!(packet.packet_status, "ready_for_operator_approval");
        assert!(
            packet
                .expected_artifact_paths
                .iter()
                .any(|path| path == "artifacts/xfstests/real-run/report.json")
        );
        assert!(packet.exact_commands.iter().any(|command| {
            command.command_id == "xfstests_permissioned_run"
                && command
                    .transcript_path_template
                    .ends_with("/xfstests_permissioned_run.log")
        }));
        let markdown = render_permissioned_campaign_handoff_markdown(&packet);
        assert!(markdown.contains(PERMISSIONED_CAMPAIGN_HANDOFF_NOTICE));
        assert!(markdown.contains("not executed evidence"));
        assert!(markdown.contains("XFSTESTS_REAL_RUN_ACK"));
        assert!(markdown.contains("Command Transcript Template"));
        Ok(())
    }

    #[test]
    fn swarm_handoff_packet_matches_golden_fields() -> Result<()> {
        let packet = generate_permissioned_campaign_handoff_packet(
            &valid_swarm_manifest(),
            &config(),
            generation(),
        )?;
        assert_eq!(packet.lane_kind, "large_host_swarm_responsiveness");
        assert!(
            packet
                .runner_env
                .iter()
                .any(|entry| entry.env_var == "FFS_SWARM_WORKLOAD_PERMISSIONED_RUNNER")
        );
        assert!(
            packet
                .host_capability_facts
                .iter()
                .any(|fact| fact.fact_id == "ram_gb" && fact.required_value == ">=256")
        );
        assert!(
            packet
                .destructive_operations
                .iter()
                .any(|operation| operation == "spawn_large_host_workers")
        );
        assert!(packet.exact_commands.iter().any(|command| {
            command.command_id == "swarm_permissioned_run"
                && command
                    .exact_command
                    .contains("FFS_SWARM_WORKLOAD_REAL_RUN_ACK")
        }));
        Ok(())
    }

    #[test]
    fn invalid_manifest_cannot_render_handoff_packet() {
        let mut manifest = valid_xfstests_manifest();
        manifest.safe_path_roots.push(path_root(
            "repo_source",
            "crates/ffs-harness",
            PermissionedCampaignPathPurpose::RunnerWorkspace,
        ));
        assert!(
            generate_permissioned_campaign_handoff_packet(&manifest, &config(), generation())
                .is_err()
        );
    }

    #[test]
    fn handoff_markdown_is_deterministic() -> Result<()> {
        let packet = generate_permissioned_campaign_handoff_packet(
            &valid_swarm_manifest(),
            &config(),
            generation(),
        )?;
        assert_eq!(
            render_permissioned_campaign_handoff_markdown(&packet),
            render_permissioned_campaign_handoff_markdown(&packet)
        );
        Ok(())
    }

    #[test]
    fn xfstests_adapter_renders_ready_handoff_packet() -> Result<()> {
        let manifest = build_xfstests_broker_manifest(&xfstests_adapter_input())?;
        let report = validate_permissioned_campaign_broker_manifest(&manifest, &config());
        assert!(report.valid, "{:?}", report.issues);
        assert_eq!(manifest.required_ack.env_var, XFSTESTS_REAL_RUN_ACK_ENV);
        assert_eq!(
            manifest.required_ack.exact_value,
            XFSTESTS_REAL_RUN_ACK_VALUE
        );
        assert!(
            manifest
                .expected_artifact_paths
                .iter()
                .any(|path| path == "artifacts/xfstests/real-run/failure_to_beads.json")
        );

        let packet =
            generate_xfstests_handoff_packet(&xfstests_adapter_input(), &config(), generation())?;
        assert_eq!(packet.product_evidence_claim, "none");
        assert!(packet.claim_text.contains("not-run rows are blockers"));
        assert!(
            packet
                .exact_commands
                .iter()
                .any(|command| command.command_id == "xfstests_permissioned_run"
                    && command.exact_command.contains(XFSTESTS_REAL_RUN_ACK_VALUE))
        );
        Ok(())
    }

    #[test]
    fn xfstests_adapter_rejects_missing_explicit_paths() {
        let clear_required_paths: [fn(&mut PermissionedXfstestsBrokerAdapterInput); 3] = [
            |input: &mut PermissionedXfstestsBrokerAdapterInput| input.test_dir.clear(),
            |input: &mut PermissionedXfstestsBrokerAdapterInput| input.scratch_mnt.clear(),
            |input: &mut PermissionedXfstestsBrokerAdapterInput| input.result_base.clear(),
        ];
        for clear_required_path in clear_required_paths {
            let mut input = xfstests_adapter_input();
            clear_required_path(&mut input);
            assert!(build_xfstests_broker_manifest(&input).is_err());
        }
    }

    #[test]
    fn xfstests_adapter_quotes_handoff_command_paths() -> Result<()> {
        let mut input = xfstests_adapter_input();
        input.test_dir = "artifacts/xfstests/test dir".to_owned();
        input.scratch_mnt = "artifacts/xfstests/scratch'space".to_owned();
        let manifest = build_xfstests_broker_manifest(&input)?;
        let permissioned_run = manifest
            .exact_commands
            .iter()
            .find(|command| command.command_id == "xfstests_permissioned_run")
            .context("permissioned run command")?;
        assert!(
            permissioned_run
                .exact_command
                .contains("TEST_DIR='artifacts/xfstests/test dir'")
        );
        assert!(
            permissioned_run
                .exact_command
                .contains("SCRATCH_MNT='artifacts/xfstests/scratch'\\''space'")
        );
        Ok(())
    }

    #[test]
    fn xfstests_adapter_rejects_stale_preflight() {
        let mut input = xfstests_adapter_input();
        input.preflight_observed_at_epoch_days = reference_epoch_days() - 30;
        assert!(generate_xfstests_handoff_packet(&input, &config(), generation()).is_err());
    }

    #[test]
    fn xfstests_adapter_rejects_not_run_as_pass_classification() {
        let mut input = xfstests_adapter_input();
        input.not_run_classification =
            PermissionedXfstestsNotRunClassification::CountsAsPassingProductSignal;
        assert!(build_xfstests_broker_manifest(&input).is_err());
    }

    #[test]
    fn swarm_adapter_renders_ready_handoff_packet_for_capable_host() -> Result<()> {
        let input = swarm_adapter_input();
        let manifest = build_swarm_broker_manifest(&input)?;
        let report = validate_permissioned_campaign_broker_manifest(&manifest, &config());
        assert!(report.valid, "{:?}", report.issues);
        assert_eq!(manifest.required_ack.env_var, SWARM_REAL_RUN_ACK_ENV);
        assert_eq!(manifest.required_ack.exact_value, SWARM_REAL_RUN_ACK_VALUE);
        assert!(manifest.required_runner_env.iter().any(|entry| {
            entry.env_var == SWARM_ENABLE_PERMISSIONED_ENV
                && entry.expected_shape == SWARM_ENABLE_PERMISSIONED_VALUE
        }));
        assert!(
            manifest
                .expected_artifact_paths
                .iter()
                .any(|path| path == "artifacts/swarm/large-host/p99_attribution.json")
        );
        assert!(
            manifest
                .expected_artifact_paths
                .iter()
                .any(|path| path == "artifacts/swarm/large-host/proof/swarm_tail_latency.json")
        );
        assert!(
            manifest
                .host_capability_facts
                .iter()
                .any(|fact| fact.fact_id == "logical_cpus" && fact.observed_value == "96")
        );

        let packet = generate_swarm_handoff_packet(&input, &config(), generation())?;
        assert_eq!(packet.product_evidence_claim, "none");
        assert_eq!(packet.packet_status, "ready_for_operator_approval");
        assert!(
            packet
                .claim_text
                .contains("cannot upgrade swarm.responsiveness")
        );
        assert!(
            packet
                .preflight_references
                .iter()
                .any(|reference| reference.summary.contains("satisfies CPU"))
        );
        assert!(packet.exact_commands.iter().any(|command| {
            command.command_id == "swarm_permissioned_run"
                && command
                    .exact_command
                    .contains(SWARM_ENABLE_PERMISSIONED_ENV)
                && command
                    .exact_command
                    .contains(SWARM_PERMISSIONED_RUNNER_ENV)
                && command.exact_command.contains(SWARM_REAL_RUN_ACK_VALUE)
        }));
        Ok(())
    }

    #[test]
    fn swarm_adapter_renders_blocker_packet_for_insufficient_host_proof() -> Result<()> {
        let mut input = swarm_adapter_input();
        input.logical_cpu_count = 16;
        input.ram_gib = 64;
        input.numa_node_count = 0;
        input.numa_topology_visible = false;

        let packet = generate_swarm_handoff_packet(&input, &config(), generation())?;
        assert_eq!(packet.product_evidence_claim, "none");
        assert_eq!(packet.packet_status, "ready_for_operator_approval");
        assert!(packet.claim_text.contains("capability blocker"));
        assert!(packet.claim_text.contains("logical_cpus=16"));
        assert!(
            packet
                .claim_text
                .contains("cannot upgrade swarm.responsiveness")
        );
        assert!(packet.preflight_references[0].summary.contains("blocked"));
        assert!(
            packet
                .host_capability_facts
                .iter()
                .any(|fact| fact.fact_id == "numa_topology_visible"
                    && fact.observed_value == "false")
        );
        Ok(())
    }

    #[test]
    fn swarm_adapter_rejects_small_host_smoke_as_authoritative() {
        let mut input = swarm_adapter_input();
        input.release_claim_classification =
            PermissionedSwarmReleaseClaimClassification::SmallHostSmoke;
        let err = build_swarm_broker_manifest(&input).expect_err("small-host smoke rejected");
        assert!(err.to_string().contains("small_host_smoke"));
        assert!(
            err.to_string()
                .contains("authoritative swarm.responsiveness")
        );
    }

    #[test]
    fn swarm_adapter_output_cannot_upgrade_swarm_responsiveness() -> Result<()> {
        let input = swarm_adapter_input();
        let manifest = build_swarm_broker_manifest(&input)?;
        assert_eq!(
            manifest.claim_boundary.product_evidence_claim,
            PermissionedCampaignProductEvidenceClaim::None
        );
        assert_eq!(
            manifest.claim_boundary.packet_status,
            PermissionedCampaignPacketStatus::ReadyForOperatorApproval
        );
        assert!(
            manifest
                .claim_boundary
                .claim_text
                .contains("cannot upgrade swarm.responsiveness")
        );

        let packet = generate_swarm_handoff_packet(&input, &config(), generation())?;
        let markdown = render_permissioned_campaign_handoff_markdown(&packet);
        assert!(markdown.contains(PERMISSIONED_CAMPAIGN_HANDOFF_NOTICE));
        assert!(markdown.contains("not executed evidence"));
        assert!(markdown.contains("cannot upgrade swarm.responsiveness"));
        assert!(!markdown.contains("packet_counts_as_pass_fail"));
        Ok(())
    }

    fn assert_valid(manifest: &PermissionedCampaignBrokerManifest) {
        let report = validate_permissioned_campaign_broker_manifest(manifest, &config());
        assert!(report.valid, "{:?}", report.issues);
        assert_eq!(report.packet_status, "ready_for_operator_approval");
        assert_eq!(report.product_evidence_claim, "none");
    }

    fn assert_issue(manifest: &PermissionedCampaignBrokerManifest, code: &str) {
        let report = validate_permissioned_campaign_broker_manifest(manifest, &config());
        assert!(
            report.issues.iter().any(|issue| issue.code == code),
            "missing issue {code}; got {:?}",
            report.issues
        );
    }

    fn config() -> PermissionedCampaignBrokerValidationConfig {
        PermissionedCampaignBrokerValidationConfig {
            reference_epoch_days: reference_epoch_days(),
        }
    }

    fn reference_epoch_days() -> u32 {
        let parsed = parse_manifest_timestamp_epoch_days(REFERENCE_TIMESTAMP);
        assert!(parsed.is_some());
        parsed.unwrap_or(0)
    }

    fn generation() -> PermissionedCampaignHandoffGeneration {
        PermissionedCampaignHandoffGeneration {
            generated_at: REFERENCE_TIMESTAMP.to_owned(),
            generated_by: "FrostyRobin".to_owned(),
            git_sha: "abcdef123456".to_owned(),
        }
    }

    fn xfstests_adapter_input() -> PermissionedXfstestsBrokerAdapterInput {
        PermissionedXfstestsBrokerAdapterInput {
            campaign_id: "bd-rchk3.3-xfstests-real-20260507".to_owned(),
            generated_at: REFERENCE_TIMESTAMP.to_owned(),
            target_beads: vec!["bd-rchk3.3".to_owned(), "bd-rchk3".to_owned()],
            selected_subset_id: "supported-smoke-subset-20260505".to_owned(),
            xfstests_dir: "third_party/xfstests-dev".to_owned(),
            test_dir: "artifacts/xfstests/test-dir".to_owned(),
            scratch_mnt: "artifacts/xfstests/scratch".to_owned(),
            result_base: "artifacts/xfstests/real-run".to_owned(),
            preflight_id: "xfstests-explicit-path-preflight".to_owned(),
            preflight_artifact_path: "artifacts/xfstests/preflight/report.json".to_owned(),
            preflight_observed_at_epoch_days: reference_epoch_days(),
            preflight_max_age_days: DEFAULT_PERMISSIONED_CAMPAIGN_PREFLIGHT_MAX_AGE_DAYS,
            not_run_classification:
                PermissionedXfstestsNotRunClassification::EnvironmentBlockerOnly,
        }
    }

    fn swarm_adapter_input() -> PermissionedSwarmBrokerAdapterInput {
        PermissionedSwarmBrokerAdapterInput {
            campaign_id: "bd-rchk0.53.8-large-host-swarm-20260507".to_owned(),
            generated_at: REFERENCE_TIMESTAMP.to_owned(),
            target_beads: vec!["bd-rchk0.53.8".to_owned(), "bd-rchk0.53".to_owned()],
            permissioned_runner: "tools/permissioned/swarm-large-host-runner".to_owned(),
            runner_workspace: "artifacts/swarm/workspace".to_owned(),
            artifact_root: "artifacts/swarm/large-host".to_owned(),
            workload_manifest_path: "benchmarks/swarm_workload_harness_manifest.json".to_owned(),
            adaptive_runtime_manifest_path: "docs/adaptive-runtime-evidence-manifest.json"
                .to_owned(),
            resource_caps_path: "artifacts/swarm/large-host/resource_caps.json".to_owned(),
            p99_attribution_ledger_path: "artifacts/swarm/large-host/p99_attribution.json"
                .to_owned(),
            proof_bundle_manifest_path: "artifacts/swarm/large-host/proof/bundle.json".to_owned(),
            proof_bundle_lane_paths: vec![
                "artifacts/swarm/large-host/proof/swarm_workload_harness.json".to_owned(),
                "artifacts/swarm/large-host/proof/swarm_tail_latency.json".to_owned(),
                "artifacts/swarm/large-host/proof/adaptive_runtime.json".to_owned(),
            ],
            raw_log_path: "artifacts/swarm/large-host/raw.log".to_owned(),
            release_gate_policy_path: "artifacts/swarm/large-host/release_gate_policy.json"
                .to_owned(),
            release_gate_output_path: "artifacts/swarm/large-host/release_gate.json".to_owned(),
            host_capability_proof_path: "artifacts/swarm/preflight/host.json".to_owned(),
            numa_capability_proof_path: "artifacts/swarm/preflight/numa.json".to_owned(),
            preflight_id: "swarm-large-host-capability-preflight".to_owned(),
            preflight_artifact_path: "artifacts/swarm/preflight/report.json".to_owned(),
            preflight_observed_at_epoch_days: reference_epoch_days(),
            preflight_max_age_days: DEFAULT_PERMISSIONED_CAMPAIGN_PREFLIGHT_MAX_AGE_DAYS,
            logical_cpu_count: 96,
            ram_gib: 512,
            numa_node_count: 2,
            numa_topology_visible: true,
            release_claim_classification:
                PermissionedSwarmReleaseClaimClassification::AuthoritativeLargeHost,
        }
    }

    fn valid_xfstests_manifest() -> PermissionedCampaignBrokerManifest {
        PermissionedCampaignBrokerManifest {
            schema_version: PERMISSIONED_CAMPAIGN_BROKER_SCHEMA_VERSION,
            campaign_id: "bd-rchk3.3-xfstests-real-20260507".to_owned(),
            lane_kind: PermissionedCampaignLaneKind::XfstestsRealBaseline,
            target_beads: vec!["bd-rchk3.3".to_owned(), "bd-rchk3".to_owned()],
            generated_at: REFERENCE_TIMESTAMP.to_owned(),
            required_ack: PermissionedCampaignAck {
                env_var: "XFSTESTS_REAL_RUN_ACK".to_owned(),
                exact_value: "xfstests-may-mutate-test-and-scratch-devices".to_owned(),
                operator_prompt:
                    "Approve real xfstests execution against scoped test and scratch devices"
                        .to_owned(),
            },
            required_runner_env: vec![
                runner_env("TEST_DIR", "scoped xfstests test mount root"),
                runner_env("SCRATCH_MNT", "scoped xfstests scratch mount root"),
                runner_env("RESULT_BASE", "artifact root for raw xfstests results"),
            ],
            host_capability_facts: vec![
                host_fact(
                    "xfstests_helpers",
                    "present",
                    "present",
                    "artifacts/xfstests/preflight/helpers.json",
                ),
                host_fact(
                    "fuse_access",
                    "available",
                    "available",
                    "artifacts/xfstests/preflight/fuse.json",
                ),
            ],
            safe_path_roots: vec![
                path_root(
                    "test_dir",
                    "artifacts/xfstests/test-dir",
                    PermissionedCampaignPathPurpose::TestData,
                ),
                path_root(
                    "scratch",
                    "artifacts/xfstests/scratch",
                    PermissionedCampaignPathPurpose::Scratch,
                ),
                path_root(
                    "results",
                    "artifacts/xfstests/real-run",
                    PermissionedCampaignPathPurpose::ArtifactRoot,
                ),
            ],
            destructive_operations: vec![
                "mount_test_device".to_owned(),
                "mount_scratch_device".to_owned(),
                "mutate_test_device".to_owned(),
                "mutate_scratch_device".to_owned(),
            ],
            expected_artifact_paths: vec![
                "artifacts/xfstests/real-run/report.json".to_owned(),
                "artifacts/xfstests/real-run/stdout.log".to_owned(),
                "artifacts/xfstests/real-run/stderr.log".to_owned(),
            ],
            cleanup_policy: cleanup_policy("xfstests_preserve_partial_artifacts"),
            claim_boundary: claim_boundary(vec![
                "raw xfstests logs".to_owned(),
                "pass/fail/not-run summary".to_owned(),
                "failure-to-bead extraction report".to_owned(),
            ]),
            preflight_references: vec![preflight_reference(
                "xfstests-explicit-path-preflight",
                "artifacts/xfstests/preflight/report.json",
            )],
            operator_risks: vec![
                "xfstests may mutate the scoped test and scratch devices".to_owned(),
                "partial runs must preserve raw logs before cleanup".to_owned(),
            ],
            exact_commands: vec![
                command(
                    "xfstests_preflight",
                    "cargo run -p ffs-harness -- xfstests-preflight --xfstests-dir third_party/xfstests-dev",
                    PermissionedCampaignCommandRole::Preflight,
                ),
                command(
                    "xfstests_permissioned_run",
                    "XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices scripts/e2e/ffs_xfstests_e2e.sh",
                    PermissionedCampaignCommandRole::PermissionedRun,
                ),
            ],
        }
    }

    fn valid_swarm_manifest() -> PermissionedCampaignBrokerManifest {
        PermissionedCampaignBrokerManifest {
            schema_version: PERMISSIONED_CAMPAIGN_BROKER_SCHEMA_VERSION,
            campaign_id: "bd-rchk0.53.8-large-host-swarm-20260507".to_owned(),
            lane_kind: PermissionedCampaignLaneKind::LargeHostSwarmResponsiveness,
            target_beads: vec!["bd-rchk0.53.8".to_owned()],
            generated_at: REFERENCE_TIMESTAMP.to_owned(),
            required_ack: PermissionedCampaignAck {
                env_var: "FFS_SWARM_WORKLOAD_REAL_RUN_ACK".to_owned(),
                exact_value: "swarm-workload-may-use-permissioned-large-host".to_owned(),
                operator_prompt: "Approve large-host swarm responsiveness execution".to_owned(),
            },
            required_runner_env: vec![
                runner_env(
                    "FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD",
                    "permissioned workload opt-in",
                ),
                runner_env(
                    "FFS_SWARM_WORKLOAD_PERMISSIONED_RUNNER",
                    "large-host runner identifier",
                ),
                runner_env(
                    "FFS_SWARM_WORKLOAD_ARTIFACT_ROOT",
                    "artifact root for swarm output",
                ),
            ],
            host_capability_facts: vec![
                host_fact(
                    "logical_cpus",
                    "96",
                    ">=64",
                    "artifacts/swarm/preflight/host.json",
                ),
                host_fact(
                    "ram_gb",
                    "512",
                    ">=256",
                    "artifacts/swarm/preflight/host.json",
                ),
                host_fact(
                    "numa_nodes",
                    "2",
                    ">=2",
                    "artifacts/swarm/preflight/numa.json",
                ),
            ],
            safe_path_roots: vec![
                path_root(
                    "runner_workspace",
                    "artifacts/swarm/workspace",
                    PermissionedCampaignPathPurpose::RunnerWorkspace,
                ),
                path_root(
                    "results",
                    "artifacts/swarm/large-host",
                    PermissionedCampaignPathPurpose::ArtifactRoot,
                ),
            ],
            destructive_operations: vec![
                "generate_filesystem_load".to_owned(),
                "spawn_large_host_workers".to_owned(),
                "consume_large_temp_storage".to_owned(),
                "kill_replay_worker".to_owned(),
            ],
            expected_artifact_paths: vec![
                "artifacts/swarm/large-host/validator_report.json".to_owned(),
                "artifacts/swarm/large-host/p99_attribution.json".to_owned(),
                "artifacts/swarm/large-host/raw.log".to_owned(),
            ],
            cleanup_policy: cleanup_policy("swarm_preserve_raw_logs"),
            claim_boundary: claim_boundary(vec![
                "validator report".to_owned(),
                "p99 attribution ledger".to_owned(),
                "release-gate output".to_owned(),
            ]),
            preflight_references: vec![preflight_reference(
                "swarm-large-host-capability-preflight",
                "artifacts/swarm/preflight/report.json",
            )],
            operator_risks: vec![
                "large-host run may consume high CPU and temporary storage".to_owned(),
                "tail latency claims require raw logs and attribution artifacts".to_owned(),
            ],
            exact_commands: vec![
                command(
                    "swarm_preflight",
                    "cargo run -p ffs-harness -- validate-swarm-workload-harness --manifest benchmarks/swarm_workload_harness_manifest.json",
                    PermissionedCampaignCommandRole::Preflight,
                ),
                command(
                    "swarm_permissioned_run",
                    "FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD=1 FFS_SWARM_WORKLOAD_REAL_RUN_ACK=swarm-workload-may-use-permissioned-large-host scripts/e2e/ffs_swarm_workload_harness_e2e.sh",
                    PermissionedCampaignCommandRole::PermissionedRun,
                ),
            ],
        }
    }

    fn runner_env(env_var: &str, purpose: &str) -> PermissionedCampaignRunnerEnv {
        PermissionedCampaignRunnerEnv {
            env_var: env_var.to_owned(),
            purpose: purpose.to_owned(),
            expected_shape: "non-empty operator-provided value".to_owned(),
        }
    }

    fn host_fact(
        fact_id: &str,
        observed_value: &str,
        required_value: &str,
        proof_path: &str,
    ) -> PermissionedCampaignHostFact {
        PermissionedCampaignHostFact {
            fact_id: fact_id.to_owned(),
            observed_value: observed_value.to_owned(),
            required_value: required_value.to_owned(),
            proof_path: proof_path.to_owned(),
        }
    }

    fn path_root(
        root_id: &str,
        path: &str,
        purpose: PermissionedCampaignPathPurpose,
    ) -> PermissionedCampaignPathRoot {
        PermissionedCampaignPathRoot {
            root_id: root_id.to_owned(),
            path: path.to_owned(),
            purpose,
        }
    }

    fn cleanup_policy(policy_id: &str) -> PermissionedCampaignCleanupPolicy {
        PermissionedCampaignCleanupPolicy {
            policy_id: policy_id.to_owned(),
            expected_status: PermissionedCampaignCleanupStatus::PreservedArtifacts,
            partial_artifact_policy: "preserve partial raw logs before any cleanup".to_owned(),
        }
    }

    fn claim_boundary(
        required_executed_evidence: Vec<String>,
    ) -> PermissionedCampaignClaimBoundary {
        PermissionedCampaignClaimBoundary {
            packet_status: PermissionedCampaignPacketStatus::ReadyForOperatorApproval,
            product_evidence_claim: PermissionedCampaignProductEvidenceClaim::None,
            required_executed_evidence,
            claim_text:
                "This packet is operator approval material only; it is not pass/fail evidence."
                    .to_owned(),
        }
    }

    fn preflight_reference(
        preflight_id: &str,
        artifact_path: &str,
    ) -> PermissionedCampaignPreflightReference {
        PermissionedCampaignPreflightReference {
            preflight_id: preflight_id.to_owned(),
            artifact_path: artifact_path.to_owned(),
            observed_at_epoch_days: reference_epoch_days(),
            max_age_days: DEFAULT_PERMISSIONED_CAMPAIGN_PREFLIGHT_MAX_AGE_DAYS,
            summary: "preflight passed; permissioned execution not started".to_owned(),
        }
    }

    fn command(
        command_id: &str,
        exact_command: &str,
        command_role: PermissionedCampaignCommandRole,
    ) -> PermissionedCampaignCommand {
        PermissionedCampaignCommand {
            command_id: command_id.to_owned(),
            exact_command: exact_command.to_owned(),
            command_role,
        }
    }
}
