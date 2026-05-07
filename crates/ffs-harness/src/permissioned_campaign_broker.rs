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
pub const DEFAULT_PERMISSIONED_CAMPAIGN_BROKER_MANIFEST: &str =
    "docs/permissioned-campaign-broker-manifest.json";
pub const DEFAULT_PERMISSIONED_CAMPAIGN_PREFLIGHT_MAX_AGE_DAYS: u32 = 14;

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
