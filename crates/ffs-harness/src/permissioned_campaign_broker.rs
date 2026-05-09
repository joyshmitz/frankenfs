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
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs;
use std::path::{Component, Path};
use std::time::{SystemTime, UNIX_EPOCH};

pub const PERMISSIONED_CAMPAIGN_BROKER_SCHEMA_VERSION: u32 = 1;
pub const PERMISSIONED_CAMPAIGN_HANDOFF_PACKET_SCHEMA_VERSION: u32 = 1;
pub const PERMISSIONED_CAMPAIGN_EXECUTION_LEDGER_SCHEMA_VERSION: u32 = 1;
pub const SWARM_CAPABILITY_CALIBRATION_SCHEMA_VERSION: u32 = 1;
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
pub const SWARM_CAPABILITY_CALIBRATION_PRODUCT_EVIDENCE_CLAIM: &str = "none";

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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PermissionedCampaignExecutionLedgerValidationConfig {
    pub current_git_sha: Option<String>,
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
pub struct PermissionedCampaignExecutionLedger {
    pub schema_version: u32,
    pub campaign_id: String,
    pub lane_kind: PermissionedCampaignLaneKind,
    pub target_beads: Vec<String>,
    pub git_sha: String,
    pub command_plan_hash: String,
    pub required_ack: PermissionedCampaignLedgerAck,
    pub preflight_snapshot: PermissionedCampaignLedgerPreflightSnapshot,
    pub steps: Vec<PermissionedCampaignLedgerStep>,
    pub artifacts: Vec<PermissionedCampaignLedgerArtifact>,
    pub resume_state: PermissionedCampaignLedgerResumeState,
    pub cleanup: PermissionedCampaignLedgerCleanup,
    #[serde(default)]
    pub proof_bundle_lane_candidates: Vec<PermissionedCampaignProofBundleLaneCandidate>,
    pub product_evidence_claim: PermissionedCampaignProductEvidenceClaim,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignLedgerAck {
    pub env_var: String,
    pub exact_value: String,
    pub observed_value: Option<String>,
    pub recorded_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignLedgerPreflightSnapshot {
    pub snapshot_id: String,
    pub observed_at: String,
    pub artifact_path: String,
    pub git_sha: String,
    pub host_class: String,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignLedgerStep {
    pub step_id: String,
    pub command_id: String,
    pub status: PermissionedCampaignLedgerStepStatus,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    #[serde(default)]
    pub raw_log_paths: Vec<String>,
    #[serde(default)]
    pub checkpoint_artifacts: Vec<String>,
    pub note: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionedCampaignLedgerStepStatus {
    NotAuthorized,
    PreflightBlocked,
    Running,
    Interrupted,
    Resumed,
    Passed,
    Failed,
    CleanupFailed,
    ArtifactStale,
}

impl PermissionedCampaignLedgerStepStatus {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotAuthorized => "not_authorized",
            Self::PreflightBlocked => "preflight_blocked",
            Self::Running => "running",
            Self::Interrupted => "interrupted",
            Self::Resumed => "resumed",
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::CleanupFailed => "cleanup_failed",
            Self::ArtifactStale => "artifact_stale",
        }
    }

    #[must_use]
    pub const fn requires_raw_logs(self) -> bool {
        matches!(
            self,
            Self::Running
                | Self::Interrupted
                | Self::Resumed
                | Self::Passed
                | Self::Failed
                | Self::CleanupFailed
                | Self::ArtifactStale
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignLedgerArtifact {
    pub artifact_id: String,
    pub path: String,
    pub sha256: String,
    pub role: PermissionedCampaignLedgerArtifactRole,
    pub stale: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionedCampaignLedgerArtifactRole {
    RawLog,
    Stdout,
    Stderr,
    Report,
    ResumeCheckpoint,
    CleanupReport,
    ProofBundleLane,
}

impl PermissionedCampaignLedgerArtifactRole {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::RawLog => "raw_log",
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
            Self::Report => "report",
            Self::ResumeCheckpoint => "resume_checkpoint",
            Self::CleanupReport => "cleanup_report",
            Self::ProofBundleLane => "proof_bundle_lane",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignLedgerResumeState {
    pub resume_token: Option<String>,
    pub last_checkpoint_artifact: Option<String>,
    pub partial_artifacts_preserved: bool,
    pub next_command_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignLedgerCleanup {
    pub status: PermissionedCampaignLedgerCleanupStatus,
    pub report_path: Option<String>,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionedCampaignLedgerCleanupStatus {
    NotStarted,
    Clean,
    PreservedArtifacts,
    ManualCleanupRequired,
    CleanupFailed,
}

impl PermissionedCampaignLedgerCleanupStatus {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotStarted => "not_started",
            Self::Clean => "clean",
            Self::PreservedArtifacts => "preserved_artifacts",
            Self::ManualCleanupRequired => "manual_cleanup_required",
            Self::CleanupFailed => "cleanup_failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignProofBundleLaneCandidate {
    pub lane_id: String,
    pub artifact_path: String,
    pub promotion_status: PermissionedCampaignProofBundlePromotionStatus,
    pub note: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionedCampaignProofBundlePromotionStatus {
    Candidate,
    Blocked,
    Promoted,
}

impl PermissionedCampaignProofBundlePromotionStatus {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Blocked => "blocked",
            Self::Promoted => "promoted",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignExecutionLedgerReport {
    pub schema_version: u32,
    pub campaign_id: String,
    pub lane_kind: String,
    pub valid: bool,
    pub git_sha: String,
    pub expected_command_plan_hash: String,
    pub observed_command_plan_hash: String,
    pub final_status: Option<String>,
    pub cleanup_status: String,
    pub product_evidence_claim: String,
    pub target_beads: Vec<String>,
    pub artifact_count: usize,
    pub proof_bundle_lane_candidates: Vec<PermissionedCampaignProofBundleLaneCandidateSummary>,
    pub issue_count: usize,
    pub issues: Vec<PermissionedCampaignExecutionLedgerIssue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmCapabilityCalibrationManifest {
    pub schema_version: u32,
    pub packet_id: String,
    pub generated_at: String,
    pub target_beads: Vec<String>,
    pub host: SwarmCapabilityCalibrationHost,
    pub worker: SwarmCapabilityCalibrationWorker,
    pub artifact_plan: SwarmCapabilityCalibrationArtifactPlan,
    pub resource_caps: SwarmCapabilityCalibrationResourceCaps,
    pub release_gate_policy_path: String,
    pub real_campaign_bead: String,
    pub handoff_summary: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmCapabilityCalibrationHost {
    pub logical_cpus: u32,
    pub ram_total_gib: f64,
    pub ram_available_gib: f64,
    pub numa_topology_visible: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub numa_nodes: Option<u32>,
    pub storage_class: String,
    pub fuse: SwarmCapabilityCalibrationFuse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmCapabilityCalibrationFuse {
    pub state: SwarmCapabilityCalibrationFuseState,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmCapabilityCalibrationFuseState {
    Available,
    Missing,
    Unknown,
}

impl SwarmCapabilityCalibrationFuseState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Missing => "missing",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmCapabilityCalibrationWorker {
    pub rch_worker_identity: String,
    pub worker_fingerprint: String,
    pub worker_fingerprint_observed_at_epoch_days: u32,
    pub worker_fingerprint_max_age_days: u32,
    pub queue_isolation: SwarmCapabilityCalibrationIsolation,
    pub target_dir_isolated: bool,
    pub target_dir: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmCapabilityCalibrationIsolation {
    Dedicated,
    Shared,
    Unknown,
}

impl SwarmCapabilityCalibrationIsolation {
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
pub struct SwarmCapabilityCalibrationArtifactPlan {
    pub expected_artifact_root: String,
    pub observed_artifact_root: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmCapabilityCalibrationResourceCaps {
    pub max_duration_secs: u64,
    pub max_threads: u32,
    pub max_memory_gib: f64,
    pub max_temp_storage_gib: f64,
    pub max_queue_depth: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmCapabilityCalibrationClassification {
    AuthoritativeLargeHostCandidate,
    SmallHostSmoke,
    CapabilityDowngradedSmoke,
    Blocked,
}

impl SwarmCapabilityCalibrationClassification {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AuthoritativeLargeHostCandidate => "authoritative_large_host_candidate",
            Self::SmallHostSmoke => "small_host_smoke",
            Self::CapabilityDowngradedSmoke => "capability_downgraded_smoke",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmCapabilityCalibrationReport {
    pub schema_version: u32,
    pub packet_id: String,
    pub valid: bool,
    pub classification: String,
    pub candidate_for_authorized_run: bool,
    pub product_evidence_claim: String,
    pub release_gate_effect: String,
    pub target_beads: Vec<String>,
    pub real_campaign_bead: String,
    pub host_facts: Vec<PermissionedCampaignHostFactSummary>,
    pub worker_identity: String,
    pub worker_fingerprint_age_days: u32,
    pub queue_isolation: String,
    pub target_dir_isolated: bool,
    pub expected_artifact_root: String,
    pub observed_artifact_root: String,
    pub resource_caps: SwarmCapabilityCalibrationResourceCapsReport,
    pub blocker_count: usize,
    pub blockers: Vec<String>,
    pub downgrade_count: usize,
    pub downgrade_reasons: Vec<String>,
    pub issue_count: usize,
    pub issues: Vec<PermissionedCampaignBrokerIssue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmCapabilityCalibrationResourceCapsReport {
    pub max_duration_secs: u64,
    pub max_threads: u32,
    pub max_memory_gib: f64,
    pub max_temp_storage_gib: f64,
    pub max_queue_depth: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwarmCapabilityCalibrationValidationConfig {
    pub reference_epoch_days: u32,
}

impl Default for SwarmCapabilityCalibrationValidationConfig {
    fn default() -> Self {
        Self {
            reference_epoch_days: current_epoch_days().unwrap_or(0),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignProofBundleLaneCandidateSummary {
    pub lane_id: String,
    pub artifact_path: String,
    pub promotion_status: String,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionedCampaignExecutionLedgerIssue {
    pub path: String,
    pub code: String,
    pub message: String,
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

pub fn load_permissioned_campaign_execution_ledger(
    path: &Path,
) -> Result<PermissionedCampaignExecutionLedger> {
    let text = fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read permissioned campaign execution ledger {}",
            path.display()
        )
    })?;
    serde_json::from_str(&text).with_context(|| {
        format!(
            "invalid permissioned campaign execution ledger JSON {}",
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

#[must_use]
pub fn permissioned_campaign_command_plan_hash(
    manifest: &PermissionedCampaignBrokerManifest,
) -> String {
    let mut hasher = Sha256::new();
    ledger_hash_part(&mut hasher, &manifest.campaign_id);
    ledger_hash_part(&mut hasher, manifest.lane_kind.label());
    for command in &manifest.exact_commands {
        ledger_hash_part(&mut hasher, &command.command_id);
        ledger_hash_part(&mut hasher, command.command_role.label());
        ledger_hash_part(&mut hasher, &command.exact_command);
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

#[must_use]
pub fn validate_permissioned_campaign_execution_ledger(
    manifest: &PermissionedCampaignBrokerManifest,
    ledger: &PermissionedCampaignExecutionLedger,
    config: &PermissionedCampaignExecutionLedgerValidationConfig,
) -> PermissionedCampaignExecutionLedgerReport {
    let mut issues = Vec::new();
    validate_ledger_top_level(manifest, ledger, config, &mut issues);
    validate_ledger_ack(manifest, ledger, &mut issues);
    validate_ledger_preflight_snapshot(ledger, &mut issues);
    validate_ledger_steps(manifest, ledger, &mut issues);
    validate_ledger_artifacts(ledger, &mut issues);
    validate_ledger_resume_state(ledger, &mut issues);
    validate_ledger_cleanup(ledger, &mut issues);
    validate_ledger_proof_bundle_candidates(ledger, &mut issues);
    validate_ledger_claim_boundary(ledger, &mut issues);

    PermissionedCampaignExecutionLedgerReport {
        schema_version: ledger.schema_version,
        campaign_id: ledger.campaign_id.clone(),
        lane_kind: ledger.lane_kind.label().to_owned(),
        valid: issues.is_empty(),
        git_sha: ledger.git_sha.clone(),
        expected_command_plan_hash: permissioned_campaign_command_plan_hash(manifest),
        observed_command_plan_hash: ledger.command_plan_hash.clone(),
        final_status: ledger
            .steps
            .last()
            .map(|step| step.status.label().to_owned()),
        cleanup_status: ledger.cleanup.status.label().to_owned(),
        product_evidence_claim: ledger.product_evidence_claim.label().to_owned(),
        target_beads: ledger.target_beads.clone(),
        artifact_count: ledger.artifacts.len(),
        proof_bundle_lane_candidates: ledger_proof_bundle_candidate_summary(ledger),
        issue_count: issues.len(),
        issues,
    }
}

#[must_use]
pub fn render_permissioned_campaign_execution_ledger_markdown(
    report: &PermissionedCampaignExecutionLedgerReport,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Permissioned Campaign Execution Ledger\n");
    let _ = writeln!(out, "- Campaign: `{}`", report.campaign_id);
    let _ = writeln!(out, "- Lane: `{}`", report.lane_kind);
    let _ = writeln!(out, "- Valid: `{}`", report.valid);
    let _ = writeln!(
        out,
        "- Final status: `{}`",
        report.final_status.as_deref().unwrap_or("none")
    );
    let _ = writeln!(out, "- Cleanup status: `{}`", report.cleanup_status);
    let _ = writeln!(
        out,
        "- Product evidence claim: `{}`",
        report.product_evidence_claim
    );
    let _ = writeln!(out, "- Git SHA: `{}`", report.git_sha);
    let _ = writeln!(
        out,
        "- Command plan hash: `{}`",
        report.observed_command_plan_hash
    );
    let _ = writeln!(
        out,
        "- Expected command plan hash: `{}`",
        report.expected_command_plan_hash
    );
    let _ = writeln!(out, "- Artifact count: `{}`", report.artifact_count);

    out.push_str("\n## Target Beads\n\n");
    for bead in &report.target_beads {
        let _ = writeln!(out, "- `{bead}`");
    }

    out.push_str("\n## Proof Bundle Lane Candidates\n\n");
    out.push_str("| Lane | Promotion status | Artifact | Note |\n");
    out.push_str("|---|---|---|---|\n");
    for lane in &report.proof_bundle_lane_candidates {
        let _ = writeln!(
            out,
            "| `{}` | `{}` | `{}` | {} |",
            lane.lane_id,
            lane.promotion_status,
            lane.artifact_path,
            markdown_cell(&lane.note)
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

pub fn fail_on_permissioned_campaign_execution_ledger_errors(
    report: &PermissionedCampaignExecutionLedgerReport,
) -> Result<()> {
    if report.valid {
        Ok(())
    } else {
        bail!(
            "permissioned campaign execution ledger validation failed: issues={}",
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

pub fn load_swarm_capability_calibration_manifest(
    path: &Path,
) -> Result<SwarmCapabilityCalibrationManifest> {
    let text = fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read swarm capability calibration manifest {}",
            path.display()
        )
    })?;
    serde_json::from_str(&text).with_context(|| {
        format!(
            "invalid swarm capability calibration manifest JSON {}",
            path.display()
        )
    })
}

#[must_use]
pub fn validate_swarm_capability_calibration_manifest(
    manifest: &SwarmCapabilityCalibrationManifest,
    config: &SwarmCapabilityCalibrationValidationConfig,
) -> SwarmCapabilityCalibrationReport {
    let mut issues = Vec::new();
    let mut blockers = Vec::new();
    let mut downgrade_reasons = Vec::new();

    validate_swarm_calibration_schema(manifest, &mut issues);
    classify_swarm_calibration_host(manifest, config, &mut blockers, &mut downgrade_reasons);

    let classification =
        swarm_calibration_classification(manifest, &issues, &blockers, &downgrade_reasons);
    let candidate_for_authorized_run =
        classification == SwarmCapabilityCalibrationClassification::AuthoritativeLargeHostCandidate;
    let host_facts = swarm_calibration_host_facts(manifest);
    let worker_fingerprint_age_days = config
        .reference_epoch_days
        .saturating_sub(manifest.worker.worker_fingerprint_observed_at_epoch_days);
    let resource_caps = SwarmCapabilityCalibrationResourceCapsReport {
        max_duration_secs: manifest.resource_caps.max_duration_secs,
        max_threads: manifest.resource_caps.max_threads,
        max_memory_gib: manifest.resource_caps.max_memory_gib,
        max_temp_storage_gib: manifest.resource_caps.max_temp_storage_gib,
        max_queue_depth: manifest.resource_caps.max_queue_depth,
    };

    SwarmCapabilityCalibrationReport {
        schema_version: SWARM_CAPABILITY_CALIBRATION_SCHEMA_VERSION,
        packet_id: manifest.packet_id.clone(),
        valid: issues.is_empty(),
        classification: classification.label().to_owned(),
        candidate_for_authorized_run,
        product_evidence_claim: SWARM_CAPABILITY_CALIBRATION_PRODUCT_EVIDENCE_CLAIM.to_owned(),
        release_gate_effect: format!(
            "swarm.responsiveness remains hidden or blocked until {} records executed large-host proof-bundle lanes and release-gate output",
            manifest.real_campaign_bead
        ),
        target_beads: manifest.target_beads.clone(),
        real_campaign_bead: manifest.real_campaign_bead.clone(),
        host_facts,
        worker_identity: manifest.worker.rch_worker_identity.clone(),
        worker_fingerprint_age_days,
        queue_isolation: manifest.worker.queue_isolation.label().to_owned(),
        target_dir_isolated: manifest.worker.target_dir_isolated,
        expected_artifact_root: manifest.artifact_plan.expected_artifact_root.clone(),
        observed_artifact_root: manifest.artifact_plan.observed_artifact_root.clone(),
        resource_caps,
        blocker_count: blockers.len(),
        blockers,
        downgrade_count: downgrade_reasons.len(),
        downgrade_reasons,
        issue_count: issues.len(),
        issues,
    }
}

#[must_use]
pub fn render_swarm_capability_calibration_markdown(
    report: &SwarmCapabilityCalibrationReport,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Swarm Capability Calibration\n");
    let _ = writeln!(out, "- Packet: `{}`", report.packet_id);
    let _ = writeln!(out, "- Valid: `{}`", report.valid);
    let _ = writeln!(out, "- Classification: `{}`", report.classification);
    let _ = writeln!(
        out,
        "- Candidate for authorized run: `{}`",
        report.candidate_for_authorized_run
    );
    let _ = writeln!(
        out,
        "- Product evidence claim: `{}`",
        report.product_evidence_claim
    );
    let _ = writeln!(
        out,
        "- Release gate effect: {}",
        markdown_cell(&report.release_gate_effect)
    );
    let _ = writeln!(out, "- Real campaign bead: `{}`", report.real_campaign_bead);
    let _ = writeln!(out, "- Worker: `{}`", report.worker_identity);
    let _ = writeln!(
        out,
        "- Worker fingerprint age days: `{}`",
        report.worker_fingerprint_age_days
    );
    let _ = writeln!(out, "- Queue isolation: `{}`", report.queue_isolation);
    let _ = writeln!(
        out,
        "- Target dir isolated: `{}`",
        report.target_dir_isolated
    );
    let _ = writeln!(
        out,
        "- Artifact root: expected `{}` observed `{}`",
        report.expected_artifact_root, report.observed_artifact_root
    );

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

    out.push_str("\n## Resource Caps\n\n");
    let _ = writeln!(
        out,
        "- Duration: `{}` seconds",
        report.resource_caps.max_duration_secs
    );
    let _ = writeln!(out, "- Threads: `{}`", report.resource_caps.max_threads);
    let _ = writeln!(
        out,
        "- Memory: `{:.1}` GiB",
        report.resource_caps.max_memory_gib
    );
    let _ = writeln!(
        out,
        "- Temp storage: `{:.1}` GiB",
        report.resource_caps.max_temp_storage_gib
    );
    let _ = writeln!(
        out,
        "- Queue depth: `{}`",
        report.resource_caps.max_queue_depth
    );

    if !report.blockers.is_empty() {
        out.push_str("\n## Blockers\n\n");
        for blocker in &report.blockers {
            let _ = writeln!(out, "- {}", markdown_cell(blocker));
        }
    }
    if !report.downgrade_reasons.is_empty() {
        out.push_str("\n## Downgrade Reasons\n\n");
        for reason in &report.downgrade_reasons {
            let _ = writeln!(out, "- {}", markdown_cell(reason));
        }
    }
    if !report.issues.is_empty() {
        out.push_str("\n## Issues\n\n");
        for issue in &report.issues {
            let _ = writeln!(
                out,
                "- `{}` `{}`: {}",
                issue.path,
                issue.code,
                markdown_cell(&issue.message)
            );
        }
    }
    out
}

pub fn fail_on_swarm_capability_calibration_errors(
    report: &SwarmCapabilityCalibrationReport,
) -> Result<()> {
    if report.valid {
        Ok(())
    } else {
        bail!(
            "swarm capability calibration validation failed: issues={}",
            report.issue_count
        )
    }
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

fn validate_swarm_calibration_schema(
    manifest: &SwarmCapabilityCalibrationManifest,
    issues: &mut Vec<PermissionedCampaignBrokerIssue>,
) {
    if manifest.schema_version != SWARM_CAPABILITY_CALIBRATION_SCHEMA_VERSION {
        push_issue(
            issues,
            "schema_version",
            "unsupported_schema_version",
            "schema_version must match the current swarm capability calibration schema",
        );
    }
    validate_non_empty(issues, "packet_id", &manifest.packet_id);
    validate_non_empty(issues, "generated_at", &manifest.generated_at);
    validate_non_empty(issues, "handoff_summary", &manifest.handoff_summary);
    validate_non_empty(
        issues,
        "worker.rch_worker_identity",
        &manifest.worker.rch_worker_identity,
    );
    validate_non_empty(
        issues,
        "worker.worker_fingerprint",
        &manifest.worker.worker_fingerprint,
    );
    validate_non_empty(issues, "host.storage_class", &manifest.host.storage_class);
    validate_non_empty(issues, "host.fuse.detail", &manifest.host.fuse.detail);
    validate_non_empty(
        issues,
        "release_gate_policy_path",
        &manifest.release_gate_policy_path,
    );
    validate_non_empty(issues, "real_campaign_bead", &manifest.real_campaign_bead);
    if !manifest.real_campaign_bead.starts_with("bd-") {
        push_issue(
            issues,
            "real_campaign_bead",
            "invalid_bead_id",
            "real_campaign_bead must start with bd-",
        );
    }
    if manifest.target_beads.is_empty() {
        push_issue(
            issues,
            "target_beads",
            "missing_target_beads",
            "target_beads must include the calibration and real campaign beads",
        );
    }
    for (index, bead) in manifest.target_beads.iter().enumerate() {
        if !bead.starts_with("bd-") {
            push_issue(
                issues,
                &format!("target_beads[{index}]"),
                "invalid_bead_id",
                "target bead must start with bd-",
            );
        }
    }
    validate_safe_path(issues, "worker.target_dir", &manifest.worker.target_dir);
    validate_safe_path(
        issues,
        "artifact_plan.expected_artifact_root",
        &manifest.artifact_plan.expected_artifact_root,
    );
    validate_safe_path(
        issues,
        "artifact_plan.observed_artifact_root",
        &manifest.artifact_plan.observed_artifact_root,
    );
    validate_safe_path(
        issues,
        "release_gate_policy_path",
        &manifest.release_gate_policy_path,
    );
    if manifest.worker.worker_fingerprint_max_age_days == 0 {
        push_issue(
            issues,
            "worker.worker_fingerprint_max_age_days",
            "invalid_freshness_window",
            "worker_fingerprint_max_age_days must be positive",
        );
    }
    if manifest.resource_caps.max_duration_secs == 0 {
        push_issue(
            issues,
            "resource_caps.max_duration_secs",
            "invalid_resource_cap",
            "max_duration_secs must be positive",
        );
    }
    if manifest.resource_caps.max_threads == 0 {
        push_issue(
            issues,
            "resource_caps.max_threads",
            "invalid_resource_cap",
            "max_threads must be positive",
        );
    }
    if manifest.resource_caps.max_memory_gib <= 0.0 {
        push_issue(
            issues,
            "resource_caps.max_memory_gib",
            "invalid_resource_cap",
            "max_memory_gib must be positive",
        );
    }
    if manifest.resource_caps.max_temp_storage_gib <= 0.0 {
        push_issue(
            issues,
            "resource_caps.max_temp_storage_gib",
            "invalid_resource_cap",
            "max_temp_storage_gib must be positive",
        );
    }
    if manifest.resource_caps.max_queue_depth == 0 {
        push_issue(
            issues,
            "resource_caps.max_queue_depth",
            "invalid_resource_cap",
            "max_queue_depth must be positive",
        );
    }
}

fn classify_swarm_calibration_host(
    manifest: &SwarmCapabilityCalibrationManifest,
    config: &SwarmCapabilityCalibrationValidationConfig,
    blockers: &mut Vec<String>,
    downgrade_reasons: &mut Vec<String>,
) {
    let host = &manifest.host;
    let worker = &manifest.worker;
    let caps = &manifest.resource_caps;
    let artifact_plan = &manifest.artifact_plan;

    let worker_age_days = config
        .reference_epoch_days
        .saturating_sub(worker.worker_fingerprint_observed_at_epoch_days);
    if worker_age_days > worker.worker_fingerprint_max_age_days {
        blockers.push(format!(
            "worker_fingerprint_stale age_days={} max_age_days={}",
            worker_age_days, worker.worker_fingerprint_max_age_days
        ));
    }
    if artifact_plan.observed_artifact_root != artifact_plan.expected_artifact_root {
        blockers.push(format!(
            "artifact_root_mismatch expected={} observed={}",
            artifact_plan.expected_artifact_root, artifact_plan.observed_artifact_root
        ));
    }
    if !worker.target_dir_isolated {
        blockers.push("target_dir_isolated=false".to_owned());
    }
    if caps.max_threads > host.logical_cpus {
        blockers.push(format!(
            "resource_caps.max_threads={} exceeds logical_cpus={}",
            caps.max_threads, host.logical_cpus
        ));
    }
    if caps.max_memory_gib > host.ram_total_gib {
        blockers.push(format!(
            "resource_caps.max_memory_gib={:.1} exceeds ram_total_gib={:.1}",
            caps.max_memory_gib, host.ram_total_gib
        ));
    }

    if host.logical_cpus < SWARM_MIN_LOGICAL_CPUS {
        downgrade_reasons.push(format!(
            "logical_cpus={} below required >={SWARM_MIN_LOGICAL_CPUS}",
            host.logical_cpus
        ));
    }
    if host.ram_total_gib < f64::from(SWARM_MIN_RAM_GIB) {
        downgrade_reasons.push(format!(
            "ram_total_gib={:.1} below required >={SWARM_MIN_RAM_GIB}",
            host.ram_total_gib
        ));
    }
    if !host.numa_topology_visible {
        downgrade_reasons.push("numa_topology_visible=false".to_owned());
    }
    match host.numa_nodes {
        Some(nodes) if nodes >= SWARM_MIN_NUMA_NODES => {}
        Some(nodes) => downgrade_reasons.push(format!(
            "numa_nodes={nodes} below required >={SWARM_MIN_NUMA_NODES}"
        )),
        None => downgrade_reasons.push("numa_nodes missing".to_owned()),
    }
    if host.fuse.state != SwarmCapabilityCalibrationFuseState::Available {
        downgrade_reasons.push(format!("fuse_capability={}", host.fuse.state.label()));
    }
    if worker.queue_isolation != SwarmCapabilityCalibrationIsolation::Dedicated {
        downgrade_reasons.push(format!(
            "queue_isolation={} expected dedicated",
            worker.queue_isolation.label()
        ));
    }
}

fn swarm_calibration_classification(
    manifest: &SwarmCapabilityCalibrationManifest,
    issues: &[PermissionedCampaignBrokerIssue],
    blockers: &[String],
    downgrade_reasons: &[String],
) -> SwarmCapabilityCalibrationClassification {
    if !issues.is_empty() || !blockers.is_empty() {
        return SwarmCapabilityCalibrationClassification::Blocked;
    }
    if manifest.host.logical_cpus < SWARM_MIN_LOGICAL_CPUS
        || manifest.host.ram_total_gib < f64::from(SWARM_MIN_RAM_GIB)
    {
        return SwarmCapabilityCalibrationClassification::SmallHostSmoke;
    }
    if !downgrade_reasons.is_empty() {
        return SwarmCapabilityCalibrationClassification::CapabilityDowngradedSmoke;
    }
    SwarmCapabilityCalibrationClassification::AuthoritativeLargeHostCandidate
}

fn swarm_calibration_host_facts(
    manifest: &SwarmCapabilityCalibrationManifest,
) -> Vec<PermissionedCampaignHostFactSummary> {
    vec![
        PermissionedCampaignHostFactSummary {
            fact_id: "logical_cpus".to_owned(),
            observed_value: manifest.host.logical_cpus.to_string(),
            required_value: format!(">={SWARM_MIN_LOGICAL_CPUS}"),
            proof_path: "swarm_capability_calibration_manifest".to_owned(),
        },
        PermissionedCampaignHostFactSummary {
            fact_id: "ram_total_gib".to_owned(),
            observed_value: format!("{:.1}", manifest.host.ram_total_gib),
            required_value: format!(">={SWARM_MIN_RAM_GIB}"),
            proof_path: "swarm_capability_calibration_manifest".to_owned(),
        },
        PermissionedCampaignHostFactSummary {
            fact_id: "ram_available_gib".to_owned(),
            observed_value: format!("{:.1}", manifest.host.ram_available_gib),
            required_value: "recorded".to_owned(),
            proof_path: "swarm_capability_calibration_manifest".to_owned(),
        },
        PermissionedCampaignHostFactSummary {
            fact_id: "numa_topology_visible".to_owned(),
            observed_value: manifest.host.numa_topology_visible.to_string(),
            required_value: "true".to_owned(),
            proof_path: "swarm_capability_calibration_manifest".to_owned(),
        },
        PermissionedCampaignHostFactSummary {
            fact_id: "numa_nodes".to_owned(),
            observed_value: manifest
                .host
                .numa_nodes
                .map_or_else(|| "missing".to_owned(), |nodes| nodes.to_string()),
            required_value: format!(">={SWARM_MIN_NUMA_NODES}"),
            proof_path: "swarm_capability_calibration_manifest".to_owned(),
        },
        PermissionedCampaignHostFactSummary {
            fact_id: "storage_class".to_owned(),
            observed_value: manifest.host.storage_class.clone(),
            required_value: "recorded".to_owned(),
            proof_path: "swarm_capability_calibration_manifest".to_owned(),
        },
        PermissionedCampaignHostFactSummary {
            fact_id: "fuse_capability".to_owned(),
            observed_value: manifest.host.fuse.state.label().to_owned(),
            required_value: "available".to_owned(),
            proof_path: "swarm_capability_calibration_manifest".to_owned(),
        },
    ]
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

fn validate_ledger_top_level(
    manifest: &PermissionedCampaignBrokerManifest,
    ledger: &PermissionedCampaignExecutionLedger,
    config: &PermissionedCampaignExecutionLedgerValidationConfig,
    issues: &mut Vec<PermissionedCampaignExecutionLedgerIssue>,
) {
    if ledger.schema_version != PERMISSIONED_CAMPAIGN_EXECUTION_LEDGER_SCHEMA_VERSION {
        push_ledger_issue(
            issues,
            "schema_version",
            "unsupported_schema_version",
            "schema_version must match the current permissioned campaign execution ledger schema",
        );
    }
    validate_ledger_non_empty(issues, "campaign_id", &ledger.campaign_id);
    if ledger.campaign_id != manifest.campaign_id {
        push_ledger_issue(
            issues,
            "campaign_id",
            "campaign_id_mismatch",
            "ledger campaign_id must match the broker manifest",
        );
    }
    if ledger.lane_kind != manifest.lane_kind {
        push_ledger_issue(
            issues,
            "lane_kind",
            "lane_kind_mismatch",
            "ledger lane_kind must match the broker manifest",
        );
    }
    if ledger.target_beads != manifest.target_beads {
        push_ledger_issue(
            issues,
            "target_beads",
            "target_beads_mismatch",
            "ledger target_beads must match the broker manifest",
        );
    }
    validate_ledger_non_empty(issues, "git_sha", &ledger.git_sha);
    if let Some(current_git_sha) = &config.current_git_sha
        && ledger.git_sha != *current_git_sha
    {
        push_ledger_issue(
            issues,
            "git_sha",
            "stale_git_sha",
            "ledger git_sha does not match the current validation git SHA",
        );
    }
    let expected_hash = permissioned_campaign_command_plan_hash(manifest);
    if ledger.command_plan_hash != expected_hash {
        push_ledger_issue(
            issues,
            "command_plan_hash",
            "changed_command_plan",
            "ledger command_plan_hash must match the broker manifest command plan",
        );
    }
    if !is_valid_sha256_prefixed(&ledger.command_plan_hash) {
        push_ledger_issue(
            issues,
            "command_plan_hash",
            "invalid_command_plan_hash",
            "command_plan_hash must be sha256:<64 lowercase hex chars>",
        );
    }
    if ledger.steps.is_empty() {
        push_ledger_issue(
            issues,
            "steps",
            "missing_ledger_steps",
            "ledger must include at least one campaign state step",
        );
    }
}

fn validate_ledger_ack(
    manifest: &PermissionedCampaignBrokerManifest,
    ledger: &PermissionedCampaignExecutionLedger,
    issues: &mut Vec<PermissionedCampaignExecutionLedgerIssue>,
) {
    validate_ledger_non_empty(issues, "required_ack.env_var", &ledger.required_ack.env_var);
    validate_ledger_non_empty(
        issues,
        "required_ack.exact_value",
        &ledger.required_ack.exact_value,
    );
    if ledger.required_ack.env_var != manifest.required_ack.env_var {
        push_ledger_issue(
            issues,
            "required_ack.env_var",
            "ack_env_mismatch",
            "ledger ACK env var must match the broker manifest",
        );
    }
    if ledger.required_ack.exact_value != manifest.required_ack.exact_value {
        push_ledger_issue(
            issues,
            "required_ack.exact_value",
            "missing_ack_text",
            "ledger ACK exact value must match the broker manifest",
        );
    }

    if ledger_has_permissioned_execution(ledger) {
        match ledger.required_ack.observed_value.as_deref() {
            Some(observed) if observed == manifest.required_ack.exact_value => {}
            Some(_) => push_ledger_issue(
                issues,
                "required_ack.observed_value",
                "ack_value_mismatch",
                "permissioned execution requires the exact operator ACK value",
            ),
            None => push_ledger_issue(
                issues,
                "required_ack.observed_value",
                "missing_ack_text",
                "permissioned execution requires recorded operator ACK text",
            ),
        }
        if ledger
            .required_ack
            .recorded_at
            .as_deref()
            .is_none_or(str::is_empty)
        {
            push_ledger_issue(
                issues,
                "required_ack.recorded_at",
                "missing_ack_timestamp",
                "permissioned execution requires an ACK timestamp",
            );
        }
    } else if let Some(observed) = ledger.required_ack.observed_value.as_deref()
        && observed != manifest.required_ack.exact_value
    {
        push_ledger_issue(
            issues,
            "required_ack.observed_value",
            "ack_value_mismatch",
            "recorded ACK value does not match the manifest",
        );
    }
}

fn validate_ledger_preflight_snapshot(
    ledger: &PermissionedCampaignExecutionLedger,
    issues: &mut Vec<PermissionedCampaignExecutionLedgerIssue>,
) {
    validate_ledger_non_empty(
        issues,
        "preflight_snapshot.snapshot_id",
        &ledger.preflight_snapshot.snapshot_id,
    );
    validate_ledger_non_empty(
        issues,
        "preflight_snapshot.observed_at",
        &ledger.preflight_snapshot.observed_at,
    );
    validate_ledger_path(
        issues,
        "preflight_snapshot.artifact_path",
        &ledger.preflight_snapshot.artifact_path,
    );
    validate_ledger_non_empty(
        issues,
        "preflight_snapshot.git_sha",
        &ledger.preflight_snapshot.git_sha,
    );
    if ledger.preflight_snapshot.git_sha != ledger.git_sha {
        push_ledger_issue(
            issues,
            "preflight_snapshot.git_sha",
            "preflight_git_sha_mismatch",
            "preflight snapshot git_sha must match the ledger git_sha",
        );
    }
    validate_ledger_non_empty(
        issues,
        "preflight_snapshot.host_class",
        &ledger.preflight_snapshot.host_class,
    );
    if matches!(
        ledger_final_status(ledger),
        Some(PermissionedCampaignLedgerStepStatus::Passed)
    ) && !ledger.preflight_snapshot.blockers.is_empty()
    {
        push_ledger_issue(
            issues,
            "preflight_snapshot.blockers",
            "preflight_blockers_not_resolved",
            "passed ledgers cannot retain unresolved preflight blockers",
        );
    }
}

fn validate_ledger_steps(
    manifest: &PermissionedCampaignBrokerManifest,
    ledger: &PermissionedCampaignExecutionLedger,
    issues: &mut Vec<PermissionedCampaignExecutionLedgerIssue>,
) {
    let mut previous_status = None;
    let mut seen_step_ids = Vec::new();
    for (index, step) in ledger.steps.iter().enumerate() {
        let step_path = format!("steps[{index}]");
        validate_ledger_non_empty(issues, &format!("{step_path}.step_id"), &step.step_id);
        if seen_step_ids.contains(&step.step_id) {
            push_ledger_issue(
                issues,
                &format!("{step_path}.step_id"),
                "duplicate_step_id",
                "ledger step ids must be unique",
            );
        }
        seen_step_ids.push(step.step_id.clone());
        validate_ledger_non_empty(issues, &format!("{step_path}.command_id"), &step.command_id);
        if !manifest
            .exact_commands
            .iter()
            .any(|command| command.command_id == step.command_id)
        {
            push_ledger_issue(
                issues,
                &format!("{step_path}.command_id"),
                "unknown_command_id",
                "ledger step command_id must come from the broker manifest command plan",
            );
        }
        if !allowed_ledger_transition(previous_status, step.status) {
            push_ledger_issue(
                issues,
                &step_path,
                "invalid_state_transition",
                "ledger step status does not follow the allowed permissioned campaign lifecycle",
            );
        }
        if step.status.requires_raw_logs() && step.raw_log_paths.is_empty() {
            push_ledger_issue(
                issues,
                &format!("{step_path}.raw_log_paths"),
                "missing_raw_log",
                "permissioned execution steps must preserve raw log paths",
            );
        }
        for (raw_index, raw_path) in step.raw_log_paths.iter().enumerate() {
            validate_ledger_path(
                issues,
                &format!("{step_path}.raw_log_paths[{raw_index}]"),
                raw_path,
            );
            if !ledger_artifact_path_exists(ledger, raw_path) {
                push_ledger_issue(
                    issues,
                    &format!("{step_path}.raw_log_paths[{raw_index}]"),
                    "missing_raw_log",
                    "raw log paths must also appear in ledger artifacts with hashes",
                );
            }
        }
        for (checkpoint_index, checkpoint_path) in step.checkpoint_artifacts.iter().enumerate() {
            validate_ledger_path(
                issues,
                &format!("{step_path}.checkpoint_artifacts[{checkpoint_index}]"),
                checkpoint_path,
            );
            if !ledger_artifact_path_exists(ledger, checkpoint_path) {
                push_ledger_issue(
                    issues,
                    &format!("{step_path}.checkpoint_artifacts[{checkpoint_index}]"),
                    "missing_checkpoint_artifact",
                    "checkpoint artifact paths must also appear in ledger artifacts with hashes",
                );
            }
        }
        validate_ledger_non_empty(issues, &format!("{step_path}.note"), &step.note);
        previous_status = Some(step.status);
    }
}

fn validate_ledger_artifacts(
    ledger: &PermissionedCampaignExecutionLedger,
    issues: &mut Vec<PermissionedCampaignExecutionLedgerIssue>,
) {
    if ledger_has_permissioned_execution(ledger) && ledger.artifacts.is_empty() {
        push_ledger_issue(
            issues,
            "artifacts",
            "missing_artifacts",
            "permissioned execution ledgers must preserve hashed artifacts",
        );
    }
    for (index, artifact) in ledger.artifacts.iter().enumerate() {
        let artifact_path = format!("artifacts[{index}]");
        validate_ledger_non_empty(
            issues,
            &format!("{artifact_path}.artifact_id"),
            &artifact.artifact_id,
        );
        validate_ledger_path(issues, &format!("{artifact_path}.path"), &artifact.path);
        if !is_valid_sha256_prefixed(&artifact.sha256) {
            push_ledger_issue(
                issues,
                &format!("{artifact_path}.sha256"),
                "invalid_artifact_hash",
                "artifact sha256 must be sha256:<64 lowercase hex chars>",
            );
        }
    }
    if matches!(
        ledger_final_status(ledger),
        Some(PermissionedCampaignLedgerStepStatus::Passed)
    ) && ledger.artifacts.iter().any(|artifact| artifact.stale)
    {
        push_ledger_issue(
            issues,
            "artifacts",
            "stale_artifact",
            "passed ledgers cannot include stale artifacts",
        );
    }
    if matches!(
        ledger_final_status(ledger),
        Some(PermissionedCampaignLedgerStepStatus::ArtifactStale)
    ) && !ledger.artifacts.iter().any(|artifact| artifact.stale)
    {
        push_ledger_issue(
            issues,
            "artifacts",
            "artifact_stale_without_stale_artifact",
            "artifact_stale ledgers must identify the stale artifact",
        );
    }
}

fn validate_ledger_resume_state(
    ledger: &PermissionedCampaignExecutionLedger,
    issues: &mut Vec<PermissionedCampaignExecutionLedgerIssue>,
) {
    if let Some(path) = &ledger.resume_state.last_checkpoint_artifact {
        validate_ledger_path(issues, "resume_state.last_checkpoint_artifact", path);
        if !ledger_artifact_path_exists(ledger, path) {
            push_ledger_issue(
                issues,
                "resume_state.last_checkpoint_artifact",
                "missing_checkpoint_artifact",
                "resume checkpoint must be present in hashed artifacts",
            );
        }
    }
    if matches!(
        ledger_final_status(ledger),
        Some(PermissionedCampaignLedgerStepStatus::Interrupted)
    ) && !ledger.resume_state.partial_artifacts_preserved
    {
        push_ledger_issue(
            issues,
            "resume_state.partial_artifacts_preserved",
            "partial_artifacts_not_preserved",
            "interrupted ledgers must preserve partial artifacts for resume",
        );
    }
    if ledger
        .steps
        .iter()
        .any(|step| step.status == PermissionedCampaignLedgerStepStatus::Resumed)
        && ledger
            .resume_state
            .resume_token
            .as_deref()
            .is_none_or(str::is_empty)
    {
        push_ledger_issue(
            issues,
            "resume_state.resume_token",
            "missing_resume_token",
            "resumed ledgers must record a resume token",
        );
    }
}

fn validate_ledger_cleanup(
    ledger: &PermissionedCampaignExecutionLedger,
    issues: &mut Vec<PermissionedCampaignExecutionLedgerIssue>,
) {
    let final_status = ledger_final_status(ledger);
    let cleanup_required = matches!(
        final_status,
        Some(
            PermissionedCampaignLedgerStepStatus::Passed
                | PermissionedCampaignLedgerStepStatus::Failed
                | PermissionedCampaignLedgerStepStatus::CleanupFailed
                | PermissionedCampaignLedgerStepStatus::ArtifactStale
        )
    );
    if cleanup_required
        && ledger.cleanup.status == PermissionedCampaignLedgerCleanupStatus::NotStarted
    {
        push_ledger_issue(
            issues,
            "cleanup.status",
            "missing_cleanup",
            "terminal permissioned execution ledgers must record cleanup status",
        );
    }
    if ledger.cleanup.status != PermissionedCampaignLedgerCleanupStatus::NotStarted {
        match ledger.cleanup.report_path.as_deref() {
            Some(path) if !path.is_empty() => {
                validate_ledger_path(issues, "cleanup.report_path", path);
                if !ledger_artifact_path_exists(ledger, path) {
                    push_ledger_issue(
                        issues,
                        "cleanup.report_path",
                        "missing_cleanup",
                        "cleanup report must be preserved as a hashed artifact",
                    );
                }
            }
            _ => push_ledger_issue(
                issues,
                "cleanup.report_path",
                "missing_cleanup",
                "cleanup status requires a cleanup report path",
            ),
        }
    }
}

fn validate_ledger_proof_bundle_candidates(
    ledger: &PermissionedCampaignExecutionLedger,
    issues: &mut Vec<PermissionedCampaignExecutionLedgerIssue>,
) {
    for (index, candidate) in ledger.proof_bundle_lane_candidates.iter().enumerate() {
        let candidate_path = format!("proof_bundle_lane_candidates[{index}]");
        validate_ledger_non_empty(
            issues,
            &format!("{candidate_path}.lane_id"),
            &candidate.lane_id,
        );
        validate_ledger_path(
            issues,
            &format!("{candidate_path}.artifact_path"),
            &candidate.artifact_path,
        );
        if !ledger_artifact_path_exists(ledger, &candidate.artifact_path) {
            push_ledger_issue(
                issues,
                &format!("{candidate_path}.artifact_path"),
                "missing_proof_bundle_lane_artifact",
                "proof-bundle lane candidates must point at a hashed artifact",
            );
        }
        validate_ledger_non_empty(issues, &format!("{candidate_path}.note"), &candidate.note);
        if candidate.promotion_status == PermissionedCampaignProofBundlePromotionStatus::Promoted
            && !matches!(
                ledger_final_status(ledger),
                Some(PermissionedCampaignLedgerStepStatus::Passed)
            )
        {
            push_ledger_issue(
                issues,
                &format!("{candidate_path}.promotion_status"),
                "premature_proof_bundle_promotion",
                "proof-bundle lanes can be promoted only after a passed executed run",
            );
        }
    }
}

fn validate_ledger_claim_boundary(
    ledger: &PermissionedCampaignExecutionLedger,
    issues: &mut Vec<PermissionedCampaignExecutionLedgerIssue>,
) {
    if ledger.product_evidence_claim
        == PermissionedCampaignProductEvidenceClaim::PacketCountsAsPassFail
    {
        push_ledger_issue(
            issues,
            "product_evidence_claim",
            "dry_run_packet_as_pass_evidence",
            "dry-run broker packets cannot be marked as pass/fail product evidence",
        );
    }
    if ledger.product_evidence_claim
        == PermissionedCampaignProductEvidenceClaim::ExecutedEvidenceRecorded
        && !matches!(
            ledger_final_status(ledger),
            Some(PermissionedCampaignLedgerStepStatus::Passed)
        )
    {
        push_ledger_issue(
            issues,
            "product_evidence_claim",
            "executed_evidence_without_pass",
            "executed evidence claims require a passed permissioned run",
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

fn ledger_proof_bundle_candidate_summary(
    ledger: &PermissionedCampaignExecutionLedger,
) -> Vec<PermissionedCampaignProofBundleLaneCandidateSummary> {
    ledger
        .proof_bundle_lane_candidates
        .iter()
        .map(
            |candidate| PermissionedCampaignProofBundleLaneCandidateSummary {
                lane_id: candidate.lane_id.clone(),
                artifact_path: candidate.artifact_path.clone(),
                promotion_status: candidate.promotion_status.label().to_owned(),
                note: candidate.note.clone(),
            },
        )
        .collect()
}

fn ledger_hash_part(hasher: &mut Sha256, value: &str) {
    hasher.update(value.as_bytes());
    hasher.update([0]);
}

fn ledger_has_permissioned_execution(ledger: &PermissionedCampaignExecutionLedger) -> bool {
    ledger
        .steps
        .iter()
        .any(|step| step.status.requires_raw_logs())
        || ledger.product_evidence_claim
            == PermissionedCampaignProductEvidenceClaim::ExecutedEvidenceRecorded
}

fn ledger_final_status(
    ledger: &PermissionedCampaignExecutionLedger,
) -> Option<PermissionedCampaignLedgerStepStatus> {
    ledger.steps.last().map(|step| step.status)
}

fn ledger_artifact_path_exists(ledger: &PermissionedCampaignExecutionLedger, path: &str) -> bool {
    ledger
        .artifacts
        .iter()
        .any(|artifact| artifact.path == path)
}

fn allowed_ledger_transition(
    previous: Option<PermissionedCampaignLedgerStepStatus>,
    next: PermissionedCampaignLedgerStepStatus,
) -> bool {
    use PermissionedCampaignLedgerStepStatus::{
        ArtifactStale, CleanupFailed, Failed, Interrupted, NotAuthorized, Passed, PreflightBlocked,
        Resumed, Running,
    };

    match previous {
        None => matches!(next, NotAuthorized | PreflightBlocked | Running),
        Some(NotAuthorized) => matches!(next, PreflightBlocked | Running),
        Some(PreflightBlocked) => matches!(next, Resumed | ArtifactStale),
        Some(Running) => matches!(
            next,
            Interrupted | Passed | Failed | CleanupFailed | ArtifactStale
        ),
        Some(Interrupted) => matches!(next, Resumed | CleanupFailed),
        Some(Resumed) => matches!(
            next,
            Interrupted | Passed | Failed | CleanupFailed | ArtifactStale
        ),
        Some(Passed | Failed | CleanupFailed | ArtifactStale) => false,
    }
}

fn is_valid_sha256_prefixed(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("sha256:") else {
        return false;
    };
    suffix.len() == 64
        && suffix
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (*byte >= b'a' && *byte <= b'f'))
}

fn validate_ledger_non_empty(
    issues: &mut Vec<PermissionedCampaignExecutionLedgerIssue>,
    path: &str,
    value: &str,
) {
    if value.trim().is_empty() {
        push_ledger_issue(
            issues,
            path,
            "missing_required_field",
            "required field must not be empty",
        );
    }
}

fn validate_ledger_path(
    issues: &mut Vec<PermissionedCampaignExecutionLedgerIssue>,
    path: &str,
    value: &str,
) {
    validate_ledger_non_empty(issues, path, value);
    if !is_safe_relative_path(value) {
        push_ledger_issue(
            issues,
            path,
            "unsafe_path",
            "path must be a non-empty relative path without parent traversal",
        );
    }
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

fn push_ledger_issue(
    issues: &mut Vec<PermissionedCampaignExecutionLedgerIssue>,
    path: &str,
    code: &str,
    message: &str,
) {
    issues.push(PermissionedCampaignExecutionLedgerIssue {
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

    #[test]
    fn swarm_calibration_accepts_authoritative_candidate_without_product_claim() {
        let manifest = valid_swarm_calibration_manifest();
        let report =
            validate_swarm_capability_calibration_manifest(&manifest, &swarm_calibration_config());
        assert!(report.valid, "{:?}", report.issues);
        assert_eq!(
            report.classification,
            SwarmCapabilityCalibrationClassification::AuthoritativeLargeHostCandidate.label()
        );
        assert!(report.candidate_for_authorized_run);
        assert_eq!(report.product_evidence_claim, "none");
        assert!(
            report
                .release_gate_effect
                .contains("swarm.responsiveness remains hidden")
        );
    }

    #[test]
    fn swarm_calibration_small_cpu_or_ram_is_smoke_only() {
        let mut manifest = valid_swarm_calibration_manifest();
        manifest.host.logical_cpus = 16;
        manifest.host.ram_total_gib = 64.0;
        manifest.resource_caps.max_threads = 16;
        manifest.resource_caps.max_memory_gib = 32.0;

        let report =
            validate_swarm_capability_calibration_manifest(&manifest, &swarm_calibration_config());
        assert!(report.valid, "{:?}", report.issues);
        assert_eq!(
            report.classification,
            SwarmCapabilityCalibrationClassification::SmallHostSmoke.label()
        );
        assert!(!report.candidate_for_authorized_run);
        assert!(
            report
                .downgrade_reasons
                .iter()
                .any(|reason| reason.contains("logical_cpus=16"))
        );
    }

    #[test]
    fn swarm_calibration_missing_numa_visibility_is_capability_downgrade() {
        let mut manifest = valid_swarm_calibration_manifest();
        manifest.host.numa_topology_visible = false;
        manifest.host.numa_nodes = None;

        let report =
            validate_swarm_capability_calibration_manifest(&manifest, &swarm_calibration_config());
        assert!(report.valid, "{:?}", report.issues);
        assert_eq!(
            report.classification,
            SwarmCapabilityCalibrationClassification::CapabilityDowngradedSmoke.label()
        );
        assert!(
            report
                .downgrade_reasons
                .iter()
                .any(|reason| reason.contains("numa_topology_visible=false"))
        );
    }

    #[test]
    fn swarm_calibration_missing_fuse_is_capability_downgrade() {
        let mut manifest = valid_swarm_calibration_manifest();
        manifest.host.fuse.state = SwarmCapabilityCalibrationFuseState::Missing;
        manifest.host.fuse.detail = "/dev/fuse unavailable".to_owned();

        let report =
            validate_swarm_capability_calibration_manifest(&manifest, &swarm_calibration_config());
        assert!(report.valid, "{:?}", report.issues);
        assert_eq!(
            report.classification,
            SwarmCapabilityCalibrationClassification::CapabilityDowngradedSmoke.label()
        );
        assert!(
            report
                .downgrade_reasons
                .iter()
                .any(|reason| reason == "fuse_capability=missing")
        );
    }

    #[test]
    fn swarm_calibration_stale_worker_fingerprint_blocks_packet() {
        let mut manifest = valid_swarm_calibration_manifest();
        manifest.worker.worker_fingerprint_observed_at_epoch_days = reference_epoch_days() - 30;
        manifest.worker.worker_fingerprint_max_age_days = 7;

        let report =
            validate_swarm_capability_calibration_manifest(&manifest, &swarm_calibration_config());
        assert!(report.valid, "{:?}", report.issues);
        assert_eq!(
            report.classification,
            SwarmCapabilityCalibrationClassification::Blocked.label()
        );
        assert!(
            report
                .blockers
                .iter()
                .any(|blocker| blocker.contains("worker_fingerprint_stale"))
        );
    }

    #[test]
    fn swarm_calibration_mismatched_artifact_root_blocks_packet() {
        let mut manifest = valid_swarm_calibration_manifest();
        manifest.artifact_plan.observed_artifact_root = "artifacts/swarm/other-root".to_owned();

        let report =
            validate_swarm_capability_calibration_manifest(&manifest, &swarm_calibration_config());
        assert!(report.valid, "{:?}", report.issues);
        assert_eq!(
            report.classification,
            SwarmCapabilityCalibrationClassification::Blocked.label()
        );
        assert!(
            report
                .blockers
                .iter()
                .any(|blocker| blocker.contains("artifact_root_mismatch"))
        );
    }

    #[test]
    fn swarm_calibration_markdown_names_handoff_boundary() {
        let manifest = valid_swarm_calibration_manifest();
        let report =
            validate_swarm_capability_calibration_manifest(&manifest, &swarm_calibration_config());
        let markdown = render_swarm_capability_calibration_markdown(&report);
        assert!(markdown.contains("Swarm Capability Calibration"));
        assert!(markdown.contains("authoritative_large_host_candidate"));
        assert!(markdown.contains("Product evidence claim: `none`"));
        assert!(markdown.contains("swarm.responsiveness remains hidden"));
    }

    #[test]
    fn execution_ledger_accepts_supported_state_lifecycle_points() {
        let cases = [
            vec![PermissionedCampaignLedgerStepStatus::NotAuthorized],
            vec![
                PermissionedCampaignLedgerStepStatus::NotAuthorized,
                PermissionedCampaignLedgerStepStatus::PreflightBlocked,
            ],
            vec![PermissionedCampaignLedgerStepStatus::Running],
            vec![
                PermissionedCampaignLedgerStepStatus::Running,
                PermissionedCampaignLedgerStepStatus::Interrupted,
            ],
            vec![
                PermissionedCampaignLedgerStepStatus::Running,
                PermissionedCampaignLedgerStepStatus::Interrupted,
                PermissionedCampaignLedgerStepStatus::Resumed,
            ],
            vec![
                PermissionedCampaignLedgerStepStatus::Running,
                PermissionedCampaignLedgerStepStatus::Passed,
            ],
            vec![
                PermissionedCampaignLedgerStepStatus::Running,
                PermissionedCampaignLedgerStepStatus::Failed,
            ],
            vec![
                PermissionedCampaignLedgerStepStatus::Running,
                PermissionedCampaignLedgerStepStatus::CleanupFailed,
            ],
            vec![
                PermissionedCampaignLedgerStepStatus::Running,
                PermissionedCampaignLedgerStepStatus::ArtifactStale,
            ],
        ];

        let manifest = valid_xfstests_manifest();
        for statuses in cases {
            let ledger = valid_execution_ledger(&manifest, &statuses);
            let report = validate_permissioned_campaign_execution_ledger(
                &manifest,
                &ledger,
                &ledger_config(),
            );
            assert!(
                report.valid,
                "statuses={statuses:?} issues={:?}",
                report.issues
            );
        }
    }

    #[test]
    fn execution_ledger_rejects_missing_ack_for_executed_run() {
        let manifest = valid_xfstests_manifest();
        let mut ledger = valid_execution_ledger(
            &manifest,
            &[
                PermissionedCampaignLedgerStepStatus::Running,
                PermissionedCampaignLedgerStepStatus::Passed,
            ],
        );
        ledger.required_ack.observed_value = None;
        ledger.required_ack.recorded_at = None;
        assert_ledger_issue(&manifest, &ledger, "missing_ack_text");
    }

    #[test]
    fn execution_ledger_rejects_changed_command_plan() {
        let manifest = valid_xfstests_manifest();
        let mut ledger = valid_execution_ledger(
            &manifest,
            &[PermissionedCampaignLedgerStepStatus::NotAuthorized],
        );
        ledger.command_plan_hash =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned();
        assert_ledger_issue(&manifest, &ledger, "changed_command_plan");
    }

    #[test]
    fn execution_ledger_rejects_stale_git_sha() {
        let manifest = valid_xfstests_manifest();
        let ledger = valid_execution_ledger(
            &manifest,
            &[PermissionedCampaignLedgerStepStatus::NotAuthorized],
        );
        let report = validate_permissioned_campaign_execution_ledger(
            &manifest,
            &ledger,
            &PermissionedCampaignExecutionLedgerValidationConfig {
                current_git_sha: Some("different-sha".to_owned()),
            },
        );
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.code == "stale_git_sha"),
            "{:?}",
            report.issues
        );
    }

    #[test]
    fn execution_ledger_rejects_missing_raw_logs() {
        let manifest = valid_xfstests_manifest();
        let mut ledger =
            valid_execution_ledger(&manifest, &[PermissionedCampaignLedgerStepStatus::Running]);
        ledger.steps[0].raw_log_paths.clear();
        assert_ledger_issue(&manifest, &ledger, "missing_raw_log");
    }

    #[test]
    fn execution_ledger_rejects_missing_cleanup_for_terminal_run() {
        let manifest = valid_xfstests_manifest();
        let mut ledger = valid_execution_ledger(
            &manifest,
            &[
                PermissionedCampaignLedgerStepStatus::Running,
                PermissionedCampaignLedgerStepStatus::Passed,
            ],
        );
        ledger.cleanup.status = PermissionedCampaignLedgerCleanupStatus::NotStarted;
        ledger.cleanup.report_path = None;
        assert_ledger_issue(&manifest, &ledger, "missing_cleanup");
    }

    #[test]
    fn execution_ledger_rejects_dry_run_packet_as_pass_evidence() {
        let manifest = valid_xfstests_manifest();
        let mut ledger = valid_execution_ledger(
            &manifest,
            &[PermissionedCampaignLedgerStepStatus::NotAuthorized],
        );
        ledger.product_evidence_claim =
            PermissionedCampaignProductEvidenceClaim::PacketCountsAsPassFail;
        assert_ledger_issue(&manifest, &ledger, "dry_run_packet_as_pass_evidence");
    }

    #[test]
    fn execution_ledger_rejects_invalid_state_transition() {
        let manifest = valid_xfstests_manifest();
        let ledger = valid_execution_ledger(
            &manifest,
            &[
                PermissionedCampaignLedgerStepStatus::Running,
                PermissionedCampaignLedgerStepStatus::Passed,
                PermissionedCampaignLedgerStepStatus::Resumed,
            ],
        );
        assert_ledger_issue(&manifest, &ledger, "invalid_state_transition");
    }

    #[test]
    fn execution_ledger_markdown_explains_resume_and_lane_candidates() {
        let manifest = valid_xfstests_manifest();
        let ledger = valid_execution_ledger(
            &manifest,
            &[
                PermissionedCampaignLedgerStepStatus::Running,
                PermissionedCampaignLedgerStepStatus::Interrupted,
                PermissionedCampaignLedgerStepStatus::Resumed,
            ],
        );
        let report =
            validate_permissioned_campaign_execution_ledger(&manifest, &ledger, &ledger_config());
        assert!(report.valid, "{:?}", report.issues);
        let markdown = render_permissioned_campaign_execution_ledger_markdown(&report);
        assert!(markdown.contains("Permissioned Campaign Execution Ledger"));
        assert!(markdown.contains("Proof Bundle Lane Candidates"));
        assert!(markdown.contains("resume_checkpoint"));
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

    fn assert_ledger_issue(
        manifest: &PermissionedCampaignBrokerManifest,
        ledger: &PermissionedCampaignExecutionLedger,
        code: &str,
    ) {
        let report =
            validate_permissioned_campaign_execution_ledger(manifest, ledger, &ledger_config());
        assert!(
            report.issues.iter().any(|issue| issue.code == code),
            "missing ledger issue {code}; got {:?}",
            report.issues
        );
    }

    fn config() -> PermissionedCampaignBrokerValidationConfig {
        PermissionedCampaignBrokerValidationConfig {
            reference_epoch_days: reference_epoch_days(),
        }
    }

    fn ledger_config() -> PermissionedCampaignExecutionLedgerValidationConfig {
        PermissionedCampaignExecutionLedgerValidationConfig {
            current_git_sha: Some("abcdef123456".to_owned()),
        }
    }

    fn swarm_calibration_config() -> SwarmCapabilityCalibrationValidationConfig {
        SwarmCapabilityCalibrationValidationConfig {
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

    fn valid_execution_ledger(
        manifest: &PermissionedCampaignBrokerManifest,
        statuses: &[PermissionedCampaignLedgerStepStatus],
    ) -> PermissionedCampaignExecutionLedger {
        let has_execution = statuses.iter().any(|status| status.requires_raw_logs());
        let final_status = statuses.last().copied();
        let terminal_cleanup = matches!(
            final_status,
            Some(
                PermissionedCampaignLedgerStepStatus::Passed
                    | PermissionedCampaignLedgerStepStatus::Failed
                    | PermissionedCampaignLedgerStepStatus::CleanupFailed
                    | PermissionedCampaignLedgerStepStatus::ArtifactStale
            )
        );
        let mut artifacts = Vec::new();
        if has_execution {
            artifacts.push(ledger_artifact(
                "raw-log",
                "artifacts/xfstests/real-run/raw.log",
                PermissionedCampaignLedgerArtifactRole::RawLog,
                final_status == Some(PermissionedCampaignLedgerStepStatus::ArtifactStale),
            ));
            artifacts.push(ledger_artifact(
                "resume-checkpoint",
                "artifacts/xfstests/real-run/checkpoint.json",
                PermissionedCampaignLedgerArtifactRole::ResumeCheckpoint,
                false,
            ));
            artifacts.push(ledger_artifact(
                "proof-lane",
                "artifacts/xfstests/real-run/proof/xfstests.json",
                PermissionedCampaignLedgerArtifactRole::ProofBundleLane,
                false,
            ));
        }
        if terminal_cleanup {
            artifacts.push(ledger_artifact(
                "cleanup-report",
                "artifacts/xfstests/real-run/cleanup.json",
                PermissionedCampaignLedgerArtifactRole::CleanupReport,
                false,
            ));
        }

        let steps = statuses
            .iter()
            .enumerate()
            .map(|(index, status)| {
                let raw_log_paths = if status.requires_raw_logs() {
                    vec!["artifacts/xfstests/real-run/raw.log".to_owned()]
                } else {
                    Vec::new()
                };
                let checkpoint_artifacts = if matches!(
                    status,
                    PermissionedCampaignLedgerStepStatus::Interrupted
                        | PermissionedCampaignLedgerStepStatus::Resumed
                ) {
                    vec!["artifacts/xfstests/real-run/checkpoint.json".to_owned()]
                } else {
                    Vec::new()
                };
                PermissionedCampaignLedgerStep {
                    step_id: format!("step-{index:02}-{}", status.label()),
                    command_id: manifest
                        .exact_commands
                        .get(usize::from(index > 0))
                        .map_or_else(
                            || manifest.exact_commands[0].command_id.clone(),
                            |command| command.command_id.clone(),
                        ),
                    status: *status,
                    started_at: Some(REFERENCE_TIMESTAMP.to_owned()),
                    finished_at: Some(REFERENCE_TIMESTAMP.to_owned()),
                    raw_log_paths,
                    checkpoint_artifacts,
                    note: format!("synthetic {} ledger state", status.label()),
                }
            })
            .collect();

        PermissionedCampaignExecutionLedger {
            schema_version: PERMISSIONED_CAMPAIGN_EXECUTION_LEDGER_SCHEMA_VERSION,
            campaign_id: manifest.campaign_id.clone(),
            lane_kind: manifest.lane_kind,
            target_beads: manifest.target_beads.clone(),
            git_sha: "abcdef123456".to_owned(),
            command_plan_hash: permissioned_campaign_command_plan_hash(manifest),
            required_ack: PermissionedCampaignLedgerAck {
                env_var: manifest.required_ack.env_var.clone(),
                exact_value: manifest.required_ack.exact_value.clone(),
                observed_value: has_execution.then(|| manifest.required_ack.exact_value.clone()),
                recorded_at: has_execution.then(|| REFERENCE_TIMESTAMP.to_owned()),
            },
            preflight_snapshot: PermissionedCampaignLedgerPreflightSnapshot {
                snapshot_id: "preflight-snapshot".to_owned(),
                observed_at: REFERENCE_TIMESTAMP.to_owned(),
                artifact_path: "artifacts/xfstests/preflight/report.json".to_owned(),
                git_sha: "abcdef123456".to_owned(),
                host_class: "synthetic_permissioned_fixture".to_owned(),
                blockers: if final_status
                    == Some(PermissionedCampaignLedgerStepStatus::PreflightBlocked)
                {
                    vec!["operator ACK not provided".to_owned()]
                } else {
                    Vec::new()
                },
            },
            steps,
            artifacts,
            resume_state: PermissionedCampaignLedgerResumeState {
                resume_token: statuses
                    .contains(&PermissionedCampaignLedgerStepStatus::Resumed)
                    .then(|| "resume-token-001".to_owned()),
                last_checkpoint_artifact: has_execution
                    .then(|| "artifacts/xfstests/real-run/checkpoint.json".to_owned()),
                partial_artifacts_preserved: has_execution,
                next_command_id: Some("xfstests_permissioned_run".to_owned()),
            },
            cleanup: PermissionedCampaignLedgerCleanup {
                status: if terminal_cleanup {
                    match final_status {
                        Some(PermissionedCampaignLedgerStepStatus::CleanupFailed) => {
                            PermissionedCampaignLedgerCleanupStatus::CleanupFailed
                        }
                        _ => PermissionedCampaignLedgerCleanupStatus::PreservedArtifacts,
                    }
                } else {
                    PermissionedCampaignLedgerCleanupStatus::NotStarted
                },
                report_path: terminal_cleanup
                    .then(|| "artifacts/xfstests/real-run/cleanup.json".to_owned()),
                completed_at: terminal_cleanup.then(|| REFERENCE_TIMESTAMP.to_owned()),
            },
            proof_bundle_lane_candidates: if has_execution {
                vec![PermissionedCampaignProofBundleLaneCandidate {
                    lane_id: "xfstests".to_owned(),
                    artifact_path: "artifacts/xfstests/real-run/proof/xfstests.json".to_owned(),
                    promotion_status: if final_status
                        == Some(PermissionedCampaignLedgerStepStatus::Passed)
                    {
                        PermissionedCampaignProofBundlePromotionStatus::Candidate
                    } else {
                        PermissionedCampaignProofBundlePromotionStatus::Blocked
                    },
                    note: "resume_checkpoint lane candidate retained for proof-bundle assembly"
                        .to_owned(),
                }]
            } else {
                Vec::new()
            },
            product_evidence_claim: if final_status
                == Some(PermissionedCampaignLedgerStepStatus::Passed)
            {
                PermissionedCampaignProductEvidenceClaim::ExecutedEvidenceRecorded
            } else {
                PermissionedCampaignProductEvidenceClaim::None
            },
        }
    }

    fn ledger_artifact(
        artifact_id: &str,
        path: &str,
        role: PermissionedCampaignLedgerArtifactRole,
        stale: bool,
    ) -> PermissionedCampaignLedgerArtifact {
        PermissionedCampaignLedgerArtifact {
            artifact_id: artifact_id.to_owned(),
            path: path.to_owned(),
            sha256: fixture_sha256(path),
            role,
            stale,
        }
    }

    fn fixture_sha256(seed: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
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

    fn valid_swarm_calibration_manifest() -> SwarmCapabilityCalibrationManifest {
        SwarmCapabilityCalibrationManifest {
            schema_version: SWARM_CAPABILITY_CALIBRATION_SCHEMA_VERSION,
            packet_id: "bd-4v16z.9-large-host-calibration-20260509".to_owned(),
            generated_at: REFERENCE_TIMESTAMP.to_owned(),
            target_beads: vec!["bd-4v16z.9".to_owned(), "bd-rchk0.53.8".to_owned()],
            host: SwarmCapabilityCalibrationHost {
                logical_cpus: 96,
                ram_total_gib: 512.0,
                ram_available_gib: 384.0,
                numa_topology_visible: true,
                numa_nodes: Some(2),
                storage_class: "local_nvme".to_owned(),
                fuse: SwarmCapabilityCalibrationFuse {
                    state: SwarmCapabilityCalibrationFuseState::Available,
                    detail: "/dev/fuse and fusermount3 available".to_owned(),
                },
            },
            worker: SwarmCapabilityCalibrationWorker {
                rch_worker_identity: "rch:large-host-01".to_owned(),
                worker_fingerprint: "worker=large-host-01 cpu=96 ram=512g numa=2".to_owned(),
                worker_fingerprint_observed_at_epoch_days: reference_epoch_days(),
                worker_fingerprint_max_age_days: 7,
                queue_isolation: SwarmCapabilityCalibrationIsolation::Dedicated,
                target_dir_isolated: true,
                target_dir: "artifacts/swarm/calibration/target".to_owned(),
            },
            artifact_plan: SwarmCapabilityCalibrationArtifactPlan {
                expected_artifact_root: "artifacts/swarm/large-host".to_owned(),
                observed_artifact_root: "artifacts/swarm/large-host".to_owned(),
            },
            resource_caps: SwarmCapabilityCalibrationResourceCaps {
                max_duration_secs: 7200,
                max_threads: 96,
                max_memory_gib: 384.0,
                max_temp_storage_gib: 512.0,
                max_queue_depth: 4096,
            },
            release_gate_policy_path: "tests/release-gates/release_gate_policy_v1.json".to_owned(),
            real_campaign_bead: "bd-rchk0.53.8".to_owned(),
            handoff_summary: "calibration packet only; run bd-rchk0.53.8 for executed evidence"
                .to_owned(),
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
