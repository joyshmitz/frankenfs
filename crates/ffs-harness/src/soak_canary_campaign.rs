#![allow(clippy::module_name_repetitions, clippy::too_many_lines)]
#![forbid(unsafe_code)]

//! Soak/canary campaign manifest for `bd-rchk0.5.9`.
//!
//! This is the executable contract for long-running mount and repair readiness
//! campaigns. It validates the campaign plan, expands dry-run commands, and
//! emits shared QA artifacts without requiring a permissioned FUSE host.

use crate::artifact_manifest::{
    ArtifactCategory, ArtifactEntry, ArtifactManifest, EnvironmentFingerprint, ManifestBuilder,
    ScenarioResult, validate_manifest,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub const SOAK_CANARY_CAMPAIGN_SCHEMA_VERSION: u32 = 1;

const REQUIRED_ENVIRONMENT_FIELDS: [&str; 14] = [
    "campaign_id",
    "git_sha",
    "kernel",
    "fuse_capability",
    "toolchain",
    "rustc_version",
    "cargo_version",
    "worker_id",
    "cpu_cores_logical",
    "ram_total_gb",
    "workload_ids",
    "seeds",
    "duration_seconds",
    "resource_usage",
];

const REQUIRED_LOG_FIELDS: [&str; 16] = [
    "campaign_id",
    "profile_id",
    "workload_id",
    "seed",
    "iteration",
    "heartbeat_index",
    "elapsed_seconds",
    "outcome",
    "classification",
    "failure_threshold",
    "resource_limits",
    "artifact_path",
    "stdout_path",
    "stderr_path",
    "cleanup_status",
    "reproduction_command",
];

const REQUIRED_ARTIFACT_CONSUMERS: [&str; 3] = [
    "operator_proof_bundle",
    "release_gate_evaluator",
    "operational_readiness_report",
];

const REQUIRED_LONG_RUN_RECORD_FIELDS: [&str; 10] = [
    "kernel",
    "fuse_capability",
    "toolchain",
    "git_sha",
    "workload_ids",
    "seeds",
    "duration_seconds",
    "resource_usage",
    "cleanup_status",
    "reproduction_command",
];

const REQUIRED_STOP_PRECEDENCE: [CampaignStopReason; 9] = [
    CampaignStopReason::ResourceBudgetExceeded,
    CampaignStopReason::Timeout,
    CampaignStopReason::InfrastructureError,
    CampaignStopReason::FailureThresholdExceeded,
    CampaignStopReason::FlakeThresholdExceeded,
    CampaignStopReason::HostCapabilitySkip,
    CampaignStopReason::StaleBaseline,
    CampaignStopReason::Inconclusive,
    CampaignStopReason::Completed,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoakCanaryCampaignManifest {
    pub schema_version: u32,
    pub manifest_id: String,
    pub shared_qa_schema_version: u32,
    pub artifact_root_template: String,
    pub classification_policy: CampaignClassificationPolicy,
    pub allowed_capabilities: Vec<String>,
    pub artifact_consumers: Vec<String>,
    pub required_environment_fields: Vec<String>,
    pub required_log_fields: Vec<String>,
    pub profiles: Vec<CampaignProfile>,
    pub workloads: Vec<CampaignWorkload>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignClassificationPolicy {
    pub stale_baseline_max_age_hours: u64,
    pub stop_condition_precedence: Vec<CampaignStopReason>,
    pub known_flake_quarantines: Vec<KnownFlakeQuarantine>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownFlakeQuarantine {
    pub quarantine_id: String,
    pub workload_id: String,
    pub signature: String,
    pub owner: String,
    pub expires_at: String,
    pub user_risk_rationale: String,
    pub reproduction_pack: String,
    pub release_gate_impact: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignProfile {
    pub profile_id: CampaignProfileId,
    pub description: String,
    pub duration_seconds: u64,
    pub max_iterations: u32,
    pub heartbeat_interval_seconds: u64,
    pub max_failures: u32,
    pub max_errors: u32,
    pub max_flakes: u32,
    pub required_capabilities: Vec<String>,
    pub resource_limits: CampaignResourceLimits,
    pub artifact_retention_days: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub long_run_context: Option<LongRunContext>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignProfileId {
    Smoke,
    Nightly,
    Stress,
    Canary,
}

impl CampaignProfileId {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Smoke => "smoke",
            Self::Nightly => "nightly",
            Self::Stress => "stress",
            Self::Canary => "canary",
        }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        match raw {
            "smoke" => Ok(Self::Smoke),
            "nightly" => Ok(Self::Nightly),
            "stress" => Ok(Self::Stress),
            "canary" => Ok(Self::Canary),
            other => bail!("unknown campaign profile {other}"),
        }
    }

    #[must_use]
    pub const fn is_long_running(self) -> bool {
        !matches!(self, Self::Smoke)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignResourceLimits {
    pub max_wall_seconds: u64,
    pub max_memory_mib: u64,
    pub max_artifact_mib: u64,
    pub max_cpu_percent: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LongRunContext {
    pub intended_hosts: Vec<String>,
    pub records_environment_fields: Vec<String>,
    pub operator_notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignWorkload {
    pub workload_id: String,
    pub description: String,
    pub kind: CampaignWorkloadKind,
    pub filesystem: CampaignFilesystem,
    pub profile_ids: Vec<CampaignProfileId>,
    pub required_capabilities: Vec<String>,
    pub seeds: Vec<u64>,
    pub command_template: String,
    pub expected_safe_behavior: String,
    pub failure_threshold: WorkloadFailureThreshold,
    pub output_artifact: CampaignOutputArtifact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignWorkloadKind {
    MountCycle,
    MetadataChurn,
    ReadWriteVerify,
    RepairScrubDryRun,
    WritebackCacheGate,
    HostCapabilityProbe,
    ArtifactAggregation,
}

impl CampaignWorkloadKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MountCycle => "mount_cycle",
            Self::MetadataChurn => "metadata_churn",
            Self::ReadWriteVerify => "read_write_verify",
            Self::RepairScrubDryRun => "repair_scrub_dry_run",
            Self::WritebackCacheGate => "writeback_cache_gate",
            Self::HostCapabilityProbe => "host_capability_probe",
            Self::ArtifactAggregation => "artifact_aggregation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignFilesystem {
    Ext4,
    Btrfs,
    Native,
    Mixed,
    NotApplicable,
}

impl CampaignFilesystem {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ext4 => "ext4",
            Self::Btrfs => "btrfs",
            Self::Native => "native",
            Self::Mixed => "mixed",
            Self::NotApplicable => "not_applicable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadFailureThreshold {
    pub max_failures: u32,
    pub max_errors: u32,
    pub max_flakes: u32,
    pub flake_window_iterations: u32,
    pub follow_up_bead: String,
    pub preserve_repro_artifacts: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignOutputArtifact {
    pub path_template: String,
    pub category: ArtifactCategory,
    pub content_type: String,
    pub aggregate_key: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignObservationStats {
    pub passes: u32,
    pub failures: u32,
    pub skips: u32,
    pub errors: u32,
    pub flakes: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignOutcomeClass {
    Pass,
    Fail,
    Skip,
    Error,
    Flake,
}

impl CampaignOutcomeClass {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Skip => "skip",
            Self::Error => "error",
            Self::Flake => "flake",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignStopReason {
    ResourceBudgetExceeded,
    Timeout,
    InfrastructureError,
    FailureThresholdExceeded,
    FlakeThresholdExceeded,
    HostCapabilitySkip,
    StaleBaseline,
    Inconclusive,
    Completed,
}

impl CampaignStopReason {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ResourceBudgetExceeded => "resource_budget_exceeded",
            Self::Timeout => "timeout",
            Self::InfrastructureError => "infrastructure_error",
            Self::FailureThresholdExceeded => "failure_threshold_exceeded",
            Self::FlakeThresholdExceeded => "flake_threshold_exceeded",
            Self::HostCapabilitySkip => "host_capability_skip",
            Self::StaleBaseline => "stale_baseline",
            Self::Inconclusive => "inconclusive",
            Self::Completed => "completed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignRootCauseClass {
    CleanPass,
    ProductRegression,
    HostCapabilitySkip,
    InfrastructureError,
    Timeout,
    ResourceExhaustion,
    KnownQuarantinedFlake,
    NewRecurringFlake,
    Inconclusive,
}

impl CampaignRootCauseClass {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::CleanPass => "clean_pass",
            Self::ProductRegression => "product_regression",
            Self::HostCapabilitySkip => "host_capability_skip",
            Self::InfrastructureError => "infrastructure_error",
            Self::Timeout => "timeout",
            Self::ResourceExhaustion => "resource_exhaustion",
            Self::KnownQuarantinedFlake => "known_quarantined_flake",
            Self::NewRecurringFlake => "new_recurring_flake",
            Self::Inconclusive => "inconclusive",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignFailureEvaluation {
    pub profile_id: CampaignProfileId,
    pub workload_id: String,
    pub outcome: CampaignOutcomeClass,
    pub threshold_summary: String,
    pub follow_up_bead: String,
    pub repro_artifacts_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignRunObservation {
    pub stats: CampaignObservationStats,
    pub elapsed_seconds: u64,
    pub baseline_age_hours: u64,
    pub host_capability_missing: bool,
    pub infrastructure_error: bool,
    pub timeout: bool,
    pub recurring_flake_signature: Option<String>,
    pub resource_usage: CampaignResourceUsage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignStopEvaluation {
    pub profile_id: CampaignProfileId,
    pub workload_id: String,
    pub stop_reason: CampaignStopReason,
    pub classification: CampaignRootCauseClass,
    pub follow_up_bead: String,
    pub quarantine_id: Option<String>,
    pub release_gate_impact: String,
    pub repro_artifacts_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignCommandExpansion {
    pub profile_id: CampaignProfileId,
    pub workload_id: String,
    pub seed: u64,
    pub command: String,
    pub artifact_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignHeartbeat {
    pub campaign_id: String,
    pub profile_id: CampaignProfileId,
    pub heartbeat_index: u32,
    pub elapsed_seconds: u64,
    pub iteration: u32,
    pub active_workloads: Vec<String>,
    pub stats: CampaignObservationStats,
    pub resource_usage: CampaignResourceUsage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignResourceUsage {
    pub cpu_percent: u32,
    pub memory_mib: u64,
    pub artifact_mib: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoakCanaryCampaignReport {
    pub schema_version: u32,
    pub manifest_id: String,
    pub valid: bool,
    pub profile_count: usize,
    pub workload_count: usize,
    pub long_profile_ids: Vec<CampaignProfileId>,
    pub required_environment_fields: Vec<String>,
    pub required_log_fields: Vec<String>,
    pub artifact_consumers: Vec<String>,
    pub stop_condition_precedence: Vec<CampaignStopReason>,
    pub command_expansions: Vec<CampaignCommandExpansion>,
    pub failure_evaluations: Vec<CampaignFailureEvaluation>,
    pub root_cause_samples: Vec<CampaignStopEvaluation>,
    pub heartbeat_summaries: Vec<String>,
    pub sample_outcome_counts: BTreeMap<String, usize>,
    pub sample_artifact_manifest_errors: Vec<String>,
    pub errors: Vec<String>,
}

pub fn load_soak_canary_campaign_manifest(path: &Path) -> Result<SoakCanaryCampaignManifest> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read soak/canary manifest {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("invalid soak/canary manifest JSON {}", path.display()))
}

#[must_use]
pub fn validate_soak_canary_campaign_manifest(
    manifest: &SoakCanaryCampaignManifest,
    artifact_root: &str,
) -> SoakCanaryCampaignReport {
    let mut errors = Vec::new();
    validate_manifest_shape(manifest, &mut errors);

    let command_expansions = expand_campaign_commands(manifest, artifact_root);
    let failure_evaluations = sample_failure_evaluations(manifest);
    let root_cause_samples = sample_root_cause_evaluations(manifest);
    let heartbeat_summaries = sample_heartbeat_summaries(manifest);
    let sample_artifact_manifest =
        build_soak_canary_sample_artifact_manifest(manifest, artifact_root, &failure_evaluations);
    let sample_artifact_manifest_errors = validate_manifest(&sample_artifact_manifest)
        .into_iter()
        .map(|error| format!("{error:?}"))
        .collect::<Vec<_>>();
    errors.extend(
        sample_artifact_manifest_errors
            .iter()
            .map(|error| format!("sample artifact manifest invalid: {error}")),
    );

    SoakCanaryCampaignReport {
        schema_version: SOAK_CANARY_CAMPAIGN_SCHEMA_VERSION,
        manifest_id: manifest.manifest_id.clone(),
        valid: errors.is_empty(),
        profile_count: manifest.profiles.len(),
        workload_count: manifest.workloads.len(),
        long_profile_ids: manifest
            .profiles
            .iter()
            .filter(|profile| profile.profile_id.is_long_running())
            .map(|profile| profile.profile_id)
            .collect(),
        required_environment_fields: manifest.required_environment_fields.clone(),
        required_log_fields: manifest.required_log_fields.clone(),
        artifact_consumers: manifest.artifact_consumers.clone(),
        stop_condition_precedence: manifest
            .classification_policy
            .stop_condition_precedence
            .clone(),
        command_expansions,
        failure_evaluations,
        root_cause_samples,
        heartbeat_summaries,
        sample_outcome_counts: sample_outcome_counts(),
        sample_artifact_manifest_errors,
        errors,
    }
}

#[must_use]
pub fn expand_campaign_commands(
    manifest: &SoakCanaryCampaignManifest,
    artifact_root: &str,
) -> Vec<CampaignCommandExpansion> {
    let profile_ids = manifest
        .profiles
        .iter()
        .map(|profile| profile.profile_id)
        .collect::<BTreeSet<_>>();
    let mut expansions = Vec::new();

    for workload in &manifest.workloads {
        for profile_id in workload
            .profile_ids
            .iter()
            .filter(|profile_id| profile_ids.contains(profile_id))
        {
            for seed in &workload.seeds {
                let artifact_path = expand_template(
                    &workload.output_artifact.path_template,
                    *profile_id,
                    workload,
                    *seed,
                    artifact_root,
                );
                expansions.push(CampaignCommandExpansion {
                    profile_id: *profile_id,
                    workload_id: workload.workload_id.clone(),
                    seed: *seed,
                    command: expand_template(
                        &workload.command_template,
                        *profile_id,
                        workload,
                        *seed,
                        artifact_root,
                    ),
                    artifact_path,
                });
            }
        }
    }

    expansions
}

#[must_use]
pub fn evaluate_failure_threshold(
    profile: &CampaignProfile,
    workload: &CampaignWorkload,
    stats: CampaignObservationStats,
) -> CampaignFailureEvaluation {
    let workload_limit = &workload.failure_threshold;
    let max_errors = profile.max_errors.min(workload_limit.max_errors);
    let max_failures = profile.max_failures.min(workload_limit.max_failures);
    let max_flakes = profile.max_flakes.min(workload_limit.max_flakes);

    let outcome = if stats.errors > max_errors {
        CampaignOutcomeClass::Error
    } else if stats.failures > max_failures {
        CampaignOutcomeClass::Fail
    } else if stats.flakes > max_flakes {
        CampaignOutcomeClass::Flake
    } else if stats.passes == 0 && stats.skips > 0 {
        CampaignOutcomeClass::Skip
    } else {
        CampaignOutcomeClass::Pass
    };

    CampaignFailureEvaluation {
        profile_id: profile.profile_id,
        workload_id: workload.workload_id.clone(),
        outcome,
        threshold_summary: format!(
            "observed pass={} fail={} skip={} error={} flake={}; allowed fail<={} error<={} flake<={}",
            stats.passes,
            stats.failures,
            stats.skips,
            stats.errors,
            stats.flakes,
            max_failures,
            max_errors,
            max_flakes
        ),
        follow_up_bead: workload_limit.follow_up_bead.clone(),
        repro_artifacts_required: workload_limit.preserve_repro_artifacts,
    }
}

#[must_use]
pub fn evaluate_stop_condition(
    policy: &CampaignClassificationPolicy,
    profile: &CampaignProfile,
    workload: &CampaignWorkload,
    observation: &CampaignRunObservation,
) -> CampaignStopEvaluation {
    let stop_reason = classify_stop_reason(policy, profile, workload, observation);
    let matching_quarantine = observation
        .recurring_flake_signature
        .as_deref()
        .and_then(|signature| find_known_quarantine(policy, &workload.workload_id, signature));
    let classification = classify_root_cause(stop_reason, matching_quarantine);
    let threshold = &workload.failure_threshold;
    let follow_up_bead = matching_quarantine.map_or_else(
        || threshold.follow_up_bead.clone(),
        |quarantine| quarantine.quarantine_id.clone(),
    );
    let release_gate_impact = matching_quarantine.map_or_else(
        || release_gate_impact_for(classification).to_owned(),
        |quarantine| quarantine.release_gate_impact.clone(),
    );

    CampaignStopEvaluation {
        profile_id: profile.profile_id,
        workload_id: workload.workload_id.clone(),
        stop_reason,
        classification,
        follow_up_bead,
        quarantine_id: matching_quarantine.map(|quarantine| quarantine.quarantine_id.clone()),
        release_gate_impact,
        repro_artifacts_required: threshold.preserve_repro_artifacts,
    }
}

fn classify_stop_reason(
    policy: &CampaignClassificationPolicy,
    profile: &CampaignProfile,
    workload: &CampaignWorkload,
    observation: &CampaignRunObservation,
) -> CampaignStopReason {
    let limits = &profile.resource_limits;
    let threshold = &workload.failure_threshold;
    let max_errors = profile.max_errors.min(threshold.max_errors);
    let max_failures = profile.max_failures.min(threshold.max_failures);
    let max_flakes = profile.max_flakes.min(threshold.max_flakes);

    if observation.resource_usage.cpu_percent > limits.max_cpu_percent
        || observation.resource_usage.memory_mib > limits.max_memory_mib
        || observation.resource_usage.artifact_mib > limits.max_artifact_mib
    {
        CampaignStopReason::ResourceBudgetExceeded
    } else if observation.timeout || observation.elapsed_seconds > limits.max_wall_seconds {
        CampaignStopReason::Timeout
    } else if observation.infrastructure_error || observation.stats.errors > max_errors {
        CampaignStopReason::InfrastructureError
    } else if observation.stats.failures > max_failures {
        CampaignStopReason::FailureThresholdExceeded
    } else if observation.stats.flakes > max_flakes {
        CampaignStopReason::FlakeThresholdExceeded
    } else if observation.host_capability_missing && observation.stats.skips > 0 {
        CampaignStopReason::HostCapabilitySkip
    } else if observation.baseline_age_hours > policy.stale_baseline_max_age_hours {
        CampaignStopReason::StaleBaseline
    } else if observation.stats.passes > 0 {
        CampaignStopReason::Completed
    } else {
        CampaignStopReason::Inconclusive
    }
}

fn classify_root_cause(
    stop_reason: CampaignStopReason,
    matching_quarantine: Option<&KnownFlakeQuarantine>,
) -> CampaignRootCauseClass {
    match stop_reason {
        CampaignStopReason::ResourceBudgetExceeded => CampaignRootCauseClass::ResourceExhaustion,
        CampaignStopReason::Timeout => CampaignRootCauseClass::Timeout,
        CampaignStopReason::InfrastructureError => CampaignRootCauseClass::InfrastructureError,
        CampaignStopReason::FailureThresholdExceeded => CampaignRootCauseClass::ProductRegression,
        CampaignStopReason::FlakeThresholdExceeded => {
            if matching_quarantine.is_some() {
                CampaignRootCauseClass::KnownQuarantinedFlake
            } else {
                CampaignRootCauseClass::NewRecurringFlake
            }
        }
        CampaignStopReason::HostCapabilitySkip => CampaignRootCauseClass::HostCapabilitySkip,
        CampaignStopReason::Completed => CampaignRootCauseClass::CleanPass,
        CampaignStopReason::StaleBaseline | CampaignStopReason::Inconclusive => {
            CampaignRootCauseClass::Inconclusive
        }
    }
}

fn find_known_quarantine<'a>(
    policy: &'a CampaignClassificationPolicy,
    workload_id: &str,
    signature: &str,
) -> Option<&'a KnownFlakeQuarantine> {
    policy.known_flake_quarantines.iter().find(|quarantine| {
        quarantine.workload_id == workload_id && quarantine.signature == signature
    })
}

fn release_gate_impact_for(classification: CampaignRootCauseClass) -> &'static str {
    match classification {
        CampaignRootCauseClass::CleanPass => "eligible",
        CampaignRootCauseClass::HostCapabilitySkip => "skip_lane_with_host_blocker",
        CampaignRootCauseClass::KnownQuarantinedFlake => "quarantine_with_expiry",
        CampaignRootCauseClass::Inconclusive => "downgrade_until_fresh_evidence",
        CampaignRootCauseClass::ProductRegression
        | CampaignRootCauseClass::InfrastructureError
        | CampaignRootCauseClass::Timeout
        | CampaignRootCauseClass::ResourceExhaustion
        | CampaignRootCauseClass::NewRecurringFlake => "block_release_gate",
    }
}

#[must_use]
pub fn render_heartbeat_summary(heartbeat: &CampaignHeartbeat) -> String {
    format!(
        "HEARTBEAT|campaign_id={}|profile_id={}|heartbeat_index={}|elapsed_seconds={}|iteration={}|pass={}|fail={}|skip={}|error={}|flake={}|active_workloads={}|cpu_percent={}|memory_mib={}|artifact_mib={}",
        heartbeat.campaign_id,
        heartbeat.profile_id.label(),
        heartbeat.heartbeat_index,
        heartbeat.elapsed_seconds,
        heartbeat.iteration,
        heartbeat.stats.passes,
        heartbeat.stats.failures,
        heartbeat.stats.skips,
        heartbeat.stats.errors,
        heartbeat.stats.flakes,
        heartbeat.active_workloads.join(","),
        heartbeat.resource_usage.cpu_percent,
        heartbeat.resource_usage.memory_mib,
        heartbeat.resource_usage.artifact_mib,
    )
}

#[must_use]
pub fn build_soak_canary_sample_artifact_manifest(
    manifest: &SoakCanaryCampaignManifest,
    artifact_root: &str,
    failure_evaluations: &[CampaignFailureEvaluation],
) -> ArtifactManifest {
    let root_cause_samples = sample_root_cause_evaluations(manifest);
    let mut builder = ManifestBuilder::new(
        "soak_canary_campaign_dry_run",
        "soak_canary_campaigns",
        "2026-05-03T00:00:00Z",
    )
    .bead_id("bd-rchk0.5.9")
    .git_context("dry-run", "main", true)
    .environment(EnvironmentFingerprint {
        hostname: "dry-run-host".to_owned(),
        cpu_model: "dry-run-cpu".to_owned(),
        cpu_count: 64,
        memory_gib: 256,
        kernel: "dry-run-kernel".to_owned(),
        rustc_version: "dry-run-rustc".to_owned(),
        cargo_version: Some("dry-run-cargo".to_owned()),
    })
    .scenario(
        "soak_campaign_manifest_validates",
        ScenarioResult::Pass,
        Some("soak/canary campaign manifest validation"),
        0.0,
    )
    .scenario(
        "soak_campaign_host_capability_skip",
        ScenarioResult::Skip,
        Some("missing FUSE capability is preserved as a host skip"),
        0.0,
    )
    .scenario(
        "soak_campaign_product_failure_preserved",
        ScenarioResult::Fail,
        Some("sample product failure keeps reproduction artifacts and follow-up bead"),
        0.0,
    )
    .scenario(
        "soak_campaign_worker_dependency_error",
        ScenarioResult::Fail,
        Some("sample worker error is classified separately from product failure"),
        0.0,
    )
    .artifact(ArtifactEntry {
        path: format!("{artifact_root}/soak_canary_campaign_report.json"),
        category: ArtifactCategory::SummaryReport,
        content_type: Some("application/json".to_owned()),
        size_bytes: 0,
        sha256: None,
        redacted: false,
        metadata: BTreeMap::from([
            ("manifest_id".to_owned(), manifest.manifest_id.clone()),
            ("bead_id".to_owned(), "bd-rchk0.5.9".to_owned()),
            (
                "proof_bundle_lane".to_owned(),
                "soak_canary_campaigns".to_owned(),
            ),
            (
                "release_gate_feature".to_owned(),
                "operational.soak_canary".to_owned(),
            ),
        ]),
    })
    .artifact(ArtifactEntry {
        path: format!("{artifact_root}/heartbeat.jsonl"),
        category: ArtifactCategory::E2eLog,
        content_type: Some("application/jsonl".to_owned()),
        size_bytes: 0,
        sha256: None,
        redacted: false,
        metadata: BTreeMap::from([
            ("log_type".to_owned(), "heartbeat".to_owned()),
            (
                "required_fields".to_owned(),
                manifest.required_log_fields.join(","),
            ),
        ]),
    })
    .artifact(ArtifactEntry {
        path: format!("{artifact_root}/flake_repro_pack.json"),
        category: ArtifactCategory::ReproPack,
        content_type: Some("application/json".to_owned()),
        size_bytes: 0,
        sha256: None,
        redacted: false,
        metadata: BTreeMap::from([
            (
                "classification".to_owned(),
                CampaignOutcomeClass::Flake.label().to_owned(),
            ),
            ("follow_up_required".to_owned(), "true".to_owned()),
        ]),
    });

    for expansion in expand_campaign_commands(manifest, artifact_root) {
        builder = builder.artifact(ArtifactEntry {
            path: expansion.artifact_path,
            category: ArtifactCategory::BenchmarkReport,
            content_type: Some("application/json".to_owned()),
            size_bytes: 0,
            sha256: None,
            redacted: false,
            metadata: BTreeMap::from([
                (
                    "profile_id".to_owned(),
                    expansion.profile_id.label().to_owned(),
                ),
                ("workload_id".to_owned(), expansion.workload_id),
                ("seed".to_owned(), expansion.seed.to_string()),
            ]),
        });
    }

    for evaluation in failure_evaluations {
        builder = builder.artifact(ArtifactEntry {
            path: format!(
                "{artifact_root}/{}/{}_threshold.json",
                evaluation.profile_id.label(),
                evaluation.workload_id
            ),
            category: ArtifactCategory::ProofArtifact,
            content_type: Some("application/json".to_owned()),
            size_bytes: 0,
            sha256: None,
            redacted: false,
            metadata: BTreeMap::from([
                ("workload_id".to_owned(), evaluation.workload_id.clone()),
                ("outcome".to_owned(), evaluation.outcome.label().to_owned()),
                (
                    "follow_up_bead".to_owned(),
                    evaluation.follow_up_bead.clone(),
                ),
            ]),
        });
    }

    for evaluation in &root_cause_samples {
        builder = builder.artifact(ArtifactEntry {
            path: format!(
                "{artifact_root}/{}/{}_{}_root_cause.json",
                evaluation.profile_id.label(),
                evaluation.workload_id,
                evaluation.classification.label()
            ),
            category: ArtifactCategory::ProofArtifact,
            content_type: Some("application/json".to_owned()),
            size_bytes: 0,
            sha256: None,
            redacted: false,
            metadata: BTreeMap::from([
                ("workload_id".to_owned(), evaluation.workload_id.clone()),
                (
                    "stop_reason".to_owned(),
                    evaluation.stop_reason.label().to_owned(),
                ),
                (
                    "classification".to_owned(),
                    evaluation.classification.label().to_owned(),
                ),
                (
                    "release_gate_impact".to_owned(),
                    evaluation.release_gate_impact.clone(),
                ),
            ]),
        });
    }

    builder.duration_secs(30.0).build()
}

#[must_use]
pub fn render_soak_canary_campaign_markdown(report: &SoakCanaryCampaignReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Soak/Canary Campaign Report");
    let _ = writeln!(out);
    let _ = writeln!(out, "- manifest: `{}`", report.manifest_id);
    let _ = writeln!(out, "- valid: `{}`", report.valid);
    let _ = writeln!(out, "- profiles: `{}`", report.profile_count);
    let _ = writeln!(out, "- workloads: `{}`", report.workload_count);
    let long_profiles = report
        .long_profile_ids
        .iter()
        .map(|profile| profile.label())
        .collect::<Vec<_>>()
        .join(", ");
    let _ = writeln!(out, "- long profiles: `{long_profiles}`");
    let _ = writeln!(
        out,
        "- consumers: `{}`",
        report.artifact_consumers.join(", ")
    );
    let precedence = report
        .stop_condition_precedence
        .iter()
        .map(|reason| reason.label())
        .collect::<Vec<_>>()
        .join(", ");
    let _ = writeln!(out, "- stop precedence: `{precedence}`");
    let _ = writeln!(out);
    let _ = writeln!(out, "## Heartbeats");
    for line in &report.heartbeat_summaries {
        let _ = writeln!(out, "- `{line}`");
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Threshold Samples");
    for evaluation in &report.failure_evaluations {
        let _ = writeln!(
            out,
            "- `{}` `{}` -> `{}` ({}) follow-up `{}`",
            evaluation.profile_id.label(),
            evaluation.workload_id,
            evaluation.outcome.label(),
            evaluation.threshold_summary,
            evaluation.follow_up_bead
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Root Cause Samples");
    for evaluation in &report.root_cause_samples {
        let _ = writeln!(
            out,
            "- `{}` `{}` -> `{}`/`{}` release-gate `{}`",
            evaluation.profile_id.label(),
            evaluation.workload_id,
            evaluation.stop_reason.label(),
            evaluation.classification.label(),
            evaluation.release_gate_impact
        );
    }
    out
}

pub fn fail_on_soak_canary_campaign_errors(report: &SoakCanaryCampaignReport) -> Result<()> {
    if report.valid {
        Ok(())
    } else {
        bail!(
            "soak/canary campaign manifest validation failed with {} error(s)",
            report.errors.len()
        )
    }
}

fn validate_manifest_shape(manifest: &SoakCanaryCampaignManifest, errors: &mut Vec<String>) {
    if manifest.schema_version != SOAK_CANARY_CAMPAIGN_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version {} expected {}",
            manifest.schema_version, SOAK_CANARY_CAMPAIGN_SCHEMA_VERSION
        ));
    }
    validate_nonempty("manifest_id", &manifest.manifest_id, errors);
    validate_nonempty(
        "artifact_root_template",
        &manifest.artifact_root_template,
        errors,
    );
    validate_classification_policy(&manifest.classification_policy, errors);
    validate_required_fields(
        "required_environment_fields",
        &manifest.required_environment_fields,
        &REQUIRED_ENVIRONMENT_FIELDS,
        errors,
    );
    validate_required_fields(
        "required_log_fields",
        &manifest.required_log_fields,
        &REQUIRED_LOG_FIELDS,
        errors,
    );
    validate_required_fields(
        "artifact_consumers",
        &manifest.artifact_consumers,
        &REQUIRED_ARTIFACT_CONSUMERS,
        errors,
    );
    if manifest.profiles.is_empty() {
        errors.push("profiles must not be empty".to_owned());
    }
    if manifest.workloads.is_empty() {
        errors.push("workloads must not be empty".to_owned());
    }

    let allowed = manifest
        .allowed_capabilities
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let profile_ids = validate_profiles(&manifest.profiles, &allowed, errors);
    validate_workloads(&manifest.workloads, &profile_ids, &allowed, errors);
}

fn validate_classification_policy(policy: &CampaignClassificationPolicy, errors: &mut Vec<String>) {
    if policy.stale_baseline_max_age_hours == 0 {
        errors
            .push("classification_policy stale_baseline_max_age_hours must be positive".to_owned());
    }

    let observed = policy
        .stop_condition_precedence
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    for reason in REQUIRED_STOP_PRECEDENCE {
        if !observed.contains(&reason) {
            errors.push(format!(
                "classification_policy stop_condition_precedence missing {}",
                reason.label()
            ));
        }
    }

    let mut quarantines = BTreeSet::new();
    for quarantine in &policy.known_flake_quarantines {
        validate_nonempty(
            "known_flake_quarantine.quarantine_id",
            &quarantine.quarantine_id,
            errors,
        );
        validate_nonempty(
            "known_flake_quarantine.workload_id",
            &quarantine.workload_id,
            errors,
        );
        validate_nonempty(
            "known_flake_quarantine.signature",
            &quarantine.signature,
            errors,
        );
        validate_nonempty("known_flake_quarantine.owner", &quarantine.owner, errors);
        validate_nonempty(
            "known_flake_quarantine.expires_at",
            &quarantine.expires_at,
            errors,
        );
        validate_nonempty(
            "known_flake_quarantine.user_risk_rationale",
            &quarantine.user_risk_rationale,
            errors,
        );
        validate_nonempty(
            "known_flake_quarantine.reproduction_pack",
            &quarantine.reproduction_pack,
            errors,
        );
        validate_nonempty(
            "known_flake_quarantine.release_gate_impact",
            &quarantine.release_gate_impact,
            errors,
        );
        if !quarantines.insert(quarantine.quarantine_id.as_str()) {
            errors.push(format!(
                "duplicate known_flake_quarantine {}",
                quarantine.quarantine_id
            ));
        }
    }
}

fn validate_profiles(
    profiles: &[CampaignProfile],
    allowed_capabilities: &BTreeSet<&str>,
    errors: &mut Vec<String>,
) -> BTreeSet<CampaignProfileId> {
    let mut seen = BTreeSet::new();
    for profile in profiles {
        if !seen.insert(profile.profile_id) {
            errors.push(format!(
                "duplicate profile_id {}",
                profile.profile_id.label()
            ));
        }
        validate_nonempty("profile.description", &profile.description, errors);
        if profile.duration_seconds == 0 {
            errors.push(format!(
                "profile {} duration_seconds must be positive",
                profile.profile_id.label()
            ));
        }
        if profile.max_iterations == 0 {
            errors.push(format!(
                "profile {} max_iterations must be positive",
                profile.profile_id.label()
            ));
        }
        if profile.heartbeat_interval_seconds == 0
            || profile.heartbeat_interval_seconds > profile.duration_seconds
        {
            errors.push(format!(
                "profile {} heartbeat_interval_seconds must be in 1..=duration_seconds",
                profile.profile_id.label()
            ));
        }
        validate_capabilities(
            &format!("profile {}", profile.profile_id.label()),
            &profile.required_capabilities,
            allowed_capabilities,
            errors,
        );
        validate_resource_limits(profile, errors);
        validate_long_run_context(profile, errors);
    }

    for required in [
        CampaignProfileId::Smoke,
        CampaignProfileId::Nightly,
        CampaignProfileId::Stress,
        CampaignProfileId::Canary,
    ] {
        if !seen.contains(&required) {
            errors.push(format!("missing required profile {}", required.label()));
        }
    }

    seen
}

fn validate_resource_limits(profile: &CampaignProfile, errors: &mut Vec<String>) {
    let limits = &profile.resource_limits;
    if limits.max_wall_seconds < profile.duration_seconds {
        errors.push(format!(
            "profile {} max_wall_seconds must cover duration_seconds",
            profile.profile_id.label()
        ));
    }
    if limits.max_memory_mib == 0 || limits.max_artifact_mib == 0 || limits.max_cpu_percent == 0 {
        errors.push(format!(
            "profile {} resource limits must be positive",
            profile.profile_id.label()
        ));
    }
}

fn validate_long_run_context(profile: &CampaignProfile, errors: &mut Vec<String>) {
    if profile.profile_id.is_long_running() {
        let Some(context) = &profile.long_run_context else {
            errors.push(format!(
                "profile {} must document long_run_context",
                profile.profile_id.label()
            ));
            return;
        };
        validate_required_fields(
            &format!(
                "profile {} long_run_context.records_environment_fields",
                profile.profile_id.label()
            ),
            &context.records_environment_fields,
            &REQUIRED_LONG_RUN_RECORD_FIELDS,
            errors,
        );
        for host in ["rch", "ci", "manual_permissioned"] {
            if !context.intended_hosts.iter().any(|value| value == host) {
                errors.push(format!(
                    "profile {} long_run_context missing intended host {host}",
                    profile.profile_id.label()
                ));
            }
        }
        validate_nonempty(
            &format!(
                "profile {} long_run_context.operator_notes",
                profile.profile_id.label()
            ),
            &context.operator_notes,
            errors,
        );
    }
}

fn validate_workloads(
    workloads: &[CampaignWorkload],
    profile_ids: &BTreeSet<CampaignProfileId>,
    allowed_capabilities: &BTreeSet<&str>,
    errors: &mut Vec<String>,
) {
    let mut workload_ids = BTreeMap::<&str, usize>::new();
    for workload in workloads {
        validate_workload(workload, profile_ids, allowed_capabilities, errors);
        *workload_ids
            .entry(workload.workload_id.as_str())
            .or_default() += 1;
    }
    for (workload_id, count) in workload_ids {
        if count > 1 {
            errors.push(format!("duplicate workload_id {workload_id}"));
        }
    }
}

fn validate_workload(
    workload: &CampaignWorkload,
    profile_ids: &BTreeSet<CampaignProfileId>,
    allowed_capabilities: &BTreeSet<&str>,
    errors: &mut Vec<String>,
) {
    validate_nonempty("workload_id", &workload.workload_id, errors);
    validate_nonempty("workload.description", &workload.description, errors);
    validate_nonempty(
        "workload.expected_safe_behavior",
        &workload.expected_safe_behavior,
        errors,
    );
    if workload.profile_ids.is_empty() {
        errors.push(format!(
            "workload {} must declare profile_ids",
            workload.workload_id
        ));
    }
    for profile_id in &workload.profile_ids {
        if !profile_ids.contains(profile_id) {
            errors.push(format!(
                "workload {} references unknown profile {}",
                workload.workload_id,
                profile_id.label()
            ));
        }
    }
    validate_capabilities(
        &format!("workload {}", workload.workload_id),
        &workload.required_capabilities,
        allowed_capabilities,
        errors,
    );
    if workload.seeds.is_empty() {
        errors.push(format!(
            "workload {} must declare seeds",
            workload.workload_id
        ));
    }
    validate_command_template(workload, errors);
    validate_failure_threshold(workload, errors);
    validate_output_artifact(workload, errors);
}

fn validate_command_template(workload: &CampaignWorkload, errors: &mut Vec<String>) {
    for token in ["{profile}", "{artifact_dir}", "{workload_id}", "{seed}"] {
        if !workload.command_template.contains(token) {
            errors.push(format!(
                "workload {} command_template must include {token}",
                workload.workload_id
            ));
        }
    }
}

fn validate_failure_threshold(workload: &CampaignWorkload, errors: &mut Vec<String>) {
    let threshold = &workload.failure_threshold;
    if threshold.flake_window_iterations == 0 {
        errors.push(format!(
            "workload {} flake_window_iterations must be positive",
            workload.workload_id
        ));
    }
    if threshold.max_flakes > 0 && threshold.follow_up_bead.trim().is_empty() {
        errors.push(format!(
            "workload {} permits flakes but has no follow_up_bead",
            workload.workload_id
        ));
    }
    if !threshold.preserve_repro_artifacts {
        errors.push(format!(
            "workload {} must preserve repro artifacts for flakes/failures",
            workload.workload_id
        ));
    }
}

fn validate_output_artifact(workload: &CampaignWorkload, errors: &mut Vec<String>) {
    let artifact = &workload.output_artifact;
    validate_nonempty(
        "output_artifact.path_template",
        &artifact.path_template,
        errors,
    );
    validate_nonempty(
        "output_artifact.content_type",
        &artifact.content_type,
        errors,
    );
    validate_nonempty(
        "output_artifact.aggregate_key",
        &artifact.aggregate_key,
        errors,
    );
    for token in ["{profile}", "{workload_id}"] {
        if !artifact.path_template.contains(token) {
            errors.push(format!(
                "workload {} output_artifact.path_template must include {token}",
                workload.workload_id
            ));
        }
    }
    if !artifact.aggregate_key.contains("campaigns[]") {
        errors.push(format!(
            "workload {} aggregate_key must identify campaigns[]",
            workload.workload_id
        ));
    }
    if !matches!(
        artifact.category,
        ArtifactCategory::BenchmarkReport
            | ArtifactCategory::E2eLog
            | ArtifactCategory::ProofArtifact
            | ArtifactCategory::SummaryReport
            | ArtifactCategory::ReproPack
    ) {
        errors.push(format!(
            "workload {} artifact category is not valid for campaign output",
            workload.workload_id
        ));
    }
}

fn validate_capabilities(
    owner: &str,
    capabilities: &[String],
    allowed_capabilities: &BTreeSet<&str>,
    errors: &mut Vec<String>,
) {
    if capabilities.is_empty() {
        errors.push(format!("{owner} must declare required_capabilities"));
    }
    for capability in capabilities {
        if !allowed_capabilities.contains(capability.as_str()) {
            errors.push(format!(
                "{owner} references unknown capability {capability}"
            ));
        }
    }
}

fn validate_required_fields(
    field_name: &str,
    observed: &[String],
    required: &[&str],
    errors: &mut Vec<String>,
) {
    let observed = observed.iter().map(String::as_str).collect::<BTreeSet<_>>();
    for field in required {
        if !observed.contains(field) {
            errors.push(format!("{field_name} missing {field}"));
        }
    }
}

fn validate_nonempty(field: &str, value: &str, errors: &mut Vec<String>) {
    if value.trim().is_empty() {
        errors.push(format!("{field} must not be empty"));
    }
}

fn expand_template(
    template: &str,
    profile_id: CampaignProfileId,
    workload: &CampaignWorkload,
    seed: u64,
    artifact_root: &str,
) -> String {
    let seed_placeholder = concat!("{", "seed", "}");
    template
        .replace("{profile}", profile_id.label())
        .replace("{artifact_dir}", artifact_root)
        .replace("{workload_id}", &workload.workload_id)
        .replace(seed_placeholder, &seed.to_string())
}

fn sample_failure_evaluations(
    manifest: &SoakCanaryCampaignManifest,
) -> Vec<CampaignFailureEvaluation> {
    let mut evaluations = Vec::new();
    let Some(smoke) = manifest
        .profiles
        .iter()
        .find(|profile| profile.profile_id == CampaignProfileId::Smoke)
    else {
        return evaluations;
    };
    let Some(first) = manifest.workloads.first() else {
        return evaluations;
    };
    evaluations.push(evaluate_failure_threshold(
        smoke,
        first,
        CampaignObservationStats {
            passes: 3,
            ..CampaignObservationStats::default()
        },
    ));
    evaluations.push(evaluate_failure_threshold(
        smoke,
        first,
        CampaignObservationStats {
            failures: smoke.max_failures.saturating_add(1),
            ..CampaignObservationStats::default()
        },
    ));
    evaluations.push(evaluate_failure_threshold(
        smoke,
        first,
        CampaignObservationStats {
            errors: smoke.max_errors.saturating_add(1),
            ..CampaignObservationStats::default()
        },
    ));
    evaluations.push(evaluate_failure_threshold(
        smoke,
        first,
        CampaignObservationStats {
            flakes: smoke.max_flakes.saturating_add(1),
            ..CampaignObservationStats::default()
        },
    ));
    evaluations.push(evaluate_failure_threshold(
        smoke,
        first,
        CampaignObservationStats {
            skips: 1,
            ..CampaignObservationStats::default()
        },
    ));
    evaluations
}

fn sample_heartbeat_summaries(manifest: &SoakCanaryCampaignManifest) -> Vec<String> {
    let Some(smoke) = manifest
        .profiles
        .iter()
        .find(|profile| profile.profile_id == CampaignProfileId::Smoke)
    else {
        return Vec::new();
    };
    let active_workloads = manifest
        .workloads
        .iter()
        .take(3)
        .map(|workload| workload.workload_id.clone())
        .collect::<Vec<_>>();
    vec![render_heartbeat_summary(&CampaignHeartbeat {
        campaign_id: "dry-run-soak-canary".to_owned(),
        profile_id: smoke.profile_id,
        heartbeat_index: 1,
        elapsed_seconds: smoke.heartbeat_interval_seconds,
        iteration: 1,
        active_workloads,
        stats: CampaignObservationStats {
            passes: 2,
            skips: 1,
            ..CampaignObservationStats::default()
        },
        resource_usage: CampaignResourceUsage {
            cpu_percent: 15,
            memory_mib: 128,
            artifact_mib: 4,
        },
    })]
}

fn sample_root_cause_evaluations(
    manifest: &SoakCanaryCampaignManifest,
) -> Vec<CampaignStopEvaluation> {
    let Some(profile) = manifest
        .profiles
        .iter()
        .find(|profile| profile.profile_id == CampaignProfileId::Smoke)
    else {
        return Vec::new();
    };
    let Some(workload) = manifest.workloads.first() else {
        return Vec::new();
    };

    let base_usage = CampaignResourceUsage {
        cpu_percent: 10,
        memory_mib: 128,
        artifact_mib: 4,
    };
    let cases = [
        CampaignRunObservation {
            stats: CampaignObservationStats {
                passes: 1,
                ..CampaignObservationStats::default()
            },
            elapsed_seconds: profile.duration_seconds,
            baseline_age_hours: 0,
            host_capability_missing: false,
            infrastructure_error: false,
            timeout: false,
            recurring_flake_signature: None,
            resource_usage: base_usage,
        },
        CampaignRunObservation {
            stats: CampaignObservationStats {
                failures: profile.max_failures.saturating_add(1),
                ..CampaignObservationStats::default()
            },
            elapsed_seconds: profile.duration_seconds,
            baseline_age_hours: 0,
            host_capability_missing: false,
            infrastructure_error: false,
            timeout: false,
            recurring_flake_signature: None,
            resource_usage: base_usage,
        },
        CampaignRunObservation {
            stats: CampaignObservationStats {
                skips: 1,
                ..CampaignObservationStats::default()
            },
            elapsed_seconds: profile.duration_seconds,
            baseline_age_hours: 0,
            host_capability_missing: true,
            infrastructure_error: false,
            timeout: false,
            recurring_flake_signature: None,
            resource_usage: base_usage,
        },
        CampaignRunObservation {
            stats: CampaignObservationStats::default(),
            elapsed_seconds: profile.duration_seconds,
            baseline_age_hours: 0,
            host_capability_missing: false,
            infrastructure_error: true,
            timeout: false,
            recurring_flake_signature: None,
            resource_usage: base_usage,
        },
        CampaignRunObservation {
            stats: CampaignObservationStats::default(),
            elapsed_seconds: profile.resource_limits.max_wall_seconds.saturating_add(1),
            baseline_age_hours: 0,
            host_capability_missing: false,
            infrastructure_error: false,
            timeout: true,
            recurring_flake_signature: None,
            resource_usage: base_usage,
        },
        CampaignRunObservation {
            stats: CampaignObservationStats::default(),
            elapsed_seconds: profile.duration_seconds,
            baseline_age_hours: 0,
            host_capability_missing: false,
            infrastructure_error: false,
            timeout: false,
            recurring_flake_signature: None,
            resource_usage: CampaignResourceUsage {
                cpu_percent: profile.resource_limits.max_cpu_percent.saturating_add(1),
                memory_mib: base_usage.memory_mib,
                artifact_mib: base_usage.artifact_mib,
            },
        },
        CampaignRunObservation {
            stats: CampaignObservationStats {
                flakes: profile.max_flakes.saturating_add(1),
                ..CampaignObservationStats::default()
            },
            elapsed_seconds: profile.duration_seconds,
            baseline_age_hours: 0,
            host_capability_missing: false,
            infrastructure_error: false,
            timeout: false,
            recurring_flake_signature: Some("known_fuse_mount_retry_jitter".to_owned()),
            resource_usage: base_usage,
        },
        CampaignRunObservation {
            stats: CampaignObservationStats {
                flakes: profile.max_flakes.saturating_add(1),
                ..CampaignObservationStats::default()
            },
            elapsed_seconds: profile.duration_seconds,
            baseline_age_hours: 0,
            host_capability_missing: false,
            infrastructure_error: false,
            timeout: false,
            recurring_flake_signature: Some("new_unclassified_flake".to_owned()),
            resource_usage: base_usage,
        },
        CampaignRunObservation {
            stats: CampaignObservationStats::default(),
            elapsed_seconds: profile.duration_seconds,
            baseline_age_hours: manifest
                .classification_policy
                .stale_baseline_max_age_hours
                .saturating_add(1),
            host_capability_missing: false,
            infrastructure_error: false,
            timeout: false,
            recurring_flake_signature: None,
            resource_usage: base_usage,
        },
    ];

    cases
        .iter()
        .map(|observation| {
            evaluate_stop_condition(
                &manifest.classification_policy,
                profile,
                workload,
                observation,
            )
        })
        .collect()
}

fn sample_outcome_counts() -> BTreeMap<String, usize> {
    BTreeMap::from([
        (CampaignOutcomeClass::Pass.label().to_owned(), 1),
        (CampaignOutcomeClass::Fail.label().to_owned(), 1),
        (CampaignOutcomeClass::Skip.label().to_owned(), 1),
        (CampaignOutcomeClass::Error.label().to_owned(), 1),
        (CampaignOutcomeClass::Flake.label().to_owned(), 1),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_manifest() -> SoakCanaryCampaignManifest {
        serde_json::from_str(include_str!(
            "../../../benchmarks/soak_canary_campaign_manifest.json"
        ))
        .expect("checked-in soak/canary manifest parses")
    }

    #[test]
    fn checked_in_manifest_validates_and_expands_commands() {
        let manifest = sample_manifest();
        let report = validate_soak_canary_campaign_manifest(&manifest, "artifacts/soak/dry-run");
        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.profile_count, 4);
        assert!(report.workload_count >= 7);
        assert_eq!(report.sample_artifact_manifest_errors, Vec::<String>::new());
        assert_eq!(
            report.stop_condition_precedence.len(),
            REQUIRED_STOP_PRECEDENCE.len()
        );
        let root_classes = report
            .root_cause_samples
            .iter()
            .map(|row| row.classification)
            .collect::<BTreeSet<_>>();
        for required in [
            CampaignRootCauseClass::ProductRegression,
            CampaignRootCauseClass::HostCapabilitySkip,
            CampaignRootCauseClass::InfrastructureError,
            CampaignRootCauseClass::Timeout,
            CampaignRootCauseClass::ResourceExhaustion,
            CampaignRootCauseClass::KnownQuarantinedFlake,
            CampaignRootCauseClass::NewRecurringFlake,
            CampaignRootCauseClass::Inconclusive,
        ] {
            assert!(root_classes.contains(&required), "{root_classes:?}");
        }
        assert!(report.command_expansions.iter().any(|row| row.profile_id
            == CampaignProfileId::Smoke
            && (row.command.contains("--profile smoke")
                || row.command.contains("--campaign-profile smoke"))
            && row.command.contains("artifacts/soak/dry-run")));
    }

    #[test]
    fn profile_parser_rejects_unknown_profiles() {
        assert_eq!(
            CampaignProfileId::parse("nightly").expect("known profile parses"),
            CampaignProfileId::Nightly
        );
        assert!(CampaignProfileId::parse("forever").is_err());
    }

    #[test]
    fn rejects_zero_profile_duration() {
        let mut manifest = sample_manifest();
        manifest.profiles[0].duration_seconds = 0;
        let report = validate_soak_canary_campaign_manifest(&manifest, "artifacts/soak");
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("duration_seconds must be positive"))
        );
    }

    #[test]
    fn rejects_missing_required_log_field() {
        let mut manifest = sample_manifest();
        manifest
            .required_log_fields
            .retain(|field| field != "reproduction_command");
        let report = validate_soak_canary_campaign_manifest(&manifest, "artifacts/soak");
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("required_log_fields missing reproduction_command"))
        );
    }

    #[test]
    fn rejects_unknown_capability_reference() {
        let mut manifest = sample_manifest();
        manifest.workloads[0]
            .required_capabilities
            .push("ambient_mutation".to_owned());
        let report = validate_soak_canary_campaign_manifest(&manifest, "artifacts/soak");
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("unknown capability ambient_mutation"))
        );
    }

    #[test]
    fn rejects_flakes_without_follow_up_and_repro_pack() {
        let mut manifest = sample_manifest();
        manifest.workloads[0].failure_threshold.max_flakes = 1;
        manifest.workloads[0]
            .failure_threshold
            .follow_up_bead
            .clear();
        manifest.workloads[0]
            .failure_threshold
            .preserve_repro_artifacts = false;
        let report = validate_soak_canary_campaign_manifest(&manifest, "artifacts/soak");
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("permits flakes but has no follow_up_bead"))
        );
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("must preserve repro artifacts"))
        );
    }

    #[test]
    fn threshold_evaluation_classifies_pass_fail_skip_error_and_flake() {
        let manifest = sample_manifest();
        let profile = &manifest.profiles[0];
        let workload = &manifest.workloads[0];
        let cases = [
            (
                CampaignObservationStats {
                    passes: 1,
                    ..CampaignObservationStats::default()
                },
                CampaignOutcomeClass::Pass,
            ),
            (
                CampaignObservationStats {
                    failures: profile.max_failures + 1,
                    ..CampaignObservationStats::default()
                },
                CampaignOutcomeClass::Fail,
            ),
            (
                CampaignObservationStats {
                    skips: 1,
                    ..CampaignObservationStats::default()
                },
                CampaignOutcomeClass::Skip,
            ),
            (
                CampaignObservationStats {
                    errors: profile.max_errors + 1,
                    ..CampaignObservationStats::default()
                },
                CampaignOutcomeClass::Error,
            ),
            (
                CampaignObservationStats {
                    flakes: profile.max_flakes + 1,
                    ..CampaignObservationStats::default()
                },
                CampaignOutcomeClass::Flake,
            ),
        ];
        for (stats, expected) in cases {
            let evaluation = evaluate_failure_threshold(profile, workload, stats);
            assert_eq!(evaluation.outcome, expected);
            assert!(evaluation.repro_artifacts_required);
            assert_eq!(evaluation.follow_up_bead, "bd-t21em");
        }
    }

    #[test]
    fn stop_condition_precedence_classifies_resource_budget_first() {
        let manifest = sample_manifest();
        let profile = &manifest.profiles[0];
        let workload = &manifest.workloads[0];
        let evaluation = evaluate_stop_condition(
            &manifest.classification_policy,
            profile,
            workload,
            &CampaignRunObservation {
                stats: CampaignObservationStats {
                    failures: profile.max_failures + 1,
                    ..CampaignObservationStats::default()
                },
                elapsed_seconds: profile.duration_seconds,
                baseline_age_hours: 0,
                host_capability_missing: false,
                infrastructure_error: false,
                timeout: false,
                recurring_flake_signature: None,
                resource_usage: CampaignResourceUsage {
                    cpu_percent: profile.resource_limits.max_cpu_percent + 1,
                    memory_mib: 1,
                    artifact_mib: 1,
                },
            },
        );

        assert_eq!(
            evaluation.stop_reason,
            CampaignStopReason::ResourceBudgetExceeded
        );
        assert_eq!(
            evaluation.classification,
            CampaignRootCauseClass::ResourceExhaustion
        );
        assert_eq!(evaluation.release_gate_impact, "block_release_gate");
    }

    #[test]
    fn classifies_stale_baseline_and_known_vs_new_flakes() {
        let manifest = sample_manifest();
        let profile = &manifest.profiles[0];
        let workload = &manifest.workloads[0];
        let resource_usage = CampaignResourceUsage {
            cpu_percent: 1,
            memory_mib: 1,
            artifact_mib: 1,
        };

        let stale = evaluate_stop_condition(
            &manifest.classification_policy,
            profile,
            workload,
            &CampaignRunObservation {
                stats: CampaignObservationStats::default(),
                elapsed_seconds: profile.duration_seconds,
                baseline_age_hours: manifest.classification_policy.stale_baseline_max_age_hours + 1,
                host_capability_missing: false,
                infrastructure_error: false,
                timeout: false,
                recurring_flake_signature: None,
                resource_usage,
            },
        );
        assert_eq!(stale.stop_reason, CampaignStopReason::StaleBaseline);
        assert_eq!(stale.classification, CampaignRootCauseClass::Inconclusive);

        let known = evaluate_stop_condition(
            &manifest.classification_policy,
            profile,
            workload,
            &CampaignRunObservation {
                stats: CampaignObservationStats {
                    flakes: profile.max_flakes + 1,
                    ..CampaignObservationStats::default()
                },
                elapsed_seconds: profile.duration_seconds,
                baseline_age_hours: 0,
                host_capability_missing: false,
                infrastructure_error: false,
                timeout: false,
                recurring_flake_signature: Some("known_fuse_mount_retry_jitter".to_owned()),
                resource_usage,
            },
        );
        assert_eq!(
            known.classification,
            CampaignRootCauseClass::KnownQuarantinedFlake
        );
        assert_eq!(
            known.quarantine_id.as_deref(),
            Some("soak_known_fuse_mount_retry_jitter")
        );

        let new_flake = evaluate_stop_condition(
            &manifest.classification_policy,
            profile,
            workload,
            &CampaignRunObservation {
                stats: CampaignObservationStats {
                    flakes: profile.max_flakes + 1,
                    ..CampaignObservationStats::default()
                },
                elapsed_seconds: profile.duration_seconds,
                baseline_age_hours: 0,
                host_capability_missing: false,
                infrastructure_error: false,
                timeout: false,
                recurring_flake_signature: Some("unclassified".to_owned()),
                resource_usage,
            },
        );
        assert_eq!(
            new_flake.classification,
            CampaignRootCauseClass::NewRecurringFlake
        );
        assert_eq!(new_flake.release_gate_impact, "block_release_gate");
    }

    #[test]
    fn rejects_incomplete_classification_policy() {
        let mut manifest = sample_manifest();
        manifest.classification_policy.stale_baseline_max_age_hours = 0;
        manifest
            .classification_policy
            .stop_condition_precedence
            .retain(|reason| *reason != CampaignStopReason::Timeout);
        manifest.classification_policy.known_flake_quarantines[0]
            .reproduction_pack
            .clear();

        let report = validate_soak_canary_campaign_manifest(&manifest, "artifacts/soak");
        assert!(!report.valid);
        assert!(
            report.errors.iter().any(|error| {
                error.contains("classification_policy stale_baseline_max_age_hours")
            })
        );
        assert!(
            report
                .errors
                .iter()
                .any(|error| { error.contains("stop_condition_precedence missing timeout") })
        );
        assert!(
            report
                .errors
                .iter()
                .any(|error| { error.contains("known_flake_quarantine.reproduction_pack") })
        );
    }

    #[test]
    fn heartbeat_summary_contains_required_log_vocabulary() {
        let heartbeat = CampaignHeartbeat {
            campaign_id: "campaign-1".to_owned(),
            profile_id: CampaignProfileId::Canary,
            heartbeat_index: 7,
            elapsed_seconds: 120,
            iteration: 12,
            active_workloads: vec!["soak_mount_cycle_ext4_ro".to_owned()],
            stats: CampaignObservationStats {
                passes: 10,
                skips: 1,
                flakes: 1,
                ..CampaignObservationStats::default()
            },
            resource_usage: CampaignResourceUsage {
                cpu_percent: 44,
                memory_mib: 512,
                artifact_mib: 8,
            },
        };
        let summary = render_heartbeat_summary(&heartbeat);
        for needle in [
            "campaign_id=campaign-1",
            "profile_id=canary",
            "heartbeat_index=7",
            "pass=10",
            "skip=1",
            "flake=1",
            "cpu_percent=44",
        ] {
            assert!(summary.contains(needle), "{summary}");
        }
    }

    #[test]
    fn long_profiles_document_rch_ci_and_manual_hosts() {
        let manifest = sample_manifest();
        for profile in manifest
            .profiles
            .iter()
            .filter(|profile| profile.profile_id.is_long_running())
        {
            let context = profile
                .long_run_context
                .as_ref()
                .expect("long profile has context");
            for host in ["rch", "ci", "manual_permissioned"] {
                assert!(context.intended_hosts.iter().any(|value| value == host));
            }
            for field in REQUIRED_LONG_RUN_RECORD_FIELDS {
                assert!(
                    context
                        .records_environment_fields
                        .iter()
                        .any(|value| value == field),
                    "{field}"
                );
            }
        }
    }

    #[test]
    fn report_markdown_preserves_consumers_and_follow_up() {
        let manifest = sample_manifest();
        let report = validate_soak_canary_campaign_manifest(&manifest, "artifacts/soak");
        let markdown = render_soak_canary_campaign_markdown(&report);
        assert!(markdown.contains("operator_proof_bundle"));
        assert!(markdown.contains("release_gate_evaluator"));
        assert!(markdown.contains("bd-t21em"));
        assert!(markdown.contains("HEARTBEAT|"));
    }

    #[test]
    fn render_soak_canary_campaign_markdown_checked_in_manifest_snapshot() {
        let manifest = sample_manifest();
        let report = validate_soak_canary_campaign_manifest(&manifest, "artifacts/soak");
        assert!(report.valid, "{:?}", report.errors);
        assert!(
            report
                .artifact_consumers
                .contains(&"release_gate_evaluator".to_owned())
        );
        assert!(
            report
                .failure_evaluations
                .iter()
                .any(|evaluation| evaluation.follow_up_bead == "bd-t21em")
        );

        let markdown = render_soak_canary_campaign_markdown(&report);
        insta::assert_snapshot!(
            "render_soak_canary_campaign_markdown_checked_in_manifest",
            markdown
        );
    }

    #[test]
    fn sample_artifact_manifest_exposes_proof_bundle_and_release_gate_metadata() {
        let manifest = sample_manifest();
        let evaluations = sample_failure_evaluations(&manifest);
        let artifact =
            build_soak_canary_sample_artifact_manifest(&manifest, "artifacts/soak", &evaluations);
        assert_eq!(validate_manifest(&artifact), Vec::new());
        assert_eq!(artifact.gate_id, "soak_canary_campaigns");
        assert_eq!(artifact.bead_id.as_deref(), Some("bd-rchk0.5.9"));
        assert!(artifact.artifacts.iter().any(|entry| {
            entry
                .metadata
                .get("proof_bundle_lane")
                .is_some_and(|value| value == "soak_canary_campaigns")
        }));
        assert!(artifact.artifacts.iter().any(|entry| {
            entry
                .metadata
                .get("release_gate_feature")
                .is_some_and(|value| value == "operational.soak_canary")
        }));
        assert!(artifact.artifacts.iter().any(|entry| {
            entry
                .metadata
                .get("classification")
                .is_some_and(|value| value == "resource_exhaustion")
        }));
    }

    #[test]
    fn serde_rejects_unknown_profile_literal() {
        let bad = json!({
            "schema_version": 1,
            "manifest_id": "bad",
            "shared_qa_schema_version": 1,
            "artifact_root_template": "artifacts/soak/{profile}",
            "allowed_capabilities": ["cargo"],
            "artifact_consumers": ["operator_proof_bundle", "release_gate_evaluator", "operational_readiness_report"],
            "required_environment_fields": REQUIRED_ENVIRONMENT_FIELDS,
            "required_log_fields": REQUIRED_LOG_FIELDS,
            "profiles": [{
                "profile_id": "forever",
                "description": "bad",
                "duration_seconds": 1,
                "max_iterations": 1,
                "heartbeat_interval_seconds": 1,
                "max_failures": 0,
                "max_errors": 0,
                "max_flakes": 0,
                "required_capabilities": ["cargo"],
                "resource_limits": {
                    "max_wall_seconds": 1,
                    "max_memory_mib": 1,
                    "max_artifact_mib": 1,
                    "max_cpu_percent": 1
                },
                "artifact_retention_days": 1
            }],
            "workloads": []
        });
        assert!(serde_json::from_value::<SoakCanaryCampaignManifest>(bad).is_err());
    }
}
