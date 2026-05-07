#![forbid(unsafe_code)]

//! Adaptive mount runtime evidence manifest contract.
//!
//! This module defines the schema and validation rules for evidence that may
//! later allow `ffs-cli` to wire optional `BackpressureGate` controls into
//! managed or per-core mounts. Local smoke and capability-downgraded evidence
//! can be structurally valid, but it must not be treated as an accepted runtime
//! control grant.

use crate::artifact_manifest::parse_manifest_timestamp_epoch_days;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::fs;
use std::path::{Component, Path};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_ADAPTIVE_RUNTIME_EVIDENCE_MANIFEST: &str =
    "docs/adaptive-runtime-evidence-manifest.json";
pub const ADAPTIVE_RUNTIME_EVIDENCE_MANIFEST_VERSION: u32 = 1;
pub const ADAPTIVE_RUNTIME_MIN_CPU_COUNT: u32 = 64;
pub const ADAPTIVE_RUNTIME_MIN_RAM_BYTES: u64 = 256 * 1024 * 1024 * 1024;
pub const ADAPTIVE_RUNTIME_MIN_NUMA_NODES: u32 = 2;
pub const ADAPTIVE_RUNTIME_RUNNER_CONTRACT_VERSION: u32 = 1;
pub const DEFAULT_ADAPTIVE_RUNTIME_RUNNER_ARTIFACT_ROOT: &str =
    "artifacts/adaptive-runtime/dry-run";
pub const DEFAULT_ADAPTIVE_RUNTIME_REAL_RUN_ACK_ENV: &str = "FFS_ADAPTIVE_RUNTIME_REAL_RUN_ACK";
pub const DEFAULT_ADAPTIVE_RUNTIME_REAL_RUN_ACK_VALUE: &str =
    "adaptive-runtime-may-mount-and-generate-load";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdaptiveRuntimeEvidenceManifest {
    pub manifest_version: u32,
    pub scenario_id: String,
    pub run_id: String,
    pub runtime_mode: AdaptiveRuntimeMode,
    pub read_write: bool,
    pub host_fingerprint: AdaptiveRuntimeHostFingerprint,
    pub fuse_capability_summary: AdaptiveRuntimeFuseCapabilitySummary,
    pub backpressure_policy_id: String,
    pub degradation_thresholds: AdaptiveRuntimeDegradationThresholds,
    pub per_core_config: AdaptiveRuntimePerCoreConfig,
    pub resource_caps: AdaptiveRuntimeResourceCaps,
    pub artifact_paths: Vec<String>,
    pub raw_stdout_path: String,
    pub raw_stderr_path: String,
    pub raw_log_paths: Vec<String>,
    pub cleanup_status: AdaptiveRuntimeCleanupStatus,
    pub controlling_ack_env: String,
    pub controlling_ack_value: String,
    pub release_claim_state: AdaptiveRuntimeReleaseClaimState,
    pub generated_at: String,
    pub expires_at: String,
    pub git_sha: String,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdaptiveRuntimeMode {
    Standard,
    Managed,
    PerCore,
}

impl AdaptiveRuntimeMode {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Managed => "managed",
            Self::PerCore => "per_core",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveRuntimeHostFingerprint {
    pub host_fingerprint: String,
    pub cpu_count: u32,
    pub ram_bytes: u64,
    pub numa_nodes: u32,
    pub kernel: String,
    pub lane: AdaptiveRuntimeHostLane,
}

impl AdaptiveRuntimeHostFingerprint {
    #[must_use]
    pub fn meets_large_host_floor(&self) -> bool {
        self.cpu_count >= ADAPTIVE_RUNTIME_MIN_CPU_COUNT
            && self.ram_bytes >= ADAPTIVE_RUNTIME_MIN_RAM_BYTES
            && self.numa_nodes >= ADAPTIVE_RUNTIME_MIN_NUMA_NODES
            && matches!(self.lane, AdaptiveRuntimeHostLane::PermissionedLargeHost)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdaptiveRuntimeHostLane {
    LocalSmoke,
    CapabilityDowngraded,
    PermissionedLargeHost,
}

impl AdaptiveRuntimeHostLane {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::LocalSmoke => "local_smoke",
            Self::CapabilityDowngraded => "capability_downgraded",
            Self::PermissionedLargeHost => "permissioned_large_host",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveRuntimeFuseCapabilitySummary {
    pub state: AdaptiveRuntimeFuseCapabilityState,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdaptiveRuntimeFuseCapabilityState {
    Available,
    Missing,
    PermissionDenied,
    DisabledByUser,
    Unknown,
}

impl AdaptiveRuntimeFuseCapabilityState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Missing => "missing",
            Self::PermissionDenied => "permission_denied",
            Self::DisabledByUser => "disabled_by_user",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdaptiveRuntimeDegradationThresholds {
    pub throttle_dirty_ratio: f64,
    pub shed_dirty_ratio: f64,
    pub emergency_dirty_ratio: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveRuntimePerCoreConfig {
    pub enabled: bool,
    pub worker_count: u32,
    pub queue_policy: String,
    pub work_stealing: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveRuntimeResourceCaps {
    pub max_duration_secs: u64,
    pub max_threads: u32,
    pub max_memory_bytes: u64,
    pub max_temp_bytes: u64,
    pub max_queue_depth: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdaptiveRuntimeCleanupStatus {
    Clean,
    PreservedArtifacts,
    Failed,
    Unknown,
}

impl AdaptiveRuntimeCleanupStatus {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::PreservedArtifacts => "preserved_artifacts",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdaptiveRuntimeReleaseClaimState {
    SmallHostSmoke,
    CapabilityDowngradedSmoke,
    AcceptedLargeHost,
}

impl AdaptiveRuntimeReleaseClaimState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SmallHostSmoke => "small_host_smoke",
            Self::CapabilityDowngradedSmoke => "capability_downgraded_smoke",
            Self::AcceptedLargeHost => "accepted_large_host",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveRuntimeEvidenceValidationConfig {
    pub reference_epoch_days: Option<u32>,
    pub current_git_sha: Option<String>,
}

impl AdaptiveRuntimeEvidenceValidationConfig {
    #[must_use]
    pub fn with_current_reference() -> Self {
        Self {
            reference_epoch_days: current_epoch_days(),
            current_git_sha: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveRuntimeEvidenceIssue {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveRuntimeEvidenceReport {
    pub manifest_version: u32,
    pub scenario_id: String,
    pub run_id: String,
    pub valid: bool,
    pub runtime_controls_accepted: bool,
    pub release_claim_state: String,
    pub runtime_mode: String,
    pub host_lane: String,
    pub host_classification: String,
    pub fuse_capability_state: String,
    pub artifact_count: usize,
    pub raw_log_count: usize,
    pub issues: Vec<AdaptiveRuntimeEvidenceIssue>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdaptiveRuntimeRunnerMode {
    DryRun,
    CapabilityProbe,
    PermissionedReal,
}

impl AdaptiveRuntimeRunnerMode {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DryRun => "dry_run",
            Self::CapabilityProbe => "capability_probe",
            Self::PermissionedReal => "permissioned_real",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdaptiveRuntimeRunnerClassification {
    SmallHostSmoke,
    CapabilityDowngradedSmoke,
    AcceptedLargeHost,
    FailedCleanup,
}

impl AdaptiveRuntimeRunnerClassification {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SmallHostSmoke => "small_host_smoke",
            Self::CapabilityDowngradedSmoke => "capability_downgraded_smoke",
            Self::AcceptedLargeHost => "accepted_large_host",
            Self::FailedCleanup => "failed_cleanup",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdaptiveRuntimeRunnerCleanupStatus {
    NotStartedDryRun,
    Clean,
    PreservedArtifacts,
    Failed,
}

impl AdaptiveRuntimeRunnerCleanupStatus {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotStartedDryRun => "not_started_dry_run",
            Self::Clean => "clean",
            Self::PreservedArtifacts => "preserved_artifacts",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveRuntimeRunnerPathPlan {
    pub artifact_root: String,
    pub raw_stdout_path: String,
    pub raw_stderr_path: String,
    pub structured_log_path: String,
    pub runner_manifest_path: String,
    pub cleanup_report_path: String,
    pub host_facts_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scratch_mnt: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveRuntimeRunnerHostFacts {
    pub host_fingerprint: String,
    pub cpu_count: u32,
    pub ram_bytes: u64,
    pub numa_nodes: u32,
    pub kernel: String,
    pub fuse_capability_summary: AdaptiveRuntimeFuseCapabilitySummary,
}

impl AdaptiveRuntimeRunnerHostFacts {
    #[must_use]
    pub fn meets_large_host_floor(&self) -> bool {
        self.cpu_count >= ADAPTIVE_RUNTIME_MIN_CPU_COUNT
            && self.ram_bytes >= ADAPTIVE_RUNTIME_MIN_RAM_BYTES
            && self.numa_nodes >= ADAPTIVE_RUNTIME_MIN_NUMA_NODES
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveRuntimeRunnerConfig {
    pub mode: AdaptiveRuntimeRunnerMode,
    pub path_plan: AdaptiveRuntimeRunnerPathPlan,
    pub ack_env: String,
    pub ack_value: String,
    pub observed_ack_value: Option<String>,
    pub generated_at: String,
    pub git_sha: String,
    pub reproduction_command: String,
    pub host_facts: AdaptiveRuntimeRunnerHostFacts,
    pub cleanup_status: AdaptiveRuntimeRunnerCleanupStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveRuntimeRunnerPlanManifest {
    pub contract_version: u32,
    pub mode: String,
    pub dry_run_default: bool,
    pub side_effect_policy: String,
    pub command_plan: String,
    pub ack_env: String,
    pub ack_value: String,
    pub ack_present: bool,
    pub ack_matches: bool,
    pub path_plan: AdaptiveRuntimeRunnerPathPlan,
    pub generated_at: String,
    pub git_sha: String,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveRuntimeRunnerCleanupReport {
    pub contract_version: u32,
    pub cleanup_status: String,
    pub cleanup_performed: bool,
    pub mutating_workload_started: bool,
    pub preserved_artifacts: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveRuntimeRunnerAckState {
    pub env: String,
    pub value: String,
    pub present: bool,
    pub matches_expected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveRuntimeRunnerExecutionState {
    pub dry_run_only: bool,
    pub permissioned_real_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveRuntimeRunnerReport {
    pub contract_version: u32,
    pub valid: bool,
    pub mode: String,
    pub classification: String,
    pub execution: AdaptiveRuntimeRunnerExecutionState,
    pub ack: AdaptiveRuntimeRunnerAckState,
    pub path_plan: AdaptiveRuntimeRunnerPathPlan,
    pub host_facts: AdaptiveRuntimeRunnerHostFacts,
    pub cleanup_status: String,
    pub artifact_paths: Vec<String>,
    pub capability_downgrade_reasons: Vec<String>,
    pub refusal_reasons: Vec<String>,
    pub errors: Vec<String>,
    pub generated_at: String,
    pub git_sha: String,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptiveRuntimeRunnerArtifacts {
    pub report: AdaptiveRuntimeRunnerReport,
    pub plan_manifest: AdaptiveRuntimeRunnerPlanManifest,
    pub cleanup_report: AdaptiveRuntimeRunnerCleanupReport,
    pub stdout_log: String,
    pub stderr_log: String,
    pub structured_log: String,
}

pub fn load_adaptive_runtime_evidence_manifest(
    path: &Path,
) -> Result<AdaptiveRuntimeEvidenceManifest> {
    let text = fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read adaptive runtime evidence manifest {}",
            path.display()
        )
    })?;
    serde_json::from_str(&text).with_context(|| {
        format!(
            "invalid adaptive runtime evidence manifest JSON {}",
            path.display()
        )
    })
}

#[must_use]
pub fn validate_adaptive_runtime_evidence_manifest(
    manifest: &AdaptiveRuntimeEvidenceManifest,
) -> AdaptiveRuntimeEvidenceReport {
    validate_adaptive_runtime_evidence_manifest_with_config(
        manifest,
        &AdaptiveRuntimeEvidenceValidationConfig::default(),
    )
}

#[must_use]
pub fn validate_adaptive_runtime_evidence_manifest_with_config(
    manifest: &AdaptiveRuntimeEvidenceManifest,
    config: &AdaptiveRuntimeEvidenceValidationConfig,
) -> AdaptiveRuntimeEvidenceReport {
    let mut issues = Vec::new();
    validate_identity(manifest, &mut issues);
    validate_git_sha(manifest, config, &mut issues);
    validate_timestamps(manifest, config, &mut issues);
    validate_host(manifest, &mut issues);
    validate_fuse(manifest, &mut issues);
    validate_policy(manifest, &mut issues);
    validate_resource_caps(manifest, &mut issues);
    validate_artifacts(manifest, &mut issues);
    validate_release_claim(manifest, &mut issues);

    let errors = issues
        .iter()
        .map(|issue| format!("{}: {}", issue.path, issue.message))
        .collect::<Vec<_>>();
    let host_meets_large_host_floor = manifest.host_fingerprint.meets_large_host_floor();
    let fuse_available = matches!(
        manifest.fuse_capability_summary.state,
        AdaptiveRuntimeFuseCapabilityState::Available
    );
    let runtime_controls_accepted = errors.is_empty()
        && host_meets_large_host_floor
        && fuse_available
        && matches!(
            manifest.release_claim_state,
            AdaptiveRuntimeReleaseClaimState::AcceptedLargeHost
        )
        && !matches!(
            manifest.cleanup_status,
            AdaptiveRuntimeCleanupStatus::Failed
        );

    AdaptiveRuntimeEvidenceReport {
        manifest_version: manifest.manifest_version,
        scenario_id: manifest.scenario_id.clone(),
        run_id: manifest.run_id.clone(),
        valid: errors.is_empty(),
        runtime_controls_accepted,
        release_claim_state: manifest.release_claim_state.label().to_owned(),
        runtime_mode: manifest.runtime_mode.label().to_owned(),
        host_lane: manifest.host_fingerprint.lane.label().to_owned(),
        host_classification: if host_meets_large_host_floor {
            "large_host_floor_met"
        } else {
            "below_large_host_floor"
        }
        .to_owned(),
        fuse_capability_state: manifest.fuse_capability_summary.state.label().to_owned(),
        artifact_count: manifest.artifact_paths.len(),
        raw_log_count: manifest.raw_log_paths.len(),
        issues,
        errors,
    }
}

#[must_use]
pub fn render_adaptive_runtime_evidence_markdown(report: &AdaptiveRuntimeEvidenceReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Adaptive Runtime Evidence Manifest\n");
    let _ = writeln!(out, "- Scenario: `{}`", report.scenario_id);
    let _ = writeln!(out, "- Run: `{}`", report.run_id);
    let _ = writeln!(out, "- Valid: `{}`", report.valid);
    let _ = writeln!(
        out,
        "- Runtime controls accepted: `{}`",
        report.runtime_controls_accepted
    );
    let _ = writeln!(out, "- Runtime mode: `{}`", report.runtime_mode);
    let _ = writeln!(out, "- Release claim: `{}`", report.release_claim_state);
    let _ = writeln!(out, "- Host lane: `{}`", report.host_lane);
    let _ = writeln!(out, "- Host class: `{}`", report.host_classification);
    let _ = writeln!(out, "- FUSE capability: `{}`", report.fuse_capability_state);
    let _ = writeln!(out, "- Artifacts: `{}`", report.artifact_count);
    let _ = writeln!(out, "- Raw logs: `{}`", report.raw_log_count);

    if report.issues.is_empty() {
        out.push_str("\n## Issues\n\nnone\n");
    } else {
        out.push_str("\n## Issues\n\n");
        for issue in &report.issues {
            let _ = writeln!(out, "- `{}`: {}", issue.path, issue.message);
        }
    }
    out
}

pub fn fail_on_adaptive_runtime_evidence_errors(
    report: &AdaptiveRuntimeEvidenceReport,
) -> Result<()> {
    if !report.valid {
        bail!(
            "adaptive runtime evidence manifest validation failed: errors={}",
            report.errors.len()
        );
    }
    if !report.runtime_controls_accepted {
        bail!(
            "adaptive runtime evidence is downgrade-only: release_claim_state={} host_classification={} fuse_capability_state={}",
            report.release_claim_state,
            report.host_classification,
            report.fuse_capability_state
        );
    }
    Ok(())
}

#[must_use]
pub fn default_adaptive_runtime_runner_path_plan(
    artifact_root: impl Into<String>,
) -> AdaptiveRuntimeRunnerPathPlan {
    let artifact_root = artifact_root.into();
    AdaptiveRuntimeRunnerPathPlan {
        raw_stdout_path: join_artifact_path(&artifact_root, "stdout.log"),
        raw_stderr_path: join_artifact_path(&artifact_root, "stderr.log"),
        structured_log_path: join_artifact_path(&artifact_root, "structured.jsonl"),
        runner_manifest_path: join_artifact_path(&artifact_root, "runner_manifest.json"),
        cleanup_report_path: join_artifact_path(&artifact_root, "cleanup_report.json"),
        host_facts_path: join_artifact_path(&artifact_root, "host_facts.json"),
        artifact_root,
        test_dir: None,
        scratch_mnt: None,
    }
}

#[must_use]
pub fn collect_adaptive_runtime_runner_host_facts() -> AdaptiveRuntimeRunnerHostFacts {
    let cpu_count = thread::available_parallelism()
        .ok()
        .and_then(|count| u32::try_from(count.get()).ok())
        .filter(|count| *count > 0)
        .unwrap_or(1);
    let ram_bytes = read_meminfo_total_bytes().unwrap_or(1);
    let numa_nodes = count_numa_nodes().unwrap_or(1).max(1);
    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|value| value.trim().to_owned())
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    let fuse_capability_summary = classify_host_fuse_capability();
    let host_fingerprint = format!("cpu{cpu_count}-ram{ram_bytes}-numa{numa_nodes}-kernel{kernel}");

    AdaptiveRuntimeRunnerHostFacts {
        host_fingerprint,
        cpu_count,
        ram_bytes,
        numa_nodes,
        kernel,
        fuse_capability_summary,
    }
}

#[must_use]
pub fn build_adaptive_runtime_runner_artifacts(
    config: AdaptiveRuntimeRunnerConfig,
) -> AdaptiveRuntimeRunnerArtifacts {
    let report = build_adaptive_runtime_runner_report(config);
    let plan_manifest = build_adaptive_runtime_runner_plan_manifest(&report);
    let cleanup_report = build_adaptive_runtime_runner_cleanup_report(&report);
    let stdout_log = render_adaptive_runtime_runner_stdout_log(&report);
    let stderr_log = render_adaptive_runtime_runner_stderr_log(&report);
    let structured_log = render_adaptive_runtime_runner_structured_log(&report);

    AdaptiveRuntimeRunnerArtifacts {
        report,
        plan_manifest,
        cleanup_report,
        stdout_log,
        stderr_log,
        structured_log,
    }
}

#[must_use]
pub fn build_adaptive_runtime_runner_report(
    config: AdaptiveRuntimeRunnerConfig,
) -> AdaptiveRuntimeRunnerReport {
    let ack_present = config
        .observed_ack_value
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    let ack_matches = config
        .observed_ack_value
        .as_deref()
        .is_some_and(|value| value.trim() == config.ack_value);
    let mut refusal_reasons = validate_runner_path_plan(&config);
    let mut capability_downgrade_reasons = capability_downgrade_reasons(&config);

    if matches!(config.mode, AdaptiveRuntimeRunnerMode::PermissionedReal) {
        if !ack_present {
            refusal_reasons.push(format!(
                "{} is required for permissioned real adaptive runtime runs",
                config.ack_env
            ));
        } else if !ack_matches {
            refusal_reasons.push(format!(
                "{} must equal {}",
                config.ack_env, config.ack_value
            ));
        }
    } else if matches!(config.mode, AdaptiveRuntimeRunnerMode::DryRun) {
        capability_downgrade_reasons
            .push("dry-run mode does not mount or generate adaptive runtime load".to_owned());
    } else {
        capability_downgrade_reasons
            .push("capability-probe mode records host facts without mutating workloads".to_owned());
    }

    let cleanup_failed = matches!(
        config.cleanup_status,
        AdaptiveRuntimeRunnerCleanupStatus::Failed
    );
    let permissioned_real_allowed =
        matches!(config.mode, AdaptiveRuntimeRunnerMode::PermissionedReal)
            && ack_matches
            && refusal_reasons.is_empty();
    let large_host_accepted = permissioned_real_allowed
        && config.host_facts.meets_large_host_floor()
        && matches!(
            config.host_facts.fuse_capability_summary.state,
            AdaptiveRuntimeFuseCapabilityState::Available
        );
    let fuse_available = matches!(
        config.host_facts.fuse_capability_summary.state,
        AdaptiveRuntimeFuseCapabilityState::Available
    );
    let classification = if cleanup_failed {
        AdaptiveRuntimeRunnerClassification::FailedCleanup
    } else if large_host_accepted {
        AdaptiveRuntimeRunnerClassification::AcceptedLargeHost
    } else if matches!(config.mode, AdaptiveRuntimeRunnerMode::CapabilityProbe) || !fuse_available {
        AdaptiveRuntimeRunnerClassification::CapabilityDowngradedSmoke
    } else {
        AdaptiveRuntimeRunnerClassification::SmallHostSmoke
    };
    let mut errors = refusal_reasons.clone();
    if cleanup_failed {
        errors.push("cleanup_status failed; artifacts require operator inspection".to_owned());
    }
    let valid = errors.is_empty();
    let artifact_paths = vec![
        config.path_plan.raw_stdout_path.clone(),
        config.path_plan.raw_stderr_path.clone(),
        config.path_plan.structured_log_path.clone(),
        config.path_plan.runner_manifest_path.clone(),
        config.path_plan.cleanup_report_path.clone(),
        config.path_plan.host_facts_path.clone(),
    ];

    AdaptiveRuntimeRunnerReport {
        contract_version: ADAPTIVE_RUNTIME_RUNNER_CONTRACT_VERSION,
        valid,
        mode: config.mode.label().to_owned(),
        classification: classification.label().to_owned(),
        execution: AdaptiveRuntimeRunnerExecutionState {
            dry_run_only: !matches!(config.mode, AdaptiveRuntimeRunnerMode::PermissionedReal),
            permissioned_real_allowed,
        },
        ack: AdaptiveRuntimeRunnerAckState {
            env: config.ack_env,
            value: config.ack_value,
            present: ack_present,
            matches_expected: ack_matches,
        },
        path_plan: config.path_plan,
        host_facts: config.host_facts,
        cleanup_status: config.cleanup_status.label().to_owned(),
        artifact_paths,
        capability_downgrade_reasons,
        refusal_reasons,
        errors,
        generated_at: config.generated_at,
        git_sha: config.git_sha,
        reproduction_command: config.reproduction_command,
    }
}

#[must_use]
pub fn render_adaptive_runtime_runner_markdown(report: &AdaptiveRuntimeRunnerReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Adaptive Runtime Runner\n");
    let _ = writeln!(out, "- Valid: `{}`", report.valid);
    let _ = writeln!(out, "- Mode: `{}`", report.mode);
    let _ = writeln!(out, "- Classification: `{}`", report.classification);
    let _ = writeln!(
        out,
        "- Permissioned real allowed: `{}`",
        report.execution.permissioned_real_allowed
    );
    let _ = writeln!(out, "- ACK env: `{}`", report.ack.env);
    let _ = writeln!(out, "- ACK present: `{}`", report.ack.present);
    let _ = writeln!(out, "- ACK matches: `{}`", report.ack.matches_expected);
    let _ = writeln!(out, "- Cleanup: `{}`", report.cleanup_status);
    let _ = writeln!(out, "- Artifact root: `{}`", report.path_plan.artifact_root);
    let _ = writeln!(out, "- CPU count: `{}`", report.host_facts.cpu_count);
    let _ = writeln!(out, "- RAM bytes: `{}`", report.host_facts.ram_bytes);
    let _ = writeln!(out, "- NUMA nodes: `{}`", report.host_facts.numa_nodes);
    let _ = writeln!(
        out,
        "- FUSE capability: `{}`",
        report.host_facts.fuse_capability_summary.state.label()
    );

    out.push_str("\n## Capability Downgrades\n\n");
    if report.capability_downgrade_reasons.is_empty() {
        out.push_str("none\n");
    } else {
        for reason in &report.capability_downgrade_reasons {
            let _ = writeln!(out, "- {reason}");
        }
    }

    out.push_str("\n## Refusals\n\n");
    if report.refusal_reasons.is_empty() {
        out.push_str("none\n");
    } else {
        for reason in &report.refusal_reasons {
            let _ = writeln!(out, "- {reason}");
        }
    }

    out.push_str("\n## Artifacts\n\n");
    for path in &report.artifact_paths {
        let _ = writeln!(out, "- `{path}`");
    }

    out
}

pub fn fail_on_adaptive_runtime_runner_errors(report: &AdaptiveRuntimeRunnerReport) -> Result<()> {
    if report.valid {
        return Ok(());
    }
    bail!(
        "adaptive runtime runner refused: classification={} errors={}",
        report.classification,
        report.errors.len()
    );
}

fn build_adaptive_runtime_runner_plan_manifest(
    report: &AdaptiveRuntimeRunnerReport,
) -> AdaptiveRuntimeRunnerPlanManifest {
    let side_effect_policy = if report.execution.permissioned_real_allowed {
        "permissioned_real_may_mount_and_generate_load_inside_artifact_scoped_paths"
    } else {
        "safe_probe_no_mount_no_workload_mutation"
    };
    let command_plan = if report.execution.permissioned_real_allowed {
        "ffs mount --adaptive-runtime-enabled --adaptive-runtime-mode per-core"
    } else {
        "dry-run: collect host facts, capability state, logs, and refusal/downgrade reasons"
    };

    AdaptiveRuntimeRunnerPlanManifest {
        contract_version: ADAPTIVE_RUNTIME_RUNNER_CONTRACT_VERSION,
        mode: report.mode.clone(),
        dry_run_default: report.execution.dry_run_only,
        side_effect_policy: side_effect_policy.to_owned(),
        command_plan: command_plan.to_owned(),
        ack_env: report.ack.env.clone(),
        ack_value: report.ack.value.clone(),
        ack_present: report.ack.present,
        ack_matches: report.ack.matches_expected,
        path_plan: report.path_plan.clone(),
        generated_at: report.generated_at.clone(),
        git_sha: report.git_sha.clone(),
        reproduction_command: report.reproduction_command.clone(),
    }
}

fn build_adaptive_runtime_runner_cleanup_report(
    report: &AdaptiveRuntimeRunnerReport,
) -> AdaptiveRuntimeRunnerCleanupReport {
    let mut notes = Vec::new();
    if report.execution.permissioned_real_allowed {
        notes.push(
            "permissioned lane was authorized; cleanup status reflects runner result".to_owned(),
        );
    } else {
        notes.push("no mount or adaptive workload was started".to_owned());
    }
    if !report.refusal_reasons.is_empty() {
        notes.push("permissioned runner refused before side effects".to_owned());
    }

    AdaptiveRuntimeRunnerCleanupReport {
        contract_version: ADAPTIVE_RUNTIME_RUNNER_CONTRACT_VERSION,
        cleanup_status: report.cleanup_status.clone(),
        cleanup_performed: report.execution.permissioned_real_allowed,
        mutating_workload_started: report.execution.permissioned_real_allowed,
        preserved_artifacts: report.artifact_paths.clone(),
        notes,
    }
}

fn render_adaptive_runtime_runner_stdout_log(report: &AdaptiveRuntimeRunnerReport) -> String {
    format!(
        "ADAPTIVE_RUNTIME_RUNNER|mode={}|classification={}|valid={}|permissioned_real_allowed={}|artifact_root={}\n",
        report.mode,
        report.classification,
        report.valid,
        report.execution.permissioned_real_allowed,
        report.path_plan.artifact_root
    )
}

fn render_adaptive_runtime_runner_stderr_log(report: &AdaptiveRuntimeRunnerReport) -> String {
    if report.errors.is_empty() {
        return "ADAPTIVE_RUNTIME_RUNNER_DIAGNOSTIC|level=info|message=no permissioned workload executed unless explicitly authorized\n".to_owned();
    }

    let mut out = String::new();
    for error in &report.errors {
        let _ = writeln!(
            out,
            "ADAPTIVE_RUNTIME_RUNNER_DIAGNOSTIC|level=error|message={}",
            error.replace('\n', " ")
        );
    }
    out
}

fn render_adaptive_runtime_runner_structured_log(report: &AdaptiveRuntimeRunnerReport) -> String {
    let events = [
        serde_json::json!({
            "event": "adaptive_runtime_runner_start",
            "mode": report.mode,
            "artifact_root": report.path_plan.artifact_root,
            "dry_run_only": report.execution.dry_run_only,
        }),
        serde_json::json!({
            "event": "adaptive_runtime_runner_capability",
            "cpu_count": report.host_facts.cpu_count,
            "ram_bytes": report.host_facts.ram_bytes,
            "numa_nodes": report.host_facts.numa_nodes,
            "fuse_state": report.host_facts.fuse_capability_summary.state.label(),
            "downgrade_reasons": report.capability_downgrade_reasons,
        }),
        serde_json::json!({
            "event": "adaptive_runtime_runner_result",
            "valid": report.valid,
            "classification": report.classification,
            "permissioned_real_allowed": report.execution.permissioned_real_allowed,
            "refusal_reasons": report.refusal_reasons,
            "cleanup_status": report.cleanup_status,
        }),
    ];
    let mut out = String::new();
    for event in events {
        let _ = writeln!(out, "{event}");
    }
    out
}

fn validate_runner_path_plan(config: &AdaptiveRuntimeRunnerConfig) -> Vec<String> {
    let mut reasons = Vec::new();
    let root = config.path_plan.artifact_root.trim();
    if !is_safe_artifact_root(root) {
        reasons.push(format!(
            "artifact_root must be an artifact-scoped path under artifacts/, /tmp/frankenfs-*, /data/tmp/frankenfs-*, or an absolute artifacts directory: {root}"
        ));
    }

    validate_artifact_child_path(
        root,
        "raw_stdout_path",
        &config.path_plan.raw_stdout_path,
        &mut reasons,
    );
    validate_artifact_child_path(
        root,
        "raw_stderr_path",
        &config.path_plan.raw_stderr_path,
        &mut reasons,
    );
    validate_artifact_child_path(
        root,
        "structured_log_path",
        &config.path_plan.structured_log_path,
        &mut reasons,
    );
    validate_artifact_child_path(
        root,
        "runner_manifest_path",
        &config.path_plan.runner_manifest_path,
        &mut reasons,
    );
    validate_artifact_child_path(
        root,
        "cleanup_report_path",
        &config.path_plan.cleanup_report_path,
        &mut reasons,
    );
    validate_artifact_child_path(
        root,
        "host_facts_path",
        &config.path_plan.host_facts_path,
        &mut reasons,
    );

    if matches!(config.mode, AdaptiveRuntimeRunnerMode::PermissionedReal) {
        validate_required_artifact_child_option(
            root,
            "test_dir",
            config.path_plan.test_dir.as_ref(),
            &mut reasons,
        );
        validate_required_artifact_child_option(
            root,
            "scratch_mnt",
            config.path_plan.scratch_mnt.as_ref(),
            &mut reasons,
        );
        if config.path_plan.test_dir == config.path_plan.scratch_mnt {
            reasons.push("test_dir and scratch_mnt must be distinct".to_owned());
        }
    }

    reasons
}

fn validate_required_artifact_child_option(
    artifact_root: &str,
    field: &str,
    value: Option<&String>,
    reasons: &mut Vec<String>,
) {
    match value {
        Some(path) => validate_artifact_child_path(artifact_root, field, path, reasons),
        None => reasons.push(format!("{field} is required for permissioned real mode")),
    }
}

fn validate_artifact_child_path(
    artifact_root: &str,
    field: &str,
    value: &str,
    reasons: &mut Vec<String>,
) {
    let value = value.trim();
    if value.is_empty() {
        reasons.push(format!("{field} must not be empty"));
        return;
    }
    let path = Path::new(value);
    if is_root_or_parent_sensitive(path) || !path.starts_with(Path::new(artifact_root)) {
        reasons.push(format!(
            "{field} must live under artifact_root {artifact_root}: {value}"
        ));
    }
}

fn capability_downgrade_reasons(config: &AdaptiveRuntimeRunnerConfig) -> Vec<String> {
    let mut reasons = Vec::new();
    if !config.host_facts.meets_large_host_floor() {
        reasons.push(format!(
            "host below large-host floor: cpu_count={} ram_bytes={} numa_nodes={}",
            config.host_facts.cpu_count, config.host_facts.ram_bytes, config.host_facts.numa_nodes
        ));
    }
    if !matches!(
        config.host_facts.fuse_capability_summary.state,
        AdaptiveRuntimeFuseCapabilityState::Available
    ) {
        reasons.push(format!(
            "FUSE capability is {}: {}",
            config.host_facts.fuse_capability_summary.state.label(),
            config.host_facts.fuse_capability_summary.detail
        ));
    }
    reasons
}

fn is_safe_artifact_root(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let path = Path::new(value);
    if is_root_or_parent_sensitive(path) {
        return false;
    }
    if path.is_absolute() {
        value.starts_with("/tmp/frankenfs-")
            || value.starts_with("/data/tmp/frankenfs-")
            || value.contains("/artifacts/")
    } else {
        path.starts_with("artifacts")
    }
}

fn is_root_or_parent_sensitive(path: &Path) -> bool {
    path.as_os_str().is_empty()
        || path == Path::new("/")
        || path == Path::new(".")
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
}

fn join_artifact_path(root: &str, leaf: &str) -> String {
    Path::new(root).join(leaf).display().to_string()
}

fn read_meminfo_total_bytes() -> Option<u64> {
    let meminfo = fs::read_to_string("/proc/meminfo").ok()?;
    let line = meminfo.lines().find(|line| line.starts_with("MemTotal:"))?;
    let kib = line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u64>().ok())?;
    kib.checked_mul(1024)
}

fn count_numa_nodes() -> Option<u32> {
    let entries = fs::read_dir("/sys/devices/system/node").ok()?;
    let mut count = 0_u32;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(suffix) = name.strip_prefix("node")
            && suffix.parse::<u32>().is_ok()
        {
            count = count.saturating_add(1);
        }
    }
    (count > 0).then_some(count)
}

fn classify_host_fuse_capability() -> AdaptiveRuntimeFuseCapabilitySummary {
    if std::env::var("FFS_ADAPTIVE_RUNTIME_DISABLE_FUSE_PROBE").is_ok() {
        return AdaptiveRuntimeFuseCapabilitySummary {
            state: AdaptiveRuntimeFuseCapabilityState::DisabledByUser,
            detail: "FFS_ADAPTIVE_RUNTIME_DISABLE_FUSE_PROBE is set".to_owned(),
        };
    }
    let fuse_path = Path::new("/dev/fuse");
    if !fuse_path.exists() {
        return AdaptiveRuntimeFuseCapabilitySummary {
            state: AdaptiveRuntimeFuseCapabilityState::Missing,
            detail: "/dev/fuse is not present".to_owned(),
        };
    }
    match fs::metadata(fuse_path) {
        Ok(_) => AdaptiveRuntimeFuseCapabilitySummary {
            state: AdaptiveRuntimeFuseCapabilityState::Available,
            detail: "/dev/fuse metadata is visible; dry-run did not mount".to_owned(),
        },
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            AdaptiveRuntimeFuseCapabilitySummary {
                state: AdaptiveRuntimeFuseCapabilityState::PermissionDenied,
                detail: "/dev/fuse exists but metadata was permission denied".to_owned(),
            }
        }
        Err(err) => AdaptiveRuntimeFuseCapabilitySummary {
            state: AdaptiveRuntimeFuseCapabilityState::Unknown,
            detail: format!("/dev/fuse probe failed: {err}"),
        },
    }
}

fn current_epoch_days() -> Option<u32> {
    let unix_epoch_days = parse_manifest_timestamp_epoch_days("1970-01-01T00:00:00Z")?;
    let elapsed_days = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() / 86_400;
    let total_days = u64::from(unix_epoch_days).checked_add(elapsed_days)?;
    u32::try_from(total_days).ok()
}

fn validate_identity(
    manifest: &AdaptiveRuntimeEvidenceManifest,
    issues: &mut Vec<AdaptiveRuntimeEvidenceIssue>,
) {
    if manifest.manifest_version != ADAPTIVE_RUNTIME_EVIDENCE_MANIFEST_VERSION {
        push_issue(
            issues,
            "manifest_version",
            format!("must be {ADAPTIVE_RUNTIME_EVIDENCE_MANIFEST_VERSION}"),
        );
    }
    if manifest.scenario_id.trim().is_empty() {
        push_issue(issues, "scenario_id", "must not be empty");
    }
    if manifest.run_id.trim().is_empty() {
        push_issue(issues, "run_id", "must not be empty");
    }
    if matches!(manifest.runtime_mode, AdaptiveRuntimeMode::Standard) {
        push_issue(
            issues,
            "runtime_mode",
            "adaptive runtime evidence only applies to managed or per_core mounts",
        );
    }
    if manifest.git_sha.trim().len() < 7 {
        push_issue(issues, "git_sha", "must contain at least 7 characters");
    }
    if manifest.reproduction_command.trim().is_empty() {
        push_issue(issues, "reproduction_command", "must not be empty");
    }
}

fn validate_git_sha(
    manifest: &AdaptiveRuntimeEvidenceManifest,
    config: &AdaptiveRuntimeEvidenceValidationConfig,
    issues: &mut Vec<AdaptiveRuntimeEvidenceIssue>,
) {
    if let Some(current_git_sha) = &config.current_git_sha {
        let current_git_sha = current_git_sha.trim();
        if current_git_sha.is_empty() {
            push_issue(
                issues,
                "current_git_sha",
                "strict git SHA must not be empty",
            );
        } else if manifest.git_sha.trim() != current_git_sha {
            push_issue(
                issues,
                "git_sha",
                "manifest git_sha does not match the strict current git SHA",
            );
        }
    }
}

fn validate_timestamps(
    manifest: &AdaptiveRuntimeEvidenceManifest,
    config: &AdaptiveRuntimeEvidenceValidationConfig,
    issues: &mut Vec<AdaptiveRuntimeEvidenceIssue>,
) {
    let generated_at_days = validate_timestamp(issues, "generated_at", &manifest.generated_at);
    let expires_at_days = validate_timestamp(issues, "expires_at", &manifest.expires_at);

    if let (Some(generated_at_days), Some(expires_at_days)) = (generated_at_days, expires_at_days) {
        if generated_at_days > expires_at_days {
            push_issue(
                issues,
                "expires_at",
                "must not be earlier than generated_at",
            );
        }
        if let Some(reference_epoch_days) = config.reference_epoch_days {
            if generated_at_days > reference_epoch_days {
                push_issue(
                    issues,
                    "generated_at",
                    "must not be after the validation reference timestamp",
                );
            }
            if expires_at_days < reference_epoch_days {
                push_issue(
                    issues,
                    "expires_at",
                    "manifest has expired for the validation reference timestamp",
                );
            }
        }
    }
}

fn validate_timestamp(
    issues: &mut Vec<AdaptiveRuntimeEvidenceIssue>,
    path: &str,
    timestamp: &str,
) -> Option<u32> {
    if timestamp.trim().is_empty() {
        push_issue(issues, path, "must not be empty");
        return None;
    }
    let parsed = parse_manifest_timestamp_epoch_days(timestamp);
    if parsed.is_none() {
        push_issue(issues, path, "must be an ISO-like RFC3339 timestamp");
    }
    parsed
}

fn validate_host(
    manifest: &AdaptiveRuntimeEvidenceManifest,
    issues: &mut Vec<AdaptiveRuntimeEvidenceIssue>,
) {
    let host = &manifest.host_fingerprint;
    if host.host_fingerprint.trim().is_empty() {
        push_issue(
            issues,
            "host_fingerprint.host_fingerprint",
            "must not be empty",
        );
    }
    if host.cpu_count == 0 {
        push_issue(
            issues,
            "host_fingerprint.cpu_count",
            "must be greater than zero",
        );
    }
    if host.ram_bytes == 0 {
        push_issue(
            issues,
            "host_fingerprint.ram_bytes",
            "must be greater than zero",
        );
    }
    if host.numa_nodes == 0 {
        push_issue(
            issues,
            "host_fingerprint.numa_nodes",
            "must be greater than zero",
        );
    }
    if host.kernel.trim().is_empty() {
        push_issue(issues, "host_fingerprint.kernel", "must not be empty");
    }
}

fn validate_fuse(
    manifest: &AdaptiveRuntimeEvidenceManifest,
    issues: &mut Vec<AdaptiveRuntimeEvidenceIssue>,
) {
    if manifest.fuse_capability_summary.detail.trim().is_empty() {
        push_issue(
            issues,
            "fuse_capability_summary.detail",
            "must not be empty",
        );
    }
}

fn validate_policy(
    manifest: &AdaptiveRuntimeEvidenceManifest,
    issues: &mut Vec<AdaptiveRuntimeEvidenceIssue>,
) {
    if manifest.backpressure_policy_id.trim().is_empty() {
        push_issue(issues, "backpressure_policy_id", "must not be empty");
    }
    let thresholds = &manifest.degradation_thresholds;
    if !(0.0..=1.0).contains(&thresholds.throttle_dirty_ratio)
        || !(0.0..=1.0).contains(&thresholds.shed_dirty_ratio)
        || !(0.0..=1.0).contains(&thresholds.emergency_dirty_ratio)
    {
        push_issue(
            issues,
            "degradation_thresholds",
            "threshold ratios must be between 0.0 and 1.0",
        );
    }
    if thresholds.throttle_dirty_ratio <= 0.0
        || thresholds.throttle_dirty_ratio > thresholds.shed_dirty_ratio
        || thresholds.shed_dirty_ratio > thresholds.emergency_dirty_ratio
    {
        push_issue(
            issues,
            "degradation_thresholds",
            "must be ordered as 0 < throttle <= shed <= emergency",
        );
    }
    let per_core = &manifest.per_core_config;
    if matches!(manifest.runtime_mode, AdaptiveRuntimeMode::PerCore) && !per_core.enabled {
        push_issue(
            issues,
            "per_core_config.enabled",
            "per_core runtime evidence must enable per-core config",
        );
    }
    if per_core.enabled && per_core.worker_count == 0 {
        push_issue(
            issues,
            "per_core_config.worker_count",
            "enabled per-core config requires at least one worker",
        );
    }
    if per_core.queue_policy.trim().is_empty() {
        push_issue(issues, "per_core_config.queue_policy", "must not be empty");
    }
}

fn validate_resource_caps(
    manifest: &AdaptiveRuntimeEvidenceManifest,
    issues: &mut Vec<AdaptiveRuntimeEvidenceIssue>,
) {
    let caps = &manifest.resource_caps;
    if caps.max_duration_secs == 0 {
        push_issue(
            issues,
            "resource_caps.max_duration_secs",
            "must be greater than zero",
        );
    }
    if caps.max_threads == 0 {
        push_issue(
            issues,
            "resource_caps.max_threads",
            "must be greater than zero",
        );
    }
    if caps.max_memory_bytes == 0 {
        push_issue(
            issues,
            "resource_caps.max_memory_bytes",
            "must be greater than zero",
        );
    }
    if caps.max_temp_bytes == 0 {
        push_issue(
            issues,
            "resource_caps.max_temp_bytes",
            "must be greater than zero",
        );
    }
    if caps.max_queue_depth == 0 {
        push_issue(
            issues,
            "resource_caps.max_queue_depth",
            "must be greater than zero",
        );
    }
}

fn validate_artifacts(
    manifest: &AdaptiveRuntimeEvidenceManifest,
    issues: &mut Vec<AdaptiveRuntimeEvidenceIssue>,
) {
    validate_non_empty_path_list(issues, "artifact_paths", &manifest.artifact_paths);
    validate_non_empty_path_list(issues, "raw_log_paths", &manifest.raw_log_paths);
    if manifest.raw_stdout_path.trim().is_empty() {
        push_issue(issues, "raw_stdout_path", "must not be empty");
    }
    if manifest.raw_stderr_path.trim().is_empty() {
        push_issue(issues, "raw_stderr_path", "must not be empty");
    }
    if matches!(
        manifest.cleanup_status,
        AdaptiveRuntimeCleanupStatus::Unknown
    ) {
        push_issue(issues, "cleanup_status", "must not be unknown");
    }
    if manifest.controlling_ack_env.trim().is_empty() {
        push_issue(issues, "controlling_ack_env", "must not be empty");
    }
    if manifest.controlling_ack_value.trim().is_empty() {
        push_issue(issues, "controlling_ack_value", "must not be empty");
    }
}

fn validate_non_empty_path_list(
    issues: &mut Vec<AdaptiveRuntimeEvidenceIssue>,
    path: &str,
    values: &[String],
) {
    if values.is_empty() {
        push_issue(issues, path, "must not be empty");
        return;
    }
    for (index, value) in values.iter().enumerate() {
        if value.trim().is_empty() {
            push_issue(issues, format!("{path}[{index}]"), "must not be empty");
        }
    }
}

fn validate_release_claim(
    manifest: &AdaptiveRuntimeEvidenceManifest,
    issues: &mut Vec<AdaptiveRuntimeEvidenceIssue>,
) {
    if matches!(
        manifest.release_claim_state,
        AdaptiveRuntimeReleaseClaimState::AcceptedLargeHost
    ) {
        if !manifest.host_fingerprint.meets_large_host_floor() {
            push_issue(
                issues,
                "release_claim_state",
                "accepted_large_host requires a permissioned host with at least 64 CPUs, 256 GiB RAM, and 2 NUMA nodes",
            );
        }
        if !matches!(
            manifest.fuse_capability_summary.state,
            AdaptiveRuntimeFuseCapabilityState::Available
        ) {
            push_issue(
                issues,
                "fuse_capability_summary.state",
                "accepted_large_host requires available FUSE capability",
            );
        }
        if matches!(
            manifest.cleanup_status,
            AdaptiveRuntimeCleanupStatus::Failed
        ) {
            push_issue(
                issues,
                "cleanup_status",
                "accepted_large_host cannot have failed cleanup",
            );
        }
    }
}

fn push_issue(
    issues: &mut Vec<AdaptiveRuntimeEvidenceIssue>,
    path: impl Into<String>,
    message: impl Into<String>,
) {
    issues.push(AdaptiveRuntimeEvidenceIssue {
        path: path.into(),
        message: message.into(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_in_adaptive_runtime_manifest_validates() {
        let manifest = load_adaptive_runtime_evidence_manifest(Path::new(&workspace_path(
            DEFAULT_ADAPTIVE_RUNTIME_EVIDENCE_MANIFEST,
        )))
        .expect("load checked-in adaptive runtime manifest");
        let report = validate_adaptive_runtime_evidence_manifest(&manifest);

        assert!(report.valid, "{:?}", report.errors);
        assert!(report.runtime_controls_accepted);
        assert_eq!(report.release_claim_state, "accepted_large_host");
        assert_eq!(report.runtime_mode, "per_core");
        assert_eq!(report.artifact_count, 3);
        assert_eq!(report.raw_log_count, 2);
    }

    #[test]
    fn render_adaptive_runtime_evidence_markdown_snapshot() {
        let manifest = fixture_manifest();
        let report = validate_adaptive_runtime_evidence_manifest(&manifest);
        let markdown = render_adaptive_runtime_evidence_markdown(&report);

        insta::assert_snapshot!("render_adaptive_runtime_evidence_markdown", markdown);
    }

    #[test]
    fn strict_git_sha_mismatch_is_rejected() {
        let manifest = fixture_manifest();
        let config = AdaptiveRuntimeEvidenceValidationConfig {
            reference_epoch_days: None,
            current_git_sha: Some("different123".to_owned()),
        };

        let report = validate_adaptive_runtime_evidence_manifest_with_config(&manifest, &config);

        assert!(!report.valid);
        assert!(report.issues.iter().any(|issue| issue.path == "git_sha"));
    }

    #[test]
    fn fail_on_rejects_downgrade_evidence() {
        let mut manifest = fixture_manifest();
        manifest.host_fingerprint.lane = AdaptiveRuntimeHostLane::LocalSmoke;
        manifest.release_claim_state = AdaptiveRuntimeReleaseClaimState::SmallHostSmoke;

        let report = validate_adaptive_runtime_evidence_manifest(&manifest);

        assert!(report.valid);
        assert!(!report.runtime_controls_accepted);
        assert!(fail_on_adaptive_runtime_evidence_errors(&report).is_err());
    }

    #[test]
    fn small_host_smoke_is_valid_but_not_accepted() {
        let mut manifest = fixture_manifest();
        manifest.host_fingerprint.cpu_count = 16;
        manifest.host_fingerprint.ram_bytes = 64 * 1024 * 1024 * 1024;
        manifest.host_fingerprint.numa_nodes = 1;
        manifest.host_fingerprint.lane = AdaptiveRuntimeHostLane::LocalSmoke;
        manifest.release_claim_state = AdaptiveRuntimeReleaseClaimState::SmallHostSmoke;
        manifest.fuse_capability_summary.state = AdaptiveRuntimeFuseCapabilityState::Unknown;

        let report = validate_adaptive_runtime_evidence_manifest(&manifest);

        assert!(report.valid, "{:?}", report.errors);
        assert!(!report.runtime_controls_accepted);
        assert_eq!(report.release_claim_state, "small_host_smoke");
        assert_eq!(report.host_classification, "below_large_host_floor");
    }

    #[test]
    fn capability_downgraded_smoke_is_valid_but_not_accepted() {
        let mut manifest = fixture_manifest();
        manifest.host_fingerprint.lane = AdaptiveRuntimeHostLane::CapabilityDowngraded;
        manifest.fuse_capability_summary.state =
            AdaptiveRuntimeFuseCapabilityState::PermissionDenied;
        manifest.release_claim_state = AdaptiveRuntimeReleaseClaimState::CapabilityDowngradedSmoke;

        let report = validate_adaptive_runtime_evidence_manifest(&manifest);

        assert!(report.valid, "{:?}", report.errors);
        assert!(!report.runtime_controls_accepted);
        assert_eq!(report.release_claim_state, "capability_downgraded_smoke");
        assert_eq!(report.fuse_capability_state, "permission_denied");
    }

    #[test]
    fn accepted_large_host_requires_large_host_facts() {
        let mut manifest = fixture_manifest();
        manifest.host_fingerprint.cpu_count = 8;

        let report = validate_adaptive_runtime_evidence_manifest(&manifest);

        assert!(!report.valid);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.path == "release_claim_state")
        );
    }

    #[test]
    fn required_identity_fields_are_rejected() {
        let mut manifest = fixture_manifest();
        manifest.manifest_version = 0;
        manifest.scenario_id.clear();
        manifest.run_id.clear();
        manifest.runtime_mode = AdaptiveRuntimeMode::Standard;
        manifest.git_sha = "abc".to_owned();
        manifest.reproduction_command.clear();

        let report = validate_adaptive_runtime_evidence_manifest(&manifest);

        assert_paths_present(
            &report,
            &[
                "manifest_version",
                "scenario_id",
                "run_id",
                "runtime_mode",
                "git_sha",
                "reproduction_command",
            ],
        );
    }

    #[test]
    fn missing_host_facts_are_rejected() {
        let mut manifest = fixture_manifest();
        manifest.host_fingerprint.host_fingerprint.clear();
        manifest.host_fingerprint.cpu_count = 0;
        manifest.host_fingerprint.ram_bytes = 0;
        manifest.host_fingerprint.numa_nodes = 0;
        manifest.host_fingerprint.kernel.clear();

        let report = validate_adaptive_runtime_evidence_manifest(&manifest);

        assert_paths_present(
            &report,
            &[
                "host_fingerprint.host_fingerprint",
                "host_fingerprint.cpu_count",
                "host_fingerprint.ram_bytes",
                "host_fingerprint.numa_nodes",
                "host_fingerprint.kernel",
            ],
        );
    }

    #[test]
    fn missing_policy_artifact_and_ack_fields_are_rejected() {
        let mut manifest = fixture_manifest();
        manifest.backpressure_policy_id.clear();
        manifest.artifact_paths.clear();
        manifest.raw_stdout_path.clear();
        manifest.raw_stderr_path.clear();
        manifest.raw_log_paths.clear();
        manifest.controlling_ack_env.clear();
        manifest.controlling_ack_value.clear();
        manifest.cleanup_status = AdaptiveRuntimeCleanupStatus::Unknown;

        let report = validate_adaptive_runtime_evidence_manifest(&manifest);

        assert_paths_present(
            &report,
            &[
                "backpressure_policy_id",
                "artifact_paths",
                "raw_stdout_path",
                "raw_stderr_path",
                "raw_log_paths",
                "controlling_ack_env",
                "controlling_ack_value",
                "cleanup_status",
            ],
        );
    }

    #[test]
    fn expired_manifest_is_rejected_with_reference_timestamp() {
        let manifest = fixture_manifest();
        let config = AdaptiveRuntimeEvidenceValidationConfig {
            reference_epoch_days: parse_manifest_timestamp_epoch_days("2026-06-01T00:00:00Z"),
            current_git_sha: None,
        };

        let report = validate_adaptive_runtime_evidence_manifest_with_config(&manifest, &config);

        assert!(!report.valid);
        assert!(
            report.issues.iter().any(|issue| issue.path == "expires_at"
                && issue.message.contains("manifest has expired"))
        );
    }

    #[test]
    fn threshold_and_per_core_contract_are_rejected() {
        let mut manifest = fixture_manifest();
        manifest.degradation_thresholds.throttle_dirty_ratio = 0.90;
        manifest.degradation_thresholds.shed_dirty_ratio = 0.80;
        manifest.per_core_config.enabled = true;
        manifest.per_core_config.worker_count = 0;
        manifest.per_core_config.queue_policy.clear();

        let report = validate_adaptive_runtime_evidence_manifest(&manifest);

        assert_paths_present(
            &report,
            &[
                "degradation_thresholds",
                "per_core_config.worker_count",
                "per_core_config.queue_policy",
            ],
        );
    }

    #[test]
    fn adaptive_runtime_runner_dry_run_is_safe_default() {
        let artifacts = build_adaptive_runtime_runner_artifacts(fixture_runner_config(
            AdaptiveRuntimeRunnerMode::DryRun,
        ));
        let report = &artifacts.report;

        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.mode, "dry_run");
        assert_eq!(report.classification, "small_host_smoke");
        assert!(report.execution.dry_run_only);
        assert!(!report.execution.permissioned_real_allowed);
        assert!(!report.ack.present);
        assert_eq!(report.artifact_paths.len(), 6);
        assert!(
            report
                .capability_downgrade_reasons
                .iter()
                .any(|reason| reason.contains("host below large-host floor"))
        );
        assert!(artifacts.stdout_log.contains("ADAPTIVE_RUNTIME_RUNNER"));
        assert!(
            artifacts
                .structured_log
                .contains("adaptive_runtime_runner_result")
        );
    }

    #[test]
    fn adaptive_runtime_runner_capability_probe_stays_downgraded() {
        let artifacts = build_adaptive_runtime_runner_artifacts(fixture_runner_config(
            AdaptiveRuntimeRunnerMode::CapabilityProbe,
        ));
        let report = &artifacts.report;

        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.classification, "capability_downgraded_smoke");
        assert!(
            report
                .capability_downgrade_reasons
                .iter()
                .any(|reason| reason.contains("capability-probe mode"))
        );
    }

    #[test]
    fn adaptive_runtime_runner_permissioned_mode_requires_ack() {
        let mut config = fixture_runner_config(AdaptiveRuntimeRunnerMode::PermissionedReal);
        config.path_plan.test_dir = Some("artifacts/adaptive-runtime/runner/test-dir".to_owned());
        config.path_plan.scratch_mnt =
            Some("artifacts/adaptive-runtime/runner/scratch-mnt".to_owned());

        let report = build_adaptive_runtime_runner_report(config);

        assert!(!report.valid);
        assert!(!report.execution.permissioned_real_allowed);
        assert!(
            report
                .refusal_reasons
                .iter()
                .any(|reason| { reason.contains("FFS_ADAPTIVE_RUNTIME_REAL_RUN_ACK is required") })
        );
        assert!(fail_on_adaptive_runtime_runner_errors(&report).is_err());
    }

    #[test]
    fn adaptive_runtime_runner_permissioned_mode_rejects_unsafe_paths() {
        let mut config = fixture_runner_config(AdaptiveRuntimeRunnerMode::PermissionedReal);
        config.observed_ack_value = Some(DEFAULT_ADAPTIVE_RUNTIME_REAL_RUN_ACK_VALUE.to_owned());
        config.path_plan.test_dir = Some("/".to_owned());
        config.path_plan.scratch_mnt =
            Some("artifacts/adaptive-runtime/runner/scratch-mnt".to_owned());

        let report = build_adaptive_runtime_runner_report(config);

        assert!(!report.valid);
        assert!(!report.execution.permissioned_real_allowed);
        assert!(
            report
                .refusal_reasons
                .iter()
                .any(|reason| reason.contains("test_dir must live under artifact_root"))
        );
    }

    #[test]
    fn adaptive_runtime_runner_allows_absolute_artifact_roots() {
        let mut config = fixture_runner_config(AdaptiveRuntimeRunnerMode::DryRun);
        config.path_plan = default_adaptive_runtime_runner_path_plan(
            "/data/projects/frankenfs/artifacts/e2e/runner",
        );

        let report = build_adaptive_runtime_runner_report(config);

        assert!(report.valid, "{:?}", report.errors);
        assert!(
            report
                .path_plan
                .raw_stdout_path
                .starts_with("/data/projects/frankenfs/artifacts/e2e/runner")
        );
    }

    #[test]
    fn adaptive_runtime_runner_accepts_large_permissioned_host() {
        let mut config = fixture_runner_config(AdaptiveRuntimeRunnerMode::PermissionedReal);
        config.observed_ack_value = Some(DEFAULT_ADAPTIVE_RUNTIME_REAL_RUN_ACK_VALUE.to_owned());
        config.path_plan.test_dir = Some("artifacts/adaptive-runtime/runner/test-dir".to_owned());
        config.path_plan.scratch_mnt =
            Some("artifacts/adaptive-runtime/runner/scratch-mnt".to_owned());
        config.cleanup_status = AdaptiveRuntimeRunnerCleanupStatus::Clean;
        config.host_facts.cpu_count = 96;
        config.host_facts.ram_bytes = 512 * 1024 * 1024 * 1024;
        config.host_facts.numa_nodes = 2;
        config.host_facts.fuse_capability_summary.state =
            AdaptiveRuntimeFuseCapabilityState::Available;

        let report = build_adaptive_runtime_runner_report(config);

        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.classification, "accepted_large_host");
        assert!(report.execution.permissioned_real_allowed);
        assert!(report.ack.present);
        assert!(report.ack.matches_expected);
    }

    #[test]
    fn adaptive_runtime_runner_failed_cleanup_classifies_and_fails() {
        let mut config = fixture_runner_config(AdaptiveRuntimeRunnerMode::DryRun);
        config.cleanup_status = AdaptiveRuntimeRunnerCleanupStatus::Failed;

        let report = build_adaptive_runtime_runner_report(config);

        assert!(!report.valid);
        assert_eq!(report.classification, "failed_cleanup");
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("cleanup_status failed"))
        );
    }

    fn assert_paths_present(report: &AdaptiveRuntimeEvidenceReport, paths: &[&str]) {
        assert!(!report.valid);
        for path in paths {
            assert!(
                report.issues.iter().any(|issue| issue.path == *path),
                "missing issue path {path}; issues={:?}",
                report.issues
            );
        }
    }

    fn fixture_manifest() -> AdaptiveRuntimeEvidenceManifest {
        AdaptiveRuntimeEvidenceManifest {
            manifest_version: ADAPTIVE_RUNTIME_EVIDENCE_MANIFEST_VERSION,
            scenario_id: "adaptive_runtime_accepted_large_host".to_owned(),
            run_id: "adaptive-runtime-run-20260507T000000Z".to_owned(),
            runtime_mode: AdaptiveRuntimeMode::PerCore,
            read_write: true,
            host_fingerprint: AdaptiveRuntimeHostFingerprint {
                host_fingerprint: "permissioned-96c-512gb-2numa".to_owned(),
                cpu_count: 96,
                ram_bytes: 512 * 1024 * 1024 * 1024,
                numa_nodes: 2,
                kernel: "Linux 6.17.0-14-generic x86_64".to_owned(),
                lane: AdaptiveRuntimeHostLane::PermissionedLargeHost,
            },
            fuse_capability_summary: AdaptiveRuntimeFuseCapabilitySummary {
                state: AdaptiveRuntimeFuseCapabilityState::Available,
                detail: "/dev/fuse and fusermount3 available in permissioned lane".to_owned(),
            },
            backpressure_policy_id: "adaptive-runtime-default-v1".to_owned(),
            degradation_thresholds: AdaptiveRuntimeDegradationThresholds {
                throttle_dirty_ratio: 0.70,
                shed_dirty_ratio: 0.85,
                emergency_dirty_ratio: 0.95,
            },
            per_core_config: AdaptiveRuntimePerCoreConfig {
                enabled: true,
                worker_count: 64,
                queue_policy: "metadata/write/repair queues are isolated per core group".to_owned(),
                work_stealing: true,
            },
            resource_caps: AdaptiveRuntimeResourceCaps {
                max_duration_secs: 900,
                max_threads: 96,
                max_memory_bytes: 128 * 1024 * 1024 * 1024,
                max_temp_bytes: 64 * 1024 * 1024 * 1024,
                max_queue_depth: 4096,
            },
            artifact_paths: vec![
                "artifacts/adaptive-runtime/accepted-large-host/report.json".to_owned(),
                "artifacts/adaptive-runtime/accepted-large-host/summary.md".to_owned(),
                "artifacts/adaptive-runtime/accepted-large-host/manifest.json".to_owned(),
            ],
            raw_stdout_path: "artifacts/adaptive-runtime/accepted-large-host/stdout.log".to_owned(),
            raw_stderr_path: "artifacts/adaptive-runtime/accepted-large-host/stderr.log".to_owned(),
            raw_log_paths: vec![
                "artifacts/adaptive-runtime/accepted-large-host/structured.jsonl".to_owned(),
                "artifacts/adaptive-runtime/accepted-large-host/mount.log".to_owned(),
            ],
            cleanup_status: AdaptiveRuntimeCleanupStatus::Clean,
            controlling_ack_env: "FFS_ADAPTIVE_RUNTIME_REAL_RUN_ACK".to_owned(),
            controlling_ack_value: "adaptive-runtime-may-mount-and-generate-load".to_owned(),
            release_claim_state: AdaptiveRuntimeReleaseClaimState::AcceptedLargeHost,
            generated_at: "2026-05-07T00:00:00Z".to_owned(),
            expires_at: "2026-05-08T00:00:00Z".to_owned(),
            git_sha: "c87266f2".to_owned(),
            reproduction_command: format!(
                "cargo run -p ffs-harness -- validate-adaptive-runtime-manifest --manifest {DEFAULT_ADAPTIVE_RUNTIME_EVIDENCE_MANIFEST}"
            ),
        }
    }

    fn fixture_runner_config(mode: AdaptiveRuntimeRunnerMode) -> AdaptiveRuntimeRunnerConfig {
        AdaptiveRuntimeRunnerConfig {
            mode,
            path_plan: default_adaptive_runtime_runner_path_plan(
                "artifacts/adaptive-runtime/runner",
            ),
            ack_env: DEFAULT_ADAPTIVE_RUNTIME_REAL_RUN_ACK_ENV.to_owned(),
            ack_value: DEFAULT_ADAPTIVE_RUNTIME_REAL_RUN_ACK_VALUE.to_owned(),
            observed_ack_value: None,
            generated_at: "2026-05-07T00:00:00Z".to_owned(),
            git_sha: "c87266f2".to_owned(),
            reproduction_command:
                "cargo run -p ffs-harness -- adaptive-runtime-runner --artifact-root artifacts/adaptive-runtime/runner"
                    .to_owned(),
            host_facts: AdaptiveRuntimeRunnerHostFacts {
                host_fingerprint: "local-smoke-16c-64gb-1numa".to_owned(),
                cpu_count: 16,
                ram_bytes: 64 * 1024 * 1024 * 1024,
                numa_nodes: 1,
                kernel: "Linux 6.17.0-14-generic x86_64".to_owned(),
                fuse_capability_summary: AdaptiveRuntimeFuseCapabilitySummary {
                    state: AdaptiveRuntimeFuseCapabilityState::Available,
                    detail: "fixture FUSE available".to_owned(),
                },
            },
            cleanup_status: AdaptiveRuntimeRunnerCleanupStatus::NotStartedDryRun,
        }
    }

    fn workspace_path(relative: &str) -> String {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative)
            .display()
            .to_string()
    }
}
