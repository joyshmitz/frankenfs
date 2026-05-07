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
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_ADAPTIVE_RUNTIME_EVIDENCE_MANIFEST: &str =
    "docs/adaptive-runtime-evidence-manifest.json";
pub const ADAPTIVE_RUNTIME_EVIDENCE_MANIFEST_VERSION: u32 = 1;
pub const ADAPTIVE_RUNTIME_MIN_CPU_COUNT: u32 = 64;
pub const ADAPTIVE_RUNTIME_MIN_RAM_BYTES: u64 = 256 * 1024 * 1024 * 1024;
pub const ADAPTIVE_RUNTIME_MIN_NUMA_NODES: u32 = 2;

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

    fn workspace_path(relative: &str) -> String {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative)
            .display()
            .to_string()
    }
}
