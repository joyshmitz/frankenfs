#![allow(clippy::module_name_repetitions, clippy::too_many_lines)]
#![forbid(unsafe_code)]

//! Machine-readable performance baseline manifest for `bd-rchk5.1`.
//!
//! This module validates the benchmark workload contract without running heavy
//! benchmarks. Benchmark execution belongs to later measurement beads.

use crate::artifact_manifest::{
    ArtifactCategory, ArtifactEntry, ArtifactManifest, EnvironmentFingerprint, GateVerdict,
    ManifestBuilder, ScenarioResult, validate_manifest,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

pub const PERFORMANCE_BASELINE_MANIFEST_SCHEMA_VERSION: u32 = 1;

const REQUIRED_ENVIRONMENT_FIELDS: [&str; 21] = [
    "manifest_version",
    "git_sha",
    "built_with",
    "os",
    "host_id",
    "worker_id",
    "cpu_model",
    "cpu_cores_logical",
    "cpu_cores_physical",
    "ram_total_gb",
    "storage_class",
    "governor",
    "mitigations",
    "kernel.version",
    "fuse.version",
    "kernel_fuse_mode",
    "cargo_profile",
    "target_dir",
    "resource_limits.cpu_cores",
    "resource_limits.memory_gib",
    "capabilities.fuse",
];

const REQUIRED_LOG_FIELDS: [&str; 38] = [
    "workload_id",
    "claim_tier_before",
    "claim_tier_after",
    "baseline_id",
    "baseline_artifact_hash",
    "current_artifact_id",
    "current_artifact_hash",
    "environment_fingerprint",
    "command",
    "profile",
    "target_dir",
    "artifact_path",
    "metric_unit",
    "observed_value",
    "comparison_target",
    "warn_percent",
    "fail_percent",
    "max_cv",
    "freshness_window_days",
    "overhead_budget",
    "runtime_seconds",
    "memory_mib",
    "instrumentation_overhead_percent",
    "stale_baseline_expiry_days",
    "noise_decision",
    "stale_decision",
    "budget_decision",
    "overhead_decision",
    "comparison_verdict",
    "public_claim_state",
    "release_claim_effect",
    "docs_wording_id",
    "statistical_summary",
    "raw_stdout_path",
    "raw_stderr_path",
    "environment_manifest",
    "output_path",
    "reproduction_command",
];

const REQUIRED_WORKLOAD_KINDS: [PerformanceWorkloadKind; 5] = [
    PerformanceWorkloadKind::CoreNonMounted,
    PerformanceWorkloadKind::PermissionedMounted,
    PerformanceWorkloadKind::RepairScrubRefresh,
    PerformanceWorkloadKind::CliInspectParity,
    PerformanceWorkloadKind::LongCampaignObservation,
];

const REQUIRED_FIXTURE_CLASSIFICATIONS: [PerformanceEvidenceClassification; 12] = [
    PerformanceEvidenceClassification::Pass,
    PerformanceEvidenceClassification::Warn,
    PerformanceEvidenceClassification::Fail,
    PerformanceEvidenceClassification::Noisy,
    PerformanceEvidenceClassification::Stale,
    PerformanceEvidenceClassification::Missing,
    PerformanceEvidenceClassification::MissingBaseline,
    PerformanceEvidenceClassification::EnvironmentMismatch,
    PerformanceEvidenceClassification::BudgetExceeded,
    PerformanceEvidenceClassification::InstrumentationOverheadExceeded,
    PerformanceEvidenceClassification::DegradedAccepted,
    PerformanceEvidenceClassification::Blocked,
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceBaselineManifest {
    pub schema_version: u32,
    pub manifest_id: String,
    pub shared_qa_schema_version: u32,
    pub profile: String,
    pub artifact_root_template: String,
    pub allowed_capabilities: Vec<String>,
    pub required_environment_fields: Vec<String>,
    pub required_log_fields: Vec<String>,
    pub workloads: Vec<PerformanceWorkload>,
    #[serde(default)]
    pub fixture_evidence: Vec<PerformanceFixtureEvidence>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceWorkload {
    pub workload_id: String,
    pub workstream: String,
    pub description: String,
    pub command_template: String,
    pub workload_kind: PerformanceWorkloadKind,
    pub cargo_profile: String,
    pub target_dir_template: String,
    pub kernel_fuse_mode: PerformanceKernelFuseMode,
    pub required_capabilities: Vec<String>,
    pub skip_semantics: PerformanceSkipSemantics,
    pub dataset: String,
    pub input_fixture_hash: String,
    pub image_size_mib: u64,
    pub warmup_runs: u32,
    pub measured_runs: u32,
    pub metric_unit: PerformanceMetricUnit,
    pub comparison_target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing_data_note: Option<String>,
    pub threshold: PerformanceThreshold,
    pub required_raw_logs: Vec<String>,
    pub quarantine_policy: PerformanceQuarantinePolicy,
    pub claim_policy: PerformanceClaimPolicy,
    pub output_artifact: PerformanceOutputArtifact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceWorkloadKind {
    CoreNonMounted,
    PermissionedMounted,
    RepairScrubRefresh,
    CliInspectParity,
    LongCampaignObservation,
}

impl PerformanceWorkloadKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::CoreNonMounted => "core_non_mounted",
            Self::PermissionedMounted => "permissioned_mounted",
            Self::RepairScrubRefresh => "repair_scrub_refresh",
            Self::CliInspectParity => "cli_inspect_parity",
            Self::LongCampaignObservation => "long_campaign_observation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceKernelFuseMode {
    NotRequired,
    HostCapabilitySkip,
    PermissionedRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceSkipSemantics {
    NeverSkip,
    CapabilitySkip,
    HostQuarantine,
    LongCampaignDeferred,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceQuarantinePolicy {
    pub stale_baseline_expiry_days: u32,
    pub claim_when_quarantined: PerformancePublicClaimState,
    pub follow_up_bead: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformancePublicClaimState {
    Unknown,
    Experimental,
    FixtureSmokeOnly,
    MeasuredLocal,
    MeasuredAuthoritative,
    RegressionFree,
    DegradedButAccepted,
    Blocked,
}

impl PerformancePublicClaimState {
    #[must_use]
    pub const fn is_safe_quarantine_claim(self) -> bool {
        matches!(self, Self::Unknown | Self::Experimental | Self::Blocked)
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Experimental => "experimental",
            Self::FixtureSmokeOnly => "fixture_smoke_only",
            Self::MeasuredLocal => "measured_local",
            Self::MeasuredAuthoritative => "measured_authoritative",
            Self::RegressionFree => "regression_free",
            Self::DegradedButAccepted => "degraded_but_accepted",
            Self::Blocked => "blocked",
        }
    }

    #[must_use]
    pub const fn is_stronger_than_experimental(self) -> bool {
        matches!(
            self,
            Self::FixtureSmokeOnly
                | Self::MeasuredLocal
                | Self::MeasuredAuthoritative
                | Self::RegressionFree
                | Self::DegradedButAccepted
        )
    }

    #[must_use]
    pub const fn requires_authoritative_evidence(self) -> bool {
        matches!(self, Self::MeasuredAuthoritative | Self::RegressionFree)
    }

    #[must_use]
    pub const fn capped_at_measured_local(self) -> Self {
        match self {
            Self::MeasuredAuthoritative | Self::RegressionFree => Self::MeasuredLocal,
            other => other,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceClaimPolicy {
    pub clean_claim_tier: PerformancePublicClaimState,
    pub freshness_window_days: u32,
    pub overhead_budget: PerformanceOverheadBudget,
    pub release_claim_effect: PerformanceReleaseClaimEffect,
    pub docs_wording_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PerformanceOverheadBudget {
    pub max_runtime_seconds: f64,
    pub max_memory_mib: u64,
    pub max_instrumentation_overhead_percent: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceReleaseClaimEffect {
    NoPublicUpgrade,
    ExperimentalOnly,
    FixtureSmokeClaim,
    LocalClaim,
    AuthoritativeClaim,
    RegressionFreeClaim,
    DowngradeToExperimental,
    BlockRelease,
}

impl PerformanceReleaseClaimEffect {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NoPublicUpgrade => "no_public_upgrade",
            Self::ExperimentalOnly => "experimental_only",
            Self::FixtureSmokeClaim => "fixture_smoke_claim",
            Self::LocalClaim => "local_claim",
            Self::AuthoritativeClaim => "authoritative_claim",
            Self::RegressionFreeClaim => "regression_free_claim",
            Self::DowngradeToExperimental => "downgrade_to_experimental",
            Self::BlockRelease => "block_release",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceMetricUnit {
    Nanoseconds,
    Microseconds,
    Milliseconds,
    OpsPerSec,
    MbPerSec,
}

impl PerformanceMetricUnit {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Nanoseconds => "nanoseconds",
            Self::Microseconds => "microseconds",
            Self::Milliseconds => "milliseconds",
            Self::OpsPerSec => "ops_per_sec",
            Self::MbPerSec => "mb_per_sec",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PerformanceThreshold {
    pub warn_percent: f64,
    pub fail_percent: f64,
    pub max_cv: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceEvidenceClassification {
    Pass,
    Warn,
    Fail,
    Noisy,
    Stale,
    Missing,
    MissingBaseline,
    EnvironmentMismatch,
    BudgetExceeded,
    InstrumentationOverheadExceeded,
    #[serde(rename = "degraded_but_accepted")]
    DegradedAccepted,
    Blocked,
}

impl PerformanceEvidenceClassification {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::Noisy => "noisy",
            Self::Stale => "stale",
            Self::Missing => "missing",
            Self::MissingBaseline => "missing_baseline",
            Self::EnvironmentMismatch => "environment_mismatch",
            Self::BudgetExceeded => "budget_exceeded",
            Self::InstrumentationOverheadExceeded => "instrumentation_overhead_exceeded",
            Self::DegradedAccepted => "degraded_but_accepted",
            Self::Blocked => "blocked",
        }
    }

    #[must_use]
    pub const fn needs_quarantine(self) -> bool {
        matches!(
            self,
            Self::Fail
                | Self::Noisy
                | Self::Stale
                | Self::Missing
                | Self::MissingBaseline
                | Self::EnvironmentMismatch
                | Self::BudgetExceeded
                | Self::InstrumentationOverheadExceeded
        )
    }

    #[must_use]
    pub const fn requires_follow_up(self) -> bool {
        matches!(self, Self::Blocked) || self.needs_quarantine()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceMeasurementState {
    Measured,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceEvidenceAuthority {
    FixtureSmoke,
    Local,
    Authoritative,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PerformanceStatisticalSummary {
    pub sample_count: u32,
    pub median: f64,
    pub p95: f64,
    pub p99: f64,
    pub coefficient_of_variation: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceFixtureEvidence {
    pub fixture_id: String,
    pub workload_id: String,
    pub claim_tier_before: PerformancePublicClaimState,
    pub evidence_authority: PerformanceEvidenceAuthority,
    pub measurement_state: PerformanceMeasurementState,
    pub baseline_id: String,
    pub baseline_artifact_hash: String,
    pub current_artifact_id: String,
    pub current_artifact_hash: String,
    pub environment_fingerprint: String,
    pub environment_matches_claim_lane: bool,
    pub baseline_age_days: u32,
    pub observed_value: f64,
    pub delta_percent: f64,
    pub coefficient_of_variation: f64,
    pub statistical_summary: PerformanceStatisticalSummary,
    pub runtime_seconds: f64,
    pub memory_mib: u64,
    pub instrumentation_overhead_percent: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_degradation_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
    pub docs_wording_id: String,
    pub output_path: String,
    pub raw_stdout_path: String,
    pub raw_stderr_path: String,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceOutputArtifact {
    pub path_template: String,
    pub category: ArtifactCategory,
    pub content_type: String,
    pub aggregate_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceCommandExpansion {
    pub workload_id: String,
    pub command: String,
    pub cargo_profile: String,
    pub target_dir: String,
    pub artifact_path: String,
    pub workload_kind: String,
    pub kernel_fuse_mode: PerformanceKernelFuseMode,
    pub skip_semantics: PerformanceSkipSemantics,
    pub metric_unit: String,
    pub comparison_target: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceEvidenceReport {
    pub fixture_id: String,
    pub workload_id: String,
    pub claim_tier_before: PerformancePublicClaimState,
    pub claim_tier_after: PerformancePublicClaimState,
    pub evidence_authority: PerformanceEvidenceAuthority,
    pub baseline_id: String,
    pub baseline_artifact_hash: String,
    pub current_artifact_id: String,
    pub current_artifact_hash: String,
    pub environment_fingerprint: String,
    pub environment_matches_claim_lane: bool,
    pub metric_unit: String,
    pub observed_value: f64,
    pub threshold: PerformanceThreshold,
    pub baseline_age_days: u32,
    pub freshness_window_days: u32,
    pub overhead_budget: PerformanceOverheadBudget,
    pub runtime_seconds: f64,
    pub memory_mib: u64,
    pub instrumentation_overhead_percent: f64,
    pub statistical_summary: PerformanceStatisticalSummary,
    pub stale_baseline_expiry_days: u32,
    pub coefficient_of_variation: f64,
    pub noise_decision: String,
    pub stale_decision: String,
    pub budget_decision: String,
    pub overhead_decision: String,
    pub comparison_verdict: PerformanceEvidenceClassification,
    pub public_claim_state: PerformancePublicClaimState,
    pub release_claim_effect: PerformanceReleaseClaimEffect,
    pub docs_wording_id: String,
    pub follow_up_bead: String,
    pub output_path: String,
    pub raw_stdout_path: String,
    pub raw_stderr_path: String,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceBaselineManifestReport {
    pub schema_version: u32,
    pub manifest_id: String,
    pub valid: bool,
    pub workload_count: usize,
    pub shared_qa_schema_version: u32,
    pub required_environment_fields: Vec<String>,
    pub required_log_fields: Vec<String>,
    pub command_expansions: Vec<PerformanceCommandExpansion>,
    pub workload_kind_counts: BTreeMap<String, usize>,
    pub missing_required_workload_kinds: Vec<String>,
    pub fixture_evidence_reports: Vec<PerformanceEvidenceReport>,
    pub fixture_classification_counts: BTreeMap<String, usize>,
    pub quarantined_workloads: Vec<String>,
    pub sample_artifact_manifest_errors: Vec<String>,
    pub errors: Vec<String>,
}

pub fn load_performance_baseline_manifest(path: &Path) -> Result<PerformanceBaselineManifest> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read performance manifest {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("invalid performance manifest JSON {}", path.display()))
}

#[must_use]
pub fn validate_performance_baseline_manifest(
    manifest: &PerformanceBaselineManifest,
    artifact_root: &str,
) -> PerformanceBaselineManifestReport {
    let mut errors = Vec::new();
    validate_manifest_shape(manifest, &mut errors);
    let command_expansions = expand_performance_commands(manifest, artifact_root);
    let workload_kind_counts = count_workload_kinds(manifest);
    let missing_required_workload_kinds = missing_required_workload_kinds(&workload_kind_counts);
    errors.extend(
        missing_required_workload_kinds
            .iter()
            .map(|kind| format!("missing workload kind {kind}")),
    );
    let fixture_evidence_reports = validate_fixture_evidence(manifest, &mut errors);
    let fixture_classification_counts = count_fixture_classifications(&fixture_evidence_reports);
    let missing_fixture_classifications =
        missing_required_fixture_classifications(&fixture_classification_counts);
    errors.extend(
        missing_fixture_classifications
            .iter()
            .map(|class| format!("missing fixture evidence classification {class}")),
    );
    let quarantined_workloads = fixture_evidence_reports
        .iter()
        .filter(|row| row.comparison_verdict.needs_quarantine())
        .map(|row| row.workload_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let sample_artifact_manifest =
        build_performance_sample_artifact_manifest(manifest, artifact_root);
    let sample_artifact_manifest_errors = validate_manifest(&sample_artifact_manifest)
        .into_iter()
        .map(|error| format!("{error:?}"))
        .collect::<Vec<_>>();
    errors.extend(
        sample_artifact_manifest_errors
            .iter()
            .map(|error| format!("sample artifact manifest invalid: {error}")),
    );

    PerformanceBaselineManifestReport {
        schema_version: PERFORMANCE_BASELINE_MANIFEST_SCHEMA_VERSION,
        manifest_id: manifest.manifest_id.clone(),
        valid: errors.is_empty(),
        workload_count: manifest.workloads.len(),
        shared_qa_schema_version: manifest.shared_qa_schema_version,
        required_environment_fields: manifest.required_environment_fields.clone(),
        required_log_fields: manifest.required_log_fields.clone(),
        command_expansions,
        workload_kind_counts,
        missing_required_workload_kinds,
        fixture_evidence_reports,
        fixture_classification_counts,
        quarantined_workloads,
        sample_artifact_manifest_errors,
        errors,
    }
}

#[must_use]
pub fn expand_performance_commands(
    manifest: &PerformanceBaselineManifest,
    artifact_root: &str,
) -> Vec<PerformanceCommandExpansion> {
    manifest
        .workloads
        .iter()
        .map(|workload| {
            let artifact_path = expand_template(
                &workload.output_artifact.path_template,
                manifest,
                workload,
                artifact_root,
            );
            PerformanceCommandExpansion {
                workload_id: workload.workload_id.clone(),
                command: expand_template(
                    &workload.command_template,
                    manifest,
                    workload,
                    artifact_root,
                ),
                cargo_profile: workload.cargo_profile.clone(),
                target_dir: expand_template(
                    &workload.target_dir_template,
                    manifest,
                    workload,
                    artifact_root,
                ),
                artifact_path,
                workload_kind: workload.workload_kind.label().to_owned(),
                kernel_fuse_mode: workload.kernel_fuse_mode,
                skip_semantics: workload.skip_semantics,
                metric_unit: workload.metric_unit.label().to_owned(),
                comparison_target: workload.comparison_target.clone(),
            }
        })
        .collect()
}

#[must_use]
pub fn build_performance_sample_artifact_manifest(
    manifest: &PerformanceBaselineManifest,
    artifact_root: &str,
) -> ArtifactManifest {
    let mut builder = ManifestBuilder::new(
        "performance_baseline_manifest_dry_run",
        "performance_baseline_manifest",
        "2026-05-03T00:00:00Z",
    )
    .bead_id("bd-rchk5.1")
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
        "performance_manifest_validate",
        ScenarioResult::Pass,
        Some("performance baseline manifest dry-run validation"),
        0.0,
    )
    .artifact(ArtifactEntry {
        path: format!("{artifact_root}/manifest_validation_report.json"),
        category: ArtifactCategory::BenchmarkReport,
        content_type: Some("application/json".to_owned()),
        size_bytes: 0,
        sha256: None,
        redacted: false,
        metadata: BTreeMap::from([
            ("manifest_id".to_owned(), manifest.manifest_id.clone()),
            ("bead_id".to_owned(), "bd-rchk5.1".to_owned()),
        ]),
    });

    for expansion in expand_performance_commands(manifest, artifact_root) {
        builder = builder.artifact(ArtifactEntry {
            path: expansion.artifact_path,
            category: ArtifactCategory::BenchmarkBaseline,
            content_type: Some("application/json".to_owned()),
            size_bytes: 0,
            sha256: None,
            redacted: false,
            metadata: BTreeMap::from([
                ("workload_id".to_owned(), expansion.workload_id),
                ("metric_unit".to_owned(), expansion.metric_unit),
                ("comparison_target".to_owned(), expansion.comparison_target),
                ("target_dir".to_owned(), expansion.target_dir),
                ("workload_kind".to_owned(), expansion.workload_kind),
                (
                    "claim_policy".to_owned(),
                    "validated_by_performance_manifest_report".to_owned(),
                ),
            ]),
        });
    }

    builder.verdict(GateVerdict::Pass).build()
}

pub fn fail_on_performance_baseline_manifest_errors(
    report: &PerformanceBaselineManifestReport,
) -> Result<()> {
    if report.valid {
        Ok(())
    } else {
        bail!(
            "performance baseline manifest validation failed with {} error(s)",
            report.errors.len()
        )
    }
}

fn validate_manifest_shape(manifest: &PerformanceBaselineManifest, errors: &mut Vec<String>) {
    if manifest.schema_version != PERFORMANCE_BASELINE_MANIFEST_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version {} expected {}",
            manifest.schema_version, PERFORMANCE_BASELINE_MANIFEST_SCHEMA_VERSION
        ));
    }
    validate_nonempty("manifest_id", &manifest.manifest_id, errors);
    validate_nonempty("profile", &manifest.profile, errors);
    validate_nonempty(
        "artifact_root_template",
        &manifest.artifact_root_template,
        errors,
    );
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
    if manifest.workloads.is_empty() {
        errors.push("workloads must not be empty".to_owned());
    }

    let allowed = manifest
        .allowed_capabilities
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut workload_ids = BTreeMap::<&str, usize>::new();
    for workload in &manifest.workloads {
        validate_workload(workload, manifest.profile.as_str(), &allowed, errors);
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
    workload: &PerformanceWorkload,
    manifest_profile: &str,
    allowed_capabilities: &BTreeSet<&str>,
    errors: &mut Vec<String>,
) {
    validate_nonempty("workload_id", &workload.workload_id, errors);
    validate_nonempty("workstream", &workload.workstream, errors);
    validate_nonempty("description", &workload.description, errors);
    validate_nonempty("command_template", &workload.command_template, errors);
    validate_nonempty("cargo_profile", &workload.cargo_profile, errors);
    validate_nonempty("target_dir_template", &workload.target_dir_template, errors);
    validate_nonempty("dataset", &workload.dataset, errors);
    validate_nonempty("input_fixture_hash", &workload.input_fixture_hash, errors);
    validate_nonempty("comparison_target", &workload.comparison_target, errors);
    if !workload.command_template.contains("{profile}") {
        errors.push(format!(
            "workload {} command_template must include {{profile}}",
            workload.workload_id
        ));
    }
    if workload.cargo_profile != manifest_profile {
        errors.push(format!(
            "workload {} cargo_profile must match manifest profile {}",
            workload.workload_id, manifest_profile
        ));
    }
    if !workload.target_dir_template.contains("{workload_id}") {
        errors.push(format!(
            "workload {} target_dir_template must include {{workload_id}}",
            workload.workload_id
        ));
    }
    if !is_sha256_ref(&workload.input_fixture_hash) {
        errors.push(format!(
            "workload {} input_fixture_hash must be sha256:<64 hex chars>",
            workload.workload_id
        ));
    }
    if workload.required_capabilities.is_empty() {
        errors.push(format!(
            "workload {} must declare required_capabilities",
            workload.workload_id
        ));
    }
    for capability in &workload.required_capabilities {
        if !allowed_capabilities.contains(capability.as_str()) {
            errors.push(format!(
                "workload {} references unknown capability {}",
                workload.workload_id, capability
            ));
        }
    }
    validate_kernel_fuse_mode(workload, errors);
    if workload.warmup_runs == 0 || workload.measured_runs == 0 {
        errors.push(format!(
            "workload {} warmup_runs and measured_runs must be positive",
            workload.workload_id
        ));
    }
    if workload.threshold.warn_percent <= 0.0
        || workload.threshold.fail_percent <= workload.threshold.warn_percent
    {
        errors.push(format!(
            "workload {} threshold must satisfy 0 < warn_percent < fail_percent",
            workload.workload_id
        ));
    }
    if workload.threshold.max_cv <= 0.0 || workload.threshold.max_cv > 1.0 {
        errors.push(format!(
            "workload {} max_cv must be in (0, 1]",
            workload.workload_id
        ));
    }
    validate_required_raw_logs(workload, errors);
    validate_quarantine_policy(workload, errors);
    validate_claim_policy(workload, errors);
    validate_artifact(workload, errors);
}

fn validate_kernel_fuse_mode(workload: &PerformanceWorkload, errors: &mut Vec<String>) {
    let requires_fuse = workload
        .required_capabilities
        .iter()
        .any(|capability| capability == "fuse");
    if workload.kernel_fuse_mode == PerformanceKernelFuseMode::PermissionedRequired
        && !requires_fuse
    {
        errors.push(format!(
            "workload {} permissioned FUSE mode must require fuse capability",
            workload.workload_id
        ));
    }
    if workload.workload_kind == PerformanceWorkloadKind::PermissionedMounted
        && workload.skip_semantics != PerformanceSkipSemantics::CapabilitySkip
    {
        errors.push(format!(
            "workload {} mounted workloads must use capability_skip semantics",
            workload.workload_id
        ));
    }
    if workload.workload_kind == PerformanceWorkloadKind::LongCampaignObservation
        && workload.skip_semantics != PerformanceSkipSemantics::LongCampaignDeferred
    {
        errors.push(format!(
            "workload {} long campaigns must use long_campaign_deferred semantics",
            workload.workload_id
        ));
    }
}

fn validate_required_raw_logs(workload: &PerformanceWorkload, errors: &mut Vec<String>) {
    let logs = workload
        .required_raw_logs
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for required in ["stdout", "stderr"] {
        if !logs.contains(required) {
            errors.push(format!(
                "workload {} required_raw_logs missing {required}",
                workload.workload_id
            ));
        }
    }
}

fn validate_quarantine_policy(workload: &PerformanceWorkload, errors: &mut Vec<String>) {
    if workload.quarantine_policy.stale_baseline_expiry_days == 0 {
        errors.push(format!(
            "workload {} stale_baseline_expiry_days must be positive",
            workload.workload_id
        ));
    }
    if !workload
        .quarantine_policy
        .claim_when_quarantined
        .is_safe_quarantine_claim()
    {
        errors.push(format!(
            "workload {} quarantined performance evidence may only claim unknown or experimental",
            workload.workload_id
        ));
    }
    if workload.quarantine_policy.follow_up_bead.trim().is_empty() {
        errors.push(format!(
            "workload {} quarantine policy must link follow_up_bead",
            workload.workload_id
        ));
    }
}

fn validate_claim_policy(workload: &PerformanceWorkload, errors: &mut Vec<String>) {
    let policy = &workload.claim_policy;
    validate_nonempty(
        "claim_policy.docs_wording_id",
        &policy.docs_wording_id,
        errors,
    );
    if policy.freshness_window_days == 0 {
        errors.push(format!(
            "workload {} claim freshness_window_days must be positive",
            workload.workload_id
        ));
    }
    if policy.freshness_window_days > workload.quarantine_policy.stale_baseline_expiry_days {
        errors.push(format!(
            "workload {} claim freshness_window_days must not exceed stale_baseline_expiry_days",
            workload.workload_id
        ));
    }
    if policy.overhead_budget.max_runtime_seconds <= 0.0
        || policy.overhead_budget.max_memory_mib == 0
        || policy.overhead_budget.max_instrumentation_overhead_percent <= 0.0
    {
        errors.push(format!(
            "workload {} claim overhead_budget values must be positive",
            workload.workload_id
        ));
    }
    if policy.clean_claim_tier.requires_authoritative_evidence()
        && !matches!(
            policy.release_claim_effect,
            PerformanceReleaseClaimEffect::AuthoritativeClaim
                | PerformanceReleaseClaimEffect::RegressionFreeClaim
        )
    {
        errors.push(format!(
            "workload {} authoritative claim tiers require authoritative release_claim_effect",
            workload.workload_id
        ));
    }
    if policy.clean_claim_tier == PerformancePublicClaimState::MeasuredLocal
        && !matches!(
            policy.release_claim_effect,
            PerformanceReleaseClaimEffect::LocalClaim
                | PerformanceReleaseClaimEffect::AuthoritativeClaim
                | PerformanceReleaseClaimEffect::RegressionFreeClaim
        )
    {
        errors.push(format!(
            "workload {} measured-local claim tier requires local or stronger release_claim_effect",
            workload.workload_id
        ));
    }
    if policy.clean_claim_tier == PerformancePublicClaimState::FixtureSmokeOnly
        && policy.release_claim_effect != PerformanceReleaseClaimEffect::FixtureSmokeClaim
    {
        errors.push(format!(
            "workload {} fixture-smoke claim tier requires fixture_smoke_claim release effect",
            workload.workload_id
        ));
    }
    if policy.clean_claim_tier.is_safe_quarantine_claim()
        && policy.release_claim_effect != PerformanceReleaseClaimEffect::ExperimentalOnly
        && policy.release_claim_effect != PerformanceReleaseClaimEffect::NoPublicUpgrade
    {
        errors.push(format!(
            "workload {} experimental/unknown clean claim tier must not publish stronger release wording",
            workload.workload_id
        ));
    }
}

fn validate_artifact(workload: &PerformanceWorkload, errors: &mut Vec<String>) {
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
    if !artifact.path_template.contains("{workload_id}") {
        errors.push(format!(
            "workload {} artifact path_template must include {{workload_id}}",
            workload.workload_id
        ));
    }
    if !artifact.aggregate_key.contains("rows[]") {
        errors.push(format!(
            "workload {} aggregate_key must identify an aggregatable rows[] field",
            workload.workload_id
        ));
    }
    if !matches!(
        artifact.category,
        ArtifactCategory::BenchmarkBaseline | ArtifactCategory::BenchmarkReport
    ) {
        errors.push(format!(
            "workload {} artifact category must be benchmark_baseline or benchmark_report",
            workload.workload_id
        ));
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

fn validate_fixture_evidence(
    manifest: &PerformanceBaselineManifest,
    errors: &mut Vec<String>,
) -> Vec<PerformanceEvidenceReport> {
    if manifest.fixture_evidence.is_empty() {
        errors.push("fixture_evidence must not be empty".to_owned());
        return Vec::new();
    }

    let workloads = manifest
        .workloads
        .iter()
        .map(|workload| (workload.workload_id.as_str(), workload))
        .collect::<BTreeMap<_, _>>();
    let mut fixture_ids = BTreeSet::new();
    let mut reports = Vec::new();

    for fixture in &manifest.fixture_evidence {
        validate_nonempty("fixture_id", &fixture.fixture_id, errors);
        if !fixture_ids.insert(fixture.fixture_id.as_str()) {
            errors.push(format!("duplicate fixture_id {}", fixture.fixture_id));
        }
        let Some(workload) = workloads.get(fixture.workload_id.as_str()).copied() else {
            errors.push(format!(
                "fixture {} references unknown workload {}",
                fixture.fixture_id, fixture.workload_id
            ));
            continue;
        };
        validate_nonempty("baseline_id", &fixture.baseline_id, errors);
        validate_nonempty(
            "baseline_artifact_hash",
            &fixture.baseline_artifact_hash,
            errors,
        );
        validate_nonempty("current_artifact_id", &fixture.current_artifact_id, errors);
        validate_nonempty(
            "current_artifact_hash",
            &fixture.current_artifact_hash,
            errors,
        );
        validate_nonempty(
            "environment_fingerprint",
            &fixture.environment_fingerprint,
            errors,
        );
        validate_nonempty("raw_stdout_path", &fixture.raw_stdout_path, errors);
        validate_nonempty("raw_stderr_path", &fixture.raw_stderr_path, errors);
        validate_nonempty(
            "reproduction_command",
            &fixture.reproduction_command,
            errors,
        );
        validate_nonempty("docs_wording_id", &fixture.docs_wording_id, errors);
        validate_nonempty("output_path", &fixture.output_path, errors);
        if !is_sha256_ref(&fixture.baseline_artifact_hash) {
            errors.push(format!(
                "fixture {} baseline_artifact_hash must be sha256:<64 hex chars>",
                fixture.fixture_id
            ));
        }
        if !is_sha256_ref(&fixture.current_artifact_hash) {
            errors.push(format!(
                "fixture {} current_artifact_hash must be sha256:<64 hex chars>",
                fixture.fixture_id
            ));
        }
        if fixture.measurement_state == PerformanceMeasurementState::Measured
            && fixture.observed_value <= 0.0
        {
            errors.push(format!(
                "fixture {} measured evidence must have positive observed_value",
                fixture.fixture_id
            ));
        }
        if fixture.coefficient_of_variation < 0.0 {
            errors.push(format!(
                "fixture {} coefficient_of_variation must be non-negative",
                fixture.fixture_id
            ));
        }
        validate_statistical_summary(fixture, workload, errors);
        if fixture.runtime_seconds < 0.0 {
            errors.push(format!(
                "fixture {} runtime_seconds must be non-negative",
                fixture.fixture_id
            ));
        }
        if fixture.instrumentation_overhead_percent < 0.0 {
            errors.push(format!(
                "fixture {} instrumentation_overhead_percent must be non-negative",
                fixture.fixture_id
            ));
        }

        let classification = classify_fixture_evidence(workload, fixture);
        let public_claim_state = public_claim_state_for_classification(workload, classification);
        validate_public_claim_state(
            workload,
            fixture,
            classification,
            public_claim_state,
            errors,
        );
        if classification.requires_follow_up() {
            if workload.quarantine_policy.follow_up_bead.trim().is_empty() {
                errors.push(format!(
                    "fixture {} requires follow-up for workload {} without follow_up_bead",
                    fixture.fixture_id, workload.workload_id
                ));
            }
            if !workload
                .quarantine_policy
                .claim_when_quarantined
                .is_safe_quarantine_claim()
                && classification.needs_quarantine()
            {
                errors.push(format!(
                    "fixture {} quarantined workload {} would overclaim public performance state",
                    fixture.fixture_id, workload.workload_id
                ));
            }
        }

        reports.push(PerformanceEvidenceReport {
            fixture_id: fixture.fixture_id.clone(),
            workload_id: fixture.workload_id.clone(),
            claim_tier_before: fixture.claim_tier_before,
            claim_tier_after: public_claim_state,
            evidence_authority: fixture.evidence_authority,
            baseline_id: fixture.baseline_id.clone(),
            baseline_artifact_hash: fixture.baseline_artifact_hash.clone(),
            current_artifact_id: fixture.current_artifact_id.clone(),
            current_artifact_hash: fixture.current_artifact_hash.clone(),
            environment_fingerprint: fixture.environment_fingerprint.clone(),
            environment_matches_claim_lane: fixture.environment_matches_claim_lane,
            metric_unit: workload.metric_unit.label().to_owned(),
            observed_value: fixture.observed_value,
            threshold: workload.threshold,
            baseline_age_days: fixture.baseline_age_days,
            freshness_window_days: workload.claim_policy.freshness_window_days,
            overhead_budget: workload.claim_policy.overhead_budget,
            runtime_seconds: fixture.runtime_seconds,
            memory_mib: fixture.memory_mib,
            instrumentation_overhead_percent: fixture.instrumentation_overhead_percent,
            statistical_summary: fixture.statistical_summary,
            stale_baseline_expiry_days: workload.quarantine_policy.stale_baseline_expiry_days,
            coefficient_of_variation: fixture.coefficient_of_variation,
            noise_decision: if fixture.statistical_summary.coefficient_of_variation
                > workload.threshold.max_cv
            {
                "quarantine_noisy"
            } else {
                "noise_within_budget"
            }
            .to_owned(),
            stale_decision: if fixture.baseline_age_days
                > workload.claim_policy.freshness_window_days
            {
                "quarantine_stale"
            } else {
                "fresh"
            }
            .to_owned(),
            budget_decision: if fixture.runtime_seconds
                > workload.claim_policy.overhead_budget.max_runtime_seconds
                || fixture.memory_mib > workload.claim_policy.overhead_budget.max_memory_mib
            {
                "budget_exceeded"
            } else {
                "budget_within_limit"
            }
            .to_owned(),
            overhead_decision: if fixture.instrumentation_overhead_percent
                > workload
                    .claim_policy
                    .overhead_budget
                    .max_instrumentation_overhead_percent
            {
                "instrumentation_overhead_exceeded"
            } else {
                "instrumentation_overhead_within_limit"
            }
            .to_owned(),
            comparison_verdict: classification,
            public_claim_state,
            release_claim_effect: workload.claim_policy.release_claim_effect,
            docs_wording_id: fixture.docs_wording_id.clone(),
            follow_up_bead: workload.quarantine_policy.follow_up_bead.clone(),
            output_path: fixture.output_path.clone(),
            raw_stdout_path: fixture.raw_stdout_path.clone(),
            raw_stderr_path: fixture.raw_stderr_path.clone(),
            reproduction_command: fixture.reproduction_command.clone(),
        });
    }

    reports
}

fn validate_statistical_summary(
    fixture: &PerformanceFixtureEvidence,
    workload: &PerformanceWorkload,
    errors: &mut Vec<String>,
) {
    let summary = fixture.statistical_summary;
    if fixture.measurement_state == PerformanceMeasurementState::Measured {
        if summary.sample_count < workload.measured_runs {
            errors.push(format!(
                "fixture {} statistical_summary.sample_count must cover measured_runs",
                fixture.fixture_id
            ));
        }
        if summary.median <= 0.0 || summary.p95 <= 0.0 || summary.p99 <= 0.0 {
            errors.push(format!(
                "fixture {} statistical_summary percentiles must be positive",
                fixture.fixture_id
            ));
        }
        if summary.p95 < summary.median || summary.p99 < summary.p95 {
            errors.push(format!(
                "fixture {} statistical_summary must satisfy median <= p95 <= p99",
                fixture.fixture_id
            ));
        }
    }
    if summary.coefficient_of_variation < 0.0 {
        errors.push(format!(
            "fixture {} statistical_summary coefficient_of_variation must be non-negative",
            fixture.fixture_id
        ));
    }
    if (summary.coefficient_of_variation - fixture.coefficient_of_variation).abs() > f64::EPSILON {
        errors.push(format!(
            "fixture {} statistical_summary cv must match coefficient_of_variation",
            fixture.fixture_id
        ));
    }
}

fn classify_fixture_evidence(
    workload: &PerformanceWorkload,
    fixture: &PerformanceFixtureEvidence,
) -> PerformanceEvidenceClassification {
    if fixture.blocked_reason.is_some() {
        return PerformanceEvidenceClassification::Blocked;
    }
    if fixture.measurement_state == PerformanceMeasurementState::Missing {
        return PerformanceEvidenceClassification::Missing;
    }
    if fixture.baseline_id == "missing-baseline"
        || fixture.baseline_artifact_hash
            == "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    {
        return PerformanceEvidenceClassification::MissingBaseline;
    }
    if !fixture.environment_matches_claim_lane {
        return PerformanceEvidenceClassification::EnvironmentMismatch;
    }
    if fixture.baseline_age_days > workload.claim_policy.freshness_window_days {
        return PerformanceEvidenceClassification::Stale;
    }
    if fixture.statistical_summary.coefficient_of_variation > workload.threshold.max_cv {
        return PerformanceEvidenceClassification::Noisy;
    }
    if fixture.instrumentation_overhead_percent
        > workload
            .claim_policy
            .overhead_budget
            .max_instrumentation_overhead_percent
    {
        return PerformanceEvidenceClassification::InstrumentationOverheadExceeded;
    }
    if fixture.runtime_seconds > workload.claim_policy.overhead_budget.max_runtime_seconds
        || fixture.memory_mib > workload.claim_policy.overhead_budget.max_memory_mib
    {
        return PerformanceEvidenceClassification::BudgetExceeded;
    }
    if fixture.delta_percent > workload.threshold.fail_percent {
        if fixture.accepted_degradation_reason.is_some() {
            PerformanceEvidenceClassification::DegradedAccepted
        } else {
            PerformanceEvidenceClassification::Fail
        }
    } else if fixture.delta_percent > workload.threshold.warn_percent {
        PerformanceEvidenceClassification::Warn
    } else {
        PerformanceEvidenceClassification::Pass
    }
}

fn public_claim_state_for_classification(
    workload: &PerformanceWorkload,
    classification: PerformanceEvidenceClassification,
) -> PerformancePublicClaimState {
    match classification {
        PerformanceEvidenceClassification::Pass => workload.claim_policy.clean_claim_tier,
        PerformanceEvidenceClassification::Warn => workload
            .claim_policy
            .clean_claim_tier
            .capped_at_measured_local(),
        PerformanceEvidenceClassification::DegradedAccepted => {
            PerformancePublicClaimState::DegradedButAccepted
        }
        PerformanceEvidenceClassification::Blocked => PerformancePublicClaimState::Blocked,
        _ => workload.quarantine_policy.claim_when_quarantined,
    }
}

fn validate_public_claim_state(
    workload: &PerformanceWorkload,
    fixture: &PerformanceFixtureEvidence,
    classification: PerformanceEvidenceClassification,
    public_claim_state: PerformancePublicClaimState,
    errors: &mut Vec<String>,
) {
    if public_claim_state.is_stronger_than_experimental()
        && !matches!(
            classification,
            PerformanceEvidenceClassification::Pass
                | PerformanceEvidenceClassification::Warn
                | PerformanceEvidenceClassification::DegradedAccepted
        )
    {
        errors.push(format!(
            "fixture {} public performance claim stronger than experimental must fail closed for {:?}",
            fixture.fixture_id, classification
        ));
    }
    if public_claim_state.requires_authoritative_evidence()
        && fixture.evidence_authority != PerformanceEvidenceAuthority::Authoritative
    {
        errors.push(format!(
            "fixture {} public performance claim stronger than experimental must cite fresh authoritative evidence",
            fixture.fixture_id
        ));
    }
    if public_claim_state.requires_authoritative_evidence()
        && (fixture.baseline_age_days > workload.claim_policy.freshness_window_days
            || fixture.runtime_seconds > workload.claim_policy.overhead_budget.max_runtime_seconds
            || fixture.memory_mib > workload.claim_policy.overhead_budget.max_memory_mib
            || fixture.instrumentation_overhead_percent
                > workload
                    .claim_policy
                    .overhead_budget
                    .max_instrumentation_overhead_percent)
    {
        errors.push(format!(
            "fixture {} authoritative performance claim must be fresh and within budget",
            fixture.fixture_id
        ));
    }
}

fn count_workload_kinds(manifest: &PerformanceBaselineManifest) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for workload in &manifest.workloads {
        *counts
            .entry(workload.workload_kind.label().to_owned())
            .or_insert(0) += 1;
    }
    counts
}

fn missing_required_workload_kinds(counts: &BTreeMap<String, usize>) -> Vec<String> {
    REQUIRED_WORKLOAD_KINDS
        .iter()
        .map(|kind| kind.label().to_owned())
        .filter(|kind| !counts.contains_key(kind))
        .collect()
}

fn count_fixture_classifications(reports: &[PerformanceEvidenceReport]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for report in reports {
        *counts
            .entry(report.comparison_verdict.label().to_owned())
            .or_insert(0) += 1;
    }
    counts
}

fn missing_required_fixture_classifications(counts: &BTreeMap<String, usize>) -> Vec<String> {
    REQUIRED_FIXTURE_CLASSIFICATIONS
        .iter()
        .map(|classification| classification.label().to_owned())
        .filter(|classification| !counts.contains_key(classification))
        .collect()
}

fn is_sha256_ref(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_nonempty(field: &str, value: &str, errors: &mut Vec<String>) {
    if value.trim().is_empty() {
        errors.push(format!("{field} must not be empty"));
    }
}

fn expand_template(
    template: &str,
    manifest: &PerformanceBaselineManifest,
    workload: &PerformanceWorkload,
    artifact_root: &str,
) -> String {
    template
        .replace("{profile}", &manifest.profile)
        .replace("{artifact_dir}", artifact_root)
        .replace("{workload_id}", &workload.workload_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_manifest() -> PerformanceBaselineManifest {
        serde_json::from_str(include_str!(
            "../../../benchmarks/performance_baseline_manifest.json"
        ))
        .expect("checked-in performance manifest parses")
    }

    #[test]
    fn checked_in_manifest_validates_and_expands_commands() {
        let manifest = sample_manifest();
        let report =
            validate_performance_baseline_manifest(&manifest, "artifacts/performance/dry-run");
        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.workload_count, 12);
        assert_eq!(report.missing_required_workload_kinds, Vec::<String>::new());
        assert_eq!(
            report
                .fixture_classification_counts
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            vec![
                "blocked",
                "budget_exceeded",
                "degraded_but_accepted",
                "environment_mismatch",
                "fail",
                "instrumentation_overhead_exceeded",
                "missing",
                "missing_baseline",
                "noisy",
                "pass",
                "stale",
                "warn"
            ]
        );
        assert!(
            report
                .quarantined_workloads
                .iter()
                .any(|workload| workload == "mvcc_conflict_detection_rate")
        );
        assert_eq!(report.sample_artifact_manifest_errors, Vec::<String>::new());
        assert!(report.command_expansions.iter().any(|row| row.workload_id
            == "fuse_metadata_readdir_1k"
            && row.command.contains("artifacts/performance/dry-run")
            && row.command.contains("--out-json")
            && row.target_dir.contains("fuse_metadata_readdir_1k")
            && row.kernel_fuse_mode == PerformanceKernelFuseMode::PermissionedRequired));
        assert!(report.command_expansions.iter().any(|row| {
            row.workload_id == "block_cache_sharded_arc_concurrent_hot_read_64threads"
                && row
                    .command
                    .contains("block_cache_sharded_arc_concurrent_hot_read_64threads")
                && row
                    .target_dir
                    .contains("block_cache_sharded_arc_concurrent_hot_read_64threads")
                && row.kernel_fuse_mode == PerformanceKernelFuseMode::NotRequired
        }));
        assert!(report.command_expansions.iter().any(|row| {
            row.workload_id == "block_cache_sharded_s3fifo_concurrent_hot_read_64threads"
                && row
                    .command
                    .contains("block_cache_sharded_s3fifo_concurrent_hot_read_64threads")
                && row.command.contains("--features s3fifo")
                && row.kernel_fuse_mode == PerformanceKernelFuseMode::NotRequired
        }));
    }

    #[test]
    fn rejects_missing_workload_id() {
        let mut manifest = sample_manifest();
        manifest.workloads[0].workload_id.clear();
        let report = validate_performance_baseline_manifest(&manifest, "artifacts/perf");
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("workload_id must not be empty"))
        );
    }

    #[test]
    fn rejects_unknown_capability_names() {
        let mut manifest = sample_manifest();
        manifest.workloads[0]
            .required_capabilities
            .push("warp_drive".to_owned());
        let report = validate_performance_baseline_manifest(&manifest, "artifacts/perf");
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("unknown capability warp_drive"))
        );
    }

    #[test]
    fn rejects_invalid_units_during_parse() {
        let mut value = json!(sample_manifest());
        value["workloads"][0]["metric_unit"] = json!("furlongs_per_fortnight");
        let parsed = serde_json::from_value::<PerformanceBaselineManifest>(value);
        assert!(parsed.is_err());
    }

    #[test]
    fn rejects_missing_thresholds_during_parse() {
        let mut value = json!(sample_manifest());
        value["workloads"][0]
            .as_object_mut()
            .expect("workload object")
            .remove("threshold");
        let parsed = serde_json::from_value::<PerformanceBaselineManifest>(value);
        assert!(parsed.is_err());
    }

    #[test]
    fn rejects_missing_environment_fields() {
        let mut manifest = sample_manifest();
        manifest
            .required_environment_fields
            .retain(|field| field != "git_sha");
        let report = validate_performance_baseline_manifest(&manifest, "artifacts/perf");
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("required_environment_fields missing git_sha"))
        );
    }

    #[test]
    fn rejects_missing_worker_metadata_field() {
        let mut manifest = sample_manifest();
        manifest
            .required_environment_fields
            .retain(|field| field != "worker_id");
        let report = validate_performance_baseline_manifest(&manifest, "artifacts/perf");
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| { error.contains("required_environment_fields missing worker_id") })
        );
    }

    #[test]
    fn rejects_workload_missing_target_dir_template() {
        let mut manifest = sample_manifest();
        manifest.workloads[0].target_dir_template.clear();
        let report = validate_performance_baseline_manifest(&manifest, "artifacts/perf");
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| { error.contains("target_dir_template must not be empty") })
        );
    }

    #[test]
    fn rejects_invalid_input_fixture_hash() {
        let mut manifest = sample_manifest();
        manifest.workloads[0].input_fixture_hash = "abc123".to_owned();
        let report = validate_performance_baseline_manifest(&manifest, "artifacts/perf");
        assert!(!report.valid);
        assert!(
            report.errors.iter().any(|error| {
                error.contains("input_fixture_hash must be sha256:<64 hex chars>")
            })
        );
    }

    #[test]
    fn rejects_missing_raw_log_contract() {
        let mut manifest = sample_manifest();
        manifest.workloads[0]
            .required_raw_logs
            .retain(|field| field != "stderr");
        let report = validate_performance_baseline_manifest(&manifest, "artifacts/perf");
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("required_raw_logs missing stderr"))
        );
    }

    #[test]
    fn fixture_rows_cover_quarantine_states() {
        let manifest = sample_manifest();
        let report = validate_performance_baseline_manifest(&manifest, "artifacts/perf");
        let by_fixture = report
            .fixture_evidence_reports
            .iter()
            .map(|row| (row.fixture_id.as_str(), row))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            by_fixture["fixture_pass_core"].comparison_verdict,
            PerformanceEvidenceClassification::Pass
        );
        assert_eq!(
            by_fixture["fixture_warn_cli"].comparison_verdict,
            PerformanceEvidenceClassification::Warn
        );
        assert_eq!(
            by_fixture["fixture_fail_mvcc"].comparison_verdict,
            PerformanceEvidenceClassification::Fail
        );
        assert_eq!(
            by_fixture["fixture_noisy_repair"].comparison_verdict,
            PerformanceEvidenceClassification::Noisy
        );
        assert_eq!(
            by_fixture["fixture_stale_fuse"].comparison_verdict,
            PerformanceEvidenceClassification::Stale
        );
        assert_eq!(
            by_fixture["fixture_missing_long_campaign"].comparison_verdict,
            PerformanceEvidenceClassification::Missing
        );
        assert_eq!(
            by_fixture["fixture_missing_baseline_arc"].comparison_verdict,
            PerformanceEvidenceClassification::MissingBaseline
        );
        assert_eq!(
            by_fixture["fixture_environment_mismatch_fuse_read"].comparison_verdict,
            PerformanceEvidenceClassification::EnvironmentMismatch
        );
        assert_eq!(
            by_fixture["fixture_budget_exceeded_mvcc"].comparison_verdict,
            PerformanceEvidenceClassification::BudgetExceeded
        );
        assert_eq!(
            by_fixture["fixture_overhead_exceeded_repair_refresh"].comparison_verdict,
            PerformanceEvidenceClassification::InstrumentationOverheadExceeded
        );
        assert_eq!(
            by_fixture["fixture_degraded_accepted_fuse"].comparison_verdict,
            PerformanceEvidenceClassification::DegradedAccepted
        );
        assert_eq!(
            by_fixture["fixture_blocked_core"].comparison_verdict,
            PerformanceEvidenceClassification::Blocked
        );
    }

    #[test]
    fn quarantined_rows_downgrade_public_claims() {
        let manifest = sample_manifest();
        let report = validate_performance_baseline_manifest(&manifest, "artifacts/perf");
        for row in &report.fixture_evidence_reports {
            if row.comparison_verdict.needs_quarantine() {
                assert!(row.public_claim_state.is_safe_quarantine_claim());
                assert!(
                    row.follow_up_bead.starts_with("bd-"),
                    "missing follow-up bead for {}",
                    row.fixture_id
                );
            }
        }
    }

    #[test]
    fn important_quarantine_requires_follow_up_bead() {
        let mut manifest = sample_manifest();
        let workload = manifest
            .workloads
            .iter_mut()
            .find(|workload| workload.workload_id == "mvcc_conflict_detection_rate")
            .expect("fixture workload exists");
        workload.quarantine_policy.follow_up_bead.clear();
        let report = validate_performance_baseline_manifest(&manifest, "artifacts/perf");
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("quarantine policy must link follow_up_bead"))
        );
    }

    #[test]
    fn quarantined_workload_cannot_overclaim_public_state() {
        let mut manifest = sample_manifest();
        let workload = manifest
            .workloads
            .iter_mut()
            .find(|workload| workload.workload_id == "repair_lrc_encode_throughput")
            .expect("fixture workload exists");
        workload.quarantine_policy.claim_when_quarantined =
            PerformancePublicClaimState::MeasuredAuthoritative;
        let report = validate_performance_baseline_manifest(&manifest, "artifacts/perf");
        assert!(!report.valid);
        assert!(report.errors.iter().any(|error| {
            error
                .contains("quarantined performance evidence may only claim unknown or experimental")
        }));
    }

    #[test]
    fn claim_tiers_and_budget_decisions_are_reported() {
        let manifest = sample_manifest();
        let report = validate_performance_baseline_manifest(&manifest, "artifacts/perf");
        let by_fixture = report
            .fixture_evidence_reports
            .iter()
            .map(|row| (row.fixture_id.as_str(), row))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            by_fixture["fixture_pass_core"].claim_tier_after,
            PerformancePublicClaimState::RegressionFree
        );
        assert_eq!(
            by_fixture["fixture_warn_cli"].claim_tier_after,
            PerformancePublicClaimState::MeasuredLocal
        );
        assert_eq!(
            by_fixture["fixture_degraded_accepted_fuse"].claim_tier_after,
            PerformancePublicClaimState::DegradedButAccepted
        );
        assert_eq!(
            by_fixture["fixture_blocked_core"].claim_tier_after,
            PerformancePublicClaimState::Blocked
        );
        assert_eq!(
            by_fixture["fixture_budget_exceeded_mvcc"].budget_decision,
            "budget_exceeded"
        );
        assert_eq!(
            by_fixture["fixture_overhead_exceeded_repair_refresh"].overhead_decision,
            "instrumentation_overhead_exceeded"
        );
    }

    #[test]
    fn rejects_missing_claim_policy_during_parse() {
        let mut value = json!(sample_manifest());
        value["workloads"][0]
            .as_object_mut()
            .expect("workload object")
            .remove("claim_policy");
        let parsed = serde_json::from_value::<PerformanceBaselineManifest>(value);
        assert!(parsed.is_err());
    }

    #[test]
    fn rejects_invalid_claim_budget() {
        let mut manifest = sample_manifest();
        manifest.workloads[0]
            .claim_policy
            .overhead_budget
            .max_runtime_seconds = 0.0;
        let report = validate_performance_baseline_manifest(&manifest, "artifacts/perf");
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("claim overhead_budget values must be positive"))
        );
    }

    #[test]
    fn rejects_missing_statistical_summary_during_parse() {
        let mut value = json!(sample_manifest());
        value["fixture_evidence"][0]
            .as_object_mut()
            .expect("fixture object")
            .remove("statistical_summary");
        let parsed = serde_json::from_value::<PerformanceBaselineManifest>(value);
        assert!(parsed.is_err());
    }

    #[test]
    fn rejects_authoritative_claim_without_authoritative_evidence() {
        let mut manifest = sample_manifest();
        manifest.fixture_evidence[0].evidence_authority = PerformanceEvidenceAuthority::Local;
        let report = validate_performance_baseline_manifest(&manifest, "artifacts/perf");
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| { error.contains("must cite fresh authoritative evidence") })
        );
    }

    #[test]
    fn rejects_non_aggregatable_artifact_fields() {
        let mut manifest = sample_manifest();
        manifest.workloads[0].output_artifact.aggregate_key = "median_ns".to_owned();
        manifest.workloads[0].output_artifact.path_template = "results/static.json".to_owned();
        let report = validate_performance_baseline_manifest(&manifest, "artifacts/perf");
        assert!(!report.valid);
        assert!(report.errors.iter().any(|error| {
            error.contains("aggregate_key must identify an aggregatable rows[] field")
        }));
        assert!(
            report.errors.iter().any(|error| {
                error.contains("artifact path_template must include {workload_id}")
            })
        );
    }

    #[test]
    fn sample_artifact_manifest_maps_to_shared_qa_schema() {
        let manifest = sample_manifest();
        let artifact_manifest =
            build_performance_sample_artifact_manifest(&manifest, "artifacts/performance/dry-run");
        let errors = validate_manifest(&artifact_manifest);
        assert_eq!(errors, Vec::new());
        assert_eq!(artifact_manifest.gate_id, "performance_baseline_manifest");
        assert_eq!(artifact_manifest.bead_id.as_deref(), Some("bd-rchk5.1"));
        assert!(
            artifact_manifest
                .artifacts
                .iter()
                .any(|artifact| artifact.category == ArtifactCategory::BenchmarkBaseline)
        );
    }
}
