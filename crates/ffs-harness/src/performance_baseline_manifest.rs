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

const REQUIRED_ENVIRONMENT_FIELDS: [&str; 12] = [
    "manifest_version",
    "git_sha",
    "built_with",
    "os",
    "cpu_model",
    "cpu_cores_logical",
    "cpu_cores_physical",
    "ram_total_gb",
    "storage_class",
    "governor",
    "mitigations",
    "capabilities.fuse",
];

const REQUIRED_LOG_FIELDS: [&str; 11] = [
    "workload_id",
    "command",
    "profile",
    "artifact_path",
    "metric_unit",
    "comparison_target",
    "warn_percent",
    "fail_percent",
    "max_cv",
    "environment_manifest",
    "reproduction_command",
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
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceWorkload {
    pub workload_id: String,
    pub workstream: String,
    pub description: String,
    pub command_template: String,
    pub required_capabilities: Vec<String>,
    pub dataset: String,
    pub image_size_mib: u64,
    pub warmup_runs: u32,
    pub measured_runs: u32,
    pub metric_unit: PerformanceMetricUnit,
    pub comparison_target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing_data_note: Option<String>,
    pub threshold: PerformanceThreshold,
    pub output_artifact: PerformanceOutputArtifact,
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
    pub artifact_path: String,
    pub metric_unit: String,
    pub comparison_target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceBaselineManifestReport {
    pub schema_version: u32,
    pub manifest_id: String,
    pub valid: bool,
    pub workload_count: usize,
    pub shared_qa_schema_version: u32,
    pub required_environment_fields: Vec<String>,
    pub required_log_fields: Vec<String>,
    pub command_expansions: Vec<PerformanceCommandExpansion>,
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
                artifact_path,
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
        validate_workload(workload, &allowed, errors);
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
    allowed_capabilities: &BTreeSet<&str>,
    errors: &mut Vec<String>,
) {
    validate_nonempty("workload_id", &workload.workload_id, errors);
    validate_nonempty("workstream", &workload.workstream, errors);
    validate_nonempty("description", &workload.description, errors);
    validate_nonempty("command_template", &workload.command_template, errors);
    validate_nonempty("dataset", &workload.dataset, errors);
    validate_nonempty("comparison_target", &workload.comparison_target, errors);
    if !workload.command_template.contains("{profile}") {
        errors.push(format!(
            "workload {} command_template must include {{profile}}",
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
    validate_artifact(workload, errors);
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
        assert_eq!(report.workload_count, 9);
        assert_eq!(report.sample_artifact_manifest_errors, Vec::<String>::new());
        assert!(
            report
                .command_expansions
                .iter()
                .any(|row| row.workload_id == "fuse_metadata_readdir_1k"
                    && row.command.contains("artifacts/performance/dry-run"))
        );
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
