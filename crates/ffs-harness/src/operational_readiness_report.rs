#![forbid(unsafe_code)]

//! One-command operational readiness aggregation for `bd-rchk0.4.3`.
//!
//! The report consumes the existing artifact-manifest schema plus legacy
//! `scripts/e2e` `result.json` summaries. It intentionally stays read-only:
//! raw logs and artifacts remain where the producing gate wrote them, while
//! this module groups outcomes, preserves links, and separates product failures
//! from host or worker blockers.

use crate::artifact_manifest::{
    ArtifactManifest, GateVerdict, OperationalErrorClass, OperationalOutcomeClass, ScenarioOutcome,
    ScenarioResult, SkipReason,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

pub const READINESS_REPORT_SCHEMA_VERSION: u32 = 1;
const REQUIRED_WORKSTREAMS: [&str; 9] = [
    "xfstests",
    "fuse_lane",
    "mounted_scenario_matrix",
    "repair_policy",
    "writeback_cache",
    "fuzz_smoke",
    "performance",
    "proof_bundle",
    "release_gate",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalReadinessReportConfig {
    pub artifacts_dir: PathBuf,
    pub current_git_sha: Option<String>,
}

impl OperationalReadinessReportConfig {
    #[must_use]
    pub fn new(artifacts_dir: impl Into<PathBuf>) -> Self {
        Self {
            artifacts_dir: artifacts_dir.into(),
            current_git_sha: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationalReadinessReport {
    pub schema_version: u32,
    pub report_id: String,
    pub source_root: String,
    pub source_manifest_count: usize,
    pub source_legacy_summary_count: usize,
    pub ignored_json_count: usize,
    pub scenario_count: usize,
    pub totals: ReadinessCounts,
    pub workstreams: BTreeMap<String, ReadinessCounts>,
    pub required_workstreams_missing: Vec<String>,
    pub contract_failed: bool,
    pub contract_violations: Vec<ReadinessContractViolation>,
    pub duplicate_scenario_ids: Vec<String>,
    pub stale_git_shas: Vec<StaleGitSha>,
    pub missing_log_paths: Vec<MissingLogPath>,
    pub scenarios: Vec<ReadinessScenarioRow>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessCounts {
    pub pass: usize,
    pub fail: usize,
    pub skip: usize,
    pub error: usize,
    pub product_failures: usize,
    pub environment_blockers: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaleGitSha {
    pub source_path: String,
    pub gate_id: String,
    pub run_id: String,
    pub observed: String,
    pub expected: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissingLogPath {
    pub source_path: String,
    pub scenario_id: Option<String>,
    pub field: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessContractViolation {
    pub source_path: String,
    pub scenario_id: Option<String>,
    pub violation: String,
    pub remediation_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessOutcome {
    Pass,
    Fail,
    Skip,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessTaxonomyClass {
    Pass,
    ProductFailure,
    HostCapabilitySkip,
    AuthoritativeLaneUnavailable,
    HarnessFailure,
    UnsupportedByScope,
    StaleArtifact,
    MissingArtifact,
    NoisyMeasurement,
    SecurityRefusal,
    UnsafeRepairRefusal,
    PassWithExperimentalCaveat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessScenarioRow {
    pub source_path: String,
    pub source_kind: SourceKind,
    pub gate_id: String,
    pub run_id: String,
    pub workstream: String,
    pub scenario_id: String,
    pub outcome: ReadinessOutcome,
    pub taxonomy_class: ReadinessTaxonomyClass,
    pub failure_kind: Option<String>,
    pub skip_reason: Option<String>,
    pub environment_only_blocker: bool,
    pub product_failure: bool,
    pub git_commit: String,
    pub stale_git_sha: bool,
    pub manifest_schema_version: Option<u32>,
    pub host_fingerprint: Option<String>,
    pub stdout_path: Option<String>,
    pub stderr_path: Option<String>,
    pub artifact_refs: Vec<String>,
    pub controlling_artifact: Option<String>,
    pub reproduction_command: Option<String>,
    pub cleanup_status: Option<String>,
    pub remediation_hint: Option<String>,
    pub owner_bead: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    ArtifactManifest,
    LegacyE2eSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct LegacyE2eSummary {
    gate_id: String,
    run_id: String,
    git_context: LegacyGitContext,
    scenarios: Vec<LegacyScenario>,
    verdict: String,
    duration_secs: u64,
    log_file: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct LegacyGitContext {
    commit: String,
    branch: String,
    clean: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct LegacyScenario {
    scenario_id: String,
    outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

#[derive(Default)]
struct ReportBuilder {
    source_manifest_count: usize,
    source_legacy_summary_count: usize,
    ignored_json_count: usize,
    totals: ReadinessCounts,
    workstreams: BTreeMap<String, ReadinessCounts>,
    seen_scenarios: BTreeMap<String, usize>,
    stale_git_shas: Vec<StaleGitSha>,
    missing_log_paths: Vec<MissingLogPath>,
    contract_violations: Vec<ReadinessContractViolation>,
    scenarios: Vec<ReadinessScenarioRow>,
}

#[derive(Clone, Copy)]
struct LogSource<'a> {
    source_path: &'a Path,
    source_path_text: &'a str,
    scenario_id: Option<&'a str>,
}

struct TaxonomyInput<'a> {
    outcome: ReadinessOutcome,
    error_class: Option<OperationalErrorClass>,
    skip_reason: Option<SkipReason>,
    workstream: &'a str,
    stale_git_sha: bool,
    artifact_refs: &'a [String],
    detail: Option<&'a str>,
    remediation_hint: Option<&'a str>,
}

pub fn build_operational_readiness_report(
    config: &OperationalReadinessReportConfig,
) -> Result<OperationalReadinessReport> {
    let source_paths = collect_json_paths(&config.artifacts_dir)
        .with_context(|| format!("failed to scan {}", config.artifacts_dir.display()))?;
    let mut builder = ReportBuilder::default();

    for source_path in source_paths {
        let text = fs::read_to_string(&source_path)
            .with_context(|| format!("failed to read {}", source_path.display()))?;
        if let Ok(manifest) = serde_json::from_str::<ArtifactManifest>(&text) {
            builder.ingest_manifest(config, &source_path, &manifest);
        } else if let Ok(summary) = serde_json::from_str::<LegacyE2eSummary>(&text) {
            builder.ingest_legacy_summary(config, &source_path, &summary);
        } else {
            builder.ignored_json_count += 1;
        }
    }

    Ok(builder.finish(config))
}

#[must_use]
pub fn render_operational_readiness_markdown(report: &OperationalReadinessReport) -> String {
    let mut out = String::new();
    writeln!(&mut out, "# FrankenFS Operational Readiness").ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "- Source root: `{}`", report.source_root).ok();
    writeln!(
        &mut out,
        "- Sources: {} manifests, {} legacy summaries, {} ignored JSON files",
        report.source_manifest_count, report.source_legacy_summary_count, report.ignored_json_count
    )
    .ok();
    writeln!(
        &mut out,
        "- Totals: pass={} fail={} skip={} error={} product_failures={} environment_blockers={}",
        report.totals.pass,
        report.totals.fail,
        report.totals.skip,
        report.totals.error,
        report.totals.product_failures,
        report.totals.environment_blockers
    )
    .ok();
    writeln!(
        &mut out,
        "- Diagnostics: duplicate_scenarios={} stale_git_shas={} missing_logs={}",
        report.duplicate_scenario_ids.len(),
        report.stale_git_shas.len(),
        report.missing_log_paths.len()
    )
    .ok();
    writeln!(
        &mut out,
        "- Contract: failed={} missing_workstreams={} violations={}",
        report.contract_failed,
        report.required_workstreams_missing.len(),
        report.contract_violations.len()
    )
    .ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "## Workstreams").ok();
    for (workstream, counts) in &report.workstreams {
        writeln!(
            &mut out,
            "- `{workstream}`: pass={} fail={} skip={} error={} product_failures={} environment_blockers={}",
            counts.pass,
            counts.fail,
            counts.skip,
            counts.error,
            counts.product_failures,
            counts.environment_blockers
        )
        .ok();
    }
    writeln!(&mut out).ok();
    writeln!(&mut out, "## Scenarios").ok();
    writeln!(
        &mut out,
        "| Workstream | Scenario | Outcome | Failure kind | Source | Logs |"
    )
    .ok();
    writeln!(&mut out, "|---|---|---:|---|---|---|").ok();
    for row in &report.scenarios {
        let failure_kind = row.failure_kind.as_deref().unwrap_or("");
        let taxonomy_class = serialized_enum_name(row.taxonomy_class);
        let logs = render_log_links(row);
        writeln!(
            &mut out,
            "| `{}` | `{}` | `{:?}` | {} / {} | `{}` | {} |",
            row.workstream,
            row.scenario_id,
            row.outcome,
            taxonomy_class,
            failure_kind,
            row.source_path,
            logs
        )
        .ok();
    }
    out
}

impl ReportBuilder {
    fn ingest_manifest(
        &mut self,
        config: &OperationalReadinessReportConfig,
        source_path: &Path,
        manifest: &ArtifactManifest,
    ) {
        self.source_manifest_count += 1;
        let source_path_text = display_path(source_path);
        let stale_git_sha = self.record_stale_git_sha(
            config,
            &source_path_text,
            &manifest.gate_id,
            &manifest.run_id,
            &manifest.git_context.commit,
        );
        self.record_manifest_run_logs(config, source_path, &source_path_text, manifest);

        for (scenario_id, scenario) in &manifest.scenarios {
            let operational = manifest.operational_scenarios.get(scenario_id);
            if let Some(record) = operational {
                self.record_scenario_log_paths(
                    config,
                    LogSource {
                        source_path,
                        source_path_text: &source_path_text,
                        scenario_id: Some(scenario_id),
                    },
                    manifest,
                    &record.stdout_path,
                    &record.stderr_path,
                );
            }
            self.push_row(build_manifest_row(
                &source_path_text,
                manifest,
                scenario_id,
                scenario,
                operational,
                stale_git_sha,
            ));
        }

        if manifest.verdict == GateVerdict::Skip && manifest.scenarios.is_empty() {
            let row = ReadinessScenarioRow {
                source_path: source_path_text,
                source_kind: SourceKind::ArtifactManifest,
                gate_id: manifest.gate_id.clone(),
                run_id: manifest.run_id.clone(),
                workstream: classify_workstream(&manifest.gate_id, "gate_skipped", &[]),
                scenario_id: "gate_skipped".to_owned(),
                outcome: ReadinessOutcome::Skip,
                taxonomy_class: ReadinessTaxonomyClass::AuthoritativeLaneUnavailable,
                failure_kind: None,
                skip_reason: Some("gate_verdict_skip".to_owned()),
                environment_only_blocker: true,
                product_failure: false,
                git_commit: manifest.git_context.commit.clone(),
                stale_git_sha,
                manifest_schema_version: Some(manifest.schema_version),
                host_fingerprint: Some(manifest_host_fingerprint(manifest)),
                stdout_path: None,
                stderr_path: None,
                artifact_refs: Vec::new(),
                controlling_artifact: None,
                reproduction_command: manifest
                    .operational_context
                    .as_ref()
                    .map(|context| context.command_line.join(" ")),
                cleanup_status: None,
                remediation_hint: Some(
                    "inspect gate-level skip reason in source manifest".to_owned(),
                ),
                owner_bead: manifest.bead_id.clone(),
                detail: None,
            };
            self.push_row(row);
        }
    }

    fn ingest_legacy_summary(
        &mut self,
        config: &OperationalReadinessReportConfig,
        source_path: &Path,
        summary: &LegacyE2eSummary,
    ) {
        self.source_legacy_summary_count += 1;
        let source_path_text = display_path(source_path);
        let stale_git_sha = self.record_stale_git_sha(
            config,
            &source_path_text,
            &summary.gate_id,
            &summary.run_id,
            &summary.git_context.commit,
        );
        self.record_log_path(
            config,
            LogSource {
                source_path,
                source_path_text: &source_path_text,
                scenario_id: None,
            },
            "log_file",
            &summary.log_file,
            &BTreeSet::new(),
        );

        for scenario in &summary.scenarios {
            let outcome = outcome_from_legacy(&scenario.outcome, &summary.verdict);
            let artifact_refs = vec![summary.log_file.clone()];
            let environment_only_blocker =
                is_environment_only_blocker(None, None, scenario.detail.as_deref());
            let product_failure = is_product_failure(outcome, None, environment_only_blocker);
            let workstream =
                classify_workstream(&summary.gate_id, &scenario.scenario_id, &artifact_refs);
            let taxonomy_class = classify_taxonomy(&TaxonomyInput {
                outcome,
                error_class: None,
                skip_reason: None,
                workstream: &workstream,
                stale_git_sha,
                artifact_refs: &artifact_refs,
                detail: scenario.detail.as_deref(),
                remediation_hint: scenario.detail.as_deref(),
            });
            let row = ReadinessScenarioRow {
                source_path: source_path_text.clone(),
                source_kind: SourceKind::LegacyE2eSummary,
                gate_id: summary.gate_id.clone(),
                run_id: summary.run_id.clone(),
                workstream,
                scenario_id: scenario.scenario_id.clone(),
                outcome,
                taxonomy_class,
                failure_kind: if product_failure {
                    Some("product_failure".to_owned())
                } else if environment_only_blocker {
                    Some("environment_blocker".to_owned())
                } else {
                    None
                },
                skip_reason: None,
                environment_only_blocker,
                product_failure,
                git_commit: summary.git_context.commit.clone(),
                stale_git_sha,
                manifest_schema_version: None,
                host_fingerprint: Some(format!(
                    "legacy:{}:{}",
                    summary.git_context.branch, summary.git_context.clean
                )),
                stdout_path: Some(summary.log_file.clone()),
                stderr_path: None,
                artifact_refs,
                controlling_artifact: Some(summary.log_file.clone()),
                reproduction_command: Some(format!("inspect legacy e2e log {}", summary.log_file)),
                cleanup_status: None,
                remediation_hint: scenario.detail.clone(),
                owner_bead: None,
                detail: scenario.detail.clone(),
            };
            self.push_row(row);
        }
    }

    fn finish(mut self, config: &OperationalReadinessReportConfig) -> OperationalReadinessReport {
        let duplicate_scenario_ids = self
            .seen_scenarios
            .iter()
            .filter(|(_, count)| **count > 1)
            .map(|(scenario_id, _)| scenario_id.clone())
            .collect();
        let required_workstreams_missing = REQUIRED_WORKSTREAMS
            .iter()
            .filter(|workstream| !self.workstreams.contains_key(**workstream))
            .map(|workstream| (*workstream).to_owned())
            .collect::<Vec<_>>();

        self.scenarios.sort_by(|left, right| {
            left.workstream
                .cmp(&right.workstream)
                .then_with(|| left.gate_id.cmp(&right.gate_id))
                .then_with(|| left.scenario_id.cmp(&right.scenario_id))
        });

        OperationalReadinessReport {
            schema_version: READINESS_REPORT_SCHEMA_VERSION,
            report_id: format!(
                "operational-readiness:{}:{}",
                display_path(&config.artifacts_dir),
                config.current_git_sha.as_deref().unwrap_or("unknown")
            ),
            source_root: display_path(&config.artifacts_dir),
            source_manifest_count: self.source_manifest_count,
            source_legacy_summary_count: self.source_legacy_summary_count,
            ignored_json_count: self.ignored_json_count,
            scenario_count: self.scenarios.len(),
            totals: self.totals,
            workstreams: self.workstreams,
            contract_failed: !required_workstreams_missing.is_empty()
                || !self.contract_violations.is_empty()
                || !self.missing_log_paths.is_empty()
                || !self.stale_git_shas.is_empty(),
            required_workstreams_missing,
            contract_violations: self.contract_violations,
            duplicate_scenario_ids,
            stale_git_shas: self.stale_git_shas,
            missing_log_paths: self.missing_log_paths,
            scenarios: self.scenarios,
        }
    }

    fn push_row(&mut self, row: ReadinessScenarioRow) {
        self.seen_scenarios
            .entry(row.scenario_id.clone())
            .and_modify(|count| *count += 1)
            .or_insert(1);
        self.totals.record(&row);
        self.workstreams
            .entry(row.workstream.clone())
            .or_default()
            .record(&row);
        self.scenarios.push(row);
    }

    fn record_stale_git_sha(
        &mut self,
        config: &OperationalReadinessReportConfig,
        source_path: &str,
        gate_id: &str,
        run_id: &str,
        observed: &str,
    ) -> bool {
        let Some(expected) = config.current_git_sha.as_deref() else {
            return false;
        };
        if same_git_ref(observed, expected) {
            return false;
        }
        self.stale_git_shas.push(StaleGitSha {
            source_path: source_path.to_owned(),
            gate_id: gate_id.to_owned(),
            run_id: run_id.to_owned(),
            observed: observed.to_owned(),
            expected: expected.to_owned(),
        });
        true
    }

    fn record_manifest_run_logs(
        &mut self,
        config: &OperationalReadinessReportConfig,
        source_path: &Path,
        source_path_text: &str,
        manifest: &ArtifactManifest,
    ) {
        if let Some(context) = &manifest.operational_context {
            let artifacts = artifact_path_set(manifest);
            self.record_log_path(
                config,
                LogSource {
                    source_path,
                    source_path_text,
                    scenario_id: None,
                },
                "operational_context.stdout_path",
                &context.stdout_path,
                &artifacts,
            );
            self.record_log_path(
                config,
                LogSource {
                    source_path,
                    source_path_text,
                    scenario_id: None,
                },
                "operational_context.stderr_path",
                &context.stderr_path,
                &artifacts,
            );
        }
    }

    fn record_scenario_log_paths(
        &mut self,
        config: &OperationalReadinessReportConfig,
        source: LogSource<'_>,
        manifest: &ArtifactManifest,
        stdout_path: &str,
        stderr_path: &str,
    ) {
        let artifacts = artifact_path_set(manifest);
        self.record_log_path(config, source, "stdout_path", stdout_path, &artifacts);
        self.record_log_path(config, source, "stderr_path", stderr_path, &artifacts);
    }

    fn record_log_path(
        &mut self,
        config: &OperationalReadinessReportConfig,
        source: LogSource<'_>,
        field: &str,
        path: &str,
        artifact_paths: &BTreeSet<String>,
    ) {
        if log_path_is_resolved(
            &config.artifacts_dir,
            source.source_path,
            path,
            artifact_paths,
        ) {
            return;
        }
        self.missing_log_paths.push(MissingLogPath {
            source_path: source.source_path_text.to_owned(),
            scenario_id: source.scenario_id.map(str::to_owned),
            field: field.to_owned(),
            path: path.to_owned(),
        });
        self.contract_violations.push(ReadinessContractViolation {
            source_path: source.source_path_text.to_owned(),
            scenario_id: source.scenario_id.map(str::to_owned),
            violation: format!("missing required log path `{field}`: {path}"),
            remediation_id: "bd-un9xt:missing-log-path".to_owned(),
        });
    }
}

impl ReadinessCounts {
    fn record(&mut self, row: &ReadinessScenarioRow) {
        match row.outcome {
            ReadinessOutcome::Pass => self.pass += 1,
            ReadinessOutcome::Fail => self.fail += 1,
            ReadinessOutcome::Skip => self.skip += 1,
            ReadinessOutcome::Error => self.error += 1,
        }
        if row.product_failure {
            self.product_failures += 1;
        }
        if row.environment_only_blocker {
            self.environment_blockers += 1;
        }
    }
}

fn collect_json_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    collect_json_paths_inner(root, &mut paths)?;
    paths.sort();
    Ok(paths)
}

fn collect_json_paths_inner(root: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(root).with_context(|| format!("failed to read {}", root.display()))? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_json_paths_inner(&path, paths)?;
        } else if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            paths.push(path);
        }
    }
    Ok(())
}

fn artifact_path_set(manifest: &ArtifactManifest) -> BTreeSet<String> {
    manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.path.clone())
        .collect()
}

fn build_manifest_row(
    source_path_text: &str,
    manifest: &ArtifactManifest,
    scenario_id: &str,
    scenario: &ScenarioOutcome,
    operational: Option<&crate::artifact_manifest::OperationalScenarioRecord>,
    stale_git_sha: bool,
) -> ReadinessScenarioRow {
    let artifact_refs = operational
        .map(|record| record.artifact_refs.clone())
        .unwrap_or_default();
    let workstream = classify_workstream(&manifest.gate_id, scenario_id, &artifact_refs);
    let outcome = operational.map_or_else(
        || outcome_from_scenario_result(scenario.outcome),
        |record| outcome_from_operational(record.classification, record.actual_outcome),
    );
    let error_class = operational.and_then(|record| record.error_class);
    let skip_reason = operational.and_then(|record| record.skip_reason);
    let detail = scenario.detail.clone();
    let environment_only_blocker =
        is_environment_only_blocker(error_class, skip_reason, detail.as_deref());
    let product_failure = is_product_failure(outcome, error_class, environment_only_blocker);
    let taxonomy_class = classify_taxonomy(&TaxonomyInput {
        outcome,
        error_class,
        skip_reason,
        workstream: &workstream,
        stale_git_sha,
        artifact_refs: &artifact_refs,
        detail: detail.as_deref(),
        remediation_hint: operational.and_then(|record| record.remediation_hint.as_deref()),
    });
    let reproduction_command = manifest
        .operational_context
        .as_ref()
        .map(|context| context.command_line.join(" "));
    let controlling_artifact = artifact_refs.first().cloned();

    ReadinessScenarioRow {
        source_path: source_path_text.to_owned(),
        source_kind: SourceKind::ArtifactManifest,
        gate_id: manifest.gate_id.clone(),
        run_id: manifest.run_id.clone(),
        workstream,
        scenario_id: scenario_id.to_owned(),
        outcome,
        taxonomy_class,
        failure_kind: error_class.map(serialized_enum_name),
        skip_reason: skip_reason.map(serialized_enum_name),
        environment_only_blocker,
        product_failure,
        git_commit: manifest.git_context.commit.clone(),
        stale_git_sha,
        manifest_schema_version: Some(manifest.schema_version),
        host_fingerprint: Some(manifest_host_fingerprint(manifest)),
        stdout_path: operational.map(|record| record.stdout_path.clone()),
        stderr_path: operational.map(|record| record.stderr_path.clone()),
        artifact_refs,
        controlling_artifact,
        reproduction_command,
        cleanup_status: operational.map(|record| serialized_enum_name(record.cleanup_status)),
        remediation_hint: operational.and_then(|record| record.remediation_hint.clone()),
        owner_bead: manifest.bead_id.clone(),
        detail,
    }
}

fn manifest_host_fingerprint(manifest: &ArtifactManifest) -> String {
    format!(
        "{}|{}|{}cpu|{}GiB|{}",
        manifest.environment.hostname,
        manifest.environment.cpu_model,
        manifest.environment.cpu_count,
        manifest.environment.memory_gib,
        manifest.environment.kernel
    )
}

fn log_path_is_resolved(
    root: &Path,
    source_path: &Path,
    log_path: &str,
    artifact_paths: &BTreeSet<String>,
) -> bool {
    if log_path.trim().is_empty() {
        return false;
    }
    if artifact_paths.contains(log_path) {
        return true;
    }

    let path = Path::new(log_path);
    if path.is_absolute() {
        return path.exists();
    }
    if root.join(path).exists() {
        return true;
    }
    source_path
        .parent()
        .is_some_and(|parent| parent.join(path).exists())
}

fn outcome_from_operational(
    classification: OperationalOutcomeClass,
    actual_outcome: ScenarioResult,
) -> ReadinessOutcome {
    match classification {
        OperationalOutcomeClass::Pass => ReadinessOutcome::Pass,
        OperationalOutcomeClass::Fail => ReadinessOutcome::Fail,
        OperationalOutcomeClass::Skip => ReadinessOutcome::Skip,
        OperationalOutcomeClass::Error => ReadinessOutcome::Error,
    }
    .max_by_actual_outcome(actual_outcome)
}

fn outcome_from_scenario_result(result: ScenarioResult) -> ReadinessOutcome {
    match result {
        ScenarioResult::Pass => ReadinessOutcome::Pass,
        ScenarioResult::Fail => ReadinessOutcome::Fail,
        ScenarioResult::Skip => ReadinessOutcome::Skip,
    }
}

fn outcome_from_legacy(raw_outcome: &str, raw_verdict: &str) -> ReadinessOutcome {
    match raw_outcome.to_ascii_uppercase().as_str() {
        "PASS" => ReadinessOutcome::Pass,
        "SKIP" => ReadinessOutcome::Skip,
        "FAIL" => {
            if raw_verdict.eq_ignore_ascii_case("ERROR") {
                ReadinessOutcome::Error
            } else {
                ReadinessOutcome::Fail
            }
        }
        _ => ReadinessOutcome::Error,
    }
}

trait OutcomeConsistency {
    fn max_by_actual_outcome(self, actual_outcome: ScenarioResult) -> Self;
}

impl OutcomeConsistency for ReadinessOutcome {
    fn max_by_actual_outcome(self, actual_outcome: ScenarioResult) -> Self {
        match (self, actual_outcome) {
            (Self::Pass, ScenarioResult::Fail) => Self::Fail,
            (Self::Pass, ScenarioResult::Skip) => Self::Skip,
            (outcome, _) => outcome,
        }
    }
}

fn classify_workstream(gate_id: &str, scenario_id: &str, artifact_refs: &[String]) -> String {
    let mut haystack = gate_id.to_ascii_lowercase();
    haystack.push(' ');
    haystack.push_str(&scenario_id.to_ascii_lowercase());
    for artifact in artifact_refs {
        haystack.push(' ');
        haystack.push_str(&artifact.to_ascii_lowercase());
    }

    if haystack.contains("release") && haystack.contains("gate") {
        "release_gate".to_owned()
    } else if haystack.contains("proof") || haystack.contains("bundle") {
        "proof_bundle".to_owned()
    } else if haystack.contains("xfstest") {
        "xfstests".to_owned()
    } else if haystack.contains("writeback") {
        "writeback_cache".to_owned()
    } else if haystack.contains("mounted") || haystack.contains("mount_matrix") {
        "mounted_scenario_matrix".to_owned()
    } else if haystack.contains("fuse") {
        "fuse_lane".to_owned()
    } else if haystack.contains("fuzz") {
        "fuzz_smoke".to_owned()
    } else if haystack.contains("repair") {
        "repair_policy".to_owned()
    } else if haystack.contains("perf") || haystack.contains("bench") {
        "performance".to_owned()
    } else {
        "other".to_owned()
    }
}

fn classify_taxonomy(input: &TaxonomyInput<'_>) -> ReadinessTaxonomyClass {
    let detail = input.detail.unwrap_or("").to_ascii_lowercase();
    let remediation_hint = input.remediation_hint.unwrap_or("").to_ascii_lowercase();
    let text = format!("{detail} {remediation_hint}");

    if input.stale_git_sha
        || matches!(
            input.error_class,
            Some(OperationalErrorClass::StaleTrackerToolingFailure)
        )
    {
        return ReadinessTaxonomyClass::StaleArtifact;
    }
    if input.artifact_refs.is_empty() {
        return ReadinessTaxonomyClass::MissingArtifact;
    }
    if text.contains("security") || text.contains("refusal") && text.contains("hostile") {
        return ReadinessTaxonomyClass::SecurityRefusal;
    }
    if text.contains("unsafe repair") || text.contains("unsafe_repair") {
        return ReadinessTaxonomyClass::UnsafeRepairRefusal;
    }
    if matches!(
        input.error_class,
        Some(
            OperationalErrorClass::WorkerDependencyMissing
                | OperationalErrorClass::FusePermissionSkip
                | OperationalErrorClass::RootOwnedBtrfsTestdirEacces
                | OperationalErrorClass::HostEnvironmentFailure
        )
    ) || matches!(
        input.skip_reason,
        Some(
            SkipReason::FuseUnavailable
                | SkipReason::FusePermissionDenied
                | SkipReason::WorkerDependencyMissing
                | SkipReason::RootOwnedBtrfsTestdirEacces
        )
    ) {
        return if text.contains("authoritative") || text.contains("required lane") {
            ReadinessTaxonomyClass::AuthoritativeLaneUnavailable
        } else {
            ReadinessTaxonomyClass::HostCapabilitySkip
        };
    }
    if matches!(
        input.error_class,
        Some(OperationalErrorClass::UnsupportedV1Scope)
    ) || matches!(input.skip_reason, Some(SkipReason::UnsupportedV1Scope))
    {
        return ReadinessTaxonomyClass::UnsupportedByScope;
    }
    if matches!(
        input.error_class,
        Some(OperationalErrorClass::HarnessBug | OperationalErrorClass::UnsafeCleanupFailure)
    ) {
        return ReadinessTaxonomyClass::HarnessFailure;
    }
    if matches!(
        input.error_class,
        Some(OperationalErrorClass::ResourceLimit)
    ) && input.workstream == "performance"
    {
        return ReadinessTaxonomyClass::NoisyMeasurement;
    }
    if matches!(
        input.error_class,
        Some(OperationalErrorClass::ProductFailure)
    ) {
        return ReadinessTaxonomyClass::ProductFailure;
    }
    if matches!(input.outcome, ReadinessOutcome::Pass)
        && (text.contains("experimental") || text.contains("caveat"))
    {
        return ReadinessTaxonomyClass::PassWithExperimentalCaveat;
    }
    match input.outcome {
        ReadinessOutcome::Pass => ReadinessTaxonomyClass::Pass,
        ReadinessOutcome::Fail => ReadinessTaxonomyClass::ProductFailure,
        ReadinessOutcome::Skip => ReadinessTaxonomyClass::HostCapabilitySkip,
        ReadinessOutcome::Error => ReadinessTaxonomyClass::HarnessFailure,
    }
}

fn is_environment_only_blocker(
    error_class: Option<OperationalErrorClass>,
    skip_reason: Option<SkipReason>,
    detail: Option<&str>,
) -> bool {
    if matches!(
        error_class,
        Some(
            OperationalErrorClass::WorkerDependencyMissing
                | OperationalErrorClass::FusePermissionSkip
                | OperationalErrorClass::RootOwnedBtrfsTestdirEacces
                | OperationalErrorClass::HostEnvironmentFailure
                | OperationalErrorClass::ResourceLimit
        )
    ) {
        return true;
    }
    if matches!(
        skip_reason,
        Some(
            SkipReason::FuseUnavailable
                | SkipReason::FusePermissionDenied
                | SkipReason::UserDisabled
                | SkipReason::WorkerDependencyMissing
                | SkipReason::RootOwnedBtrfsTestdirEacces
        )
    ) {
        return true;
    }

    let Some(detail) = detail else {
        return false;
    };
    let detail = detail.to_ascii_lowercase();
    detail.contains("fuse")
        || detail.contains("permission")
        || detail.contains("worker")
        || detail.contains("dependency")
        || detail.contains("environment")
}

fn is_product_failure(
    outcome: ReadinessOutcome,
    error_class: Option<OperationalErrorClass>,
    environment_only_blocker: bool,
) -> bool {
    if matches!(error_class, Some(OperationalErrorClass::ProductFailure)) {
        return true;
    }
    if error_class.is_some() {
        return false;
    }
    matches!(outcome, ReadinessOutcome::Fail) && !environment_only_blocker
}

fn serialized_enum_name<T>(value: T) -> String
where
    T: Serialize + std::fmt::Debug,
{
    serde_json::to_value(&value)
        .ok()
        .and_then(|json| json.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{value:?}"))
}

fn same_git_ref(observed: &str, expected: &str) -> bool {
    let observed = observed.trim();
    let expected = expected.trim();
    let observed_matches_expected = observed.starts_with(expected);
    let expected_matches_observed = expected.starts_with(observed);
    !observed.is_empty()
        && !expected.is_empty()
        && (observed_matches_expected || expected_matches_observed)
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
}

fn render_log_links(row: &ReadinessScenarioRow) -> String {
    let mut links = Vec::new();
    if let Some(path) = &row.stdout_path {
        links.push(format!("stdout `{path}`"));
    }
    if let Some(path) = &row.stderr_path {
        links.push(format!("stderr `{path}`"));
    }
    for artifact in &row.artifact_refs {
        links.push(format!("artifact `{artifact}`"));
    }
    links.join("<br>")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_manifest::{
        ArtifactCategory, ArtifactEntry, CleanupStatus, EnvironmentFingerprint,
        FuseCapabilityResult, GitContext, OperationalRunContext, OperationalScenarioRecord,
        WorkerContext,
    };
    use tempfile::TempDir;

    #[test]
    fn aggregates_mixed_operational_manifest_outcomes() {
        let fixture = ReadinessFixture::new();
        let manifest = sample_operational_manifest("abc123");
        fixture.write_manifest("operational.json", &manifest);

        let report = fixture.report(Some("abc123"));

        assert_eq!(report.source_manifest_count, 1);
        assert_eq!(report.scenario_count, 9);
        assert_eq!(report.totals.pass, 2);
        assert_eq!(report.totals.fail, 3);
        assert_eq!(report.totals.skip, 2);
        assert_eq!(report.totals.error, 2);
        assert_eq!(report.totals.product_failures, 2);
        assert_eq!(report.totals.environment_blockers, 3);
        assert!(!report.contract_failed);
        assert!(report.required_workstreams_missing.is_empty());
        assert!(report.workstreams.contains_key("xfstests"));
        assert!(report.workstreams.contains_key("fuse_lane"));
        assert!(report.workstreams.contains_key("mounted_scenario_matrix"));
        assert!(report.workstreams.contains_key("repair_policy"));
        assert!(report.workstreams.contains_key("writeback_cache"));
        assert!(report.workstreams.contains_key("fuzz_smoke"));
        assert!(report.workstreams.contains_key("performance"));
        assert!(report.workstreams.contains_key("proof_bundle"));
        assert!(report.workstreams.contains_key("release_gate"));
        assert!(report.scenarios.iter().any(|row| {
            row.scenario_id == "proof_bundle_stale"
                && row.taxonomy_class == ReadinessTaxonomyClass::StaleArtifact
        }));
        assert!(report.scenarios.iter().any(|row| {
            row.scenario_id == "release_gate_unsupported"
                && row.taxonomy_class == ReadinessTaxonomyClass::UnsupportedByScope
        }));
    }

    #[test]
    fn detects_duplicate_scenario_ids_and_stale_git_shas() {
        let fixture = ReadinessFixture::new();
        let first = sample_legacy_summary("oldsha", "shared_scenario");
        let second = sample_legacy_summary("newsha", "shared_scenario");
        fixture.write_legacy("first.json", &first);
        fixture.write_legacy("second.json", &second);

        let report = fixture.report(Some("newsha"));

        assert_eq!(report.source_legacy_summary_count, 2);
        assert_eq!(report.duplicate_scenario_ids, vec!["shared_scenario"]);
        assert_eq!(report.stale_git_shas.len(), 1);
        assert_eq!(report.stale_git_shas[0].observed, "oldsha");
    }

    #[test]
    fn reports_missing_log_paths_without_failing_aggregation() {
        let fixture = ReadinessFixture::new();
        let mut manifest = sample_operational_manifest("abc123");
        manifest
            .operational_scenarios
            .get_mut("mounted_ext4_rw")
            .expect("scenario exists")
            .stdout_path = "missing/stdout.log".to_owned();
        fixture.write_manifest("manifest.json", &manifest);

        let report = fixture.report(Some("abc123"));

        assert!(report.missing_log_paths.iter().any(|missing| {
            missing.scenario_id.as_deref() == Some("mounted_ext4_rw")
                && missing.field == "stdout_path"
        }));
        assert!(report.contract_failed);
        assert!(report.contract_violations.iter().any(|violation| {
            violation.scenario_id.as_deref() == Some("mounted_ext4_rw")
                && violation.violation.contains("missing required log path")
        }));
    }

    #[test]
    fn markdown_preserves_links_and_counts() {
        let fixture = ReadinessFixture::new();
        let manifest = sample_operational_manifest("abc123");
        fixture.write_manifest("operational.json", &manifest);

        let report = fixture.report(Some("abc123"));
        let markdown = render_operational_readiness_markdown(&report);

        assert!(markdown.contains("Totals: pass=2 fail=3 skip=2 error=2"));
        assert!(markdown.contains("`mounted_ext4_rw`"));
        assert!(markdown.contains("artifact `mounted/ext4_rw.json`"));
        assert!(markdown.contains("Contract: failed=false missing_workstreams=0 violations=0"));
    }

    #[test]
    fn taxonomy_covers_actionable_failure_contract_values() {
        let cases = [
            (
                ReadinessTaxonomyClass::ProductFailure,
                ReadinessOutcome::Fail,
                Some(OperationalErrorClass::ProductFailure),
                None,
                "repair_policy",
                false,
                &["repair/policy.json"][..],
                "",
                "open repair policy bead",
            ),
            (
                ReadinessTaxonomyClass::HostCapabilitySkip,
                ReadinessOutcome::Skip,
                Some(OperationalErrorClass::FusePermissionSkip),
                Some(SkipReason::FusePermissionDenied),
                "fuse_lane",
                false,
                &["fuse/capability.json"][..],
                "",
                "rerun with /dev/fuse access",
            ),
            (
                ReadinessTaxonomyClass::AuthoritativeLaneUnavailable,
                ReadinessOutcome::Skip,
                Some(OperationalErrorClass::HostEnvironmentFailure),
                Some(SkipReason::WorkerDependencyMissing),
                "mounted_scenario_matrix",
                false,
                &["mounted/capability.json"][..],
                "authoritative required lane unavailable",
                "rerun on permissioned worker",
            ),
            (
                ReadinessTaxonomyClass::HarnessFailure,
                ReadinessOutcome::Error,
                Some(OperationalErrorClass::HarnessBug),
                None,
                "xfstests",
                false,
                &["xfstests/raw.log"][..],
                "",
                "fix harness parser",
            ),
            (
                ReadinessTaxonomyClass::UnsupportedByScope,
                ReadinessOutcome::Skip,
                Some(OperationalErrorClass::UnsupportedV1Scope),
                Some(SkipReason::UnsupportedV1Scope),
                "release_gate",
                false,
                &["release/unsupported.json"][..],
                "",
                "explicit V1 non-goal",
            ),
            (
                ReadinessTaxonomyClass::StaleArtifact,
                ReadinessOutcome::Fail,
                Some(OperationalErrorClass::StaleTrackerToolingFailure),
                None,
                "proof_bundle",
                false,
                &["proof/stale.json"][..],
                "",
                "refresh proof bundle",
            ),
            (
                ReadinessTaxonomyClass::MissingArtifact,
                ReadinessOutcome::Error,
                None,
                None,
                "proof_bundle",
                false,
                &[][..],
                "",
                "attach missing report",
            ),
            (
                ReadinessTaxonomyClass::NoisyMeasurement,
                ReadinessOutcome::Error,
                Some(OperationalErrorClass::ResourceLimit),
                None,
                "performance",
                false,
                &["perf/baseline.json"][..],
                "",
                "rerun with isolated worker",
            ),
            (
                ReadinessTaxonomyClass::SecurityRefusal,
                ReadinessOutcome::Fail,
                Some(OperationalErrorClass::ProductFailure),
                None,
                "release_gate",
                false,
                &["security/refusal.json"][..],
                "security refusal for hostile proof path",
                "keep release blocked",
            ),
            (
                ReadinessTaxonomyClass::UnsafeRepairRefusal,
                ReadinessOutcome::Fail,
                Some(OperationalErrorClass::ProductFailure),
                None,
                "repair_policy",
                false,
                &["repair/refusal.json"][..],
                "unsafe repair refused before mutation",
                "use dry-run first",
            ),
            (
                ReadinessTaxonomyClass::PassWithExperimentalCaveat,
                ReadinessOutcome::Pass,
                None,
                None,
                "performance",
                false,
                &["perf/smoke.json"][..],
                "pass with experimental caveat",
                "",
            ),
        ];

        for (
            expected,
            outcome,
            error_class,
            skip_reason,
            workstream,
            stale_git_sha,
            artifact_refs,
            detail,
            remediation_hint,
        ) in cases
        {
            let artifact_refs = artifact_refs
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            assert_eq!(
                classify_taxonomy(&TaxonomyInput {
                    outcome,
                    error_class,
                    skip_reason,
                    workstream,
                    stale_git_sha,
                    artifact_refs: &artifact_refs,
                    detail: Some(detail),
                    remediation_hint: Some(remediation_hint),
                }),
                expected
            );
        }
    }

    struct ReadinessFixture {
        dir: TempDir,
    }

    impl ReadinessFixture {
        fn new() -> Self {
            Self {
                dir: TempDir::new().expect("tempdir"),
            }
        }

        fn report(&self, current_git_sha: Option<&str>) -> OperationalReadinessReport {
            let config = OperationalReadinessReportConfig {
                artifacts_dir: self.dir.path().to_path_buf(),
                current_git_sha: current_git_sha.map(str::to_owned),
            };
            build_operational_readiness_report(&config).expect("report builds")
        }

        fn write_manifest(&self, name: &str, manifest: &ArtifactManifest) {
            let path = self.dir.path().join(name);
            fs::write(
                path,
                serde_json::to_string_pretty(manifest).expect("manifest serializes"),
            )
            .expect("write manifest");
        }

        fn write_legacy(&self, name: &str, summary: &LegacyE2eSummary) {
            let path = self.dir.path().join(name);
            fs::write(
                path,
                serde_json::to_string_pretty(summary).expect("summary serializes"),
            )
            .expect("write summary");
        }
    }

    fn sample_operational_manifest(commit: &str) -> ArtifactManifest {
        let mut manifest = ArtifactManifest {
            schema_version: crate::artifact_manifest::SCHEMA_VERSION,
            run_id: "run-operational".to_owned(),
            created_at: "2026-05-03T00:00:00Z".to_owned(),
            gate_id: "operational_readiness".to_owned(),
            bead_id: Some("bd-rchk0.4.3".to_owned()),
            git_context: GitContext {
                commit: commit.to_owned(),
                branch: "main".to_owned(),
                clean: true,
            },
            environment: EnvironmentFingerprint {
                hostname: "host".to_owned(),
                cpu_model: "cpu".to_owned(),
                cpu_count: 64,
                memory_gib: 256,
                kernel: "Linux 6.17.0".to_owned(),
                rustc_version: "rustc 1.85.0".to_owned(),
                cargo_version: Some("cargo 1.85.0".to_owned()),
            },
            scenarios: BTreeMap::new(),
            operational_context: Some(OperationalRunContext {
                command_line: vec!["scripts/e2e/operational.sh".to_owned()],
                worker: WorkerContext {
                    host: "host".to_owned(),
                    worker_id: Some("worker-a".to_owned()),
                },
                fuse_capability: FuseCapabilityResult::PermissionDenied,
                stdout_path: "run/stdout.log".to_owned(),
                stderr_path: "run/stderr.log".to_owned(),
            }),
            operational_scenarios: BTreeMap::new(),
            artifacts: vec![
                artifact("run/stdout.log", ArtifactCategory::RawLog),
                artifact("run/stderr.log", ArtifactCategory::RawLog),
            ],
            verdict: GateVerdict::Fail,
            duration_secs: 7.0,
            retention: None,
        };

        for case in sample_cases() {
            add_case(&mut manifest, case);
        }
        manifest
    }

    #[derive(Clone, Copy)]
    struct Case {
        scenario_id: &'static str,
        gate_hint: &'static str,
        result: ScenarioResult,
        classification: OperationalOutcomeClass,
        error_class: Option<OperationalErrorClass>,
        skip_reason: Option<SkipReason>,
        remediation_hint: Option<&'static str>,
    }

    fn sample_cases() -> [Case; 9] {
        [
            Case {
                scenario_id: "xfstests_generic_subset",
                gate_hint: "xfstests/results.json",
                result: ScenarioResult::Pass,
                classification: OperationalOutcomeClass::Pass,
                error_class: None,
                skip_reason: None,
                remediation_hint: None,
            },
            Case {
                scenario_id: "fuse_capability_probe",
                gate_hint: "fuse/capability.json",
                result: ScenarioResult::Skip,
                classification: OperationalOutcomeClass::Skip,
                error_class: Some(OperationalErrorClass::FusePermissionSkip),
                skip_reason: Some(SkipReason::FusePermissionDenied),
                remediation_hint: Some("rerun on worker with /dev/fuse access"),
            },
            Case {
                scenario_id: "mounted_ext4_rw",
                gate_hint: "mounted/ext4_rw.json",
                result: ScenarioResult::Pass,
                classification: OperationalOutcomeClass::Pass,
                error_class: None,
                skip_reason: None,
                remediation_hint: None,
            },
            Case {
                scenario_id: "repair_policy_refusal",
                gate_hint: "repair/policy.json",
                result: ScenarioResult::Fail,
                classification: OperationalOutcomeClass::Fail,
                error_class: Some(OperationalErrorClass::ProductFailure),
                skip_reason: None,
                remediation_hint: Some("open repair policy bead with artifact"),
            },
            Case {
                scenario_id: "writeback_crash_matrix",
                gate_hint: "writeback/crash.json",
                result: ScenarioResult::Fail,
                classification: OperationalOutcomeClass::Fail,
                error_class: Some(OperationalErrorClass::ProductFailure),
                skip_reason: None,
                remediation_hint: Some("open writeback crash-consistency bead"),
            },
            Case {
                scenario_id: "fuzz_repair_smoke",
                gate_hint: "fuzz/repair.json",
                result: ScenarioResult::Fail,
                classification: OperationalOutcomeClass::Error,
                error_class: Some(OperationalErrorClass::WorkerDependencyMissing),
                skip_reason: None,
                remediation_hint: Some("run on fuzz-capable worker"),
            },
            Case {
                scenario_id: "perf_baseline_run",
                gate_hint: "perf/baseline.json",
                result: ScenarioResult::Skip,
                classification: OperationalOutcomeClass::Error,
                error_class: Some(OperationalErrorClass::HostEnvironmentFailure),
                skip_reason: Some(SkipReason::WorkerDependencyMissing),
                remediation_hint: Some("run on performance worker"),
            },
            Case {
                scenario_id: "proof_bundle_stale",
                gate_hint: "proof/bundle.json",
                result: ScenarioResult::Fail,
                classification: OperationalOutcomeClass::Fail,
                error_class: Some(OperationalErrorClass::StaleTrackerToolingFailure),
                skip_reason: None,
                remediation_hint: Some("refresh proof bundle before release"),
            },
            Case {
                scenario_id: "release_gate_unsupported",
                gate_hint: "release/unsupported.json",
                result: ScenarioResult::Skip,
                classification: OperationalOutcomeClass::Skip,
                error_class: Some(OperationalErrorClass::UnsupportedV1Scope),
                skip_reason: Some(SkipReason::UnsupportedV1Scope),
                remediation_hint: Some("document explicit V1 non-goal"),
            },
        ]
    }

    fn add_case(manifest: &mut ArtifactManifest, case: Case) {
        let stdout_path = format!("{}/stdout.log", case.scenario_id);
        let stderr_path = format!("{}/stderr.log", case.scenario_id);

        manifest.scenarios.insert(
            case.scenario_id.to_owned(),
            crate::artifact_manifest::ScenarioOutcome {
                scenario_id: case.scenario_id.to_owned(),
                outcome: case.result,
                detail: case.remediation_hint.map(str::to_owned),
                duration_secs: 1.0,
            },
        );
        manifest
            .artifacts
            .push(artifact(case.gate_hint, ArtifactCategory::SummaryReport));
        manifest
            .artifacts
            .push(artifact(&stdout_path, ArtifactCategory::RawLog));
        manifest
            .artifacts
            .push(artifact(&stderr_path, ArtifactCategory::RawLog));
        manifest.operational_scenarios.insert(
            case.scenario_id.to_owned(),
            OperationalScenarioRecord {
                scenario_id: case.scenario_id.to_owned(),
                filesystem: crate::artifact_manifest::FilesystemFlavor::NotApplicable,
                image_hash: None,
                mount_options: Vec::new(),
                expected_outcome: case.result,
                actual_outcome: case.result,
                classification: case.classification,
                exit_status: i32::from(case.result != ScenarioResult::Pass),
                stdout_path,
                stderr_path,
                ledger_paths: Vec::new(),
                artifact_refs: vec![case.gate_hint.to_owned()],
                cleanup_status: CleanupStatus::Clean,
                error_class: case.error_class,
                remediation_hint: case.remediation_hint.map(str::to_owned),
                skip_reason: case.skip_reason,
            },
        );
    }

    fn artifact(path: &str, category: ArtifactCategory) -> ArtifactEntry {
        ArtifactEntry {
            path: path.to_owned(),
            category,
            content_type: Some("application/json".to_owned()),
            size_bytes: 128,
            sha256: None,
            redacted: false,
            metadata: BTreeMap::new(),
        }
    }

    fn sample_legacy_summary(commit: &str, scenario_id: &str) -> LegacyE2eSummary {
        LegacyE2eSummary {
            gate_id: "legacy_fuse_gate".to_owned(),
            run_id: format!("run-{commit}"),
            git_context: LegacyGitContext {
                commit: commit.to_owned(),
                branch: "main".to_owned(),
                clean: true,
            },
            scenarios: vec![LegacyScenario {
                scenario_id: scenario_id.to_owned(),
                outcome: "FAIL".to_owned(),
                detail: Some("FUSE permission denied on worker".to_owned()),
            }],
            verdict: "FAIL".to_owned(),
            duration_secs: 4,
            log_file: "run.log".to_owned(),
        }
    }
}
