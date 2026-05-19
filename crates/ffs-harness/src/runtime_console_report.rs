#![allow(clippy::struct_excessive_bools, clippy::too_many_lines)]
#![forbid(unsafe_code)]

//! Runtime console artifact contract for managed and per-core mounts.
//!
//! The console report is an operational observability artifact. It may help an
//! operator inspect a mounted run, but it is deliberately not product evidence
//! and cannot promote `swarm.responsiveness` or `adaptive_runtime` acceptance.

use crate::artifact_manifest::parse_manifest_timestamp_epoch_days;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Component, Path};
use std::time::{SystemTime, UNIX_EPOCH};

pub const RUNTIME_CONSOLE_REPORT_SCHEMA_VERSION: u32 = 1;
pub const RUNTIME_CONSOLE_REPORT_ID: &str = "runtime_console_report";
pub const RUNTIME_CONSOLE_PRODUCT_EVIDENCE_CLAIM: &str = "none";
pub const RUNTIME_CONSOLE_RELEASE_GATE_EFFECT: &str = "operational_observability_only";
pub const RUNTIME_CONSOLE_SWARM_RESPONSIVENESS_CLAIM: &str = "not_claimed";
pub const RUNTIME_CONSOLE_ADAPTIVE_RUNTIME_CLAIM: &str = "not_claimed";
pub const RUNTIME_CONSOLE_DEFAULT_MAX_AGE_DAYS: u32 = 7;
pub const RUNTIME_CONSOLE_MAX_ARTIFACT_PATHS: usize = 32;
pub const RUNTIME_CONSOLE_MAX_LOG_BYTES: u64 = 16 * 1024 * 1024;
pub const RUNTIME_CONSOLE_MAX_SNAPSHOTS: u32 = 240;
pub const RUNTIME_CONSOLE_MIN_INTERVAL_MILLIS: u64 = 1_000;
pub const RUNTIME_CONSOLE_MAX_INTERVAL_MILLIS: u64 = 600_000;
pub const RUNTIME_CONSOLE_MAX_IMBALANCE_RATIO: f64 = 64.0;
const FLOAT_TOLERANCE: f64 = 0.01;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeConsoleReport {
    pub schema_version: u32,
    pub report_id: String,
    pub operation_id: String,
    pub scenario_id: String,
    pub runtime_mode: RuntimeConsoleMode,
    pub read_write: bool,
    pub worker_count: u32,
    pub started_at: String,
    pub shutdown_at: String,
    pub counters: RuntimeConsoleCounters,
    pub backpressure_decisions: RuntimeConsoleBackpressureDecisionCounts,
    pub degradation_level: RuntimeConsoleDegradationLevel,
    pub per_core_distribution: RuntimeConsolePerCoreDistribution,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adaptive_runtime_manifest_ref: Option<RuntimeConsoleAdaptiveRuntimeManifestRef>,
    pub artifact_paths: Vec<String>,
    pub cleanup_status: RuntimeConsoleCleanupStatus,
    pub reproduction_command: String,
    pub product_evidence_claim: String,
    pub release_gate_effect: String,
    pub claim_state: RuntimeConsoleClaimState,
    pub capture_bounds: RuntimeConsoleCaptureBounds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeConsoleMode {
    Managed,
    PerCore,
}

impl RuntimeConsoleMode {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Managed => "managed",
            Self::PerCore => "per_core",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConsoleCounters {
    pub requests_total: u64,
    pub requests_read: u64,
    pub requests_write: u64,
    pub requests_metadata: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub errors_total: u64,
    pub throttled_requests: u64,
    pub shed_requests: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConsoleBackpressureDecisionCounts {
    pub pass: u64,
    pub throttle: u64,
    pub shed: u64,
    pub emergency: u64,
    pub no_signal: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeConsoleDegradationLevel {
    Normal,
    Degraded,
    Throttling,
    Shedding,
    Emergency,
}

impl RuntimeConsoleDegradationLevel {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Degraded => "degraded",
            Self::Throttling => "throttling",
            Self::Shedding => "shedding",
            Self::Emergency => "emergency",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeConsolePerCoreDistribution {
    pub rows: Vec<RuntimeConsoleCoreDistribution>,
    pub imbalance_ratio: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConsoleCoreDistribution {
    pub core_id: u32,
    pub request_count: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConsoleAdaptiveRuntimeManifestRef {
    pub manifest_path: String,
    pub report_id: String,
    pub runtime_controls_accepted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeConsoleCleanupStatus {
    Clean,
    PreservedArtifacts,
    Failed,
    Unknown,
}

impl RuntimeConsoleCleanupStatus {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConsoleClaimState {
    pub swarm_responsiveness: String,
    pub adaptive_runtime: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConsoleCaptureBounds {
    pub host_paths_redacted: bool,
    pub mountpoints_redacted: bool,
    pub operator_env_redacted: bool,
    pub max_log_bytes: u64,
    pub snapshot_count: u32,
    pub interval_millis: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConsoleValidationConfig {
    pub reference_epoch_days: Option<u32>,
    pub max_age_days: Option<u32>,
}

impl RuntimeConsoleValidationConfig {
    #[must_use]
    pub fn with_current_reference() -> Self {
        Self {
            reference_epoch_days: current_epoch_days(),
            max_age_days: Some(RUNTIME_CONSOLE_DEFAULT_MAX_AGE_DAYS),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConsoleIssue {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConsoleValidationReport {
    pub schema_version: u32,
    pub report_id: String,
    pub valid: bool,
    pub operation_id: String,
    pub scenario_id: String,
    pub runtime_mode: String,
    pub read_write: bool,
    pub worker_count: u32,
    pub requests_total: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub errors_total: u64,
    pub throttled_requests: u64,
    pub shed_requests: u64,
    pub degradation_level: String,
    pub backpressure_decision_total: u64,
    pub per_core_row_count: usize,
    pub imbalance_ratio: String,
    pub adaptive_runtime_manifest_path: Option<String>,
    pub artifact_count: usize,
    pub cleanup_status: String,
    pub product_evidence_claim: String,
    pub release_gate_effect: String,
    pub swarm_responsiveness_claim: String,
    pub adaptive_runtime_claim: String,
    pub capture_snapshot_count: u32,
    pub capture_interval_millis: u64,
    pub max_log_bytes: u64,
    pub issues: Vec<RuntimeConsoleIssue>,
    pub errors: Vec<String>,
}

#[must_use]
pub fn validate_runtime_console_report(
    report: &RuntimeConsoleReport,
) -> RuntimeConsoleValidationReport {
    validate_runtime_console_report_with_config(report, &RuntimeConsoleValidationConfig::default())
}

#[must_use]
pub fn validate_runtime_console_report_with_config(
    report: &RuntimeConsoleReport,
    config: &RuntimeConsoleValidationConfig,
) -> RuntimeConsoleValidationReport {
    let mut issues = Vec::new();
    validate_identity(report, &mut issues);
    validate_timestamps(report, config, &mut issues);
    validate_counters(report, &mut issues);
    validate_distribution(report, &mut issues);
    validate_adaptive_runtime_ref(report, &mut issues);
    validate_paths(report, &mut issues);
    validate_claims(report, &mut issues);
    validate_capture_bounds(report, &mut issues);

    let errors = issues
        .iter()
        .map(|issue| format!("{}: {}", issue.path, issue.message))
        .collect::<Vec<_>>();
    let valid = errors.is_empty();

    RuntimeConsoleValidationReport {
        schema_version: report.schema_version,
        report_id: report.report_id.clone(),
        valid,
        operation_id: report.operation_id.clone(),
        scenario_id: report.scenario_id.clone(),
        runtime_mode: report.runtime_mode.label().to_owned(),
        read_write: report.read_write,
        worker_count: report.worker_count,
        requests_total: report.counters.requests_total,
        bytes_read: report.counters.bytes_read,
        bytes_written: report.counters.bytes_written,
        errors_total: report.counters.errors_total,
        throttled_requests: report.counters.throttled_requests,
        shed_requests: report.counters.shed_requests,
        degradation_level: report.degradation_level.label().to_owned(),
        backpressure_decision_total: report.backpressure_decisions.total(),
        per_core_row_count: report.per_core_distribution.rows.len(),
        imbalance_ratio: format!("{:.2}", report.per_core_distribution.imbalance_ratio),
        adaptive_runtime_manifest_path: report
            .adaptive_runtime_manifest_ref
            .as_ref()
            .map(|reference| reference.manifest_path.clone()),
        artifact_count: report.artifact_paths.len(),
        cleanup_status: report.cleanup_status.label().to_owned(),
        product_evidence_claim: report.product_evidence_claim.clone(),
        release_gate_effect: report.release_gate_effect.clone(),
        swarm_responsiveness_claim: report.claim_state.swarm_responsiveness.clone(),
        adaptive_runtime_claim: report.claim_state.adaptive_runtime.clone(),
        capture_snapshot_count: report.capture_bounds.snapshot_count,
        capture_interval_millis: report.capture_bounds.interval_millis,
        max_log_bytes: report.capture_bounds.max_log_bytes,
        issues,
        errors,
    }
}

#[must_use]
pub fn validate_runtime_console_report_json(
    json: &str,
    config: &RuntimeConsoleValidationConfig,
) -> RuntimeConsoleValidationReport {
    match serde_json::from_str::<RuntimeConsoleReport>(json) {
        Ok(report) => validate_runtime_console_report_with_config(&report, config),
        Err(error) => invalid_json_report(error.to_string()),
    }
}

pub fn fail_on_runtime_console_report_errors(
    report: &RuntimeConsoleValidationReport,
) -> Result<()> {
    if report.valid {
        return Ok(());
    }
    bail!(
        "runtime console report invalid: {} error(s)",
        report.errors.len()
    )
}

#[must_use]
pub fn render_runtime_console_report_markdown(report: &RuntimeConsoleValidationReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Runtime Console Report");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Report: `{}`", report.report_id);
    let _ = writeln!(out, "- Valid: `{}`", report.valid);
    let _ = writeln!(out, "- Operation: `{}`", report.operation_id);
    let _ = writeln!(out, "- Scenario: `{}`", report.scenario_id);
    let _ = writeln!(out, "- Runtime mode: `{}`", report.runtime_mode);
    let _ = writeln!(out, "- Read/write: `{}`", report.read_write);
    let _ = writeln!(out, "- Workers: `{}`", report.worker_count);
    let _ = writeln!(
        out,
        "- Product evidence claim: `{}`",
        report.product_evidence_claim
    );
    let _ = writeln!(
        out,
        "- Release gate effect: `{}`",
        report.release_gate_effect
    );
    let _ = writeln!(
        out,
        "- Swarm responsiveness claim: `{}`",
        report.swarm_responsiveness_claim
    );
    let _ = writeln!(
        out,
        "- Adaptive runtime claim: `{}`",
        report.adaptive_runtime_claim
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Counters");
    let _ = writeln!(out);
    let _ = writeln!(out, "| Metric | Value |");
    let _ = writeln!(out, "|---|---:|");
    let _ = writeln!(out, "| Requests | {} |", report.requests_total);
    let _ = writeln!(out, "| Bytes read | {} |", report.bytes_read);
    let _ = writeln!(out, "| Bytes written | {} |", report.bytes_written);
    let _ = writeln!(out, "| Errors | {} |", report.errors_total);
    let _ = writeln!(out, "| Throttled | {} |", report.throttled_requests);
    let _ = writeln!(out, "| Shed | {} |", report.shed_requests);
    let _ = writeln!(
        out,
        "| Backpressure decisions | {} |",
        report.backpressure_decision_total
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Distribution");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Per-core rows: `{}`", report.per_core_row_count);
    let _ = writeln!(out, "- Imbalance ratio: `{}`", report.imbalance_ratio);
    let _ = writeln!(out, "- Degradation level: `{}`", report.degradation_level);
    let _ = writeln!(out);
    let _ = writeln!(out, "## Bounds");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Snapshot count: `{}`", report.capture_snapshot_count);
    let _ = writeln!(
        out,
        "- Interval millis: `{}`",
        report.capture_interval_millis
    );
    let _ = writeln!(out, "- Max log bytes: `{}`", report.max_log_bytes);
    let _ = writeln!(out, "- Artifact count: `{}`", report.artifact_count);
    let _ = writeln!(out, "- Cleanup: `{}`", report.cleanup_status);
    if let Some(path) = &report.adaptive_runtime_manifest_path {
        let _ = writeln!(out, "- Adaptive runtime manifest: `{path}`");
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "## Issues");
    if report.issues.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "none");
    } else {
        for issue in &report.issues {
            let _ = writeln!(out, "- `{}`: {}", issue.path, issue.message);
        }
    }

    out
}

impl RuntimeConsoleBackpressureDecisionCounts {
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.pass
            .saturating_add(self.throttle)
            .saturating_add(self.shed)
            .saturating_add(self.emergency)
            .saturating_add(self.no_signal)
    }
}

fn invalid_json_report(error: String) -> RuntimeConsoleValidationReport {
    let issue = RuntimeConsoleIssue {
        path: "$".to_owned(),
        message: format!("invalid or incomplete runtime console JSON: {error}"),
    };
    RuntimeConsoleValidationReport {
        schema_version: 0,
        report_id: "<invalid-json>".to_owned(),
        valid: false,
        operation_id: String::new(),
        scenario_id: String::new(),
        runtime_mode: String::new(),
        read_write: false,
        worker_count: 0,
        requests_total: 0,
        bytes_read: 0,
        bytes_written: 0,
        errors_total: 0,
        throttled_requests: 0,
        shed_requests: 0,
        degradation_level: String::new(),
        backpressure_decision_total: 0,
        per_core_row_count: 0,
        imbalance_ratio: String::new(),
        adaptive_runtime_manifest_path: None,
        artifact_count: 0,
        cleanup_status: String::new(),
        product_evidence_claim: String::new(),
        release_gate_effect: String::new(),
        swarm_responsiveness_claim: String::new(),
        adaptive_runtime_claim: String::new(),
        capture_snapshot_count: 0,
        capture_interval_millis: 0,
        max_log_bytes: 0,
        errors: vec![format!(
            "$: invalid or incomplete runtime console JSON: {error}"
        )],
        issues: vec![issue],
    }
}

fn validate_identity(report: &RuntimeConsoleReport, issues: &mut Vec<RuntimeConsoleIssue>) {
    if report.schema_version != RUNTIME_CONSOLE_REPORT_SCHEMA_VERSION {
        push_issue(
            issues,
            "schema_version",
            format!("must be {RUNTIME_CONSOLE_REPORT_SCHEMA_VERSION}"),
        );
    }
    if report.report_id != RUNTIME_CONSOLE_REPORT_ID {
        push_issue(
            issues,
            "report_id",
            format!("must be `{RUNTIME_CONSOLE_REPORT_ID}`"),
        );
    }
    require_non_empty("operation_id", &report.operation_id, issues);
    require_non_empty("scenario_id", &report.scenario_id, issues);
    if report.worker_count == 0 {
        push_issue(issues, "worker_count", "must be greater than zero");
    }
    if matches!(report.runtime_mode, RuntimeConsoleMode::Managed) && report.worker_count != 1 {
        push_issue(issues, "worker_count", "managed mode must use one worker");
    }
    require_non_empty("reproduction_command", &report.reproduction_command, issues);
}

fn validate_timestamps(
    report: &RuntimeConsoleReport,
    config: &RuntimeConsoleValidationConfig,
    issues: &mut Vec<RuntimeConsoleIssue>,
) {
    let started_at_days = validate_timestamp(issues, "started_at", &report.started_at);
    let shutdown_at_days = validate_timestamp(issues, "shutdown_at", &report.shutdown_at);
    if let (Some(started_at_days), Some(shutdown_at_days)) = (started_at_days, shutdown_at_days) {
        if started_at_days > shutdown_at_days {
            push_issue(issues, "shutdown_at", "must not be earlier than started_at");
        }
        if let Some(reference_epoch_days) = config.reference_epoch_days {
            if started_at_days > reference_epoch_days {
                push_issue(
                    issues,
                    "started_at",
                    "must not be after the validation reference timestamp",
                );
            }
            if shutdown_at_days > reference_epoch_days {
                push_issue(
                    issues,
                    "shutdown_at",
                    "must not be after the validation reference timestamp",
                );
            }
            let max_age_days = config
                .max_age_days
                .unwrap_or(RUNTIME_CONSOLE_DEFAULT_MAX_AGE_DAYS);
            let age_days = reference_epoch_days.saturating_sub(shutdown_at_days);
            if age_days > max_age_days {
                push_issue(
                    issues,
                    "shutdown_at",
                    format!(
                        "stale runtime console report: age_days={age_days} \
                         max_age_days={max_age_days}"
                    ),
                );
            }
        }
    }
}

fn validate_timestamp(
    issues: &mut Vec<RuntimeConsoleIssue>,
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

fn validate_counters(report: &RuntimeConsoleReport, issues: &mut Vec<RuntimeConsoleIssue>) {
    let classified_total = report
        .counters
        .requests_read
        .saturating_add(report.counters.requests_write)
        .saturating_add(report.counters.requests_metadata);
    if classified_total != report.counters.requests_total {
        push_issue(
            issues,
            "counters.requests_total",
            format!("must equal read + write + metadata requests ({classified_total})"),
        );
    }
    if !report.read_write && report.counters.requests_write > 0 {
        push_issue(
            issues,
            "counters.requests_write",
            "read-only console reports cannot record write requests",
        );
    }
    if !report.read_write && report.counters.bytes_written > 0 {
        push_issue(
            issues,
            "counters.bytes_written",
            "read-only console reports cannot record written bytes",
        );
    }
    if report.counters.throttled_requests != report.backpressure_decisions.throttle {
        push_issue(
            issues,
            "counters.throttled_requests",
            "must match backpressure_decisions.throttle",
        );
    }
    if report.counters.shed_requests != report.backpressure_decisions.shed {
        push_issue(
            issues,
            "counters.shed_requests",
            "must match backpressure_decisions.shed",
        );
    }
    if report.backpressure_decisions.total() != report.counters.requests_total {
        push_issue(
            issues,
            "backpressure_decisions",
            "decision counts must sum to requests_total",
        );
    }
}

fn validate_distribution(report: &RuntimeConsoleReport, issues: &mut Vec<RuntimeConsoleIssue>) {
    let row_count = report.per_core_distribution.rows.len();
    let expected_rows = usize::try_from(report.worker_count).unwrap_or(usize::MAX);
    if row_count != expected_rows {
        push_issue(
            issues,
            "per_core_distribution.rows",
            format!(
                "row count {row_count} must match worker_count {}",
                report.worker_count
            ),
        );
    }
    if !report.per_core_distribution.imbalance_ratio.is_finite()
        || report.per_core_distribution.imbalance_ratio < 1.0
        || report.per_core_distribution.imbalance_ratio > RUNTIME_CONSOLE_MAX_IMBALANCE_RATIO
    {
        push_issue(
            issues,
            "per_core_distribution.imbalance_ratio",
            format!("must be finite and between 1.0 and {RUNTIME_CONSOLE_MAX_IMBALANCE_RATIO}"),
        );
    }

    let mut seen_core_ids = BTreeSet::new();
    let mut request_sum = 0_u64;
    let mut min_requests = u64::MAX;
    let mut max_requests = 0_u64;
    for (index, row) in report.per_core_distribution.rows.iter().enumerate() {
        let path = format!("per_core_distribution.rows[{index}]");
        if row.core_id >= report.worker_count {
            push_issue(
                issues,
                format!("{path}.core_id"),
                format!("must be less than worker_count {}", report.worker_count),
            );
        }
        if !seen_core_ids.insert(row.core_id) {
            push_issue(
                issues,
                format!("{path}.core_id"),
                format!("duplicates core_id {}", row.core_id),
            );
        }
        if row.cache_hits.saturating_add(row.cache_misses) > row.request_count {
            push_issue(
                issues,
                format!("{path}.cache_hits"),
                "cache hits + misses must not exceed request_count",
            );
        }
        request_sum = request_sum.saturating_add(row.request_count);
        min_requests = min_requests.min(row.request_count);
        max_requests = max_requests.max(row.request_count);
    }
    if request_sum != report.counters.requests_total {
        push_issue(
            issues,
            "per_core_distribution.rows",
            format!(
                "per-core request sum {request_sum} must match requests_total {}",
                report.counters.requests_total
            ),
        );
    }

    if row_count > 0 && report.counters.requests_total > 0 {
        if min_requests == 0 {
            push_issue(
                issues,
                "per_core_distribution.imbalance_ratio",
                "active console reports cannot have zero-request workers",
            );
        } else {
            let expected_ratio = max_requests as f64 / min_requests as f64;
            if (expected_ratio - report.per_core_distribution.imbalance_ratio).abs()
                > FLOAT_TOLERANCE
            {
                push_issue(
                    issues,
                    "per_core_distribution.imbalance_ratio",
                    format!(
                        "must match max/min request ratio {:.2}",
                        round_two_decimals(expected_ratio)
                    ),
                );
            }
        }
    }
}

fn validate_adaptive_runtime_ref(
    report: &RuntimeConsoleReport,
    issues: &mut Vec<RuntimeConsoleIssue>,
) {
    let Some(reference) = &report.adaptive_runtime_manifest_ref else {
        return;
    };
    require_non_empty(
        "adaptive_runtime_manifest_ref.report_id",
        &reference.report_id,
        issues,
    );
    validate_safe_artifact_path(
        issues,
        "adaptive_runtime_manifest_ref.manifest_path",
        &reference.manifest_path,
    );
    if reference.runtime_controls_accepted {
        push_issue(
            issues,
            "adaptive_runtime_manifest_ref.runtime_controls_accepted",
            "local console artifacts cannot claim adaptive_runtime acceptance",
        );
    }
}

fn validate_paths(report: &RuntimeConsoleReport, issues: &mut Vec<RuntimeConsoleIssue>) {
    if report.artifact_paths.is_empty() {
        push_issue(issues, "artifact_paths", "must not be empty");
        return;
    }
    if report.artifact_paths.len() > RUNTIME_CONSOLE_MAX_ARTIFACT_PATHS {
        push_issue(
            issues,
            "artifact_paths",
            format!("must contain at most {RUNTIME_CONSOLE_MAX_ARTIFACT_PATHS} paths"),
        );
    }
    let mut seen = BTreeSet::new();
    for (index, path) in report.artifact_paths.iter().enumerate() {
        let field = format!("artifact_paths[{index}]");
        validate_safe_artifact_path(issues, &field, path);
        if !seen.insert(path) {
            push_issue(issues, field, "must not duplicate another artifact path");
        }
    }
}

fn validate_claims(report: &RuntimeConsoleReport, issues: &mut Vec<RuntimeConsoleIssue>) {
    if report.product_evidence_claim != RUNTIME_CONSOLE_PRODUCT_EVIDENCE_CLAIM {
        push_issue(
            issues,
            "product_evidence_claim",
            format!("must be `{RUNTIME_CONSOLE_PRODUCT_EVIDENCE_CLAIM}`"),
        );
    }
    if report.release_gate_effect != RUNTIME_CONSOLE_RELEASE_GATE_EFFECT {
        push_issue(
            issues,
            "release_gate_effect",
            format!("must be `{RUNTIME_CONSOLE_RELEASE_GATE_EFFECT}`"),
        );
    }
    if report.claim_state.swarm_responsiveness != RUNTIME_CONSOLE_SWARM_RESPONSIVENESS_CLAIM {
        push_issue(
            issues,
            "claim_state.swarm_responsiveness",
            "local console artifacts cannot claim swarm.responsiveness acceptance",
        );
    }
    if report.claim_state.adaptive_runtime != RUNTIME_CONSOLE_ADAPTIVE_RUNTIME_CLAIM {
        push_issue(
            issues,
            "claim_state.adaptive_runtime",
            "local console artifacts cannot claim adaptive_runtime acceptance",
        );
    }
}

fn validate_capture_bounds(report: &RuntimeConsoleReport, issues: &mut Vec<RuntimeConsoleIssue>) {
    let bounds = &report.capture_bounds;
    if !bounds.host_paths_redacted {
        push_issue(
            issues,
            "capture_bounds.host_paths_redacted",
            "host paths must be redacted before console artifact persistence",
        );
    }
    if !bounds.mountpoints_redacted {
        push_issue(
            issues,
            "capture_bounds.mountpoints_redacted",
            "mountpoints must be redacted before console artifact persistence",
        );
    }
    if !bounds.operator_env_redacted {
        push_issue(
            issues,
            "capture_bounds.operator_env_redacted",
            "operator environment must be redacted before console artifact persistence",
        );
    }
    if bounds.max_log_bytes == 0 || bounds.max_log_bytes > RUNTIME_CONSOLE_MAX_LOG_BYTES {
        push_issue(
            issues,
            "capture_bounds.max_log_bytes",
            format!("must be between 1 and {RUNTIME_CONSOLE_MAX_LOG_BYTES}"),
        );
    }
    if bounds.snapshot_count == 0 || bounds.snapshot_count > RUNTIME_CONSOLE_MAX_SNAPSHOTS {
        push_issue(
            issues,
            "capture_bounds.snapshot_count",
            format!("must be between 1 and {RUNTIME_CONSOLE_MAX_SNAPSHOTS}"),
        );
    }
    if !(RUNTIME_CONSOLE_MIN_INTERVAL_MILLIS..=RUNTIME_CONSOLE_MAX_INTERVAL_MILLIS)
        .contains(&bounds.interval_millis)
    {
        push_issue(
            issues,
            "capture_bounds.interval_millis",
            format!(
                "must be between \
                 {RUNTIME_CONSOLE_MIN_INTERVAL_MILLIS} and \
                 {RUNTIME_CONSOLE_MAX_INTERVAL_MILLIS}"
            ),
        );
    }
}

fn validate_safe_artifact_path(issues: &mut Vec<RuntimeConsoleIssue>, field: &str, value: &str) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        push_issue(issues, field, "must not be empty");
        return;
    }
    let path = Path::new(trimmed);
    if is_root_or_parent_sensitive(path) || contains_secret_path_token(trimmed) {
        push_issue(
            issues,
            field,
            "must be a redacted artifact path without parent traversal or secret-bearing \
             components",
        );
        return;
    }
    if !is_artifact_scoped_path(trimmed) {
        push_issue(
            issues,
            field,
            "must be relative to artifacts/ or a redacted FrankenFS artifact temp root",
        );
    }
}

fn is_artifact_scoped_path(value: &str) -> bool {
    let path = Path::new(value);
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

fn contains_secret_path_token(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [
        "/.aws/",
        "/.config/",
        "/.gnupg/",
        "/.ssh/",
        "/etc/",
        "id_rsa",
        "secret",
        "token",
    ]
    .iter()
    .any(|token| lower.contains(token))
}

fn require_non_empty(field: &str, value: &str, issues: &mut Vec<RuntimeConsoleIssue>) {
    if value.trim().is_empty() {
        push_issue(issues, field, "must not be empty");
    }
}

fn push_issue(
    issues: &mut Vec<RuntimeConsoleIssue>,
    path: impl Into<String>,
    message: impl Into<String>,
) {
    issues.push(RuntimeConsoleIssue {
        path: path.into(),
        message: message.into(),
    });
}

fn round_two_decimals(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn current_epoch_days() -> Option<u32> {
    let unix_epoch_days = parse_manifest_timestamp_epoch_days("1970-01-01T00:00:00Z")?;
    let elapsed_days = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() / 86_400;
    let total_days = u64::from(unix_epoch_days).checked_add(elapsed_days)?;
    u32::try_from(total_days).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    use serde_json::json;

    const REFERENCE_TIMESTAMP: &str = "2026-05-19T12:00:00Z";

    #[test]
    fn runtime_console_report_json_shape() -> Result<()> {
        let report = sample_report();
        let validation =
            validate_runtime_console_report_with_config(&report, &fixture_validation_config());
        assert!(validation.valid, "{:?}", validation.errors);

        let shape = json!({
            "schema_version": report.schema_version,
            "report_id": report.report_id,
            "operation_id": report.operation_id,
            "scenario_id": report.scenario_id,
            "runtime_mode": report.runtime_mode,
            "read_write": report.read_write,
            "worker_count": report.worker_count,
            "started_at": report.started_at,
            "shutdown_at": report.shutdown_at,
            "counters": report.counters,
            "backpressure_decisions": report.backpressure_decisions,
            "degradation_level": report.degradation_level,
            "per_core_distribution": report.per_core_distribution,
            "adaptive_runtime_manifest_ref": report.adaptive_runtime_manifest_ref,
            "artifact_paths": report.artifact_paths,
            "cleanup_status": report.cleanup_status,
            "reproduction_command": report.reproduction_command,
            "product_evidence_claim": report.product_evidence_claim,
            "release_gate_effect": report.release_gate_effect,
            "claim_state": report.claim_state,
            "capture_bounds": report.capture_bounds,
            "validation": {
                "valid": validation.valid,
                "runtime_mode": validation.runtime_mode,
                "backpressure_decision_total": validation.backpressure_decision_total,
                "per_core_row_count": validation.per_core_row_count,
                "imbalance_ratio": validation.imbalance_ratio,
                "artifact_count": validation.artifact_count,
                "issues": validation.issues,
            },
        });
        let json = serde_json::to_string_pretty(&shape)?;

        insta::assert_snapshot!("runtime_console_report_json_shape", json);
        let encoded = serde_json::to_string_pretty(&report)?;
        let parsed: RuntimeConsoleReport = serde_json::from_str(&encoded)?;
        assert_eq!(parsed, report);
        Ok(())
    }

    #[test]
    fn render_runtime_console_report_markdown_sample() {
        let report = validate_runtime_console_report_with_config(
            &sample_report(),
            &fixture_validation_config(),
        );
        let markdown = render_runtime_console_report_markdown(&report);

        insta::assert_snapshot!("render_runtime_console_report_markdown_sample", markdown);
    }

    #[test]
    fn missing_required_fields_are_rejected() -> Result<()> {
        let mut value = serde_json::to_value(sample_report())?;
        value
            .as_object_mut()
            .context("sample report object")?
            .remove("operation_id");

        let report = validate_runtime_console_report_json(
            &serde_json::to_string(&value)?,
            &fixture_validation_config(),
        );

        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("missing field `operation_id`")),
            "{:?}",
            report.errors
        );
        Ok(())
    }

    #[test]
    fn future_and_stale_timestamps_are_rejected() {
        let mut future = sample_report();
        future.started_at = "2026-05-20T00:00:00Z".to_owned();
        future.shutdown_at = "2026-05-20T00:10:00Z".to_owned();
        let report =
            validate_runtime_console_report_with_config(&future, &fixture_validation_config());
        assert_paths_present(&report, &["started_at", "shutdown_at"]);

        let mut stale = sample_report();
        stale.shutdown_at = "2026-05-01T00:10:00Z".to_owned();
        let report =
            validate_runtime_console_report_with_config(&stale, &fixture_validation_config());
        assert_path_message_contains(&report, "shutdown_at", "stale runtime console report");
    }

    #[test]
    fn bounded_capture_contract_is_enforced() {
        let mut report = sample_report();
        report.capture_bounds.host_paths_redacted = false;
        report.capture_bounds.mountpoints_redacted = false;
        report.capture_bounds.operator_env_redacted = false;
        report.capture_bounds.max_log_bytes = RUNTIME_CONSOLE_MAX_LOG_BYTES + 1;
        report.capture_bounds.snapshot_count = RUNTIME_CONSOLE_MAX_SNAPSHOTS + 1;
        report.capture_bounds.interval_millis = RUNTIME_CONSOLE_MIN_INTERVAL_MILLIS - 1;

        let report =
            validate_runtime_console_report_with_config(&report, &fixture_validation_config());

        assert_paths_present(
            &report,
            &[
                "capture_bounds.host_paths_redacted",
                "capture_bounds.mountpoints_redacted",
                "capture_bounds.operator_env_redacted",
                "capture_bounds.max_log_bytes",
                "capture_bounds.snapshot_count",
                "capture_bounds.interval_millis",
            ],
        );
    }

    #[test]
    fn absolute_secret_bearing_paths_are_rejected() {
        let mut report = sample_report();
        report.artifact_paths[0] = "/home/ubuntu/.ssh/id_rsa".to_owned();

        let report =
            validate_runtime_console_report_with_config(&report, &fixture_validation_config());

        assert_path_message_contains(&report, "artifact_paths[0]", "secret-bearing");
    }

    #[test]
    fn malformed_per_core_distribution_is_rejected() {
        let mut report = sample_report();
        report.per_core_distribution.rows[1].core_id = 0;
        report.per_core_distribution.rows[1].cache_hits = 10_000;
        report.per_core_distribution.rows[1].request_count = 1;
        report.per_core_distribution.imbalance_ratio = 99.0;

        let report =
            validate_runtime_console_report_with_config(&report, &fixture_validation_config());

        assert_paths_present(
            &report,
            &[
                "per_core_distribution.rows[1].core_id",
                "per_core_distribution.rows[1].cache_hits",
                "per_core_distribution.imbalance_ratio",
            ],
        );
    }

    #[test]
    fn forbidden_acceptance_claims_are_rejected() {
        let mut report = sample_report();
        report.product_evidence_claim = "swarm.responsiveness".to_owned();
        report.release_gate_effect = "adaptive_runtime".to_owned();
        report.claim_state.swarm_responsiveness = "accepted".to_owned();
        report.claim_state.adaptive_runtime = "accepted".to_owned();
        if let Some(reference) = &mut report.adaptive_runtime_manifest_ref {
            reference.runtime_controls_accepted = true;
        }

        let report =
            validate_runtime_console_report_with_config(&report, &fixture_validation_config());

        assert_paths_present(
            &report,
            &[
                "product_evidence_claim",
                "release_gate_effect",
                "claim_state.swarm_responsiveness",
                "claim_state.adaptive_runtime",
                "adaptive_runtime_manifest_ref.runtime_controls_accepted",
            ],
        );
    }

    #[test]
    fn fail_on_runtime_console_report_errors_rejects_invalid_report() {
        let mut report = sample_report();
        report.artifact_paths.clear();
        let validation =
            validate_runtime_console_report_with_config(&report, &fixture_validation_config());

        assert!(fail_on_runtime_console_report_errors(&validation).is_err());
    }

    fn assert_paths_present(report: &RuntimeConsoleValidationReport, paths: &[&str]) {
        assert!(!report.valid);
        for path in paths {
            assert!(
                report.issues.iter().any(|issue| issue.path == *path),
                "missing issue path {path}; issues={:?}",
                report.issues
            );
        }
    }

    fn assert_path_message_contains(
        report: &RuntimeConsoleValidationReport,
        path: &str,
        expected: &str,
    ) {
        assert!(!report.valid);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.path == path && issue.message.contains(expected)),
            "missing issue {path} containing {expected}; issues={:?}",
            report.issues
        );
    }

    fn fixture_validation_config() -> RuntimeConsoleValidationConfig {
        RuntimeConsoleValidationConfig {
            reference_epoch_days: parse_manifest_timestamp_epoch_days(REFERENCE_TIMESTAMP),
            max_age_days: Some(7),
        }
    }

    fn sample_report() -> RuntimeConsoleReport {
        RuntimeConsoleReport {
            schema_version: RUNTIME_CONSOLE_REPORT_SCHEMA_VERSION,
            report_id: RUNTIME_CONSOLE_REPORT_ID.to_owned(),
            operation_id: "runtime-console-op-20260519T000000Z".to_owned(),
            scenario_id: "managed_writeback_console_observability".to_owned(),
            runtime_mode: RuntimeConsoleMode::PerCore,
            read_write: true,
            worker_count: 4,
            started_at: "2026-05-19T00:00:00Z".to_owned(),
            shutdown_at: "2026-05-19T00:10:00Z".to_owned(),
            counters: RuntimeConsoleCounters {
                requests_total: 1_000,
                requests_read: 600,
                requests_write: 250,
                requests_metadata: 150,
                bytes_read: 8_388_608,
                bytes_written: 2_097_152,
                errors_total: 2,
                throttled_requests: 20,
                shed_requests: 4,
            },
            backpressure_decisions: RuntimeConsoleBackpressureDecisionCounts {
                pass: 960,
                throttle: 20,
                shed: 4,
                emergency: 0,
                no_signal: 16,
            },
            degradation_level: RuntimeConsoleDegradationLevel::Throttling,
            per_core_distribution: RuntimeConsolePerCoreDistribution {
                rows: vec![
                    RuntimeConsoleCoreDistribution {
                        core_id: 0,
                        request_count: 250,
                        cache_hits: 180,
                        cache_misses: 40,
                    },
                    RuntimeConsoleCoreDistribution {
                        core_id: 1,
                        request_count: 200,
                        cache_hits: 140,
                        cache_misses: 45,
                    },
                    RuntimeConsoleCoreDistribution {
                        core_id: 2,
                        request_count: 300,
                        cache_hits: 210,
                        cache_misses: 60,
                    },
                    RuntimeConsoleCoreDistribution {
                        core_id: 3,
                        request_count: 250,
                        cache_hits: 170,
                        cache_misses: 55,
                    },
                ],
                imbalance_ratio: 1.50,
            },
            adaptive_runtime_manifest_ref: Some(RuntimeConsoleAdaptiveRuntimeManifestRef {
                manifest_path: "artifacts/adaptive-runtime/runner/runner_manifest.json".to_owned(),
                report_id: "adaptive_runtime_runner_report".to_owned(),
                runtime_controls_accepted: false,
            }),
            artifact_paths: vec![
                "artifacts/runtime-console/console_report.json".to_owned(),
                "artifacts/runtime-console/console_report.md".to_owned(),
                "artifacts/runtime-console/structured.jsonl".to_owned(),
            ],
            cleanup_status: RuntimeConsoleCleanupStatus::Clean,
            reproduction_command: concat!(
                "ffs mount --runtime-mode per-core --console --console-out ",
                "artifacts/runtime-console/console_report.json"
            )
            .to_owned(),
            product_evidence_claim: RUNTIME_CONSOLE_PRODUCT_EVIDENCE_CLAIM.to_owned(),
            release_gate_effect: RUNTIME_CONSOLE_RELEASE_GATE_EFFECT.to_owned(),
            claim_state: RuntimeConsoleClaimState {
                swarm_responsiveness: RUNTIME_CONSOLE_SWARM_RESPONSIVENESS_CLAIM.to_owned(),
                adaptive_runtime: RUNTIME_CONSOLE_ADAPTIVE_RUNTIME_CLAIM.to_owned(),
            },
            capture_bounds: RuntimeConsoleCaptureBounds {
                host_paths_redacted: true,
                mountpoints_redacted: true,
                operator_env_redacted: true,
                max_log_bytes: 1_048_576,
                snapshot_count: 10,
                interval_millis: 5_000,
            },
        }
    }
}
