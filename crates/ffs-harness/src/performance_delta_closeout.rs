#![allow(clippy::too_many_lines)]
#![forbid(unsafe_code)]

//! Performance delta closeout for `bd-rchk5.4`.
//!
//! The closeout consumes measured baseline artifacts and reference-comparison
//! artifacts, then turns them into release-safe tracking signal. Rows that
//! regress, lack a comparable reference, or remain unmeasured must link to a
//! live bead before the report is valid.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub const DEFAULT_PERFORMANCE_DELTA_CLOSEOUT_CONFIG: &str =
    "benchmarks/performance_delta_closeout.json";
pub const PERFORMANCE_DELTA_CLOSEOUT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceDeltaCloseoutConfig {
    pub schema_version: u32,
    pub closeout_id: String,
    pub source_bead_id: String,
    pub generated_at: String,
    pub issues_path: String,
    pub reference_baselines: Vec<String>,
    pub current_baselines: Vec<String>,
    pub comparison_artifacts: Vec<String>,
    pub policy: PerformanceDeltaPolicy,
    #[serde(default)]
    pub follow_up_overrides: Vec<PerformanceDeltaFollowUpOverride>,
    #[serde(default)]
    pub unmeasured_claims: Vec<PerformanceUnmeasuredClaim>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceDeltaPolicy {
    pub p99_warn_percent: f64,
    pub p99_fail_percent: f64,
    pub throughput_fail_percent: f64,
    pub missing_reference_follow_up_bead: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceDeltaFollowUpOverride {
    pub operation: String,
    pub follow_up_bead: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<PerformanceDeltaClassification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_contains: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceUnmeasuredClaim {
    pub claim_id: String,
    pub operation: String,
    pub reason: String,
    pub follow_up_bead: String,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceDeltaClassification {
    Improved,
    WithinThreshold,
    Warning,
    Regression,
    MissingReference,
    PendingCapability,
    Unmeasured,
}

impl PerformanceDeltaClassification {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Improved => "improved",
            Self::WithinThreshold => "within_threshold",
            Self::Warning => "warning",
            Self::Regression => "regression",
            Self::MissingReference => "missing_reference",
            Self::PendingCapability => "pending_capability",
            Self::Unmeasured => "unmeasured",
        }
    }

    #[must_use]
    pub const fn requires_follow_up(self) -> bool {
        matches!(
            self,
            Self::Warning
                | Self::Regression
                | Self::MissingReference
                | Self::PendingCapability
                | Self::Unmeasured
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceDeltaRow {
    pub row_id: String,
    pub row_kind: String,
    pub operation: String,
    pub source_artifact: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_artifact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_source_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_p99_us: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_p99_us: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p99_delta_percent: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_throughput_ops_sec: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_throughput_ops_sec: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub throughput_delta_percent: Option<f64>,
    pub classification: PerformanceDeltaClassification,
    pub release_claim_state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follow_up_bead: Option<String>,
    pub follow_up_present: bool,
    pub rationale: String,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceDeltaCloseoutReport {
    pub schema_version: u32,
    pub closeout_id: String,
    pub source_bead_id: String,
    pub generated_at: String,
    pub valid: bool,
    pub row_count: usize,
    pub classification_counts: BTreeMap<String, usize>,
    pub follow_up_beads: Vec<String>,
    pub rows_requiring_follow_up: usize,
    pub rows: Vec<PerformanceDeltaRow>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
struct Measurement {
    operation: String,
    source_artifact: String,
    source_json: Option<String>,
    p99_us: Option<f64>,
    throughput_ops_sec: Option<f64>,
    status: String,
    command: String,
}

pub fn load_performance_delta_closeout_config(
    path: &Path,
) -> Result<PerformanceDeltaCloseoutConfig> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read performance closeout {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("invalid performance closeout JSON {}", path.display()))
}

pub fn run_performance_delta_closeout(
    config: &PerformanceDeltaCloseoutConfig,
) -> Result<PerformanceDeltaCloseoutReport> {
    let mut errors = validate_config_shape(config);
    let issue_ids = load_issue_ids(Path::new(&config.issues_path))?;
    let reference_map = load_reference_measurements(config)?;
    let mut rows = Vec::new();

    for artifact in &config.current_baselines {
        rows.extend(load_current_rows(
            artifact,
            &reference_map,
            config,
            &issue_ids,
            &mut errors,
        )?);
    }

    for artifact in &config.comparison_artifacts {
        rows.extend(load_comparison_rows(
            artifact,
            config,
            &issue_ids,
            &mut errors,
        )?);
    }

    for claim in &config.unmeasured_claims {
        rows.push(unmeasured_claim_row(claim, &issue_ids, &mut errors));
    }

    validate_follow_up_overrides(config, &issue_ids, &mut errors);
    validate_required_follow_ups(&rows, &mut errors);
    let classification_counts = count_classifications(&rows);
    let follow_up_beads = rows
        .iter()
        .filter_map(|row| row.follow_up_bead.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let rows_requiring_follow_up = rows
        .iter()
        .filter(|row| row.classification.requires_follow_up())
        .count();

    Ok(PerformanceDeltaCloseoutReport {
        schema_version: PERFORMANCE_DELTA_CLOSEOUT_SCHEMA_VERSION,
        closeout_id: config.closeout_id.clone(),
        source_bead_id: config.source_bead_id.clone(),
        generated_at: config.generated_at.clone(),
        valid: errors.is_empty(),
        row_count: rows.len(),
        classification_counts,
        follow_up_beads,
        rows_requiring_follow_up,
        rows,
        errors,
    })
}

#[must_use]
pub fn render_performance_delta_closeout_markdown(
    report: &PerformanceDeltaCloseoutReport,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Performance Delta Closeout\n");
    let _ = writeln!(out, "- Closeout: `{}`", report.closeout_id);
    let _ = writeln!(out, "- Source bead: `{}`", report.source_bead_id);
    let _ = writeln!(out, "- Generated at: `{}`", report.generated_at);
    let _ = writeln!(out, "- Valid: `{}`", report.valid);
    let _ = writeln!(out, "- Rows: `{}`", report.row_count);
    let _ = writeln!(
        out,
        "- Rows requiring follow-up: `{}`",
        report.rows_requiring_follow_up
    );
    out.push('\n');
    out.push_str("## Classification Counts\n\n");
    for (class, count) in &report.classification_counts {
        let _ = writeln!(out, "- `{class}`: {count}");
    }
    out.push_str("\n## Follow-Up Beads\n\n");
    for bead in &report.follow_up_beads {
        let _ = writeln!(out, "- `{bead}`");
    }
    out.push_str("\n## Rows\n\n");
    out.push_str("| Operation | Class | p99 delta | Throughput delta | Follow-up | Rationale |\n");
    out.push_str("|---|---:|---:|---:|---|---|\n");
    for row in &report.rows {
        let p99 = format_optional_percent(row.p99_delta_percent);
        let throughput = format_optional_percent(row.throughput_delta_percent);
        let follow_up = row.follow_up_bead.as_deref().unwrap_or("n/a");
        let rationale = row.rationale.replace('|', "/");
        let _ = writeln!(
            out,
            "| `{}` | `{}` | {} | {} | `{}` | {} |",
            row.operation,
            row.classification.label(),
            p99,
            throughput,
            follow_up,
            rationale
        );
    }
    if !report.errors.is_empty() {
        out.push_str("\n## Errors\n\n");
        for error in &report.errors {
            let _ = writeln!(out, "- {error}");
        }
    }
    out
}

pub fn fail_on_performance_delta_closeout_errors(
    report: &PerformanceDeltaCloseoutReport,
) -> Result<()> {
    if report.valid {
        Ok(())
    } else {
        bail!(
            "performance delta closeout validation failed: errors={}",
            report.errors.len()
        )
    }
}

fn validate_config_shape(config: &PerformanceDeltaCloseoutConfig) -> Vec<String> {
    let mut errors = Vec::new();
    if config.schema_version != PERFORMANCE_DELTA_CLOSEOUT_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version must be {PERFORMANCE_DELTA_CLOSEOUT_SCHEMA_VERSION}"
        ));
    }
    if config.closeout_id.trim().is_empty() {
        errors.push("closeout_id must not be empty".to_owned());
    }
    if config.source_bead_id.trim().is_empty() {
        errors.push("source_bead_id must not be empty".to_owned());
    }
    if config.reference_baselines.is_empty() {
        errors.push("reference_baselines must not be empty".to_owned());
    }
    if config.current_baselines.is_empty() && config.comparison_artifacts.is_empty() {
        errors.push("at least one current baseline or comparison artifact is required".to_owned());
    }
    if config.policy.p99_warn_percent <= 0.0 {
        errors.push("policy.p99_warn_percent must be positive".to_owned());
    }
    if config.policy.p99_fail_percent <= config.policy.p99_warn_percent {
        errors.push("policy.p99_fail_percent must exceed p99_warn_percent".to_owned());
    }
    if config.policy.throughput_fail_percent >= 0.0 {
        errors.push("policy.throughput_fail_percent must be negative".to_owned());
    }
    if config
        .policy
        .missing_reference_follow_up_bead
        .trim()
        .is_empty()
    {
        errors.push("policy.missing_reference_follow_up_bead must not be empty".to_owned());
    }
    errors
}

fn load_issue_ids(path: &Path) -> Result<BTreeSet<String>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read issue JSONL {}", path.display()))?;
    let mut ids = BTreeSet::new();
    for (line_no, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(trimmed).with_context(|| {
            format!(
                "invalid issue JSON at {}:{}",
                path.display(),
                line_no.saturating_add(1)
            )
        })?;
        if let Some(id) = value.get("id").and_then(Value::as_str) {
            ids.insert(id.to_owned());
        }
    }
    Ok(ids)
}

fn load_reference_measurements(
    config: &PerformanceDeltaCloseoutConfig,
) -> Result<BTreeMap<String, Measurement>> {
    let mut map = BTreeMap::new();
    for artifact in &config.reference_baselines {
        for measurement in load_measurements(artifact)? {
            map.insert(measurement.operation.clone(), measurement);
        }
    }
    Ok(map)
}

fn load_current_rows(
    artifact: &str,
    reference_map: &BTreeMap<String, Measurement>,
    config: &PerformanceDeltaCloseoutConfig,
    issue_ids: &BTreeSet<String>,
    errors: &mut Vec<String>,
) -> Result<Vec<PerformanceDeltaRow>> {
    let mut rows = Vec::new();
    for current in load_measurements(artifact)? {
        if current.status != "measured" {
            let classification = if current.status == "pending" {
                PerformanceDeltaClassification::PendingCapability
            } else {
                PerformanceDeltaClassification::Unmeasured
            };
            rows.push(row_without_reference(
                "measurement",
                &current,
                classification,
                config,
                issue_ids,
                errors,
            ));
            continue;
        }
        if let Some(reference) = reference_map.get(&current.operation) {
            rows.push(row_with_reference(
                "measurement",
                &current,
                reference,
                config,
                issue_ids,
                errors,
            ));
        } else {
            rows.push(row_without_reference(
                "measurement",
                &current,
                PerformanceDeltaClassification::MissingReference,
                config,
                issue_ids,
                errors,
            ));
        }
    }
    Ok(rows)
}

fn load_comparison_rows(
    artifact: &str,
    config: &PerformanceDeltaCloseoutConfig,
    issue_ids: &BTreeSet<String>,
    errors: &mut Vec<String>,
) -> Result<Vec<PerformanceDeltaRow>> {
    let value = load_json_file(artifact)?;
    let rows = value
        .get("rows")
        .and_then(Value::as_array)
        .with_context(|| format!("{artifact} must contain rows[]"))?;
    let mut out = Vec::new();
    for row in rows {
        let operation = string_field(row, "operation")
            .with_context(|| format!("{artifact} comparison row missing operation"))?;
        let p99_delta = number_field(row, "p99_delta_percent");
        let throughput_delta = number_field(row, "throughput_delta_percent");
        let classification = classify_delta(p99_delta, throughput_delta, config);
        let follow_up = follow_up_for(
            &operation,
            classification,
            artifact,
            config,
            issue_ids,
            errors,
        );
        let current_source_json = string_field(row, "current_source_json");
        out.push(PerformanceDeltaRow {
            row_id: format!("comparison:{operation}:{artifact}"),
            row_kind: "comparison".to_owned(),
            operation: operation.clone(),
            source_artifact: artifact.to_owned(),
            reference_artifact: string_field(row, "reference_source_json"),
            current_source_json,
            reference_p99_us: number_field(row, "reference_p99_us"),
            current_p99_us: number_field(row, "current_p99_us"),
            p99_delta_percent: p99_delta,
            reference_throughput_ops_sec: number_field(row, "reference_throughput_ops_sec"),
            current_throughput_ops_sec: number_field(row, "current_throughput_ops_sec"),
            throughput_delta_percent: throughput_delta,
            classification,
            release_claim_state: release_claim_state(classification).to_owned(),
            follow_up_present: follow_up
                .as_ref()
                .is_some_and(|bead| issue_ids.contains(bead)),
            follow_up_bead: follow_up,
            rationale: comparison_rationale(row, classification),
            reproduction_command: format!(
                "cargo run -p ffs-harness -- performance-delta-closeout --config {DEFAULT_PERFORMANCE_DELTA_CLOSEOUT_CONFIG}"
            ),
        });
    }
    Ok(out)
}

fn unmeasured_claim_row(
    claim: &PerformanceUnmeasuredClaim,
    issue_ids: &BTreeSet<String>,
    errors: &mut Vec<String>,
) -> PerformanceDeltaRow {
    let follow_up_present = issue_ids.contains(&claim.follow_up_bead);
    if !follow_up_present {
        errors.push(format!(
            "unmeasured claim {} references missing follow-up bead {}",
            claim.claim_id, claim.follow_up_bead
        ));
    }
    PerformanceDeltaRow {
        row_id: format!("claim:{}", claim.claim_id),
        row_kind: "claim".to_owned(),
        operation: claim.operation.clone(),
        source_artifact: claim.claim_id.clone(),
        reference_artifact: None,
        current_source_json: None,
        reference_p99_us: None,
        current_p99_us: None,
        p99_delta_percent: None,
        reference_throughput_ops_sec: None,
        current_throughput_ops_sec: None,
        throughput_delta_percent: None,
        classification: PerformanceDeltaClassification::Unmeasured,
        release_claim_state: release_claim_state(PerformanceDeltaClassification::Unmeasured)
            .to_owned(),
        follow_up_bead: Some(claim.follow_up_bead.clone()),
        follow_up_present,
        rationale: claim.reason.clone(),
        reproduction_command: claim.reproduction_command.clone(),
    }
}

fn load_measurements(artifact: &str) -> Result<Vec<Measurement>> {
    let value = load_json_file(artifact)?;
    let measurements = value
        .get("measurements")
        .and_then(Value::as_array)
        .with_context(|| format!("{artifact} must contain measurements[]"))?;
    let mut out = Vec::new();
    for row in measurements {
        let operation = string_field(row, "operation")
            .with_context(|| format!("{artifact} measurement missing operation"))?;
        out.push(Measurement {
            operation,
            source_artifact: artifact.to_owned(),
            source_json: string_field(row, "source_json"),
            p99_us: number_field(row, "p99_us"),
            throughput_ops_sec: number_field(row, "throughput_ops_sec"),
            status: string_field(row, "status").unwrap_or_else(|| "unknown".to_owned()),
            command: string_field(row, "command").unwrap_or_default(),
        });
    }
    Ok(out)
}

fn load_json_file(path: &str) -> Result<Value> {
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read artifact {path}"))?;
    serde_json::from_str(&text).with_context(|| format!("invalid JSON artifact {path}"))
}

fn row_with_reference(
    row_kind: &str,
    current: &Measurement,
    reference: &Measurement,
    config: &PerformanceDeltaCloseoutConfig,
    issue_ids: &BTreeSet<String>,
    errors: &mut Vec<String>,
) -> PerformanceDeltaRow {
    let p99_delta = match (current.p99_us, reference.p99_us) {
        (Some(current_p99), Some(reference_p99)) if reference_p99 > 0.0 => {
            Some(percent_delta(current_p99, reference_p99))
        }
        _ => None,
    };
    let throughput_delta = match (current.throughput_ops_sec, reference.throughput_ops_sec) {
        (Some(current_tput), Some(reference_tput)) if reference_tput > 0.0 => {
            Some(percent_delta(current_tput, reference_tput))
        }
        _ => None,
    };
    let classification = classify_delta(p99_delta, throughput_delta, config);
    let follow_up = follow_up_for(
        &current.operation,
        classification,
        &current.source_artifact,
        config,
        issue_ids,
        errors,
    );
    PerformanceDeltaRow {
        row_id: format!(
            "{row_kind}:{}:{}",
            current.operation, current.source_artifact
        ),
        row_kind: row_kind.to_owned(),
        operation: current.operation.clone(),
        source_artifact: current.source_artifact.clone(),
        reference_artifact: Some(reference.source_artifact.clone()),
        current_source_json: current.source_json.clone(),
        reference_p99_us: reference.p99_us,
        current_p99_us: current.p99_us,
        p99_delta_percent: p99_delta,
        reference_throughput_ops_sec: reference.throughput_ops_sec,
        current_throughput_ops_sec: current.throughput_ops_sec,
        throughput_delta_percent: throughput_delta,
        classification,
        release_claim_state: release_claim_state(classification).to_owned(),
        follow_up_present: follow_up
            .as_ref()
            .is_some_and(|bead| issue_ids.contains(bead)),
        follow_up_bead: follow_up,
        rationale: reference_rationale(current, reference, classification),
        reproduction_command: current.command.clone(),
    }
}

fn row_without_reference(
    row_kind: &str,
    current: &Measurement,
    classification: PerformanceDeltaClassification,
    config: &PerformanceDeltaCloseoutConfig,
    issue_ids: &BTreeSet<String>,
    errors: &mut Vec<String>,
) -> PerformanceDeltaRow {
    let follow_up = follow_up_for(
        &current.operation,
        classification,
        &current.source_artifact,
        config,
        issue_ids,
        errors,
    );
    PerformanceDeltaRow {
        row_id: format!(
            "{row_kind}:{}:{}",
            current.operation, current.source_artifact
        ),
        row_kind: row_kind.to_owned(),
        operation: current.operation.clone(),
        source_artifact: current.source_artifact.clone(),
        reference_artifact: None,
        current_source_json: current.source_json.clone(),
        reference_p99_us: None,
        current_p99_us: current.p99_us,
        p99_delta_percent: None,
        reference_throughput_ops_sec: None,
        current_throughput_ops_sec: current.throughput_ops_sec,
        throughput_delta_percent: None,
        classification,
        release_claim_state: release_claim_state(classification).to_owned(),
        follow_up_present: follow_up
            .as_ref()
            .is_some_and(|bead| issue_ids.contains(bead)),
        follow_up_bead: follow_up,
        rationale: missing_reference_rationale(current, classification),
        reproduction_command: current.command.clone(),
    }
}

fn classify_delta(
    p99_delta: Option<f64>,
    throughput_delta: Option<f64>,
    config: &PerformanceDeltaCloseoutConfig,
) -> PerformanceDeltaClassification {
    if p99_delta.is_none() && throughput_delta.is_none() {
        return PerformanceDeltaClassification::MissingReference;
    }
    if p99_delta.is_some_and(|delta| delta >= config.policy.p99_fail_percent)
        || throughput_delta.is_some_and(|delta| delta <= config.policy.throughput_fail_percent)
    {
        return PerformanceDeltaClassification::Regression;
    }
    if p99_delta.is_some_and(|delta| delta >= config.policy.p99_warn_percent) {
        return PerformanceDeltaClassification::Warning;
    }
    if p99_delta.is_some_and(|delta| delta < 0.0)
        || throughput_delta.is_some_and(|delta| delta > 0.0)
    {
        return PerformanceDeltaClassification::Improved;
    }
    PerformanceDeltaClassification::WithinThreshold
}

fn follow_up_for(
    operation: &str,
    classification: PerformanceDeltaClassification,
    source_artifact: &str,
    config: &PerformanceDeltaCloseoutConfig,
    issue_ids: &BTreeSet<String>,
    errors: &mut Vec<String>,
) -> Option<String> {
    if !classification.requires_follow_up() {
        return None;
    }
    let exact = config
        .follow_up_overrides
        .iter()
        .find(|override_row| {
            override_row.operation == operation
                && override_row
                    .classification
                    .is_none_or(|class| class == classification)
                && override_row
                    .source_contains
                    .as_ref()
                    .is_none_or(|needle| source_artifact.contains(needle))
        })
        .map(|override_row| override_row.follow_up_bead.clone());
    let follow_up = exact.unwrap_or_else(|| {
        if classification == PerformanceDeltaClassification::MissingReference {
            config.policy.missing_reference_follow_up_bead.clone()
        } else {
            String::new()
        }
    });
    if follow_up.is_empty() {
        errors.push(format!(
            "{operation} has classification {} but no follow-up bead",
            classification.label()
        ));
        return None;
    }
    if !issue_ids.contains(&follow_up) {
        errors.push(format!(
            "{operation} follow-up bead {follow_up} is missing from {}",
            config.issues_path
        ));
    }
    Some(follow_up)
}

fn validate_follow_up_overrides(
    config: &PerformanceDeltaCloseoutConfig,
    issue_ids: &BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    for override_row in &config.follow_up_overrides {
        if override_row.operation.trim().is_empty() {
            errors.push("follow_up_overrides.operation must not be empty".to_owned());
        }
        if !issue_ids.contains(&override_row.follow_up_bead) {
            errors.push(format!(
                "follow-up override for {} references missing bead {}",
                override_row.operation, override_row.follow_up_bead
            ));
        }
    }
    if !issue_ids.contains(&config.policy.missing_reference_follow_up_bead) {
        errors.push(format!(
            "missing-reference follow-up bead {} is absent from {}",
            config.policy.missing_reference_follow_up_bead, config.issues_path
        ));
    }
}

fn validate_required_follow_ups(rows: &[PerformanceDeltaRow], errors: &mut Vec<String>) {
    for row in rows {
        if row.classification.requires_follow_up() && row.follow_up_bead.is_none() {
            errors.push(format!(
                "{} requires follow-up for {}",
                row.row_id,
                row.classification.label()
            ));
        }
        if row.classification.requires_follow_up() && !row.follow_up_present {
            errors.push(format!(
                "{} follow-up bead is not present in tracker",
                row.row_id
            ));
        }
    }
}

fn count_classifications(rows: &[PerformanceDeltaRow]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for row in rows {
        *counts
            .entry(row.classification.label().to_owned())
            .or_insert(0) += 1;
    }
    counts
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn number_field(value: &Value, key: &str) -> Option<f64> {
    let raw = value.get(key)?;
    raw.as_f64()
        .or_else(|| raw.as_i64().map(|number| number as f64))
        .or_else(|| raw.as_u64().map(|number| number as f64))
}

fn percent_delta(current: f64, reference: f64) -> f64 {
    ((current - reference) / reference) * 100.0
}

fn release_claim_state(classification: PerformanceDeltaClassification) -> &'static str {
    match classification {
        PerformanceDeltaClassification::Improved
        | PerformanceDeltaClassification::WithinThreshold => "measured_local",
        PerformanceDeltaClassification::Warning => "experimental",
        PerformanceDeltaClassification::Regression
        | PerformanceDeltaClassification::MissingReference
        | PerformanceDeltaClassification::PendingCapability
        | PerformanceDeltaClassification::Unmeasured => "unknown",
    }
}

fn reference_rationale(
    current: &Measurement,
    reference: &Measurement,
    classification: PerformanceDeltaClassification,
) -> String {
    format!(
        "same-operation comparison against {}; classified as {}",
        reference.source_artifact,
        classification.label()
    )
    .replace(&current.source_artifact, "")
}

fn comparison_rationale(row: &Value, classification: PerformanceDeltaClassification) -> String {
    let verdict = string_field(row, "verdict").unwrap_or_else(|| "unknown".to_owned());
    format!(
        "comparison artifact verdict={verdict}; classified as {}",
        classification.label()
    )
}

fn missing_reference_rationale(
    current: &Measurement,
    classification: PerformanceDeltaClassification,
) -> String {
    match classification {
        PerformanceDeltaClassification::MissingReference => format!(
            "measured in {} but no checked-in same-operation reference baseline exists",
            current.source_artifact
        ),
        PerformanceDeltaClassification::PendingCapability => format!(
            "artifact {} is pending because required host capability was unavailable",
            current.source_artifact
        ),
        PerformanceDeltaClassification::Unmeasured => {
            format!(
                "artifact {} did not produce a measured row",
                current.source_artifact
            )
        }
        other => format!("classified as {}", other.label()),
    }
}

fn format_optional_percent(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_owned(), |number| format!("{number:.3}%"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn issue_ids() -> BTreeSet<String> {
        [
            "bd-rchk5.5",
            "bd-rchk5.6",
            "bd-rchk5.7",
            "bd-rchk5.8",
            "bd-9vzzk",
            "bd-t21em",
        ]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect()
    }

    fn base_config() -> PerformanceDeltaCloseoutConfig {
        PerformanceDeltaCloseoutConfig {
            schema_version: PERFORMANCE_DELTA_CLOSEOUT_SCHEMA_VERSION,
            closeout_id: "test-closeout".to_owned(),
            source_bead_id: "bd-rchk5.4".to_owned(),
            generated_at: "2026-05-03T00:00:00Z".to_owned(),
            issues_path: ".beads/issues.jsonl".to_owned(),
            reference_baselines: vec!["reference.json".to_owned()],
            current_baselines: vec!["current.json".to_owned()],
            comparison_artifacts: Vec::new(),
            policy: PerformanceDeltaPolicy {
                p99_warn_percent: 10.0,
                p99_fail_percent: 50.0,
                throughput_fail_percent: -25.0,
                missing_reference_follow_up_bead: "bd-rchk5.8".to_owned(),
            },
            follow_up_overrides: vec![PerformanceDeltaFollowUpOverride {
                operation: "mount_cold".to_owned(),
                follow_up_bead: "bd-rchk5.5".to_owned(),
                classification: Some(PerformanceDeltaClassification::Regression),
                source_contains: None,
            }],
            unmeasured_claims: Vec::new(),
        }
    }

    fn workspace_path(relative: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative)
    }

    fn absolutize_paths(
        mut config: PerformanceDeltaCloseoutConfig,
    ) -> PerformanceDeltaCloseoutConfig {
        config.issues_path = workspace_path(&config.issues_path).display().to_string();
        config.reference_baselines = config
            .reference_baselines
            .iter()
            .map(|path| workspace_path(path).display().to_string())
            .collect();
        config.current_baselines = config
            .current_baselines
            .iter()
            .map(|path| workspace_path(path).display().to_string())
            .collect();
        config.comparison_artifacts = config
            .comparison_artifacts
            .iter()
            .map(|path| workspace_path(path).display().to_string())
            .collect();
        config
    }

    #[test]
    fn classify_delta_marks_reference_regression() {
        let config = base_config();
        let class = classify_delta(Some(55.0), Some(-5.0), &config);
        assert_eq!(class, PerformanceDeltaClassification::Regression);
    }

    #[test]
    fn classify_delta_marks_throughput_regression() {
        let config = base_config();
        let class = classify_delta(Some(1.0), Some(-30.0), &config);
        assert_eq!(class, PerformanceDeltaClassification::Regression);
    }

    #[test]
    fn classify_delta_marks_improvement() {
        let config = base_config();
        let class = classify_delta(Some(-80.0), Some(70.0), &config);
        assert_eq!(class, PerformanceDeltaClassification::Improved);
    }

    #[test]
    fn missing_reference_uses_policy_follow_up() {
        let mut errors = Vec::new();
        let follow_up = follow_up_for(
            "wal_commit_4k_sync",
            PerformanceDeltaClassification::MissingReference,
            "current.json",
            &base_config(),
            &issue_ids(),
            &mut errors,
        );
        assert_eq!(follow_up.as_deref(), Some("bd-rchk5.8"));
        assert!(errors.is_empty());
    }

    #[test]
    fn missing_override_bead_is_invalid() {
        let mut errors = Vec::new();
        let follow_up = follow_up_for(
            "mount_cold",
            PerformanceDeltaClassification::Regression,
            "comparison.json",
            &base_config(),
            &BTreeSet::new(),
            &mut errors,
        );
        assert_eq!(follow_up.as_deref(), Some("bd-rchk5.5"));
        assert!(errors.iter().any(|error| error.contains("bd-rchk5.5")));
    }

    #[test]
    fn checked_in_closeout_config_validates_and_links_followups() {
        let config = load_performance_delta_closeout_config(Path::new(&workspace_path(
            DEFAULT_PERFORMANCE_DELTA_CLOSEOUT_CONFIG,
        )))
        .expect("load checked-in config");
        let config = absolutize_paths(config);
        let report = run_performance_delta_closeout(&config).expect("build closeout report");
        assert!(report.valid, "{:?}", report.errors);
        assert!(report.row_count >= 10);
        assert!(
            report
                .classification_counts
                .contains_key(PerformanceDeltaClassification::Regression.label())
        );
        assert!(
            report
                .classification_counts
                .contains_key(PerformanceDeltaClassification::MissingReference.label())
        );
        assert!(
            report
                .follow_up_beads
                .iter()
                .any(|bead| bead == "bd-rchk5.5")
        );
        assert!(
            report
                .follow_up_beads
                .iter()
                .any(|bead| bead == "bd-rchk5.8")
        );
    }

    #[test]
    fn markdown_mentions_follow_up_beads() {
        let report = PerformanceDeltaCloseoutReport {
            schema_version: PERFORMANCE_DELTA_CLOSEOUT_SCHEMA_VERSION,
            closeout_id: "test".to_owned(),
            source_bead_id: "bd-rchk5.4".to_owned(),
            generated_at: "now".to_owned(),
            valid: true,
            row_count: 1,
            classification_counts: BTreeMap::from([("regression".to_owned(), 1)]),
            follow_up_beads: vec!["bd-rchk5.5".to_owned()],
            rows_requiring_follow_up: 1,
            rows: vec![PerformanceDeltaRow {
                row_id: "comparison:mount_cold".to_owned(),
                row_kind: "comparison".to_owned(),
                operation: "mount_cold".to_owned(),
                source_artifact: "comparison.json".to_owned(),
                reference_artifact: None,
                current_source_json: None,
                reference_p99_us: Some(10.0),
                current_p99_us: Some(20.0),
                p99_delta_percent: Some(100.0),
                reference_throughput_ops_sec: None,
                current_throughput_ops_sec: None,
                throughput_delta_percent: None,
                classification: PerformanceDeltaClassification::Regression,
                release_claim_state: "unknown".to_owned(),
                follow_up_bead: Some("bd-rchk5.5".to_owned()),
                follow_up_present: true,
                rationale: "slow".to_owned(),
                reproduction_command: "cargo run".to_owned(),
            }],
            errors: Vec::new(),
        };
        let markdown = render_performance_delta_closeout_markdown(&report);
        assert!(markdown.contains("bd-rchk5.5"));
        assert!(markdown.contains("mount_cold"));
    }
}
