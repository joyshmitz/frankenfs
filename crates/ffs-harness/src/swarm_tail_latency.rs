#![allow(clippy::too_many_lines)]
#![forbid(unsafe_code)]

//! Swarm tail-latency decomposition ledger for `bd-p2j3e.1`.
//!
//! This validator keeps 64-core/256GB performance evidence honest by requiring
//! explicit p99 attribution for queueing, service, I/O, retries,
//! synchronization, allocator, repair backlog, cache pressure, WAL fsync, and
//! FUSE wrapper time before any release wording can become stronger than an
//! experimental or missing-reference claim.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub const DEFAULT_SWARM_TAIL_LATENCY_LEDGER: &str = "benchmarks/swarm_tail_latency_ledger.json";
pub const SWARM_TAIL_LATENCY_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_DOMINANCE_THRESHOLD_RATIO: f64 = 0.20;
pub const DEFAULT_COMPONENT_SUM_TOLERANCE_RATIO: f64 = 0.35;

const REQUIRED_COMPONENTS: [TailLatencyComponent; 10] = [
    TailLatencyComponent::Queueing,
    TailLatencyComponent::Service,
    TailLatencyComponent::Io,
    TailLatencyComponent::Retries,
    TailLatencyComponent::Synchronization,
    TailLatencyComponent::Allocator,
    TailLatencyComponent::RepairBacklog,
    TailLatencyComponent::CachePressure,
    TailLatencyComponent::WalFsync,
    TailLatencyComponent::FuseWrapper,
];

const WATCHED_DOMINANT_COMPONENTS: [TailLatencyComponent; 5] = [
    TailLatencyComponent::FuseWrapper,
    TailLatencyComponent::WalFsync,
    TailLatencyComponent::RepairBacklog,
    TailLatencyComponent::Synchronization,
    TailLatencyComponent::Allocator,
];

const REQUIRED_LOG_FIELDS: [&str; 17] = [
    "workload_id",
    "workload_seed",
    "scenario_id",
    "host_fingerprint",
    "cpu_cores_logical",
    "ram_total_gb",
    "ram_available_gb",
    "component_latency_buckets",
    "p50_latency_us",
    "p95_latency_us",
    "p99_latency_us",
    "queue_depth",
    "backpressure_state",
    "release_claim_state",
    "reference_state",
    "reproduction_command",
    "artifact_paths",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmTailLatencyLedger {
    pub schema_version: u32,
    pub ledger_id: String,
    pub generated_at: String,
    pub target_host: SwarmTailTargetHost,
    #[serde(default = "default_dominance_threshold_ratio")]
    pub dominance_threshold_ratio: f64,
    #[serde(default = "default_component_sum_tolerance_ratio")]
    pub component_sum_tolerance_ratio: f64,
    pub rows: Vec<SwarmTailLatencyRow>,
    #[serde(default)]
    pub required_log_fields: Vec<String>,
    #[serde(default)]
    pub release_gate_consumers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmTailTargetHost {
    pub min_cpu_cores_logical: u32,
    pub min_ram_total_gb: u32,
    pub min_ram_available_gb: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmTailLatencyRow {
    pub workload_id: String,
    #[serde(default)]
    pub workload_seed: u64,
    pub scenario_id: String,
    pub workload_class: SwarmTailWorkloadClass,
    pub host: SwarmTailHostFingerprint,
    pub latency: TailLatencyBuckets,
    pub queue_depth: TailQueueDepth,
    pub backpressure_state: TailBackpressureState,
    pub classification: TailLatencyClassification,
    pub release_claim_state: TailReleaseClaimState,
    pub reference_state: TailReferenceState,
    pub public_wording: String,
    pub reproduction_command: String,
    pub raw_logs: Vec<String>,
    pub artifact_paths: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmTailWorkloadClass {
    MetadataStorm,
    AppendFsync,
    MixedReadWrite,
    ScrubRepairOverlap,
    CachePressure,
    MountLifecycle,
}

impl SwarmTailWorkloadClass {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MetadataStorm => "metadata_storm",
            Self::AppendFsync => "append_fsync",
            Self::MixedReadWrite => "mixed_read_write",
            Self::ScrubRepairOverlap => "scrub_repair_overlap",
            Self::CachePressure => "cache_pressure",
            Self::MountLifecycle => "mount_lifecycle",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmTailHostFingerprint {
    pub host_fingerprint: String,
    pub cpu_cores_logical: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub numa_nodes: Option<u32>,
    pub ram_total_gb: f64,
    pub ram_available_gb: f64,
    pub storage_class: String,
    pub kernel: String,
    pub lane: TailHostLane,
}

impl SwarmTailHostFingerprint {
    #[must_use]
    pub fn complete(&self) -> bool {
        !self.host_fingerprint.trim().is_empty()
            && self.cpu_cores_logical > 0
            && self.ram_total_gb > 0.0
            && self.ram_available_gb > 0.0
            && !self.storage_class.trim().is_empty()
            && !self.kernel.trim().is_empty()
    }

    #[must_use]
    pub fn meets_target(&self, target: &SwarmTailTargetHost) -> bool {
        self.cpu_cores_logical >= target.min_cpu_cores_logical
            && self.ram_total_gb >= f64::from(target.min_ram_total_gb)
            && self.ram_available_gb >= f64::from(target.min_ram_available_gb)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TailHostLane {
    DeveloperSmoke,
    RchWorker,
    PermissionedLargeHost,
    CiSmoke,
}

impl TailHostLane {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DeveloperSmoke => "developer_smoke",
            Self::RchWorker => "rch_worker",
            Self::PermissionedLargeHost => "permissioned_large_host",
            Self::CiSmoke => "ci_smoke",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TailLatencyBuckets {
    pub p50_latency_us: f64,
    pub p95_latency_us: f64,
    pub p99_latency_us: f64,
    pub components: Vec<TailLatencyComponentBucket>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TailLatencyComponentBucket {
    pub component: TailLatencyComponent,
    pub p50_us: f64,
    pub p95_us: f64,
    pub p99_us: f64,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TailLatencyComponent {
    Queueing,
    Service,
    Io,
    Retries,
    Synchronization,
    Allocator,
    RepairBacklog,
    CachePressure,
    WalFsync,
    FuseWrapper,
}

impl TailLatencyComponent {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Queueing => "queueing",
            Self::Service => "service",
            Self::Io => "io",
            Self::Retries => "retries",
            Self::Synchronization => "synchronization",
            Self::Allocator => "allocator",
            Self::RepairBacklog => "repair_backlog",
            Self::CachePressure => "cache_pressure",
            Self::WalFsync => "wal_fsync",
            Self::FuseWrapper => "fuse_wrapper",
        }
    }

    #[must_use]
    pub fn watched_for_dominance(self) -> bool {
        WATCHED_DOMINANT_COMPONENTS.contains(&self)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TailQueueDepth {
    pub average: f64,
    pub p99: f64,
    pub max: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TailBackpressureState {
    Healthy,
    Throttled,
    Critical,
    Unknown,
}

impl TailBackpressureState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Throttled => "throttled",
            Self::Critical => "critical",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TailLatencyClassification {
    Pass,
    Warn,
    Fail,
    Noisy,
    MissingReference,
}

impl TailLatencyClassification {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::Noisy => "noisy",
            Self::MissingReference => "missing_reference",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TailReleaseClaimState {
    Experimental,
    SmallHostSmoke,
    MissingReference,
    MeasuredLocal,
    MeasuredAuthoritative,
    Blocked,
}

impl TailReleaseClaimState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Experimental => "experimental",
            Self::SmallHostSmoke => "small_host_smoke",
            Self::MissingReference => "missing_reference",
            Self::MeasuredLocal => "measured_local",
            Self::MeasuredAuthoritative => "measured_authoritative",
            Self::Blocked => "blocked",
        }
    }

    #[must_use]
    pub const fn stronger_than_experimental(self) -> bool {
        matches!(self, Self::MeasuredLocal | Self::MeasuredAuthoritative)
    }

    #[must_use]
    pub const fn safe_for_incomplete_evidence(self) -> bool {
        matches!(
            self,
            Self::Experimental | Self::SmallHostSmoke | Self::MissingReference | Self::Blocked
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailReferenceState {
    pub state: TailReferenceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_artifact: Option<String>,
    pub rationale: String,
}

impl TailReferenceState {
    #[must_use]
    pub fn comparable(&self) -> bool {
        self.state == TailReferenceKind::Comparable
            && self
                .baseline_id
                .as_ref()
                .is_some_and(|value| !value.trim().is_empty())
            && self
                .baseline_artifact
                .as_ref()
                .is_some_and(|value| !value.trim().is_empty())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TailReferenceKind {
    Comparable,
    Missing,
    Noisy,
    NotApplicable,
}

impl TailReferenceKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Comparable => "comparable",
            Self::Missing => "missing",
            Self::Noisy => "noisy",
            Self::NotApplicable => "not_applicable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmTailLatencyReport {
    pub schema_version: u32,
    pub ledger_id: String,
    pub valid: bool,
    pub row_count: usize,
    pub missing_reference_count: usize,
    pub incomplete_host_count: usize,
    pub component_dominance_alert_count: usize,
    pub component_sum_tolerance_ratio: f64,
    pub classification_counts: BTreeMap<String, usize>,
    pub release_claim_counts: BTreeMap<String, usize>,
    pub rows: Vec<SwarmTailLatencyReportRow>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmTailLatencyReportRow {
    pub workload_id: String,
    pub scenario_id: String,
    pub workload_class: String,
    pub classification: String,
    pub release_claim_state: String,
    pub host_meets_target: bool,
    pub workload_seed: u64,
    pub p99_latency_us: f64,
    pub component_p99_sum_us: f64,
    pub component_sum_delta_ratio: f64,
    pub dominant_component: String,
    pub dominant_component_share: f64,
    pub watched_dominant_components: Vec<String>,
    pub reference_state: String,
    pub backpressure_state: String,
    pub queue_depth_p99: f64,
}

#[must_use]
pub const fn default_dominance_threshold_ratio() -> f64 {
    DEFAULT_DOMINANCE_THRESHOLD_RATIO
}

#[must_use]
pub const fn default_component_sum_tolerance_ratio() -> f64 {
    DEFAULT_COMPONENT_SUM_TOLERANCE_RATIO
}

pub fn load_swarm_tail_latency_ledger(path: &Path) -> Result<SwarmTailLatencyLedger> {
    let text = fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read swarm tail-latency ledger {}",
            path.display()
        )
    })?;
    serde_json::from_str(&text)
        .with_context(|| format!("invalid swarm tail-latency ledger JSON {}", path.display()))
}

#[must_use]
pub fn validate_swarm_tail_latency_ledger(
    ledger: &SwarmTailLatencyLedger,
) -> SwarmTailLatencyReport {
    let mut errors = Vec::new();
    validate_ledger_shape(ledger, &mut errors);
    let mut rows = Vec::new();

    for row in &ledger.rows {
        validate_row(ledger, row, &mut errors);
        rows.push(build_report_row(ledger, row));
    }

    let missing_reference_count = ledger
        .rows
        .iter()
        .filter(|row| row.reference_state.state == TailReferenceKind::Missing)
        .count();
    let incomplete_host_count = ledger
        .rows
        .iter()
        .filter(|row| !row.host.complete())
        .count();
    let component_dominance_alert_count = rows
        .iter()
        .filter(|row| !row.watched_dominant_components.is_empty())
        .count();

    SwarmTailLatencyReport {
        schema_version: SWARM_TAIL_LATENCY_SCHEMA_VERSION,
        ledger_id: ledger.ledger_id.clone(),
        valid: errors.is_empty(),
        row_count: ledger.rows.len(),
        missing_reference_count,
        incomplete_host_count,
        component_dominance_alert_count,
        component_sum_tolerance_ratio: ledger.component_sum_tolerance_ratio,
        classification_counts: count_classifications(ledger),
        release_claim_counts: count_release_claims(ledger),
        rows,
        errors,
    }
}

pub fn fail_on_swarm_tail_latency_errors(report: &SwarmTailLatencyReport) -> Result<()> {
    if report.valid {
        Ok(())
    } else {
        bail!(
            "swarm tail-latency ledger validation failed: {} error(s)",
            report.errors.len()
        )
    }
}

#[must_use]
pub fn render_swarm_tail_latency_markdown(report: &SwarmTailLatencyReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Swarm Tail-Latency Ledger\n");
    let _ = writeln!(out, "- Ledger: `{}`", report.ledger_id);
    let _ = writeln!(out, "- Valid: `{}`", report.valid);
    let _ = writeln!(out, "- Rows: `{}`", report.row_count);
    let _ = writeln!(
        out,
        "- Missing references: `{}`",
        report.missing_reference_count
    );
    let _ = writeln!(
        out,
        "- Incomplete host fingerprints: `{}`",
        report.incomplete_host_count
    );
    let _ = writeln!(
        out,
        "- Component dominance alerts: `{}`",
        report.component_dominance_alert_count
    );
    let _ = writeln!(
        out,
        "- Component sum tolerance: `{:.1}%`",
        report.component_sum_tolerance_ratio * 100.0
    );

    out.push_str("\n## Classification Counts\n\n");
    for (classification, count) in &report.classification_counts {
        let _ = writeln!(out, "- `{classification}`: {count}");
    }
    out.push_str("\n## Release Claim Counts\n\n");
    for (claim, count) in &report.release_claim_counts {
        let _ = writeln!(out, "- `{claim}`: {count}");
    }

    out.push_str("\n## Tail Attribution\n\n");
    out.push_str(
        "| Scenario | Workload | Seed | Class | Claim | p99 | Component Sum | Dominant | Watched Alerts | Reference |\n",
    );
    out.push_str("|---|---|---:|---|---|---:|---:|---|---|---|\n");
    for row in &report.rows {
        let watched = if row.watched_dominant_components.is_empty() {
            "none".to_owned()
        } else {
            row.watched_dominant_components.join(", ")
        };
        let _ = writeln!(
            out,
            "| `{}` | `{}` | {} | `{}` | `{}` | {:.1}us | {:.1}us ({:.1}%) | `{}` {:.1}% | {} | `{}` |",
            row.scenario_id,
            row.workload_id,
            row.workload_seed,
            row.workload_class,
            row.release_claim_state,
            row.p99_latency_us,
            row.component_p99_sum_us,
            row.component_sum_delta_ratio * 100.0,
            row.dominant_component,
            row.dominant_component_share * 100.0,
            watched.replace('|', "/"),
            row.reference_state
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

fn validate_ledger_shape(ledger: &SwarmTailLatencyLedger, errors: &mut Vec<String>) {
    if ledger.schema_version != SWARM_TAIL_LATENCY_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version must be {SWARM_TAIL_LATENCY_SCHEMA_VERSION}"
        ));
    }
    require_non_empty("ledger_id", &ledger.ledger_id, errors);
    require_non_empty("generated_at", &ledger.generated_at, errors);
    if ledger.target_host.min_cpu_cores_logical < 64 {
        errors.push("target_host.min_cpu_cores_logical must be at least 64".to_owned());
    }
    if ledger.target_host.min_ram_total_gb < 256 {
        errors.push("target_host.min_ram_total_gb must be at least 256".to_owned());
    }
    if ledger.target_host.min_ram_available_gb == 0 {
        errors.push("target_host.min_ram_available_gb must be positive".to_owned());
    }
    if !(ledger.dominance_threshold_ratio > 0.0 && ledger.dominance_threshold_ratio <= 1.0) {
        errors.push("dominance_threshold_ratio must be in (0,1]".to_owned());
    }
    if !(ledger.component_sum_tolerance_ratio >= 0.0 && ledger.component_sum_tolerance_ratio <= 1.0)
    {
        errors.push("component_sum_tolerance_ratio must be in [0,1]".to_owned());
    }
    if ledger.rows.is_empty() {
        errors.push("rows must not be empty".to_owned());
    }
    validate_required_log_fields(&ledger.required_log_fields, errors);
    if ledger.release_gate_consumers.is_empty() {
        errors.push("release_gate_consumers must include at least one consumer".to_owned());
    }
}

fn validate_required_log_fields(fields: &[String], errors: &mut Vec<String>) {
    let field_set = fields.iter().map(String::as_str).collect::<BTreeSet<_>>();
    for required in REQUIRED_LOG_FIELDS {
        if !field_set.contains(required) {
            errors.push(format!("required_log_fields missing {required}"));
        }
    }
}

fn validate_row(
    ledger: &SwarmTailLatencyLedger,
    row: &SwarmTailLatencyRow,
    errors: &mut Vec<String>,
) {
    require_non_empty("workload_id", &row.workload_id, errors);
    if row.workload_seed == 0 {
        errors.push(format!(
            "scenario {} workload_seed must be non-zero",
            row.scenario_id
        ));
    }
    require_non_empty("scenario_id", &row.scenario_id, errors);
    require_non_empty("public_wording", &row.public_wording, errors);
    require_non_empty("reproduction_command", &row.reproduction_command, errors);
    validate_paths("raw_logs", &row.raw_logs, errors);
    validate_paths("artifact_paths", &row.artifact_paths, errors);
    validate_host(ledger, row, errors);
    validate_latency(ledger, &row.scenario_id, &row.latency, errors);
    validate_queue_depth(&row.scenario_id, &row.queue_depth, errors);
    validate_reference_and_claim(ledger, row, errors);
}

fn validate_host(
    ledger: &SwarmTailLatencyLedger,
    row: &SwarmTailLatencyRow,
    errors: &mut Vec<String>,
) {
    require_non_empty(
        &format!("scenario {} host.host_fingerprint", row.scenario_id),
        &row.host.host_fingerprint,
        errors,
    );
    require_non_empty(
        &format!("scenario {} host.storage_class", row.scenario_id),
        &row.host.storage_class,
        errors,
    );
    require_non_empty(
        &format!("scenario {} host.kernel", row.scenario_id),
        &row.host.kernel,
        errors,
    );
    if row.host.cpu_cores_logical == 0 {
        errors.push(format!(
            "scenario {} host.cpu_cores_logical must be positive",
            row.scenario_id
        ));
    }
    if let Some(numa_nodes) = row.host.numa_nodes
        && numa_nodes == 0
    {
        errors.push(format!(
            "scenario {} host.numa_nodes must be positive when present",
            row.scenario_id
        ));
    }
    if row.host.ram_total_gb <= 0.0 || row.host.ram_available_gb <= 0.0 {
        errors.push(format!(
            "scenario {} host RAM totals must be positive",
            row.scenario_id
        ));
    }
    if row.host.ram_available_gb > row.host.ram_total_gb {
        errors.push(format!(
            "scenario {} ram_available_gb exceeds ram_total_gb",
            row.scenario_id
        ));
    }

    if !row.host.meets_target(&ledger.target_host)
        && !row.release_claim_state.safe_for_incomplete_evidence()
    {
        errors.push(format!(
            "scenario {} is below the 64-core/256GB target but claims {}",
            row.scenario_id,
            row.release_claim_state.label()
        ));
    }
    if row.release_claim_state == TailReleaseClaimState::MeasuredAuthoritative
        && row.host.lane != TailHostLane::PermissionedLargeHost
    {
        errors.push(format!(
            "scenario {} authoritative claim must run in permissioned_large_host lane",
            row.scenario_id
        ));
    }
}

fn validate_latency(
    ledger: &SwarmTailLatencyLedger,
    scenario_id: &str,
    latency: &TailLatencyBuckets,
    errors: &mut Vec<String>,
) {
    if latency.p50_latency_us <= 0.0
        || latency.p95_latency_us <= 0.0
        || latency.p99_latency_us <= 0.0
    {
        errors.push(format!(
            "scenario {scenario_id} p50/p95/p99 latency buckets must be positive"
        ));
    }
    if latency.p50_latency_us > latency.p95_latency_us
        || latency.p95_latency_us > latency.p99_latency_us
    {
        errors.push(format!(
            "scenario {scenario_id} latency buckets must satisfy p50 <= p95 <= p99"
        ));
    }
    if latency.components.is_empty() {
        errors.push(format!(
            "scenario {scenario_id} component_latency_buckets must not be empty"
        ));
        return;
    }

    let mut seen = BTreeSet::new();
    for component in &latency.components {
        if !seen.insert(component.component) {
            errors.push(format!(
                "scenario {scenario_id} duplicates component {}",
                component.component.label()
            ));
        }
        require_non_empty(
            &format!(
                "scenario {scenario_id} component {} detail",
                component.component.label()
            ),
            &component.detail,
            errors,
        );
        if component.p50_us < 0.0 || component.p95_us < 0.0 || component.p99_us < 0.0 {
            errors.push(format!(
                "scenario {scenario_id} component {} latency buckets must be non-negative",
                component.component.label()
            ));
        }
        if component.p50_us > component.p95_us || component.p95_us > component.p99_us {
            errors.push(format!(
                "scenario {scenario_id} component {} must satisfy p50 <= p95 <= p99",
                component.component.label()
            ));
        }
        if component.p99_us > latency.p99_latency_us {
            errors.push(format!(
                "scenario {scenario_id} component {} p99 exceeds row p99",
                component.component.label()
            ));
        }
    }

    for required in REQUIRED_COMPONENTS {
        if !seen.contains(&required) {
            errors.push(format!(
                "scenario {scenario_id} missing required component {}",
                required.label()
            ));
        }
    }
    validate_component_total(ledger, scenario_id, latency, errors);
}

fn validate_component_total(
    ledger: &SwarmTailLatencyLedger,
    scenario_id: &str,
    latency: &TailLatencyBuckets,
    errors: &mut Vec<String>,
) {
    if latency.p99_latency_us <= 0.0 || latency.components.is_empty() {
        return;
    }
    let component_sum = component_p99_sum(latency);
    let delta_ratio = component_sum_delta_ratio(latency);
    if delta_ratio > ledger.component_sum_tolerance_ratio {
        errors.push(format!(
            "scenario {scenario_id} component p99 sum {:.1}us differs from row p99 {:.1}us by {:.1}% (tolerance {:.1}%)",
            component_sum,
            latency.p99_latency_us,
            delta_ratio * 100.0,
            ledger.component_sum_tolerance_ratio * 100.0
        ));
    }
}

fn validate_queue_depth(scenario_id: &str, queue: &TailQueueDepth, errors: &mut Vec<String>) {
    if queue.average < 0.0 || queue.p99 < 0.0 {
        errors.push(format!(
            "scenario {scenario_id} queue_depth average and p99 must be non-negative"
        ));
    }
    if queue.p99 < queue.average {
        errors.push(format!(
            "scenario {scenario_id} queue_depth.p99 must be >= average"
        ));
    }
    if queue.max == 0 {
        errors.push(format!(
            "scenario {scenario_id} queue_depth.max must be positive"
        ));
    }
    if queue.p99 > f64::from(queue.max) {
        errors.push(format!(
            "scenario {scenario_id} queue_depth.p99 exceeds queue_depth.max"
        ));
    }
}

fn validate_reference_and_claim(
    ledger: &SwarmTailLatencyLedger,
    row: &SwarmTailLatencyRow,
    errors: &mut Vec<String>,
) {
    require_non_empty(
        &format!("scenario {} reference rationale", row.scenario_id),
        &row.reference_state.rationale,
        errors,
    );
    if row.reference_state.state == TailReferenceKind::Comparable
        && !row.reference_state.comparable()
    {
        errors.push(format!(
            "scenario {} comparable reference requires baseline_id and baseline_artifact",
            row.scenario_id
        ));
    }
    if row.reference_state.state == TailReferenceKind::Missing
        && row.classification != TailLatencyClassification::MissingReference
    {
        errors.push(format!(
            "scenario {} missing reference must use missing_reference classification",
            row.scenario_id
        ));
    }
    if !row.reference_state.comparable() && row.release_claim_state.stronger_than_experimental() {
        errors.push(format!(
            "scenario {} public performance wording must remain experimental when reference evidence is {}",
            row.scenario_id,
            row.reference_state.state.label()
        ));
    }
    if (!row.host.complete() || row.latency.components.is_empty())
        && !row.release_claim_state.safe_for_incomplete_evidence()
    {
        errors.push(format!(
            "scenario {} public performance wording must remain experimental when host fingerprint or component attribution is incomplete",
            row.scenario_id
        ));
    }
    if row.release_claim_state == TailReleaseClaimState::MeasuredAuthoritative
        && (!row.host.meets_target(&ledger.target_host) || !row.reference_state.comparable())
    {
        errors.push(format!(
            "scenario {} measured_authoritative claim requires target host and comparable reference",
            row.scenario_id
        ));
    }
}

fn build_report_row(
    ledger: &SwarmTailLatencyLedger,
    row: &SwarmTailLatencyRow,
) -> SwarmTailLatencyReportRow {
    let (dominant_component, dominant_share) = dominant_component(&row.latency);
    let watched_dominant_components = row
        .latency
        .components
        .iter()
        .filter(|component| {
            component.component.watched_for_dominance()
                && row.latency.p99_latency_us > 0.0
                && component.p99_us / row.latency.p99_latency_us >= ledger.dominance_threshold_ratio
        })
        .map(|component| component.component.label().to_owned())
        .collect::<Vec<_>>();

    SwarmTailLatencyReportRow {
        workload_id: row.workload_id.clone(),
        scenario_id: row.scenario_id.clone(),
        workload_class: row.workload_class.label().to_owned(),
        classification: row.classification.label().to_owned(),
        release_claim_state: row.release_claim_state.label().to_owned(),
        host_meets_target: row.host.meets_target(&ledger.target_host),
        workload_seed: row.workload_seed,
        p99_latency_us: row.latency.p99_latency_us,
        component_p99_sum_us: component_p99_sum(&row.latency),
        component_sum_delta_ratio: component_sum_delta_ratio(&row.latency),
        dominant_component,
        dominant_component_share: dominant_share,
        watched_dominant_components,
        reference_state: row.reference_state.state.label().to_owned(),
        backpressure_state: row.backpressure_state.label().to_owned(),
        queue_depth_p99: row.queue_depth.p99,
    }
}

fn dominant_component(latency: &TailLatencyBuckets) -> (String, f64) {
    latency
        .components
        .iter()
        .max_by(|left, right| left.p99_us.total_cmp(&right.p99_us))
        .map_or_else(
            || ("missing".to_owned(), 0.0),
            |component| {
                let share = if latency.p99_latency_us > 0.0 {
                    component.p99_us / latency.p99_latency_us
                } else {
                    0.0
                };
                (component.component.label().to_owned(), share)
            },
        )
}

fn component_p99_sum(latency: &TailLatencyBuckets) -> f64 {
    latency
        .components
        .iter()
        .map(|component| component.p99_us)
        .sum()
}

fn component_sum_delta_ratio(latency: &TailLatencyBuckets) -> f64 {
    if latency.p99_latency_us <= 0.0 {
        return 0.0;
    }
    (component_p99_sum(latency) - latency.p99_latency_us).abs() / latency.p99_latency_us
}

fn count_classifications(ledger: &SwarmTailLatencyLedger) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for row in &ledger.rows {
        *counts
            .entry(row.classification.label().to_owned())
            .or_insert(0) += 1;
    }
    counts
}

fn count_release_claims(ledger: &SwarmTailLatencyLedger) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for row in &ledger.rows {
        *counts
            .entry(row.release_claim_state.label().to_owned())
            .or_insert(0) += 1;
    }
    counts
}

fn validate_paths(field: &str, paths: &[String], errors: &mut Vec<String>) {
    if paths.is_empty() {
        errors.push(format!("{field} must not be empty"));
    }
    for path in paths {
        require_non_empty(field, path, errors);
    }
}

fn require_non_empty(field: &str, value: &str, errors: &mut Vec<String>) {
    if value.trim().is_empty() {
        errors.push(format!("{field} must not be empty"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn workspace_path(path: &str) -> String {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root")
            .join(path)
            .display()
            .to_string()
    }

    #[test]
    fn checked_in_swarm_tail_latency_ledger_validates() {
        let ledger = load_swarm_tail_latency_ledger(Path::new(&workspace_path(
            DEFAULT_SWARM_TAIL_LATENCY_LEDGER,
        )))
        .expect("checked-in ledger loads");
        let report = validate_swarm_tail_latency_ledger(&ledger);
        assert!(
            report.valid,
            "checked-in swarm tail-latency ledger should validate: {:?}",
            report.errors
        );
        assert_eq!(report.row_count, 5);
        assert_eq!(report.missing_reference_count, 1);
        assert!(report.component_dominance_alert_count >= 2);
        assert_eq!(report.classification_counts.get("pass"), Some(&1));
        assert_eq!(report.classification_counts.get("warn"), Some(&1));
        assert_eq!(report.classification_counts.get("fail"), Some(&1));
        assert_eq!(report.classification_counts.get("noisy"), Some(&1));
        assert_eq!(
            report.classification_counts.get("missing_reference"),
            Some(&1)
        );
    }

    #[test]
    fn missing_component_is_rejected() {
        let mut ledger = fixture_ledger();
        ledger.rows[0]
            .latency
            .components
            .retain(|component| component.component != TailLatencyComponent::WalFsync);
        let report = validate_swarm_tail_latency_ledger(&ledger);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("missing required component wal_fsync"))
        );
    }

    #[test]
    fn invalid_component_total_is_rejected() {
        let mut ledger = fixture_ledger();
        ledger.rows[0].latency.components[0].p99_us = 50_000.0;
        let report = validate_swarm_tail_latency_ledger(&ledger);
        assert!(
            report.errors.iter().any(|error| {
                error.contains("component p99 sum") && error.contains("tolerance")
            })
        );
    }

    #[test]
    fn missing_workload_seed_is_rejected() {
        let mut ledger = fixture_ledger();
        ledger.rows[0].workload_seed = 0;
        let report = validate_swarm_tail_latency_ledger(&ledger);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("workload_seed must be non-zero"))
        );
    }

    #[test]
    fn missing_raw_logs_are_rejected() {
        let mut ledger = fixture_ledger();
        ledger.rows[0].raw_logs.clear();
        let report = validate_swarm_tail_latency_ledger(&ledger);
        assert!(
            report
                .errors
                .iter()
                .any(|error| { error.contains("raw_logs must not be empty") })
        );
    }

    #[test]
    fn missing_reference_state_is_rejected() {
        let mut ledger = fixture_ledger();
        ledger.rows[0].reference_state.baseline_id = None;
        ledger.rows[0].reference_state.baseline_artifact = None;
        let report = validate_swarm_tail_latency_ledger(&ledger);
        assert!(report.errors.iter().any(|error| {
            error.contains("comparable reference requires baseline_id and baseline_artifact")
        }));
    }

    #[test]
    fn missing_reproduction_command_is_rejected() {
        let mut ledger = fixture_ledger();
        ledger.rows[0].reproduction_command.clear();
        let report = validate_swarm_tail_latency_ledger(&ledger);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("reproduction_command must not be empty"))
        );
    }

    #[test]
    fn unsupported_release_claim_upgrade_is_rejected() {
        let mut ledger = fixture_ledger();
        ledger.rows[0].host.lane = TailHostLane::DeveloperSmoke;
        ledger.rows[0].release_claim_state = TailReleaseClaimState::MeasuredAuthoritative;
        let report = validate_swarm_tail_latency_ledger(&ledger);
        assert!(report.errors.iter().any(|error| {
            error.contains("authoritative claim must run in permissioned_large_host lane")
        }));
    }

    #[test]
    fn missing_reference_cannot_make_measured_claim() {
        let mut ledger = fixture_ledger();
        ledger.rows[0].reference_state.state = TailReferenceKind::Missing;
        ledger.rows[0].reference_state.baseline_id = None;
        ledger.rows[0].reference_state.baseline_artifact = None;
        ledger.rows[0].classification = TailLatencyClassification::MissingReference;
        ledger.rows[0].release_claim_state = TailReleaseClaimState::MeasuredAuthoritative;
        let report = validate_swarm_tail_latency_ledger(&ledger);
        assert!(report.errors.iter().any(|error| {
            error.contains("public performance wording must remain experimental")
        }));
    }

    #[test]
    fn missing_host_fingerprint_is_rejected() {
        let mut ledger = fixture_ledger();
        ledger.rows[0].host.host_fingerprint.clear();
        let report = validate_swarm_tail_latency_ledger(&ledger);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("host.host_fingerprint"))
        );
    }

    #[test]
    fn nonmonotonic_latency_buckets_are_rejected() {
        let mut ledger = fixture_ledger();
        ledger.rows[0].latency.p95_latency_us = ledger.rows[0].latency.p50_latency_us - 1.0;
        let report = validate_swarm_tail_latency_ledger(&ledger);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("p50 <= p95 <= p99"))
        );
    }

    #[test]
    fn watched_dominant_components_are_reported() {
        let ledger = fixture_ledger();
        let report = validate_swarm_tail_latency_ledger(&ledger);
        let row = report
            .rows
            .iter()
            .find(|row| row.scenario_id == "tail_latency_repair_backlog_fail")
            .expect("repair backlog row");
        assert_eq!(row.dominant_component, "repair_backlog");
        assert!(
            row.watched_dominant_components
                .contains(&"repair_backlog".to_owned())
        );
    }

    fn fixture_ledger() -> SwarmTailLatencyLedger {
        SwarmTailLatencyLedger {
            schema_version: SWARM_TAIL_LATENCY_SCHEMA_VERSION,
            ledger_id: "test-swarm-tail-latency".to_owned(),
            generated_at: "2026-05-03T00:00:00Z".to_owned(),
            target_host: SwarmTailTargetHost {
                min_cpu_cores_logical: 64,
                min_ram_total_gb: 256,
                min_ram_available_gb: 128,
            },
            dominance_threshold_ratio: DEFAULT_DOMINANCE_THRESHOLD_RATIO,
            component_sum_tolerance_ratio: DEFAULT_COMPONENT_SUM_TOLERANCE_RATIO,
            rows: vec![
                fixture_row(
                    "tail_latency_metadata_pass",
                    TailLatencyClassification::Pass,
                    TailReleaseClaimState::MeasuredAuthoritative,
                    TailReferenceKind::Comparable,
                    TailLatencyComponent::Synchronization,
                ),
                fixture_row(
                    "tail_latency_repair_backlog_fail",
                    TailLatencyClassification::Fail,
                    TailReleaseClaimState::Blocked,
                    TailReferenceKind::Comparable,
                    TailLatencyComponent::RepairBacklog,
                ),
            ],
            required_log_fields: REQUIRED_LOG_FIELDS
                .iter()
                .map(|field| (*field).to_owned())
                .collect(),
            release_gate_consumers: vec!["bd-p2j3e.7".to_owned()],
        }
    }

    fn fixture_row(
        scenario_id: &str,
        classification: TailLatencyClassification,
        release_claim_state: TailReleaseClaimState,
        reference_kind: TailReferenceKind,
        dominant: TailLatencyComponent,
    ) -> SwarmTailLatencyRow {
        SwarmTailLatencyRow {
            workload_id: scenario_id.replace("tail_latency_", ""),
            workload_seed: 7_310_001,
            scenario_id: scenario_id.to_owned(),
            workload_class: SwarmTailWorkloadClass::MetadataStorm,
            host: SwarmTailHostFingerprint {
                host_fingerprint: "test-host-64c-256gb".to_owned(),
                cpu_cores_logical: 96,
                numa_nodes: Some(2),
                ram_total_gb: 512.0,
                ram_available_gb: 384.0,
                storage_class: "nvme".to_owned(),
                kernel: "Linux 6.14".to_owned(),
                lane: TailHostLane::PermissionedLargeHost,
            },
            latency: TailLatencyBuckets {
                p50_latency_us: 2_000.0,
                p95_latency_us: 7_000.0,
                p99_latency_us: 10_000.0,
                components: fixture_components(dominant),
            },
            queue_depth: TailQueueDepth {
                average: 24.0,
                p99: 96.0,
                max: 256,
            },
            backpressure_state: TailBackpressureState::Healthy,
            classification,
            release_claim_state,
            reference_state: TailReferenceState {
                state: reference_kind,
                baseline_id: Some("baseline-test".to_owned()),
                baseline_artifact: Some("artifacts/baseline.json".to_owned()),
                rationale: "fixture comparable baseline".to_owned(),
            },
            public_wording: "fixture wording stays tied to measured evidence".to_owned(),
            reproduction_command: "cargo run -p ffs-harness -- validate-swarm-tail-latency"
                .to_owned(),
            raw_logs: vec!["artifacts/tail/run.log".to_owned()],
            artifact_paths: vec!["artifacts/tail/report.json".to_owned()],
        }
    }

    fn fixture_components(dominant: TailLatencyComponent) -> Vec<TailLatencyComponentBucket> {
        REQUIRED_COMPONENTS
            .iter()
            .map(|component| {
                let p99 = if *component == dominant {
                    3_000.0
                } else {
                    500.0
                };
                TailLatencyComponentBucket {
                    component: *component,
                    p50_us: p99 / 4.0,
                    p95_us: p99 / 2.0,
                    p99_us: p99,
                    detail: format!("{} fixture attribution", component.label()),
                }
            })
            .collect()
    }
}
