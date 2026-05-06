#![allow(clippy::too_many_lines)]
#![forbid(unsafe_code)]

//! NUMA-aware swarm workload harness contract for `bd-p2j3e.2`.
//!
//! This validator defines the workload plan and host fingerprint needed before
//! a 64-core/256GB swarm run can strengthen performance claims. Local smoke
//! rows must stay downgraded when NUMA visibility, host resources, FUSE
//! capability, or worker isolation evidence is missing.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub const DEFAULT_SWARM_WORKLOAD_HARNESS_MANIFEST: &str =
    "benchmarks/swarm_workload_harness_manifest.json";
pub const SWARM_WORKLOAD_HARNESS_SCHEMA_VERSION: u32 = 1;

const REQUIRED_WORKLOAD_CLASSES: [SwarmWorkloadClass; 5] = [
    SwarmWorkloadClass::MetadataStorm,
    SwarmWorkloadClass::AppendFsync,
    SwarmWorkloadClass::MixedReadWrite,
    SwarmWorkloadClass::ScrubRepairOverlap,
    SwarmWorkloadClass::CachePressure,
];

const REQUIRED_LOG_FIELDS: [&str; 18] = [
    "scenario_id",
    "host_fingerprint",
    "cpu_cores_logical",
    "numa_nodes",
    "ram_total_gb",
    "ram_available_gb",
    "storage_class",
    "fuse_capability",
    "kernel",
    "rch_or_local_lane",
    "worker_isolation_notes",
    "workload_profile_id",
    "workload_seeds",
    "queue_depth",
    "backpressure_state",
    "cleanup_status",
    "release_claim_state",
    "reproduction_command",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmWorkloadHarnessManifest {
    pub schema_version: u32,
    pub manifest_id: String,
    pub generated_at: String,
    pub target_host: SwarmWorkloadTargetHost,
    pub workload_profiles: Vec<SwarmWorkloadProfile>,
    pub scenarios: Vec<SwarmWorkloadScenario>,
    #[serde(default)]
    pub required_log_fields: Vec<String>,
    #[serde(default)]
    pub proof_consumers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmWorkloadTargetHost {
    pub min_cpu_cores_logical: u32,
    pub min_ram_total_gb: u32,
    pub min_ram_available_gb: u32,
    pub min_numa_nodes: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmWorkloadProfile {
    pub workload_profile_id: String,
    pub workload_class: SwarmWorkloadClass,
    pub description: String,
    pub command_plan: SwarmCommandPlan,
    pub placement: SwarmPlacementIntent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmWorkloadClass {
    MetadataStorm,
    AppendFsync,
    MixedReadWrite,
    ScrubRepairOverlap,
    CachePressure,
}

impl SwarmWorkloadClass {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MetadataStorm => "metadata_storm",
            Self::AppendFsync => "append_fsync",
            Self::MixedReadWrite => "mixed_read_write",
            Self::ScrubRepairOverlap => "scrub_repair_overlap",
            Self::CachePressure => "cache_pressure",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmCommandPlan {
    pub plan_id: String,
    pub plan_mode: SwarmCommandPlanMode,
    pub exact_command: String,
    pub dry_run_only: bool,
    pub mutates_host_filesystems: bool,
    pub expected_artifacts: Vec<SwarmExpectedArtifact>,
    pub resource_caps: SwarmResourceCaps,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmCommandPlanMode {
    DryRun,
    PermissionedReal,
}

impl SwarmCommandPlanMode {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DryRun => "dry_run",
            Self::PermissionedReal => "permissioned_real",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmExpectedArtifact {
    pub path: String,
    pub kind: String,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmResourceCaps {
    pub max_duration_secs: u64,
    pub max_threads: u32,
    pub max_memory_gb: f64,
    pub max_temp_storage_gb: f64,
    pub max_queue_depth: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmPlacementIntent {
    pub shard_count: u32,
    pub core_allocation: String,
    pub numa_policy: String,
    pub queue_isolation: String,
    pub cleanup_policy: SwarmCleanupPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmCleanupPolicy {
    ControlledTempRoots,
    NoHostMutation,
    Missing,
}

impl SwarmCleanupPolicy {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ControlledTempRoots => "controlled_temp_roots",
            Self::NoHostMutation => "no_host_mutation",
            Self::Missing => "missing",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmWorkloadScenario {
    pub scenario_id: String,
    pub host: SwarmHostFingerprint,
    pub workload_profile_ids: Vec<String>,
    pub workload_seeds: Vec<u64>,
    pub counters: SwarmQueueBackpressureCounters,
    pub cleanup_status: SwarmCleanupStatus,
    pub classification: SwarmHarnessClassification,
    pub release_claim_state: SwarmHarnessReleaseClaimState,
    pub reproduction_command: String,
    pub raw_logs: Vec<String>,
    pub artifact_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmHostFingerprint {
    pub host_fingerprint: String,
    pub cpu_cores_logical: u32,
    pub numa: SwarmNumaObservation,
    pub ram_total_gb: f64,
    pub ram_available_gb: f64,
    pub storage_class: String,
    pub fuse_capability: SwarmFuseCapability,
    pub kernel: String,
    pub lane: SwarmHostLane,
    pub rch_or_local_lane: SwarmRchOrLocalLane,
    pub worker_isolation_notes: String,
}

impl SwarmHostFingerprint {
    #[must_use]
    pub fn meets_target(&self, target: &SwarmWorkloadTargetHost) -> bool {
        self.cpu_cores_logical >= target.min_cpu_cores_logical
            && self.ram_total_gb >= f64::from(target.min_ram_total_gb)
            && self.ram_available_gb >= f64::from(target.min_ram_available_gb)
            && self
                .numa
                .node_count
                .is_some_and(|nodes| nodes >= target.min_numa_nodes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmNumaObservation {
    pub observable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_count: Option<u32>,
    pub placement_intent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing_reason: Option<String>,
}

impl SwarmNumaObservation {
    #[must_use]
    pub fn authoritative(&self) -> bool {
        self.observable && self.node_count.is_some_and(|nodes| nodes > 0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmFuseCapability {
    pub state: SwarmFuseCapabilityState,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmFuseCapabilityState {
    Available,
    Missing,
    Unknown,
    NotRequired,
}

impl SwarmFuseCapabilityState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Missing => "missing",
            Self::Unknown => "unknown",
            Self::NotRequired => "not_required",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmHostLane {
    DeveloperSmoke,
    RchWorker,
    PermissionedLargeHost,
    CiSmoke,
}

impl SwarmHostLane {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmRchOrLocalLane {
    Local,
    Rch,
    Ci,
    Unknown,
}

impl SwarmRchOrLocalLane {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Rch => "rch",
            Self::Ci => "ci",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmQueueBackpressureCounters {
    pub max_queue_depth: u32,
    pub average_queue_depth: f64,
    pub backpressure_state: SwarmBackpressureState,
    pub throttle_events: u64,
    pub rejected_writes: u64,
    pub p99_latency_budget_us: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmBackpressureState {
    Healthy,
    Throttled,
    Critical,
    Unknown,
}

impl SwarmBackpressureState {
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
pub enum SwarmCleanupStatus {
    NotStartedDryRun,
    Clean,
    PartialArtifactsPreserved,
    Failed,
    Unknown,
}

impl SwarmCleanupStatus {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotStartedDryRun => "not_started_dry_run",
            Self::Clean => "clean",
            Self::PartialArtifactsPreserved => "partial_artifacts_preserved",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmHarnessClassification {
    Pass,
    Warn,
    Fail,
    CapabilitySkip,
}

impl SwarmHarnessClassification {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::CapabilitySkip => "capability_skip",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmHarnessReleaseClaimState {
    Experimental,
    PlanReady,
    SmallHostSmoke,
    CapabilitySkip,
    MeasuredLocal,
    MeasuredAuthoritative,
    Blocked,
}

impl SwarmHarnessReleaseClaimState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Experimental => "experimental",
            Self::PlanReady => "plan_ready",
            Self::SmallHostSmoke => "small_host_smoke",
            Self::CapabilitySkip => "capability_skip",
            Self::MeasuredLocal => "measured_local",
            Self::MeasuredAuthoritative => "measured_authoritative",
            Self::Blocked => "blocked",
        }
    }

    #[must_use]
    pub const fn safe_for_inadequate_host(self) -> bool {
        matches!(
            self,
            Self::Experimental | Self::SmallHostSmoke | Self::CapabilitySkip | Self::Blocked
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmWorkloadHarnessReport {
    pub schema_version: u32,
    pub manifest_id: String,
    pub valid: bool,
    pub profile_count: usize,
    pub scenario_count: usize,
    pub command_plan_count: usize,
    pub required_workload_class_count: usize,
    pub missing_workload_classes: Vec<String>,
    pub large_host_plan_count: usize,
    pub host_downgrade_count: usize,
    pub classification_counts: BTreeMap<String, usize>,
    pub release_claim_counts: BTreeMap<String, usize>,
    pub profile_matrix: Vec<SwarmProfileMatrixRow>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmProfileMatrixRow {
    pub workload_profile_id: String,
    pub workload_class: String,
    pub plan_mode: String,
    pub exact_command: String,
    pub max_threads: u32,
    pub max_memory_gb: f64,
    pub max_queue_depth: u32,
    pub shard_count: u32,
    pub numa_policy: String,
    pub cleanup_policy: String,
}

pub fn load_swarm_workload_harness_manifest(path: &Path) -> Result<SwarmWorkloadHarnessManifest> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read swarm workload manifest {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("invalid swarm workload manifest JSON {}", path.display()))
}

#[must_use]
pub fn validate_swarm_workload_harness_manifest(
    manifest: &SwarmWorkloadHarnessManifest,
) -> SwarmWorkloadHarnessReport {
    let mut errors = Vec::new();
    validate_header(manifest, &mut errors);

    let profile_ids = validate_profiles(manifest, &mut errors);
    let missing_workload_classes = missing_required_workload_classes(manifest);
    for workload_class in &missing_workload_classes {
        errors.push(format!(
            "missing required workload profile class {workload_class}"
        ));
    }

    let (classification_counts, release_claim_counts, large_host_plan_count, host_downgrade_count) =
        validate_scenarios(manifest, &profile_ids, &mut errors);
    let profile_matrix = build_profile_matrix(manifest);

    SwarmWorkloadHarnessReport {
        schema_version: SWARM_WORKLOAD_HARNESS_SCHEMA_VERSION,
        manifest_id: manifest.manifest_id.clone(),
        valid: errors.is_empty(),
        profile_count: manifest.workload_profiles.len(),
        scenario_count: manifest.scenarios.len(),
        command_plan_count: manifest.workload_profiles.len(),
        required_workload_class_count: REQUIRED_WORKLOAD_CLASSES.len(),
        missing_workload_classes,
        large_host_plan_count,
        host_downgrade_count,
        classification_counts,
        release_claim_counts,
        profile_matrix,
        errors,
    }
}

#[must_use]
pub fn render_swarm_workload_harness_markdown(report: &SwarmWorkloadHarnessReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Swarm Workload Harness\n");
    let _ = writeln!(out, "- Manifest: `{}`", report.manifest_id);
    let _ = writeln!(out, "- Valid: `{}`", report.valid);
    let _ = writeln!(out, "- Workload profiles: `{}`", report.profile_count);
    let _ = writeln!(out, "- Scenarios: `{}`", report.scenario_count);
    let _ = writeln!(
        out,
        "- Large-host plans: `{}`",
        report.large_host_plan_count
    );
    let _ = writeln!(out, "- Host downgrades: `{}`", report.host_downgrade_count);
    out.push_str("\n## Classification Counts\n\n");
    for (classification, count) in &report.classification_counts {
        let _ = writeln!(out, "- `{classification}`: {count}");
    }
    out.push_str("\n## Release Claim Counts\n\n");
    for (claim, count) in &report.release_claim_counts {
        let _ = writeln!(out, "- `{claim}`: {count}");
    }
    out.push_str("\n## Workload Profiles\n\n");
    out.push_str(
        "| Profile | Class | Plan | Max threads | Max memory | Queue cap | NUMA policy |\n",
    );
    out.push_str("|---|---|---|---:|---:|---:|---|\n");
    for row in &report.profile_matrix {
        let _ = writeln!(
            out,
            "| `{}` | `{}` | `{}` | {} | {:.1} GB | {} | {} |",
            row.workload_profile_id,
            row.workload_class,
            row.plan_mode,
            row.max_threads,
            row.max_memory_gb,
            row.max_queue_depth,
            row.numa_policy.replace('|', "/")
        );
    }
    if !report.missing_workload_classes.is_empty() {
        out.push_str("\n## Missing Workload Classes\n\n");
        for workload_class in &report.missing_workload_classes {
            let _ = writeln!(out, "- `{workload_class}`");
        }
    }
    if !report.errors.is_empty() {
        out.push_str("\n## Errors\n\n");
        for error in &report.errors {
            let _ = writeln!(out, "- {error}");
        }
    }
    out
}

pub fn fail_on_swarm_workload_harness_errors(report: &SwarmWorkloadHarnessReport) -> Result<()> {
    if report.valid {
        Ok(())
    } else {
        bail!(
            "swarm workload harness validation failed: errors={}",
            report.errors.len()
        )
    }
}

fn validate_header(manifest: &SwarmWorkloadHarnessManifest, errors: &mut Vec<String>) {
    if manifest.schema_version != SWARM_WORKLOAD_HARNESS_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version must be {SWARM_WORKLOAD_HARNESS_SCHEMA_VERSION}"
        ));
    }
    if manifest.manifest_id.trim().is_empty() {
        errors.push("manifest_id must not be empty".to_owned());
    }
    if manifest.generated_at.trim().is_empty() {
        errors.push("generated_at must not be empty".to_owned());
    }
    if manifest.target_host.min_cpu_cores_logical < 64 {
        errors.push("target_host.min_cpu_cores_logical must be at least 64".to_owned());
    }
    if manifest.target_host.min_ram_total_gb < 256 {
        errors.push("target_host.min_ram_total_gb must be at least 256".to_owned());
    }
    if manifest.target_host.min_ram_available_gb == 0 {
        errors.push("target_host.min_ram_available_gb must be positive".to_owned());
    }
    if manifest.target_host.min_numa_nodes == 0 {
        errors.push("target_host.min_numa_nodes must be positive".to_owned());
    }
    if manifest.workload_profiles.is_empty() {
        errors.push("workload_profiles must not be empty".to_owned());
    }
    if manifest.scenarios.is_empty() {
        errors.push("scenarios must not be empty".to_owned());
    }
    for required in REQUIRED_LOG_FIELDS {
        if !manifest
            .required_log_fields
            .iter()
            .any(|field| field == required)
        {
            errors.push(format!("required_log_fields missing {required}"));
        }
    }
    if manifest.proof_consumers.is_empty() {
        errors.push("proof_consumers must not be empty".to_owned());
    }
}

fn validate_profiles(
    manifest: &SwarmWorkloadHarnessManifest,
    errors: &mut Vec<String>,
) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    for profile in &manifest.workload_profiles {
        if profile.workload_profile_id.trim().is_empty() {
            errors.push("workload_profile_id must not be empty".to_owned());
        }
        if !seen.insert(profile.workload_profile_id.clone()) {
            errors.push(format!(
                "duplicate workload_profile_id {}",
                profile.workload_profile_id
            ));
        }
        if profile.description.trim().is_empty() {
            errors.push(format!(
                "profile {} description must not be empty",
                profile.workload_profile_id
            ));
        }
        validate_command_plan(profile, errors);
        validate_placement(profile, errors);
    }
    seen
}

fn validate_command_plan(profile: &SwarmWorkloadProfile, errors: &mut Vec<String>) {
    let plan = &profile.command_plan;
    if plan.plan_id.trim().is_empty() {
        errors.push(format!(
            "profile {} command_plan.plan_id must not be empty",
            profile.workload_profile_id
        ));
    }
    if plan.exact_command.trim().is_empty() {
        errors.push(format!(
            "profile {} command_plan.exact_command must not be empty",
            profile.workload_profile_id
        ));
    }
    if matches!(plan.plan_mode, SwarmCommandPlanMode::DryRun) && !plan.dry_run_only {
        errors.push(format!(
            "profile {} dry_run plan must set dry_run_only",
            profile.workload_profile_id
        ));
    }
    if plan.mutates_host_filesystems {
        errors.push(format!(
            "profile {} command plan mutates host filesystems; bd-p2j3e.2 requires dry-run-safe plans",
            profile.workload_profile_id
        ));
    }
    if plan.expected_artifacts.is_empty() {
        errors.push(format!(
            "profile {} command plan missing expected_artifacts",
            profile.workload_profile_id
        ));
    }
    for artifact in &plan.expected_artifacts {
        if artifact.path.trim().is_empty() || artifact.kind.trim().is_empty() {
            errors.push(format!(
                "profile {} expected artifact path/kind must not be empty",
                profile.workload_profile_id
            ));
        }
    }
    validate_resource_caps(profile, errors);
}

fn validate_resource_caps(profile: &SwarmWorkloadProfile, errors: &mut Vec<String>) {
    let caps = &profile.command_plan.resource_caps;
    if caps.max_duration_secs == 0 {
        errors.push(format!(
            "profile {} max_duration_secs must be positive",
            profile.workload_profile_id
        ));
    }
    if caps.max_threads == 0 {
        errors.push(format!(
            "profile {} max_threads must be positive",
            profile.workload_profile_id
        ));
    }
    if caps.max_memory_gb <= 0.0 {
        errors.push(format!(
            "profile {} max_memory_gb must be positive",
            profile.workload_profile_id
        ));
    }
    if caps.max_temp_storage_gb < 0.0 {
        errors.push(format!(
            "profile {} max_temp_storage_gb must not be negative",
            profile.workload_profile_id
        ));
    }
    if caps.max_queue_depth == 0 {
        errors.push(format!(
            "profile {} max_queue_depth must be positive",
            profile.workload_profile_id
        ));
    }
}

fn validate_placement(profile: &SwarmWorkloadProfile, errors: &mut Vec<String>) {
    let placement = &profile.placement;
    if placement.shard_count == 0 {
        errors.push(format!(
            "profile {} placement.shard_count must be positive",
            profile.workload_profile_id
        ));
    }
    for (field, value) in [
        ("core_allocation", placement.core_allocation.as_str()),
        ("numa_policy", placement.numa_policy.as_str()),
        ("queue_isolation", placement.queue_isolation.as_str()),
    ] {
        if value.trim().is_empty() {
            errors.push(format!(
                "profile {} placement.{field} must not be empty",
                profile.workload_profile_id
            ));
        }
    }
    if matches!(placement.cleanup_policy, SwarmCleanupPolicy::Missing) {
        errors.push(format!(
            "profile {} placement.cleanup_policy must not be missing",
            profile.workload_profile_id
        ));
    }
}

fn missing_required_workload_classes(manifest: &SwarmWorkloadHarnessManifest) -> Vec<String> {
    let covered = manifest
        .workload_profiles
        .iter()
        .map(|profile| profile.workload_class)
        .collect::<BTreeSet<_>>();
    REQUIRED_WORKLOAD_CLASSES
        .iter()
        .filter(|workload_class| !covered.contains(workload_class))
        .map(|workload_class| workload_class.label().to_owned())
        .collect()
}

fn validate_scenarios(
    manifest: &SwarmWorkloadHarnessManifest,
    profile_ids: &BTreeSet<String>,
    errors: &mut Vec<String>,
) -> (
    BTreeMap<String, usize>,
    BTreeMap<String, usize>,
    usize,
    usize,
) {
    let mut seen = BTreeSet::new();
    let mut classification_counts = BTreeMap::new();
    let mut release_claim_counts = BTreeMap::new();
    let mut large_host_plan_count = 0;
    let mut host_downgrade_count = 0;

    for scenario in &manifest.scenarios {
        if scenario.scenario_id.trim().is_empty() {
            errors.push("scenario_id must not be empty".to_owned());
        }
        if !seen.insert(scenario.scenario_id.clone()) {
            errors.push(format!("duplicate scenario_id {}", scenario.scenario_id));
        }
        *classification_counts
            .entry(scenario.classification.label().to_owned())
            .or_insert(0) += 1;
        *release_claim_counts
            .entry(scenario.release_claim_state.label().to_owned())
            .or_insert(0) += 1;

        validate_scenario_shape(scenario, profile_ids, errors);
        validate_host(&scenario.host, &scenario.scenario_id, errors);
        validate_counters(scenario, errors);

        let meets_target = scenario.host.meets_target(&manifest.target_host);
        let numa_authoritative = scenario.host.numa.authoritative();
        let inadequate_or_unobservable = !meets_target || !numa_authoritative;
        if inadequate_or_unobservable {
            host_downgrade_count += 1;
            validate_downgraded_scenario(scenario, errors);
        }
        if matches!(
            scenario.release_claim_state,
            SwarmHarnessReleaseClaimState::MeasuredAuthoritative
        ) {
            validate_authoritative_scenario(scenario, meets_target, numa_authoritative, errors);
        }
        if matches!(
            scenario.release_claim_state,
            SwarmHarnessReleaseClaimState::PlanReady
                | SwarmHarnessReleaseClaimState::MeasuredAuthoritative
        ) {
            large_host_plan_count += 1;
        }
    }

    (
        classification_counts,
        release_claim_counts,
        large_host_plan_count,
        host_downgrade_count,
    )
}

fn validate_scenario_shape(
    scenario: &SwarmWorkloadScenario,
    profile_ids: &BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    if scenario.workload_profile_ids.is_empty() {
        errors.push(format!(
            "scenario {} must reference at least one workload profile",
            scenario.scenario_id
        ));
    }
    if scenario.workload_seeds.is_empty() {
        errors.push(format!(
            "scenario {} workload_seeds must not be empty",
            scenario.scenario_id
        ));
    }
    if matches!(scenario.cleanup_status, SwarmCleanupStatus::Unknown) {
        errors.push(format!(
            "scenario {} cleanup_status must not be unknown",
            scenario.scenario_id
        ));
    }
    for workload_profile_id in &scenario.workload_profile_ids {
        if !profile_ids.contains(workload_profile_id) {
            errors.push(format!(
                "scenario {} references unknown workload profile {}",
                scenario.scenario_id, workload_profile_id
            ));
        }
    }
    if scenario.reproduction_command.trim().is_empty() {
        errors.push(format!(
            "scenario {} reproduction_command must not be empty",
            scenario.scenario_id
        ));
    }
    if scenario.raw_logs.is_empty() {
        errors.push(format!(
            "scenario {} raw_logs must not be empty",
            scenario.scenario_id
        ));
    }
    if scenario.artifact_paths.is_empty() {
        errors.push(format!(
            "scenario {} artifact_paths must not be empty",
            scenario.scenario_id
        ));
    }
}

fn validate_host(host: &SwarmHostFingerprint, scenario_id: &str, errors: &mut Vec<String>) {
    for (field, value) in [
        ("host_fingerprint", host.host_fingerprint.as_str()),
        ("storage_class", host.storage_class.as_str()),
        ("kernel", host.kernel.as_str()),
        (
            "worker_isolation_notes",
            host.worker_isolation_notes.as_str(),
        ),
        (
            "fuse_capability.detail",
            host.fuse_capability.detail.as_str(),
        ),
        ("numa.placement_intent", host.numa.placement_intent.as_str()),
    ] {
        if value.trim().is_empty() {
            errors.push(format!(
                "scenario {scenario_id} host.{field} must not be empty"
            ));
        }
    }
    if host.cpu_cores_logical == 0 {
        errors.push(format!(
            "scenario {scenario_id} host.cpu_cores_logical must be positive"
        ));
    }
    if host.ram_total_gb <= 0.0 || host.ram_available_gb < 0.0 {
        errors.push(format!(
            "scenario {scenario_id} host RAM totals must be non-negative and total must be positive"
        ));
    }
    if host.ram_available_gb > host.ram_total_gb {
        errors.push(format!(
            "scenario {scenario_id} host.ram_available_gb cannot exceed ram_total_gb"
        ));
    }
    if host.numa.observable && host.numa.node_count.is_none_or(|nodes| nodes == 0) {
        errors.push(format!(
            "scenario {scenario_id} NUMA is observable but node_count is missing or zero"
        ));
    }
    if !host.numa.observable
        && host
            .numa
            .missing_reason
            .as_ref()
            .is_none_or(|reason| reason.trim().is_empty())
    {
        errors.push(format!(
            "scenario {scenario_id} NUMA is not observable but missing_reason is absent"
        ));
    }
    if matches!(host.rch_or_local_lane, SwarmRchOrLocalLane::Unknown) {
        errors.push(format!(
            "scenario {scenario_id} rch_or_local_lane must not be unknown"
        ));
    }
}

fn validate_counters(scenario: &SwarmWorkloadScenario, errors: &mut Vec<String>) {
    let counters = &scenario.counters;
    if counters.average_queue_depth < 0.0 {
        errors.push(format!(
            "scenario {} average_queue_depth must not be negative",
            scenario.scenario_id
        ));
    }
    if counters.average_queue_depth > f64::from(counters.max_queue_depth) {
        errors.push(format!(
            "scenario {} average_queue_depth cannot exceed max_queue_depth",
            scenario.scenario_id
        ));
    }
    if counters.p99_latency_budget_us <= 0.0 {
        errors.push(format!(
            "scenario {} p99_latency_budget_us must be positive",
            scenario.scenario_id
        ));
    }
    if matches!(counters.backpressure_state, SwarmBackpressureState::Unknown) {
        errors.push(format!(
            "scenario {} backpressure_state must not be unknown",
            scenario.scenario_id
        ));
    }
}

fn validate_downgraded_scenario(scenario: &SwarmWorkloadScenario, errors: &mut Vec<String>) {
    if matches!(scenario.classification, SwarmHarnessClassification::Pass) {
        errors.push(format!(
            "scenario {} is below target or lacks NUMA visibility but is classified pass",
            scenario.scenario_id
        ));
    }
    if !scenario.release_claim_state.safe_for_inadequate_host() {
        errors.push(format!(
            "scenario {} is below target or lacks NUMA visibility but release_claim_state is {}",
            scenario.scenario_id,
            scenario.release_claim_state.label()
        ));
    }
}

fn validate_authoritative_scenario(
    scenario: &SwarmWorkloadScenario,
    meets_target: bool,
    numa_authoritative: bool,
    errors: &mut Vec<String>,
) {
    if !meets_target {
        errors.push(format!(
            "scenario {} measured_authoritative claim is below the 64-core/256GB target",
            scenario.scenario_id
        ));
    }
    if !numa_authoritative {
        errors.push(format!(
            "scenario {} measured_authoritative claim lacks observable NUMA nodes",
            scenario.scenario_id
        ));
    }
    if !matches!(scenario.host.lane, SwarmHostLane::PermissionedLargeHost) {
        errors.push(format!(
            "scenario {} measured_authoritative claim must use permissioned_large_host lane",
            scenario.scenario_id
        ));
    }
}

fn build_profile_matrix(manifest: &SwarmWorkloadHarnessManifest) -> Vec<SwarmProfileMatrixRow> {
    manifest
        .workload_profiles
        .iter()
        .map(|profile| SwarmProfileMatrixRow {
            workload_profile_id: profile.workload_profile_id.clone(),
            workload_class: profile.workload_class.label().to_owned(),
            plan_mode: profile.command_plan.plan_mode.label().to_owned(),
            exact_command: profile.command_plan.exact_command.clone(),
            max_threads: profile.command_plan.resource_caps.max_threads,
            max_memory_gb: profile.command_plan.resource_caps.max_memory_gb,
            max_queue_depth: profile.command_plan.resource_caps.max_queue_depth,
            shard_count: profile.placement.shard_count,
            numa_policy: profile.placement.numa_policy.clone(),
            cleanup_policy: profile.placement.cleanup_policy.label().to_owned(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_in_swarm_workload_harness_manifest_validates() {
        let manifest = load_swarm_workload_harness_manifest(Path::new(&workspace_path(
            DEFAULT_SWARM_WORKLOAD_HARNESS_MANIFEST,
        )))
        .expect("load checked-in manifest");
        let report = validate_swarm_workload_harness_manifest(&manifest);
        assert!(
            report.valid,
            "checked-in swarm workload harness manifest should validate: {:?}",
            report.errors
        );
        assert_eq!(report.profile_count, REQUIRED_WORKLOAD_CLASSES.len());
        assert_eq!(report.host_downgrade_count, 1);
        assert_eq!(report.large_host_plan_count, 1);
    }

    #[test]
    fn small_host_pass_claim_fails_closed() {
        let mut manifest = fixture_manifest();
        manifest.scenarios[1].classification = SwarmHarnessClassification::Pass;
        manifest.scenarios[1].release_claim_state =
            SwarmHarnessReleaseClaimState::MeasuredAuthoritative;
        let report = validate_swarm_workload_harness_manifest(&manifest);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("classified pass"))
        );
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("below the 64-core/256GB target"))
        );
    }

    #[test]
    fn missing_numa_reason_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.scenarios[1].host.numa.missing_reason = None;
        let report = validate_swarm_workload_harness_manifest(&manifest);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("missing_reason"))
        );
    }

    #[test]
    fn missing_required_workload_class_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest
            .workload_profiles
            .retain(|profile| profile.workload_class != SwarmWorkloadClass::CachePressure);
        let report = validate_swarm_workload_harness_manifest(&manifest);
        assert!(!report.valid);
        assert!(
            report
                .missing_workload_classes
                .contains(&"cache_pressure".to_owned())
        );
    }

    #[test]
    fn missing_workload_seeds_are_rejected() {
        let mut manifest = fixture_manifest();
        manifest.scenarios[0].workload_seeds.clear();
        let report = validate_swarm_workload_harness_manifest(&manifest);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("workload_seeds"))
        );
    }

    #[test]
    fn unknown_cleanup_status_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.scenarios[0].cleanup_status = SwarmCleanupStatus::Unknown;
        let report = validate_swarm_workload_harness_manifest(&manifest);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("cleanup_status"))
        );
    }

    #[test]
    fn mutating_command_plan_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.workload_profiles[0]
            .command_plan
            .mutates_host_filesystems = true;
        let report = validate_swarm_workload_harness_manifest(&manifest);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("mutates host filesystems"))
        );
    }

    fn fixture_manifest() -> SwarmWorkloadHarnessManifest {
        let target_host = SwarmWorkloadTargetHost {
            min_cpu_cores_logical: 64,
            min_ram_total_gb: 256,
            min_ram_available_gb: 192,
            min_numa_nodes: 2,
        };
        let profiles = REQUIRED_WORKLOAD_CLASSES
            .iter()
            .map(|workload_class| fixture_profile(*workload_class))
            .collect::<Vec<_>>();
        SwarmWorkloadHarnessManifest {
            schema_version: SWARM_WORKLOAD_HARNESS_SCHEMA_VERSION,
            manifest_id: "test-swarm-workload-harness".to_owned(),
            generated_at: "2026-05-03T23:20:00Z".to_owned(),
            target_host,
            workload_profiles: profiles,
            scenarios: vec![large_host_scenario(), small_host_scenario()],
            required_log_fields: REQUIRED_LOG_FIELDS
                .iter()
                .map(|field| (*field).to_owned())
                .collect(),
            proof_consumers: vec!["bd-p2j3e.2".to_owned(), "proof-bundle".to_owned()],
        }
    }

    fn fixture_profile(workload_class: SwarmWorkloadClass) -> SwarmWorkloadProfile {
        let workload_id = format!("{}_dry_run", workload_class.label());
        SwarmWorkloadProfile {
            workload_profile_id: workload_id.clone(),
            workload_class,
            description: format!("dry-run plan for {}", workload_class.label()),
            command_plan: SwarmCommandPlan {
                plan_id: format!("{workload_id}_plan"),
                plan_mode: SwarmCommandPlanMode::DryRun,
                exact_command: format!(
                    "cargo run -p ffs-harness -- validate-swarm-workload-harness --manifest {DEFAULT_SWARM_WORKLOAD_HARNESS_MANIFEST}"
                ),
                dry_run_only: true,
                mutates_host_filesystems: false,
                expected_artifacts: vec![SwarmExpectedArtifact {
                    path: format!("artifacts/performance/swarm-workload/{workload_id}.json"),
                    kind: "json_report".to_owned(),
                    required: true,
                }],
                resource_caps: SwarmResourceCaps {
                    max_duration_secs: 600,
                    max_threads: 64,
                    max_memory_gb: 64.0,
                    max_temp_storage_gb: 16.0,
                    max_queue_depth: 4096,
                },
            },
            placement: SwarmPlacementIntent {
                shard_count: 64,
                core_allocation: "spread across isolated worker core groups".to_owned(),
                numa_policy: "pin shards to observed NUMA nodes; downgrade if unavailable"
                    .to_owned(),
                queue_isolation: "separate metadata/write/repair queues".to_owned(),
                cleanup_policy: SwarmCleanupPolicy::NoHostMutation,
            },
        }
    }

    fn large_host_scenario() -> SwarmWorkloadScenario {
        SwarmWorkloadScenario {
            scenario_id: "swarm_workload_64c_256gb_dry_run_plan".to_owned(),
            host: SwarmHostFingerprint {
                host_fingerprint: "synthetic-96c-512gb-2numa-plan-lane".to_owned(),
                cpu_cores_logical: 96,
                numa: SwarmNumaObservation {
                    observable: true,
                    node_count: Some(2),
                    placement_intent: "2-node spread with per-node shard groups".to_owned(),
                    missing_reason: None,
                },
                ram_total_gb: 512.0,
                ram_available_gb: 420.0,
                storage_class: "nvme".to_owned(),
                fuse_capability: SwarmFuseCapability {
                    state: SwarmFuseCapabilityState::Available,
                    detail: "permissioned lane reports /dev/fuse and fusermount3".to_owned(),
                },
                kernel: "Linux 6.17.0-14-generic x86_64 GNU/Linux".to_owned(),
                lane: SwarmHostLane::PermissionedLargeHost,
                rch_or_local_lane: SwarmRchOrLocalLane::Rch,
                worker_isolation_notes: "reserved worker with isolated target dir".to_owned(),
            },
            workload_profile_ids: REQUIRED_WORKLOAD_CLASSES
                .iter()
                .map(|workload_class| format!("{}_dry_run", workload_class.label()))
                .collect(),
            workload_seeds: vec![10_001, 10_002, 10_003, 10_004, 10_005],
            counters: SwarmQueueBackpressureCounters {
                max_queue_depth: 4096,
                average_queue_depth: 512.0,
                backpressure_state: SwarmBackpressureState::Healthy,
                throttle_events: 0,
                rejected_writes: 0,
                p99_latency_budget_us: 12_000.0,
            },
            cleanup_status: SwarmCleanupStatus::NotStartedDryRun,
            classification: SwarmHarnessClassification::Pass,
            release_claim_state: SwarmHarnessReleaseClaimState::PlanReady,
            reproduction_command: format!(
                "cargo run -p ffs-harness -- validate-swarm-workload-harness --manifest {DEFAULT_SWARM_WORKLOAD_HARNESS_MANIFEST}"
            ),
            raw_logs: vec!["artifacts/performance/swarm-workload/large-host/run.log".to_owned()],
            artifact_paths: vec![
                "artifacts/performance/swarm-workload/large-host/report.json".to_owned(),
            ],
        }
    }

    fn small_host_scenario() -> SwarmWorkloadScenario {
        SwarmWorkloadScenario {
            scenario_id: "swarm_workload_small_host_smoke".to_owned(),
            host: SwarmHostFingerprint {
                host_fingerprint: "developer-smoke-16c-64gb-no-numa".to_owned(),
                cpu_cores_logical: 16,
                numa: SwarmNumaObservation {
                    observable: false,
                    node_count: None,
                    placement_intent: "single-node smoke; no placement claim".to_owned(),
                    missing_reason: Some("NUMA topology not visible in developer lane".to_owned()),
                },
                ram_total_gb: 64.0,
                ram_available_gb: 40.0,
                storage_class: "nvme".to_owned(),
                fuse_capability: SwarmFuseCapability {
                    state: SwarmFuseCapabilityState::Unknown,
                    detail: "developer smoke does not require mounted execution".to_owned(),
                },
                kernel: "Linux developer-smoke".to_owned(),
                lane: SwarmHostLane::DeveloperSmoke,
                rch_or_local_lane: SwarmRchOrLocalLane::Local,
                worker_isolation_notes: "uses dry-run-only artifacts".to_owned(),
            },
            workload_profile_ids: vec!["metadata_storm_dry_run".to_owned()],
            workload_seeds: vec![20_001],
            counters: SwarmQueueBackpressureCounters {
                max_queue_depth: 128,
                average_queue_depth: 4.0,
                backpressure_state: SwarmBackpressureState::Healthy,
                throttle_events: 0,
                rejected_writes: 0,
                p99_latency_budget_us: 25_000.0,
            },
            cleanup_status: SwarmCleanupStatus::NotStartedDryRun,
            classification: SwarmHarnessClassification::CapabilitySkip,
            release_claim_state: SwarmHarnessReleaseClaimState::SmallHostSmoke,
            reproduction_command: format!(
                "cargo run -p ffs-harness -- validate-swarm-workload-harness --manifest {DEFAULT_SWARM_WORKLOAD_HARNESS_MANIFEST}"
            ),
            raw_logs: vec!["artifacts/performance/swarm-workload/small-host/run.log".to_owned()],
            artifact_paths: vec![
                "artifacts/performance/swarm-workload/small-host/report.json".to_owned(),
            ],
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
