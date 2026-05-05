#![allow(clippy::too_many_lines)]
#![forbid(unsafe_code)]

//! Morsel-driven scrub/repair scheduler proof contract for `bd-p2j3e.6`.
//!
//! The validator keeps background repair/scrub scheduling conservative until
//! there is explicit evidence for foreground latency, backlog freshness, ledger
//! completeness, stale-symbol refusal, and mutation-route serialization.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub const DEFAULT_SCRUB_REPAIR_SCHEDULER_MANIFEST: &str =
    "benchmarks/scrub_repair_scheduler_manifest.json";
pub const SCRUB_REPAIR_SCHEDULER_SCHEMA_VERSION: u32 = 1;

const REQUIRED_INVARIANTS: [&str; 5] = [
    "no_repair_writeback_bypass",
    "bounded_foreground_interference",
    "cancellation_safe",
    "ledger_complete",
    "stale_symbols_refused",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScrubRepairSchedulerManifest {
    pub schema_version: u32,
    pub manifest_id: String,
    pub generated_at: String,
    pub policy: ScrubRepairSchedulerPolicy,
    pub scenarios: Vec<ScrubRepairSchedulerScenario>,
    #[serde(default)]
    pub required_invariants: Vec<String>,
    #[serde(default)]
    pub proof_bundle_consumers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScrubRepairSchedulerPolicy {
    pub max_foreground_p99_regression_pct: f64,
    pub max_repair_backlog_age_secs: u64,
    pub max_stale_symbol_age_secs: u64,
    pub min_fairness_index: f64,
    pub default_release_claim_state: SchedulerReleaseClaimState,
    pub expected_loss_weights: SchedulerExpectedLossWeights,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SchedulerExpectedLossWeights {
    pub repair_freshness_weight: f64,
    pub foreground_latency_weight: f64,
    pub stale_symbol_weight: f64,
    pub fairness_weight: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScrubRepairSchedulerScenario {
    pub scenario_id: String,
    pub workload_class: ScrubRepairWorkloadClass,
    pub scheduler_mode: ScrubRepairSchedulerMode,
    pub lane: ScrubRepairSchedulerLane,
    pub baseline_foreground_p99_us: f64,
    pub observed_foreground_p99_us: f64,
    pub repair_backlog_age_secs: u64,
    pub stale_symbol_age_secs: u64,
    pub fairness: SchedulerFairnessCounters,
    pub ledger: SchedulerLedgerObservation,
    pub classification: SchedulerClassification,
    pub release_claim_state: SchedulerReleaseClaimState,
    pub reproduction_command: String,
    pub raw_logs: Vec<String>,
    pub artifact_paths: Vec<String>,
    pub proof_bundle_artifact_paths: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScrubRepairWorkloadClass {
    MetadataStorm,
    MixedReadWrite,
    ScrubRepairOverlap,
    CachePressure,
    FixtureSmoke,
}

impl ScrubRepairWorkloadClass {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MetadataStorm => "metadata_storm",
            Self::MixedReadWrite => "mixed_read_write",
            Self::ScrubRepairOverlap => "scrub_repair_overlap",
            Self::CachePressure => "cache_pressure",
            Self::FixtureSmoke => "fixture_smoke",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScrubRepairSchedulerMode {
    Disabled,
    ForegroundFirst,
    MorselDriven,
    RepairOnly,
}

impl ScrubRepairSchedulerMode {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::ForegroundFirst => "foreground_first",
            Self::MorselDriven => "morsel_driven",
            Self::RepairOnly => "repair_only",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScrubRepairSchedulerLane {
    DeveloperSmoke,
    RchWorker,
    PermissionedLargeHost,
    CiSmoke,
}

impl ScrubRepairSchedulerLane {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerFairnessCounters {
    pub foreground_morsels: u64,
    pub repair_morsels: u64,
    pub yielded_to_foreground: u64,
    pub throttled_repair_morsels: u64,
    pub cancellation: SchedulerCancellationState,
}

impl SchedulerFairnessCounters {
    #[must_use]
    pub fn fairness_index(&self) -> f64 {
        let max = self.foreground_morsels.max(self.repair_morsels);
        if max == 0 {
            0.0
        } else {
            self.foreground_morsels.min(self.repair_morsels) as f64 / max as f64
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerCancellationState {
    NotExercised,
    CancellationObserved,
    Unknown,
}

impl SchedulerCancellationState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotExercised => "not_exercised",
            Self::CancellationObserved => "cancellation_observed",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerLedgerObservation {
    pub mutation_route: RepairMutationRoute,
    pub ledger_state: SchedulerLedgerState,
    pub stale_symbol_policy: StaleSymbolPolicy,
    pub rollback_policy: SchedulerRollbackPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairMutationRoute {
    NoMutation,
    DetectionOnly,
    MountedMutationAuthority,
    DirectBlockWrite,
}

impl RepairMutationRoute {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NoMutation => "no_mutation",
            Self::DetectionOnly => "detection_only",
            Self::MountedMutationAuthority => "mounted_mutation_authority",
            Self::DirectBlockWrite => "direct_block_write",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerLedgerState {
    Complete,
    Missing,
    Incomplete,
    Stale,
}

impl SchedulerLedgerState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Missing => "missing",
            Self::Incomplete => "incomplete",
            Self::Stale => "stale",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaleSymbolPolicy {
    RefuseMutation,
    RefreshBeforeMutation,
    Unknown,
}

impl StaleSymbolPolicy {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::RefuseMutation => "refuse_mutation",
            Self::RefreshBeforeMutation => "refresh_before_mutation",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerRollbackPolicy {
    AbortAndRollback,
    DetectionOnlyNoWrite,
    Missing,
}

impl SchedulerRollbackPolicy {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AbortAndRollback => "abort_and_rollback",
            Self::DetectionOnlyNoWrite => "detection_only_no_write",
            Self::Missing => "missing",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerClassification {
    Pass,
    Warn,
    Fail,
    Skip,
}

impl SchedulerClassification {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::Skip => "skip",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerReleaseClaimState {
    Experimental,
    FixtureSmokeOnly,
    SmallHostSmoke,
    MeasuredLocal,
    MeasuredAuthoritative,
    Blocked,
}

impl SchedulerReleaseClaimState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Experimental => "experimental",
            Self::FixtureSmokeOnly => "fixture_smoke_only",
            Self::SmallHostSmoke => "small_host_smoke",
            Self::MeasuredLocal => "measured_local",
            Self::MeasuredAuthoritative => "measured_authoritative",
            Self::Blocked => "blocked",
        }
    }

    #[must_use]
    pub const fn is_conservative(self) -> bool {
        matches!(
            self,
            Self::Experimental | Self::FixtureSmokeOnly | Self::SmallHostSmoke | Self::Blocked
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScrubRepairSchedulerReport {
    pub schema_version: u32,
    pub manifest_id: String,
    pub valid: bool,
    pub scenario_count: usize,
    pub classification_counts: BTreeMap<String, usize>,
    pub conservative_claim_count: usize,
    pub authoritative_claim_count: usize,
    pub rows: Vec<ScrubRepairSchedulerRow>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScrubRepairSchedulerRow {
    pub scenario_id: String,
    pub workload_class: String,
    pub scheduler_mode: String,
    pub lane: String,
    pub classification: String,
    pub release_claim_state: String,
    pub foreground_p99_regression_pct: f64,
    pub fairness_index: f64,
    pub repair_freshness_loss: f64,
    pub foreground_latency_loss: f64,
    pub dominant_loss: String,
    pub mutation_route: String,
    pub ledger_state: String,
    pub stale_symbol_policy: String,
}

pub fn load_scrub_repair_scheduler_manifest(path: &Path) -> Result<ScrubRepairSchedulerManifest> {
    let text = fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read scrub/repair scheduler manifest {}",
            path.display()
        )
    })?;
    serde_json::from_str(&text).with_context(|| {
        format!(
            "invalid scrub/repair scheduler manifest JSON {}",
            path.display()
        )
    })
}

#[must_use]
pub fn validate_scrub_repair_scheduler_manifest(
    manifest: &ScrubRepairSchedulerManifest,
) -> ScrubRepairSchedulerReport {
    let mut errors = validate_manifest_shape(manifest);
    let mut rows = Vec::new();

    for scenario in &manifest.scenarios {
        validate_scenario(&manifest.policy, scenario, &mut errors);
        rows.push(build_row(&manifest.policy, scenario));
    }

    let classification_counts = count_classifications(manifest);
    let conservative_claim_count = manifest
        .scenarios
        .iter()
        .filter(|scenario| scenario.release_claim_state.is_conservative())
        .count();
    let authoritative_claim_count = manifest
        .scenarios
        .iter()
        .filter(|scenario| {
            scenario.release_claim_state == SchedulerReleaseClaimState::MeasuredAuthoritative
        })
        .count();

    ScrubRepairSchedulerReport {
        schema_version: SCRUB_REPAIR_SCHEDULER_SCHEMA_VERSION,
        manifest_id: manifest.manifest_id.clone(),
        valid: errors.is_empty(),
        scenario_count: manifest.scenarios.len(),
        classification_counts,
        conservative_claim_count,
        authoritative_claim_count,
        rows,
        errors,
    }
}

pub fn fail_on_scrub_repair_scheduler_errors(report: &ScrubRepairSchedulerReport) -> Result<()> {
    if report.valid {
        Ok(())
    } else {
        bail!(
            "scrub/repair scheduler manifest invalid: {} error(s)",
            report.errors.len()
        )
    }
}

#[must_use]
pub fn render_scrub_repair_scheduler_markdown(report: &ScrubRepairSchedulerReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Scrub/Repair Scheduler Proof Plan");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Manifest: `{}`", report.manifest_id);
    let _ = writeln!(out, "- Valid: `{}`", report.valid);
    let _ = writeln!(out, "- Scenarios: `{}`", report.scenario_count);
    let _ = writeln!(
        out,
        "- Conservative claims: `{}`",
        report.conservative_claim_count
    );
    let _ = writeln!(
        out,
        "- Authoritative claims: `{}`",
        report.authoritative_claim_count
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| Scenario | Mode | Class | Claim | p99 delta | Freshness loss | Foreground loss | Route |"
    );
    let _ = writeln!(
        out,
        "|----------|------|-------|-------|-----------|----------------|-----------------|-------|"
    );
    for row in &report.rows {
        let _ = writeln!(
            out,
            "| `{}` | `{}` | `{}` | `{}` | `{:.2}%` | `{:.2}` | `{:.2}` | `{}` |",
            row.scenario_id,
            row.scheduler_mode,
            row.classification,
            row.release_claim_state,
            row.foreground_p99_regression_pct,
            row.repair_freshness_loss,
            row.foreground_latency_loss,
            row.mutation_route
        );
    }

    if !report.errors.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "## Errors");
        for error in &report.errors {
            let _ = writeln!(out, "- {error}");
        }
    }

    out
}

fn validate_manifest_shape(manifest: &ScrubRepairSchedulerManifest) -> Vec<String> {
    let mut errors = Vec::new();
    if manifest.schema_version != SCRUB_REPAIR_SCHEDULER_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version must be {}; got {}",
            SCRUB_REPAIR_SCHEDULER_SCHEMA_VERSION, manifest.schema_version
        ));
    }
    require_non_empty("manifest_id", &manifest.manifest_id, &mut errors);
    require_non_empty("generated_at", &manifest.generated_at, &mut errors);
    validate_policy(&manifest.policy, &mut errors);
    validate_required_invariants(&manifest.required_invariants, &mut errors);
    if manifest.proof_bundle_consumers.is_empty() {
        errors.push("proof_bundle_consumers must include at least one consumer".to_owned());
    }
    if manifest.scenarios.is_empty() {
        errors.push("at least one scrub/repair scheduler scenario is required".to_owned());
    }
    errors
}

fn validate_policy(policy: &ScrubRepairSchedulerPolicy, errors: &mut Vec<String>) {
    validate_non_negative(
        "policy.max_foreground_p99_regression_pct",
        policy.max_foreground_p99_regression_pct,
        errors,
    );
    if policy.max_repair_backlog_age_secs == 0 {
        errors.push("policy.max_repair_backlog_age_secs must be positive".to_owned());
    }
    if policy.max_stale_symbol_age_secs == 0 {
        errors.push("policy.max_stale_symbol_age_secs must be positive".to_owned());
    }
    validate_ratio(
        "policy.min_fairness_index",
        policy.min_fairness_index,
        errors,
    );
    if !policy.default_release_claim_state.is_conservative() {
        errors.push(
            "policy.default_release_claim_state must stay conservative by default".to_owned(),
        );
    }
    validate_non_negative(
        "policy.expected_loss_weights.repair_freshness_weight",
        policy.expected_loss_weights.repair_freshness_weight,
        errors,
    );
    validate_non_negative(
        "policy.expected_loss_weights.foreground_latency_weight",
        policy.expected_loss_weights.foreground_latency_weight,
        errors,
    );
    validate_non_negative(
        "policy.expected_loss_weights.stale_symbol_weight",
        policy.expected_loss_weights.stale_symbol_weight,
        errors,
    );
    validate_non_negative(
        "policy.expected_loss_weights.fairness_weight",
        policy.expected_loss_weights.fairness_weight,
        errors,
    );
}

fn validate_scenario(
    policy: &ScrubRepairSchedulerPolicy,
    scenario: &ScrubRepairSchedulerScenario,
    errors: &mut Vec<String>,
) {
    require_non_empty("scenario.scenario_id", &scenario.scenario_id, errors);
    require_non_empty(
        "scenario.reproduction_command",
        &scenario.reproduction_command,
        errors,
    );
    validate_non_empty_paths("scenario.raw_logs", &scenario.raw_logs, errors);
    validate_non_empty_paths("scenario.artifact_paths", &scenario.artifact_paths, errors);
    validate_non_empty_paths(
        "scenario.proof_bundle_artifact_paths",
        &scenario.proof_bundle_artifact_paths,
        errors,
    );
    validate_non_negative(
        &format!(
            "scenario {} baseline_foreground_p99_us",
            scenario.scenario_id
        ),
        scenario.baseline_foreground_p99_us,
        errors,
    );
    validate_non_negative(
        &format!(
            "scenario {} observed_foreground_p99_us",
            scenario.scenario_id
        ),
        scenario.observed_foreground_p99_us,
        errors,
    );
    if scenario.baseline_foreground_p99_us <= 0.0 {
        errors.push(format!(
            "scenario {} baseline_foreground_p99_us must be positive",
            scenario.scenario_id
        ));
    }
    if scenario.fairness.foreground_morsels == 0 && scenario.fairness.repair_morsels == 0 {
        errors.push(format!(
            "scenario {} must record foreground or repair morsels",
            scenario.scenario_id
        ));
    }
    if scenario.fairness.cancellation == SchedulerCancellationState::Unknown {
        errors.push(format!(
            "scenario {} cancellation state must be explicit",
            scenario.scenario_id
        ));
    }
    validate_ledger(policy, scenario, errors);
    validate_classification(policy, scenario, errors);
    validate_release_claim(scenario, errors);
}

fn validate_ledger(
    policy: &ScrubRepairSchedulerPolicy,
    scenario: &ScrubRepairSchedulerScenario,
    errors: &mut Vec<String>,
) {
    if scenario.ledger.mutation_route == RepairMutationRoute::DirectBlockWrite {
        errors.push(format!(
            "scenario {} repair writeback bypasses the mounted mutation authority",
            scenario.scenario_id
        ));
    }
    if scenario.ledger.ledger_state != SchedulerLedgerState::Complete {
        errors.push(format!(
            "scenario {} ledger_state must be complete, got {}",
            scenario.scenario_id,
            scenario.ledger.ledger_state.label()
        ));
    }
    if scenario.ledger.rollback_policy == SchedulerRollbackPolicy::Missing {
        errors.push(format!(
            "scenario {} rollback_policy must be explicit",
            scenario.scenario_id
        ));
    }
    if scenario.stale_symbol_age_secs > policy.max_stale_symbol_age_secs
        && scenario.ledger.stale_symbol_policy != StaleSymbolPolicy::RefuseMutation
    {
        errors.push(format!(
            "scenario {} stale symbols exceed policy but are not refused",
            scenario.scenario_id
        ));
    }
}

fn validate_classification(
    policy: &ScrubRepairSchedulerPolicy,
    scenario: &ScrubRepairSchedulerScenario,
    errors: &mut Vec<String>,
) {
    let row = build_row(policy, scenario);
    if scenario.classification == SchedulerClassification::Pass {
        if row.foreground_p99_regression_pct > policy.max_foreground_p99_regression_pct {
            errors.push(format!(
                "scenario {} passes despite foreground p99 regression {:.2}% above budget {:.2}%",
                scenario.scenario_id,
                row.foreground_p99_regression_pct,
                policy.max_foreground_p99_regression_pct
            ));
        }
        if scenario.repair_backlog_age_secs > policy.max_repair_backlog_age_secs {
            errors.push(format!(
                "scenario {} passes despite repair backlog age {}s above budget {}s",
                scenario.scenario_id,
                scenario.repair_backlog_age_secs,
                policy.max_repair_backlog_age_secs
            ));
        }
        if scenario.stale_symbol_age_secs > policy.max_stale_symbol_age_secs {
            errors.push(format!(
                "scenario {} passes despite stale symbol age {}s above budget {}s",
                scenario.scenario_id,
                scenario.stale_symbol_age_secs,
                policy.max_stale_symbol_age_secs
            ));
        }
        if row.fairness_index < policy.min_fairness_index {
            errors.push(format!(
                "scenario {} passes despite fairness index {:.3} below {:.3}",
                scenario.scenario_id, row.fairness_index, policy.min_fairness_index
            ));
        }
    }
}

fn validate_release_claim(scenario: &ScrubRepairSchedulerScenario, errors: &mut Vec<String>) {
    if scenario.release_claim_state == SchedulerReleaseClaimState::MeasuredAuthoritative {
        if scenario.lane != ScrubRepairSchedulerLane::PermissionedLargeHost {
            errors.push(format!(
                "scenario {} authoritative claim must run in permissioned_large_host lane",
                scenario.scenario_id
            ));
        }
        if scenario.classification != SchedulerClassification::Pass {
            errors.push(format!(
                "scenario {} authoritative claim must have pass classification",
                scenario.scenario_id
            ));
        }
    }
}

fn build_row(
    policy: &ScrubRepairSchedulerPolicy,
    scenario: &ScrubRepairSchedulerScenario,
) -> ScrubRepairSchedulerRow {
    let foreground_p99_regression_pct = foreground_p99_regression_pct(scenario);
    let fairness_index = scenario.fairness.fairness_index();
    let repair_freshness_loss = repair_freshness_loss(policy, scenario, fairness_index);
    let foreground_latency_loss = policy
        .expected_loss_weights
        .foreground_latency_weight
        .mul_add(foreground_p99_regression_pct.max(0.0), 0.0);
    let dominant_loss = if repair_freshness_loss >= foreground_latency_loss {
        "repair_freshness"
    } else {
        "foreground_latency"
    };

    ScrubRepairSchedulerRow {
        scenario_id: scenario.scenario_id.clone(),
        workload_class: scenario.workload_class.label().to_owned(),
        scheduler_mode: scenario.scheduler_mode.label().to_owned(),
        lane: scenario.lane.label().to_owned(),
        classification: scenario.classification.label().to_owned(),
        release_claim_state: scenario.release_claim_state.label().to_owned(),
        foreground_p99_regression_pct,
        fairness_index,
        repair_freshness_loss,
        foreground_latency_loss,
        dominant_loss: dominant_loss.to_owned(),
        mutation_route: scenario.ledger.mutation_route.label().to_owned(),
        ledger_state: scenario.ledger.ledger_state.label().to_owned(),
        stale_symbol_policy: scenario.ledger.stale_symbol_policy.label().to_owned(),
    }
}

fn foreground_p99_regression_pct(scenario: &ScrubRepairSchedulerScenario) -> f64 {
    if scenario.baseline_foreground_p99_us <= 0.0 {
        0.0
    } else {
        ((scenario.observed_foreground_p99_us - scenario.baseline_foreground_p99_us)
            / scenario.baseline_foreground_p99_us)
            * 100.0
    }
}

fn repair_freshness_loss(
    policy: &ScrubRepairSchedulerPolicy,
    scenario: &ScrubRepairSchedulerScenario,
    fairness_index: f64,
) -> f64 {
    let backlog_ratio = ratio_against_budget(
        scenario.repair_backlog_age_secs,
        policy.max_repair_backlog_age_secs,
    );
    let stale_ratio = ratio_against_budget(
        scenario.stale_symbol_age_secs,
        policy.max_stale_symbol_age_secs,
    );
    let fairness_debt = (1.0 - fairness_index).clamp(0.0, 1.0);
    let loss = policy
        .expected_loss_weights
        .repair_freshness_weight
        .mul_add(backlog_ratio, 0.0);
    let loss = policy
        .expected_loss_weights
        .stale_symbol_weight
        .mul_add(stale_ratio, loss);
    policy
        .expected_loss_weights
        .fairness_weight
        .mul_add(fairness_debt, loss)
}

fn ratio_against_budget(observed: u64, budget: u64) -> f64 {
    if budget == 0 {
        0.0
    } else {
        observed as f64 / budget as f64
    }
}

fn count_classifications(manifest: &ScrubRepairSchedulerManifest) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for scenario in &manifest.scenarios {
        *counts
            .entry(scenario.classification.label().to_owned())
            .or_insert(0) += 1;
    }
    counts
}

fn validate_required_invariants(required_invariants: &[String], errors: &mut Vec<String>) {
    let actual = required_invariants
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for required in REQUIRED_INVARIANTS {
        if !actual.contains(required) {
            errors.push(format!("required_invariants missing {required}"));
        }
    }
}

fn validate_ratio(field: &str, value: f64, errors: &mut Vec<String>) {
    if !(0.0..=1.0).contains(&value) {
        errors.push(format!("{field} must be in [0,1]"));
    }
}

fn validate_non_negative(field: &str, value: f64, errors: &mut Vec<String>) {
    if value < 0.0 {
        errors.push(format!("{field} must be non-negative"));
    }
}

fn require_non_empty(field: &str, value: &str, errors: &mut Vec<String>) {
    if value.trim().is_empty() {
        errors.push(format!("{field} must not be empty"));
    }
}

fn validate_non_empty_paths(field: &str, paths: &[String], errors: &mut Vec<String>) {
    if paths.is_empty() {
        errors.push(format!("{field} must not be empty"));
    }
    for path in paths {
        require_non_empty(field, path, errors);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_manifest_accepts_authoritative_and_smoke_rows() {
        let report = validate_scrub_repair_scheduler_manifest(&sample_manifest());

        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.scenario_count, 2);
        assert_eq!(report.authoritative_claim_count, 1);
        assert_eq!(report.conservative_claim_count, 1);
        assert_eq!(report.classification_counts.get("pass"), Some(&1));
        assert_eq!(report.classification_counts.get("skip"), Some(&1));
    }

    #[test]
    fn direct_repair_writeback_route_fails_closed() {
        let mut manifest = sample_manifest();
        manifest.scenarios[0].ledger.mutation_route = RepairMutationRoute::DirectBlockWrite;

        let report = validate_scrub_repair_scheduler_manifest(&manifest);

        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("bypasses the mounted mutation authority"))
        );
    }

    #[test]
    fn stale_symbols_must_be_refused_when_over_budget() {
        let mut manifest = sample_manifest();
        manifest.scenarios[0].stale_symbol_age_secs = 901;
        manifest.scenarios[0].ledger.stale_symbol_policy = StaleSymbolPolicy::RefreshBeforeMutation;

        let report = validate_scrub_repair_scheduler_manifest(&manifest);

        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("stale symbols exceed policy"))
        );
    }

    #[test]
    fn pass_rows_must_respect_foreground_budget() {
        let mut manifest = sample_manifest();
        manifest.scenarios[0].observed_foreground_p99_us = 7_500.0;

        let report = validate_scrub_repair_scheduler_manifest(&manifest);

        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("foreground p99 regression"))
        );
    }

    fn sample_manifest() -> ScrubRepairSchedulerManifest {
        ScrubRepairSchedulerManifest {
            schema_version: SCRUB_REPAIR_SCHEDULER_SCHEMA_VERSION,
            manifest_id: "scrub-repair-scheduler-test".to_owned(),
            generated_at: "2026-05-03T00:00:00Z".to_owned(),
            policy: ScrubRepairSchedulerPolicy {
                max_foreground_p99_regression_pct: 12.0,
                max_repair_backlog_age_secs: 900,
                max_stale_symbol_age_secs: 600,
                min_fairness_index: 0.70,
                default_release_claim_state: SchedulerReleaseClaimState::Experimental,
                expected_loss_weights: SchedulerExpectedLossWeights {
                    repair_freshness_weight: 20.0,
                    foreground_latency_weight: 1.0,
                    stale_symbol_weight: 30.0,
                    fairness_weight: 15.0,
                },
            },
            scenarios: vec![authoritative_scenario(), smoke_scenario()],
            required_invariants: REQUIRED_INVARIANTS
                .iter()
                .map(|invariant| (*invariant).to_owned())
                .collect(),
            proof_bundle_consumers: vec!["bd-p2j3e".to_owned(), "proof-bundle".to_owned()],
        }
    }

    fn authoritative_scenario() -> ScrubRepairSchedulerScenario {
        ScrubRepairSchedulerScenario {
            scenario_id: "scrub_repair_overlap_large_host".to_owned(),
            workload_class: ScrubRepairWorkloadClass::ScrubRepairOverlap,
            scheduler_mode: ScrubRepairSchedulerMode::MorselDriven,
            lane: ScrubRepairSchedulerLane::PermissionedLargeHost,
            baseline_foreground_p99_us: 5_000.0,
            observed_foreground_p99_us: 5_300.0,
            repair_backlog_age_secs: 300,
            stale_symbol_age_secs: 120,
            fairness: SchedulerFairnessCounters {
                foreground_morsels: 1_000,
                repair_morsels: 850,
                yielded_to_foreground: 144,
                throttled_repair_morsels: 21,
                cancellation: SchedulerCancellationState::CancellationObserved,
            },
            ledger: SchedulerLedgerObservation {
                mutation_route: RepairMutationRoute::MountedMutationAuthority,
                ledger_state: SchedulerLedgerState::Complete,
                stale_symbol_policy: StaleSymbolPolicy::RefuseMutation,
                rollback_policy: SchedulerRollbackPolicy::AbortAndRollback,
            },
            classification: SchedulerClassification::Pass,
            release_claim_state: SchedulerReleaseClaimState::MeasuredAuthoritative,
            reproduction_command: "ffs-harness validate-scrub-repair-scheduler".to_owned(),
            raw_logs: vec!["artifacts/scheduler/large-host/run.log".to_owned()],
            artifact_paths: vec!["artifacts/scheduler/large-host/report.json".to_owned()],
            proof_bundle_artifact_paths: vec![
                "artifacts/proof/scheduler/large-host.json".to_owned(),
            ],
        }
    }

    fn smoke_scenario() -> ScrubRepairSchedulerScenario {
        ScrubRepairSchedulerScenario {
            scenario_id: "scrub_repair_fixture_smoke".to_owned(),
            workload_class: ScrubRepairWorkloadClass::FixtureSmoke,
            scheduler_mode: ScrubRepairSchedulerMode::ForegroundFirst,
            lane: ScrubRepairSchedulerLane::DeveloperSmoke,
            baseline_foreground_p99_us: 8_000.0,
            observed_foreground_p99_us: 8_100.0,
            repair_backlog_age_secs: 60,
            stale_symbol_age_secs: 30,
            fairness: SchedulerFairnessCounters {
                foreground_morsels: 100,
                repair_morsels: 40,
                yielded_to_foreground: 12,
                throttled_repair_morsels: 8,
                cancellation: SchedulerCancellationState::NotExercised,
            },
            ledger: SchedulerLedgerObservation {
                mutation_route: RepairMutationRoute::DetectionOnly,
                ledger_state: SchedulerLedgerState::Complete,
                stale_symbol_policy: StaleSymbolPolicy::RefuseMutation,
                rollback_policy: SchedulerRollbackPolicy::DetectionOnlyNoWrite,
            },
            classification: SchedulerClassification::Skip,
            release_claim_state: SchedulerReleaseClaimState::FixtureSmokeOnly,
            reproduction_command: "ffs-harness validate-scrub-repair-scheduler".to_owned(),
            raw_logs: vec!["artifacts/scheduler/smoke/run.log".to_owned()],
            artifact_paths: vec!["artifacts/scheduler/smoke/report.json".to_owned()],
            proof_bundle_artifact_paths: vec!["artifacts/proof/scheduler/smoke.json".to_owned()],
        }
    }

    /// bd-dzdog — golden-output snapshot for
    /// `render_scrub_repair_scheduler_markdown` on the deterministic
    /// `sample_manifest()` fixture. The function previously had ZERO
    /// tests despite being a public renderer. Pins:
    ///   * the title line `# Scrub/Repair Scheduler Proof Plan`
    ///   * the 5-bullet header (Manifest / Valid / Scenarios /
    ///     Conservative claims / Authoritative claims)
    ///   * the 8-column table header + alignment row
    ///   * per-scenario row layout including the percent format
    ///     `{:.2}%`, freshness/foreground floats, and the route enum
    ///     name (`mounted_mutation_authority` / `detection_only`)
    /// Pairs with bd-by4bc (perf_comparison) / bd-aofgb
    /// (remediation_catalog) / bd-bogcc (invariant_oracle).
    #[test]
    fn render_scrub_repair_scheduler_markdown_default_sample_snapshot() {
        let report = validate_scrub_repair_scheduler_manifest(&sample_manifest());
        let markdown = render_scrub_repair_scheduler_markdown(&report);
        insta::assert_snapshot!(
            "render_scrub_repair_scheduler_markdown_default_sample",
            markdown
        );
    }
}
