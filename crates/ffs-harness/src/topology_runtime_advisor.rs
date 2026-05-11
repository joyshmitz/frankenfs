#![forbid(unsafe_code)]

//! Advisory topology/runtime manifest contract.
//!
//! The topology runtime advisor is a non-permissioned preflight surface. It
//! records host topology, workload shape, candidate runtime modes, and artifact
//! paths so operators can prepare a later permissioned large-host run without
//! upgrading product readiness claims.

use crate::artifact_manifest::parse_manifest_timestamp_epoch_days;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Component, Path};
use std::time::{SystemTime, UNIX_EPOCH};

pub const TOPOLOGY_RUNTIME_ADVISOR_MANIFEST_VERSION: u32 = 1;
pub const DEFAULT_TOPOLOGY_RUNTIME_ADVISOR_MANIFEST: &str =
    "docs/topology-runtime-advisor-manifest.json";
pub const TOPOLOGY_RUNTIME_ADVISOR_PRODUCT_EVIDENCE_CLAIM: &str = "none";
pub const TOPOLOGY_RUNTIME_ADVISOR_RELEASE_GATE_EFFECT: &str = "advisory_only";
pub const TOPOLOGY_RUNTIME_ADVISOR_DEFAULT_MAX_AGE_DAYS: u32 = 14;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TopologyRuntimeAdvisorManifest {
    pub manifest_version: u32,
    pub operation_id: String,
    pub scenario_id: String,
    pub source_bead: String,
    pub real_campaign_bead: String,
    pub generated_at: String,
    pub expires_at: String,
    pub manifest_path: String,
    pub artifact_root: String,
    pub host_topology: TopologyHostTopology,
    pub fuse_capability: TopologyFuseCapability,
    pub rch_worker_identity: Option<String>,
    pub resource_caps: TopologyResourceCaps,
    pub runtime_candidates: Vec<TopologyRuntimeCandidate>,
    pub workload_shapes: Vec<TopologyWorkloadShape>,
    pub artifact_paths: Vec<String>,
    pub command_transcript: TopologyCommandTranscript,
    pub product_evidence_claim: String,
    pub release_gate_effect: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyHostTopology {
    pub cpu_count: u32,
    pub numa_nodes: u32,
    pub ram_bytes: u64,
    pub storage_profile: TopologyStorageProfile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyStorageProfile {
    LocalNvme,
    LocalSsd,
    NetworkBlock,
    Tmpfs,
    Unknown,
}

impl TopologyStorageProfile {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::LocalNvme => "local_nvme",
            Self::LocalSsd => "local_ssd",
            Self::NetworkBlock => "network_block",
            Self::Tmpfs => "tmpfs",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyFuseCapability {
    pub state: TopologyFuseCapabilityState,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyFuseCapabilityState {
    Available,
    Missing,
    PermissionDenied,
    DisabledByUser,
    Unknown,
}

impl TopologyFuseCapabilityState {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyResourceCaps {
    pub max_duration_secs: u64,
    pub max_threads: u32,
    pub max_memory_bytes: u64,
    pub max_temp_bytes: u64,
    pub max_queue_depth: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyRuntimeCandidate {
    pub mode: TopologyRuntimeMode,
    pub enabled: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyRuntimeMode {
    Standard,
    Managed,
    PerCore,
}

impl TopologyRuntimeMode {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Managed => "managed",
            Self::PerCore => "per_core",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TopologyWorkloadShape {
    pub workload_id: String,
    pub hot_inode_concentration: f64,
    pub directory_fanout: u32,
    pub read_ratio: f64,
    pub write_ratio: f64,
    pub fsyncs_per_second: f64,
    pub expected_dirty_bytes: u64,
    pub queue_depth: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyCommandTranscript {
    pub invocation: String,
    pub stdout_path: String,
    pub stderr_path: String,
    pub structured_log_path: String,
    pub report_path: String,
    pub summary_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyRuntimeAdvisorValidationConfig {
    pub reference_epoch_days: Option<u32>,
    pub max_age_days: u32,
}

impl Default for TopologyRuntimeAdvisorValidationConfig {
    fn default() -> Self {
        Self {
            reference_epoch_days: current_epoch_days(),
            max_age_days: TOPOLOGY_RUNTIME_ADVISOR_DEFAULT_MAX_AGE_DAYS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyRuntimeAdvisorIssue {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyRuntimeAdvisorReport {
    pub manifest_version: u32,
    pub operation_id: String,
    pub scenario_id: String,
    pub valid: bool,
    pub outcome: String,
    pub advisory_only: bool,
    pub product_evidence_claim: String,
    pub release_gate_effect: String,
    pub manifest_path: String,
    pub artifact_root: String,
    pub source_bead: String,
    pub real_campaign_bead: String,
    pub host_classification: String,
    pub fuse_capability_state: String,
    pub workload_count: usize,
    pub runtime_candidate_count: usize,
    pub artifact_count: usize,
    pub stdout_path: String,
    pub stderr_path: String,
    pub structured_log_path: String,
    pub error_class: Option<String>,
    pub issues: Vec<TopologyRuntimeAdvisorIssue>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyRuntimeAdvisorConfidenceTier {
    High,
    Medium,
    Low,
    NoRecommendation,
}

impl TopologyRuntimeAdvisorConfidenceTier {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::NoRecommendation => "no_recommendation",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyRuntimeAdvisorCandidateScore {
    pub runtime_candidate: String,
    pub score: i32,
    pub confidence_tier: String,
    pub rejection_reason: Option<String>,
    pub rationale: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyRuntimeAdvisorLossRiskEntry {
    pub signal: String,
    pub expected_loss: u32,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyRuntimeAdvisorScoringReport {
    pub operation_id: String,
    pub scenario_id: String,
    pub valid: bool,
    pub advisory_only: bool,
    pub product_evidence_claim: String,
    pub release_gate_effect: String,
    pub release_claim_state: String,
    pub recommendation: Option<String>,
    pub confidence_tier: String,
    pub candidate_scores: Vec<TopologyRuntimeAdvisorCandidateScore>,
    pub rejected_candidates: usize,
    pub loss_risk_ledger: Vec<TopologyRuntimeAdvisorLossRiskEntry>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct WorkloadSignals {
    max_hot_inode_concentration: f64,
    max_directory_fanout: u32,
    average_read_ratio: f64,
    average_write_ratio: f64,
    max_fsyncs_per_second: f64,
    max_dirty_pressure: f64,
    max_queue_pressure: f64,
}

pub fn load_topology_runtime_advisor_manifest(
    path: &Path,
) -> Result<TopologyRuntimeAdvisorManifest> {
    let text = fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read topology runtime advisor manifest {}",
            path.display()
        )
    })?;
    serde_json::from_str(&text).with_context(|| {
        format!(
            "invalid topology runtime advisor manifest JSON {}",
            path.display()
        )
    })
}

#[must_use]
pub fn validate_topology_runtime_advisor_manifest(
    manifest: &TopologyRuntimeAdvisorManifest,
) -> TopologyRuntimeAdvisorReport {
    validate_topology_runtime_advisor_manifest_with_config(
        manifest,
        &TopologyRuntimeAdvisorValidationConfig::default(),
    )
}

#[must_use]
pub fn validate_topology_runtime_advisor_manifest_with_config(
    manifest: &TopologyRuntimeAdvisorManifest,
    config: &TopologyRuntimeAdvisorValidationConfig,
) -> TopologyRuntimeAdvisorReport {
    let mut issues = Vec::new();
    validate_identity(manifest, &mut issues);
    validate_timestamps(manifest, config, &mut issues);
    validate_host_topology(manifest, &mut issues);
    validate_resource_caps(manifest, &mut issues);
    validate_runtime_candidates(manifest, &mut issues);
    validate_workload_shapes(manifest, &mut issues);
    validate_paths(manifest, &mut issues);
    validate_claim_boundary(manifest, &mut issues);

    let errors = issues
        .iter()
        .map(|issue| format!("{}: {}", issue.path, issue.message))
        .collect::<Vec<_>>();
    let valid = errors.is_empty();
    let advisory_only = manifest.product_evidence_claim
        == TOPOLOGY_RUNTIME_ADVISOR_PRODUCT_EVIDENCE_CLAIM
        && manifest.release_gate_effect == TOPOLOGY_RUNTIME_ADVISOR_RELEASE_GATE_EFFECT;

    TopologyRuntimeAdvisorReport {
        manifest_version: manifest.manifest_version,
        operation_id: manifest.operation_id.clone(),
        scenario_id: manifest.scenario_id.clone(),
        valid,
        outcome: if valid { "pass" } else { "fail" }.to_owned(),
        advisory_only,
        product_evidence_claim: manifest.product_evidence_claim.clone(),
        release_gate_effect: manifest.release_gate_effect.clone(),
        manifest_path: manifest.manifest_path.clone(),
        artifact_root: manifest.artifact_root.clone(),
        source_bead: manifest.source_bead.clone(),
        real_campaign_bead: manifest.real_campaign_bead.clone(),
        host_classification: host_classification(&manifest.host_topology),
        fuse_capability_state: manifest.fuse_capability.state.label().to_owned(),
        workload_count: manifest.workload_shapes.len(),
        runtime_candidate_count: manifest.runtime_candidates.len(),
        artifact_count: manifest.artifact_paths.len(),
        stdout_path: manifest.command_transcript.stdout_path.clone(),
        stderr_path: manifest.command_transcript.stderr_path.clone(),
        structured_log_path: manifest.command_transcript.structured_log_path.clone(),
        error_class: (!valid).then(|| "topology_runtime_advisor_manifest_invalid".to_owned()),
        issues,
        errors,
    }
}

#[must_use]
pub fn score_topology_runtime_advisor_manifest(
    manifest: &TopologyRuntimeAdvisorManifest,
) -> TopologyRuntimeAdvisorScoringReport {
    score_topology_runtime_advisor_manifest_with_config(
        manifest,
        &TopologyRuntimeAdvisorValidationConfig::default(),
    )
}

#[must_use]
pub fn score_topology_runtime_advisor_manifest_with_config(
    manifest: &TopologyRuntimeAdvisorManifest,
    config: &TopologyRuntimeAdvisorValidationConfig,
) -> TopologyRuntimeAdvisorScoringReport {
    let validation_report =
        validate_topology_runtime_advisor_manifest_with_config(manifest, config);
    if !validation_report.valid {
        return TopologyRuntimeAdvisorScoringReport {
            operation_id: manifest.operation_id.clone(),
            scenario_id: manifest.scenario_id.clone(),
            valid: false,
            advisory_only: validation_report.advisory_only,
            product_evidence_claim: manifest.product_evidence_claim.clone(),
            release_gate_effect: manifest.release_gate_effect.clone(),
            release_claim_state: "not_product_evidence".to_owned(),
            recommendation: None,
            confidence_tier: TopologyRuntimeAdvisorConfidenceTier::NoRecommendation
                .label()
                .to_owned(),
            candidate_scores: Vec::new(),
            rejected_candidates: 0,
            loss_risk_ledger: Vec::new(),
            errors: validation_report.errors,
        };
    }

    let signals = derive_workload_signals(manifest);
    let mut candidate_scores = manifest
        .runtime_candidates
        .iter()
        .map(|candidate| score_runtime_candidate(manifest, &signals, candidate))
        .collect::<Vec<_>>();
    sort_candidate_scores_for_recommendation(&mut candidate_scores);

    let rejected_candidates = candidate_scores
        .iter()
        .filter(|score| score.rejection_reason.is_some())
        .count();
    let recommendation = candidate_scores
        .iter()
        .find(|score| score.rejection_reason.is_none())
        .map(|score| score.runtime_candidate.clone());
    let confidence_tier = confidence_tier(&candidate_scores);
    for score in &mut candidate_scores {
        confidence_tier
            .label()
            .clone_into(&mut score.confidence_tier);
    }

    TopologyRuntimeAdvisorScoringReport {
        operation_id: manifest.operation_id.clone(),
        scenario_id: manifest.scenario_id.clone(),
        valid: true,
        advisory_only: true,
        product_evidence_claim: TOPOLOGY_RUNTIME_ADVISOR_PRODUCT_EVIDENCE_CLAIM.to_owned(),
        release_gate_effect: TOPOLOGY_RUNTIME_ADVISOR_RELEASE_GATE_EFFECT.to_owned(),
        release_claim_state: "not_product_evidence".to_owned(),
        recommendation,
        confidence_tier: confidence_tier.label().to_owned(),
        candidate_scores,
        rejected_candidates,
        loss_risk_ledger: build_loss_risk_ledger(manifest, &signals),
        errors: Vec::new(),
    }
}

#[must_use]
pub fn render_topology_runtime_advisor_markdown(report: &TopologyRuntimeAdvisorReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Topology Runtime Advisor Report\n");
    let _ = writeln!(out, "- Operation: `{}`", report.operation_id);
    let _ = writeln!(out, "- Scenario: `{}`", report.scenario_id);
    let _ = writeln!(out, "- Valid: `{}`", report.valid);
    let _ = writeln!(out, "- Outcome: `{}`", report.outcome);
    let _ = writeln!(out, "- Advisory only: `{}`", report.advisory_only);
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
    let _ = writeln!(out, "- Source bead: `{}`", report.source_bead);
    let _ = writeln!(out, "- Real campaign bead: `{}`", report.real_campaign_bead);
    let _ = writeln!(out, "- Host class: `{}`", report.host_classification);
    let _ = writeln!(out, "- FUSE capability: `{}`", report.fuse_capability_state);
    let _ = writeln!(out, "- Workloads: `{}`", report.workload_count);
    let _ = writeln!(
        out,
        "- Runtime candidates: `{}`",
        report.runtime_candidate_count
    );
    let _ = writeln!(out, "- Artifacts: `{}`", report.artifact_count);

    out.push_str("\n## Command Transcript\n\n");
    let _ = writeln!(out, "- Manifest: `{}`", report.manifest_path);
    let _ = writeln!(out, "- Artifact root: `{}`", report.artifact_root);
    let _ = writeln!(out, "- Stdout: `{}`", report.stdout_path);
    let _ = writeln!(out, "- Stderr: `{}`", report.stderr_path);
    let _ = writeln!(out, "- Structured log: `{}`", report.structured_log_path);

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

#[must_use]
pub fn render_topology_runtime_advisor_score_markdown(
    report: &TopologyRuntimeAdvisorScoringReport,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Topology Runtime Advisor Score\n");
    let _ = writeln!(out, "- Operation: `{}`", report.operation_id);
    let _ = writeln!(out, "- Scenario: `{}`", report.scenario_id);
    let _ = writeln!(out, "- Valid: `{}`", report.valid);
    let _ = writeln!(out, "- Advisory only: `{}`", report.advisory_only);
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
        "- Release claim state: `{}`",
        report.release_claim_state
    );
    let _ = writeln!(
        out,
        "- Recommendation: `{}`",
        report.recommendation.as_deref().unwrap_or("none")
    );
    let _ = writeln!(out, "- Confidence: `{}`", report.confidence_tier);

    out.push_str("\n## Candidates\n\n");
    for candidate in &report.candidate_scores {
        let _ = writeln!(
            out,
            "- `{}`: score `{}` rejection `{}`",
            candidate.runtime_candidate,
            candidate.score,
            candidate.rejection_reason.as_deref().unwrap_or("none")
        );
        for rationale in &candidate.rationale {
            let _ = writeln!(out, "  - {rationale}");
        }
    }

    if report.loss_risk_ledger.is_empty() {
        out.push_str("\n## Loss/Risk Ledger\n\nnone\n");
    } else {
        out.push_str("\n## Loss/Risk Ledger\n\n");
        for entry in &report.loss_risk_ledger {
            let _ = writeln!(
                out,
                "- `{}` expected_loss `{}`: {}",
                entry.signal, entry.expected_loss, entry.rationale
            );
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

#[must_use]
pub fn render_topology_runtime_advisor_structured_log(
    report: &TopologyRuntimeAdvisorReport,
) -> String {
    let events = [
        json!({
            "event": "topology_runtime_advisor_validation_start",
            "operation_id": report.operation_id,
            "scenario_id": report.scenario_id,
            "advisory_only": true,
            "manifest_path": report.manifest_path,
            "artifact_root": report.artifact_root,
        }),
        json!({
            "event": "topology_runtime_advisor_validation_result",
            "operation_id": report.operation_id,
            "scenario_id": report.scenario_id,
            "outcome": report.outcome,
            "advisory_only": report.advisory_only,
            "product_evidence_claim": report.product_evidence_claim,
            "release_gate_effect": report.release_gate_effect,
            "error_class": report.error_class,
            "issue_count": report.issues.len(),
        }),
    ];

    let mut out = String::new();
    for event in events {
        let _ = writeln!(out, "{event}");
    }
    out
}

#[must_use]
pub fn render_topology_runtime_advisor_score_structured_log(
    report: &TopologyRuntimeAdvisorScoringReport,
) -> String {
    let mut out = String::new();
    for candidate in &report.candidate_scores {
        let _ = writeln!(
            out,
            "{}",
            json!({
                "event": "topology_runtime_advisor_score_candidate",
                "operation_id": report.operation_id,
                "scenario_id": report.scenario_id,
                "runtime_candidate": candidate.runtime_candidate,
                "score": candidate.score,
                "confidence_tier": report.confidence_tier,
                "rejection_reason": candidate.rejection_reason,
                "advisory_only": report.advisory_only,
            })
        );
    }
    let _ = writeln!(
        out,
        "{}",
        json!({
            "event": "topology_runtime_advisor_score_result",
            "operation_id": report.operation_id,
            "scenario_id": report.scenario_id,
            "runtime_candidate": report.recommendation,
            "confidence_tier": report.confidence_tier,
            "advisory_only": report.advisory_only,
            "product_evidence_claim": report.product_evidence_claim,
            "release_gate_effect": report.release_gate_effect,
            "release_claim_state": report.release_claim_state,
            "rejected_candidates": report.rejected_candidates,
            "error_count": report.errors.len(),
        })
    );
    out
}

pub fn fail_on_topology_runtime_advisor_errors(
    report: &TopologyRuntimeAdvisorReport,
) -> Result<()> {
    if !report.valid {
        bail!(
            "topology runtime advisor manifest validation failed: errors={}",
            report.errors.len()
        );
    }
    Ok(())
}

pub fn fail_on_topology_runtime_advisor_score_errors(
    report: &TopologyRuntimeAdvisorScoringReport,
) -> Result<()> {
    if !report.valid {
        bail!(
            "topology runtime advisor scoring failed: errors={}",
            report.errors.len()
        );
    }
    if report.recommendation.is_none() {
        bail!("topology runtime advisor scoring produced no recommendation");
    }
    Ok(())
}

#[allow(clippy::cast_precision_loss)]
fn derive_workload_signals(manifest: &TopologyRuntimeAdvisorManifest) -> WorkloadSignals {
    let workload_count = manifest.workload_shapes.len() as f64;
    let total_read_ratio = manifest
        .workload_shapes
        .iter()
        .map(|workload| workload.read_ratio)
        .sum::<f64>();
    let total_write_ratio = manifest
        .workload_shapes
        .iter()
        .map(|workload| workload.write_ratio)
        .sum::<f64>();
    let max_dirty_pressure = manifest
        .workload_shapes
        .iter()
        .map(|workload| {
            ratio_u64(
                workload.expected_dirty_bytes,
                manifest.resource_caps.max_memory_bytes,
            )
        })
        .fold(0.0, f64::max);
    let max_queue_pressure = manifest
        .workload_shapes
        .iter()
        .map(|workload| ratio_u32(workload.queue_depth, manifest.resource_caps.max_queue_depth))
        .fold(0.0, f64::max);

    WorkloadSignals {
        max_hot_inode_concentration: manifest
            .workload_shapes
            .iter()
            .map(|workload| workload.hot_inode_concentration)
            .fold(0.0, f64::max),
        max_directory_fanout: manifest
            .workload_shapes
            .iter()
            .map(|workload| workload.directory_fanout)
            .max()
            .unwrap_or(0),
        average_read_ratio: total_read_ratio / workload_count,
        average_write_ratio: total_write_ratio / workload_count,
        max_fsyncs_per_second: manifest
            .workload_shapes
            .iter()
            .map(|workload| workload.fsyncs_per_second)
            .fold(0.0, f64::max),
        max_dirty_pressure,
        max_queue_pressure,
    }
}

fn score_runtime_candidate(
    manifest: &TopologyRuntimeAdvisorManifest,
    signals: &WorkloadSignals,
    candidate: &TopologyRuntimeCandidate,
) -> TopologyRuntimeAdvisorCandidateScore {
    let mut score = match candidate.mode {
        TopologyRuntimeMode::Standard => 50,
        TopologyRuntimeMode::Managed => 45,
        TopologyRuntimeMode::PerCore => 40,
    };
    let mut rejection_reason = rejection_reason(manifest, candidate);
    let mut rationale = Vec::new();

    match candidate.mode {
        TopologyRuntimeMode::Standard => score_standard(signals, &mut score, &mut rationale),
        TopologyRuntimeMode::Managed => score_managed(signals, &mut score, &mut rationale),
        TopologyRuntimeMode::PerCore => {
            score_per_core(manifest, signals, &mut score, &mut rationale);
        }
    }
    if !candidate.enabled {
        rejection_reason = Some("candidate disabled by manifest".to_owned());
    }

    TopologyRuntimeAdvisorCandidateScore {
        runtime_candidate: candidate.mode.label().to_owned(),
        score,
        confidence_tier: TopologyRuntimeAdvisorConfidenceTier::NoRecommendation
            .label()
            .to_owned(),
        rejection_reason,
        rationale,
    }
}

fn score_standard(signals: &WorkloadSignals, score: &mut i32, rationale: &mut Vec<String>) {
    if signals.max_hot_inode_concentration < 0.45 {
        *score += 10;
        rationale.push("low hot-inode concentration keeps standard mode viable".to_owned());
    }
    if signals.max_dirty_pressure < 0.15 && signals.max_queue_pressure < 0.20 {
        *score += 10;
        rationale.push("low dirty-byte and queue pressure favor the baseline mode".to_owned());
    }
    if signals.average_read_ratio >= 0.70 && signals.max_directory_fanout >= 1_024 {
        *score -= 20;
        rationale.push("read-heavy sharded fanout needs more parallel routing".to_owned());
    }
    if signals.max_dirty_pressure >= 0.25 || signals.max_fsyncs_per_second >= 8.0 {
        *score -= 15;
        rationale.push("writeback pressure needs explicit backpressure management".to_owned());
    }
}

fn score_managed(signals: &WorkloadSignals, score: &mut i32, rationale: &mut Vec<String>) {
    if signals.max_hot_inode_concentration >= 0.65 {
        *score += 30;
        rationale.push("hot-inode skew favors centralized backpressure".to_owned());
    }
    if signals.max_dirty_pressure >= 0.25 {
        *score += 25;
        rationale.push("dirty-byte pressure requires backpressure thresholds".to_owned());
    }
    if signals.average_write_ratio >= 0.50 || signals.max_fsyncs_per_second >= 8.0 {
        *score += 10;
        rationale.push("write-heavy fsync cadence favors managed scheduling".to_owned());
    }
    if signals.average_read_ratio >= 0.75 && signals.max_directory_fanout >= 2_048 {
        *score -= 15;
        rationale.push("read-heavy sharded fanout can outgrow managed routing".to_owned());
    }
}

fn score_per_core(
    manifest: &TopologyRuntimeAdvisorManifest,
    signals: &WorkloadSignals,
    score: &mut i32,
    rationale: &mut Vec<String>,
) {
    if large_host_floor_met(&manifest.host_topology) {
        *score += 30;
        rationale.push("CPU/RAM/NUMA floor can support per-core routing".to_owned());
    }
    if signals.average_read_ratio >= 0.70 && signals.max_directory_fanout >= 1_024 {
        *score += 30;
        rationale.push("read-heavy sharded fanout favors per-core routing".to_owned());
    }
    if signals.max_queue_pressure >= 0.10 {
        *score += 10;
        rationale.push("queue depth can amortize per-core scheduling overhead".to_owned());
    }
    if signals.max_hot_inode_concentration >= 0.65 {
        *score -= 30;
        rationale.push("hot-inode skew risks per-core imbalance".to_owned());
    }
    if signals.max_dirty_pressure >= 0.25 {
        *score -= 10;
        rationale.push("dirty-byte pressure should be managed before sharding".to_owned());
    }
}

fn rejection_reason(
    manifest: &TopologyRuntimeAdvisorManifest,
    candidate: &TopologyRuntimeCandidate,
) -> Option<String> {
    if !candidate.enabled {
        return Some("candidate disabled by manifest".to_owned());
    }
    if candidate.mode != TopologyRuntimeMode::Standard
        && manifest.fuse_capability.state != TopologyFuseCapabilityState::Available
    {
        return Some("requires available FUSE capability".to_owned());
    }
    if candidate.mode == TopologyRuntimeMode::PerCore
        && !large_host_floor_met(&manifest.host_topology)
    {
        return Some("requires at least 64 CPUs, 256 GiB RAM, and two NUMA nodes".to_owned());
    }
    None
}

fn sort_candidate_scores_for_recommendation(scores: &mut [TopologyRuntimeAdvisorCandidateScore]) {
    scores.sort_by(|left, right| {
        left.rejection_reason
            .is_some()
            .cmp(&right.rejection_reason.is_some())
            .then_with(|| right.score.cmp(&left.score))
            .then_with(|| {
                mode_rank(&left.runtime_candidate).cmp(&mode_rank(&right.runtime_candidate))
            })
    });
}

fn confidence_tier(
    scores: &[TopologyRuntimeAdvisorCandidateScore],
) -> TopologyRuntimeAdvisorConfidenceTier {
    let mut viable = scores
        .iter()
        .filter(|score| score.rejection_reason.is_none());
    let Some(best) = viable.next() else {
        return TopologyRuntimeAdvisorConfidenceTier::NoRecommendation;
    };
    let best_score = best.score;
    let runner_up = viable.next().map_or(0, |score| score.score);
    match best_score - runner_up {
        gap if gap >= 20 => TopologyRuntimeAdvisorConfidenceTier::High,
        gap if gap >= 8 => TopologyRuntimeAdvisorConfidenceTier::Medium,
        _ => TopologyRuntimeAdvisorConfidenceTier::Low,
    }
}

fn build_loss_risk_ledger(
    manifest: &TopologyRuntimeAdvisorManifest,
    signals: &WorkloadSignals,
) -> Vec<TopologyRuntimeAdvisorLossRiskEntry> {
    let mut ledger = Vec::new();
    if !large_host_floor_met(&manifest.host_topology) {
        ledger.push(loss_risk(
            "small_host_downgrade",
            80,
            "per-core recommendations are rejected until the large-host floor is visible",
        ));
    }
    if signals.max_hot_inode_concentration >= 0.65 {
        ledger.push(loss_risk(
            "hot_inode_imbalance",
            70,
            "per-core sharding risks routing most work to one hot inode shard",
        ));
    }
    if signals.average_read_ratio >= 0.70 && signals.max_directory_fanout >= 1_024 {
        ledger.push(loss_risk(
            "sharded_read_fanout",
            30,
            "standard mode may underuse host parallelism on read-heavy directory fanout",
        ));
    }
    if signals.max_dirty_pressure >= 0.25 || signals.max_fsyncs_per_second >= 8.0 {
        ledger.push(loss_risk(
            "writeback_backpressure",
            65,
            "dirty-byte pressure and fsync cadence require explicit backpressure thresholds",
        ));
    }
    ledger
}

fn loss_risk(
    signal: impl Into<String>,
    expected_loss: u32,
    rationale: impl Into<String>,
) -> TopologyRuntimeAdvisorLossRiskEntry {
    TopologyRuntimeAdvisorLossRiskEntry {
        signal: signal.into(),
        expected_loss,
        rationale: rationale.into(),
    }
}

fn large_host_floor_met(host: &TopologyHostTopology) -> bool {
    host.cpu_count >= 64 && host.ram_bytes >= 256 * 1024 * 1024 * 1024 && host.numa_nodes >= 2
}

#[allow(clippy::cast_precision_loss)]
fn ratio_u64(value: u64, maximum: u64) -> f64 {
    if maximum == 0 {
        0.0
    } else {
        value as f64 / maximum as f64
    }
}

fn ratio_u32(value: u32, maximum: u32) -> f64 {
    if maximum == 0 {
        0.0
    } else {
        f64::from(value) / f64::from(maximum)
    }
}

fn mode_rank(mode: &str) -> u8 {
    match mode {
        "standard" => 0,
        "managed" => 1,
        "per_core" => 2,
        _ => 3,
    }
}

fn validate_identity(
    manifest: &TopologyRuntimeAdvisorManifest,
    issues: &mut Vec<TopologyRuntimeAdvisorIssue>,
) {
    if manifest.manifest_version != TOPOLOGY_RUNTIME_ADVISOR_MANIFEST_VERSION {
        push_issue(
            issues,
            "manifest_version",
            format!("must be {TOPOLOGY_RUNTIME_ADVISOR_MANIFEST_VERSION}"),
        );
    }
    validate_non_empty(issues, "operation_id", &manifest.operation_id);
    validate_non_empty(issues, "scenario_id", &manifest.scenario_id);
    validate_non_empty(issues, "source_bead", &manifest.source_bead);
    validate_non_empty(issues, "real_campaign_bead", &manifest.real_campaign_bead);
}

fn validate_timestamps(
    manifest: &TopologyRuntimeAdvisorManifest,
    config: &TopologyRuntimeAdvisorValidationConfig,
    issues: &mut Vec<TopologyRuntimeAdvisorIssue>,
) {
    let Some(generated_day) = parse_manifest_timestamp_epoch_days(&manifest.generated_at) else {
        push_issue(issues, "generated_at", "must be an RFC3339-like timestamp");
        return;
    };
    let Some(expires_day) = parse_manifest_timestamp_epoch_days(&manifest.expires_at) else {
        push_issue(issues, "expires_at", "must be an RFC3339-like timestamp");
        return;
    };
    if expires_day < generated_day {
        push_issue(issues, "expires_at", "must not be before generated_at");
    }
    if let Some(reference_day) = config.reference_epoch_days {
        if generated_day > reference_day.saturating_add(1) {
            push_issue(issues, "generated_at", "must not be in the future");
        }
        if reference_day.saturating_sub(generated_day) > config.max_age_days {
            push_issue(issues, "generated_at", "manifest is stale");
        }
        if expires_day < reference_day {
            push_issue(issues, "expires_at", "manifest is expired");
        }
    }
}

fn validate_host_topology(
    manifest: &TopologyRuntimeAdvisorManifest,
    issues: &mut Vec<TopologyRuntimeAdvisorIssue>,
) {
    if manifest.host_topology.cpu_count == 0 {
        push_issue(
            issues,
            "host_topology.cpu_count",
            "must be greater than zero",
        );
    }
    if manifest.host_topology.numa_nodes == 0 {
        push_issue(
            issues,
            "host_topology.numa_nodes",
            "must be greater than zero",
        );
    }
    if manifest.host_topology.ram_bytes == 0 {
        push_issue(
            issues,
            "host_topology.ram_bytes",
            "must be greater than zero",
        );
    }
    validate_non_empty(
        issues,
        "fuse_capability.detail",
        &manifest.fuse_capability.detail,
    );
    if let Some(worker) = &manifest.rch_worker_identity {
        validate_non_empty(issues, "rch_worker_identity", worker);
    }
}

fn validate_resource_caps(
    manifest: &TopologyRuntimeAdvisorManifest,
    issues: &mut Vec<TopologyRuntimeAdvisorIssue>,
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
    if manifest.host_topology.cpu_count > 0
        && caps.max_threads > manifest.host_topology.cpu_count.saturating_mul(8)
    {
        push_issue(
            issues,
            "resource_caps.max_threads",
            "exceeds eight times host CPU count",
        );
    }
    if manifest.host_topology.ram_bytes > 0
        && caps.max_memory_bytes > manifest.host_topology.ram_bytes
    {
        push_issue(issues, "resource_caps.max_memory_bytes", "exceeds host RAM");
    }
}

fn validate_runtime_candidates(
    manifest: &TopologyRuntimeAdvisorManifest,
    issues: &mut Vec<TopologyRuntimeAdvisorIssue>,
) {
    if manifest.runtime_candidates.is_empty() {
        push_issue(issues, "runtime_candidates", "must not be empty");
        return;
    }

    let mut modes = BTreeSet::new();
    for (index, candidate) in manifest.runtime_candidates.iter().enumerate() {
        if !modes.insert(candidate.mode) {
            push_issue(
                issues,
                format!("runtime_candidates[{index}].mode"),
                "must be unique",
            );
        }
        validate_non_empty(
            issues,
            format!("runtime_candidates[{index}].reason"),
            &candidate.reason,
        );
    }
}

fn validate_workload_shapes(
    manifest: &TopologyRuntimeAdvisorManifest,
    issues: &mut Vec<TopologyRuntimeAdvisorIssue>,
) {
    if manifest.workload_shapes.is_empty() {
        push_issue(issues, "workload_shapes", "must not be empty");
        return;
    }

    let mut workload_ids = BTreeSet::new();
    for (index, workload) in manifest.workload_shapes.iter().enumerate() {
        if workload.workload_id.trim().is_empty() {
            push_issue(
                issues,
                format!("workload_shapes[{index}].workload_id"),
                "must not be empty",
            );
        } else if !workload_ids.insert(workload.workload_id.as_str()) {
            push_issue(
                issues,
                format!("workload_shapes[{index}].workload_id"),
                "must be unique",
            );
        }
        validate_ratio(
            issues,
            format!("workload_shapes[{index}].hot_inode_concentration"),
            workload.hot_inode_concentration,
        );
        validate_ratio(
            issues,
            format!("workload_shapes[{index}].read_ratio"),
            workload.read_ratio,
        );
        validate_ratio(
            issues,
            format!("workload_shapes[{index}].write_ratio"),
            workload.write_ratio,
        );
        if workload.read_ratio + workload.write_ratio <= 0.0
            || workload.read_ratio + workload.write_ratio > 1.0
        {
            push_issue(
                issues,
                format!("workload_shapes[{index}].read_write_mix"),
                "read_ratio + write_ratio must be in (0, 1]",
            );
        }
        if workload.directory_fanout == 0 {
            push_issue(
                issues,
                format!("workload_shapes[{index}].directory_fanout"),
                "must be greater than zero",
            );
        }
        if !workload.fsyncs_per_second.is_finite() || workload.fsyncs_per_second < 0.0 {
            push_issue(
                issues,
                format!("workload_shapes[{index}].fsyncs_per_second"),
                "must be finite and non-negative",
            );
        }
        if workload.queue_depth == 0 {
            push_issue(
                issues,
                format!("workload_shapes[{index}].queue_depth"),
                "must be greater than zero",
            );
        }
        if workload.queue_depth > manifest.resource_caps.max_queue_depth {
            push_issue(
                issues,
                format!("workload_shapes[{index}].queue_depth"),
                "exceeds resource_caps.max_queue_depth",
            );
        }
        if workload.expected_dirty_bytes > manifest.resource_caps.max_memory_bytes {
            push_issue(
                issues,
                format!("workload_shapes[{index}].expected_dirty_bytes"),
                "exceeds resource_caps.max_memory_bytes",
            );
        }
    }
}

fn validate_paths(
    manifest: &TopologyRuntimeAdvisorManifest,
    issues: &mut Vec<TopologyRuntimeAdvisorIssue>,
) {
    validate_safe_relative_path(issues, "manifest_path", &manifest.manifest_path);
    validate_safe_relative_path(issues, "artifact_root", &manifest.artifact_root);
    validate_safe_relative_path(
        issues,
        "command_transcript.stdout_path",
        &manifest.command_transcript.stdout_path,
    );
    validate_safe_relative_path(
        issues,
        "command_transcript.stderr_path",
        &manifest.command_transcript.stderr_path,
    );
    validate_safe_relative_path(
        issues,
        "command_transcript.structured_log_path",
        &manifest.command_transcript.structured_log_path,
    );
    validate_safe_relative_path(
        issues,
        "command_transcript.report_path",
        &manifest.command_transcript.report_path,
    );
    validate_safe_relative_path(
        issues,
        "command_transcript.summary_path",
        &manifest.command_transcript.summary_path,
    );
    validate_non_empty(
        issues,
        "command_transcript.invocation",
        &manifest.command_transcript.invocation,
    );

    if manifest.artifact_paths.is_empty() {
        push_issue(issues, "artifact_paths", "must not be empty");
        return;
    }
    for (index, path) in manifest.artifact_paths.iter().enumerate() {
        validate_safe_relative_path(issues, format!("artifact_paths[{index}]"), path);
    }
}

fn validate_claim_boundary(
    manifest: &TopologyRuntimeAdvisorManifest,
    issues: &mut Vec<TopologyRuntimeAdvisorIssue>,
) {
    if manifest.product_evidence_claim != TOPOLOGY_RUNTIME_ADVISOR_PRODUCT_EVIDENCE_CLAIM {
        push_issue(
            issues,
            "product_evidence_claim",
            "must be none for advisory topology reports",
        );
    }
    if manifest.release_gate_effect != TOPOLOGY_RUNTIME_ADVISOR_RELEASE_GATE_EFFECT {
        push_issue(
            issues,
            "release_gate_effect",
            "must be advisory_only for topology reports",
        );
    }

    for (path, value) in [
        (
            "product_evidence_claim",
            manifest.product_evidence_claim.as_str(),
        ),
        ("release_gate_effect", manifest.release_gate_effect.as_str()),
        (
            "fuse_capability.detail",
            manifest.fuse_capability.detail.as_str(),
        ),
        ("manifest_path", manifest.manifest_path.as_str()),
        ("artifact_root", manifest.artifact_root.as_str()),
        (
            "command_transcript.invocation",
            manifest.command_transcript.invocation.as_str(),
        ),
        (
            "command_transcript.stdout_path",
            manifest.command_transcript.stdout_path.as_str(),
        ),
        (
            "command_transcript.stderr_path",
            manifest.command_transcript.stderr_path.as_str(),
        ),
        (
            "command_transcript.structured_log_path",
            manifest.command_transcript.structured_log_path.as_str(),
        ),
        (
            "command_transcript.report_path",
            manifest.command_transcript.report_path.as_str(),
        ),
        (
            "command_transcript.summary_path",
            manifest.command_transcript.summary_path.as_str(),
        ),
    ] {
        if value.contains("accepted_large_host") {
            push_issue(issues, path, "must not claim accepted_large_host evidence");
        }
    }

    for (index, candidate) in manifest.runtime_candidates.iter().enumerate() {
        if candidate.reason.contains("accepted_large_host") {
            push_issue(
                issues,
                format!("runtime_candidates[{index}].reason"),
                "must not claim accepted_large_host evidence",
            );
        }
    }

    for (index, path) in manifest.artifact_paths.iter().enumerate() {
        if path.contains("accepted_large_host") {
            push_issue(
                issues,
                format!("artifact_paths[{index}]"),
                "must not claim accepted_large_host evidence",
            );
        }
    }
}

fn validate_non_empty(
    issues: &mut Vec<TopologyRuntimeAdvisorIssue>,
    path: impl Into<String>,
    value: &str,
) {
    if value.trim().is_empty() {
        push_issue(issues, path, "must not be empty");
    }
}

fn validate_ratio(
    issues: &mut Vec<TopologyRuntimeAdvisorIssue>,
    path: impl Into<String>,
    value: f64,
) {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        push_issue(issues, path, "must be finite and between 0 and 1");
    }
}

fn validate_safe_relative_path(
    issues: &mut Vec<TopologyRuntimeAdvisorIssue>,
    path: impl Into<String>,
    value: &str,
) {
    let path = path.into();
    if !is_safe_relative_path(value) {
        push_issue(
            issues,
            path,
            "must be a non-empty relative path without parent traversal",
        );
    }
}

fn is_safe_relative_path(value: &str) -> bool {
    if value.trim().is_empty() {
        return false;
    }
    let path = Path::new(value);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn host_classification(host: &TopologyHostTopology) -> String {
    if host.cpu_count >= 64 && host.ram_bytes >= 256 * 1024 * 1024 * 1024 && host.numa_nodes >= 2 {
        "large_host_floor_met"
    } else {
        "advisory_or_small_host"
    }
    .to_owned()
}

fn current_epoch_days() -> Option<u32> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    u32::try_from(duration.as_secs() / 86_400).ok()
}

fn push_issue(
    issues: &mut Vec<TopologyRuntimeAdvisorIssue>,
    path: impl Into<String>,
    message: impl Into<String>,
) {
    issues.push(TopologyRuntimeAdvisorIssue {
        path: path.into(),
        message: message.into(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const REFERENCE_TIMESTAMP: &str = "2026-05-10T00:00:00Z";

    #[test]
    fn valid_manifest_renders_advisory_report() {
        let manifest = fixture_manifest();
        let report = validate_fixture(&manifest);

        assert!(report.valid, "{:?}", report.errors);
        assert!(report.advisory_only);
        assert_eq!(report.product_evidence_claim, "none");
        assert_eq!(report.release_gate_effect, "advisory_only");
        assert_eq!(report.outcome, "pass");
        assert_eq!(report.workload_count, 2);

        let markdown = render_topology_runtime_advisor_markdown(&report);
        assert!(markdown.contains("Topology Runtime Advisor Report"));
        assert!(markdown.contains("Product evidence claim: `none`"));

        let json = serde_json::to_string_pretty(&report).expect("serialize report");
        assert!(json.contains("\"product_evidence_claim\": \"none\""));
    }

    /// bd-rchk0.212.7 - exact-output snapshot for the primary topology
    /// runtime advisor markdown consumed by operator handoffs.
    ///
    /// The validation tests prove advisory-only semantics and rejection
    /// behavior. This snapshot pins the rendered host/FUSE classification,
    /// command transcript paths, advisory wording, and empty Issues section.
    #[test]
    fn render_topology_runtime_advisor_markdown_fixture_snapshot() {
        let manifest = fixture_manifest();
        let report = validate_fixture(&manifest);
        let markdown = render_topology_runtime_advisor_markdown(&report);

        insta::assert_snapshot!("render_topology_runtime_advisor_markdown_fixture", markdown);
    }

    #[test]
    fn checked_in_sample_manifest_validates() {
        let manifest: TopologyRuntimeAdvisorManifest = serde_json::from_str(include_str!(
            "../../../docs/topology-runtime-advisor-manifest.json"
        ))
        .expect("checked-in topology advisor sample must parse");
        let report = validate_fixture(&manifest);

        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(
            manifest.manifest_path,
            DEFAULT_TOPOLOGY_RUNTIME_ADVISOR_MANIFEST
        );
        assert_eq!(report.product_evidence_claim, "none");
        assert_eq!(report.release_gate_effect, "advisory_only");
    }

    #[test]
    fn duplicate_workload_ids_are_rejected() {
        let mut manifest = fixture_manifest();
        manifest.workload_shapes[1].workload_id = manifest.workload_shapes[0].workload_id.clone();

        let report = validate_fixture(&manifest);

        assert!(!report.valid);
        assert_issue(&report, "workload_shapes[1].workload_id");
    }

    #[test]
    fn missing_host_topology_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.host_topology.cpu_count = 0;
        manifest.host_topology.numa_nodes = 0;
        manifest.host_topology.ram_bytes = 0;

        let report = validate_fixture(&manifest);

        assert!(!report.valid);
        assert_issue(&report, "host_topology.cpu_count");
        assert_issue(&report, "host_topology.numa_nodes");
        assert_issue(&report, "host_topology.ram_bytes");
    }

    #[test]
    fn stale_and_future_timestamps_are_rejected() {
        let mut stale = fixture_manifest();
        stale.generated_at = "2026-04-01T00:00:00Z".to_owned();
        stale.expires_at = "2026-04-02T00:00:00Z".to_owned();
        let stale_report = validate_fixture(&stale);
        assert!(!stale_report.valid);
        assert_issue(&stale_report, "generated_at");
        assert_issue(&stale_report, "expires_at");

        let mut future = fixture_manifest();
        future.generated_at = "2030-01-01T00:00:00Z".to_owned();
        future.expires_at = "2030-01-02T00:00:00Z".to_owned();
        let future_report = validate_fixture(&future);
        assert!(!future_report.valid);
        assert_issue(&future_report, "generated_at");
    }

    #[test]
    fn unsafe_artifact_paths_are_rejected() {
        let mut manifest = fixture_manifest();
        manifest.artifact_paths = vec![
            "/tmp/unsafe/report.json".to_owned(),
            "../escape/report.md".to_owned(),
        ];

        let report = validate_fixture(&manifest);

        assert!(!report.valid);
        assert_issue(&report, "artifact_paths[0]");
        assert_issue(&report, "artifact_paths[1]");
    }

    #[test]
    fn impossible_resource_caps_are_rejected() {
        let mut manifest = fixture_manifest();
        manifest.resource_caps.max_threads = 10_000;
        manifest.resource_caps.max_memory_bytes = 512 * 1024 * 1024 * 1024;

        let report = validate_fixture(&manifest);

        assert!(!report.valid);
        assert_issue(&report, "resource_caps.max_threads");
        assert_issue(&report, "resource_caps.max_memory_bytes");
    }

    #[test]
    fn accepted_large_host_claims_are_rejected() {
        let mut manifest = fixture_manifest();
        manifest.product_evidence_claim = "accepted_large_host".to_owned();
        manifest.release_gate_effect = "strengthens_public_claim".to_owned();
        manifest.fuse_capability.detail =
            "accepted_large_host proof is not allowed here".to_owned();
        manifest.runtime_candidates[0].reason =
            "accepted_large_host promotion is forbidden".to_owned();
        manifest.artifact_paths[0] =
            "artifacts/topology-advisor/accepted_large_host/report.json".to_owned();

        let report = validate_fixture(&manifest);

        assert!(!report.valid);
        assert!(!report.advisory_only);
        assert_issue(&report, "product_evidence_claim");
        assert_issue(&report, "release_gate_effect");
        assert_issue(&report, "fuse_capability.detail");
        assert_issue(&report, "runtime_candidates[0].reason");
        assert_issue(&report, "artifact_paths[0]");
    }

    #[test]
    fn structured_log_preserves_required_fields() {
        let manifest = fixture_manifest();
        let report = validate_fixture(&manifest);
        let log = render_topology_runtime_advisor_structured_log(&report);

        assert!(log.contains("topology_runtime_advisor_validation_result"));
        assert!(log.contains("\"operation_id\":\"topology-advisor-op-001\""));
        assert!(log.contains("\"scenario_id\":\"topology-advisor-valid\""));
        assert!(log.contains("\"outcome\":\"pass\""));
        assert!(log.contains("\"advisory_only\":true"));
        assert!(log.contains("\"manifest_path\":\"artifacts/topology-advisor/manifest.json\""));
        assert!(log.contains("\"artifact_root\":\"artifacts/topology-advisor\""));
        assert!(log.contains("\"error_class\":null"));
    }

    #[test]
    fn small_host_downgrades_per_core_candidate() {
        let mut manifest = fixture_manifest();
        manifest.host_topology.cpu_count = 16;
        manifest.host_topology.numa_nodes = 1;
        manifest.host_topology.ram_bytes = 32 * 1024 * 1024 * 1024;
        manifest.resource_caps.max_threads = 64;
        manifest.resource_caps.max_memory_bytes = 16 * 1024 * 1024 * 1024;

        let report = score_fixture(&manifest);

        assert!(report.valid, "{:?}", report.errors);
        assert_ne!(report.recommendation.as_deref(), Some("per_core"));
        assert_candidate_rejected(&report, "per_core", "requires at least 64 CPUs");
        assert_ledger(&report, "small_host_downgrade");
    }

    #[test]
    fn read_heavy_sharded_workload_favors_per_core_on_large_host() {
        let mut manifest = fixture_manifest();
        manifest.workload_shapes = vec![TopologyWorkloadShape {
            workload_id: "wide-read-fanout".to_owned(),
            hot_inode_concentration: 0.10,
            directory_fanout: 8_192,
            read_ratio: 0.90,
            write_ratio: 0.05,
            fsyncs_per_second: 1.0,
            expected_dirty_bytes: 64 * 1024 * 1024,
            queue_depth: 256,
        }];

        let report = score_fixture(&manifest);

        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.recommendation.as_deref(), Some("per_core"));
        assert_candidate_not_rejected(&report, "per_core");
        assert_ledger(&report, "sharded_read_fanout");
    }

    #[test]
    fn hot_inode_imbalance_favors_managed_over_per_core() {
        let manifest = fixture_manifest();

        let report = score_fixture(&manifest);

        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.recommendation.as_deref(), Some("managed"));
        assert_candidate_score_above(&report, "managed", "per_core");
        assert_ledger(&report, "hot_inode_imbalance");
    }

    /// bd-rchk0.212.6 - exact-output snapshot for the advisory scoring
    /// markdown consumed by topology-runtime operator handoffs.
    ///
    /// The scoring tests above prove the selected candidate and ledger signals.
    /// This snapshot pins the rendered recommendation, confidence tier,
    /// candidate ordering, rejection fields, and loss/risk rationale.
    #[test]
    fn render_topology_runtime_advisor_score_markdown_fixture_snapshot() {
        let manifest = fixture_manifest();
        let report = score_fixture(&manifest);
        let markdown = render_topology_runtime_advisor_score_markdown(&report);

        insta::assert_snapshot!(
            "render_topology_runtime_advisor_score_markdown_fixture",
            markdown
        );
    }

    #[test]
    fn writeback_pressure_requires_backpressure_thresholds() {
        let mut manifest = fixture_manifest();
        manifest.workload_shapes = vec![TopologyWorkloadShape {
            workload_id: "dirty-writeback".to_owned(),
            hot_inode_concentration: 0.70,
            directory_fanout: 256,
            read_ratio: 0.10,
            write_ratio: 0.80,
            fsyncs_per_second: 15.0,
            expected_dirty_bytes: 80 * 1024 * 1024 * 1024,
            queue_depth: 128,
        }];

        let report = score_fixture(&manifest);

        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.recommendation.as_deref(), Some("managed"));
        assert_ledger(&report, "writeback_backpressure");
        let managed = candidate(&report, "managed");
        assert!(
            managed
                .rationale
                .iter()
                .any(|reason| reason.contains("backpressure thresholds")),
            "{:?}",
            managed.rationale
        );
    }

    #[test]
    fn malformed_numeric_inputs_make_scoring_invalid() {
        let mut manifest = fixture_manifest();
        manifest.workload_shapes[0].read_ratio = f64::NAN;
        manifest.workload_shapes[0].fsyncs_per_second = -1.0;

        let report = score_fixture(&manifest);

        assert!(!report.valid);
        assert!(report.recommendation.is_none());
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("read_ratio"))
        );
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("fsyncs_per_second"))
        );
    }

    #[test]
    fn scoring_tie_breaks_are_deterministic() {
        let mut scores = vec![
            score_for_test("per_core", 80),
            score_for_test("managed", 80),
            score_for_test("standard", 80),
        ];

        sort_candidate_scores_for_recommendation(&mut scores);

        assert_eq!(scores[0].runtime_candidate, "standard");
        assert_eq!(scores[1].runtime_candidate, "managed");
        assert_eq!(scores[2].runtime_candidate, "per_core");
        assert_eq!(
            confidence_tier(&scores),
            TopologyRuntimeAdvisorConfidenceTier::Low
        );
    }

    #[test]
    fn scoring_structured_log_preserves_required_fields() {
        let manifest = fixture_manifest();
        let report = score_fixture(&manifest);
        let log = render_topology_runtime_advisor_score_structured_log(&report);

        assert!(log.contains("topology_runtime_advisor_score_candidate"));
        assert!(log.contains("\"operation_id\":\"topology-advisor-op-001\""));
        assert!(log.contains("\"scenario_id\":\"topology-advisor-valid\""));
        assert!(log.contains("\"runtime_candidate\":\"managed\""));
        assert!(log.contains("\"score\":"));
        assert!(log.contains("\"confidence_tier\":\""));
        assert!(log.contains("\"rejection_reason\":"));
        assert!(log.contains("\"advisory_only\":true"));
        assert!(log.contains("\"product_evidence_claim\":\"none\""));
        assert!(log.contains("\"release_claim_state\":\"not_product_evidence\""));
        assert!(!log.contains("accepted_large_host"));
    }

    #[test]
    fn operator_docs_preserve_advisory_topology_boundary() {
        let docs = include_str!("../../../docs/mount-runtime-modes.md");
        for required in [
            "validate-topology-runtime-advisor",
            "score-topology-runtime-advisor",
            "docs/topology-runtime-advisor-manifest.json",
            "advisory_only",
            "product_evidence_claim=none",
            "release_gate_effect=advisory_only",
            "bd-rchk0.53.8",
            "FFS_SWARM_WORKLOAD_REAL_RUN_ACK",
            "swarm-workload-may-use-permissioned-large-host",
            "XFSTESTS_REAL_RUN_ACK",
            "Forbidden Promotions",
            "High imbalance",
            "Low NUMA visibility",
            "Missing FUSE capability",
            "Stale RCH worker fingerprint",
            "Overloaded artifact root",
        ] {
            assert!(docs.contains(required), "missing docs phrase: {required}");
        }

        let normalized = docs.to_ascii_lowercase();
        for forbidden in [
            "topology advisor validates swarm.responsiveness",
            "topology advisor validates xfstests",
            "topology advisor validates adaptive_runtime",
            "topology advisor produces accepted_large_host",
            "topology advisor upgrades public readiness",
            "advisory report validates swarm.responsiveness",
            "advisory reports validate swarm.responsiveness",
            "product_evidence_claim=product_pass_fail",
            "release_gate_effect=accepted_large_host",
            "release_gate_effect=product_pass",
        ] {
            assert!(
                !normalized.contains(forbidden),
                "docs contain forbidden promotion wording: {forbidden}"
            );
        }
    }

    fn validate_fixture(manifest: &TopologyRuntimeAdvisorManifest) -> TopologyRuntimeAdvisorReport {
        validate_topology_runtime_advisor_manifest_with_config(
            manifest,
            &TopologyRuntimeAdvisorValidationConfig {
                reference_epoch_days: parse_manifest_timestamp_epoch_days(REFERENCE_TIMESTAMP),
                max_age_days: 14,
            },
        )
    }

    fn score_fixture(
        manifest: &TopologyRuntimeAdvisorManifest,
    ) -> TopologyRuntimeAdvisorScoringReport {
        score_topology_runtime_advisor_manifest_with_config(
            manifest,
            &TopologyRuntimeAdvisorValidationConfig {
                reference_epoch_days: parse_manifest_timestamp_epoch_days(REFERENCE_TIMESTAMP),
                max_age_days: 14,
            },
        )
    }

    fn assert_issue(report: &TopologyRuntimeAdvisorReport, path: &str) {
        assert!(
            report.issues.iter().any(|issue| issue.path == path),
            "{path} missing from {:?}",
            report.issues
        );
    }

    fn assert_candidate_rejected(
        report: &TopologyRuntimeAdvisorScoringReport,
        runtime_candidate: &str,
        expected_reason: &str,
    ) {
        let candidate = candidate(report, runtime_candidate);
        let rejection = candidate
            .rejection_reason
            .as_deref()
            .expect("candidate should be rejected");
        assert!(
            rejection.contains(expected_reason),
            "{expected_reason} missing from {rejection}"
        );
    }

    fn assert_candidate_not_rejected(
        report: &TopologyRuntimeAdvisorScoringReport,
        runtime_candidate: &str,
    ) {
        assert!(
            candidate(report, runtime_candidate)
                .rejection_reason
                .is_none(),
            "{runtime_candidate} should not be rejected"
        );
    }

    fn assert_candidate_score_above(
        report: &TopologyRuntimeAdvisorScoringReport,
        higher: &str,
        lower: &str,
    ) {
        assert!(
            candidate(report, higher).score > candidate(report, lower).score,
            "{higher} should score above {lower}: {:?}",
            report.candidate_scores
        );
    }

    fn assert_ledger(report: &TopologyRuntimeAdvisorScoringReport, signal: &str) {
        assert!(
            report
                .loss_risk_ledger
                .iter()
                .any(|entry| entry.signal == signal),
            "{signal} missing from {:?}",
            report.loss_risk_ledger
        );
    }

    fn candidate<'a>(
        report: &'a TopologyRuntimeAdvisorScoringReport,
        runtime_candidate: &str,
    ) -> &'a TopologyRuntimeAdvisorCandidateScore {
        report
            .candidate_scores
            .iter()
            .find(|candidate| candidate.runtime_candidate == runtime_candidate)
            .expect("candidate score should exist")
    }

    fn score_for_test(runtime_candidate: &str, score: i32) -> TopologyRuntimeAdvisorCandidateScore {
        TopologyRuntimeAdvisorCandidateScore {
            runtime_candidate: runtime_candidate.to_owned(),
            score,
            confidence_tier: "low".to_owned(),
            rejection_reason: None,
            rationale: Vec::new(),
        }
    }

    fn fixture_manifest() -> TopologyRuntimeAdvisorManifest {
        TopologyRuntimeAdvisorManifest {
            manifest_version: TOPOLOGY_RUNTIME_ADVISOR_MANIFEST_VERSION,
            operation_id: "topology-advisor-op-001".to_owned(),
            scenario_id: "topology-advisor-valid".to_owned(),
            source_bead: "bd-rchk0.212.1".to_owned(),
            real_campaign_bead: "bd-rchk0.53.8".to_owned(),
            generated_at: "2026-05-09T00:00:00Z".to_owned(),
            expires_at: "2026-05-16T00:00:00Z".to_owned(),
            manifest_path: "artifacts/topology-advisor/manifest.json".to_owned(),
            artifact_root: "artifacts/topology-advisor".to_owned(),
            host_topology: TopologyHostTopology {
                cpu_count: 64,
                numa_nodes: 2,
                ram_bytes: 256 * 1024 * 1024 * 1024,
                storage_profile: TopologyStorageProfile::LocalNvme,
            },
            fuse_capability: TopologyFuseCapability {
                state: TopologyFuseCapabilityState::Available,
                detail: "capability probe available in dry-run fixture".to_owned(),
            },
            rch_worker_identity: Some("rch-worker-large-host-dry-run".to_owned()),
            resource_caps: TopologyResourceCaps {
                max_duration_secs: 900,
                max_threads: 256,
                max_memory_bytes: 128 * 1024 * 1024 * 1024,
                max_temp_bytes: 16 * 1024 * 1024 * 1024,
                max_queue_depth: 1024,
            },
            runtime_candidates: vec![
                TopologyRuntimeCandidate {
                    mode: TopologyRuntimeMode::Standard,
                    enabled: true,
                    reason: "baseline candidate".to_owned(),
                },
                TopologyRuntimeCandidate {
                    mode: TopologyRuntimeMode::Managed,
                    enabled: true,
                    reason: "backpressure candidate".to_owned(),
                },
                TopologyRuntimeCandidate {
                    mode: TopologyRuntimeMode::PerCore,
                    enabled: true,
                    reason: "large-host per-core candidate".to_owned(),
                },
            ],
            workload_shapes: vec![
                TopologyWorkloadShape {
                    workload_id: "hot-inode-writeback".to_owned(),
                    hot_inode_concentration: 0.82,
                    directory_fanout: 64,
                    read_ratio: 0.25,
                    write_ratio: 0.65,
                    fsyncs_per_second: 12.0,
                    expected_dirty_bytes: 512 * 1024 * 1024,
                    queue_depth: 128,
                },
                TopologyWorkloadShape {
                    workload_id: "sharded-read-heavy".to_owned(),
                    hot_inode_concentration: 0.12,
                    directory_fanout: 4096,
                    read_ratio: 0.85,
                    write_ratio: 0.10,
                    fsyncs_per_second: 2.0,
                    expected_dirty_bytes: 64 * 1024 * 1024,
                    queue_depth: 64,
                },
            ],
            artifact_paths: vec![
                "artifacts/topology-advisor/report.json".to_owned(),
                "artifacts/topology-advisor/summary.md".to_owned(),
                "artifacts/topology-advisor/structured.jsonl".to_owned(),
            ],
            command_transcript: TopologyCommandTranscript {
                invocation: "ffs-harness validate-topology-runtime-advisor --manifest artifacts/topology-advisor/manifest.json".to_owned(),
                stdout_path: "artifacts/topology-advisor/stdout.log".to_owned(),
                stderr_path: "artifacts/topology-advisor/stderr.log".to_owned(),
                structured_log_path: "artifacts/topology-advisor/structured.jsonl".to_owned(),
                report_path: "artifacts/topology-advisor/report.json".to_owned(),
                summary_path: "artifacts/topology-advisor/summary.md".to_owned(),
            },
            product_evidence_claim: TOPOLOGY_RUNTIME_ADVISOR_PRODUCT_EVIDENCE_CLAIM.to_owned(),
            release_gate_effect: TOPOLOGY_RUNTIME_ADVISOR_RELEASE_GATE_EFFECT.to_owned(),
        }
    }
}
