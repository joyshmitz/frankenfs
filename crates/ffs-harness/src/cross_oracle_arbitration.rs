#![allow(clippy::module_name_repetitions)]

//! Cross-oracle disagreement arbitration for `bd-zj57e`.
//!
//! This validator does not choose filesystem truth by majority vote. It keeps
//! multiple proof lanes honest by preserving conflicting evidence, routing
//! ownership, and forcing user-facing claims to fail closed while unresolved.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub const CROSS_ORACLE_ARBITRATION_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_CROSS_ORACLE_ARBITRATION_REPORT: &str =
    "artifacts/e2e/cross_oracle_arbitration/report.json";

const BEAD_ID: &str = "bd-zj57e";
const RUNNER_PATH: &str = "scripts/e2e/ffs_cross_oracle_arbitration_e2e.sh";

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "arbitration_id",
    "source_oracle_ids",
    "artifact_hashes",
    "normalized_observation_summary",
    "classification",
    "confidence",
    "rationale",
    "release_gate_impact",
    "follow_up_bead_id",
    "output_path",
    "reproduction_command",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossOracleArbitrationReport {
    pub schema_version: u32,
    pub bead_id: String,
    pub generated_at: String,
    pub runner: String,
    pub arbitrations: Vec<CrossOracleArbitration>,
    pub artifact_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossOracleArbitration {
    pub arbitration_id: String,
    pub status: CrossOracleConflictStatus,
    pub classification: CrossOracleDisagreementCategory,
    pub source_oracles: Vec<CrossOracleEvidence>,
    pub normalized_observation_summary: String,
    pub confidence: CrossOracleConfidence,
    pub confidence_rationale: String,
    pub release_gate_impact: CrossOracleReleaseGateImpact,
    #[serde(default)]
    pub blocked_public_claims: Vec<CrossOraclePublicClaim>,
    pub owning_bead: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follow_up_bead_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub non_goal_reason: Option<String>,
    pub output_path: String,
    pub reproduction_command: String,
    #[serde(default)]
    pub artifact_paths: Vec<String>,
    #[serde(default)]
    pub log_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossOracleEvidence {
    pub oracle_id: String,
    pub oracle_kind: CrossOracleKind,
    pub status: CrossOracleEvidenceStatus,
    pub artifact_path: String,
    pub artifact_sha256: String,
    pub observed_at: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossOracleReleaseGateImpact {
    pub effect: CrossOracleReleaseGateEffect,
    #[serde(default)]
    pub gates: Vec<String>,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossOracleArbitrationValidationReport {
    pub schema_version: u32,
    pub bead_id: String,
    pub valid: bool,
    pub arbitration_count: usize,
    pub fail_closed_count: usize,
    pub category_counts: BTreeMap<String, usize>,
    pub source_kind_counts: BTreeMap<String, usize>,
    pub blocked_public_claims: Vec<String>,
    pub summaries: Vec<CrossOracleArbitrationSummary>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossOracleArbitrationSummary {
    pub arbitration_id: String,
    pub status: String,
    pub classification: String,
    pub source_oracle_ids: Vec<String>,
    pub controlling_artifacts: Vec<String>,
    pub blocked_public_claims: Vec<String>,
    pub release_gate_impact: String,
    pub owning_bead: String,
    pub remediation_id: Option<String>,
    pub follow_up_bead_id: Option<String>,
    pub non_goal_reason: Option<String>,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossOracleDisagreementCategory {
    ModelBug,
    KernelBaselineIssue,
    #[serde(rename = "frankenfs_product_bug")]
    FrankenFsProductBug,
    HarnessBug,
    FixtureBug,
    UnsupportedScope,
    HostCapabilityGap,
    RepairOracleGap,
    InconclusiveConflict,
}

impl CrossOracleDisagreementCategory {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ModelBug => "model_bug",
            Self::KernelBaselineIssue => "kernel_baseline_issue",
            Self::FrankenFsProductBug => "frankenfs_product_bug",
            Self::HarnessBug => "harness_bug",
            Self::FixtureBug => "fixture_bug",
            Self::UnsupportedScope => "unsupported_scope",
            Self::HostCapabilityGap => "host_capability_gap",
            Self::RepairOracleGap => "repair_oracle_gap",
            Self::InconclusiveConflict => "inconclusive_conflict",
        }
    }

    #[must_use]
    pub const fn accepts_stale_or_missing_evidence(self) -> bool {
        matches!(
            self,
            Self::KernelBaselineIssue
                | Self::HarnessBug
                | Self::FixtureBug
                | Self::HostCapabilityGap
                | Self::RepairOracleGap
                | Self::InconclusiveConflict
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossOracleKind {
    InvariantTrace,
    MountedDifferential,
    RepairConfidence,
    CrashReplaySurvivor,
    ReleaseGateStatus,
}

impl CrossOracleKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::InvariantTrace => "invariant_trace",
            Self::MountedDifferential => "mounted_differential",
            Self::RepairConfidence => "repair_confidence",
            Self::CrashReplaySurvivor => "crash_replay_survivor",
            Self::ReleaseGateStatus => "release_gate_status",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossOracleEvidenceStatus {
    Pass,
    Fail,
    Skip,
    Error,
    Stale,
    Missing,
}

impl CrossOracleEvidenceStatus {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Skip => "skip",
            Self::Error => "error",
            Self::Stale => "stale",
            Self::Missing => "missing",
        }
    }

    #[must_use]
    pub const fn is_stale_or_missing(self) -> bool {
        matches!(self, Self::Stale | Self::Missing)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossOracleConflictStatus {
    Resolved,
    Unresolved,
    ScopedOut,
}

impl CrossOracleConflictStatus {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::Unresolved => "unresolved",
            Self::ScopedOut => "scoped_out",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossOracleConfidence {
    Low,
    Medium,
    High,
}

impl CrossOracleConfidence {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossOracleReleaseGateEffect {
    FailClosed,
    Downgrade,
    NoImpact,
}

impl CrossOracleReleaseGateEffect {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::Downgrade => "downgrade",
            Self::NoImpact => "no_impact",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossOraclePublicClaim {
    MountedWrites,
    MutatingRepair,
    WritebackCache,
    BackgroundScrubMutation,
    DataIntegrity,
    ProofBundleCompleteness,
    PerformanceBaseline,
}

impl CrossOraclePublicClaim {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MountedWrites => "mounted_writes",
            Self::MutatingRepair => "mutating_repair",
            Self::WritebackCache => "writeback_cache",
            Self::BackgroundScrubMutation => "background_scrub_mutation",
            Self::DataIntegrity => "data_integrity",
            Self::ProofBundleCompleteness => "proof_bundle_completeness",
            Self::PerformanceBaseline => "performance_baseline",
        }
    }

    #[must_use]
    pub const fn is_high_risk(self) -> bool {
        matches!(
            self,
            Self::MountedWrites
                | Self::MutatingRepair
                | Self::WritebackCache
                | Self::BackgroundScrubMutation
                | Self::DataIntegrity
        )
    }
}

pub fn load_cross_oracle_arbitration_report(path: &Path) -> Result<CrossOracleArbitrationReport> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read cross-oracle report {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("invalid cross-oracle report {}", path.display()))
}

#[must_use]
pub fn validate_cross_oracle_arbitration_report(
    report: &CrossOracleArbitrationReport,
) -> CrossOracleArbitrationValidationReport {
    let mut errors = Vec::new();
    let mut category_counts = BTreeMap::new();
    let mut source_kind_counts = BTreeMap::new();
    let mut blocked_public_claims = BTreeSet::new();
    let mut summaries = Vec::new();
    let mut seen_arbitrations = BTreeSet::new();
    let mut fail_closed_count = 0;

    validate_report_header(report, &mut errors);

    for arbitration in &report.arbitrations {
        *category_counts
            .entry(arbitration.classification.label().to_owned())
            .or_insert(0) += 1;
        if arbitration.release_gate_impact.effect == CrossOracleReleaseGateEffect::FailClosed {
            fail_closed_count += 1;
        }
        for claim in &arbitration.blocked_public_claims {
            blocked_public_claims.insert(claim.label().to_owned());
        }
        validate_arbitration(
            arbitration,
            report,
            &mut seen_arbitrations,
            &mut source_kind_counts,
            &mut errors,
        );
        summaries.push(summarize_arbitration(arbitration));
    }

    CrossOracleArbitrationValidationReport {
        schema_version: CROSS_ORACLE_ARBITRATION_SCHEMA_VERSION,
        bead_id: BEAD_ID.to_owned(),
        valid: errors.is_empty(),
        arbitration_count: report.arbitrations.len(),
        fail_closed_count,
        category_counts,
        source_kind_counts,
        blocked_public_claims: blocked_public_claims.into_iter().collect(),
        summaries,
        errors,
    }
}

pub fn fail_on_cross_oracle_arbitration_errors(
    report: &CrossOracleArbitrationValidationReport,
) -> Result<()> {
    if !report.valid {
        bail!(
            "cross-oracle arbitration report failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        );
    }
    Ok(())
}

#[must_use]
pub fn render_cross_oracle_arbitration_markdown(
    report: &CrossOracleArbitrationValidationReport,
) -> String {
    let mut out = String::new();
    out.push_str("# Cross-Oracle Arbitration Validation\n\n");
    let _ = writeln!(out, "- Valid: `{}`", report.valid);
    let _ = writeln!(out, "- Arbitrations: `{}`", report.arbitration_count);
    let _ = writeln!(out, "- Fail-closed impacts: `{}`", report.fail_closed_count);

    if !report.blocked_public_claims.is_empty() {
        out.push_str("\n## Blocked Public Claims\n\n");
        for claim in &report.blocked_public_claims {
            let _ = writeln!(out, "- `{claim}`");
        }
    }

    out.push_str("\n## Arbitrations\n\n");
    for summary in &report.summaries {
        let _ = writeln!(
            out,
            "### `{}`: `{}` / `{}`",
            summary.arbitration_id, summary.classification, summary.status
        );
        let _ = writeln!(
            out,
            "- Release-gate impact: `{}`",
            summary.release_gate_impact
        );
        let _ = writeln!(
            out,
            "- Source oracles: `{}`",
            summary.source_oracle_ids.join(", ")
        );
        let _ = writeln!(
            out,
            "- Controlling artifacts: `{}`",
            summary.controlling_artifacts.join(", ")
        );
        if !summary.blocked_public_claims.is_empty() {
            let _ = writeln!(
                out,
                "- Blocked claims: `{}`",
                summary.blocked_public_claims.join(", ")
            );
        }
        if let Some(follow_up) = &summary.follow_up_bead_id {
            let _ = writeln!(out, "- Follow-up bead: `{follow_up}`");
        }
        if let Some(remediation) = &summary.remediation_id {
            let _ = writeln!(out, "- Remediation: `{remediation}`");
        }
        if let Some(non_goal) = &summary.non_goal_reason {
            let _ = writeln!(out, "- Non-goal: {non_goal}");
        }
        let _ = writeln!(out, "- Reproduce: `{}`", summary.reproduction_command);
        out.push('\n');
    }

    if !report.errors.is_empty() {
        out.push_str("## Errors\n\n");
        for error in &report.errors {
            let _ = writeln!(out, "- {error}");
        }
    }

    out
}

fn validate_report_header(report: &CrossOracleArbitrationReport, errors: &mut Vec<String>) {
    if report.schema_version != CROSS_ORACLE_ARBITRATION_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version must be {}, got {}",
            CROSS_ORACLE_ARBITRATION_SCHEMA_VERSION, report.schema_version
        ));
    }
    if report.bead_id != BEAD_ID {
        errors.push(format!("bead_id must be {BEAD_ID}, got {}", report.bead_id));
    }
    if report.generated_at.trim().is_empty() {
        errors.push("generated_at is required".to_owned());
    }
    if report.runner != RUNNER_PATH {
        errors.push(format!(
            "runner must be {RUNNER_PATH}, got {}",
            report.runner
        ));
    }
    if report.arbitrations.is_empty() {
        errors.push("at least one arbitration is required".to_owned());
    }
}

fn validate_arbitration(
    arbitration: &CrossOracleArbitration,
    report: &CrossOracleArbitrationReport,
    seen_arbitrations: &mut BTreeSet<String>,
    source_kind_counts: &mut BTreeMap<String, usize>,
    errors: &mut Vec<String>,
) {
    if arbitration.arbitration_id.trim().is_empty() {
        errors.push("arbitration_id is required".to_owned());
    } else if !seen_arbitrations.insert(arbitration.arbitration_id.clone()) {
        errors.push(format!(
            "duplicate arbitration_id {}",
            arbitration.arbitration_id
        ));
    }

    if arbitration.source_oracles.len() < 2 {
        errors.push(format!(
            "{} must include at least two source oracles",
            arbitration.arbitration_id
        ));
    }

    validate_source_oracles(arbitration, source_kind_counts, errors);
    validate_arbitration_shape(arbitration, errors);
    validate_release_gate_impact(arbitration, errors);
    validate_log_fields(arbitration, errors);
    validate_artifact_coverage(arbitration, report, errors);
}

fn validate_source_oracles(
    arbitration: &CrossOracleArbitration,
    source_kind_counts: &mut BTreeMap<String, usize>,
    errors: &mut Vec<String>,
) {
    let mut seen_source_ids = BTreeSet::new();
    let mut has_stale_or_missing = false;

    for source in &arbitration.source_oracles {
        if source.oracle_id.trim().is_empty() {
            errors.push(format!(
                "{} has source oracle with empty oracle_id",
                arbitration.arbitration_id
            ));
        } else if !seen_source_ids.insert(source.oracle_id.clone()) {
            errors.push(format!(
                "{} has duplicate source oracle {}",
                arbitration.arbitration_id, source.oracle_id
            ));
        }

        *source_kind_counts
            .entry(source.oracle_kind.label().to_owned())
            .or_insert(0) += 1;

        if source.summary.trim().is_empty() {
            errors.push(format!(
                "{} source {} missing summary",
                arbitration.arbitration_id, source.oracle_id
            ));
        }
        if source.observed_at.trim().is_empty() {
            errors.push(format!(
                "{} source {} missing observed_at",
                arbitration.arbitration_id, source.oracle_id
            ));
        }
        if source.status == CrossOracleEvidenceStatus::Missing {
            if source.artifact_sha256 != "missing" {
                errors.push(format!(
                    "{} source {} missing evidence must use artifact_sha256=missing",
                    arbitration.arbitration_id, source.oracle_id
                ));
            }
        } else if !is_sha256_hex(&source.artifact_sha256) {
            errors.push(format!(
                "{} source {} artifact_sha256 must be 64 lowercase hex chars",
                arbitration.arbitration_id, source.oracle_id
            ));
        }
        if source.artifact_path.trim().is_empty() {
            errors.push(format!(
                "{} source {} missing artifact_path",
                arbitration.arbitration_id, source.oracle_id
            ));
        }
        has_stale_or_missing |= source.status.is_stale_or_missing();
    }

    if has_stale_or_missing
        && !arbitration
            .classification
            .accepts_stale_or_missing_evidence()
    {
        errors.push(format!(
            "{} uses stale/missing oracle evidence but classification {} cannot absorb evidence gaps",
            arbitration.arbitration_id,
            arbitration.classification.label()
        ));
    }
}

fn validate_arbitration_shape(arbitration: &CrossOracleArbitration, errors: &mut Vec<String>) {
    if arbitration.normalized_observation_summary.trim().is_empty() {
        errors.push(format!(
            "{} missing normalized_observation_summary",
            arbitration.arbitration_id
        ));
    }
    if arbitration.confidence_rationale.trim().is_empty() {
        errors.push(format!(
            "{} missing confidence_rationale",
            arbitration.arbitration_id
        ));
    }
    if arbitration.owning_bead.trim().is_empty() {
        errors.push(format!(
            "{} missing owning_bead",
            arbitration.arbitration_id
        ));
    }
    if arbitration.output_path.trim().is_empty() {
        errors.push(format!(
            "{} missing output_path",
            arbitration.arbitration_id
        ));
    }
    if arbitration.reproduction_command.trim().is_empty() {
        errors.push(format!(
            "{} missing reproduction_command",
            arbitration.arbitration_id
        ));
    }
    if arbitration.status == CrossOracleConflictStatus::ScopedOut
        && arbitration
            .non_goal_reason
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
    {
        errors.push(format!(
            "{} scoped-out conflict requires non_goal_reason",
            arbitration.arbitration_id
        ));
    }
    if arbitration.status == CrossOracleConflictStatus::Unresolved
        && arbitration
            .follow_up_bead_id
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
        && arbitration
            .remediation_id
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
    {
        errors.push(format!(
            "{} unresolved conflict requires follow_up_bead_id or remediation_id",
            arbitration.arbitration_id
        ));
    }
}

fn validate_release_gate_impact(arbitration: &CrossOracleArbitration, errors: &mut Vec<String>) {
    if arbitration.release_gate_impact.rationale.trim().is_empty() {
        errors.push(format!(
            "{} missing release_gate_impact.rationale",
            arbitration.arbitration_id
        ));
    }
    if arbitration.release_gate_impact.effect != CrossOracleReleaseGateEffect::NoImpact
        && arbitration.release_gate_impact.gates.is_empty()
    {
        errors.push(format!(
            "{} release-gate impact requires at least one gate",
            arbitration.arbitration_id
        ));
    }
    if arbitration.release_gate_impact.effect == CrossOracleReleaseGateEffect::FailClosed
        && arbitration.blocked_public_claims.is_empty()
    {
        errors.push(format!(
            "{} fail-closed impact requires blocked_public_claims",
            arbitration.arbitration_id
        ));
    }

    let unresolved_high_risk = arbitration.status == CrossOracleConflictStatus::Unresolved
        && arbitration
            .blocked_public_claims
            .iter()
            .any(|claim| claim.is_high_risk());
    if unresolved_high_risk
        && arbitration.release_gate_impact.effect != CrossOracleReleaseGateEffect::FailClosed
    {
        errors.push(format!(
            "{} unresolved high-risk public claim must fail closed",
            arbitration.arbitration_id
        ));
    }
}

fn validate_log_fields(arbitration: &CrossOracleArbitration, errors: &mut Vec<String>) {
    let fields: BTreeSet<&str> = arbitration.log_fields.iter().map(String::as_str).collect();
    for required in REQUIRED_LOG_FIELDS {
        if !fields.contains(required) {
            errors.push(format!(
                "{} missing required log field {}",
                arbitration.arbitration_id, required
            ));
        }
    }
}

fn validate_artifact_coverage(
    arbitration: &CrossOracleArbitration,
    report: &CrossOracleArbitrationReport,
    errors: &mut Vec<String>,
) {
    let arbitration_artifacts: BTreeSet<&str> = arbitration
        .artifact_paths
        .iter()
        .map(String::as_str)
        .collect();
    let report_artifacts: BTreeSet<&str> =
        report.artifact_paths.iter().map(String::as_str).collect();

    if !arbitration_artifacts.contains(arbitration.output_path.as_str()) {
        errors.push(format!(
            "{} artifact_paths must include output_path {}",
            arbitration.arbitration_id, arbitration.output_path
        ));
    }
    for source in &arbitration.source_oracles {
        if source.status == CrossOracleEvidenceStatus::Missing {
            continue;
        }
        if !arbitration_artifacts.contains(source.artifact_path.as_str()) {
            errors.push(format!(
                "{} artifact_paths missing source artifact {}",
                arbitration.arbitration_id, source.artifact_path
            ));
        }
    }
    for artifact in &arbitration.artifact_paths {
        if !report_artifacts.contains(artifact.as_str()) {
            errors.push(format!(
                "{} report artifact_paths missing arbitration artifact {}",
                arbitration.arbitration_id, artifact
            ));
        }
    }
}

fn summarize_arbitration(arbitration: &CrossOracleArbitration) -> CrossOracleArbitrationSummary {
    CrossOracleArbitrationSummary {
        arbitration_id: arbitration.arbitration_id.clone(),
        status: arbitration.status.label().to_owned(),
        classification: arbitration.classification.label().to_owned(),
        source_oracle_ids: arbitration
            .source_oracles
            .iter()
            .map(|source| source.oracle_id.clone())
            .collect(),
        controlling_artifacts: arbitration
            .source_oracles
            .iter()
            .filter(|source| source.status != CrossOracleEvidenceStatus::Missing)
            .map(|source| source.artifact_path.clone())
            .collect(),
        blocked_public_claims: arbitration
            .blocked_public_claims
            .iter()
            .map(|claim| claim.label().to_owned())
            .collect(),
        release_gate_impact: arbitration.release_gate_impact.effect.label().to_owned(),
        owning_bead: arbitration.owning_bead.clone(),
        remediation_id: arbitration.remediation_id.clone(),
        follow_up_bead_id: arbitration.follow_up_bead_id.clone(),
        non_goal_reason: arbitration.non_goal_reason.clone(),
        reproduction_command: arbitration.reproduction_command.clone(),
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn source(
        oracle_id: &str,
        oracle_kind: CrossOracleKind,
        status: CrossOracleEvidenceStatus,
    ) -> CrossOracleEvidence {
        let artifact_sha256 = if status == CrossOracleEvidenceStatus::Missing {
            "missing".to_owned()
        } else if oracle_kind == CrossOracleKind::MountedDifferential {
            HASH_B.to_owned()
        } else {
            HASH_A.to_owned()
        };
        CrossOracleEvidence {
            oracle_id: oracle_id.to_owned(),
            oracle_kind,
            status,
            artifact_path: if status == CrossOracleEvidenceStatus::Missing {
                format!("missing://{oracle_id}")
            } else {
                format!("artifacts/oracles/{oracle_id}.json")
            },
            artifact_sha256,
            observed_at: "2026-05-03T00:00:00Z".to_owned(),
            summary: format!("{oracle_id} observed {status}", status = status.label()),
        }
    }

    fn arbitration(
        arbitration_id: &str,
        classification: CrossOracleDisagreementCategory,
        status: CrossOracleConflictStatus,
        source_oracles: Vec<CrossOracleEvidence>,
        blocked_public_claims: Vec<CrossOraclePublicClaim>,
        effect: CrossOracleReleaseGateEffect,
    ) -> CrossOracleArbitration {
        let output_path = format!("artifacts/cross_oracle/{arbitration_id}/arbitration.json");
        let mut artifact_paths = vec![output_path.clone()];
        artifact_paths.extend(
            source_oracles
                .iter()
                .filter(|source| source.status != CrossOracleEvidenceStatus::Missing)
                .map(|source| source.artifact_path.clone()),
        );
        CrossOracleArbitration {
            arbitration_id: arbitration_id.to_owned(),
            status,
            classification,
            source_oracles,
            normalized_observation_summary: format!(
                "{arbitration_id} normalized disagreement summary"
            ),
            confidence: CrossOracleConfidence::High,
            confidence_rationale: "two independent artifacts agree on routing".to_owned(),
            release_gate_impact: CrossOracleReleaseGateImpact {
                effect,
                gates: if effect == CrossOracleReleaseGateEffect::NoImpact {
                    Vec::new()
                } else {
                    vec!["mount.rw.ext4".to_owned(), "repair.rw.writeback".to_owned()]
                },
                rationale: "claim remains weaker until arbitration closes".to_owned(),
            },
            blocked_public_claims,
            owning_bead: BEAD_ID.to_owned(),
            remediation_id: Some("remediate_cross_oracle_conflict".to_owned()),
            follow_up_bead_id: if status == CrossOracleConflictStatus::Unresolved {
                Some(BEAD_ID.to_owned())
            } else {
                None
            },
            non_goal_reason: if status == CrossOracleConflictStatus::ScopedOut {
                Some("unsupported V1 scope is explicitly non-goal".to_owned())
            } else {
                None
            },
            output_path,
            reproduction_command: format!(
                "ffs-harness validate-cross-oracle-arbitration --report artifacts/cross_oracle/{arbitration_id}/report.json"
            ),
            artifact_paths,
            log_fields: REQUIRED_LOG_FIELDS
                .iter()
                .map(|field| (*field).to_owned())
                .collect(),
        }
    }

    fn model_bug_arbitration() -> CrossOracleArbitration {
        arbitration(
            "arb_model_bug",
            CrossOracleDisagreementCategory::ModelBug,
            CrossOracleConflictStatus::Resolved,
            vec![
                source(
                    "invariant_model",
                    CrossOracleKind::InvariantTrace,
                    CrossOracleEvidenceStatus::Fail,
                ),
                source(
                    "mounted_pass",
                    CrossOracleKind::MountedDifferential,
                    CrossOracleEvidenceStatus::Pass,
                ),
            ],
            vec![CrossOraclePublicClaim::ProofBundleCompleteness],
            CrossOracleReleaseGateEffect::Downgrade,
        )
    }

    fn kernel_baseline_issue_arbitration() -> CrossOracleArbitration {
        arbitration(
            "arb_kernel_baseline_issue",
            CrossOracleDisagreementCategory::KernelBaselineIssue,
            CrossOracleConflictStatus::Unresolved,
            vec![
                source(
                    "mounted_kernel",
                    CrossOracleKind::MountedDifferential,
                    CrossOracleEvidenceStatus::Stale,
                ),
                source(
                    "release_gate_kernel",
                    CrossOracleKind::ReleaseGateStatus,
                    CrossOracleEvidenceStatus::Fail,
                ),
            ],
            vec![CrossOraclePublicClaim::MountedWrites],
            CrossOracleReleaseGateEffect::FailClosed,
        )
    }

    fn product_bug_arbitration() -> CrossOracleArbitration {
        arbitration(
            "arb_frankenfs_product_bug",
            CrossOracleDisagreementCategory::FrankenFsProductBug,
            CrossOracleConflictStatus::Unresolved,
            vec![
                source(
                    "invariant_product",
                    CrossOracleKind::InvariantTrace,
                    CrossOracleEvidenceStatus::Fail,
                ),
                source(
                    "mounted_product",
                    CrossOracleKind::MountedDifferential,
                    CrossOracleEvidenceStatus::Fail,
                ),
                source(
                    "release_product",
                    CrossOracleKind::ReleaseGateStatus,
                    CrossOracleEvidenceStatus::Fail,
                ),
            ],
            vec![
                CrossOraclePublicClaim::MountedWrites,
                CrossOraclePublicClaim::DataIntegrity,
            ],
            CrossOracleReleaseGateEffect::FailClosed,
        )
    }

    fn harness_bug_arbitration() -> CrossOracleArbitration {
        arbitration(
            "arb_harness_bug",
            CrossOracleDisagreementCategory::HarnessBug,
            CrossOracleConflictStatus::Resolved,
            vec![
                source(
                    "crash_harness",
                    CrossOracleKind::CrashReplaySurvivor,
                    CrossOracleEvidenceStatus::Error,
                ),
                source(
                    "invariant_harness",
                    CrossOracleKind::InvariantTrace,
                    CrossOracleEvidenceStatus::Pass,
                ),
            ],
            vec![CrossOraclePublicClaim::ProofBundleCompleteness],
            CrossOracleReleaseGateEffect::Downgrade,
        )
    }

    fn fixture_bug_arbitration() -> CrossOracleArbitration {
        arbitration(
            "arb_fixture_bug",
            CrossOracleDisagreementCategory::FixtureBug,
            CrossOracleConflictStatus::Resolved,
            vec![
                source(
                    "mounted_fixture",
                    CrossOracleKind::MountedDifferential,
                    CrossOracleEvidenceStatus::Fail,
                ),
                source(
                    "crash_fixture",
                    CrossOracleKind::CrashReplaySurvivor,
                    CrossOracleEvidenceStatus::Pass,
                ),
            ],
            vec![CrossOraclePublicClaim::ProofBundleCompleteness],
            CrossOracleReleaseGateEffect::Downgrade,
        )
    }

    fn unsupported_scope_arbitration() -> CrossOracleArbitration {
        arbitration(
            "arb_unsupported_scope",
            CrossOracleDisagreementCategory::UnsupportedScope,
            CrossOracleConflictStatus::ScopedOut,
            vec![
                source(
                    "mounted_unsupported",
                    CrossOracleKind::MountedDifferential,
                    CrossOracleEvidenceStatus::Skip,
                ),
                source(
                    "release_unsupported",
                    CrossOracleKind::ReleaseGateStatus,
                    CrossOracleEvidenceStatus::Pass,
                ),
            ],
            vec![CrossOraclePublicClaim::WritebackCache],
            CrossOracleReleaseGateEffect::Downgrade,
        )
    }

    fn host_capability_gap_arbitration() -> CrossOracleArbitration {
        arbitration(
            "arb_host_capability_gap",
            CrossOracleDisagreementCategory::HostCapabilityGap,
            CrossOracleConflictStatus::Resolved,
            vec![
                source(
                    "mounted_host",
                    CrossOracleKind::MountedDifferential,
                    CrossOracleEvidenceStatus::Skip,
                ),
                source(
                    "release_host",
                    CrossOracleKind::ReleaseGateStatus,
                    CrossOracleEvidenceStatus::Pass,
                ),
            ],
            vec![CrossOraclePublicClaim::MountedWrites],
            CrossOracleReleaseGateEffect::Downgrade,
        )
    }

    fn repair_oracle_gap_arbitration() -> CrossOracleArbitration {
        arbitration(
            "arb_repair_oracle_gap",
            CrossOracleDisagreementCategory::RepairOracleGap,
            CrossOracleConflictStatus::Unresolved,
            vec![
                source(
                    "repair_missing",
                    CrossOracleKind::RepairConfidence,
                    CrossOracleEvidenceStatus::Missing,
                ),
                source(
                    "release_repair",
                    CrossOracleKind::ReleaseGateStatus,
                    CrossOracleEvidenceStatus::Fail,
                ),
            ],
            vec![
                CrossOraclePublicClaim::MutatingRepair,
                CrossOraclePublicClaim::BackgroundScrubMutation,
            ],
            CrossOracleReleaseGateEffect::FailClosed,
        )
    }

    fn inconclusive_conflict_arbitration() -> CrossOracleArbitration {
        arbitration(
            "arb_inconclusive_conflict",
            CrossOracleDisagreementCategory::InconclusiveConflict,
            CrossOracleConflictStatus::Unresolved,
            vec![
                source(
                    "invariant_inconclusive",
                    CrossOracleKind::InvariantTrace,
                    CrossOracleEvidenceStatus::Pass,
                ),
                source(
                    "crash_inconclusive",
                    CrossOracleKind::CrashReplaySurvivor,
                    CrossOracleEvidenceStatus::Fail,
                ),
            ],
            vec![CrossOraclePublicClaim::DataIntegrity],
            CrossOracleReleaseGateEffect::FailClosed,
        )
    }

    fn valid_arbitrations() -> Vec<CrossOracleArbitration> {
        vec![
            model_bug_arbitration(),
            kernel_baseline_issue_arbitration(),
            product_bug_arbitration(),
            harness_bug_arbitration(),
            fixture_bug_arbitration(),
            unsupported_scope_arbitration(),
            host_capability_gap_arbitration(),
            repair_oracle_gap_arbitration(),
            inconclusive_conflict_arbitration(),
        ]
    }

    fn valid_report() -> CrossOracleArbitrationReport {
        let arbitrations = valid_arbitrations();
        let artifact_paths = arbitrations
            .iter()
            .flat_map(|arbitration| arbitration.artifact_paths.iter().cloned())
            .collect();
        CrossOracleArbitrationReport {
            schema_version: CROSS_ORACLE_ARBITRATION_SCHEMA_VERSION,
            bead_id: BEAD_ID.to_owned(),
            generated_at: "2026-05-03T00:00:00Z".to_owned(),
            runner: RUNNER_PATH.to_owned(),
            arbitrations,
            artifact_paths,
        }
    }

    #[test]
    fn valid_report_covers_all_categories_and_oracle_inputs() {
        let validation = validate_cross_oracle_arbitration_report(&valid_report());

        assert!(validation.valid, "{:?}", validation.errors);
        assert_eq!(validation.arbitration_count, 9);
        for category in [
            CrossOracleDisagreementCategory::ModelBug,
            CrossOracleDisagreementCategory::KernelBaselineIssue,
            CrossOracleDisagreementCategory::FrankenFsProductBug,
            CrossOracleDisagreementCategory::HarnessBug,
            CrossOracleDisagreementCategory::FixtureBug,
            CrossOracleDisagreementCategory::UnsupportedScope,
            CrossOracleDisagreementCategory::HostCapabilityGap,
            CrossOracleDisagreementCategory::RepairOracleGap,
            CrossOracleDisagreementCategory::InconclusiveConflict,
        ] {
            assert_eq!(validation.category_counts.get(category.label()), Some(&1));
        }
        for kind in [
            CrossOracleKind::InvariantTrace,
            CrossOracleKind::MountedDifferential,
            CrossOracleKind::RepairConfidence,
            CrossOracleKind::CrashReplaySurvivor,
            CrossOracleKind::ReleaseGateStatus,
        ] {
            assert!(validation.source_kind_counts.contains_key(kind.label()));
        }
        assert!(
            validation
                .blocked_public_claims
                .contains(&CrossOraclePublicClaim::DataIntegrity.label().to_owned())
        );
    }

    #[test]
    fn unresolved_high_risk_conflicts_must_fail_closed() {
        let mut report = valid_report();
        report.arbitrations[2].release_gate_impact.effect = CrossOracleReleaseGateEffect::Downgrade;

        let validation = validate_cross_oracle_arbitration_report(&report);

        assert!(!validation.valid);
        assert!(validation.errors.iter().any(|error| {
            error.contains("arb_frankenfs_product_bug")
                && error.contains("unresolved high-risk public claim must fail closed")
        }));
    }

    #[test]
    fn stale_or_missing_evidence_requires_gap_aware_classification() {
        let mut report = valid_report();
        report.arbitrations[7].classification =
            CrossOracleDisagreementCategory::FrankenFsProductBug;

        let validation = validate_cross_oracle_arbitration_report(&report);

        assert!(!validation.valid);
        assert!(validation.errors.iter().any(|error| {
            error.contains("arb_repair_oracle_gap") && error.contains("cannot absorb evidence gaps")
        }));
    }

    #[test]
    fn missing_log_fields_and_source_artifacts_fail_closed() {
        let mut report = valid_report();
        let arbitration = &mut report.arbitrations[0];
        arbitration
            .log_fields
            .retain(|field| field != "artifact_hashes");
        arbitration
            .artifact_paths
            .retain(|path| !path.contains("invariant_model"));

        let validation = validate_cross_oracle_arbitration_report(&report);

        assert!(!validation.valid);
        assert!(validation.errors.iter().any(|error| {
            error.contains("arb_model_bug") && error.contains("missing required log field")
        }));
        assert!(validation.errors.iter().any(|error| {
            error.contains("arb_model_bug") && error.contains("missing source artifact")
        }));
    }

    #[test]
    fn missing_oracle_uses_explicit_missing_hash() {
        let mut report = valid_report();
        report.arbitrations[7].source_oracles[0].artifact_sha256 = HASH_A.to_owned();

        let validation = validate_cross_oracle_arbitration_report(&report);

        assert!(!validation.valid);
        assert!(validation.errors.iter().any(|error| {
            error.contains("repair_missing") && error.contains("artifact_sha256=missing")
        }));
    }

    #[test]
    fn markdown_renders_blocked_claims_and_reproduction_commands() {
        let validation = validate_cross_oracle_arbitration_report(&valid_report());
        let markdown = render_cross_oracle_arbitration_markdown(&validation);

        assert!(markdown.contains("mounted_writes"));
        assert!(markdown.contains("data_integrity"));
        assert!(markdown.contains("arb_frankenfs_product_bug"));
        assert!(markdown.contains("validate-cross-oracle-arbitration"));
    }
}
