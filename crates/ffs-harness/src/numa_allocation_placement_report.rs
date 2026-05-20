#![forbid(unsafe_code)]

//! NUMA allocation placement evidence contract.
//!
//! `ffs-alloc`/`ffs-core` emit structured `numa_allocation_hint` decision logs
//! when the opt-in NUMA allocation policy is active. This module turns those
//! decision logs, the validated group-to-node topology mapping, and an optional
//! p99 latency attribution into a single `numa_allocation_placement_report`
//! artifact that explains whether placement helped, hurt, or fell back.
//!
//! The report is advisory replay/downgrade evidence only. It can never, on its
//! own, claim that NUMA placement improved `swarm.responsiveness`: that claim
//! requires the permissioned large-host campaign (`bd-rchk0.53.8`).

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Component, Path};

pub const NUMA_PLACEMENT_REPORT_SCHEMA_VERSION: u32 = 1;
pub const NUMA_PLACEMENT_REPORT_ID: &str = "numa_allocation_placement_report";
pub const NUMA_PLACEMENT_PRODUCT_EVIDENCE_CLAIM: &str = "none";
pub const NUMA_PLACEMENT_SWARM_RESPONSIVENESS_CLAIM: &str = "not_claimed";
pub const NUMA_PLACEMENT_RELEASE_GATE_ADVISORY: &str = "advisory_replay_only";
pub const NUMA_PLACEMENT_RELEASE_GATE_DOWNGRADE: &str = "small_host_downgrade_only";
/// Highest NUMA node id accepted (mirrors `ffs_alloc::MAX_NUMA_NODE_ID`).
pub const NUMA_PLACEMENT_MAX_NODE_ID: u32 = 4095;
/// Largest advisory topology evidence window accepted (7 days).
pub const NUMA_PLACEMENT_MAX_TOPOLOGY_AGE_SECS: u64 = 7 * 24 * 60 * 60;
pub const NUMA_PLACEMENT_MAX_ARTIFACT_PATHS: usize = 32;
/// p99 deltas within this many microseconds are treated as `neutral`.
const P99_NEUTRAL_BAND_MICROS: u64 = 50;

/// Host topology evidence source backing the placement decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NumaPlacementTopologySource {
    /// Fresh observed multi-node topology with a group-to-node map.
    Observed,
    /// Host exposes a single NUMA node; placement is fallback-only.
    SingleNode,
    /// No trusted node map; legacy placement semantics are preserved.
    Unknown,
}

impl NumaPlacementTopologySource {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::SingleNode => "single_node",
            Self::Unknown => "unknown",
        }
    }
}

/// Claim tier carried by the placement evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NumaPlacementClaimTier {
    /// Advisory placement replay evidence.
    Advisory,
    /// Placement ran on a host that can only produce downgrade evidence.
    CapabilityDowngraded,
}

impl NumaPlacementClaimTier {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Advisory => "advisory",
            Self::CapabilityDowngraded => "capability_downgraded",
        }
    }

    /// The only release-gate effect this tier may declare.
    #[must_use]
    pub const fn required_release_gate_effect(self) -> &'static str {
        match self {
            Self::Advisory => NUMA_PLACEMENT_RELEASE_GATE_ADVISORY,
            Self::CapabilityDowngraded => NUMA_PLACEMENT_RELEASE_GATE_DOWNGRADE,
        }
    }
}

/// p99 attribution verdict for the placement policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NumaPlacementP99Outcome {
    /// Observed p99 improved versus baseline.
    Helped,
    /// Observed p99 regressed versus baseline.
    Hurt,
    /// Observed p99 is within the neutral band of baseline.
    Neutral,
    /// No usable p99 attribution was captured for this run.
    NotAttributed,
}

impl NumaPlacementP99Outcome {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Helped => "helped",
            Self::Hurt => "hurt",
            Self::Neutral => "neutral",
            Self::NotAttributed => "not_attributed",
        }
    }
}

/// One validated group-to-node assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumaGroupNodeAssignment {
    pub group: u32,
    pub node: u32,
}

/// Placement decision tallies lifted from `numa_allocation_hint` logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumaPlacementDecisionCounts {
    /// Decisions that used the advisory node map to choose a goal group.
    pub advisory_map_used: u64,
    /// Decisions where an explicit `goal_group`/`goal_block` hint took precedence.
    pub explicit_hint: u64,
    /// Decisions that fell back because the topology was unknown.
    pub fallback_unknown_topology: u64,
    /// Decisions that fell back because the host is single-node.
    pub fallback_single_node: u64,
    /// Decisions that fell back because topology contract validation failed.
    pub fallback_validation_error: u64,
}

impl NumaPlacementDecisionCounts {
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.advisory_map_used
            .saturating_add(self.explicit_hint)
            .saturating_add(self.fallback_unknown_topology)
            .saturating_add(self.fallback_single_node)
            .saturating_add(self.fallback_validation_error)
    }
}

/// p99 latency attribution for the placement policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumaP99Attribution {
    pub baseline_p99_micros: u64,
    pub observed_p99_micros: u64,
    pub outcome: NumaPlacementP99Outcome,
}

/// Executable NUMA allocation placement evidence report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumaAllocationPlacementReport {
    pub schema_version: u32,
    pub report_id: String,
    pub operation_id: String,
    pub scenario_id: String,
    pub topology_source: NumaPlacementTopologySource,
    pub node_count: u32,
    pub group_count: u32,
    pub topology_observed_at_unix_secs: u64,
    pub topology_max_age_secs: u64,
    pub group_node_map: Vec<NumaGroupNodeAssignment>,
    pub claim_tier: NumaPlacementClaimTier,
    pub decisions: NumaPlacementDecisionCounts,
    pub p99: NumaP99Attribution,
    pub artifact_paths: Vec<String>,
    pub raw_log_paths: Vec<String>,
    pub cleanup_status: String,
    pub reproduction_command: String,
    pub product_evidence_claim: String,
    pub release_gate_effect: String,
    pub swarm_responsiveness_claim: String,
}

/// Optional validation context for topology freshness checks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NumaPlacementValidationConfig {
    pub reference_unix_secs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumaPlacementIssue {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumaPlacementValidationReport {
    pub schema_version: u32,
    pub report_id: String,
    pub valid: bool,
    pub operation_id: String,
    pub scenario_id: String,
    pub topology_source: String,
    pub node_count: u32,
    pub group_count: u32,
    pub claim_tier: String,
    pub decision_total: u64,
    pub advisory_map_used: u64,
    pub p99_outcome: String,
    pub release_gate_effect: String,
    pub swarm_responsiveness_claim: String,
    pub issues: Vec<NumaPlacementIssue>,
    pub errors: Vec<String>,
}

#[must_use]
pub fn validate_numa_allocation_placement_report(
    report: &NumaAllocationPlacementReport,
) -> NumaPlacementValidationReport {
    validate_numa_allocation_placement_report_with_config(
        report,
        &NumaPlacementValidationConfig::default(),
    )
}

#[must_use]
pub fn validate_numa_allocation_placement_report_with_config(
    report: &NumaAllocationPlacementReport,
    config: &NumaPlacementValidationConfig,
) -> NumaPlacementValidationReport {
    let mut issues = Vec::new();
    validate_identity(report, &mut issues);
    validate_topology(report, config, &mut issues);
    validate_decisions(report, &mut issues);
    validate_p99(report, &mut issues);
    validate_claims(report, &mut issues);
    validate_paths(report, &mut issues);

    let errors = issues
        .iter()
        .map(|issue| format!("{}: {}", issue.path, issue.message))
        .collect::<Vec<_>>();
    let valid = errors.is_empty();

    NumaPlacementValidationReport {
        schema_version: report.schema_version,
        report_id: report.report_id.clone(),
        valid,
        operation_id: report.operation_id.clone(),
        scenario_id: report.scenario_id.clone(),
        topology_source: report.topology_source.label().to_owned(),
        node_count: report.node_count,
        group_count: report.group_count,
        claim_tier: report.claim_tier.label().to_owned(),
        decision_total: report.decisions.total(),
        advisory_map_used: report.decisions.advisory_map_used,
        p99_outcome: report.p99.outcome.label().to_owned(),
        release_gate_effect: report.release_gate_effect.clone(),
        swarm_responsiveness_claim: report.swarm_responsiveness_claim.clone(),
        issues,
        errors,
    }
}

#[must_use]
pub fn validate_numa_allocation_placement_report_json(
    json: &str,
    config: &NumaPlacementValidationConfig,
) -> NumaPlacementValidationReport {
    match serde_json::from_str::<NumaAllocationPlacementReport>(json) {
        Ok(report) => validate_numa_allocation_placement_report_with_config(&report, config),
        Err(error) => invalid_json_report(&error.to_string()),
    }
}

pub fn fail_on_numa_allocation_placement_errors(
    report: &NumaPlacementValidationReport,
) -> Result<()> {
    if report.valid {
        return Ok(());
    }
    bail!(
        "numa allocation placement report invalid: {} error(s)",
        report.errors.len()
    )
}

#[must_use]
pub fn render_numa_allocation_placement_markdown(report: &NumaPlacementValidationReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# NUMA Allocation Placement Report");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Report: `{}`", report.report_id);
    let _ = writeln!(out, "- Valid: `{}`", report.valid);
    let _ = writeln!(out, "- Operation: `{}`", report.operation_id);
    let _ = writeln!(out, "- Scenario: `{}`", report.scenario_id);
    let _ = writeln!(out, "- Topology source: `{}`", report.topology_source);
    let _ = writeln!(out, "- Node count: `{}`", report.node_count);
    let _ = writeln!(out, "- Group count: `{}`", report.group_count);
    let _ = writeln!(out, "- Claim tier: `{}`", report.claim_tier);
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
    let _ = writeln!(out);
    let _ = writeln!(out, "## Placement Decisions");
    let _ = writeln!(out);
    let _ = writeln!(out, "| Metric | Value |");
    let _ = writeln!(out, "|---|---:|");
    let _ = writeln!(out, "| Total decisions | {} |", report.decision_total);
    let _ = writeln!(out, "| Advisory map used | {} |", report.advisory_map_used);
    let _ = writeln!(out, "| p99 outcome | {} |", report.p99_outcome);
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

fn invalid_json_report(error: &str) -> NumaPlacementValidationReport {
    let issue = NumaPlacementIssue {
        path: "$".to_owned(),
        message: format!("invalid or incomplete numa allocation placement JSON: {error}"),
    };
    NumaPlacementValidationReport {
        schema_version: 0,
        report_id: "<invalid-json>".to_owned(),
        valid: false,
        operation_id: String::new(),
        scenario_id: String::new(),
        topology_source: String::new(),
        node_count: 0,
        group_count: 0,
        claim_tier: String::new(),
        decision_total: 0,
        advisory_map_used: 0,
        p99_outcome: String::new(),
        release_gate_effect: String::new(),
        swarm_responsiveness_claim: String::new(),
        errors: vec![format!("$: {}", issue.message)],
        issues: vec![issue],
    }
}

fn validate_identity(report: &NumaAllocationPlacementReport, issues: &mut Vec<NumaPlacementIssue>) {
    if report.schema_version != NUMA_PLACEMENT_REPORT_SCHEMA_VERSION {
        push_issue(
            issues,
            "schema_version",
            format!("must be {NUMA_PLACEMENT_REPORT_SCHEMA_VERSION}"),
        );
    }
    if report.report_id != NUMA_PLACEMENT_REPORT_ID {
        push_issue(
            issues,
            "report_id",
            format!("must be `{NUMA_PLACEMENT_REPORT_ID}`"),
        );
    }
    require_non_empty("operation_id", &report.operation_id, issues);
    require_non_empty("scenario_id", &report.scenario_id, issues);
    require_non_empty("reproduction_command", &report.reproduction_command, issues);
    require_non_empty("cleanup_status", &report.cleanup_status, issues);
    if report.group_count == 0 {
        push_issue(issues, "group_count", "must be greater than zero");
    }
    if report.node_count == 0 {
        push_issue(issues, "node_count", "must be greater than zero");
    }
}

fn validate_topology(
    report: &NumaAllocationPlacementReport,
    config: &NumaPlacementValidationConfig,
    issues: &mut Vec<NumaPlacementIssue>,
) {
    match report.topology_source {
        NumaPlacementTopologySource::Observed => {
            validate_observed_group_map(report, issues);
            validate_topology_freshness(report, config, issues);
        }
        NumaPlacementTopologySource::SingleNode => {
            if report.node_count != 1 {
                push_issue(
                    issues,
                    "node_count",
                    "single-node topology must report node_count=1",
                );
            }
            if report
                .group_node_map
                .iter()
                .any(|assignment| assignment.node != 0)
            {
                push_issue(
                    issues,
                    "group_node_map",
                    "single-node topology may only map groups to node 0",
                );
            }
        }
        NumaPlacementTopologySource::Unknown => {
            if !report.group_node_map.is_empty() {
                push_issue(
                    issues,
                    "group_node_map",
                    "unknown topology must not carry a group-to-node map",
                );
            }
        }
    }
}

fn validate_observed_group_map(
    report: &NumaAllocationPlacementReport,
    issues: &mut Vec<NumaPlacementIssue>,
) {
    let mut seen_groups = BTreeSet::new();
    for (index, assignment) in report.group_node_map.iter().enumerate() {
        let path = format!("group_node_map[{index}]");
        if assignment.group >= report.group_count {
            push_issue(
                issues,
                format!("{path}.group"),
                format!(
                    "group {} is outside group_count {}",
                    assignment.group, report.group_count
                ),
            );
        }
        if assignment.node >= report.node_count || assignment.node > NUMA_PLACEMENT_MAX_NODE_ID {
            push_issue(
                issues,
                format!("{path}.node"),
                format!(
                    "node {} is not a valid node for node_count {}",
                    assignment.node, report.node_count
                ),
            );
        }
        if !seen_groups.insert(assignment.group) {
            push_issue(
                issues,
                format!("{path}.group"),
                format!("group {} is mapped more than once", assignment.group),
            );
        }
    }
    let expected = usize::try_from(report.group_count).unwrap_or(usize::MAX);
    if report.group_node_map.len() != expected {
        push_issue(
            issues,
            "group_node_map",
            format!(
                "observed topology must map every group exactly once \
                 (have {}, need {})",
                report.group_node_map.len(),
                report.group_count
            ),
        );
    }
}

fn validate_topology_freshness(
    report: &NumaAllocationPlacementReport,
    config: &NumaPlacementValidationConfig,
    issues: &mut Vec<NumaPlacementIssue>,
) {
    if report.topology_observed_at_unix_secs == 0 {
        push_issue(
            issues,
            "topology_observed_at_unix_secs",
            "observed topology must record a non-zero observation timestamp",
        );
    }
    if report.topology_max_age_secs == 0
        || report.topology_max_age_secs > NUMA_PLACEMENT_MAX_TOPOLOGY_AGE_SECS
    {
        push_issue(
            issues,
            "topology_max_age_secs",
            format!("must be between 1 and {NUMA_PLACEMENT_MAX_TOPOLOGY_AGE_SECS} seconds"),
        );
    }
    let Some(reference) = config.reference_unix_secs else {
        return;
    };
    if report.topology_observed_at_unix_secs > reference {
        push_issue(
            issues,
            "topology_observed_at_unix_secs",
            "observed topology timestamp is in the future",
        );
        return;
    }
    let age = reference - report.topology_observed_at_unix_secs;
    if report.topology_max_age_secs > 0 && age > report.topology_max_age_secs {
        push_issue(
            issues,
            "topology_observed_at_unix_secs",
            format!(
                "stale topology evidence: age_secs={age} max_age_secs={}",
                report.topology_max_age_secs
            ),
        );
    }
}

fn validate_decisions(
    report: &NumaAllocationPlacementReport,
    issues: &mut Vec<NumaPlacementIssue>,
) {
    let decisions = &report.decisions;
    if decisions.total() == 0 {
        push_issue(
            issues,
            "decisions",
            "report carries no allocation-placement decisions (missing decision logs)",
        );
    }
    if decisions.advisory_map_used > 0
        && report.topology_source != NumaPlacementTopologySource::Observed
    {
        push_issue(
            issues,
            "decisions.advisory_map_used",
            "advisory map cannot be used without an observed topology",
        );
    }
    if decisions.fallback_single_node > 0
        && report.topology_source == NumaPlacementTopologySource::Observed
    {
        push_issue(
            issues,
            "decisions.fallback_single_node",
            "single-node fallback is impossible under an observed multi-node topology",
        );
    }
}

fn validate_p99(report: &NumaAllocationPlacementReport, issues: &mut Vec<NumaPlacementIssue>) {
    let p99 = &report.p99;
    let expected = classify_p99_outcome(p99.baseline_p99_micros, p99.observed_p99_micros);
    if p99.outcome != expected {
        push_issue(
            issues,
            "p99.outcome",
            format!(
                "outcome `{}` does not match baseline/observed p99 (expected `{}`)",
                p99.outcome.label(),
                expected.label()
            ),
        );
    }
}

/// Classify a p99 attribution from baseline and observed microsecond values.
#[must_use]
pub fn classify_p99_outcome(baseline_micros: u64, observed_micros: u64) -> NumaPlacementP99Outcome {
    if baseline_micros == 0 || observed_micros == 0 {
        return NumaPlacementP99Outcome::NotAttributed;
    }
    let delta = baseline_micros.abs_diff(observed_micros);
    if delta <= P99_NEUTRAL_BAND_MICROS {
        NumaPlacementP99Outcome::Neutral
    } else if observed_micros < baseline_micros {
        NumaPlacementP99Outcome::Helped
    } else {
        NumaPlacementP99Outcome::Hurt
    }
}

fn validate_claims(report: &NumaAllocationPlacementReport, issues: &mut Vec<NumaPlacementIssue>) {
    if report.product_evidence_claim != NUMA_PLACEMENT_PRODUCT_EVIDENCE_CLAIM {
        push_issue(
            issues,
            "product_evidence_claim",
            format!("must be `{NUMA_PLACEMENT_PRODUCT_EVIDENCE_CLAIM}`"),
        );
    }
    if report.swarm_responsiveness_claim != NUMA_PLACEMENT_SWARM_RESPONSIVENESS_CLAIM {
        push_issue(
            issues,
            "swarm_responsiveness_claim",
            "NUMA placement replay cannot claim swarm.responsiveness acceptance",
        );
    }
    // The release-gate effect is pinned to the claim tier: even a p99 `helped`
    // outcome stays advisory replay/downgrade evidence and never upgrades a
    // public readiness gate without the permissioned large-host campaign.
    let required = report.claim_tier.required_release_gate_effect();
    if report.release_gate_effect != required {
        push_issue(
            issues,
            "release_gate_effect",
            format!(
                "claim tier `{}` must declare release_gate_effect `{required}`",
                report.claim_tier.label()
            ),
        );
    }
}

fn validate_paths(report: &NumaAllocationPlacementReport, issues: &mut Vec<NumaPlacementIssue>) {
    if report.artifact_paths.is_empty() {
        push_issue(issues, "artifact_paths", "must not be empty");
    }
    if report.artifact_paths.len() > NUMA_PLACEMENT_MAX_ARTIFACT_PATHS {
        push_issue(
            issues,
            "artifact_paths",
            format!("must contain at most {NUMA_PLACEMENT_MAX_ARTIFACT_PATHS} paths"),
        );
    }
    for (index, path) in report.artifact_paths.iter().enumerate() {
        validate_safe_path(issues, &format!("artifact_paths[{index}]"), path);
    }
    for (index, path) in report.raw_log_paths.iter().enumerate() {
        validate_safe_path(issues, &format!("raw_log_paths[{index}]"), path);
    }
}

fn validate_safe_path(issues: &mut Vec<NumaPlacementIssue>, field: &str, value: &str) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        push_issue(issues, field, "must not be empty");
        return;
    }
    let path = Path::new(trimmed);
    let parent_sensitive = path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)));
    let lower = trimmed.to_ascii_lowercase();
    let secret = ["/.ssh/", "/.aws/", "/etc/", "id_rsa", "secret", "token"]
        .iter()
        .any(|token| lower.contains(token));
    if parent_sensitive || secret {
        push_issue(
            issues,
            field,
            "must be a redacted artifact path without parent traversal or secrets",
        );
        return;
    }
    let scoped = if path.is_absolute() {
        trimmed.contains("/artifacts/") || trimmed.starts_with("/tmp/frankenfs-")
    } else {
        path.starts_with("artifacts")
    };
    if !scoped {
        push_issue(
            issues,
            field,
            "must be relative to artifacts/ or a redacted FrankenFS artifact temp root",
        );
    }
}

fn require_non_empty(field: &str, value: &str, issues: &mut Vec<NumaPlacementIssue>) {
    if value.trim().is_empty() {
        push_issue(issues, field, "must not be empty");
    }
}

fn push_issue(
    issues: &mut Vec<NumaPlacementIssue>,
    path: impl Into<String>,
    message: impl Into<String>,
) {
    issues.push(NumaPlacementIssue {
        path: path.into(),
        message: message.into(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    use serde_json::json;

    const REFERENCE_UNIX_SECS: u64 = 1_779_000_000;

    fn observed_report() -> NumaAllocationPlacementReport {
        NumaAllocationPlacementReport {
            schema_version: NUMA_PLACEMENT_REPORT_SCHEMA_VERSION,
            report_id: NUMA_PLACEMENT_REPORT_ID.to_owned(),
            operation_id: "numa-placement-op-20260519T000000Z".to_owned(),
            scenario_id: "numa_allocation_balanced_replay".to_owned(),
            topology_source: NumaPlacementTopologySource::Observed,
            node_count: 2,
            group_count: 4,
            topology_observed_at_unix_secs: REFERENCE_UNIX_SECS - 3_600,
            topology_max_age_secs: NUMA_PLACEMENT_MAX_TOPOLOGY_AGE_SECS,
            group_node_map: vec![
                NumaGroupNodeAssignment { group: 0, node: 0 },
                NumaGroupNodeAssignment { group: 1, node: 0 },
                NumaGroupNodeAssignment { group: 2, node: 1 },
                NumaGroupNodeAssignment { group: 3, node: 1 },
            ],
            claim_tier: NumaPlacementClaimTier::Advisory,
            decisions: NumaPlacementDecisionCounts {
                advisory_map_used: 720,
                explicit_hint: 180,
                fallback_unknown_topology: 0,
                fallback_single_node: 0,
                fallback_validation_error: 0,
            },
            p99: NumaP99Attribution {
                baseline_p99_micros: 4_200,
                observed_p99_micros: 3_600,
                outcome: NumaPlacementP99Outcome::Helped,
            },
            artifact_paths: vec![
                "artifacts/numa-placement/balanced_report.json".to_owned(),
            ],
            raw_log_paths: vec!["artifacts/numa-placement/numa_hint.log".to_owned()],
            cleanup_status: "clean".to_owned(),
            reproduction_command:
                "ffs-harness validate-numa-allocation-placement --report artifacts/numa-placement/balanced_report.json"
                    .to_owned(),
            product_evidence_claim: NUMA_PLACEMENT_PRODUCT_EVIDENCE_CLAIM.to_owned(),
            release_gate_effect: NUMA_PLACEMENT_RELEASE_GATE_ADVISORY.to_owned(),
            swarm_responsiveness_claim: NUMA_PLACEMENT_SWARM_RESPONSIVENESS_CLAIM.to_owned(),
        }
    }

    fn fixture_config() -> NumaPlacementValidationConfig {
        NumaPlacementValidationConfig {
            reference_unix_secs: Some(REFERENCE_UNIX_SECS),
        }
    }

    fn assert_issue(report: &NumaPlacementValidationReport, path: &str) {
        assert!(!report.valid);
        assert!(
            report.issues.iter().any(|issue| issue.path == path),
            "missing issue path {path}; issues={:?}",
            report.issues
        );
    }

    #[test]
    fn numa_allocation_placement_report_json_shape() -> Result<()> {
        let report = observed_report();
        let validation =
            validate_numa_allocation_placement_report_with_config(&report, &fixture_config());
        assert!(validation.valid, "{:?}", validation.errors);

        let shape = json!({
            "schema_version": report.schema_version,
            "report_id": report.report_id,
            "operation_id": report.operation_id,
            "scenario_id": report.scenario_id,
            "topology_source": report.topology_source,
            "node_count": report.node_count,
            "group_count": report.group_count,
            "topology_observed_at_unix_secs": report.topology_observed_at_unix_secs,
            "topology_max_age_secs": report.topology_max_age_secs,
            "group_node_map": report.group_node_map,
            "claim_tier": report.claim_tier,
            "decisions": report.decisions,
            "p99": report.p99,
            "artifact_paths": report.artifact_paths,
            "raw_log_paths": report.raw_log_paths,
            "cleanup_status": report.cleanup_status,
            "reproduction_command": report.reproduction_command,
            "product_evidence_claim": report.product_evidence_claim,
            "release_gate_effect": report.release_gate_effect,
            "swarm_responsiveness_claim": report.swarm_responsiveness_claim,
            "validation": {
                "valid": validation.valid,
                "decision_total": validation.decision_total,
                "p99_outcome": validation.p99_outcome,
                "issues": validation.issues,
            },
        });
        let encoded = serde_json::to_string_pretty(&shape)?;
        insta::assert_snapshot!("numa_allocation_placement_report_json_shape", encoded);

        let round_trip = serde_json::to_string_pretty(&report)?;
        let parsed: NumaAllocationPlacementReport = serde_json::from_str(&round_trip)?;
        assert_eq!(parsed, report);
        Ok(())
    }

    #[test]
    fn render_numa_allocation_placement_markdown_sample() {
        let validation = validate_numa_allocation_placement_report_with_config(
            &observed_report(),
            &fixture_config(),
        );
        let markdown = render_numa_allocation_placement_markdown(&validation);
        insta::assert_snapshot!("render_numa_allocation_placement_markdown_sample", markdown);
    }

    #[test]
    fn balanced_observed_report_validates() {
        let validation = validate_numa_allocation_placement_report_with_config(
            &observed_report(),
            &fixture_config(),
        );
        assert!(validation.valid, "{:?}", validation.errors);
    }

    #[test]
    fn missing_required_fields_are_rejected() -> Result<()> {
        let mut value = serde_json::to_value(observed_report())?;
        value
            .as_object_mut()
            .context("report object")?
            .remove("operation_id");
        let validation =
            validate_numa_allocation_placement_report_json(&value.to_string(), &fixture_config());
        assert!(!validation.valid);
        assert!(
            validation
                .errors
                .iter()
                .any(|error| error.contains("missing field `operation_id`")),
            "{:?}",
            validation.errors
        );
        Ok(())
    }

    #[test]
    fn stale_topology_is_rejected() {
        let mut report = observed_report();
        report.topology_observed_at_unix_secs =
            REFERENCE_UNIX_SECS - NUMA_PLACEMENT_MAX_TOPOLOGY_AGE_SECS - 10;
        let validation =
            validate_numa_allocation_placement_report_with_config(&report, &fixture_config());
        assert_issue(&validation, "topology_observed_at_unix_secs");
    }

    #[test]
    fn missing_allocation_logs_are_rejected() {
        let mut report = observed_report();
        report.decisions = NumaPlacementDecisionCounts {
            advisory_map_used: 0,
            explicit_hint: 0,
            fallback_unknown_topology: 0,
            fallback_single_node: 0,
            fallback_validation_error: 0,
        };
        let validation =
            validate_numa_allocation_placement_report_with_config(&report, &fixture_config());
        assert_issue(&validation, "decisions");
    }

    #[test]
    fn impossible_group_to_node_map_is_rejected() {
        let mut report = observed_report();
        report.group_node_map[2].node = 9;
        report.group_node_map[3].group = 0;
        let validation =
            validate_numa_allocation_placement_report_with_config(&report, &fixture_config());
        assert_issue(&validation, "group_node_map[2].node");
        assert_issue(&validation, "group_node_map[3].group");
    }

    #[test]
    fn p99_attribution_mismatch_is_rejected() {
        let mut report = observed_report();
        // Observed p99 is worse than baseline, but the report claims `helped`.
        report.p99 = NumaP99Attribution {
            baseline_p99_micros: 3_000,
            observed_p99_micros: 5_000,
            outcome: NumaPlacementP99Outcome::Helped,
        };
        let validation =
            validate_numa_allocation_placement_report_with_config(&report, &fixture_config());
        assert_issue(&validation, "p99.outcome");
    }

    #[test]
    fn release_gate_effect_must_match_claim_tier() {
        let mut report = observed_report();
        // A capability-downgraded run cannot keep the advisory release effect.
        report.claim_tier = NumaPlacementClaimTier::CapabilityDowngraded;
        let validation =
            validate_numa_allocation_placement_report_with_config(&report, &fixture_config());
        assert_issue(&validation, "release_gate_effect");

        let mut fixed = observed_report();
        fixed.claim_tier = NumaPlacementClaimTier::CapabilityDowngraded;
        fixed.release_gate_effect = NUMA_PLACEMENT_RELEASE_GATE_DOWNGRADE.to_owned();
        let validation =
            validate_numa_allocation_placement_report_with_config(&fixed, &fixture_config());
        assert!(validation.valid, "{:?}", validation.errors);
    }

    #[test]
    fn swarm_responsiveness_promotion_is_rejected() {
        let mut report = observed_report();
        report.swarm_responsiveness_claim = "accepted".to_owned();
        report.product_evidence_claim = "swarm.responsiveness".to_owned();
        let validation =
            validate_numa_allocation_placement_report_with_config(&report, &fixture_config());
        assert_issue(&validation, "swarm_responsiveness_claim");
        assert_issue(&validation, "product_evidence_claim");
    }

    #[test]
    fn advisory_map_use_without_observed_topology_is_rejected() {
        let mut report = observed_report();
        report.topology_source = NumaPlacementTopologySource::Unknown;
        report.node_count = 1;
        report.group_node_map.clear();
        let validation =
            validate_numa_allocation_placement_report_with_config(&report, &fixture_config());
        assert_issue(&validation, "decisions.advisory_map_used");
    }

    #[test]
    fn unknown_topology_fallback_report_validates() {
        let mut report = observed_report();
        report.scenario_id = "numa_allocation_unknown_topology_replay".to_owned();
        report.topology_source = NumaPlacementTopologySource::Unknown;
        report.node_count = 1;
        report.group_node_map.clear();
        report.decisions = NumaPlacementDecisionCounts {
            advisory_map_used: 0,
            explicit_hint: 120,
            fallback_unknown_topology: 880,
            fallback_single_node: 0,
            fallback_validation_error: 0,
        };
        report.p99 = NumaP99Attribution {
            baseline_p99_micros: 0,
            observed_p99_micros: 0,
            outcome: NumaPlacementP99Outcome::NotAttributed,
        };
        let validation =
            validate_numa_allocation_placement_report_with_config(&report, &fixture_config());
        assert!(validation.valid, "{:?}", validation.errors);
    }

    #[test]
    fn p99_outcome_classification_uses_a_neutral_band() {
        assert_eq!(
            classify_p99_outcome(0, 100),
            NumaPlacementP99Outcome::NotAttributed
        );
        assert_eq!(
            classify_p99_outcome(1_000, 1_020),
            NumaPlacementP99Outcome::Neutral
        );
        assert_eq!(
            classify_p99_outcome(2_000, 1_000),
            NumaPlacementP99Outcome::Helped
        );
        assert_eq!(
            classify_p99_outcome(1_000, 2_000),
            NumaPlacementP99Outcome::Hurt
        );
    }

    #[test]
    fn fail_on_errors_rejects_invalid_report() {
        let mut report = observed_report();
        report.artifact_paths.clear();
        let validation =
            validate_numa_allocation_placement_report_with_config(&report, &fixture_config());
        assert!(fail_on_numa_allocation_placement_errors(&validation).is_err());
    }
}
