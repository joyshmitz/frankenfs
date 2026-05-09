#![allow(
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::too_many_lines
)]
#![forbid(unsafe_code)]

//! Read-only operator dashboard over strict readiness validators.
//!
//! This module deliberately does not evaluate readiness itself. It consumes
//! reports already emitted by the proof-bundle validator, release-gate
//! evaluator, operational evidence index, and permissioned campaign tooling.

use crate::operational_evidence_index::{
    OperationalEvidenceFreshness, OperationalEvidenceHostClass, OperationalEvidenceIndex,
    OperationalEvidenceRecord, OperationalEvidenceReleaseClaimEffect,
};
use crate::proof_bundle::{
    ProofBundleClaimEffect, ProofBundleOutcome, ProofBundleValidationReport,
};
use crate::release_gate::{FeatureState, ReleaseGateEvaluationReport, ReleaseGateFindingSeverity};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

pub const READINESS_DASHBOARD_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_READINESS_DASHBOARD_BEAD: &str = "bd-4v16z.10";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReadinessDashboardConfig {
    pub proof_bundle_reports: Vec<PathBuf>,
    pub release_gate_reports: Vec<PathBuf>,
    pub operational_evidence_indexes: Vec<PathBuf>,
    pub permissioned_campaign_reports: Vec<PathBuf>,
    pub beads_path: Option<PathBuf>,
    pub default_remediation_bead: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessDashboardReport {
    pub schema_version: u32,
    pub dashboard_id: String,
    pub valid: bool,
    pub source_report_count: usize,
    pub claim_count: usize,
    pub recommendation_count: usize,
    pub source_validator_failure_count: usize,
    pub sources: Vec<ReadinessDashboardSourceReport>,
    pub claims: Vec<ReadinessDashboardClaimReport>,
    pub recommendations: Vec<ReadinessDashboardRecommendation>,
    pub tracker_follow_up_beads: Vec<ReadinessDashboardTrackerBead>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessDashboardSourceReport {
    pub source_kind: String,
    pub path: String,
    pub valid: bool,
    pub summary: String,
    pub referenced_beads: Vec<String>,
    pub produced_claim_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessDashboardClaimReport {
    pub claim_id: String,
    pub claim_state: ReadinessDashboardClaimState,
    pub source_kind: String,
    pub source_path: String,
    pub validator_report: String,
    pub controlling_lane: Option<String>,
    pub freshness: Option<String>,
    pub host_class: Option<String>,
    pub missing_artifacts: Vec<String>,
    pub remediation_bead: Option<String>,
    pub next_safe_command: String,
    pub evidence_basis: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessDashboardClaimState {
    Validated,
    OptInMutating,
    Experimental,
    DetectionOnly,
    DryRunOnly,
    Disabled,
    Hidden,
    HandoffOnly,
    Blocked,
    Unknown,
}

impl ReadinessDashboardClaimState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Validated => "validated",
            Self::OptInMutating => "opt_in_mutating",
            Self::Experimental => "experimental",
            Self::DetectionOnly => "detection_only",
            Self::DryRunOnly => "dry_run_only",
            Self::Disabled => "disabled",
            Self::Hidden => "hidden",
            Self::HandoffOnly => "handoff_only",
            Self::Blocked => "blocked",
            Self::Unknown => "unknown",
        }
    }

    #[must_use]
    pub const fn needs_follow_up(self) -> bool {
        !matches!(self, Self::Validated)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessDashboardRecommendation {
    pub action_id: String,
    pub claim_id: String,
    pub severity: ReadinessDashboardRecommendationSeverity,
    pub title: String,
    pub validator_report: Option<String>,
    pub bead_id: Option<String>,
    pub next_safe_command: String,
    pub rationale: String,
    pub missing_artifacts: Vec<String>,
    pub controlling_lane: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessDashboardRecommendationSeverity {
    Info,
    FollowUp,
    Blocker,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessDashboardTrackerBead {
    pub issue_id: String,
    pub status: String,
    pub title: String,
    pub priority: Option<String>,
}

struct DashboardBuilder {
    report: ReadinessDashboardReport,
    default_remediation_bead: Option<String>,
}

impl DashboardBuilder {
    fn new(config: &ReadinessDashboardConfig) -> Self {
        Self {
            report: ReadinessDashboardReport {
                schema_version: READINESS_DASHBOARD_SCHEMA_VERSION,
                dashboard_id: "frankenfs-readiness-dashboard:v1".to_owned(),
                valid: true,
                source_report_count: 0,
                claim_count: 0,
                recommendation_count: 0,
                source_validator_failure_count: 0,
                sources: Vec::new(),
                claims: Vec::new(),
                recommendations: Vec::new(),
                tracker_follow_up_beads: Vec::new(),
                warnings: Vec::new(),
                errors: Vec::new(),
            },
            default_remediation_bead: config
                .default_remediation_bead
                .clone()
                .or_else(|| Some(DEFAULT_READINESS_DASHBOARD_BEAD.to_owned())),
        }
    }

    fn push_source(&mut self, source: ReadinessDashboardSourceReport) {
        if !source.valid {
            self.report.source_validator_failure_count += 1;
        }
        self.report.sources.push(source);
    }

    fn push_claim(&mut self, claim: ReadinessDashboardClaimReport) {
        self.report.claims.push(claim);
    }

    fn finish(mut self) -> ReadinessDashboardReport {
        if self.report.sources.is_empty() {
            let bead_id = self.default_remediation_bead.clone();
            self.report.warnings.push(
                "no readiness validator reports were provided; dashboard cannot display claim state"
                    .to_owned(),
            );
            self.report
                .recommendations
                .push(ReadinessDashboardRecommendation {
                    action_id: "dashboard-missing-validator-inputs".to_owned(),
                    claim_id: "dashboard:missing-inputs".to_owned(),
                    severity: ReadinessDashboardRecommendationSeverity::Blocker,
                    title: "Provide validator reports before reviewing readiness".to_owned(),
                    validator_report: None,
                    bead_id: bead_id.clone(),
                    next_safe_command: bead_id
                        .as_deref()
                        .map_or_else(|| "br ready --no-db --json".to_owned(), bead_show_command),
                    rationale: "the dashboard is only a display layer over validator outputs"
                        .to_owned(),
                    missing_artifacts: vec![
                        "proof-bundle report, release-gate report, operational evidence index, or permissioned campaign report".to_owned(),
                    ],
                    controlling_lane: None,
                });
        }

        let claims = self.report.claims.clone();
        for claim in &claims {
            if !claim.claim_state.needs_follow_up() {
                continue;
            }
            self.report
                .recommendations
                .push(recommendation_for_claim(claim));
        }

        self.report.source_report_count = self.report.sources.len();
        self.report.claim_count = self.report.claims.len();
        self.report.recommendation_count = self.report.recommendations.len();
        self.report.valid = self.report.errors.is_empty();
        self.report
    }
}

pub fn build_readiness_dashboard(
    config: &ReadinessDashboardConfig,
) -> Result<ReadinessDashboardReport> {
    let mut builder = DashboardBuilder::new(config);

    if let Some(path) = &config.beads_path {
        builder.report.tracker_follow_up_beads = load_tracker_beads(path)?;
    }

    for path in &config.release_gate_reports {
        let report = load_json::<ReleaseGateEvaluationReport>(path)?;
        add_release_gate_report(&mut builder, path, &report);
    }
    for path in &config.proof_bundle_reports {
        let report = load_json::<ProofBundleValidationReport>(path)?;
        add_proof_bundle_report(&mut builder, path, &report);
    }
    for path in &config.operational_evidence_indexes {
        let index = load_json::<OperationalEvidenceIndex>(path)?;
        add_operational_evidence_index(&mut builder, path, &index);
    }
    for path in &config.permissioned_campaign_reports {
        let report = load_json::<Value>(path)?;
        add_permissioned_campaign_report(&mut builder, path, &report);
    }

    Ok(builder.finish())
}

#[must_use]
pub fn render_readiness_dashboard_markdown(report: &ReadinessDashboardReport) -> String {
    let mut out = String::new();
    writeln!(&mut out, "# FrankenFS Operator Readiness Dashboard").ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "- Dashboard valid: `{}`", report.valid).ok();
    writeln!(
        &mut out,
        "- Sources: `{}` validator_failures=`{}`",
        report.source_report_count, report.source_validator_failure_count
    )
    .ok();
    writeln!(
        &mut out,
        "- Claims: `{}` recommendations=`{}`",
        report.claim_count, report.recommendation_count
    )
    .ok();
    writeln!(&mut out).ok();

    if !report.sources.is_empty() {
        writeln!(&mut out, "## Sources").ok();
        writeln!(&mut out, "| Kind | Valid | Path | Claims | Beads |").ok();
        writeln!(&mut out, "|---|---:|---|---|---|").ok();
        for source in &report.sources {
            writeln!(
                &mut out,
                "| `{}` | `{}` | `{}` | {} | {} |",
                source.source_kind,
                source.valid,
                source.path,
                markdown_list(&source.produced_claim_ids),
                markdown_list(&source.referenced_beads)
            )
            .ok();
        }
        writeln!(&mut out).ok();
    }

    if !report.claims.is_empty() {
        writeln!(&mut out, "## Claims").ok();
        writeln!(
            &mut out,
            "| Claim | State | Lane | Freshness | Host | Missing Artifacts | Next Safe Command |"
        )
        .ok();
        writeln!(&mut out, "|---|---|---|---|---|---|---|").ok();
        for claim in &report.claims {
            writeln!(
                &mut out,
                "| `{}` | `{}` | `{}` | `{}` | `{}` | {} | `{}` |",
                claim.claim_id,
                claim.claim_state.label(),
                claim.controlling_lane.as_deref().unwrap_or(""),
                claim.freshness.as_deref().unwrap_or(""),
                claim.host_class.as_deref().unwrap_or(""),
                markdown_list(&claim.missing_artifacts),
                claim.next_safe_command
            )
            .ok();
        }
        writeln!(&mut out).ok();
    }

    if !report.recommendations.is_empty() {
        writeln!(&mut out, "## Recommendations").ok();
        for recommendation in &report.recommendations {
            writeln!(
                &mut out,
                "- `{}` `{}` claim=`{}` validator=`{}` bead=`{}` command=`{}`",
                recommendation.action_id,
                severity_label(recommendation.severity),
                recommendation.claim_id,
                recommendation.validator_report.as_deref().unwrap_or(""),
                recommendation.bead_id.as_deref().unwrap_or(""),
                recommendation.next_safe_command
            )
            .ok();
            writeln!(&mut out, "  - {}", recommendation.rationale).ok();
        }
        writeln!(&mut out).ok();
    }

    if !report.tracker_follow_up_beads.is_empty() {
        writeln!(&mut out, "## Tracker Follow-Up Beads").ok();
        writeln!(&mut out, "| Bead | Status | Priority | Title |").ok();
        writeln!(&mut out, "|---|---|---|---|").ok();
        for bead in &report.tracker_follow_up_beads {
            writeln!(
                &mut out,
                "| `{}` | `{}` | `{}` | {} |",
                bead.issue_id,
                bead.status,
                bead.priority.as_deref().unwrap_or(""),
                bead.title
            )
            .ok();
        }
        writeln!(&mut out).ok();
    }

    if !report.warnings.is_empty() {
        writeln!(&mut out, "## Warnings").ok();
        for warning in &report.warnings {
            writeln!(&mut out, "- {warning}").ok();
        }
    }
    out
}

fn add_release_gate_report(
    builder: &mut DashboardBuilder,
    path: &Path,
    report: &ReleaseGateEvaluationReport,
) {
    let source_path = display_path(path);
    let mut produced_claim_ids = Vec::new();
    for feature in &report.feature_reports {
        let findings = report
            .findings
            .iter()
            .filter(|finding| finding.feature_id == feature.feature_id)
            .collect::<Vec<_>>();
        let missing_artifacts = release_gate_missing_artifacts(&findings);
        let remediation_bead = findings
            .iter()
            .find_map(|finding| finding.remediation_id.as_deref())
            .and_then(bead_like)
            .or_else(|| builder.default_remediation_bead.clone());
        let controlling_lane = findings
            .iter()
            .find_map(|finding| finding.controlling_lane.clone());
        let claim_state = if !report.valid || !report.proof_bundle_valid {
            ReadinessDashboardClaimState::Blocked
        } else {
            feature_state_to_claim_state(feature.final_state)
        };
        let next_safe_command =
            next_safe_command(remediation_bead.as_deref(), &report.reproduction_command);
        let claim_id = format!("release_gate:{}", feature.feature_id);
        produced_claim_ids.push(claim_id.clone());
        builder.push_claim(ReadinessDashboardClaimReport {
            claim_id,
            claim_state,
            source_kind: "release_gate".to_owned(),
            source_path: source_path.clone(),
            validator_report: source_path.clone(),
            controlling_lane,
            freshness: Some(if report.proof_bundle_valid {
                "validator_reported_fresh_or_unchecked".to_owned()
            } else {
                "proof_bundle_invalid".to_owned()
            }),
            host_class: None,
            missing_artifacts,
            remediation_bead,
            next_safe_command,
            evidence_basis: release_gate_evidence_basis(report, feature.feature_id.as_str()),
        });
    }

    builder.push_source(ReadinessDashboardSourceReport {
        source_kind: "release_gate".to_owned(),
        path: source_path,
        valid: report.valid,
        summary: format!(
            "policy={} bundle={} release_ready={} findings={}",
            report.policy_id,
            report.bundle_id,
            report.release_ready,
            report.findings.len()
        ),
        referenced_beads: report
            .findings
            .iter()
            .filter_map(|finding| finding.remediation_id.as_deref())
            .filter_map(bead_like)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        produced_claim_ids,
    });
}

fn add_proof_bundle_report(
    builder: &mut DashboardBuilder,
    path: &Path,
    report: &ProofBundleValidationReport,
) {
    let source_path = display_path(path);
    let mut produced_claim_ids = Vec::new();
    if report.lane_provenance.is_empty() {
        let missing_artifacts = proof_bundle_missing_artifacts(report);
        let remediation_bead = builder.default_remediation_bead.clone();
        let claim_id = format!("proof_bundle:{}", report.bundle_id);
        produced_claim_ids.push(claim_id.clone());
        builder.push_claim(ReadinessDashboardClaimReport {
            claim_id,
            claim_state: if report.valid {
                ReadinessDashboardClaimState::Unknown
            } else {
                ReadinessDashboardClaimState::Blocked
            },
            source_kind: "proof_bundle".to_owned(),
            source_path: source_path.clone(),
            validator_report: source_path.clone(),
            controlling_lane: None,
            freshness: Some(proof_bundle_freshness(report)),
            host_class: None,
            missing_artifacts,
            remediation_bead: remediation_bead.clone(),
            next_safe_command: next_safe_command(
                remediation_bead.as_deref(),
                &report.reproduction_command,
            ),
            evidence_basis: vec![
                format!("proof_bundle:{}", report.bundle_id),
                format!("valid:{}", report.valid),
            ],
        });
    } else {
        for provenance in &report.lane_provenance {
            let mut missing_artifacts = Vec::new();
            if !provenance.raw_log_present {
                missing_artifacts.push(format!("raw log `{}`", provenance.raw_log_path));
            }
            missing_artifacts.extend(
                report
                    .broken_links
                    .iter()
                    .filter(|link| link.lane_id == provenance.lane_id)
                    .map(|link| format!("{} `{}`", link.field, link.path)),
            );
            let remediation_bead = builder.default_remediation_bead.clone();
            let claim_id = format!("proof_bundle:{}:{}", report.bundle_id, provenance.lane_id);
            produced_claim_ids.push(claim_id.clone());
            builder.push_claim(ReadinessDashboardClaimReport {
                claim_id,
                claim_state: proof_claim_effect_to_state(provenance.claim_effect, report.valid),
                source_kind: "proof_bundle".to_owned(),
                source_path: source_path.clone(),
                validator_report: source_path.clone(),
                controlling_lane: Some(provenance.lane_id.clone()),
                freshness: Some(provenance.freshness.clone()),
                host_class: Some(provenance.host_class.clone()),
                missing_artifacts,
                remediation_bead: remediation_bead.clone(),
                next_safe_command: next_safe_command(
                    remediation_bead.as_deref(),
                    &report.reproduction_command,
                ),
                evidence_basis: vec![
                    format!("proof_bundle:{}", report.bundle_id),
                    format!("lane_status:{}", proof_outcome_label(provenance.status)),
                    format!("claim_effect:{}", provenance.claim_effect.label()),
                    format!("source_command:{}", provenance.source_command),
                ],
            });
        }
    }

    for lane in &report.missing_required_lanes {
        let remediation_bead = builder.default_remediation_bead.clone();
        let claim_id = format!("proof_bundle:{}:missing:{lane}", report.bundle_id);
        produced_claim_ids.push(claim_id.clone());
        builder.push_claim(ReadinessDashboardClaimReport {
            claim_id,
            claim_state: ReadinessDashboardClaimState::Blocked,
            source_kind: "proof_bundle".to_owned(),
            source_path: source_path.clone(),
            validator_report: source_path.clone(),
            controlling_lane: Some(lane.clone()),
            freshness: Some(proof_bundle_freshness(report)),
            host_class: None,
            missing_artifacts: vec![format!("required proof-bundle lane `{lane}`")],
            remediation_bead: remediation_bead.clone(),
            next_safe_command: next_safe_command(
                remediation_bead.as_deref(),
                &report.reproduction_command,
            ),
            evidence_basis: vec![
                format!("proof_bundle:{}", report.bundle_id),
                "validator_reported_missing_required_lane".to_owned(),
            ],
        });
    }

    builder.push_source(ReadinessDashboardSourceReport {
        source_kind: "proof_bundle".to_owned(),
        path: source_path,
        valid: report.valid,
        summary: format!(
            "bundle={} lanes={} artifacts={} missing_required_lanes={}",
            report.bundle_id,
            report.totals.lanes,
            report.totals.artifacts,
            report.missing_required_lanes.len()
        ),
        referenced_beads: Vec::new(),
        produced_claim_ids,
    });
}

fn add_operational_evidence_index(
    builder: &mut DashboardBuilder,
    path: &Path,
    index: &OperationalEvidenceIndex,
) {
    let source_path = display_path(path);
    let mut produced_claim_ids = Vec::new();
    let records_by_id = index
        .records
        .iter()
        .map(|record| (record.record_id.as_str(), record))
        .collect::<BTreeMap<_, _>>();

    for selection in &index.selections {
        let Some(record) = records_by_id.get(selection.selected_record_id.as_str()) else {
            builder.report.warnings.push(format!(
                "{} selected missing record `{}`",
                source_path, selection.selected_record_id
            ));
            continue;
        };
        let remediation_bead = record
            .bead_id
            .clone()
            .or_else(|| builder.default_remediation_bead.clone());
        let claim_id = format!(
            "operational_evidence:{}:{}",
            selection.lane_id, selection.scenario_id
        );
        produced_claim_ids.push(claim_id.clone());
        builder.push_claim(ReadinessDashboardClaimReport {
            claim_id,
            claim_state: operational_claim_effect_to_state(selection.selected_release_claim_effect),
            source_kind: "operational_evidence_index".to_owned(),
            source_path: source_path.clone(),
            validator_report: source_path.clone(),
            controlling_lane: Some(selection.lane_id.clone()),
            freshness: Some(freshness_label(record.freshness).to_owned()),
            host_class: Some(host_class_label(record.host_class).to_owned()),
            missing_artifacts: operational_missing_artifacts(record),
            remediation_bead: remediation_bead.clone(),
            next_safe_command: next_safe_command(
                remediation_bead.as_deref(),
                record.reproduction_command.as_deref().unwrap_or(""),
            ),
            evidence_basis: vec![
                format!("readiness_report:{}", index.readiness_report_id),
                format!("record:{}", record.record_id),
                format!(
                    "effect:{}",
                    release_claim_effect_label(record.release_claim_effect)
                ),
            ],
        });
    }

    builder.push_source(ReadinessDashboardSourceReport {
        source_kind: "operational_evidence_index".to_owned(),
        path: source_path,
        valid: index.conflict_count == 0 && index.duplicate_run_id_count == 0,
        summary: format!(
            "records={} selected={} authoritative={} stale={} conflicts={}",
            index.source_record_count,
            index.selected_record_count,
            index.authoritative_record_count,
            index.stale_record_count,
            index.conflict_count
        ),
        referenced_beads: index
            .records
            .iter()
            .filter_map(|record| record.bead_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        produced_claim_ids,
    });
}

fn add_permissioned_campaign_report(builder: &mut DashboardBuilder, path: &Path, value: &Value) {
    let source_path = display_path(path);
    let source_kind = permissioned_source_kind(value);
    let valid = value.get("valid").and_then(Value::as_bool).unwrap_or(false);
    let product_evidence_claim =
        string_field(value, "product_evidence_claim").unwrap_or_else(|| "unknown".to_owned());
    let referenced_beads = permissioned_beads(value);
    let remediation_bead = referenced_beads
        .first()
        .cloned()
        .or_else(|| builder.default_remediation_bead.clone());
    let claim_id = permissioned_claim_id(value, &source_path);
    let claim_state = permissioned_claim_state(value, valid, product_evidence_claim.as_str());
    let missing_artifacts = permissioned_missing_artifacts(value, product_evidence_claim.as_str());
    let next_safe = next_safe_command(remediation_bead.as_deref(), "");

    builder.push_claim(ReadinessDashboardClaimReport {
        claim_id: claim_id.clone(),
        claim_state,
        source_kind: source_kind.clone(),
        source_path: source_path.clone(),
        validator_report: source_path.clone(),
        controlling_lane: string_field(value, "lane_kind"),
        freshness: string_field(value, "worker_fingerprint_age_days")
            .map(|days| format!("worker_fingerprint_age_days={days}")),
        host_class: permissioned_host_class(value),
        missing_artifacts,
        remediation_bead,
        next_safe_command: next_safe,
        evidence_basis: vec![
            format!("permissioned_source_kind:{source_kind}"),
            format!("product_evidence_claim:{product_evidence_claim}"),
        ],
    });
    builder.push_source(ReadinessDashboardSourceReport {
        source_kind,
        path: source_path,
        valid,
        summary: format!("product_evidence_claim={product_evidence_claim}"),
        referenced_beads,
        produced_claim_ids: vec![claim_id],
    });
}

fn recommendation_for_claim(
    claim: &ReadinessDashboardClaimReport,
) -> ReadinessDashboardRecommendation {
    let severity = match claim.claim_state {
        ReadinessDashboardClaimState::Blocked
        | ReadinessDashboardClaimState::Disabled
        | ReadinessDashboardClaimState::Hidden
        | ReadinessDashboardClaimState::Unknown => {
            ReadinessDashboardRecommendationSeverity::Blocker
        }
        ReadinessDashboardClaimState::HandoffOnly
        | ReadinessDashboardClaimState::DryRunOnly
        | ReadinessDashboardClaimState::DetectionOnly
        | ReadinessDashboardClaimState::Experimental
        | ReadinessDashboardClaimState::OptInMutating => {
            ReadinessDashboardRecommendationSeverity::FollowUp
        }
        ReadinessDashboardClaimState::Validated => ReadinessDashboardRecommendationSeverity::Info,
    };
    ReadinessDashboardRecommendation {
        action_id: format!("dashboard-{}-follow-up", sanitize_id(&claim.claim_id)),
        claim_id: claim.claim_id.clone(),
        severity,
        title: format!("Follow up readiness claim {}", claim.claim_id),
        validator_report: Some(claim.validator_report.clone()),
        bead_id: claim.remediation_bead.clone(),
        next_safe_command: claim.next_safe_command.clone(),
        rationale: format!(
            "claim is `{}` in `{}`; inspect the validator report before changing docs or parity wording",
            claim.claim_state.label(),
            claim.source_kind
        ),
        missing_artifacts: claim.missing_artifacts.clone(),
        controlling_lane: claim.controlling_lane.clone(),
    }
}

fn load_json<T>(path: &Path) -> Result<T>
where
    T: DeserializeOwned,
{
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))
}

fn load_tracker_beads(path: &Path) -> Result<Vec<ReadinessDashboardTrackerBead>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut beads = Vec::new();
    for (line_index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value = serde_json::from_str::<Value>(line).with_context(|| {
            format!(
                "failed to parse tracker row {} in {}",
                line_index + 1,
                path.display()
            )
        })?;
        let Some(issue_id) = string_field(&value, "id") else {
            continue;
        };
        if !issue_id.starts_with("bd-") {
            continue;
        }
        let status = string_field(&value, "status").unwrap_or_else(|| "unknown".to_owned());
        if !matches!(status.as_str(), "open" | "in_progress" | "blocked") {
            continue;
        }
        let title = string_field(&value, "title").unwrap_or_else(|| "(untitled)".to_owned());
        let priority = value.get("priority").map(value_to_string);
        beads.push(ReadinessDashboardTrackerBead {
            issue_id,
            status,
            title,
            priority,
        });
    }
    beads.sort_by(|left, right| left.issue_id.cmp(&right.issue_id));
    Ok(beads)
}

fn release_gate_missing_artifacts(
    findings: &[&crate::release_gate::ReleaseGateFinding],
) -> Vec<String> {
    let mut artifacts = BTreeSet::new();
    for finding in findings {
        if let Some(lane) = &finding.controlling_lane {
            artifacts.insert(format!("controlling lane `{lane}`"));
        }
        if finding.severity == ReleaseGateFindingSeverity::Block {
            artifacts.insert(finding.transition_reason.clone());
        }
        if let Some(hash) = &finding.controlling_artifact_hash {
            artifacts.insert(format!("artifact hash `{hash}`"));
        }
    }
    artifacts.into_iter().collect()
}

fn proof_bundle_missing_artifacts(report: &ProofBundleValidationReport) -> Vec<String> {
    let mut artifacts = BTreeSet::new();
    artifacts.extend(
        report
            .missing_required_lanes
            .iter()
            .map(|lane| format!("required lane `{lane}`")),
    );
    artifacts.extend(
        report
            .broken_links
            .iter()
            .map(|link| format!("{} `{}`", link.field, link.path)),
    );
    artifacts.extend(
        report
            .raw_log_hash_mismatches
            .iter()
            .map(|mismatch| format!("raw log hash `{}`", mismatch.path)),
    );
    artifacts.extend(
        report
            .artifact_hash_mismatches
            .iter()
            .map(|mismatch| format!("artifact hash `{}`", mismatch.path)),
    );
    artifacts.into_iter().collect()
}

fn operational_missing_artifacts(record: &OperationalEvidenceRecord) -> Vec<String> {
    let mut artifacts = Vec::new();
    if record.missing_raw_logs {
        artifacts.extend(
            record
                .raw_log_paths
                .iter()
                .map(|path| format!("raw log `{path}`")),
        );
    }
    if record.stale_git_sha {
        artifacts.push(format!("fresh git evidence for `{}`", record.git_sha));
    }
    if record.stale_artifact {
        artifacts.push(format!("fresh artifact `{}`", record.source_path));
    }
    artifacts
}

fn permissioned_missing_artifacts(value: &Value, product_evidence_claim: &str) -> Vec<String> {
    let mut artifacts = BTreeSet::new();
    artifacts.extend(string_array_field(value, "blockers"));
    artifacts.extend(string_array_field(value, "required_executed_evidence"));
    if product_evidence_claim == "none" {
        artifacts.extend(
            string_array_field(value, "expected_artifact_paths")
                .into_iter()
                .map(|path| format!("executed evidence artifact `{path}`")),
        );
    }
    if let Some(issues) = value.get("issues").and_then(Value::as_array) {
        artifacts.extend(
            issues
                .iter()
                .filter_map(|issue| string_field(issue, "message")),
        );
    }
    artifacts.into_iter().collect()
}

fn release_gate_evidence_basis(
    report: &ReleaseGateEvaluationReport,
    feature_id: &str,
) -> Vec<String> {
    let mut basis = vec![
        format!("policy:{}", report.policy_id),
        format!("bundle:{}", report.bundle_id),
    ];
    basis.extend(
        report
            .findings
            .iter()
            .filter(|finding| finding.feature_id == feature_id)
            .map(|finding| {
                format!(
                    "finding:{}:{}:{}",
                    finding.finding_id,
                    finding.severity.label(),
                    finding.transition_reason
                )
            }),
    );
    basis
}

fn feature_state_to_claim_state(state: FeatureState) -> ReadinessDashboardClaimState {
    match state {
        FeatureState::Validated => ReadinessDashboardClaimState::Validated,
        FeatureState::OptInMutating => ReadinessDashboardClaimState::OptInMutating,
        FeatureState::Experimental => ReadinessDashboardClaimState::Experimental,
        FeatureState::DetectionOnly => ReadinessDashboardClaimState::DetectionOnly,
        FeatureState::DryRunOnly => ReadinessDashboardClaimState::DryRunOnly,
        FeatureState::Hidden => ReadinessDashboardClaimState::Hidden,
        FeatureState::Disabled | FeatureState::DeprecatedBlocked => {
            ReadinessDashboardClaimState::Disabled
        }
    }
}

fn proof_claim_effect_to_state(
    effect: ProofBundleClaimEffect,
    report_valid: bool,
) -> ReadinessDashboardClaimState {
    if !report_valid && effect.strengthens_public_claim() {
        return ReadinessDashboardClaimState::Blocked;
    }
    match effect {
        ProofBundleClaimEffect::StrengthensPublicClaim => ReadinessDashboardClaimState::Validated,
        ProofBundleClaimEffect::BlocksPublicClaim
        | ProofBundleClaimEffect::EvidenceProductionFailure => {
            ReadinessDashboardClaimState::Blocked
        }
        ProofBundleClaimEffect::ExperimentalOnly => ReadinessDashboardClaimState::Experimental,
        ProofBundleClaimEffect::HandoffOnly => ReadinessDashboardClaimState::HandoffOnly,
        ProofBundleClaimEffect::DoesNotStrengthenPublicClaim => {
            ReadinessDashboardClaimState::Unknown
        }
    }
}

fn operational_claim_effect_to_state(
    effect: OperationalEvidenceReleaseClaimEffect,
) -> ReadinessDashboardClaimState {
    match effect {
        OperationalEvidenceReleaseClaimEffect::Strengthens => {
            ReadinessDashboardClaimState::Validated
        }
        OperationalEvidenceReleaseClaimEffect::Blocks
        | OperationalEvidenceReleaseClaimEffect::Downgrades => {
            ReadinessDashboardClaimState::Blocked
        }
        OperationalEvidenceReleaseClaimEffect::FollowUpOnly => {
            ReadinessDashboardClaimState::HandoffOnly
        }
        OperationalEvidenceReleaseClaimEffect::None => ReadinessDashboardClaimState::Unknown,
    }
}

fn permissioned_claim_state(
    value: &Value,
    valid: bool,
    product_evidence_claim: &str,
) -> ReadinessDashboardClaimState {
    if !valid {
        return ReadinessDashboardClaimState::Blocked;
    }
    if product_evidence_claim == "none" {
        return ReadinessDashboardClaimState::HandoffOnly;
    }
    match string_field(value, "final_status").as_deref() {
        Some("passed" | "pass") => ReadinessDashboardClaimState::Validated,
        Some("failed" | "fail" | "blocked" | "error") => ReadinessDashboardClaimState::Blocked,
        _ => ReadinessDashboardClaimState::Unknown,
    }
}

fn proof_bundle_freshness(report: &ProofBundleValidationReport) -> String {
    if let Some(stale) = &report.stale_timestamp {
        return format!(
            "stale generated_at={} max_age_days={}",
            stale.generated_at, stale.max_age_days
        );
    }
    if let Some(stale) = &report.stale_git_sha {
        return format!(
            "stale_git_sha observed={} expected={}",
            stale.observed, stale.expected
        );
    }
    "validator_reported_fresh_or_unchecked".to_owned()
}

fn permissioned_source_kind(value: &Value) -> String {
    if value.get("candidate_for_authorized_run").is_some() {
        "swarm_capability_calibration".to_owned()
    } else if value.get("final_status").is_some() {
        "permissioned_campaign_execution_ledger".to_owned()
    } else if value.get("authorization_notice").is_some() {
        "permissioned_campaign_handoff_packet".to_owned()
    } else {
        "permissioned_campaign_broker".to_owned()
    }
}

fn permissioned_claim_id(value: &Value, source_path: &str) -> String {
    string_field(value, "campaign_id")
        .or_else(|| string_field(value, "packet_id"))
        .map_or_else(
            || format!("permissioned:{}", sanitize_id(source_path)),
            |id| format!("permissioned:{id}"),
        )
}

fn permissioned_beads(value: &Value) -> Vec<String> {
    let mut beads = BTreeSet::new();
    beads.extend(
        string_array_field(value, "target_beads")
            .into_iter()
            .filter(|id| id.starts_with("bd-")),
    );
    if let Some(bead) = string_field(value, "real_campaign_bead")
        && bead.starts_with("bd-")
    {
        beads.insert(bead);
    }
    beads.into_iter().collect()
}

fn permissioned_host_class(value: &Value) -> Option<String> {
    string_field(value, "classification")
        .or_else(|| {
            value
                .get("preflight_snapshot")
                .and_then(|snapshot| string_field(snapshot, "host_class"))
        })
        .or_else(|| {
            value
                .get("host_facts")
                .and_then(Value::as_array)
                .and_then(|facts| {
                    facts.iter().find_map(|fact| {
                        let fact_id = string_field(fact, "fact_id")?;
                        if fact_id.contains("host_class") {
                            string_field(fact, "observed_value")
                        } else {
                            None
                        }
                    })
                })
        })
}

fn string_field(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .map(value_to_string)
        .filter(|value| !value.is_empty())
}

fn string_array_field(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(value_to_string)
                .filter(|item| !item.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn value_to_string(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned)
}

fn bead_like(raw: &str) -> Option<String> {
    raw.split(|character: char| {
        !(character.is_ascii_alphanumeric() || matches!(character, '-' | '.'))
    })
    .find(|token| token.starts_with("bd-"))
    .map(str::to_owned)
}

fn next_safe_command(remediation_bead: Option<&str>, reproduction_command: &str) -> String {
    remediation_bead.map_or_else(
        || {
            if reproduction_command.trim().is_empty() {
                "br ready --no-db --json".to_owned()
            } else {
                reproduction_command.to_owned()
            }
        },
        bead_show_command,
    )
}

fn bead_show_command(bead_id: &str) -> String {
    format!("br show {bead_id} --no-db --json")
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
}

fn sanitize_id(raw: &str) -> String {
    raw.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn markdown_list(items: &[String]) -> String {
    if items.is_empty() {
        String::new()
    } else {
        items
            .iter()
            .map(|item| format!("`{item}`"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn severity_label(severity: ReadinessDashboardRecommendationSeverity) -> &'static str {
    match severity {
        ReadinessDashboardRecommendationSeverity::Info => "info",
        ReadinessDashboardRecommendationSeverity::FollowUp => "follow_up",
        ReadinessDashboardRecommendationSeverity::Blocker => "blocker",
    }
}

fn proof_outcome_label(outcome: ProofBundleOutcome) -> &'static str {
    outcome.label()
}

fn freshness_label(freshness: OperationalEvidenceFreshness) -> &'static str {
    match freshness {
        OperationalEvidenceFreshness::NotChecked => "not_checked",
        OperationalEvidenceFreshness::Fresh => "fresh",
        OperationalEvidenceFreshness::Stale => "stale",
    }
}

fn host_class_label(host_class: OperationalEvidenceHostClass) -> &'static str {
    match host_class {
        OperationalEvidenceHostClass::PermissionedLargeHost => "permissioned_large_host",
        OperationalEvidenceHostClass::DeveloperSmoke => "developer_smoke",
        OperationalEvidenceHostClass::SmallHostSmoke => "small_host_smoke",
        OperationalEvidenceHostClass::CapabilityDowngraded => "capability_downgraded",
        OperationalEvidenceHostClass::Unknown => "unknown",
        OperationalEvidenceHostClass::NotApplicable => "not_applicable",
    }
}

fn release_claim_effect_label(effect: OperationalEvidenceReleaseClaimEffect) -> &'static str {
    match effect {
        OperationalEvidenceReleaseClaimEffect::Strengthens => "strengthens",
        OperationalEvidenceReleaseClaimEffect::Blocks => "blocks",
        OperationalEvidenceReleaseClaimEffect::Downgrades => "downgrades",
        OperationalEvidenceReleaseClaimEffect::FollowUpOnly => "follow_up_only",
        OperationalEvidenceReleaseClaimEffect::None => "none",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_state_mapping_covers_dashboard_claim_states() {
        let states = [
            feature_state_to_claim_state(FeatureState::Validated),
            feature_state_to_claim_state(FeatureState::OptInMutating),
            feature_state_to_claim_state(FeatureState::Experimental),
            feature_state_to_claim_state(FeatureState::DetectionOnly),
            feature_state_to_claim_state(FeatureState::DryRunOnly),
            feature_state_to_claim_state(FeatureState::Disabled),
            feature_state_to_claim_state(FeatureState::DeprecatedBlocked),
            feature_state_to_claim_state(FeatureState::Hidden),
            proof_claim_effect_to_state(ProofBundleClaimEffect::HandoffOnly, true),
            proof_claim_effect_to_state(ProofBundleClaimEffect::BlocksPublicClaim, true),
            proof_claim_effect_to_state(ProofBundleClaimEffect::DoesNotStrengthenPublicClaim, true),
        ];
        assert!(states.contains(&ReadinessDashboardClaimState::Validated));
        assert!(states.contains(&ReadinessDashboardClaimState::OptInMutating));
        assert!(states.contains(&ReadinessDashboardClaimState::Experimental));
        assert!(states.contains(&ReadinessDashboardClaimState::DetectionOnly));
        assert!(states.contains(&ReadinessDashboardClaimState::DryRunOnly));
        assert!(states.contains(&ReadinessDashboardClaimState::Disabled));
        assert!(states.contains(&ReadinessDashboardClaimState::Hidden));
        assert!(states.contains(&ReadinessDashboardClaimState::HandoffOnly));
        assert!(states.contains(&ReadinessDashboardClaimState::Blocked));
        assert!(states.contains(&ReadinessDashboardClaimState::Unknown));
    }

    #[test]
    fn missing_inputs_emit_tracker_linked_recommendation() {
        let report = build_readiness_dashboard(&ReadinessDashboardConfig {
            default_remediation_bead: Some("bd-4v16z.10".to_owned()),
            ..ReadinessDashboardConfig::default()
        })
        .expect("dashboard without inputs");

        assert!(report.valid);
        assert_eq!(report.claim_count, 0);
        assert_eq!(report.recommendation_count, 1);
        let recommendation = &report.recommendations[0];
        assert_eq!(recommendation.bead_id.as_deref(), Some("bd-4v16z.10"));
        assert!(recommendation.validator_report.is_none());
        assert!(recommendation.next_safe_command.contains("bd-4v16z.10"));
    }

    #[test]
    fn release_gate_report_preserves_validator_and_remediation_links() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("release_gate.json");
        fs::write(
            &path,
            r#"{
  "schema_version": 1,
  "policy_id": "policy-a",
  "bundle_id": "bundle-a",
  "valid": true,
  "release_ready": false,
  "proof_bundle_valid": true,
  "feature_reports": [
    {
      "feature_id": "mount.rw.ext4",
      "docs_wording_id": "docs-mount",
      "previous_state": "experimental",
      "target_state": "validated",
      "final_state": "validated",
      "upgrade_allowed": true,
      "finding_ids": []
    },
    {
      "feature_id": "xfstests.baseline",
      "docs_wording_id": "docs-xfstests",
      "previous_state": "hidden",
      "target_state": "validated",
      "final_state": "hidden",
      "upgrade_allowed": false,
      "finding_ids": ["missing-xfstests"]
    }
  ],
  "findings": [
    {
      "finding_id": "missing-xfstests",
      "feature_id": "xfstests.baseline",
      "severity": "block",
      "previous_state": "hidden",
      "proposed_state": "validated",
      "final_state": "hidden",
      "transition_reason": "fresh permissioned xfstests baseline proof lane is missing",
      "controlling_lane": "xfstests",
      "remediation_id": "bd-rchk3.3",
      "docs_wording_id": "docs-xfstests",
      "reproduction_command": "cargo run -p ffs-harness -- evaluate-release-gates --bundle bundle.json --policy policy.json"
    }
  ],
  "generated_wording": [],
  "required_log_fields": [],
  "errors": [],
  "warnings": [],
  "reproduction_command": "cargo run -p ffs-harness -- evaluate-release-gates --bundle bundle.json --policy policy.json"
}"#,
        )
        .expect("write release gate");

        let report = build_readiness_dashboard(&ReadinessDashboardConfig {
            release_gate_reports: vec![path.clone()],
            default_remediation_bead: Some("bd-4v16z.10".to_owned()),
            ..ReadinessDashboardConfig::default()
        })
        .expect("dashboard");

        assert_eq!(report.claim_count, 2);
        let validated = report
            .claims
            .iter()
            .find(|claim| claim.claim_id == "release_gate:mount.rw.ext4")
            .expect("validated claim");
        assert_eq!(
            validated.claim_state,
            ReadinessDashboardClaimState::Validated
        );
        let hidden = report
            .claims
            .iter()
            .find(|claim| claim.claim_id == "release_gate:xfstests.baseline")
            .expect("hidden claim");
        assert_eq!(hidden.claim_state, ReadinessDashboardClaimState::Hidden);
        assert_eq!(hidden.controlling_lane.as_deref(), Some("xfstests"));
        assert_eq!(hidden.remediation_bead.as_deref(), Some("bd-rchk3.3"));
        assert_eq!(report.recommendation_count, 1);
        let expected_path = path.display().to_string();
        assert_eq!(
            report.recommendations[0].validator_report.as_deref(),
            Some(expected_path.as_str())
        );
    }

    #[test]
    fn permissioned_handoff_stays_non_product_evidence() {
        let mut builder = DashboardBuilder::new(&ReadinessDashboardConfig {
            default_remediation_bead: Some("bd-4v16z.10".to_owned()),
            ..ReadinessDashboardConfig::default()
        });
        let value = serde_json::json!({
            "schema_version": 1,
            "campaign_id": "swarm-large-host",
            "lane_kind": "swarm.responsiveness",
            "valid": true,
            "product_evidence_claim": "none",
            "target_beads": ["bd-rchk0.53.8"],
            "required_executed_evidence": ["raw workload logs", "p99 attribution ledger"],
            "expected_artifact_paths": ["swarm/report.json"]
        });
        add_permissioned_campaign_report(&mut builder, Path::new("handoff.json"), &value);
        let report = builder.finish();

        assert_eq!(
            report.claims[0].claim_state,
            ReadinessDashboardClaimState::HandoffOnly
        );
        assert_eq!(
            report.claims[0].remediation_bead.as_deref(),
            Some("bd-rchk0.53.8")
        );
        assert!(
            report.claims[0]
                .missing_artifacts
                .iter()
                .any(|artifact| artifact.contains("raw workload logs"))
        );
        assert_eq!(report.recommendation_count, 1);
        assert_eq!(
            report.recommendations[0].bead_id.as_deref(),
            Some("bd-rchk0.53.8")
        );
    }

    #[test]
    fn tracker_jsonl_filters_local_follow_up_beads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("issues.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"id\":\"bd-4v16z.10\",\"title\":\"Dashboard\",\"status\":\"in_progress\",\"priority\":3}\n",
                "{\"id\":\"br-r37-c1\",\"title\":\"Foreign\",\"status\":\"open\",\"priority\":1}\n",
                "{\"id\":\"bd-done\",\"title\":\"Closed\",\"status\":\"closed\",\"priority\":2}\n"
            ),
        )
        .expect("write tracker");

        let beads = load_tracker_beads(&path).expect("tracker beads");
        assert_eq!(beads.len(), 1);
        assert_eq!(beads[0].issue_id, "bd-4v16z.10");
        assert_eq!(beads[0].status, "in_progress");
    }
}
