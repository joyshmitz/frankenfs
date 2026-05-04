#![allow(clippy::too_many_lines)]
#![forbid(unsafe_code)]

//! Operator decision report for the `bd-p2j3e` swarm performance workstream.
//!
//! The report is deliberately data-backed: every card must carry invariants,
//! evidence, fallback behavior, expected-loss policy, validation commands, and
//! downstream proof/release-gate consumers before it can inform public claims.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub const DEFAULT_SWARM_OPERATOR_REPORT: &str = "benchmarks/swarm_operator_report.json";
pub const SWARM_OPERATOR_REPORT_SCHEMA_VERSION: u32 = 1;

const REQUIRED_CARD_IDS: [&str; 6] = [
    "tail_latency_decomposition",
    "numa_shard_harness",
    "rcu_qsbr_metadata",
    "parallel_wal_group_commit",
    "cache_budget_controller",
    "scrub_repair_scheduler",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmOperatorReport {
    pub schema_version: u32,
    pub report_id: String,
    pub generated_at: String,
    #[serde(default)]
    pub required_card_ids: Vec<String>,
    #[serde(default)]
    pub proof_bundle_consumers: Vec<String>,
    #[serde(default)]
    pub release_gate_consumers: Vec<String>,
    pub cards: Vec<SwarmOperatorCard>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmOperatorCard {
    pub idea_id: String,
    pub title: String,
    pub source_lane: String,
    pub selected_algorithmic_pattern: String,
    pub invariants: Vec<String>,
    pub evidence: Vec<SwarmOperatorEvidence>,
    pub expected_loss_rule: String,
    pub fallback: String,
    pub validation_command: String,
    pub release_claim_state: SwarmOperatorReleaseClaimState,
    pub linked_bead_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmOperatorEvidence {
    pub evidence_id: String,
    pub summary: String,
    pub artifact_paths: Vec<String>,
    pub validation_command: String,
    pub linked_bead_id: String,
    pub release_claim_state: SwarmOperatorReleaseClaimState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmOperatorReleaseClaimState {
    DesignOnly,
    Experimental,
    FixtureSmokeOnly,
    SmallHostSmoke,
    MeasuredLocal,
    MeasuredAuthoritative,
    Blocked,
}

impl SwarmOperatorReleaseClaimState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DesignOnly => "design_only",
            Self::Experimental => "experimental",
            Self::FixtureSmokeOnly => "fixture_smoke_only",
            Self::SmallHostSmoke => "small_host_smoke",
            Self::MeasuredLocal => "measured_local",
            Self::MeasuredAuthoritative => "measured_authoritative",
            Self::Blocked => "blocked",
        }
    }

    #[must_use]
    pub const fn requires_measurement_evidence(self) -> bool {
        matches!(self, Self::MeasuredLocal | Self::MeasuredAuthoritative)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmOperatorValidationReport {
    pub schema_version: u32,
    pub report_id: String,
    pub valid: bool,
    pub card_count: usize,
    pub required_card_count: usize,
    pub proof_bundle_consumers: Vec<String>,
    pub release_gate_consumers: Vec<String>,
    pub proof_bundle_consumer_count: usize,
    pub release_gate_consumer_count: usize,
    pub claim_state_counts: BTreeMap<String, usize>,
    pub cards: Vec<SwarmOperatorCardSummary>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmOperatorCardSummary {
    pub idea_id: String,
    pub source_lane: String,
    pub selected_algorithmic_pattern: String,
    pub release_claim_state: String,
    pub evidence_count: usize,
    pub linked_bead_ids: Vec<String>,
}

pub fn load_swarm_operator_report(path: &Path) -> Result<SwarmOperatorReport> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read swarm operator report {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("invalid swarm operator report JSON {}", path.display()))
}

#[must_use]
pub fn validate_swarm_operator_report(
    report: &SwarmOperatorReport,
) -> SwarmOperatorValidationReport {
    let mut errors = validate_report_shape(report);
    let required_card_count = REQUIRED_CARD_IDS.len();
    let mut seen = BTreeSet::new();
    let mut card_summaries = Vec::new();

    for card in &report.cards {
        validate_card(card, &mut seen, &mut errors);
        card_summaries.push(SwarmOperatorCardSummary {
            idea_id: card.idea_id.clone(),
            source_lane: card.source_lane.clone(),
            selected_algorithmic_pattern: card.selected_algorithmic_pattern.clone(),
            release_claim_state: card.release_claim_state.label().to_owned(),
            evidence_count: card.evidence.len(),
            linked_bead_ids: card.linked_bead_ids.clone(),
        });
    }

    validate_required_cards(report, &seen, &mut errors);

    SwarmOperatorValidationReport {
        schema_version: SWARM_OPERATOR_REPORT_SCHEMA_VERSION,
        report_id: report.report_id.clone(),
        valid: errors.is_empty(),
        card_count: report.cards.len(),
        required_card_count,
        proof_bundle_consumers: report.proof_bundle_consumers.clone(),
        release_gate_consumers: report.release_gate_consumers.clone(),
        proof_bundle_consumer_count: report.proof_bundle_consumers.len(),
        release_gate_consumer_count: report.release_gate_consumers.len(),
        claim_state_counts: count_claim_states(report),
        cards: card_summaries,
        errors,
    }
}

pub fn fail_on_swarm_operator_report_errors(report: &SwarmOperatorValidationReport) -> Result<()> {
    if report.valid {
        Ok(())
    } else {
        bail!(
            "swarm operator report invalid: {} error(s)",
            report.errors.len()
        )
    }
}

#[must_use]
pub fn render_swarm_operator_report_markdown(report: &SwarmOperatorValidationReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Swarm Operator Decision Report");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Report: `{}`", report.report_id);
    let _ = writeln!(out, "- Valid: `{}`", report.valid);
    let _ = writeln!(out, "- Cards: `{}`", report.card_count);
    let _ = writeln!(out, "- Required cards: `{}`", report.required_card_count);
    let _ = writeln!(
        out,
        "- Proof-bundle consumers: `{}`",
        report.proof_bundle_consumers.join(", ")
    );
    let _ = writeln!(
        out,
        "- Release-gate consumers: `{}`",
        report.release_gate_consumers.join(", ")
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "| Idea | Lane | Pattern | Claim | Evidence | Beads |");
    let _ = writeln!(out, "|------|------|---------|-------|----------|-------|");
    for card in &report.cards {
        let _ = writeln!(
            out,
            "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |",
            card.idea_id,
            card.source_lane,
            card.selected_algorithmic_pattern,
            card.release_claim_state,
            card.evidence_count,
            card.linked_bead_ids.join(", ")
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

fn validate_report_shape(report: &SwarmOperatorReport) -> Vec<String> {
    let mut errors = Vec::new();
    if report.schema_version != SWARM_OPERATOR_REPORT_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version must be {}; got {}",
            SWARM_OPERATOR_REPORT_SCHEMA_VERSION, report.schema_version
        ));
    }
    require_non_empty("report_id", &report.report_id, &mut errors);
    require_non_empty("generated_at", &report.generated_at, &mut errors);
    if report.cards.is_empty() {
        errors.push("cards must not be empty".to_owned());
    }
    validate_required_card_declarations(report, &mut errors);
    validate_non_empty_paths(
        "proof_bundle_consumers",
        &report.proof_bundle_consumers,
        &mut errors,
    );
    validate_non_empty_paths(
        "release_gate_consumers",
        &report.release_gate_consumers,
        &mut errors,
    );
    errors
}

fn validate_required_card_declarations(report: &SwarmOperatorReport, errors: &mut Vec<String>) {
    let declared = report
        .required_card_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for required in REQUIRED_CARD_IDS {
        if !declared.contains(required) {
            errors.push(format!("required_card_ids missing {required}"));
        }
    }
}

fn validate_required_cards(
    report: &SwarmOperatorReport,
    seen: &BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    for required in REQUIRED_CARD_IDS {
        if !seen.contains(required) {
            errors.push(format!("cards missing required idea_id {required}"));
        }
    }
    for required in &report.required_card_ids {
        if !seen.contains(required) {
            errors.push(format!("cards missing declared idea_id {required}"));
        }
    }
}

fn validate_card(card: &SwarmOperatorCard, seen: &mut BTreeSet<String>, errors: &mut Vec<String>) {
    require_non_empty("card.idea_id", &card.idea_id, errors);
    require_non_empty("card.title", &card.title, errors);
    require_non_empty("card.source_lane", &card.source_lane, errors);
    require_non_empty(
        "card.selected_algorithmic_pattern",
        &card.selected_algorithmic_pattern,
        errors,
    );
    require_non_empty("card.expected_loss_rule", &card.expected_loss_rule, errors);
    require_non_empty("card.fallback", &card.fallback, errors);
    require_non_empty("card.validation_command", &card.validation_command, errors);
    validate_non_empty_paths("card.invariants", &card.invariants, errors);
    validate_non_empty_paths("card.linked_bead_ids", &card.linked_bead_ids, errors);
    if !card.idea_id.is_empty() && !seen.insert(card.idea_id.clone()) {
        errors.push(format!("duplicate idea_id {}", card.idea_id));
    }
    validate_evidence(card, errors);
}

fn validate_evidence(card: &SwarmOperatorCard, errors: &mut Vec<String>) {
    if card.evidence.is_empty() {
        errors.push(format!("card {} evidence must not be empty", card.idea_id));
    }

    let mut seen = BTreeSet::new();
    for evidence in &card.evidence {
        require_non_empty("evidence.evidence_id", &evidence.evidence_id, errors);
        require_non_empty("evidence.summary", &evidence.summary, errors);
        require_non_empty(
            "evidence.validation_command",
            &evidence.validation_command,
            errors,
        );
        require_non_empty("evidence.linked_bead_id", &evidence.linked_bead_id, errors);
        validate_non_empty_paths("evidence.artifact_paths", &evidence.artifact_paths, errors);
        if !evidence.evidence_id.is_empty() && !seen.insert(evidence.evidence_id.clone()) {
            errors.push(format!(
                "card {} duplicates evidence_id {}",
                card.idea_id, evidence.evidence_id
            ));
        }
        if !evidence.linked_bead_id.is_empty()
            && !card.linked_bead_ids.contains(&evidence.linked_bead_id)
        {
            errors.push(format!(
                "card {} evidence {} references unlinked bead {}",
                card.idea_id, evidence.evidence_id, evidence.linked_bead_id
            ));
        }
    }

    if card.release_claim_state.requires_measurement_evidence()
        && !has_measurement_evidence_for_claim(card)
    {
        errors.push(format!(
            "card {} claims {} without matching measurement evidence",
            card.idea_id,
            card.release_claim_state.label()
        ));
    }
}

fn has_measurement_evidence_for_claim(card: &SwarmOperatorCard) -> bool {
    card.evidence.iter().any(|evidence| {
        evidence.release_claim_state >= card.release_claim_state
            && !evidence.artifact_paths.is_empty()
            && !evidence.validation_command.trim().is_empty()
    })
}

fn count_claim_states(report: &SwarmOperatorReport) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for card in &report.cards {
        *counts
            .entry(card.release_claim_state.label().to_owned())
            .or_insert(0) += 1;
    }
    counts
}

fn require_non_empty(field: &str, value: &str, errors: &mut Vec<String>) {
    if value.trim().is_empty() {
        errors.push(format!("{field} must not be empty"));
    }
}

fn validate_non_empty_paths(field: &str, values: &[String], errors: &mut Vec<String>) {
    if values.is_empty() {
        errors.push(format!("{field} must not be empty"));
    }
    for value in values {
        require_non_empty(field, value, errors);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_in_swarm_operator_report_validates() {
        let report: SwarmOperatorReport = serde_json::from_str(include_str!(
            "../../../benchmarks/swarm_operator_report.json"
        ))
        .expect("checked-in report parses");
        let validation = validate_swarm_operator_report(&report);

        assert!(validation.valid, "{:?}", validation.errors);
        assert_eq!(validation.card_count, REQUIRED_CARD_IDS.len());
        assert_eq!(validation.required_card_count, REQUIRED_CARD_IDS.len());
    }

    #[test]
    fn missing_invariants_fail() {
        let mut report = sample_report();
        report.cards[0].invariants.clear();

        let validation = validate_swarm_operator_report(&report);

        assert!(!validation.valid);
        assert!(
            validation
                .errors
                .iter()
                .any(|error| error.contains("card.invariants"))
        );
    }

    #[test]
    fn missing_fallback_fails() {
        let mut report = sample_report();
        report.cards[0].fallback.clear();

        let validation = validate_swarm_operator_report(&report);

        assert!(!validation.valid);
        assert!(
            validation
                .errors
                .iter()
                .any(|error| error.contains("card.fallback"))
        );
    }

    #[test]
    fn missing_validation_command_fails() {
        let mut report = sample_report();
        report.cards[0].validation_command.clear();

        let validation = validate_swarm_operator_report(&report);

        assert!(!validation.valid);
        assert!(
            validation
                .errors
                .iter()
                .any(|error| error.contains("card.validation_command"))
        );
    }

    #[test]
    fn duplicate_idea_ids_fail() {
        let mut report = sample_report();
        let duplicate_idea_id = report.cards[0].idea_id.clone();
        report.cards[1].idea_id = duplicate_idea_id;

        let validation = validate_swarm_operator_report(&report);

        assert!(!validation.valid);
        assert!(
            validation
                .errors
                .iter()
                .any(|error| error.contains("duplicate idea_id"))
        );
    }

    #[test]
    fn claim_upgrade_without_evidence_fails() {
        let mut report = sample_report();
        report.cards[0].release_claim_state = SwarmOperatorReleaseClaimState::MeasuredAuthoritative;
        report.cards[0].evidence[0].release_claim_state =
            SwarmOperatorReleaseClaimState::Experimental;

        let validation = validate_swarm_operator_report(&report);

        assert!(!validation.valid);
        assert!(
            validation
                .errors
                .iter()
                .any(|error| error.contains("without matching measurement evidence"))
        );
    }

    #[test]
    fn markdown_is_generated_from_validation_rows() {
        let validation = validate_swarm_operator_report(&sample_report());
        let markdown = render_swarm_operator_report_markdown(&validation);

        assert!(markdown.contains("# Swarm Operator Decision Report"));
        assert!(markdown.contains("tail_latency_decomposition"));
        assert!(markdown.contains("proof-bundle"));
    }

    fn sample_report() -> SwarmOperatorReport {
        SwarmOperatorReport {
            schema_version: SWARM_OPERATOR_REPORT_SCHEMA_VERSION,
            report_id: "bd-p2j3e.7-swarm-operator-report-test".to_owned(),
            generated_at: "2026-05-04T00:00:00Z".to_owned(),
            required_card_ids: REQUIRED_CARD_IDS
                .iter()
                .map(|id| (*id).to_owned())
                .collect(),
            proof_bundle_consumers: vec!["proof-bundle".to_owned()],
            release_gate_consumers: vec!["release-gate".to_owned()],
            cards: REQUIRED_CARD_IDS
                .iter()
                .enumerate()
                .map(|(index, idea_id)| sample_card(idea_id, index))
                .collect(),
        }
    }

    fn sample_card(idea_id: &str, index: usize) -> SwarmOperatorCard {
        let bead_id = format!("bd-p2j3e.{}", index + 1);
        SwarmOperatorCard {
            idea_id: idea_id.to_owned(),
            title: format!("operator card for {idea_id}"),
            source_lane: bead_id.clone(),
            selected_algorithmic_pattern: format!("{idea_id}_pattern"),
            invariants: vec!["claim_state_is_explicit".to_owned()],
            evidence: vec![SwarmOperatorEvidence {
                evidence_id: format!("{idea_id}_evidence"),
                summary: "focused validator passed".to_owned(),
                artifact_paths: vec![format!("benchmarks/{idea_id}.json")],
                validation_command: "cargo test -p ffs-harness swarm_operator_report".to_owned(),
                linked_bead_id: bead_id.clone(),
                release_claim_state: SwarmOperatorReleaseClaimState::Experimental,
            }],
            expected_loss_rule: "prefer conservative fallback until evidence is current".to_owned(),
            fallback: "keep current conservative behavior".to_owned(),
            validation_command: "cargo test -p ffs-harness swarm_operator_report".to_owned(),
            release_claim_state: SwarmOperatorReleaseClaimState::Experimental,
            linked_bead_ids: vec![bead_id],
        }
    }
}
