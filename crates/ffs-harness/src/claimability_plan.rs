#![allow(clippy::module_name_repetitions)]
#![forbid(unsafe_code)]

use crate::tracker_source_hygiene::{
    AgentMailReservationSnapshotReport, TrackerDependencyStatus, TrackerIssueProgressRow,
    TrackerIssueSample, TrackerIssueWorkRow, TrackerPermissionGate, TrackerPermissionGatedRow,
    TrackerSourceHygieneReport,
};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

pub const CLAIMABILITY_PLAN_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimabilityPlanConfig {
    pub generated_at: String,
    pub tracker_report_path: String,
    pub reservation_report_path: Option<String>,
    pub bv_report_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimabilityPlanReport {
    pub schema_version: u32,
    pub status: String,
    pub generated_at: String,
    pub mutation_policy: String,
    pub tracker_report_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reservation_report_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bv_report_path: Option<String>,
    pub tracker_queue_verdict: String,
    pub source_aware_claimable_ids: Vec<String>,
    pub reservation_snapshot: ClaimabilityReservationSnapshotSummary,
    pub bv_snapshot: ClaimabilityBvSnapshotSummary,
    pub rows: Vec<ClaimabilityPlanRow>,
    pub next_safe_actions: Vec<String>,
    pub reproduction_commands: Vec<String>,
    pub validation: ClaimabilityPlanValidationReport,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimabilityReservationSnapshotSummary {
    pub present: bool,
    pub source_freshness: String,
    pub conflict_classification: String,
    pub active_peer_conflict_count: usize,
    pub target_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimabilityBvSnapshotSummary {
    pub present: bool,
    pub recommendation_count: usize,
    pub parent_epic_recommendation_ids: Vec<String>,
    pub suppressed_parent_epic_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimabilityPlanRow {
    pub id: String,
    pub title: String,
    pub status: String,
    pub priority: Option<i64>,
    pub issue_type: Option<String>,
    pub source_repo: Option<String>,
    pub assignee: Option<String>,
    pub classification: ClaimabilityClassification,
    pub reason: String,
    pub blocked_by: Vec<TrackerDependencyStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_gate: Option<TrackerPermissionGate>,
    pub owner_handoff_required: bool,
    pub next_safe_actions: Vec<String>,
    pub reproduction_commands: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimabilityClassification {
    Claimable,
    PermissionGated,
    Blocked,
    ReservedByPeer,
    ParentEpic,
    StaleInProgressReclaimCandidate,
    ForeignExcluded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimabilityPlanValidationReport {
    pub schema_version: u32,
    pub valid: bool,
    pub row_count: usize,
    pub classifications_seen: Vec<ClaimabilityClassification>,
    pub errors: Vec<String>,
}

#[must_use]
pub fn build_claimability_plan_report(
    config: &ClaimabilityPlanConfig,
    tracker_report: &TrackerSourceHygieneReport,
    reservation_report: Option<&AgentMailReservationSnapshotReport>,
    bv_snapshot: Option<&Value>,
) -> ClaimabilityPlanReport {
    let reservation_snapshot = reservation_summary(reservation_report);
    let active_peer_conflict = reservation_snapshot.active_peer_conflict_count > 0;
    let parent_epic_ids = parent_epic_ids(tracker_report);
    let bv_snapshot = bv_summary(bv_snapshot, &parent_epic_ids, tracker_report);
    let mut rows = BTreeMap::new();

    for row in &tracker_report.source_aware_ready_rows {
        let classification = if active_peer_conflict {
            ClaimabilityClassification::ReservedByPeer
        } else {
            ClaimabilityClassification::Claimable
        };
        insert_row(
            &mut rows,
            plan_row_from_work_row(row, classification, reservation_report),
        );
    }
    for row in &tracker_report.permission_gated_rows {
        insert_row(&mut rows, plan_row_from_permission_gated_row(row));
    }
    for row in &tracker_report.blocked_local_rows {
        insert_row(&mut rows, plan_row_from_blocked_row(row));
    }
    for row in tracker_report
        .local_nonclaimable_rows
        .iter()
        .filter(|row| row.reason == "epic")
    {
        insert_row(&mut rows, plan_row_from_epic_row(row));
    }
    for row in &tracker_report.stale_in_progress_rows {
        insert_row(&mut rows, plan_row_from_stale_row(row));
    }
    for row in &tracker_report.foreign_open_samples {
        insert_row(&mut rows, plan_row_from_foreign_sample(row));
    }

    let rows: Vec<ClaimabilityPlanRow> = rows.into_values().collect();
    let mut next_safe_actions =
        plan_next_safe_actions(tracker_report, &rows, &reservation_snapshot, &bv_snapshot);
    next_safe_actions.sort();
    next_safe_actions.dedup();

    let reproduction_commands = plan_reproduction_commands(
        config,
        config.reservation_report_path.is_some(),
        config.bv_report_path.is_some(),
    );
    let mut report = ClaimabilityPlanReport {
        schema_version: CLAIMABILITY_PLAN_SCHEMA_VERSION,
        status: "pass".to_owned(),
        generated_at: config.generated_at.clone(),
        mutation_policy:
            "report-only; this planner never claims, closes, deletes, rewrites, or edits tracker rows"
                .to_owned(),
        tracker_report_path: config.tracker_report_path.clone(),
        reservation_report_path: config.reservation_report_path.clone(),
        bv_report_path: config.bv_report_path.clone(),
        tracker_queue_verdict: tracker_report.source_aware_queue_state.verdict.clone(),
        source_aware_claimable_ids: tracker_report
            .source_aware_queue_state
            .claimable_ids
            .clone(),
        reservation_snapshot,
        bv_snapshot,
        rows,
        next_safe_actions,
        reproduction_commands,
        validation: ClaimabilityPlanValidationReport {
            schema_version: CLAIMABILITY_PLAN_SCHEMA_VERSION,
            valid: true,
            row_count: 0,
            classifications_seen: Vec::new(),
            errors: Vec::new(),
        },
        errors: Vec::new(),
    };
    let validation = validate_claimability_plan_report(&report);
    if validation.valid {
        "pass".clone_into(&mut report.status);
    } else {
        "fail".clone_into(&mut report.status);
    }
    report.errors.clone_from(&validation.errors);
    report.validation = validation;
    report
}

#[must_use]
pub fn validate_claimability_plan_report(
    report: &ClaimabilityPlanReport,
) -> ClaimabilityPlanValidationReport {
    let mut errors = Vec::new();
    let mut classifications_seen = BTreeSet::new();
    if report.schema_version != CLAIMABILITY_PLAN_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version must be {CLAIMABILITY_PLAN_SCHEMA_VERSION}; got {}",
            report.schema_version
        ));
    }
    if report.mutation_policy.trim().is_empty() {
        errors.push("mutation_policy must be explicit".to_owned());
    }
    if report.tracker_report_path.trim().is_empty() {
        errors.push("tracker_report_path is required".to_owned());
    }
    if report.next_safe_actions.is_empty() {
        errors.push("next_safe_actions must not be empty".to_owned());
    }
    if report.reproduction_commands.is_empty() {
        errors.push("reproduction_commands must not be empty".to_owned());
    }

    for row in &report.rows {
        classifications_seen.insert(row.classification);
        if row.id.trim().is_empty() {
            errors.push("row id must not be empty".to_owned());
        }
        if row.title.trim().is_empty() {
            errors.push(format!("row {} title must not be empty", row.id));
        }
        if row.next_safe_actions.is_empty() {
            errors.push(format!(
                "row {} next_safe_actions must not be empty",
                row.id
            ));
        }
        if row.reproduction_commands.is_empty() {
            errors.push(format!(
                "row {} reproduction_commands must not be empty",
                row.id
            ));
        }
        if row.classification == ClaimabilityClassification::ForeignExcluded
            && !row.owner_handoff_required
        {
            errors.push(format!(
                "foreign-excluded row {} must require owner handoff",
                row.id
            ));
        }
        if row.classification == ClaimabilityClassification::PermissionGated
            && row.permission_gate.is_none()
        {
            errors.push(format!(
                "permission-gated row {} must include permission_gate",
                row.id
            ));
        }
    }

    if report.source_aware_claimable_ids.is_empty()
        && !report.bv_snapshot.suppressed_parent_epic_ids.is_empty()
        && !report
            .next_safe_actions
            .iter()
            .any(|action| action.contains("do not claim raw bv parent epics"))
    {
        errors.push(
            "empty source-aware queue with bv parent epics must include a suppression action"
                .to_owned(),
        );
    }

    ClaimabilityPlanValidationReport {
        schema_version: CLAIMABILITY_PLAN_SCHEMA_VERSION,
        valid: errors.is_empty(),
        row_count: report.rows.len(),
        classifications_seen: classifications_seen.into_iter().collect(),
        errors,
    }
}

pub fn fail_on_claimability_plan_errors(report: &ClaimabilityPlanReport) -> Result<()> {
    if !report.errors.is_empty() {
        bail!(
            "claimability plan found {} errors: {}",
            report.errors.len(),
            report.errors.join("; ")
        );
    }
    if report.status != "pass" {
        bail!("claimability plan status={}", report.status);
    }
    Ok(())
}

#[must_use]
pub fn render_claimability_plan_markdown(report: &ClaimabilityPlanReport) -> String {
    let mut markdown = String::new();
    markdown.push_str("# Claimability Plan\n\n");
    let _ = writeln!(markdown, "- Status: `{}`", report.status);
    let _ = writeln!(markdown, "- Generated at: `{}`", report.generated_at);
    let _ = writeln!(
        markdown,
        "- Tracker queue verdict: `{}`",
        report.tracker_queue_verdict
    );
    let _ = writeln!(markdown, "- Rows: `{}`", report.rows.len());
    let _ = writeln!(
        markdown,
        "- Reservation conflict: `{}`",
        report.reservation_snapshot.conflict_classification
    );
    let _ = writeln!(
        markdown,
        "- Suppressed bv parent epics: `{}`",
        report.bv_snapshot.suppressed_parent_epic_ids.len()
    );

    markdown.push_str("\n## Next Safe Actions\n\n");
    for action in &report.next_safe_actions {
        let _ = writeln!(markdown, "- `{action}`");
    }

    markdown.push_str("\n## Rows\n\n");
    markdown.push_str("| ID | Classification | Status | Reason | Next Action |\n");
    markdown.push_str("|---|---|---|---|---|\n");
    for row in &report.rows {
        let _ = writeln!(
            markdown,
            "| `{}` | `{:?}` | `{}` | {} | `{}` |",
            markdown_table_cell(&row.id),
            row.classification,
            markdown_table_cell(&row.status),
            markdown_table_cell(&row.reason),
            markdown_table_cell(row.next_safe_actions.first().map_or("", String::as_str))
        );
    }

    markdown.push_str("\n## Reproduction\n\n");
    for command in &report.reproduction_commands {
        let _ = writeln!(markdown, "- `{command}`");
    }
    markdown
}

fn insert_row(rows: &mut BTreeMap<String, ClaimabilityPlanRow>, row: ClaimabilityPlanRow) {
    rows.entry(row.id.clone()).or_insert(row);
}

fn plan_row_from_work_row(
    row: &TrackerIssueWorkRow,
    classification: ClaimabilityClassification,
    reservation_report: Option<&AgentMailReservationSnapshotReport>,
) -> ClaimabilityPlanRow {
    let (reason, next_safe_actions) = if classification
        == ClaimabilityClassification::ReservedByPeer
    {
        (
            "active peer file reservation overlaps the planner target surface".to_owned(),
            vec![
                "do not edit reserved paths until Agent Mail reservation is released or handed off"
                    .to_owned(),
                format!(
                    "message reservation holder(s) on Agent Mail thread {} before claiming",
                    row.id
                ),
            ],
        )
    } else {
        (
            "source-aware tracker report marks this row claimable".to_owned(),
            vec![
                format!(
                    "br update --no-db --json --actor $AGENT_NAME --claim {}",
                    row.id
                ),
                format!(
                    "file_reservation_paths(project_key, agent_name, target_paths, reason=\"{}\")",
                    row.id
                ),
                format!(
                    "send_message(... thread_id=\"{}\", subject=\"[{}] Start: {}\")",
                    row.id, row.id, row.title
                ),
            ],
        )
    };
    let mut reproduction_commands = vec![
        "ffs-harness claimability-plan --tracker-report tracker_source_hygiene_report.json --out claimability_plan.json"
            .to_owned(),
    ];
    if reservation_report.is_some() {
        reproduction_commands.push(
            "ffs-harness claimability-plan --tracker-report tracker_source_hygiene_report.json --reservation-report agent_mail_reservations.json --out claimability_plan.json"
                .to_owned(),
        );
    }
    ClaimabilityPlanRow {
        id: row.id.clone(),
        title: row.title.clone(),
        status: row.status.clone(),
        priority: row.priority,
        issue_type: row.issue_type.clone(),
        source_repo: row.source_repo.clone(),
        assignee: row.assignee.clone(),
        classification,
        reason,
        blocked_by: row.blocked_by.clone(),
        permission_gate: None,
        owner_handoff_required: false,
        next_safe_actions,
        reproduction_commands,
    }
}

fn plan_row_from_permission_gated_row(row: &TrackerPermissionGatedRow) -> ClaimabilityPlanRow {
    ClaimabilityPlanRow {
        id: row.id.clone(),
        title: row.title.clone(),
        status: row.status.clone(),
        priority: row.priority,
        issue_type: row.issue_type.clone(),
        source_repo: row.source_repo.clone(),
        assignee: row.assignee.clone(),
        classification: ClaimabilityClassification::PermissionGated,
        reason: format!(
            "requires explicit permission gate {}={}",
            row.permission_gate.required_env, row.permission_gate.required_value
        ),
        blocked_by: row.blocked_by.clone(),
        permission_gate: Some(row.permission_gate.clone()),
        owner_handoff_required: false,
        next_safe_actions: vec![format!(
            "request exact ACK {}={} before running or claiming {}",
            row.permission_gate.required_env, row.permission_gate.required_value, row.id
        )],
        reproduction_commands: vec![
            "ffs-harness validate-tracker-source-hygiene --issues .beads/issues.jsonl".to_owned(),
        ],
    }
}

fn plan_row_from_blocked_row(row: &TrackerIssueWorkRow) -> ClaimabilityPlanRow {
    let blockers = row
        .blocked_by
        .iter()
        .map(|dependency| dependency.id.as_str())
        .collect::<Vec<_>>()
        .join(",");
    ClaimabilityPlanRow {
        id: row.id.clone(),
        title: row.title.clone(),
        status: row.status.clone(),
        priority: row.priority,
        issue_type: row.issue_type.clone(),
        source_repo: row.source_repo.clone(),
        assignee: row.assignee.clone(),
        classification: ClaimabilityClassification::Blocked,
        reason: format!("blocked_by={blockers}"),
        blocked_by: row.blocked_by.clone(),
        permission_gate: None,
        owner_handoff_required: false,
        next_safe_actions: vec![format!("complete blockers for {} before claiming", row.id)],
        reproduction_commands: vec![
            "ffs-harness validate-tracker-source-hygiene --issues .beads/issues.jsonl".to_owned(),
        ],
    }
}

fn plan_row_from_epic_row(
    row: &crate::tracker_source_hygiene::TrackerLocalNonclaimableRow,
) -> ClaimabilityPlanRow {
    ClaimabilityPlanRow {
        id: row.id.clone(),
        title: row.title.clone(),
        status: row.status.clone(),
        priority: row.priority,
        issue_type: row.issue_type.clone(),
        source_repo: row.source_repo.clone(),
        assignee: row.assignee.clone(),
        classification: ClaimabilityClassification::ParentEpic,
        reason: "parent epic is planning context, not a direct claim".to_owned(),
        blocked_by: row.blocked_by.clone(),
        permission_gate: row.permission_gate.clone(),
        owner_handoff_required: false,
        next_safe_actions: vec![format!(
            "create or claim a narrow child bead under {} instead of claiming the parent epic",
            row.id
        )],
        reproduction_commands: vec![
            "bv --robot-next".to_owned(),
            "ffs-harness validate-tracker-source-hygiene --issues .beads/issues.jsonl".to_owned(),
        ],
    }
}

fn plan_row_from_stale_row(row: &TrackerIssueProgressRow) -> ClaimabilityPlanRow {
    ClaimabilityPlanRow {
        id: row.id.clone(),
        title: row.title.clone(),
        status: row.status.clone(),
        priority: row.priority,
        issue_type: row.issue_type.clone(),
        source_repo: row.source_repo.clone(),
        assignee: row.assignee.clone(),
        classification: ClaimabilityClassification::StaleInProgressReclaimCandidate,
        reason: format!(
            "in-progress row is stale after {} seconds",
            row.stale_after_seconds
        ),
        blocked_by: row.blocked_by.clone(),
        permission_gate: None,
        owner_handoff_required: false,
        next_safe_actions: vec![format!(
            "inspect Agent Mail thread {} and live reservations before reopening or reclaiming",
            row.id
        )],
        reproduction_commands: vec![
            "ffs-harness validate-tracker-source-hygiene --issues .beads/issues.jsonl".to_owned(),
        ],
    }
}

fn plan_row_from_foreign_sample(row: &TrackerIssueSample) -> ClaimabilityPlanRow {
    ClaimabilityPlanRow {
        id: row.id.clone(),
        title: row.title.clone(),
        status: row.status.clone(),
        priority: row.priority,
        issue_type: row.issue_type.clone(),
        source_repo: row.source_repo.clone(),
        assignee: None,
        classification: ClaimabilityClassification::ForeignExcluded,
        reason: "foreign-looking row is owner-handoff only".to_owned(),
        blocked_by: Vec::new(),
        permission_gate: None,
        owner_handoff_required: true,
        next_safe_actions: vec![format!(
            "message owner project before moving, closing, rewriting, or claiming foreign row {}",
            row.id
        )],
        reproduction_commands: vec![
            "ffs-harness validate-tracker-source-hygiene --issues .beads/issues.jsonl".to_owned(),
        ],
    }
}

fn reservation_summary(
    reservation_report: Option<&AgentMailReservationSnapshotReport>,
) -> ClaimabilityReservationSnapshotSummary {
    let Some(report) = reservation_report else {
        return ClaimabilityReservationSnapshotSummary {
            present: false,
            source_freshness: "unknown".to_owned(),
            conflict_classification: "unknown".to_owned(),
            active_peer_conflict_count: 0,
            target_paths: Vec::new(),
        };
    };
    ClaimabilityReservationSnapshotSummary {
        present: true,
        source_freshness: report.source_freshness.clone(),
        conflict_classification: report.conflict_classification.clone(),
        active_peer_conflict_count: report
            .reservations
            .iter()
            .filter(|row| row.conflict_classification == "active_peer_conflict")
            .count(),
        target_paths: report.target_paths.clone(),
    }
}

fn bv_summary(
    bv_snapshot: Option<&Value>,
    parent_epic_ids: &BTreeSet<String>,
    tracker_report: &TrackerSourceHygieneReport,
) -> ClaimabilityBvSnapshotSummary {
    let Some(snapshot) = bv_snapshot else {
        return ClaimabilityBvSnapshotSummary {
            present: false,
            recommendation_count: 0,
            parent_epic_recommendation_ids: Vec::new(),
            suppressed_parent_epic_ids: Vec::new(),
        };
    };
    let mut recommendation_ids = BTreeSet::new();
    collect_bv_ids(snapshot, &mut recommendation_ids);
    let parent_epic_recommendation_ids: Vec<String> = recommendation_ids
        .iter()
        .filter(|id| parent_epic_ids.contains(*id))
        .cloned()
        .collect();
    let suppressed_parent_epic_ids = if tracker_report
        .source_aware_queue_state
        .claimable_ids
        .is_empty()
    {
        parent_epic_recommendation_ids.clone()
    } else {
        Vec::new()
    };
    ClaimabilityBvSnapshotSummary {
        present: true,
        recommendation_count: recommendation_ids.len(),
        parent_epic_recommendation_ids,
        suppressed_parent_epic_ids,
    }
}

fn collect_bv_ids(value: &Value, ids: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for key in ["id", "issue_id", "bead_id"] {
                if let Some(id) = map.get(key).and_then(Value::as_str) {
                    ids.insert(id.to_owned());
                }
            }
            for child in map.values() {
                collect_bv_ids(child, ids);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_bv_ids(child, ids);
            }
        }
        _ => {}
    }
}

fn parent_epic_ids(report: &TrackerSourceHygieneReport) -> BTreeSet<String> {
    report
        .local_nonclaimable_rows
        .iter()
        .filter(|row| row.reason == "epic")
        .map(|row| row.id.clone())
        .collect()
}

fn plan_next_safe_actions(
    tracker_report: &TrackerSourceHygieneReport,
    rows: &[ClaimabilityPlanRow],
    reservation_summary: &ClaimabilityReservationSnapshotSummary,
    bv_summary: &ClaimabilityBvSnapshotSummary,
) -> Vec<String> {
    let mut actions = Vec::new();
    if rows
        .iter()
        .any(|row| row.classification == ClaimabilityClassification::Claimable)
    {
        actions.push(
            "claim one claimable row, reserve its exact files, then announce on Agent Mail"
                .to_owned(),
        );
    }
    if reservation_summary.active_peer_conflict_count > 0 {
        actions.push(
            "wait for peer reservation release or obtain explicit handoff before editing reserved paths"
                .to_owned(),
        );
    }
    if rows
        .iter()
        .any(|row| row.classification == ClaimabilityClassification::PermissionGated)
    {
        actions.push("do not run permission-gated rows without the exact required ACK".to_owned());
    }
    if rows
        .iter()
        .any(|row| row.classification == ClaimabilityClassification::Blocked)
    {
        actions.push("clear blockers before claiming blocked local rows".to_owned());
    }
    if rows.iter().any(|row| {
        row.classification == ClaimabilityClassification::StaleInProgressReclaimCandidate
    }) {
        actions.push(
            "inspect Agent Mail and live reservations before reclaiming stale in-progress rows"
                .to_owned(),
        );
    }
    if !bv_summary.suppressed_parent_epic_ids.is_empty() {
        actions.push(format!(
            "do not claim raw bv parent epics when source_aware_queue_state.claimable_ids is empty: {}",
            bv_summary.suppressed_parent_epic_ids.join(",")
        ));
    }
    if rows
        .iter()
        .any(|row| row.classification == ClaimabilityClassification::ForeignExcluded)
    {
        actions.push(
            "preserve foreign rows as owner-handoff only; do not mutate them locally".to_owned(),
        );
    }
    if actions.is_empty() {
        actions.extend(
            tracker_report
                .source_aware_queue_state
                .next_safe_actions
                .clone(),
        );
    }
    actions
}

fn plan_reproduction_commands(
    config: &ClaimabilityPlanConfig,
    has_reservation_report: bool,
    has_bv_report: bool,
) -> Vec<String> {
    let mut command = format!(
        "ffs-harness claimability-plan --tracker-report {}",
        shell_arg(&config.tracker_report_path)
    );
    if let Some(path) = config
        .reservation_report_path
        .as_ref()
        .filter(|_| has_reservation_report)
    {
        let _ = write!(command, " --reservation-report {}", shell_arg(path));
    }
    if let Some(path) = config.bv_report_path.as_ref().filter(|_| has_bv_report) {
        let _ = write!(command, " --bv-report {}", shell_arg(path));
    }
    command.push_str(" --out claimability_plan.json");
    vec![
        format!(
            "ffs-harness validate-tracker-source-hygiene --issues .beads/issues.jsonl --out {}",
            shell_arg(&config.tracker_report_path)
        ),
        command,
    ]
}

fn shell_arg(value: &str) -> String {
    if !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '/' | '_' | '-' | ':'))
    {
        return value.to_owned();
    }

    let mut quoted = String::from("'");
    for ch in value.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

fn markdown_table_cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracker_source_hygiene::{
        AgentMailReservationLeaseReport, TrackerForeignReconciliationPlan, TrackerIssueProgressRow,
        TrackerLocalGraphExports, TrackerLocalNonclaimableRow, TrackerPermissionGate,
        TrackerPrefixCount, TrackerSourceAwareQueueState, TrackerSourceHygieneClassifier,
    };

    fn config() -> ClaimabilityPlanConfig {
        ClaimabilityPlanConfig {
            generated_at: "2026-05-14T00:00:00Z".to_owned(),
            tracker_report_path: "tracker_source_hygiene_report.json".to_owned(),
            reservation_report_path: None,
            bv_report_path: None,
        }
    }

    fn base_report() -> TrackerSourceHygieneReport {
        TrackerSourceHygieneReport {
            schema_version: 1,
            issues_path: ".beads/issues.jsonl".to_owned(),
            strict: false,
            report_now_epoch: 2_000_000_000,
            status: "pass".to_owned(),
            mutation_policy: "report-only".to_owned(),
            classifier: TrackerSourceHygieneClassifier {
                local_id_regex: "^(bd|frankenfs)-".to_owned(),
                local_rule: "local".to_owned(),
                foreign_rule: "foreign".to_owned(),
            },
            total_rows: 0,
            local_total: 0,
            foreign_total: 0,
            open_total: 0,
            local_open: 0,
            foreign_open: 0,
            foreign_in_progress: 0,
            excluded_foreign_open_count: 0,
            excluded_foreign_in_progress_count: 0,
            excluded_foreign_stale_in_progress_count: 0,
            excluded_foreign_by_prefix: Vec::<TrackerPrefixCount>::new(),
            foreign_group_summaries: Vec::new(),
            foreign_reconciliation_plan: TrackerForeignReconciliationPlan {
                schema_version: 1,
                mutation_policy: "owner-handoff-required".to_owned(),
                authorization_required: false,
                conservation_check_required: false,
                groups: Vec::new(),
                next_steps: Vec::new(),
            },
            local_open_ids: Vec::new(),
            local_open_rows: Vec::new(),
            source_aware_ready_rows: Vec::new(),
            source_aware_queue_state: queue_state("empty", Vec::new()),
            local_graph_exports: Option::<TrackerLocalGraphExports>::None,
            permission_gated_rows: Vec::new(),
            blocked_local_rows: Vec::new(),
            local_nonclaimable_rows: Vec::new(),
            local_in_progress_rows: Vec::new(),
            stale_in_progress_rows: Vec::new(),
            foreign_open_samples: Vec::new(),
            foreign_in_progress_samples: Vec::new(),
            foreign_stale_in_progress_samples: Vec::new(),
            reproduction_commands: Vec::new(),
            errors: Vec::new(),
        }
    }

    fn queue_state(verdict: &str, claimable_ids: Vec<String>) -> TrackerSourceAwareQueueState {
        TrackerSourceAwareQueueState {
            schema_version: 1,
            verdict: verdict.to_owned(),
            claimable_count: claimable_ids.len(),
            local_open_count: 0,
            local_epic_count: 0,
            blocked_local_count: 0,
            permission_gated_count: 0,
            local_nonclaimable_count: 0,
            local_in_progress_count: 0,
            stale_in_progress_count: 0,
            excluded_foreign_open_count: 0,
            excluded_foreign_in_progress_count: 0,
            excluded_foreign_stale_in_progress_count: 0,
            excluded_foreign_stale_in_progress_ids: Vec::new(),
            claimable_ids,
            local_epic_ids: Vec::new(),
            blocked_local_ids: Vec::new(),
            permission_gated_ids: Vec::new(),
            local_nonclaimable_ids: Vec::new(),
            local_in_progress_ids: Vec::new(),
            stale_in_progress_ids: Vec::new(),
            next_safe_actions: vec!["fixture fallback".to_owned()],
        }
    }

    fn work_row(id: &str, title: &str) -> TrackerIssueWorkRow {
        TrackerIssueWorkRow {
            id: id.to_owned(),
            title: title.to_owned(),
            status: "open".to_owned(),
            priority: Some(1),
            issue_type: Some("task".to_owned()),
            source_repo: Some(".".to_owned()),
            assignee: None,
            blocked_by: Vec::new(),
        }
    }

    fn permission_gate() -> TrackerPermissionGate {
        TrackerPermissionGate {
            gate_kind: "large_host_swarm_real_run".to_owned(),
            required_env: "FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD,FFS_SWARM_WORKLOAD_REAL_RUN_ACK"
                .to_owned(),
            required_value: "1,swarm-workload-may-use-permissioned-large-host".to_owned(),
            present: false,
        }
    }

    fn class_ids(
        report: &ClaimabilityPlanReport,
        class: ClaimabilityClassification,
    ) -> Vec<String> {
        report
            .rows
            .iter()
            .filter(|row| row.classification == class)
            .map(|row| row.id.clone())
            .collect()
    }

    #[test]
    fn clean_claimable_task_gets_exact_start_actions() {
        let mut tracker = base_report();
        tracker.source_aware_ready_rows = vec![work_row("bd-clean", "Clean local task")];
        tracker.source_aware_queue_state = queue_state("ready", vec!["bd-clean".to_owned()]);

        let report = build_claimability_plan_report(&config(), &tracker, None, None);

        assert_eq!(report.status, "pass");
        assert_eq!(
            class_ids(&report, ClaimabilityClassification::Claimable),
            vec!["bd-clean"]
        );
        let row = report.rows.iter().find(|row| row.id == "bd-clean").unwrap();
        assert!(row.next_safe_actions.iter().any(|action| {
            action == "br update --no-db --json --actor $AGENT_NAME --claim bd-clean"
        }));
        assert!(row.next_safe_actions.iter().any(|action| {
            action.contains("file_reservation_paths") && action.contains("bd-clean")
        }));
    }

    #[test]
    fn permissioned_bd_rchk3_row_requires_ack() {
        let mut tracker = base_report();
        tracker.permission_gated_rows = vec![TrackerPermissionGatedRow {
            id: "bd-rchk3".to_owned(),
            title: "Run permissioned swarm workload".to_owned(),
            status: "open".to_owned(),
            priority: Some(1),
            issue_type: Some("task".to_owned()),
            source_repo: Some(".".to_owned()),
            assignee: None,
            blocked_by: Vec::new(),
            permission_gate: permission_gate(),
        }];
        tracker.source_aware_queue_state = queue_state("permission_gated", Vec::new());

        let report = build_claimability_plan_report(&config(), &tracker, None, None);

        assert_eq!(
            class_ids(&report, ClaimabilityClassification::PermissionGated),
            vec!["bd-rchk3"]
        );
        let row = report.rows.iter().find(|row| row.id == "bd-rchk3").unwrap();
        assert!(row.permission_gate.is_some());
        assert!(row.next_safe_actions[0].contains("request exact ACK"));
    }

    #[test]
    fn active_peer_reservation_blocks_otherwise_claimable_row() {
        let mut tracker = base_report();
        tracker.source_aware_ready_rows = vec![work_row("bd-ready", "Ready but reserved")];
        tracker.source_aware_queue_state = queue_state("ready", vec!["bd-ready".to_owned()]);
        let reservation = AgentMailReservationSnapshotReport {
            schema_version: 1,
            snapshot_status: "present".to_owned(),
            snapshot_schema_version: Some(1),
            current_agent: "SapphireLotus".to_owned(),
            target_paths: vec!["crates/ffs-harness/src/main.rs".to_owned()],
            source: Some("agent-mail".to_owned()),
            source_freshness: "fresh".to_owned(),
            generated_at: Some("2026-05-14T00:00:00Z".to_owned()),
            generated_at_epoch: Some(1_768_000_000),
            age_seconds: Some(0),
            source_max_age_seconds: 3_600,
            conflict_classification: "active_peer_conflict".to_owned(),
            reservations: vec![AgentMailReservationLeaseReport {
                holder: "SageMeadow".to_owned(),
                path_pattern: "crates/ffs-harness/src/main.rs".to_owned(),
                exclusive: true,
                reason: Some("bd-ready".to_owned()),
                created_ts: Some("2026-05-14T00:00:00Z".to_owned()),
                expires_ts: Some("2026-05-14T01:00:00Z".to_owned()),
                released_ts: None,
                created_epoch: Some(1_768_000_000),
                expires_epoch: Some(1_768_003_600),
                released_epoch: None,
                active: true,
                overlaps_target: true,
                conflict_classification: "active_peer_conflict".to_owned(),
            }],
            errors: Vec::new(),
        };

        let report = build_claimability_plan_report(&config(), &tracker, Some(&reservation), None);

        assert_eq!(
            class_ids(&report, ClaimabilityClassification::ReservedByPeer),
            vec!["bd-ready"]
        );
        assert!(
            report
                .next_safe_actions
                .iter()
                .any(|action| { action.contains("wait for peer reservation release") })
        );
    }

    #[test]
    fn stale_in_progress_without_reservation_is_reclaim_candidate() {
        let mut tracker = base_report();
        tracker.stale_in_progress_rows = vec![TrackerIssueProgressRow {
            id: "bd-stale".to_owned(),
            title: "Stale claim".to_owned(),
            status: "in_progress".to_owned(),
            priority: Some(1),
            issue_type: Some("task".to_owned()),
            source_repo: Some(".".to_owned()),
            assignee: Some("OldAgent".to_owned()),
            blocked_by: Vec::new(),
            created_at: Some("2026-05-13T00:00:00Z".to_owned()),
            updated_at: Some("2026-05-13T00:00:00Z".to_owned()),
            last_activity_epoch: Some(1_767_900_000),
            age_seconds: Some(100_000),
            stale_after_seconds: 3_600,
            stale: true,
        }];
        tracker.source_aware_queue_state = queue_state("stale_in_progress", Vec::new());

        let report = build_claimability_plan_report(&config(), &tracker, None, None);

        assert_eq!(
            class_ids(
                &report,
                ClaimabilityClassification::StaleInProgressReclaimCandidate
            ),
            vec!["bd-stale"]
        );
        let row = report.rows.iter().find(|row| row.id == "bd-stale").unwrap();
        assert!(row.next_safe_actions[0].contains("inspect Agent Mail"));
    }

    #[test]
    fn polluted_br_r37_rows_are_owner_handoff_and_bv_parent_epics_are_suppressed() {
        let mut tracker = base_report();
        tracker.foreign_open_samples = vec![TrackerIssueSample {
            id: "br-r37".to_owned(),
            title: "Foreign tracker row".to_owned(),
            status: "open".to_owned(),
            priority: Some(1),
            issue_type: Some("task".to_owned()),
            source_repo: Some("../other".to_owned()),
        }];
        tracker.local_nonclaimable_rows = vec![TrackerLocalNonclaimableRow {
            id: "bd-rchk0".to_owned(),
            title: "Parent epic".to_owned(),
            status: "open".to_owned(),
            priority: Some(1),
            issue_type: Some("epic".to_owned()),
            source_repo: Some(".".to_owned()),
            assignee: None,
            reason: "epic".to_owned(),
            blocked_by: Vec::new(),
            permission_gate: None,
        }];
        tracker.source_aware_queue_state = queue_state("epic_only", Vec::new());
        let bv = serde_json::json!({
            "recommendations": [
                {"id": "bd-rchk0", "title": "Parent epic"}
            ]
        });
        let mut cfg = config();
        cfg.bv_report_path = Some("bv_robot_next.json".to_owned());

        let report = build_claimability_plan_report(&cfg, &tracker, None, Some(&bv));

        assert_eq!(
            class_ids(&report, ClaimabilityClassification::ForeignExcluded),
            vec!["br-r37"]
        );
        let foreign = report.rows.iter().find(|row| row.id == "br-r37").unwrap();
        assert!(foreign.owner_handoff_required);
        assert_eq!(
            report.bv_snapshot.suppressed_parent_epic_ids,
            vec!["bd-rchk0"]
        );
        assert!(
            report
                .next_safe_actions
                .iter()
                .any(|action| { action.contains("do not claim raw bv parent epics") })
        );
    }
}
