use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_TRACKER_SOURCE_HYGIENE_ISSUES: &str = ".beads/issues.jsonl";
pub const DEFAULT_STALE_IN_PROGRESS_SECONDS: u64 = 21_600;
pub const XFSTESTS_REAL_RUN_ACK_VALUE: &str = "xfstests-may-mutate-test-and-scratch-devices";
pub const SWARM_WORKLOAD_REAL_RUN_ACK_VALUE: &str =
    "swarm-workload-may-use-permissioned-large-host";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackerSourceHygieneConfig {
    pub issues_jsonl: PathBuf,
    pub strict: bool,
    pub report_now_epoch: i64,
    pub stale_in_progress_seconds: u64,
    pub xfstests_real_run_ack: Option<String>,
    pub swarm_workload_enabled: bool,
    pub swarm_workload_real_run_ack: Option<String>,
}

impl Default for TrackerSourceHygieneConfig {
    fn default() -> Self {
        Self {
            issues_jsonl: PathBuf::from(DEFAULT_TRACKER_SOURCE_HYGIENE_ISSUES),
            strict: false,
            report_now_epoch: current_epoch_seconds(),
            stale_in_progress_seconds: DEFAULT_STALE_IN_PROGRESS_SECONDS,
            xfstests_real_run_ack: None,
            swarm_workload_enabled: false,
            swarm_workload_real_run_ack: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackerSourceHygieneAnalysisConfig {
    pub issues_path: String,
    pub strict: bool,
    pub report_now_epoch: i64,
    pub stale_in_progress_seconds: u64,
    pub xfstests_real_run_ack: Option<String>,
    pub swarm_workload_enabled: bool,
    pub swarm_workload_real_run_ack: Option<String>,
}

impl TrackerSourceHygieneAnalysisConfig {
    #[must_use]
    pub fn from_config(config: &TrackerSourceHygieneConfig) -> Self {
        Self {
            issues_path: config.issues_jsonl.display().to_string(),
            strict: config.strict,
            report_now_epoch: config.report_now_epoch,
            stale_in_progress_seconds: config.stale_in_progress_seconds,
            xfstests_real_run_ack: config.xfstests_real_run_ack.clone(),
            swarm_workload_enabled: config.swarm_workload_enabled,
            swarm_workload_real_run_ack: config.swarm_workload_real_run_ack.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackerSourceHygieneReport {
    pub schema_version: u32,
    pub issues_path: String,
    pub strict: bool,
    pub report_now_epoch: i64,
    pub status: String,
    pub mutation_policy: String,
    pub classifier: TrackerSourceHygieneClassifier,
    pub total_rows: usize,
    pub local_total: usize,
    pub foreign_total: usize,
    pub open_total: usize,
    pub local_open: usize,
    pub foreign_open: usize,
    pub excluded_foreign_open_count: usize,
    pub excluded_foreign_by_prefix: Vec<TrackerPrefixCount>,
    pub foreign_group_summaries: Vec<TrackerForeignGroupSummary>,
    pub local_open_ids: Vec<String>,
    pub local_open_rows: Vec<TrackerIssueWorkRow>,
    pub source_aware_ready_rows: Vec<TrackerIssueWorkRow>,
    pub source_aware_queue_state: TrackerSourceAwareQueueState,
    pub permission_gated_rows: Vec<TrackerPermissionGatedRow>,
    pub blocked_local_rows: Vec<TrackerIssueWorkRow>,
    pub local_in_progress_rows: Vec<TrackerIssueProgressRow>,
    pub stale_in_progress_rows: Vec<TrackerIssueProgressRow>,
    pub foreign_open_samples: Vec<TrackerIssueSample>,
    pub reproduction_commands: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackerSourceHygieneClassifier {
    pub local_id_regex: String,
    pub local_rule: String,
    pub foreign_rule: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackerPrefixCount {
    pub prefix: String,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackerForeignGroupSummary {
    pub prefix: String,
    pub count: usize,
    pub owner_hints: Vec<String>,
    pub sample_ids: Vec<String>,
    pub sample_titles: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackerIssueSample {
    pub id: String,
    pub title: String,
    pub status: String,
    pub priority: Option<i64>,
    pub issue_type: Option<String>,
    pub source_repo: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackerIssueWorkRow {
    pub id: String,
    pub title: String,
    pub status: String,
    pub priority: Option<i64>,
    pub issue_type: Option<String>,
    pub source_repo: Option<String>,
    pub assignee: Option<String>,
    pub blocked_by: Vec<TrackerDependencyStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackerIssueProgressRow {
    pub id: String,
    pub title: String,
    pub status: String,
    pub priority: Option<i64>,
    pub issue_type: Option<String>,
    pub source_repo: Option<String>,
    pub assignee: Option<String>,
    pub blocked_by: Vec<TrackerDependencyStatus>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub last_activity_epoch: Option<i64>,
    pub age_seconds: Option<i64>,
    pub stale_after_seconds: u64,
    pub stale: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackerPermissionGatedRow {
    pub id: String,
    pub title: String,
    pub status: String,
    pub priority: Option<i64>,
    pub issue_type: Option<String>,
    pub source_repo: Option<String>,
    pub assignee: Option<String>,
    pub blocked_by: Vec<TrackerDependencyStatus>,
    pub permission_gate: TrackerPermissionGate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackerDependencyStatus {
    pub id: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackerPermissionGate {
    pub gate_kind: String,
    pub required_env: String,
    pub required_value: String,
    pub present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackerSourceAwareQueueState {
    pub schema_version: u32,
    pub verdict: String,
    pub claimable_count: usize,
    pub local_open_count: usize,
    pub local_epic_count: usize,
    pub blocked_local_count: usize,
    pub permission_gated_count: usize,
    pub local_in_progress_count: usize,
    pub stale_in_progress_count: usize,
    pub excluded_foreign_open_count: usize,
    pub claimable_ids: Vec<String>,
    pub local_epic_ids: Vec<String>,
    pub blocked_local_ids: Vec<String>,
    pub permission_gated_ids: Vec<String>,
    pub local_in_progress_ids: Vec<String>,
    pub stale_in_progress_ids: Vec<String>,
    pub next_safe_actions: Vec<String>,
}

#[derive(Debug, Clone)]
struct TrackerIssue<'a> {
    value: &'a Value,
}

impl<'a> TrackerIssue<'a> {
    const fn new(value: &'a Value) -> Self {
        Self { value }
    }

    fn id(&self) -> String {
        string_field(self.value, "id")
    }

    fn title(&self) -> String {
        string_field(self.value, "title")
    }

    fn status(&self) -> String {
        string_field_or(self.value, "status", "open")
    }

    fn priority(&self) -> Option<i64> {
        self.value.get("priority").and_then(Value::as_i64)
    }

    fn issue_type(&self) -> Option<String> {
        optional_string_field(self.value, "issue_type")
    }

    fn source_repo(&self) -> Option<String> {
        optional_string_field(self.value, "source_repo")
    }

    fn assignee(&self) -> Option<String> {
        optional_string_field(self.value, "assignee")
            .or_else(|| optional_string_field(self.value, "owner"))
    }

    fn created_at(&self) -> Option<String> {
        optional_string_field(self.value, "created_at")
    }

    fn updated_at(&self) -> Option<String> {
        optional_string_field(self.value, "updated_at")
    }

    fn is_local(&self) -> bool {
        is_local_issue_id(&self.id())
    }

    fn is_open(&self) -> bool {
        self.status() == "open"
    }

    fn is_in_progress(&self) -> bool {
        self.status() == "in_progress"
    }

    fn is_epic(&self) -> bool {
        self.issue_type().as_deref() == Some("epic")
    }

    fn sample(&self) -> TrackerIssueSample {
        TrackerIssueSample {
            id: self.id(),
            title: self.title(),
            status: self.status(),
            priority: self.priority(),
            issue_type: self.issue_type(),
            source_repo: self.source_repo(),
        }
    }

    fn work_row(&self, statuses: &BTreeMap<String, String>) -> TrackerIssueWorkRow {
        TrackerIssueWorkRow {
            id: self.id(),
            title: self.title(),
            status: self.status(),
            priority: self.priority(),
            issue_type: self.issue_type(),
            source_repo: self.source_repo(),
            assignee: self.assignee(),
            blocked_by: self.blocking_dependencies(statuses),
        }
    }

    fn progress_row(
        &self,
        statuses: &BTreeMap<String, String>,
        config: &TrackerSourceHygieneAnalysisConfig,
    ) -> TrackerIssueProgressRow {
        let last_activity_epoch = self
            .updated_at()
            .or_else(|| self.created_at())
            .as_deref()
            .and_then(parse_utc_timestamp_seconds);
        let age_seconds = last_activity_epoch.map(|epoch| config.report_now_epoch - epoch);
        let stale = age_seconds.is_none_or(|age| {
            age >= i64::try_from(config.stale_in_progress_seconds).unwrap_or(i64::MAX)
        });
        TrackerIssueProgressRow {
            id: self.id(),
            title: self.title(),
            status: self.status(),
            priority: self.priority(),
            issue_type: self.issue_type(),
            source_repo: self.source_repo(),
            assignee: self.assignee(),
            blocked_by: self.blocking_dependencies(statuses),
            created_at: self.created_at(),
            updated_at: self.updated_at(),
            last_activity_epoch,
            age_seconds,
            stale_after_seconds: config.stale_in_progress_seconds,
            stale,
        }
    }

    fn permission_gated_row(
        &self,
        statuses: &BTreeMap<String, String>,
        gate: TrackerPermissionGate,
    ) -> TrackerPermissionGatedRow {
        TrackerPermissionGatedRow {
            id: self.id(),
            title: self.title(),
            status: self.status(),
            priority: self.priority(),
            issue_type: self.issue_type(),
            source_repo: self.source_repo(),
            assignee: self.assignee(),
            blocked_by: self.blocking_dependencies(statuses),
            permission_gate: gate,
        }
    }

    fn blocking_dependencies(
        &self,
        statuses: &BTreeMap<String, String>,
    ) -> Vec<TrackerDependencyStatus> {
        self.value
            .get("dependencies")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|dependency| string_field_or(dependency, "type", "") == "blocks")
            .filter_map(|dependency| {
                let dep_id = string_field(dependency, "depends_on_id");
                if dep_id.is_empty() {
                    return None;
                }
                let status = statuses
                    .get(&dep_id)
                    .cloned()
                    .unwrap_or_else(|| "missing".to_owned());
                (status != "closed").then_some(TrackerDependencyStatus { id: dep_id, status })
            })
            .collect()
    }

    fn text_for_classification(&self) -> String {
        let mut parts = vec![
            self.id(),
            self.title(),
            string_field(self.value, "description"),
            string_field(self.value, "notes"),
        ];
        if let Some(labels) = self.value.get("labels").and_then(Value::as_array) {
            parts.extend(labels.iter().filter_map(Value::as_str).map(str::to_owned));
        }
        parts.join(" ")
    }
}

pub fn run_tracker_source_hygiene(
    config: &TrackerSourceHygieneConfig,
) -> Result<TrackerSourceHygieneReport> {
    let issues_jsonl = fs::read_to_string(&config.issues_jsonl)
        .with_context(|| format!("failed to read {}", config.issues_jsonl.display()))?;
    analyze_tracker_source_hygiene(
        &issues_jsonl,
        &TrackerSourceHygieneAnalysisConfig::from_config(config),
    )
}

pub fn analyze_tracker_source_hygiene(
    issues_jsonl: &str,
    config: &TrackerSourceHygieneAnalysisConfig,
) -> Result<TrackerSourceHygieneReport> {
    let issues = parse_issues_jsonl(issues_jsonl)?;
    Ok(build_report(&issues, config))
}

pub fn fail_on_tracker_source_hygiene_errors(report: &TrackerSourceHygieneReport) -> Result<()> {
    if !report.errors.is_empty() {
        bail!(
            "tracker source hygiene found {} errors: {}",
            report.errors.len(),
            report.errors.join("; ")
        );
    }
    if report.status != "pass" {
        bail!(
            "tracker source hygiene status={} foreign_open={}",
            report.status,
            report.foreign_open
        );
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn build_report(
    issues: &[Value],
    config: &TrackerSourceHygieneAnalysisConfig,
) -> TrackerSourceHygieneReport {
    let statuses = issue_statuses(issues);
    let wrapped: Vec<TrackerIssue<'_>> = issues.iter().map(TrackerIssue::new).collect();

    let local_total = wrapped.iter().filter(|issue| issue.is_local()).count();
    let foreign_total = issues.len() - local_total;
    let open_total = wrapped.iter().filter(|issue| issue.is_open()).count();
    let local_open = wrapped
        .iter()
        .filter(|issue| issue.is_local() && issue.is_open())
        .count();
    let foreign_open = wrapped
        .iter()
        .filter(|issue| !issue.is_local() && issue.is_open())
        .count();

    let mut local_open_rows: Vec<TrackerIssueWorkRow> = wrapped
        .iter()
        .filter(|issue| issue.is_local() && issue.is_open())
        .map(|issue| issue.work_row(&statuses))
        .collect();
    sort_work_rows(&mut local_open_rows);

    let mut source_aware_ready_rows: Vec<TrackerIssueWorkRow> = wrapped
        .iter()
        .filter(|issue| {
            issue.is_local()
                && issue.is_open()
                && !issue.is_epic()
                && issue.blocking_dependencies(&statuses).is_empty()
                && permission_gate(issue, config).is_none()
        })
        .map(|issue| issue.work_row(&statuses))
        .collect();
    sort_work_rows(&mut source_aware_ready_rows);

    let mut permission_gated_rows: Vec<TrackerPermissionGatedRow> = wrapped
        .iter()
        .filter(|issue| issue.is_local() && issue.is_open() && !issue.is_epic())
        .filter_map(|issue| {
            permission_gate(issue, config).map(|gate| issue.permission_gated_row(&statuses, gate))
        })
        .collect();
    permission_gated_rows.sort_by(|left, right| {
        left.priority
            .cmp(&right.priority)
            .then_with(|| left.id.cmp(&right.id))
    });

    let mut blocked_local_rows: Vec<TrackerIssueWorkRow> = wrapped
        .iter()
        .filter(|issue| issue.is_local() && issue.is_open() && !issue.is_epic())
        .filter(|issue| {
            permission_gate(issue, config).is_none()
                && !issue.blocking_dependencies(&statuses).is_empty()
        })
        .map(|issue| issue.work_row(&statuses))
        .collect();
    sort_work_rows(&mut blocked_local_rows);

    let mut local_epic_rows: Vec<TrackerIssueSample> = wrapped
        .iter()
        .filter(|issue| issue.is_local() && issue.is_open() && issue.is_epic())
        .map(TrackerIssue::sample)
        .collect();
    sort_samples(&mut local_epic_rows);

    let mut local_in_progress_rows: Vec<TrackerIssueProgressRow> = wrapped
        .iter()
        .filter(|issue| issue.is_local() && issue.is_in_progress())
        .map(|issue| issue.progress_row(&statuses, config))
        .collect();
    local_in_progress_rows.sort_by(|left, right| {
        left.priority
            .cmp(&right.priority)
            .then_with(|| left.id.cmp(&right.id))
    });

    let stale_in_progress_rows: Vec<TrackerIssueProgressRow> = local_in_progress_rows
        .iter()
        .filter(|row| row.stale)
        .cloned()
        .collect();

    let mut foreign_open_samples: Vec<TrackerIssueSample> = wrapped
        .iter()
        .filter(|issue| !issue.is_local() && issue.is_open())
        .map(TrackerIssue::sample)
        .collect();
    foreign_open_samples.sort_by(|left, right| left.id.cmp(&right.id));
    foreign_open_samples.truncate(20);

    let queue_state = build_queue_state(
        &source_aware_ready_rows,
        &local_epic_rows,
        &blocked_local_rows,
        &permission_gated_rows,
        &local_in_progress_rows,
        &stale_in_progress_rows,
        foreign_open,
    );

    TrackerSourceHygieneReport {
        schema_version: 1,
        issues_path: config.issues_path.clone(),
        strict: config.strict,
        report_now_epoch: config.report_now_epoch,
        status: if config.strict && foreign_open > 0 {
            "fail".to_owned()
        } else {
            "pass".to_owned()
        },
        mutation_policy:
            "report-only; this command never deletes, rewrites, closes, or edits tracker rows"
                .to_owned(),
        classifier: TrackerSourceHygieneClassifier {
            local_id_regex: "^(bd|frankenfs)-".to_owned(),
            local_rule: "FrankenFS-local rows use bd-* or frankenfs-* issue IDs".to_owned(),
            foreign_rule: "Rows with other issue ID prefixes are reported as foreign-looking"
                .to_owned(),
        },
        total_rows: issues.len(),
        local_total,
        foreign_total,
        open_total,
        local_open,
        foreign_open,
        excluded_foreign_open_count: foreign_open,
        excluded_foreign_by_prefix: excluded_foreign_by_prefix(&wrapped),
        foreign_group_summaries: foreign_group_summaries(&wrapped),
        local_open_ids: sorted_ids(
            wrapped
                .iter()
                .filter(|issue| issue.is_local() && issue.is_open()),
        ),
        local_open_rows,
        source_aware_ready_rows,
        source_aware_queue_state: queue_state,
        permission_gated_rows,
        blocked_local_rows,
        local_in_progress_rows,
        stale_in_progress_rows,
        foreign_open_samples,
        reproduction_commands: reproduction_commands(),
        errors: Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_queue_state(
    ready_rows: &[TrackerIssueWorkRow],
    epic_rows: &[TrackerIssueSample],
    blocked_rows: &[TrackerIssueWorkRow],
    permission_gated_rows: &[TrackerPermissionGatedRow],
    in_progress_rows: &[TrackerIssueProgressRow],
    stale_rows: &[TrackerIssueProgressRow],
    foreign_open: usize,
) -> TrackerSourceAwareQueueState {
    let verdict = if !ready_rows.is_empty() {
        "ready"
    } else if !stale_rows.is_empty() {
        "stale_in_progress"
    } else if !permission_gated_rows.is_empty() && !blocked_rows.is_empty() {
        "blocked_or_permission_gated"
    } else if !permission_gated_rows.is_empty() {
        "permission_gated"
    } else if !blocked_rows.is_empty() {
        "blocked"
    } else if !epic_rows.is_empty() {
        "epic_only"
    } else {
        "empty"
    };

    TrackerSourceAwareQueueState {
        schema_version: 1,
        verdict: verdict.to_owned(),
        claimable_count: ready_rows.len(),
        local_open_count: ready_rows.len()
            + epic_rows.len()
            + blocked_rows.len()
            + permission_gated_rows.len(),
        local_epic_count: epic_rows.len(),
        blocked_local_count: blocked_rows.len(),
        permission_gated_count: permission_gated_rows.len(),
        local_in_progress_count: in_progress_rows.len(),
        stale_in_progress_count: stale_rows.len(),
        excluded_foreign_open_count: foreign_open,
        claimable_ids: ready_rows.iter().map(|row| row.id.clone()).collect(),
        local_epic_ids: epic_rows.iter().map(|row| row.id.clone()).collect(),
        blocked_local_ids: blocked_rows.iter().map(|row| row.id.clone()).collect(),
        permission_gated_ids: permission_gated_rows
            .iter()
            .map(|row| row.id.clone())
            .collect(),
        local_in_progress_ids: in_progress_rows.iter().map(|row| row.id.clone()).collect(),
        stale_in_progress_ids: stale_rows.iter().map(|row| row.id.clone()).collect(),
        next_safe_actions: next_safe_actions(verdict),
    }
}

fn parse_issues_jsonl(issues_jsonl: &str) -> Result<Vec<Value>> {
    issues_jsonl
        .lines()
        .enumerate()
        .filter_map(|(line_index, raw_line)| {
            let line = raw_line.trim();
            if line.is_empty() {
                return None;
            }
            Some(
                serde_json::from_str::<Value>(line)
                    .with_context(|| format!("invalid issue JSONL at line {}", line_index + 1)),
            )
        })
        .collect()
}

fn issue_statuses(issues: &[Value]) -> BTreeMap<String, String> {
    issues
        .iter()
        .filter_map(|value| {
            let id = string_field(value, "id");
            if id.is_empty() {
                return None;
            }
            Some((id, string_field_or(value, "status", "open")))
        })
        .collect()
}

fn permission_gate(
    issue: &TrackerIssue<'_>,
    config: &TrackerSourceHygieneAnalysisConfig,
) -> Option<TrackerPermissionGate> {
    let text = issue.text_for_classification().to_ascii_lowercase();
    let xfstests_ack_present = config
        .xfstests_real_run_ack
        .as_deref()
        .is_some_and(|ack| ack == XFSTESTS_REAL_RUN_ACK_VALUE);
    let swarm_ack_present = config.swarm_workload_enabled
        && config
            .swarm_workload_real_run_ack
            .as_deref()
            .is_some_and(|ack| ack == SWARM_WORKLOAD_REAL_RUN_ACK_VALUE);

    if xfstests_text_matches(&text) && !xfstests_ack_present {
        Some(TrackerPermissionGate {
            gate_kind: "xfstests_real_run".to_owned(),
            required_env: "XFSTESTS_REAL_RUN_ACK".to_owned(),
            required_value: XFSTESTS_REAL_RUN_ACK_VALUE.to_owned(),
            present: false,
        })
    } else if swarm_text_matches(&text) && !swarm_ack_present {
        Some(TrackerPermissionGate {
            gate_kind: "large_host_swarm_real_run".to_owned(),
            required_env: "FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD,FFS_SWARM_WORKLOAD_REAL_RUN_ACK"
                .to_owned(),
            required_value: format!("1,{SWARM_WORKLOAD_REAL_RUN_ACK_VALUE}"),
            present: false,
        })
    } else {
        None
    }
}

fn xfstests_text_matches(text: &str) -> bool {
    text.contains("xfstests_real_run_ack")
        || text.contains(XFSTESTS_REAL_RUN_ACK_VALUE)
        || text.contains("real xfstests run")
        || (text.contains("execute") && text.contains("xfstests baseline"))
        || (text.contains("run") && text.contains("xfstests baseline"))
}

fn swarm_text_matches(text: &str) -> bool {
    text.contains("ffs_swarm_workload_real_run_ack")
        || text.contains(SWARM_WORKLOAD_REAL_RUN_ACK_VALUE)
        || text.contains("large-host")
        || text.contains("large host")
        || (text.contains("permissioned") && text.contains("swarm"))
}

fn excluded_foreign_by_prefix(issues: &[TrackerIssue<'_>]) -> Vec<TrackerPrefixCount> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for issue in issues
        .iter()
        .filter(|issue| !issue.is_local() && issue.is_open())
    {
        *counts.entry(issue_prefix(&issue.id())).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(prefix, count)| TrackerPrefixCount { prefix, count })
        .collect()
}

fn foreign_group_summaries(issues: &[TrackerIssue<'_>]) -> Vec<TrackerForeignGroupSummary> {
    let mut groups: BTreeMap<String, Vec<&TrackerIssue<'_>>> = BTreeMap::new();
    for issue in issues
        .iter()
        .filter(|issue| !issue.is_local() && issue.is_open())
    {
        groups
            .entry(issue_prefix(&issue.id()))
            .or_default()
            .push(issue);
    }

    groups
        .into_iter()
        .map(|(prefix, mut rows)| {
            rows.sort_by_key(|issue| issue.id());
            let owner_hints = owner_hints_for_rows(&rows);
            TrackerForeignGroupSummary {
                prefix,
                count: rows.len(),
                owner_hints,
                sample_ids: rows.iter().take(10).map(|issue| issue.id()).collect(),
                sample_titles: rows.iter().take(3).map(|issue| issue.title()).collect(),
            }
        })
        .collect()
}

fn owner_hints_for_rows(rows: &[&TrackerIssue<'_>]) -> Vec<String> {
    let hints: BTreeSet<String> = rows.iter().map(|issue| owner_hint(issue)).collect();
    if hints.len() > 1 && hints.contains("unknown") {
        hints.into_iter().filter(|hint| hint != "unknown").collect()
    } else {
        hints.into_iter().collect()
    }
}

fn owner_hint(issue: &TrackerIssue<'_>) -> String {
    let text = issue.text_for_classification().to_ascii_lowercase();
    if text.contains("franken_networkx")
        || text.contains("networkx")
        || issue.id().starts_with("franken_networkx-")
    {
        "franken_networkx".to_owned()
    } else if text.contains("frankenfs") || issue.is_local() {
        "frankenfs".to_owned()
    } else {
        "unknown".to_owned()
    }
}

fn issue_prefix(id: &str) -> String {
    let mut segments = id.split('-');
    let Some(first) = segments.next().filter(|segment| !segment.is_empty()) else {
        return "unknown".to_owned();
    };
    segments
        .next()
        .filter(|segment| !segment.is_empty())
        .map_or_else(|| first.to_owned(), |second| format!("{first}-{second}"))
}

fn sorted_ids<'a>(issues: impl Iterator<Item = &'a TrackerIssue<'a>>) -> Vec<String> {
    let mut ids: Vec<String> = issues.map(TrackerIssue::id).collect();
    ids.sort();
    ids
}

fn sort_work_rows(rows: &mut [TrackerIssueWorkRow]) {
    rows.sort_by(|left, right| {
        left.priority
            .cmp(&right.priority)
            .then_with(|| left.id.cmp(&right.id))
    });
}

fn sort_samples(rows: &mut [TrackerIssueSample]) {
    rows.sort_by(|left, right| {
        left.priority
            .cmp(&right.priority)
            .then_with(|| left.id.cmp(&right.id))
    });
}

fn next_safe_actions(verdict: &str) -> Vec<String> {
    match verdict {
        "ready" => {
            vec!["claim one source_aware_ready row before creating fallback work".to_owned()]
        }
        "stale_in_progress" => {
            vec![
                "inspect stale_in_progress_ids and Agent Mail before reopening stalled claims"
                    .to_owned(),
            ]
        }
        "blocked_or_permission_gated" | "permission_gated" => vec![
            "request the exact permission ACK before running permissioned rows".to_owned(),
            "create or claim only non-mutating fallback work".to_owned(),
        ],
        "blocked" => vec!["inspect blocked_local_ids and unblock prerequisites first".to_owned()],
        "epic_only" => {
            vec!["create a narrow child bead under the open epic before editing code".to_owned()]
        }
        _ => vec!["run idea-wizard or a testing skill to create a new narrow bead".to_owned()],
    }
}

fn reproduction_commands() -> Vec<String> {
    vec![
        "ffs-harness validate-tracker-source-hygiene --issues .beads/issues.jsonl".to_owned(),
        "./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh".to_owned(),
        "XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices ffs-harness validate-tracker-source-hygiene --issues .beads/issues.jsonl".to_owned(),
        "FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD=1 FFS_SWARM_WORKLOAD_REAL_RUN_ACK=swarm-workload-may-use-permissioned-large-host ffs-harness validate-tracker-source-hygiene --issues .beads/issues.jsonl".to_owned(),
        "TRACKER_SOURCE_HYGIENE_STRICT=1 ffs-harness validate-tracker-source-hygiene --issues .beads/issues.jsonl --strict".to_owned(),
    ]
}

fn string_field(value: &Value, field: &str) -> String {
    optional_string_field(value, field).unwrap_or_default()
}

fn string_field_or(value: &Value, field: &str, default: &str) -> String {
    optional_string_field(value, field).unwrap_or_else(|| default.to_owned())
}

fn optional_string_field(value: &Value, field: &str) -> Option<String> {
    value.get(field).and_then(Value::as_str).map(str::to_owned)
}

fn is_local_issue_id(id: &str) -> bool {
    id.starts_with("bd-") || id.starts_with("frankenfs-")
}

fn current_epoch_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
        })
}

fn parse_utc_timestamp_seconds(raw: &str) -> Option<i64> {
    let raw = raw.trim();
    let without_zone = raw
        .strip_suffix('Z')
        .or_else(|| raw.strip_suffix("+00:00"))?;
    let (date, time) = without_zone.split_once('T')?;
    let mut date_parts = date.split('-');
    let year: i32 = date_parts.next()?.parse().ok()?;
    let month: u32 = date_parts.next()?.parse().ok()?;
    let day: u32 = date_parts.next()?.parse().ok()?;
    if date_parts.next().is_some() {
        return None;
    }

    let time_main = time.split('.').next()?;
    let mut time_parts = time_main.split(':');
    let hour: u32 = time_parts.next()?.parse().ok()?;
    let minute: u32 = time_parts.next()?.parse().ok()?;
    let second: u32 = time_parts.next()?.parse().ok()?;
    if time_parts.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    let days = days_from_civil(year, month, day)?;
    days.checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3_600)?
        .checked_add(i64::from(minute) * 60)?
        .checked_add(i64::from(second))
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return None;
    }
    let adjusted_year = i64::from(year) - i64::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let year_of_era = adjusted_year - era * 400;
    let month_i64 = i64::from(month);
    let day_of_year =
        (153 * (month_i64 + if month > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146_097 + day_of_era - 719_468)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

const fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 2_000_000_000;
    const COMMITTED_FIXTURE_ISSUES: &str =
        include_str!("../../../tests/fixtures/tracker_source_hygiene.jsonl");
    const COMMITTED_FIXTURE_GOLDEN: &str =
        include_str!("../../../tests/fixtures/tracker_source_hygiene_report.golden.json");

    fn config() -> TrackerSourceHygieneAnalysisConfig {
        TrackerSourceHygieneAnalysisConfig {
            issues_path: "fixture.jsonl".to_owned(),
            strict: false,
            report_now_epoch: NOW,
            stale_in_progress_seconds: 3_600,
            xfstests_real_run_ack: None,
            swarm_workload_enabled: false,
            swarm_workload_real_run_ack: None,
        }
    }

    fn line(value: &serde_json::Value) -> String {
        serde_json::to_string(value).expect("serialize fixture")
    }

    fn golden_field<'a>(golden: &'a Value, field: &str) -> Result<&'a Value, String> {
        golden
            .get(field)
            .ok_or_else(|| format!("golden field {field} is missing"))
    }

    fn golden_array_len(golden: &Value, field: &str) -> Result<usize, String> {
        Ok(golden_field(golden, field)?
            .as_array()
            .ok_or_else(|| format!("golden field {field} must be an array"))?
            .len())
    }

    fn golden_usize(golden: &Value, field: &str) -> Result<usize, String> {
        let value = golden_field(golden, field)?
            .as_u64()
            .ok_or_else(|| format!("golden field {field} must be an unsigned integer"))?;
        usize::try_from(value).map_err(|_| format!("golden field {field} must fit usize"))
    }

    fn golden_string_array(value: &Value) -> Result<Vec<String>, String> {
        value
            .as_array()
            .ok_or_else(|| "golden field must be an array".to_owned())?
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                entry
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("golden array entry {index} must be a string"))
            })
            .collect()
    }

    #[test]
    fn committed_fixture_matches_shell_golden_core_queue_state() -> Result<(), String> {
        let report = analyze_tracker_source_hygiene(COMMITTED_FIXTURE_ISSUES, &config())
            .map_err(|err| err.to_string())?;
        let golden: Value =
            serde_json::from_str(COMMITTED_FIXTURE_GOLDEN).map_err(|err| err.to_string())?;
        let golden_queue = golden_field(&golden, "source_aware_queue_state")?;

        assert_eq!(report.local_open, golden_usize(&golden, "local_open")?);
        assert_eq!(report.foreign_open, golden_usize(&golden, "foreign_open")?);
        assert_eq!(
            report.excluded_foreign_open_count,
            golden_usize(&golden, "excluded_foreign_open_count")?
        );
        assert_eq!(
            report.source_aware_ready_rows.len(),
            golden_array_len(&golden, "source_aware_ready_rows")?
        );
        assert_eq!(
            report.permission_gated_rows.len(),
            golden_array_len(&golden, "permission_gated_rows")?
        );
        assert_eq!(
            report.blocked_local_rows.len(),
            golden_array_len(&golden, "blocked_local_rows")?
        );
        assert_eq!(
            report.local_in_progress_rows.len(),
            golden_array_len(&golden, "local_in_progress_rows")?
        );
        assert_eq!(
            report.stale_in_progress_rows.len(),
            golden_array_len(&golden, "stale_in_progress_rows")?
        );
        assert_eq!(
            report.source_aware_queue_state.verdict,
            golden_queue
                .get("verdict")
                .and_then(Value::as_str)
                .ok_or_else(|| "golden verdict must be a string".to_owned())?
        );
        assert_eq!(
            report.source_aware_queue_state.claimable_ids,
            golden_string_array(golden_field(golden_queue, "claimable_ids")?)?
        );
        assert_eq!(
            report.source_aware_queue_state.permission_gated_ids,
            golden_string_array(golden_field(golden_queue, "permission_gated_ids")?)?
        );
        assert_eq!(
            report.source_aware_queue_state.blocked_local_ids,
            golden_string_array(golden_field(golden_queue, "blocked_local_ids")?)?
        );
        assert_eq!(
            report.source_aware_queue_state.local_in_progress_ids,
            golden_string_array(golden_field(golden_queue, "local_in_progress_ids")?)?
        );
        assert_eq!(
            report.source_aware_queue_state.stale_in_progress_ids,
            golden_string_array(golden_field(golden_queue, "stale_in_progress_ids")?)?
        );

        let golden_prefixes: Vec<TrackerPrefixCount> =
            serde_json::from_value(golden_field(&golden, "excluded_foreign_by_prefix")?.clone())
                .map_err(|err| err.to_string())?;
        let golden_groups: Vec<TrackerForeignGroupSummary> =
            serde_json::from_value(golden_field(&golden, "foreign_group_summaries")?.clone())
                .map_err(|err| err.to_string())?;
        assert_eq!(report.excluded_foreign_by_prefix, golden_prefixes);
        assert_eq!(report.foreign_group_summaries, golden_groups);
        let permission_gate = report
            .permission_gated_rows
            .first()
            .ok_or_else(|| "fixture must include one permission-gated row".to_owned())?;
        assert_eq!(
            permission_gate.permission_gate.gate_kind,
            "xfstests_real_run",
        );
        Ok(())
    }

    #[test]
    fn classifies_ready_blocked_permission_and_foreign_rows() {
        let issues = [
            line(&serde_json::json!({
                "id": "bd-ready",
                "title": "safe local work",
                "status": "open",
                "priority": 2,
                "labels": ["qa_unit_required"]
            })),
            line(&serde_json::json!({
                "id": "bd-blocked",
                "title": "blocked local work",
                "status": "open",
                "priority": 1,
                "dependencies": [
                    {"type": "blocks", "depends_on_id": "bd-prereq"}
                ]
            })),
            line(&serde_json::json!({
                "id": "bd-prereq",
                "title": "prerequisite",
                "status": "open"
            })),
            line(&serde_json::json!({
                "id": "bd-xfstests",
                "title": "execute xfstests baseline",
                "description": "requires real xfstests run",
                "status": "open",
                "priority": 1
            })),
            line(&serde_json::json!({
                "id": "br-r37-c1",
                "title": "NetworkX imported row",
                "description": "franken_networkx parity",
                "status": "open",
                "priority": 0
            })),
            line(&serde_json::json!({
                "id": "bd-epic",
                "title": "open epic",
                "issue_type": "epic",
                "status": "open"
            })),
        ]
        .join("\n");

        let report = analyze_tracker_source_hygiene(&issues, &config()).expect("analyze");

        assert_eq!(report.status, "pass");
        assert_eq!(report.local_open, 5);
        assert_eq!(report.foreign_open, 1);
        assert_eq!(
            report
                .source_aware_ready_rows
                .iter()
                .map(|row| row.id.as_str())
                .collect::<Vec<_>>(),
            vec!["bd-prereq", "bd-ready"]
        );
        assert_eq!(
            report
                .blocked_local_rows
                .iter()
                .map(|row| row.id.as_str())
                .collect::<Vec<_>>(),
            vec!["bd-blocked"]
        );
        assert_eq!(report.permission_gated_rows[0].id, "bd-xfstests");
        assert_eq!(
            report.permission_gated_rows[0].permission_gate.gate_kind,
            "xfstests_real_run"
        );
        assert_eq!(report.source_aware_queue_state.verdict, "ready");
        assert_eq!(report.foreign_group_summaries[0].prefix, "br-r37");
        assert_eq!(
            report.foreign_group_summaries[0].owner_hints,
            vec!["franken_networkx"]
        );
    }

    #[test]
    fn exact_permission_acks_make_gated_rows_claimable() {
        let mut cfg = config();
        cfg.xfstests_real_run_ack = Some(XFSTESTS_REAL_RUN_ACK_VALUE.to_owned());
        cfg.swarm_workload_enabled = true;
        cfg.swarm_workload_real_run_ack = Some(SWARM_WORKLOAD_REAL_RUN_ACK_VALUE.to_owned());
        let issues = [
            line(&serde_json::json!({
                "id": "bd-xfstests",
                "title": "run xfstests baseline",
                "status": "open"
            })),
            line(&serde_json::json!({
                "id": "bd-swarm",
                "title": "permissioned large-host swarm campaign",
                "status": "open"
            })),
        ]
        .join("\n");

        let report = analyze_tracker_source_hygiene(&issues, &cfg).expect("analyze");

        assert!(report.permission_gated_rows.is_empty());
        assert_eq!(
            report.source_aware_queue_state.claimable_ids,
            vec!["bd-swarm", "bd-xfstests"]
        );
    }

    #[test]
    fn stale_in_progress_takes_precedence_when_no_ready_rows() {
        let issues = line(&serde_json::json!({
            "id": "bd-active",
            "title": "claimed row",
            "status": "in_progress",
            "updated_at": "2033-05-18T02:33:19Z"
        }));

        let report = analyze_tracker_source_hygiene(&issues, &config()).expect("analyze");

        assert_eq!(report.source_aware_queue_state.verdict, "stale_in_progress");
        assert_eq!(
            report.source_aware_queue_state.stale_in_progress_ids,
            vec!["bd-active"]
        );
        assert_eq!(report.local_in_progress_rows[0].age_seconds, Some(3_601));
    }

    #[test]
    fn strict_mode_fails_when_foreign_open_rows_exist() {
        let mut cfg = config();
        cfg.strict = true;
        let issues = line(&serde_json::json!({
            "id": "br-r37-c1",
            "title": "foreign row",
            "status": "open"
        }));

        let report = analyze_tracker_source_hygiene(&issues, &cfg).expect("analyze");

        assert_eq!(report.status, "fail");
        assert!(fail_on_tracker_source_hygiene_errors(&report).is_err());
    }

    #[test]
    fn parses_fractional_utc_timestamps() {
        assert_eq!(
            parse_utc_timestamp_seconds("1970-01-01T00:00:00.123456789Z"),
            Some(0)
        );
        assert_eq!(
            parse_utc_timestamp_seconds("2033-05-18T03:33:20Z"),
            Some(NOW)
        );
    }

    #[test]
    fn rejects_invalid_jsonl() {
        let error = analyze_tracker_source_hygiene("{not-json}", &config())
            .expect_err("invalid JSONL must fail");
        assert!(error.to_string().contains("line 1"));
    }

    #[test]
    fn missing_dependency_status_blocks_work() {
        let issues = line(&serde_json::json!({
            "id": "bd-blocked",
            "title": "blocked on missing row",
            "status": "open",
            "dependencies": [
                {"type": "blocks", "depends_on_id": "bd-missing"}
            ]
        }));

        let report = analyze_tracker_source_hygiene(&issues, &config()).expect("analyze");

        assert_eq!(report.source_aware_queue_state.verdict, "blocked");
        assert_eq!(report.blocked_local_rows[0].blocked_by[0].status, "missing");
    }

    #[test]
    fn closed_dependencies_do_not_block_ready_work() {
        let issues = [
            line(&serde_json::json!({
                "id": "bd-work",
                "title": "work",
                "status": "open",
                "dependencies": [
                    {"type": "blocks", "depends_on_id": "bd-done"}
                ]
            })),
            line(&serde_json::json!({
                "id": "bd-done",
                "title": "done",
                "status": "closed"
            })),
        ]
        .join("\n");

        let report = analyze_tracker_source_hygiene(&issues, &config()).expect("analyze");

        assert_eq!(report.source_aware_queue_state.verdict, "ready");
        assert_eq!(report.source_aware_ready_rows[0].id, "bd-work");
    }

    #[test]
    fn epic_only_queue_has_create_child_action() {
        let issues = line(&serde_json::json!({
            "id": "bd-epic",
            "title": "only epic",
            "status": "open",
            "issue_type": "epic"
        }));

        let report = analyze_tracker_source_hygiene(&issues, &config()).expect("analyze");

        assert_eq!(report.source_aware_queue_state.verdict, "epic_only");
        assert!(report.source_aware_queue_state.next_safe_actions[0].contains("narrow child bead"));
    }
}
