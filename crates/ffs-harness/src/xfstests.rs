use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum XfstestsStatus {
    Passed,
    Failed,
    Skipped,
    NotRun,
    Planned,
}

impl XfstestsStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
            Self::NotRun => "not_run",
            Self::Planned => "planned",
        }
    }

    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::NotRun | Self::Planned => 1,
            Self::Skipped => 2,
            Self::Passed => 3,
            Self::Failed => 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XfstestsCase {
    pub id: String,
    pub status: XfstestsStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_snippet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowlist_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_row_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_risk_category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_operation_class: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_capabilities: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracker_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub comparison: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct XfstestsRun {
    pub source: String,
    pub check_rc: i32,
    pub dry_run: bool,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub not_run: usize,
    pub planned: usize,
    pub pass_rate: f64,
    pub policy_summary: XfstestsPolicySummary,
    pub tests: Vec<XfstestsCase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct XfstestsPolicySummary {
    pub by_allowlist_status: BTreeMap<String, usize>,
    pub by_classification: BTreeMap<String, usize>,
    pub by_expected_outcome: BTreeMap<String, usize>,
    pub by_user_risk_category: BTreeMap<String, usize>,
    pub by_operation_class: BTreeMap<String, usize>,
    pub not_run_by_classification: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct XfstestsAllowlistEntry {
    pub test_id: String,
    pub failure_reason: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_row_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem_flavor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v1_scope_mapping: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_operation_class: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operation_class_tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_risk_category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection_decision: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifact_requirements: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracker_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repro_command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_plan: Option<XfstestsCommandPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct XfstestsCommandPlan {
    pub plan_id: String,
    pub execution_lane: String,
    pub image_path: String,
    pub scratch_path: String,
    pub mountpoint: String,
    pub test_device: String,
    pub scratch_device: String,
    pub image_hash: String,
    #[serde(default)]
    pub helper_binaries: Vec<String>,
    #[serde(default)]
    pub required_privileges: Vec<String>,
    pub mutation_surface: String,
    pub cleanup_action: String,
    #[serde(default)]
    pub argv: Vec<String>,
    #[serde(default)]
    pub destructive: bool,
    pub expected_plan_outcome: String,
    pub command_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XfstestsBaselineEntry {
    pub test_id: String,
    pub expected_status: XfstestsStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct XfstestsComparison {
    pub regressions: Vec<String>,
    pub improvements: Vec<String>,
    pub unchanged: Vec<String>,
}

const REQUIRED_XFSTESTS_OPERATION_CLASSES: &[&str] = &[
    "read_only_mount",
    "rw_file_lifecycle",
    "directory_mutation",
    "rename_link_semantics",
    "xattr_semantics",
    "fsync_boundary",
    "writeback_cache_unsupported",
    "host_capability_skip",
];

const REQUIRED_XFSTESTS_FILESYSTEM_FLAVORS: &[&str] = &["generic", "ext4", "btrfs"];

const KNOWN_XFSTESTS_RISK_CATEGORIES: &[&str] = &[
    "data_visibility",
    "data_integrity",
    "metadata_integrity",
    "namespace_integrity",
    "operator_honesty",
    "unsupported_feature",
    "host_environment",
];

const KNOWN_XFSTESTS_OUTCOMES: &[&str] = &[
    "expected_pass",
    "product_actionable_failure",
    "environment_blocked",
    "unsupported_by_v1",
    "expected_failure",
];

const REQUIRED_XFSTESTS_ARTIFACTS: &[&str] = &[
    "selected_tests.txt",
    "policy_plan.json",
    "policy_report.md",
    "summary.json",
    "results.json",
    "junit.xml",
    "check.log",
];

const KNOWN_XFSTESTS_COMMAND_PLAN_LANES: &[&str] = &[
    "dry_run_only",
    "fixture_only",
    "permissioned_real",
    "host_skip",
    "unsupported_by_scope",
];

const KNOWN_XFSTESTS_COMMAND_PLAN_PRIVILEGES: &[&str] = &[
    "none",
    "user_mount",
    "fuse_mount",
    "root_required",
    "cap_sys_admin",
    "scratch_device",
    "host_tooling",
];

const KNOWN_XFSTESTS_COMMAND_PLAN_OUTCOMES: &[&str] = &[
    "dry_run_only",
    "fixture_only",
    "permissioned_real",
    "host_skip",
    "unsupported_by_scope",
    "product_failure",
    "harness_failure",
    "cleanup_failure",
];

pub fn load_selected_tests(path: &Path) -> Result<Vec<String>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read selected tests {}", path.display()))?;
    Ok(text
        .lines()
        .map(|line| line.split_once('#').map_or(line, |(prefix, _)| prefix))
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

pub fn load_allowlist(path: &Path) -> Result<Vec<XfstestsAllowlistEntry>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read allowlist {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("invalid allowlist json {}", path.display()))
}

pub fn load_baseline(path: &Path) -> Result<Vec<XfstestsBaselineEntry>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read baseline {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("invalid baseline json {}", path.display()))
}

#[must_use]
pub fn validate_xfstests_policy(
    selected: &[String],
    allowlist: &[XfstestsAllowlistEntry],
) -> Vec<String> {
    let mut errors = Vec::new();
    let mut selected_ids = BTreeSet::new();

    for test_id in selected {
        if !selected_ids.insert(test_id.as_str()) {
            errors.push(format!("duplicate selected xfstests id: {test_id}"));
        }
    }

    let mut policy_ids = BTreeSet::new();
    for entry in allowlist {
        if !policy_ids.insert(entry.test_id.as_str()) {
            errors.push(format!("duplicate xfstests policy id: {}", entry.test_id));
        }

        validate_policy_entry(
            entry,
            selected_ids.contains(entry.test_id.as_str()),
            &mut errors,
        );
    }

    for test_id in &selected_ids {
        if !policy_ids.contains(test_id) {
            errors.push(format!(
                "selected xfstests id lacks policy metadata: {test_id}"
            ));
        }
    }

    for test_id in &policy_ids {
        if !selected_ids.contains(test_id) {
            errors.push(format!(
                "xfstests policy references unselected id: {test_id}"
            ));
        }
    }

    errors
}

#[must_use]
pub fn validate_xfstests_policy_coverage(allowlist: &[XfstestsAllowlistEntry]) -> Vec<String> {
    let mut errors = Vec::new();
    let mut covered = BTreeSet::new();
    let mut flavors = BTreeSet::new();

    for entry in allowlist {
        if let Some(filesystem_flavor) = entry.filesystem_flavor.as_deref() {
            flavors.insert(filesystem_flavor.to_owned());
        }
        if let Some(operation_class) = entry.expected_operation_class.as_deref() {
            covered.insert(operation_class.to_owned());
        }
        for operation_class in &entry.operation_class_tags {
            covered.insert(operation_class.clone());
        }
    }

    for required in REQUIRED_XFSTESTS_OPERATION_CLASSES {
        if !covered.contains(*required) {
            errors.push(format!(
                "xfstests policy is missing representative operation class: {required}"
            ));
        }
    }

    for required in REQUIRED_XFSTESTS_FILESYSTEM_FLAVORS {
        if !flavors.contains(*required) {
            errors.push(format!(
                "xfstests policy is missing representative filesystem flavor: {required}"
            ));
        }
    }

    errors
}

fn validate_policy_entry(entry: &XfstestsAllowlistEntry, selected: bool, errors: &mut Vec<String>) {
    if !selected {
        return;
    }

    validate_policy_identity(entry, errors);
    validate_policy_scope(entry, errors);
    validate_policy_risk(entry, errors);
    validate_policy_artifacts(entry, errors);
    validate_policy_command_plan(entry, errors);
    validate_policy_outcome(entry, errors);
    validate_policy_links(entry, errors);
}

fn validate_policy_identity(entry: &XfstestsAllowlistEntry, errors: &mut Vec<String>) {
    let test_prefix = entry.test_id.split('/').next().unwrap_or_default();
    if !matches!(test_prefix, "generic" | "ext4" | "btrfs") {
        errors.push(format!(
            "xfstests policy has unsupported test id format: {}",
            entry.test_id
        ));
    }

    match entry.status.as_str() {
        "expected_pass" | "known_fail" | "wont_fix" | "likely_pass" => {}
        other => errors.push(format!(
            "xfstests policy {} has unknown status: {other}",
            entry.test_id
        )),
    }

    match entry.policy_row_id.as_deref() {
        Some(row_id) if row_id.starts_with("xfstests-policy-") => {}
        Some(row_id) => errors.push(format!(
            "xfstests policy {} has malformed policy_row_id: {row_id}",
            entry.test_id
        )),
        None => errors.push(format!(
            "xfstests policy {} is missing policy_row_id",
            entry.test_id
        )),
    }

    match entry.filesystem_flavor.as_deref() {
        Some("generic" | "ext4" | "btrfs")
            if entry.filesystem_flavor.as_deref() == Some(test_prefix) => {}
        Some("generic" | "ext4" | "btrfs") => errors.push(format!(
            "xfstests policy {} has filesystem_flavor that does not match id prefix",
            entry.test_id
        )),
        Some(other) => errors.push(format!(
            "xfstests policy {} has unknown filesystem_flavor: {other}",
            entry.test_id
        )),
        None => errors.push(format!(
            "xfstests policy {} is missing filesystem_flavor",
            entry.test_id
        )),
    }
}

fn validate_policy_scope(entry: &XfstestsAllowlistEntry, errors: &mut Vec<String>) {
    match entry.v1_scope_mapping.as_deref() {
        Some(reference) if is_supported_scope_reference(reference) => {}
        Some(reference) => errors.push(format!(
            "xfstests policy {} has stale V1 scope mapping: {reference}",
            entry.test_id
        )),
        None => errors.push(format!(
            "xfstests policy {} is missing V1 scope mapping",
            entry.test_id
        )),
    }

    match entry.expected_operation_class.as_deref() {
        Some(operation_class) if is_known_operation_class(operation_class) => {}
        Some(operation_class) => errors.push(format!(
            "xfstests policy {} has unknown expected operation class: {operation_class}",
            entry.test_id
        )),
        None => errors.push(format!(
            "xfstests policy {} is missing expected operation class",
            entry.test_id
        )),
    }
    for operation_class in &entry.operation_class_tags {
        if !is_known_operation_class(operation_class) {
            errors.push(format!(
                "xfstests policy {} has unknown operation class tag: {operation_class}",
                entry.test_id
            ));
        }
    }
}

fn validate_policy_risk(entry: &XfstestsAllowlistEntry, errors: &mut Vec<String>) {
    match entry.user_risk_category.as_deref() {
        Some(category) if KNOWN_XFSTESTS_RISK_CATEGORIES.contains(&category) => {}
        Some(category) => errors.push(format!(
            "xfstests policy {} has unknown user risk category: {category}",
            entry.test_id
        )),
        None => errors.push(format!(
            "xfstests policy {} is missing user risk category",
            entry.test_id
        )),
    }

    match entry.expected_outcome.as_deref() {
        Some(outcome) if KNOWN_XFSTESTS_OUTCOMES.contains(&outcome) => {}
        Some(outcome) => errors.push(format!(
            "xfstests policy {} has unknown expected outcome: {outcome}",
            entry.test_id
        )),
        None => errors.push(format!(
            "xfstests policy {} is missing expected outcome",
            entry.test_id
        )),
    }

    if let Some(outcome) = entry.expected_outcome.as_deref() {
        let expected = expected_outcome_for_classification(entry);
        if outcome != expected {
            errors.push(format!(
                "xfstests policy {} expected_outcome={outcome} does not match status/classification expectation {expected}",
                entry.test_id
            ));
        }
    }

    match entry.selection_decision.as_deref() {
        Some("selected" | "skipped") => {}
        Some(decision) => errors.push(format!(
            "xfstests policy {} has unknown selection decision: {decision}",
            entry.test_id
        )),
        None => errors.push(format!(
            "xfstests policy {} is missing selection decision",
            entry.test_id
        )),
    }
}

fn validate_policy_artifacts(entry: &XfstestsAllowlistEntry, errors: &mut Vec<String>) {
    for required_artifact in REQUIRED_XFSTESTS_ARTIFACTS {
        if !entry
            .artifact_requirements
            .iter()
            .any(|artifact| artifact == required_artifact)
        {
            errors.push(format!(
                "xfstests policy {} is missing artifact requirement: {required_artifact}",
                entry.test_id
            ));
        }
    }

    if entry.required_capabilities.is_empty() {
        errors.push(format!(
            "xfstests policy {} is missing required_capabilities",
            entry.test_id
        ));
    }
}

fn validate_policy_command_plan(entry: &XfstestsAllowlistEntry, errors: &mut Vec<String>) {
    let Some(plan) = entry.command_plan.as_ref() else {
        errors.push(format!(
            "xfstests policy {} is missing command_plan",
            entry.test_id
        ));
        return;
    };

    validate_command_plan_identity(entry, plan, errors);
    validate_command_plan_paths(entry, plan, errors);
    validate_command_plan_helpers(entry, plan, errors);
    validate_command_plan_argv(entry, plan, errors);

    if plan.destructive && plan.execution_lane != "permissioned_real" {
        errors.push(format!(
            "xfstests policy {} command plan marks destructive action outside permissioned_real lane",
            entry.test_id
        ));
    }
}

fn validate_command_plan_identity(
    entry: &XfstestsAllowlistEntry,
    plan: &XfstestsCommandPlan,
    errors: &mut Vec<String>,
) {
    if !plan.plan_id.starts_with("xfstests-plan-") {
        errors.push(format!(
            "xfstests policy {} has malformed command plan id: {}",
            entry.test_id, plan.plan_id
        ));
    }

    if !KNOWN_XFSTESTS_COMMAND_PLAN_LANES.contains(&plan.execution_lane.as_str()) {
        errors.push(format!(
            "xfstests policy {} has unknown command plan lane: {}",
            entry.test_id, plan.execution_lane
        ));
    }

    if !KNOWN_XFSTESTS_COMMAND_PLAN_OUTCOMES.contains(&plan.expected_plan_outcome.as_str()) {
        errors.push(format!(
            "xfstests policy {} command plan has unknown expected outcome: {}",
            entry.test_id, plan.expected_plan_outcome
        ));
    }
}

fn validate_command_plan_paths(
    entry: &XfstestsAllowlistEntry,
    plan: &XfstestsCommandPlan,
    errors: &mut Vec<String>,
) {
    if !is_temp_scoped_path(&plan.image_path) {
        errors.push(format!(
            "xfstests policy {} command plan uses non-temporary image path: {}",
            entry.test_id, plan.image_path
        ));
    }

    if !is_temp_scoped_path(&plan.scratch_path) {
        errors.push(format!(
            "xfstests policy {} command plan uses non-temporary scratch path: {}",
            entry.test_id, plan.scratch_path
        ));
    }

    if !is_temp_scoped_path(&plan.mountpoint) {
        errors.push(format!(
            "xfstests policy {} command plan uses non-temporary mountpoint: {}",
            entry.test_id, plan.mountpoint
        ));
    }

    if !is_temp_scoped_path(&plan.test_device) {
        errors.push(format!(
            "xfstests policy {} command plan uses non-temporary test device placeholder: {}",
            entry.test_id, plan.test_device
        ));
    }

    if !is_temp_scoped_path(&plan.scratch_device) {
        errors.push(format!(
            "xfstests policy {} command plan uses non-temporary scratch device placeholder: {}",
            entry.test_id, plan.scratch_device
        ));
    }

    if !plan.image_hash.starts_with("sha256:") || plan.image_hash.len() <= "sha256:".len() {
        errors.push(format!(
            "xfstests policy {} command plan is missing image hash",
            entry.test_id
        ));
    }
}

fn validate_command_plan_helpers(
    entry: &XfstestsAllowlistEntry,
    plan: &XfstestsCommandPlan,
    errors: &mut Vec<String>,
) {
    if plan.helper_binaries.is_empty() {
        errors.push(format!(
            "xfstests policy {} command plan is missing helper binaries",
            entry.test_id
        ));
    }
    for helper in &plan.helper_binaries {
        if is_broad_shell_token(helper) || helper.contains('<') || helper.trim().is_empty() {
            errors.push(format!(
                "xfstests policy {} command plan has unresolved helper binary: {helper}",
                entry.test_id
            ));
        }
    }

    if plan.required_privileges.is_empty() {
        errors.push(format!(
            "xfstests policy {} command plan is missing required privileges",
            entry.test_id
        ));
    }
    for privilege in &plan.required_privileges {
        if !KNOWN_XFSTESTS_COMMAND_PLAN_PRIVILEGES.contains(&privilege.as_str()) {
            errors.push(format!(
                "xfstests policy {} command plan has unknown privilege requirement: {privilege}",
                entry.test_id
            ));
        }
    }

    if plan.cleanup_action.trim().is_empty() {
        errors.push(format!(
            "xfstests policy {} command plan is missing cleanup action",
            entry.test_id
        ));
    }

    if plan.mutation_surface.trim().is_empty() {
        errors.push(format!(
            "xfstests policy {} command plan is missing mutation surface",
            entry.test_id
        ));
    }

    if plan.command_summary.trim().is_empty() {
        errors.push(format!(
            "xfstests policy {} command plan is missing human-readable command summary",
            entry.test_id
        ));
    }
}

fn validate_command_plan_argv(
    entry: &XfstestsAllowlistEntry,
    plan: &XfstestsCommandPlan,
    errors: &mut Vec<String>,
) {
    if plan.argv.is_empty() {
        errors.push(format!(
            "xfstests policy {} command plan is missing argv",
            entry.test_id
        ));
    }
    if !plan.argv.iter().any(|arg| arg == &entry.test_id) {
        errors.push(format!(
            "xfstests policy {} command plan argv does not name the test id",
            entry.test_id
        ));
    }
    for arg in &plan.argv {
        if is_broad_shell_token(arg) || arg.contains("&&") || arg.contains(';') || arg.contains('*')
        {
            errors.push(format!(
                "xfstests policy {} command plan has broad shell command token: {arg}",
                entry.test_id
            ));
        }
    }
}

fn validate_policy_outcome(entry: &XfstestsAllowlistEntry, errors: &mut Vec<String>) {
    match entry.classification.as_deref() {
        Some(
            "expected_failure"
            | "environment_blocked"
            | "unsupported_by_v1"
            | "harness_blocked"
            | "product_actionable",
        ) => {}
        Some(other) => errors.push(format!(
            "xfstests policy {} has unknown classification: {other}",
            entry.test_id
        )),
        None => errors.push(format!(
            "xfstests policy {} is missing classification",
            entry.test_id
        )),
    }

    if entry.failure_reason.trim().is_empty() {
        errors.push(format!(
            "xfstests policy {} is missing outcome rationale",
            entry.test_id
        ));
    }

    let needs_skip_reason = entry.status != "expected_pass";
    if needs_skip_reason && entry.failure_reason.trim().is_empty() {
        errors.push(format!(
            "xfstests policy {} is missing skip reason",
            entry.test_id
        ));
    }

    if entry.classification.as_deref() == Some("unsupported_by_v1") {
        match entry.scope_reference.as_deref() {
            Some(reference) if is_supported_scope_reference(reference) => {}
            Some(reference) => errors.push(format!(
                "xfstests policy {} has stale scope reference: {reference}",
                entry.test_id
            )),
            None => errors.push(format!(
                "xfstests policy {} marks unsupported_by_v1 without scope_reference",
                entry.test_id
            )),
        }
    }

    if entry.status == "wont_fix" && entry.classification.as_deref() != Some("unsupported_by_v1") {
        errors.push(format!(
            "xfstests policy {} is wont_fix without unsupported_by_v1 classification",
            entry.test_id
        ));
    }
}

fn validate_policy_links(entry: &XfstestsAllowlistEntry, errors: &mut Vec<String>) {
    match entry.tracker_id.as_deref() {
        Some(tracker_id) if tracker_id.starts_with("bd-") => {}
        Some(tracker_id) => errors.push(format!(
            "xfstests policy {} has malformed tracker_id: {tracker_id}",
            entry.test_id
        )),
        None => errors.push(format!(
            "xfstests policy {} is missing tracker_id",
            entry.test_id
        )),
    }

    match entry.repro_command.as_deref() {
        Some(command) if !command.is_empty() => {}
        Some(_) | None => errors.push(format!(
            "xfstests policy {} is missing reproduction command",
            entry.test_id
        )),
    }
}

fn is_supported_scope_reference(reference: &str) -> bool {
    reference.starts_with("README.md#")
        || reference.starts_with("FEATURE_PARITY.md#")
        || reference == "README.md"
        || reference == "FEATURE_PARITY.md"
}

fn is_known_operation_class(operation_class: &str) -> bool {
    REQUIRED_XFSTESTS_OPERATION_CLASSES.contains(&operation_class)
}

fn is_temp_scoped_path(path: &str) -> bool {
    path.starts_with("${TMPDIR:-/tmp}/frankenfs-xfstests/")
        || path.starts_with("$TMPDIR/frankenfs-xfstests/")
        || path.starts_with("/tmp/frankenfs-xfstests/")
}

fn is_broad_shell_token(token: &str) -> bool {
    matches!(token, "sh" | "bash" | "zsh" | "-c" | "shell")
}

fn expected_outcome_for_classification(entry: &XfstestsAllowlistEntry) -> &'static str {
    match (entry.status.as_str(), entry.classification.as_deref()) {
        ("expected_pass", _) => "expected_pass",
        (_, Some("product_actionable")) => "product_actionable_failure",
        (_, Some("environment_blocked" | "harness_blocked")) => "environment_blocked",
        (_, Some("unsupported_by_v1")) => "unsupported_by_v1",
        _ => "expected_failure",
    }
}

#[must_use]
pub fn parse_check_output(
    selected: &[String],
    check_log: &str,
    check_rc: i32,
    dry_run: bool,
) -> XfstestsRun {
    let mut cases: Vec<XfstestsCase> = selected
        .iter()
        .map(|id| XfstestsCase {
            id: id.clone(),
            status: XfstestsStatus::NotRun,
            duration_secs: None,
            output_snippet: None,
            allowlist_status: None,
            failure_reason: None,
            policy_row_id: None,
            classification: None,
            expected_outcome: None,
            user_risk_category: None,
            expected_operation_class: None,
            required_capabilities: Vec::new(),
            tracker_id: None,
            comparison: Vec::new(),
        })
        .collect();

    for line in check_log.lines() {
        let lower = line.to_ascii_lowercase();
        for case in &mut cases {
            if !line_mentions_test_id(line, case.id.as_str()) {
                continue;
            }

            let candidate = if lower.contains("not run") || lower.contains("notrun") {
                Some(XfstestsStatus::NotRun)
            } else if lower.contains("skipped") {
                Some(XfstestsStatus::Skipped)
            } else if contains_word(&lower, "fail")
                || contains_word(&lower, "failed")
                || contains_word(&lower, "error")
            {
                Some(XfstestsStatus::Failed)
            } else if contains_word(&lower, "pass")
                || contains_word(&lower, "passed")
                || contains_word(&lower, "ok")
                || contains_word(&lower, "success")
            {
                Some(XfstestsStatus::Passed)
            } else {
                None
            };

            if let Some(next) = candidate {
                if next.rank() >= case.status.rank() {
                    case.status = next;
                    case.output_snippet = Some(line.trim().to_owned());
                }
                if case.duration_secs.is_none() {
                    case.duration_secs = parse_duration_secs(line);
                }
            }
        }
    }

    if check_rc == 0 && !dry_run {
        for case in &mut cases {
            if case.status == XfstestsStatus::NotRun && case.output_snippet.is_none() {
                case.status = XfstestsStatus::Passed;
            }
        }
    }

    summarize_run("check-log", check_rc, dry_run, cases)
}

#[must_use]
pub fn summarize_uniform(
    selected: &[String],
    status: XfstestsStatus,
    note: Option<&str>,
) -> XfstestsRun {
    let cases = selected
        .iter()
        .map(|id| XfstestsCase {
            id: id.clone(),
            status,
            duration_secs: None,
            output_snippet: note.map(ToOwned::to_owned),
            allowlist_status: None,
            failure_reason: None,
            policy_row_id: None,
            classification: None,
            expected_outcome: None,
            user_risk_category: None,
            expected_operation_class: None,
            required_capabilities: Vec::new(),
            tracker_id: None,
            comparison: Vec::new(),
        })
        .collect();
    summarize_run("uniform", 0, false, cases)
}

pub fn apply_allowlist(run: &mut XfstestsRun, allowlist: &[XfstestsAllowlistEntry]) {
    let by_test: BTreeMap<&str, &XfstestsAllowlistEntry> = allowlist
        .iter()
        .map(|entry| (entry.test_id.as_str(), entry))
        .collect();
    for case in &mut run.tests {
        if let Some(entry) = by_test.get(case.id.as_str()) {
            case.allowlist_status = Some(entry.status.clone());
            case.failure_reason = Some(entry.failure_reason.clone());
            case.policy_row_id = entry.policy_row_id.clone();
            case.classification = entry.classification.clone();
            case.expected_outcome = entry.expected_outcome.clone();
            case.user_risk_category = entry.user_risk_category.clone();
            case.expected_operation_class = entry.expected_operation_class.clone();
            case.required_capabilities = entry.required_capabilities.clone();
            case.tracker_id = entry.tracker_id.clone();
        }
    }
    refresh_policy_summary(run);
}

pub fn compare_against_baseline(
    run: &mut XfstestsRun,
    baseline: &[XfstestsBaselineEntry],
) -> XfstestsComparison {
    let baseline_map: BTreeMap<&str, XfstestsStatus> = baseline
        .iter()
        .map(|entry| (entry.test_id.as_str(), entry.expected_status))
        .collect();
    let mut comparison = XfstestsComparison::default();

    for case in &mut run.tests {
        let Some(expected) = baseline_map.get(case.id.as_str()).copied() else {
            continue;
        };

        if expected == case.status {
            comparison.unchanged.push(case.id.clone());
            case.comparison
                .push(format!("baseline match: {}", expected.as_str()));
            continue;
        }

        let message = format!("{} -> {}", expected.as_str(), case.status.as_str());
        match (expected, case.status) {
            (
                XfstestsStatus::Passed,
                XfstestsStatus::Failed | XfstestsStatus::Skipped | XfstestsStatus::NotRun,
            ) => {
                comparison
                    .regressions
                    .push(format!("{} ({message})", case.id));
                case.comparison.push(format!("regression: {message}"));
            }
            (
                XfstestsStatus::Failed | XfstestsStatus::Skipped | XfstestsStatus::NotRun,
                XfstestsStatus::Passed,
            ) => {
                comparison
                    .improvements
                    .push(format!("{} ({message})", case.id));
                case.comparison.push(format!("improvement: {message}"));
            }
            _ => {
                comparison.unchanged.push(case.id.clone());
                case.comparison.push(format!("status drift: {message}"));
            }
        }
    }

    comparison
}

pub fn write_junit_xml(path: &Path, run: &XfstestsRun) -> Result<()> {
    let failures = run.failed;
    let skipped = run.skipped + run.not_run + run.planned;
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let _ = writeln!(
        xml,
        "<testsuite name=\"ffs_xfstests_e2e\" tests=\"{}\" failures=\"{}\" skipped=\"{}\">",
        run.total, failures, skipped
    );

    for case in &run.tests {
        let _ = write!(
            xml,
            "  <testcase name=\"{}\" time=\"{:.3}\">",
            escape_xml(&case.id),
            case.duration_secs.unwrap_or(0.0)
        );
        match case.status {
            XfstestsStatus::Failed => {
                let detail = case
                    .output_snippet
                    .as_deref()
                    .or(case.failure_reason.as_deref())
                    .unwrap_or("xfstests failure");
                let detail = escape_xml(detail);
                let _ = write!(
                    xml,
                    "<failure message=\"xfstests failure\">{detail}</failure>"
                );
            }
            XfstestsStatus::Skipped | XfstestsStatus::NotRun | XfstestsStatus::Planned => {
                let detail = escape_xml(case.status.as_str());
                let _ = write!(xml, "<skipped message=\"{detail}\"/>");
            }
            XfstestsStatus::Passed => {}
        }
        xml.push_str("</testcase>\n");
    }
    xml.push_str("</testsuite>\n");
    fs::write(path, xml).with_context(|| format!("failed to write junit xml {}", path.display()))
}

fn summarize_run(
    source: &str,
    check_rc: i32,
    dry_run: bool,
    tests: Vec<XfstestsCase>,
) -> XfstestsRun {
    let mut passed = 0_usize;
    let mut failed = 0_usize;
    let mut skipped = 0_usize;
    let mut not_run = 0_usize;
    let mut planned = 0_usize;

    for case in &tests {
        match case.status {
            XfstestsStatus::Passed => passed += 1,
            XfstestsStatus::Failed => failed += 1,
            XfstestsStatus::Skipped => skipped += 1,
            XfstestsStatus::NotRun => not_run += 1,
            XfstestsStatus::Planned => planned += 1,
        }
    }

    let total = tests.len();
    let pass_rate = if total == 0 {
        0.0
    } else {
        passed as f64 / total as f64
    };

    XfstestsRun {
        source: source.to_owned(),
        check_rc,
        dry_run,
        total,
        passed,
        failed,
        skipped,
        not_run,
        planned,
        pass_rate,
        policy_summary: XfstestsPolicySummary::default(),
        tests,
    }
}

fn refresh_policy_summary(run: &mut XfstestsRun) {
    let mut summary = XfstestsPolicySummary::default();

    for case in &run.tests {
        bump_count_if_present(
            &mut summary.by_allowlist_status,
            case.allowlist_status.as_deref(),
        );
        bump_count_if_present(
            &mut summary.by_classification,
            case.classification.as_deref(),
        );
        bump_count_if_present(
            &mut summary.by_expected_outcome,
            case.expected_outcome.as_deref(),
        );
        bump_count_if_present(
            &mut summary.by_user_risk_category,
            case.user_risk_category.as_deref(),
        );
        bump_count_if_present(
            &mut summary.by_operation_class,
            case.expected_operation_class.as_deref(),
        );

        if case.status == XfstestsStatus::NotRun
            && let Some(classification) = case.classification.as_ref()
        {
            *summary
                .not_run_by_classification
                .entry(classification.clone())
                .or_default() += 1;
        }
    }

    run.policy_summary = summary;
}

fn bump_count_if_present(counts: &mut BTreeMap<String, usize>, value: Option<&str>) {
    if let Some(value) = value {
        *counts.entry(value.to_owned()).or_default() += 1;
    }
}

fn contains_word(haystack: &str, needle: &str) -> bool {
    haystack
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '/')
        .any(|part| part == needle)
}

fn line_mentions_test_id(line: &str, test_id: &str) -> bool {
    line.split_whitespace().any(|part| part == test_id)
}

fn parse_duration_secs(line: &str) -> Option<f64> {
    for token in line.split_whitespace() {
        if let Some(raw) = token.strip_suffix('s') {
            if let Ok(value) = raw.parse::<f64>() {
                return Some(value);
            }
        }
    }
    None
}

fn escape_xml(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn repo_xfstests_allowlist_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("scripts")
            .join("e2e")
            .join("xfstests_allowlist.json")
    }

    fn repo_xfstests_list_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("scripts")
            .join("e2e")
            .join(name)
    }

    fn valid_policy_entry(test_id: &str) -> XfstestsAllowlistEntry {
        let filesystem_flavor = test_id.split('/').next().unwrap_or("generic").to_owned();
        XfstestsAllowlistEntry {
            test_id: test_id.to_owned(),
            failure_reason: "selected canary; failure is product-actionable".to_owned(),
            status: "expected_pass".to_owned(),
            policy_row_id: Some(format!("xfstests-policy-{}", test_id.replace('/', "-"))),
            filesystem_flavor: Some(filesystem_flavor),
            v1_scope_mapping: Some("README.md#v1-filesystem-scope".to_owned()),
            expected_operation_class: Some("read_only_mount".to_owned()),
            operation_class_tags: Vec::new(),
            user_risk_category: Some("data_visibility".to_owned()),
            expected_outcome: Some("expected_pass".to_owned()),
            selection_decision: Some("selected".to_owned()),
            artifact_requirements: REQUIRED_XFSTESTS_ARTIFACTS
                .iter()
                .map(|artifact| (*artifact).to_owned())
                .collect(),
            required_capabilities: vec!["fuse_mount".to_owned()],
            classification: Some("product_actionable".to_owned()),
            scope_reference: None,
            tracker_id: Some("bd-rchk3.2".to_owned()),
            repro_command: Some(format!("./check -n {test_id}")),
            command_plan: Some(XfstestsCommandPlan {
                plan_id: format!("xfstests-plan-{}", test_id.replace('/', "-")),
                execution_lane: "dry_run_only".to_owned(),
                image_path: format!(
                    "${{TMPDIR:-/tmp}}/frankenfs-xfstests/images/{}.img",
                    test_id.replace('/', "-")
                ),
                scratch_path: format!(
                    "${{TMPDIR:-/tmp}}/frankenfs-xfstests/scratch/{}",
                    test_id.replace('/', "-")
                ),
                mountpoint: format!(
                    "${{TMPDIR:-/tmp}}/frankenfs-xfstests/mnt/{}",
                    test_id.replace('/', "-")
                ),
                test_device: format!(
                    "${{TMPDIR:-/tmp}}/frankenfs-xfstests/devices/{}.test.img",
                    test_id.replace('/', "-")
                ),
                scratch_device: format!(
                    "${{TMPDIR:-/tmp}}/frankenfs-xfstests/devices/{}.scratch.img",
                    test_id.replace('/', "-")
                ),
                image_hash: format!("sha256:test-fixture-{}", test_id.replace('/', "-")),
                helper_binaries: vec![
                    "xfstests/check".to_owned(),
                    "ffs-cli".to_owned(),
                    "fusermount3".to_owned(),
                ],
                required_privileges: vec!["none".to_owned(), "fuse_mount".to_owned()],
                mutation_surface: "dry-run command selection under temp root".to_owned(),
                cleanup_action: "umount temp mountpoint if mounted; remove temp scratch root"
                    .to_owned(),
                argv: vec!["./check".to_owned(), "-n".to_owned(), test_id.to_owned()],
                destructive: false,
                expected_plan_outcome: "dry_run_only".to_owned(),
                command_summary: format!("dry-run xfstests plan for {test_id} under temp root"),
            }),
        }
    }

    #[test]
    fn parse_check_output_classifies_statuses_and_duration() {
        let selected = vec![
            "generic/001".to_owned(),
            "ext4/003".to_owned(),
            "generic/030".to_owned(),
        ];
        let log = "\
generic/001  1s ... pass\n\
ext4/003  2.5s ... failed due to mismatch\n\
generic/030  skipped: needs root\n";

        let run = parse_check_output(&selected, log, 1, false);

        assert_eq!(run.passed, 1);
        assert_eq!(run.failed, 1);
        assert_eq!(run.skipped, 1);
        assert_eq!(run.not_run, 0);
        assert_eq!(run.tests[0].duration_secs, Some(1.0));
        assert_eq!(run.tests[1].duration_secs, Some(2.5));
        assert_eq!(run.tests[0].status, XfstestsStatus::Passed);
        assert_eq!(run.tests[1].status, XfstestsStatus::Failed);
        assert_eq!(run.tests[2].status, XfstestsStatus::Skipped);
    }

    #[test]
    fn parse_check_output_promotes_not_run_to_passed_on_clean_non_dry_run() {
        let selected = vec!["generic/001".to_owned()];
        let run = parse_check_output(&selected, "", 0, false);
        assert_eq!(run.tests[0].status, XfstestsStatus::Passed);
        assert_eq!(run.passed, 1);
    }

    #[test]
    fn parse_check_output_preserves_explicit_not_run_status() {
        let selected = vec!["generic/001".to_owned(), "generic/030".to_owned()];
        let log = "\
generic/001  -- not run: requires aio-stress\n\
generic/030  skipped: needs root\n";

        let run = parse_check_output(&selected, log, 0, false);

        assert_eq!(run.not_run, 1);
        assert_eq!(run.skipped, 1);
        assert_eq!(run.passed, 0);
        assert_eq!(run.tests[0].status, XfstestsStatus::NotRun);
        assert_eq!(run.tests[1].status, XfstestsStatus::Skipped);
    }

    #[test]
    fn parse_check_output_requires_exact_test_id_match() {
        let selected = vec!["generic/001".to_owned(), "generic/0010".to_owned()];
        let log = "\
generic/0010  1s ... failed due to mismatch\n\
generic/001  2s ... pass\n";

        let run = parse_check_output(&selected, log, 1, false);

        assert_eq!(run.tests[0].status, XfstestsStatus::Passed);
        assert_eq!(run.tests[1].status, XfstestsStatus::Failed);
    }

    #[test]
    fn allowlist_annotations_are_applied() {
        let selected = vec!["generic/001".to_owned()];
        let mut run = summarize_uniform(&selected, XfstestsStatus::Failed, Some("boom"));
        let allowlist = vec![XfstestsAllowlistEntry {
            test_id: "generic/001".to_owned(),
            failure_reason: "requires unsupported ioctl".to_owned(),
            status: "known_fail".to_owned(),
            classification: Some("expected_failure".to_owned()),
            expected_outcome: Some("expected_failure".to_owned()),
            ..XfstestsAllowlistEntry::default()
        }];

        apply_allowlist(&mut run, &allowlist);

        assert_eq!(run.tests[0].allowlist_status.as_deref(), Some("known_fail"));
        assert_eq!(
            run.tests[0].failure_reason.as_deref(),
            Some("requires unsupported ioctl")
        );
        assert_eq!(
            run.tests[0].classification.as_deref(),
            Some("expected_failure")
        );
        assert_eq!(
            run.tests[0].expected_outcome.as_deref(),
            Some("expected_failure")
        );
        assert_eq!(
            run.policy_summary.by_classification.get("expected_failure"),
            Some(&1)
        );
    }

    #[test]
    fn policy_summary_separates_not_run_rows_by_classification() {
        let selected = vec!["generic/003".to_owned(), "generic/030".to_owned()];
        let mut run = summarize_uniform(&selected, XfstestsStatus::NotRun, Some("blocked"));
        let mut environment = valid_policy_entry("generic/003");
        environment.status = "likely_pass".to_owned();
        environment.classification = Some("environment_blocked".to_owned());
        environment.expected_outcome = Some("environment_blocked".to_owned());
        environment.user_risk_category = Some("host_environment".to_owned());
        environment.expected_operation_class = Some("host_capability_skip".to_owned());

        let mut product = valid_policy_entry("generic/030");
        product.status = "known_fail".to_owned();
        product.classification = Some("product_actionable".to_owned());
        product.expected_outcome = Some("product_actionable_failure".to_owned());
        product.user_risk_category = Some("data_integrity".to_owned());
        product.expected_operation_class = Some("rw_file_lifecycle".to_owned());

        apply_allowlist(&mut run, &[environment, product]);

        assert_eq!(
            run.policy_summary
                .not_run_by_classification
                .get("environment_blocked"),
            Some(&1)
        );
        assert_eq!(
            run.policy_summary
                .not_run_by_classification
                .get("product_actionable"),
            Some(&1)
        );
        assert_eq!(
            run.policy_summary
                .by_expected_outcome
                .get("product_actionable_failure"),
            Some(&1)
        );
        assert_eq!(
            run.tests[0].required_capabilities,
            vec!["fuse_mount".to_owned()]
        );
    }

    #[test]
    fn ext4_ioctl_allowlist_entries_match_current_runtime_evidence() {
        let allowlist = load_allowlist(&repo_xfstests_allowlist_path()).expect("load allowlist");
        let by_test: BTreeMap<&str, &XfstestsAllowlistEntry> = allowlist
            .iter()
            .map(|entry| (entry.test_id.as_str(), entry))
            .collect();

        let ext4_001 = by_test.get("ext4/001").expect("ext4/001 allowlist entry");
        assert_eq!(ext4_001.status, "likely_pass");
        assert!(
            ext4_001.failure_reason.contains("ZERO_RANGE"),
            "ext4/001 should reference zero-range coverage: {}",
            ext4_001.failure_reason
        );
        assert!(
            ext4_001.failure_reason.contains("FIEMAP"),
            "ext4/001 should reference fiemap coverage: {}",
            ext4_001.failure_reason
        );
        assert!(
            ext4_001
                .failure_reason
                .contains("no longer blocked on missing FIEMAP forwarding"),
            "ext4/001 should not regress to the stale FIEMAP-forwarding claim: {}",
            ext4_001.failure_reason
        );

        let ext4_005 = by_test.get("ext4/005").expect("ext4/005 allowlist entry");
        assert_eq!(ext4_005.status, "known_fail");
        assert!(
            ext4_005.failure_reason.contains("chattr -e"),
            "ext4/005 should name the real xfstests operation: {}",
            ext4_005.failure_reason
        );
        assert!(
            ext4_005.failure_reason.contains("EXT4_EXTENTS_FL"),
            "ext4/005 should call out the system-managed extent flag: {}",
            ext4_005.failure_reason
        );
        assert!(
            ext4_005
                .failure_reason
                .contains("mounted-path EXT4_IOC_GETFLAGS")
                && ext4_005.failure_reason.contains("EXT4_IOC_SETFLAGS"),
            "ext4/005 should distinguish the unsupported extent conversion from supported flag ioctls: {}",
            ext4_005.failure_reason
        );
    }

    #[test]
    fn repo_xfstests_policy_covers_curated_subset() -> Result<()> {
        let mut selected = load_selected_tests(&repo_xfstests_list_path("xfstests_generic.list"))?;
        selected.extend(load_selected_tests(&repo_xfstests_list_path(
            "xfstests_ext4.list",
        ))?);
        selected.extend(load_selected_tests(&repo_xfstests_list_path(
            "xfstests_btrfs.list",
        ))?);
        let allowlist = load_allowlist(&repo_xfstests_allowlist_path())?;

        let mut errors = validate_xfstests_policy(&selected, &allowlist);
        errors.extend(validate_xfstests_policy_coverage(&allowlist));

        assert!(
            errors.is_empty(),
            "xfstests policy must cover the curated subset cleanly: {errors:#?}"
        );
        Ok(())
    }

    #[test]
    fn xfstests_policy_rejects_missing_artifact_requirements() {
        let selected = vec!["generic/001".to_owned()];
        let mut entry = valid_policy_entry("generic/001");
        entry
            .artifact_requirements
            .retain(|artifact| artifact != "policy_report.md");

        let errors = validate_xfstests_policy(&selected, &[entry]);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("missing artifact requirement: policy_report.md")),
            "expected missing artifact requirement error, got {errors:#?}"
        );
    }

    #[test]
    fn xfstests_policy_rejects_missing_check_log_artifact_requirement() {
        let selected = vec!["generic/001".to_owned()];
        let mut entry = valid_policy_entry("generic/001");
        entry
            .artifact_requirements
            .retain(|artifact| artifact != "check.log");

        let errors = validate_xfstests_policy(&selected, &[entry]);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("missing artifact requirement: check.log")),
            "expected missing check.log artifact requirement error, got {errors:#?}"
        );
    }

    #[test]
    fn xfstests_policy_rejects_missing_risk_outcome_or_operation_metadata() {
        let selected = vec!["generic/001".to_owned()];
        let mut entry = valid_policy_entry("generic/001");
        entry.expected_operation_class = None;
        entry.user_risk_category = None;
        entry.expected_outcome = None;

        let errors = validate_xfstests_policy(&selected, &[entry]);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("missing expected operation class")),
            "expected missing operation class error, got {errors:#?}"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("missing user risk category")),
            "expected missing risk category error, got {errors:#?}"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("missing expected outcome")),
            "expected missing expected outcome error, got {errors:#?}"
        );
    }

    #[test]
    fn xfstests_policy_rejects_missing_command_plan() {
        let selected = vec!["generic/001".to_owned()];
        let mut entry = valid_policy_entry("generic/001");
        entry.command_plan = None;

        let errors = validate_xfstests_policy(&selected, &[entry]);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("missing command_plan")),
            "expected missing command plan error, got {errors:#?}"
        );
    }

    #[test]
    fn xfstests_policy_rejects_unsafe_command_plan_fields() {
        let selected = vec!["generic/001".to_owned()];
        let mut entry = valid_policy_entry("generic/001");
        let plan = entry.command_plan.as_mut().expect("command plan");
        plan.image_path = "/var/lib/frankenfs/fixture.img".to_owned();
        plan.scratch_path = "/srv/xfstests/scratch".to_owned();
        plan.mountpoint.clear();
        plan.test_device = "/dev/loop0".to_owned();
        plan.scratch_device = "/dev/loop1".to_owned();
        plan.image_hash.clear();
        plan.helper_binaries = vec!["bash".to_owned()];
        plan.required_privileges = vec!["magic_admin".to_owned()];
        plan.cleanup_action.clear();
        plan.command_summary.clear();
        plan.argv = vec!["bash".to_owned(), "-c".to_owned(), "rm *".to_owned()];

        let errors = validate_xfstests_policy(&selected, &[entry]);

        for expected in [
            "non-temporary image path",
            "non-temporary scratch path",
            "non-temporary mountpoint",
            "non-temporary test device placeholder",
            "non-temporary scratch device placeholder",
            "missing image hash",
            "unresolved helper binary",
            "unknown privilege requirement",
            "missing cleanup action",
            "missing human-readable command summary",
            "does not name the test id",
            "broad shell command token",
        ] {
            assert!(
                errors.iter().any(|error| error.contains(expected)),
                "expected {expected} error, got {errors:#?}"
            );
        }
    }

    #[test]
    fn xfstests_policy_rejects_destructive_plan_outside_permissioned_lane() {
        let selected = vec!["generic/001".to_owned()];
        let mut entry = valid_policy_entry("generic/001");
        let plan = entry.command_plan.as_mut().expect("command plan");
        plan.destructive = true;
        plan.execution_lane = "dry_run_only".to_owned();

        let errors = validate_xfstests_policy(&selected, &[entry]);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("outside permissioned_real lane")),
            "expected destructive lane error, got {errors:#?}"
        );
    }

    #[test]
    fn xfstests_policy_accepts_command_plan_lanes_and_outcome_classes() {
        for (lane, expected_outcome, destructive) in [
            ("dry_run_only", "dry_run_only", false),
            ("fixture_only", "fixture_only", false),
            ("permissioned_real", "permissioned_real", true),
            ("host_skip", "host_skip", false),
            ("unsupported_by_scope", "unsupported_by_scope", false),
            ("dry_run_only", "product_failure", false),
            ("dry_run_only", "harness_failure", false),
            ("dry_run_only", "cleanup_failure", false),
        ] {
            let selected = vec!["generic/001".to_owned()];
            let mut entry = valid_policy_entry("generic/001");
            let plan = entry.command_plan.as_mut().expect("command plan");
            plan.execution_lane = lane.to_owned();
            plan.expected_plan_outcome = expected_outcome.to_owned();
            plan.destructive = destructive;

            let errors = validate_xfstests_policy(&selected, &[entry]);

            assert!(
                errors.is_empty(),
                "expected command plan lane={lane} outcome={expected_outcome} to validate, got {errors:#?}"
            );
        }
    }

    #[test]
    fn xfstests_policy_coverage_requires_representative_operation_classes() {
        let mut allowlist = Vec::new();
        for operation_class in REQUIRED_XFSTESTS_OPERATION_CLASSES {
            let mut entry = valid_policy_entry("generic/001");
            entry.test_id = format!("generic/{:03}", allowlist.len() + 1);
            entry.policy_row_id = Some(format!(
                "xfstests-policy-{}",
                entry.test_id.replace('/', "-")
            ));
            entry.expected_operation_class = Some((*operation_class).to_owned());
            allowlist.push(entry);
        }
        allowlist
            .last_mut()
            .expect("allowlist entry")
            .expected_operation_class = Some("read_only_mount".to_owned());

        let errors = validate_xfstests_policy_coverage(&allowlist);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("host_capability_skip")),
            "expected missing representative operation class error, got {errors:#?}"
        );
    }

    #[test]
    fn xfstests_policy_coverage_requires_representative_filesystem_flavors() {
        let allowlist = vec![
            valid_policy_entry("generic/001"),
            valid_policy_entry("ext4/001"),
        ];

        let errors = validate_xfstests_policy_coverage(&allowlist);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("filesystem flavor: btrfs")),
            "expected missing btrfs flavor error, got {errors:#?}"
        );
    }

    #[test]
    fn xfstests_policy_rejects_duplicate_ids() {
        let selected = vec!["generic/001".to_owned()];
        let allowlist = vec![
            valid_policy_entry("generic/001"),
            valid_policy_entry("generic/001"),
        ];

        let errors = validate_xfstests_policy(&selected, &allowlist);

        assert!(errors.iter().any(|error| error.contains("duplicate")));
    }

    #[test]
    fn xfstests_policy_rejects_missing_skip_reasons() {
        let selected = vec!["generic/030".to_owned()];
        let mut entry = valid_policy_entry("generic/030");
        entry.status = "known_fail".to_owned();
        entry.classification = Some("expected_failure".to_owned());
        entry.failure_reason.clear();

        let errors = validate_xfstests_policy(&selected, &[entry]);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("missing skip reason")),
            "expected missing skip reason error, got {errors:#?}"
        );
    }

    #[test]
    fn xfstests_policy_rejects_unknown_classifications() {
        let selected = vec!["generic/001".to_owned()];
        let mut entry = valid_policy_entry("generic/001");
        entry.classification = Some("surprising".to_owned());

        let errors = validate_xfstests_policy(&selected, &[entry]);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("unknown classification")),
            "expected unknown classification error, got {errors:#?}"
        );
    }

    #[test]
    fn xfstests_policy_rejects_unsupported_tests_without_scope_rationale() {
        let selected = vec!["generic/068".to_owned()];
        let mut entry = valid_policy_entry("generic/068");
        entry.status = "wont_fix".to_owned();
        entry.classification = Some("unsupported_by_v1".to_owned());
        entry.scope_reference = None;

        let errors = validate_xfstests_policy(&selected, &[entry]);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("without scope_reference")),
            "expected missing scope reference error, got {errors:#?}"
        );
    }

    #[test]
    fn baseline_comparison_detects_regressions_and_improvements() {
        let selected = vec!["generic/001".to_owned(), "generic/013".to_owned()];
        let mut run = XfstestsRun {
            source: "check-log".to_owned(),
            check_rc: 1,
            dry_run: false,
            total: 2,
            passed: 1,
            failed: 1,
            skipped: 0,
            not_run: 0,
            planned: 0,
            pass_rate: 0.5,
            tests: vec![
                XfstestsCase {
                    id: "generic/001".to_owned(),
                    status: XfstestsStatus::Failed,
                    duration_secs: None,
                    output_snippet: None,
                    allowlist_status: None,
                    failure_reason: None,
                    policy_row_id: None,
                    classification: None,
                    expected_outcome: None,
                    user_risk_category: None,
                    expected_operation_class: None,
                    required_capabilities: Vec::new(),
                    tracker_id: None,
                    comparison: Vec::new(),
                },
                XfstestsCase {
                    id: "generic/013".to_owned(),
                    status: XfstestsStatus::Passed,
                    duration_secs: None,
                    output_snippet: None,
                    allowlist_status: None,
                    failure_reason: None,
                    policy_row_id: None,
                    classification: None,
                    expected_outcome: None,
                    user_risk_category: None,
                    expected_operation_class: None,
                    required_capabilities: Vec::new(),
                    tracker_id: None,
                    comparison: Vec::new(),
                },
            ],
            policy_summary: XfstestsPolicySummary::default(),
        };
        let baseline = vec![
            XfstestsBaselineEntry {
                test_id: "generic/001".to_owned(),
                expected_status: XfstestsStatus::Passed,
            },
            XfstestsBaselineEntry {
                test_id: "generic/013".to_owned(),
                expected_status: XfstestsStatus::Failed,
            },
        ];

        let comparison = compare_against_baseline(&mut run, &baseline);

        assert_eq!(
            comparison.regressions,
            vec!["generic/001 (passed -> failed)"]
        );
        assert_eq!(
            comparison.improvements,
            vec!["generic/013 (failed -> passed)"]
        );
        assert!(run.tests[0].comparison[0].contains("regression"));
        assert!(run.tests[1].comparison[0].contains("improvement"));
        let _ = selected;
    }
}
