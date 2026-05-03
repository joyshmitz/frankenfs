#![allow(clippy::module_name_repetitions)]

//! Mounted differential oracle artifact validation for `bd-rchk0.5.2.1`.
//!
//! The validator keeps kernel-reference comparisons honest: observations are
//! normalized before comparison, host setup skips stay separate from product
//! failures, and every accepted difference needs a narrow, expiring allowlist.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub const MOUNTED_DIFFERENTIAL_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_MOUNTED_DIFFERENTIAL_REPORT: &str =
    "artifacts/e2e/mounted_differential_oracle/report.json";
const BEAD_ID: &str = "bd-rchk0.5.2.1";
const RUNNER_PATH: &str = "scripts/e2e/ffs_mounted_differential_oracle_e2e.sh";
const REVIEW_DATE: &str = "2026-05-03";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedDifferentialOracleReport {
    pub schema_version: u32,
    pub bead_id: String,
    pub generated_at: String,
    pub kernel_release: String,
    pub runner: String,
    pub execute_permissioned: bool,
    pub capability: MountedDifferentialCapability,
    pub allowlist: Vec<MountedDifferentialAllowlistRecord>,
    pub scenarios: Vec<MountedDifferentialScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedDifferentialCapability {
    pub fuse: CapabilityState,
    pub kernel_mount: CapabilityState,
    pub mkfs_ext4: CapabilityState,
    pub mkfs_btrfs: CapabilityState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Available,
    Missing,
    PermissionDenied,
    DisabledByUser,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedDifferentialAllowlistRecord {
    pub allowlist_id: String,
    pub scenario_id: String,
    pub operation_id: String,
    pub field: String,
    pub kernel_value: String,
    pub frankenfs_value: String,
    pub reason: String,
    pub owner_bead: String,
    pub expires_on: String,
    pub removal_plan: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedDifferentialScenario {
    pub scenario_id: String,
    pub operation_id: String,
    pub filesystem: MountedDifferentialFilesystem,
    pub scenario_kind: MountedDifferentialScenarioKind,
    pub classification: MountedDifferentialClassification,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_skip_class: Option<MountedDifferentialHostSkipClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowlist_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_bead: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub non_goal_reason: Option<String>,
    pub kernel_observation: MountedDifferentialObservation,
    pub frankenfs_observation: MountedDifferentialObservation,
    pub normalized_diff: Vec<MountedDifferentialDiff>,
    pub cleanup_status: CleanupStatus,
    pub reproduction_command: String,
    pub artifact_paths: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountedDifferentialFilesystem {
    Ext4,
    Btrfs,
}

impl MountedDifferentialFilesystem {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ext4 => "ext4",
            Self::Btrfs => "btrfs",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountedDifferentialScenarioKind {
    Positive,
    Unsupported,
    HostSkip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountedDifferentialClassification {
    Pass,
    AllowedDiff,
    Diff,
    HostSkip,
    Unsupported,
    Error,
}

impl MountedDifferentialClassification {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::AllowedDiff => "allowed_diff",
            Self::Diff => "diff",
            Self::HostSkip => "host_skip",
            Self::Unsupported => "unsupported",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountedDifferentialHostSkipClass {
    FuseMissing,
    FusePermissionDenied,
    KernelMountPermissionDenied,
    MkfsMissing,
    BtrfsDefaultPermissionsRootOwned,
    UnsupportedScope,
}

impl MountedDifferentialHostSkipClass {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::FuseMissing => "fuse_missing",
            Self::FusePermissionDenied => "fuse_permission_denied",
            Self::KernelMountPermissionDenied => "kernel_mount_permission_denied",
            Self::MkfsMissing => "mkfs_missing",
            Self::BtrfsDefaultPermissionsRootOwned => "btrfs_default_permissions_root_owned",
            Self::UnsupportedScope => "unsupported_scope",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedDifferentialObservation {
    pub side: MountedDifferentialSide,
    pub result: MountedDifferentialObservationResult,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errno: Option<String>,
    pub stdout_path: String,
    pub stderr_path: String,
    pub image_hash_before: String,
    pub image_hash_after: String,
    pub mount_options: Vec<String>,
    pub uid: u32,
}

impl MountedDifferentialObservation {
    fn normalized_value(&self) -> String {
        match self.result {
            MountedDifferentialObservationResult::Ok => "ok".to_owned(),
            MountedDifferentialObservationResult::Errno => self
                .errno
                .clone()
                .unwrap_or_else(|| "errno_missing".to_owned()),
            MountedDifferentialObservationResult::Skip => self
                .errno
                .clone()
                .unwrap_or_else(|| "skip_without_class".to_owned()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountedDifferentialSide {
    Kernel,
    Frankenfs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountedDifferentialObservationResult {
    Ok,
    Errno,
    Skip,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedDifferentialDiff {
    pub field: String,
    pub kernel_value: String,
    pub frankenfs_value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupStatus {
    Clean,
    PreservedArtifacts,
    Failed,
    NotRun,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedDifferentialValidationReport {
    pub schema_version: u32,
    pub bead_id: String,
    pub valid: bool,
    pub scenario_count: usize,
    pub filesystems: Vec<String>,
    pub classification_counts: BTreeMap<String, usize>,
    pub allowlist_count: usize,
    pub unresolved_public_claims: Vec<String>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn load_mounted_differential_oracle_report(
    path: &Path,
) -> Result<MountedDifferentialOracleReport> {
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("invalid mounted differential report {}", path.display()))
}

#[must_use]
pub fn validate_mounted_differential_oracle_report(
    report: &MountedDifferentialOracleReport,
) -> MountedDifferentialValidationReport {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut unresolved_public_claims = Vec::new();
    let mut filesystems = BTreeSet::new();
    let mut classification_counts = BTreeMap::new();
    let allowlists = validate_allowlist_records(&report.allowlist, &mut errors);
    let mut scenario_ids = BTreeSet::new();

    validate_top_level(report, &mut errors);

    for scenario in &report.scenarios {
        validate_scenario(
            scenario,
            &allowlists,
            &mut scenario_ids,
            &mut filesystems,
            &mut classification_counts,
            &mut unresolved_public_claims,
            &mut errors,
            &mut warnings,
        );
    }

    validate_coverage(
        &filesystems,
        &classification_counts,
        report.allowlist.len(),
        &mut errors,
    );

    MountedDifferentialValidationReport {
        schema_version: report.schema_version,
        bead_id: report.bead_id.clone(),
        valid: errors.is_empty(),
        scenario_count: report.scenarios.len(),
        filesystems: filesystems.into_iter().collect(),
        classification_counts,
        allowlist_count: report.allowlist.len(),
        unresolved_public_claims,
        errors,
        warnings,
    }
}

pub fn fail_on_mounted_differential_oracle_errors(
    report: &MountedDifferentialValidationReport,
) -> Result<()> {
    if report.valid {
        Ok(())
    } else {
        bail!(
            "mounted differential oracle report failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        )
    }
}

#[must_use]
pub fn render_mounted_differential_oracle_markdown(
    report: &MountedDifferentialValidationReport,
) -> String {
    let mut output = String::new();
    output.push_str("# Mounted Differential Oracle Report\n\n");
    let _ = writeln!(output, "- Bead: `{}`", report.bead_id);
    let _ = writeln!(output, "- Valid: `{}`", report.valid);
    let _ = writeln!(output, "- Scenarios: `{}`", report.scenario_count);
    let _ = writeln!(output, "- Allowlists: `{}`", report.allowlist_count);
    output.push_str("\n## Classifications\n\n");
    for (classification, count) in &report.classification_counts {
        let _ = writeln!(output, "- `{classification}`: {count}");
    }
    if !report.unresolved_public_claims.is_empty() {
        output.push_str("\n## Release Gate Blocks\n\n");
        for claim in &report.unresolved_public_claims {
            let _ = writeln!(output, "- {claim}");
        }
    }
    if !report.errors.is_empty() {
        output.push_str("\n## Errors\n\n");
        for error in &report.errors {
            let _ = writeln!(output, "- {error}");
        }
    }
    if !report.warnings.is_empty() {
        output.push_str("\n## Warnings\n\n");
        for warning in &report.warnings {
            let _ = writeln!(output, "- {warning}");
        }
    }
    output
}

fn validate_top_level(report: &MountedDifferentialOracleReport, errors: &mut Vec<String>) {
    if report.schema_version != MOUNTED_DIFFERENTIAL_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version must be {MOUNTED_DIFFERENTIAL_SCHEMA_VERSION}, got {}",
            report.schema_version
        ));
    }
    if report.bead_id != BEAD_ID {
        errors.push(format!("bead_id must be {BEAD_ID}, got {}", report.bead_id));
    }
    if report.runner != RUNNER_PATH {
        errors.push(format!(
            "runner must be {RUNNER_PATH}, got {}",
            report.runner
        ));
    }
    if report.generated_at.trim().is_empty() {
        errors.push("generated_at must be populated".to_owned());
    }
    if report.kernel_release.trim().is_empty() {
        errors.push("kernel_release must be populated".to_owned());
    }
    if report.scenarios.is_empty() {
        errors.push("report must include at least one scenario".to_owned());
    }
}

fn validate_allowlist_records<'a>(
    records: &'a [MountedDifferentialAllowlistRecord],
    errors: &mut Vec<String>,
) -> BTreeMap<String, &'a MountedDifferentialAllowlistRecord> {
    let mut by_id = BTreeMap::new();
    for record in records {
        if by_id.contains_key(&record.allowlist_id) {
            errors.push(format!("duplicate allowlist_id {}", record.allowlist_id));
        } else {
            by_id.insert(record.allowlist_id.clone(), record);
        }
        if !record.allowlist_id.starts_with("allow_") {
            errors.push(format!(
                "allowlist {} must use allow_ prefix",
                record.allowlist_id
            ));
        }
        reject_broad_allowlist_value(
            &record.allowlist_id,
            "scenario_id",
            &record.scenario_id,
            errors,
        );
        reject_broad_allowlist_value(
            &record.allowlist_id,
            "operation_id",
            &record.operation_id,
            errors,
        );
        reject_broad_allowlist_value(&record.allowlist_id, "field", &record.field, errors);
        reject_broad_allowlist_value(
            &record.allowlist_id,
            "kernel_value",
            &record.kernel_value,
            errors,
        );
        reject_broad_allowlist_value(
            &record.allowlist_id,
            "frankenfs_value",
            &record.frankenfs_value,
            errors,
        );
        if record.reason.trim().is_empty() {
            errors.push(format!("allowlist {} missing reason", record.allowlist_id));
        }
        if !record.owner_bead.starts_with("bd-") {
            errors.push(format!(
                "allowlist {} owner_bead must start with bd-",
                record.allowlist_id
            ));
        }
        if !expiry_is_future(&record.expires_on) {
            errors.push(format!(
                "allowlist {} expires_on {} is not after {REVIEW_DATE}",
                record.allowlist_id, record.expires_on
            ));
        }
        if record.removal_plan.trim().is_empty() {
            errors.push(format!(
                "allowlist {} missing removal_plan",
                record.allowlist_id
            ));
        }
    }
    by_id
}

#[allow(clippy::too_many_arguments)]
fn validate_scenario(
    scenario: &MountedDifferentialScenario,
    allowlists: &BTreeMap<String, &MountedDifferentialAllowlistRecord>,
    scenario_ids: &mut BTreeSet<String>,
    filesystems: &mut BTreeSet<String>,
    classification_counts: &mut BTreeMap<String, usize>,
    unresolved_public_claims: &mut Vec<String>,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    if !scenario_ids.insert(scenario.scenario_id.clone()) {
        errors.push(format!("duplicate scenario_id {}", scenario.scenario_id));
    }
    if !scenario.scenario_id.starts_with("mounted_diff_") {
        errors.push(format!(
            "scenario {} must start with mounted_diff_",
            scenario.scenario_id
        ));
    }
    if scenario.operation_id.trim().is_empty() {
        errors.push(format!(
            "scenario {} missing operation_id",
            scenario.scenario_id
        ));
    }
    filesystems.insert(scenario.filesystem.label().to_owned());
    *classification_counts
        .entry(scenario.classification.label().to_owned())
        .or_default() += 1;

    validate_observation(
        scenario,
        &scenario.kernel_observation,
        MountedDifferentialSide::Kernel,
        errors,
    );
    validate_observation(
        scenario,
        &scenario.frankenfs_observation,
        MountedDifferentialSide::Frankenfs,
        errors,
    );
    validate_reproduction(scenario, errors);
    validate_artifacts(scenario, errors);
    validate_declared_diff(scenario, errors);

    match scenario.classification {
        MountedDifferentialClassification::Pass => validate_pass_scenario(scenario, errors),
        MountedDifferentialClassification::AllowedDiff => {
            validate_allowed_diff_scenario(scenario, allowlists, errors);
        }
        MountedDifferentialClassification::Diff => {
            unresolved_public_claims.push(format!(
                "{}:{} has unresolved kernel/FrankenFS disagreement",
                scenario.scenario_id, scenario.operation_id
            ));
            errors.push(format!(
                "scenario {} has unresolved diff without narrow allowlist",
                scenario.scenario_id
            ));
        }
        MountedDifferentialClassification::HostSkip => {
            validate_host_skip_scenario(scenario, errors);
        }
        MountedDifferentialClassification::Unsupported => {
            validate_unsupported_scenario(scenario, errors);
        }
        MountedDifferentialClassification::Error => {
            unresolved_public_claims.push(format!(
                "{}:{} ended in harness/error state",
                scenario.scenario_id, scenario.operation_id
            ));
            errors.push(format!(
                "scenario {} has error classification and cannot support a public claim",
                scenario.scenario_id
            ));
        }
    }

    if scenario.cleanup_status == CleanupStatus::Failed {
        warnings.push(format!(
            "scenario {} preserved a cleanup failure artifact",
            scenario.scenario_id
        ));
    }
}

fn validate_observation(
    scenario: &MountedDifferentialScenario,
    observation: &MountedDifferentialObservation,
    expected_side: MountedDifferentialSide,
    errors: &mut Vec<String>,
) {
    if observation.side != expected_side {
        errors.push(format!(
            "scenario {} observation side mismatch: expected {:?}, got {:?}",
            scenario.scenario_id, expected_side, observation.side
        ));
    }
    if observation.stdout_path.trim().is_empty() {
        errors.push(format!(
            "scenario {} {:?} observation missing stdout_path",
            scenario.scenario_id, expected_side
        ));
    }
    if observation.stderr_path.trim().is_empty() {
        errors.push(format!(
            "scenario {} {:?} observation missing stderr_path",
            scenario.scenario_id, expected_side
        ));
    }
    if !is_sha256_hex(&observation.image_hash_before) {
        errors.push(format!(
            "scenario {} {:?} image_hash_before must be SHA-256 hex",
            scenario.scenario_id, expected_side
        ));
    }
    if !is_sha256_hex(&observation.image_hash_after) {
        errors.push(format!(
            "scenario {} {:?} image_hash_after must be SHA-256 hex",
            scenario.scenario_id, expected_side
        ));
    }
    if observation.result == MountedDifferentialObservationResult::Errno
        && observation
            .errno
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
    {
        errors.push(format!(
            "scenario {} {:?} errno result missing errno",
            scenario.scenario_id, expected_side
        ));
    }
    if observation.result != MountedDifferentialObservationResult::Skip
        && observation.mount_options.is_empty()
    {
        errors.push(format!(
            "scenario {} {:?} observation missing mount_options",
            scenario.scenario_id, expected_side
        ));
    }
}

fn validate_reproduction(scenario: &MountedDifferentialScenario, errors: &mut Vec<String>) {
    if scenario.reproduction_command.trim().is_empty() {
        errors.push(format!(
            "scenario {} missing reproduction_command",
            scenario.scenario_id
        ));
    }
    if !scenario.reproduction_command.contains(RUNNER_PATH)
        && !scenario
            .reproduction_command
            .contains("validate-mounted-differential-oracle")
    {
        errors.push(format!(
            "scenario {} reproduction_command must name mounted differential runner or validator",
            scenario.scenario_id
        ));
    }
}

fn validate_artifacts(scenario: &MountedDifferentialScenario, errors: &mut Vec<String>) {
    if scenario.artifact_paths.is_empty() {
        errors.push(format!(
            "scenario {} missing artifact_paths",
            scenario.scenario_id
        ));
    }
    for path in &scenario.artifact_paths {
        if path.trim().is_empty() || path.contains("..") {
            errors.push(format!(
                "scenario {} has invalid artifact path {}",
                scenario.scenario_id, path
            ));
        }
    }
}

fn validate_declared_diff(scenario: &MountedDifferentialScenario, errors: &mut Vec<String>) {
    let observed_kernel = scenario.kernel_observation.normalized_value();
    let observed_frankenfs = scenario.frankenfs_observation.normalized_value();
    let declared = diff_map(&scenario.normalized_diff);
    if observed_kernel == observed_frankenfs && !scenario.normalized_diff.is_empty() {
        errors.push(format!(
            "scenario {} declares diff even though normalized observations match",
            scenario.scenario_id
        ));
    }
    if observed_kernel != observed_frankenfs {
        match declared.get("result") {
            Some(diff)
                if diff.kernel_value == observed_kernel
                    && diff.frankenfs_value == observed_frankenfs => {}
            _ => errors.push(format!(
                "scenario {} must declare result diff {} vs {}",
                scenario.scenario_id, observed_kernel, observed_frankenfs
            )),
        }
    }
}

fn validate_pass_scenario(scenario: &MountedDifferentialScenario, errors: &mut Vec<String>) {
    if scenario.scenario_kind != MountedDifferentialScenarioKind::Positive {
        errors.push(format!(
            "scenario {} pass classification must be positive kind",
            scenario.scenario_id
        ));
    }
    if scenario.kernel_observation.normalized_value()
        != scenario.frankenfs_observation.normalized_value()
        || !scenario.normalized_diff.is_empty()
    {
        errors.push(format!(
            "scenario {} pass classification has normalized differences",
            scenario.scenario_id
        ));
    }
}

fn validate_allowed_diff_scenario(
    scenario: &MountedDifferentialScenario,
    allowlists: &BTreeMap<String, &MountedDifferentialAllowlistRecord>,
    errors: &mut Vec<String>,
) {
    let Some(allowlist_id) = scenario.allowlist_id.as_deref() else {
        errors.push(format!(
            "scenario {} allowed_diff missing allowlist_id",
            scenario.scenario_id
        ));
        return;
    };
    let Some(record) = allowlists.get(allowlist_id) else {
        errors.push(format!(
            "scenario {} references missing allowlist {}",
            scenario.scenario_id, allowlist_id
        ));
        return;
    };
    if scenario.normalized_diff.is_empty() {
        errors.push(format!(
            "scenario {} allowed_diff must include normalized_diff rows",
            scenario.scenario_id
        ));
    }
    let matches = scenario.normalized_diff.iter().any(|diff| {
        record.scenario_id == scenario.scenario_id
            && record.operation_id == scenario.operation_id
            && record.field == diff.field
            && record.kernel_value == diff.kernel_value
            && record.frankenfs_value == diff.frankenfs_value
    });
    if !matches {
        errors.push(format!(
            "scenario {} allowlist {} does not exactly match any normalized_diff row",
            scenario.scenario_id, allowlist_id
        ));
    }
}

fn validate_host_skip_scenario(scenario: &MountedDifferentialScenario, errors: &mut Vec<String>) {
    if scenario.scenario_kind != MountedDifferentialScenarioKind::HostSkip {
        errors.push(format!(
            "scenario {} host_skip classification must be host_skip kind",
            scenario.scenario_id
        ));
    }
    let Some(skip_class) = scenario.host_skip_class else {
        errors.push(format!(
            "scenario {} host_skip missing host_skip_class",
            scenario.scenario_id
        ));
        return;
    };
    if skip_class == MountedDifferentialHostSkipClass::BtrfsDefaultPermissionsRootOwned
        && scenario.filesystem != MountedDifferentialFilesystem::Btrfs
    {
        errors.push(format!(
            "scenario {} btrfs DefaultPermissions diagnosis used on non-btrfs scenario",
            scenario.scenario_id
        ));
    }
    if ![
        scenario.kernel_observation.result,
        scenario.frankenfs_observation.result,
    ]
    .contains(&MountedDifferentialObservationResult::Skip)
    {
        errors.push(format!(
            "scenario {} host_skip must include at least one skip observation",
            scenario.scenario_id
        ));
    }
    let skip_label = skip_class.label();
    if scenario.kernel_observation.normalized_value() != skip_label
        && scenario.frankenfs_observation.normalized_value() != skip_label
    {
        errors.push(format!(
            "scenario {} host_skip observation must carry {skip_label}",
            scenario.scenario_id
        ));
    }
}

fn validate_unsupported_scenario(scenario: &MountedDifferentialScenario, errors: &mut Vec<String>) {
    if scenario.scenario_kind != MountedDifferentialScenarioKind::Unsupported {
        errors.push(format!(
            "scenario {} unsupported classification must be unsupported kind",
            scenario.scenario_id
        ));
    }
    let has_owner = scenario
        .owner_bead
        .as_deref()
        .is_some_and(|owner| owner.starts_with("bd-"));
    let has_non_goal = scenario
        .non_goal_reason
        .as_deref()
        .is_some_and(|reason| !reason.trim().is_empty());
    if !has_owner && !has_non_goal {
        errors.push(format!(
            "scenario {} unsupported classification needs owner_bead or non_goal_reason",
            scenario.scenario_id
        ));
    }
}

fn validate_coverage(
    filesystems: &BTreeSet<String>,
    classification_counts: &BTreeMap<String, usize>,
    allowlist_count: usize,
    errors: &mut Vec<String>,
) {
    for required in ["ext4", "btrfs"] {
        if !filesystems.contains(required) {
            errors.push(format!(
                "mounted differential report missing filesystem {required}"
            ));
        }
    }
    for required in ["pass", "allowed_diff", "host_skip", "unsupported"] {
        if !classification_counts.contains_key(required) {
            errors.push(format!(
                "mounted differential report missing {required} classification"
            ));
        }
    }
    if allowlist_count == 0 {
        errors.push(
            "mounted differential report must include at least one narrow allowlist".to_owned(),
        );
    }
}

fn reject_broad_allowlist_value(
    allowlist_id: &str,
    field: &str,
    value: &str,
    errors: &mut Vec<String>,
) {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "*" || trimmed.contains('*') {
        errors.push(format!(
            "allowlist {allowlist_id} has broad or empty {field}: {value}"
        ));
    }
}

fn expiry_is_future(value: &str) -> bool {
    value.len() == 10 && value > REVIEW_DATE
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn diff_map(diffs: &[MountedDifferentialDiff]) -> BTreeMap<&str, &MountedDifferentialDiff> {
    diffs
        .iter()
        .map(|diff| (diff.field.as_str(), diff))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn observation(
        side: MountedDifferentialSide,
        result: MountedDifferentialObservationResult,
        errno: Option<&str>,
    ) -> MountedDifferentialObservation {
        MountedDifferentialObservation {
            side,
            result,
            errno: errno.map(str::to_owned),
            stdout_path: format!("logs/{side:?}.out"),
            stderr_path: format!("logs/{side:?}.err"),
            image_hash_before: HASH_A.to_owned(),
            image_hash_after: HASH_B.to_owned(),
            mount_options: if result == MountedDifferentialObservationResult::Skip {
                Vec::new()
            } else {
                vec!["rw".to_owned(), "default_permissions".to_owned()]
            },
            uid: 1000,
        }
    }

    fn base_scenario(
        scenario_id: &str,
        filesystem: MountedDifferentialFilesystem,
        classification: MountedDifferentialClassification,
        kernel: MountedDifferentialObservation,
        frankenfs: MountedDifferentialObservation,
    ) -> MountedDifferentialScenario {
        MountedDifferentialScenario {
            scenario_id: scenario_id.to_owned(),
            operation_id: "open_readback".to_owned(),
            filesystem,
            scenario_kind: MountedDifferentialScenarioKind::Positive,
            classification,
            host_skip_class: None,
            allowlist_id: None,
            owner_bead: None,
            non_goal_reason: None,
            kernel_observation: kernel,
            frankenfs_observation: frankenfs,
            normalized_diff: Vec::new(),
            cleanup_status: CleanupStatus::Clean,
            reproduction_command: format!("{RUNNER_PATH} --scenario {scenario_id}"),
            artifact_paths: vec![format!("artifacts/{scenario_id}.json")],
        }
    }

    #[allow(clippy::too_many_lines)]
    fn valid_report() -> MountedDifferentialOracleReport {
        let allowlist = MountedDifferentialAllowlistRecord {
            allowlist_id: "allow_ext4_fiemap_transport_errno".to_owned(),
            scenario_id: "mounted_diff_ext4_fiemap_transport_errno".to_owned(),
            operation_id: "fiemap_probe".to_owned(),
            field: "result".to_owned(),
            kernel_value: "EOPNOTSUPP".to_owned(),
            frankenfs_value: "ENOTTY".to_owned(),
            reason: "current FUSE transport may reject before userspace ioctl dispatch".to_owned(),
            owner_bead: "bd-29cpd".to_owned(),
            expires_on: "2026-12-31".to_owned(),
            removal_plan: "remove once kernel baseline provenance lane proves ioctl forwarding"
                .to_owned(),
        };

        let pass = base_scenario(
            "mounted_diff_ext4_create_readback",
            MountedDifferentialFilesystem::Ext4,
            MountedDifferentialClassification::Pass,
            observation(
                MountedDifferentialSide::Kernel,
                MountedDifferentialObservationResult::Ok,
                None,
            ),
            observation(
                MountedDifferentialSide::Frankenfs,
                MountedDifferentialObservationResult::Ok,
                None,
            ),
        );

        let mut allowed = base_scenario(
            "mounted_diff_ext4_fiemap_transport_errno",
            MountedDifferentialFilesystem::Ext4,
            MountedDifferentialClassification::AllowedDiff,
            observation(
                MountedDifferentialSide::Kernel,
                MountedDifferentialObservationResult::Errno,
                Some("EOPNOTSUPP"),
            ),
            observation(
                MountedDifferentialSide::Frankenfs,
                MountedDifferentialObservationResult::Errno,
                Some("ENOTTY"),
            ),
        );
        allowed.operation_id = "fiemap_probe".to_owned();
        allowed.allowlist_id = Some(allowlist.allowlist_id.clone());
        allowed.normalized_diff = vec![MountedDifferentialDiff {
            field: "result".to_owned(),
            kernel_value: "EOPNOTSUPP".to_owned(),
            frankenfs_value: "ENOTTY".to_owned(),
        }];

        let mut host_skip = base_scenario(
            "mounted_diff_btrfs_default_permissions_root_owned",
            MountedDifferentialFilesystem::Btrfs,
            MountedDifferentialClassification::HostSkip,
            observation(
                MountedDifferentialSide::Kernel,
                MountedDifferentialObservationResult::Skip,
                Some("btrfs_default_permissions_root_owned"),
            ),
            observation(
                MountedDifferentialSide::Frankenfs,
                MountedDifferentialObservationResult::Skip,
                Some("btrfs_default_permissions_root_owned"),
            ),
        );
        host_skip.scenario_kind = MountedDifferentialScenarioKind::HostSkip;
        host_skip.host_skip_class =
            Some(MountedDifferentialHostSkipClass::BtrfsDefaultPermissionsRootOwned);

        let mut unsupported = base_scenario(
            "mounted_diff_btrfs_unsupported_clone_range",
            MountedDifferentialFilesystem::Btrfs,
            MountedDifferentialClassification::Unsupported,
            observation(
                MountedDifferentialSide::Kernel,
                MountedDifferentialObservationResult::Errno,
                Some("EOPNOTSUPP"),
            ),
            observation(
                MountedDifferentialSide::Frankenfs,
                MountedDifferentialObservationResult::Errno,
                Some("EOPNOTSUPP"),
            ),
        );
        unsupported.operation_id = "clone_range".to_owned();
        unsupported.scenario_kind = MountedDifferentialScenarioKind::Unsupported;
        unsupported.owner_bead = Some("bd-rchk0.5.2".to_owned());

        MountedDifferentialOracleReport {
            schema_version: MOUNTED_DIFFERENTIAL_SCHEMA_VERSION,
            bead_id: BEAD_ID.to_owned(),
            generated_at: "2026-05-03T14:40:00Z".to_owned(),
            kernel_release: "6.19.0-test".to_owned(),
            runner: RUNNER_PATH.to_owned(),
            execute_permissioned: false,
            capability: MountedDifferentialCapability {
                fuse: CapabilityState::PermissionDenied,
                kernel_mount: CapabilityState::PermissionDenied,
                mkfs_ext4: CapabilityState::Available,
                mkfs_btrfs: CapabilityState::Available,
            },
            allowlist: vec![allowlist],
            scenarios: vec![pass, allowed, host_skip, unsupported],
        }
    }

    #[test]
    fn valid_report_covers_strict_allowlist_and_host_skip_contract() {
        let validation = validate_mounted_differential_oracle_report(&valid_report());
        assert!(validation.valid, "{:?}", validation.errors);
        assert_eq!(validation.scenario_count, 4);
        assert_eq!(validation.filesystems, vec!["btrfs", "ext4"]);
        assert_eq!(validation.classification_counts["allowed_diff"], 1);
        assert_eq!(validation.classification_counts["host_skip"], 1);
    }

    #[test]
    fn broad_and_expired_allowlists_are_rejected() {
        let mut report = valid_report();
        report.allowlist[0].scenario_id = "*".to_owned();
        report.allowlist[0].expires_on = "2026-01-01".to_owned();
        let validation = validate_mounted_differential_oracle_report(&report);
        assert!(!validation.valid);
        assert!(
            validation
                .errors
                .iter()
                .any(|error| error.contains("broad or empty scenario_id"))
        );
        assert!(
            validation
                .errors
                .iter()
                .any(|error| error.contains("expires_on"))
        );
    }

    #[test]
    fn unresolved_diffs_fail_closed_for_public_claims() {
        let mut report = valid_report();
        report.scenarios[1].classification = MountedDifferentialClassification::Diff;
        report.scenarios[1].allowlist_id = None;
        let validation = validate_mounted_differential_oracle_report(&report);
        assert!(!validation.valid);
        assert!(
            validation
                .unresolved_public_claims
                .iter()
                .any(|claim| claim.contains("unresolved kernel/FrankenFS disagreement"))
        );
    }

    #[test]
    fn btrfs_default_permissions_skip_cannot_mask_product_failure() {
        let mut report = valid_report();
        report.scenarios[2].filesystem = MountedDifferentialFilesystem::Ext4;
        let validation = validate_mounted_differential_oracle_report(&report);
        assert!(!validation.valid);
        assert!(
            validation
                .errors
                .iter()
                .any(|error| error.contains("DefaultPermissions diagnosis used on non-btrfs"))
        );
    }

    #[test]
    fn unsupported_scope_requires_owner_or_non_goal() {
        let mut report = valid_report();
        report.scenarios[3].owner_bead = None;
        report.scenarios[3].non_goal_reason = None;
        let validation = validate_mounted_differential_oracle_report(&report);
        assert!(!validation.valid);
        assert!(
            validation
                .errors
                .iter()
                .any(|error| error.contains("needs owner_bead or non_goal_reason"))
        );
    }

    #[test]
    fn markdown_renders_diff_counts_and_gate_blocks() {
        let mut report = valid_report();
        report.scenarios[1].classification = MountedDifferentialClassification::Diff;
        report.scenarios[1].allowlist_id = None;
        let validation = validate_mounted_differential_oracle_report(&report);
        let markdown = render_mounted_differential_oracle_markdown(&validation);
        assert!(markdown.contains("Mounted Differential Oracle Report"));
        assert!(markdown.contains("`diff`: 1"));
        assert!(markdown.contains("Release Gate Blocks"));
    }
}
