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

pub const MOUNTED_DIFFERENTIAL_SCHEMA_VERSION: u32 = 2;
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
    pub fusermount: CapabilityState,
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
pub struct MountedDifferentialBaselineManifest {
    pub baseline_id: String,
    pub kernel_release: String,
    pub filesystem: MountedDifferentialFilesystem,
    pub mkfs_command: String,
    pub image_seed: String,
    pub image_hash: String,
    pub mount_options: Vec<String>,
    pub uid: u32,
    pub gid: u32,
    pub root_ownership: MountedDifferentialRootOwnership,
    pub capability_probe: MountedDifferentialCapabilityProbe,
    pub allowed_errno_normalization: Vec<MountedDifferentialErrnoNormalizationRule>,
    pub cleanup_requirements: MountedDifferentialCleanupRequirements,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedDifferentialRootOwnership {
    pub uid: u32,
    pub gid: u32,
    pub mode: String,
    pub default_permissions: bool,
    pub root_owned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedDifferentialCapabilityProbe {
    pub probe_id: String,
    pub dev_fuse: CapabilityState,
    pub fusermount: CapabilityState,
    pub kernel_mount: CapabilityState,
    pub mkfs_helper: CapabilityState,
    pub stdout_path: String,
    pub stderr_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedDifferentialErrnoNormalizationRule {
    pub rule_id: String,
    pub operation_id: String,
    pub kernel_errno: String,
    pub frankenfs_errno: String,
    pub normalized_errno: String,
    pub rationale: String,
    pub owner_bead: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedDifferentialCleanupRequirements {
    pub unmount: MountedDifferentialCleanupRequirement,
    pub mountpoints: MountedDifferentialCleanupRequirement,
    pub images_on_success: MountedDifferentialCleanupSuccessImagePolicy,
    pub images_on_failure: MountedDifferentialCleanupFailureImagePolicy,
    pub raw_logs: MountedDifferentialRawLogPolicy,
    pub cleanup_status_path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountedDifferentialCleanupRequirement {
    Required,
    NotRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountedDifferentialCleanupSuccessImagePolicy {
    Remove,
    Preserve,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountedDifferentialCleanupFailureImagePolicy {
    Preserve,
    Remove,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountedDifferentialRawLogPolicy {
    Preserve,
    Discard,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedDifferentialLaneIsolation {
    pub kernel_image_path: String,
    pub frankenfs_image_path: String,
    pub kernel_mountpoint: String,
    pub frankenfs_mountpoint: String,
    pub kernel_output_root: String,
    pub frankenfs_output_root: String,
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
    pub baseline_manifest: MountedDifferentialBaselineManifest,
    pub lane_isolation: MountedDifferentialLaneIsolation,
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
    MkfsExt4Missing,
    MkfsBtrfsMissing,
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
            Self::MkfsExt4Missing => "mkfs_ext4_missing",
            Self::MkfsBtrfsMissing => "mkfs_btrfs_missing",
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
    pub gid: u32,
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
    pub host_skip_classes: Vec<String>,
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
    let mut host_skip_classes = BTreeSet::new();
    let mut classification_counts = BTreeMap::new();
    let allowlists = validate_allowlist_records(&report.allowlist, &mut errors);
    let mut scenario_ids = BTreeSet::new();

    validate_top_level(report, &mut errors);

    for scenario in &report.scenarios {
        validate_scenario(
            scenario,
            report,
            &allowlists,
            &mut scenario_ids,
            &mut filesystems,
            &mut host_skip_classes,
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
        host_skip_classes: host_skip_classes.into_iter().collect(),
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
    if !report.host_skip_classes.is_empty() {
        output.push_str("\n## Host Skip Classes\n\n");
        for skip_class in &report.host_skip_classes {
            let _ = writeln!(output, "- `{skip_class}`");
        }
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
    report: &MountedDifferentialOracleReport,
    allowlists: &BTreeMap<String, &MountedDifferentialAllowlistRecord>,
    scenario_ids: &mut BTreeSet<String>,
    filesystems: &mut BTreeSet<String>,
    host_skip_classes: &mut BTreeSet<String>,
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
    if let Some(skip_class) = scenario.host_skip_class {
        host_skip_classes.insert(skip_class.label().to_owned());
    }

    validate_baseline_manifest(scenario, report, errors);
    validate_lane_isolation(scenario, errors);
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

fn validate_baseline_manifest(
    scenario: &MountedDifferentialScenario,
    report: &MountedDifferentialOracleReport,
    errors: &mut Vec<String>,
) {
    let baseline = &scenario.baseline_manifest;
    if !baseline.baseline_id.starts_with("baseline_") {
        errors.push(format!(
            "scenario {} baseline_id {} must start with baseline_",
            scenario.scenario_id, baseline.baseline_id
        ));
    }
    if baseline.kernel_release != report.kernel_release {
        errors.push(format!(
            "scenario {} baseline kernel_release {} must match report kernel_release {}",
            scenario.scenario_id, baseline.kernel_release, report.kernel_release
        ));
    }
    if baseline.filesystem != scenario.filesystem {
        errors.push(format!(
            "scenario {} baseline filesystem {:?} does not match scenario {:?}",
            scenario.scenario_id, baseline.filesystem, scenario.filesystem
        ));
    }
    let expected_mkfs = match scenario.filesystem {
        MountedDifferentialFilesystem::Ext4 => "mkfs.ext4",
        MountedDifferentialFilesystem::Btrfs => "mkfs.btrfs",
    };
    if !baseline.mkfs_command.contains(expected_mkfs) {
        errors.push(format!(
            "scenario {} mkfs_command must include {expected_mkfs}",
            scenario.scenario_id
        ));
    }
    if baseline.image_seed.trim().is_empty() {
        errors.push(format!(
            "scenario {} baseline missing image_seed",
            scenario.scenario_id
        ));
    }
    if !is_sha256_hex(&baseline.image_hash) {
        errors.push(format!(
            "scenario {} baseline image_hash must be SHA-256 hex",
            scenario.scenario_id
        ));
    }
    if baseline.image_hash != scenario.kernel_observation.image_hash_before
        || baseline.image_hash != scenario.frankenfs_observation.image_hash_before
    {
        errors.push(format!(
            "scenario {} baseline image_hash must match both lane pre-run image hashes",
            scenario.scenario_id
        ));
    }
    if baseline.mount_options.is_empty() {
        errors.push(format!(
            "scenario {} baseline must record intended mount_options",
            scenario.scenario_id
        ));
    }
    if baseline.uid != scenario.kernel_observation.uid
        || baseline.uid != scenario.frankenfs_observation.uid
    {
        errors.push(format!(
            "scenario {} baseline uid must match both observations",
            scenario.scenario_id
        ));
    }
    if baseline.gid != scenario.kernel_observation.gid
        || baseline.gid != scenario.frankenfs_observation.gid
    {
        errors.push(format!(
            "scenario {} baseline gid must match both observations",
            scenario.scenario_id
        ));
    }
    validate_root_ownership(scenario, &baseline.root_ownership, errors);
    validate_capability_probe(scenario, &baseline.capability_probe, report, errors);
    validate_errno_normalization_rules(scenario, &baseline.allowed_errno_normalization, errors);
    validate_cleanup_requirements(scenario, &baseline.cleanup_requirements, errors);
}

fn validate_root_ownership(
    scenario: &MountedDifferentialScenario,
    ownership: &MountedDifferentialRootOwnership,
    errors: &mut Vec<String>,
) {
    if ownership.mode.trim().is_empty() {
        errors.push(format!(
            "scenario {} root_ownership missing mode",
            scenario.scenario_id
        ));
    }
    if scenario.host_skip_class
        == Some(MountedDifferentialHostSkipClass::BtrfsDefaultPermissionsRootOwned)
        && (!ownership.root_owned || !ownership.default_permissions)
    {
        errors.push(format!(
            "scenario {} btrfs DefaultPermissions skip requires root_owned default_permissions root",
            scenario.scenario_id
        ));
    }
}

fn validate_capability_probe(
    scenario: &MountedDifferentialScenario,
    probe: &MountedDifferentialCapabilityProbe,
    report: &MountedDifferentialOracleReport,
    errors: &mut Vec<String>,
) {
    if !probe.probe_id.starts_with("capability_") {
        errors.push(format!(
            "scenario {} capability probe_id {} must start with capability_",
            scenario.scenario_id, probe.probe_id
        ));
    }
    if scenario.scenario_kind != MountedDifferentialScenarioKind::HostSkip {
        if probe.dev_fuse != report.capability.fuse {
            errors.push(format!(
                "scenario {} capability probe dev_fuse does not match report fuse state",
                scenario.scenario_id
            ));
        }
        if probe.fusermount != report.capability.fusermount {
            errors.push(format!(
                "scenario {} capability probe fusermount does not match report fusermount state",
                scenario.scenario_id
            ));
        }
        if probe.kernel_mount != report.capability.kernel_mount {
            errors.push(format!(
                "scenario {} capability probe kernel_mount does not match report kernel_mount state",
                scenario.scenario_id
            ));
        }
        let expected_mkfs_state = match scenario.filesystem {
            MountedDifferentialFilesystem::Ext4 => report.capability.mkfs_ext4,
            MountedDifferentialFilesystem::Btrfs => report.capability.mkfs_btrfs,
        };
        if probe.mkfs_helper != expected_mkfs_state {
            errors.push(format!(
                "scenario {} capability probe mkfs_helper does not match report helper state",
                scenario.scenario_id
            ));
        }
    } else if let Some(skip_class) = scenario.host_skip_class {
        match skip_class {
            MountedDifferentialHostSkipClass::FuseMissing
                if probe.dev_fuse != CapabilityState::Missing =>
            {
                errors.push(format!(
                    "scenario {} fuse_missing skip requires missing /dev/fuse probe",
                    scenario.scenario_id
                ));
            }
            MountedDifferentialHostSkipClass::FusePermissionDenied
                if probe.fusermount != CapabilityState::PermissionDenied =>
            {
                errors.push(format!(
                    "scenario {} fuse_permission_denied skip requires fusermount permission denial",
                    scenario.scenario_id
                ));
            }
            MountedDifferentialHostSkipClass::KernelMountPermissionDenied
                if probe.kernel_mount != CapabilityState::PermissionDenied =>
            {
                errors.push(format!(
                    "scenario {} kernel_mount_permission_denied skip requires kernel mount permission denial",
                    scenario.scenario_id
                ));
            }
            MountedDifferentialHostSkipClass::MkfsExt4Missing
            | MountedDifferentialHostSkipClass::MkfsBtrfsMissing
                if probe.mkfs_helper != CapabilityState::Missing =>
            {
                errors.push(format!(
                    "scenario {} mkfs missing skip requires missing mkfs helper probe",
                    scenario.scenario_id
                ));
            }
            _ => {}
        }
    }
    validate_artifact_path(
        &scenario.scenario_id,
        "capability stdout_path",
        &probe.stdout_path,
        errors,
    );
    validate_artifact_path(
        &scenario.scenario_id,
        "capability stderr_path",
        &probe.stderr_path,
        errors,
    );
}

fn validate_errno_normalization_rules(
    scenario: &MountedDifferentialScenario,
    rules: &[MountedDifferentialErrnoNormalizationRule],
    errors: &mut Vec<String>,
) {
    for rule in rules {
        if !rule.rule_id.starts_with("errno_") {
            errors.push(format!(
                "scenario {} errno normalization rule {} must start with errno_",
                scenario.scenario_id, rule.rule_id
            ));
        }
        if rule.operation_id != scenario.operation_id {
            errors.push(format!(
                "scenario {} errno normalization rule {} operation mismatch",
                scenario.scenario_id, rule.rule_id
            ));
        }
        reject_broad_allowlist_value(&rule.rule_id, "kernel_errno", &rule.kernel_errno, errors);
        reject_broad_allowlist_value(
            &rule.rule_id,
            "frankenfs_errno",
            &rule.frankenfs_errno,
            errors,
        );
        reject_broad_allowlist_value(
            &rule.rule_id,
            "normalized_errno",
            &rule.normalized_errno,
            errors,
        );
        if rule.rationale.trim().is_empty() {
            errors.push(format!(
                "scenario {} errno normalization rule {} missing rationale",
                scenario.scenario_id, rule.rule_id
            ));
        }
        if !rule.owner_bead.starts_with("bd-") {
            errors.push(format!(
                "scenario {} errno normalization rule {} owner_bead must start with bd-",
                scenario.scenario_id, rule.rule_id
            ));
        }
    }
    if scenario.classification == MountedDifferentialClassification::AllowedDiff
        && scenario
            .normalized_diff
            .iter()
            .any(|diff| diff.field == "result")
        && rules.is_empty()
    {
        errors.push(format!(
            "scenario {} allowed errno/result diff needs explicit normalization rule",
            scenario.scenario_id
        ));
    }
}

fn validate_cleanup_requirements(
    scenario: &MountedDifferentialScenario,
    cleanup: &MountedDifferentialCleanupRequirements,
    errors: &mut Vec<String>,
) {
    if cleanup.unmount != MountedDifferentialCleanupRequirement::Required {
        errors.push(format!(
            "scenario {} cleanup requirements must require unmount",
            scenario.scenario_id
        ));
    }
    if cleanup.mountpoints != MountedDifferentialCleanupRequirement::Required {
        errors.push(format!(
            "scenario {} cleanup requirements must remove mountpoints",
            scenario.scenario_id
        ));
    }
    if cleanup.images_on_success != MountedDifferentialCleanupSuccessImagePolicy::Remove {
        errors.push(format!(
            "scenario {} cleanup requirements must remove images on success",
            scenario.scenario_id
        ));
    }
    if cleanup.images_on_failure != MountedDifferentialCleanupFailureImagePolicy::Preserve {
        errors.push(format!(
            "scenario {} cleanup requirements must preserve images on failure",
            scenario.scenario_id
        ));
    }
    if cleanup.raw_logs != MountedDifferentialRawLogPolicy::Preserve {
        errors.push(format!(
            "scenario {} cleanup requirements must preserve raw logs",
            scenario.scenario_id
        ));
    }
    validate_artifact_path(
        &scenario.scenario_id,
        "cleanup_status_path",
        &cleanup.cleanup_status_path,
        errors,
    );
}

fn validate_lane_isolation(scenario: &MountedDifferentialScenario, errors: &mut Vec<String>) {
    let isolation = &scenario.lane_isolation;
    validate_artifact_path(
        &scenario.scenario_id,
        "kernel_image_path",
        &isolation.kernel_image_path,
        errors,
    );
    validate_artifact_path(
        &scenario.scenario_id,
        "frankenfs_image_path",
        &isolation.frankenfs_image_path,
        errors,
    );
    validate_artifact_path(
        &scenario.scenario_id,
        "kernel_mountpoint",
        &isolation.kernel_mountpoint,
        errors,
    );
    validate_artifact_path(
        &scenario.scenario_id,
        "frankenfs_mountpoint",
        &isolation.frankenfs_mountpoint,
        errors,
    );
    validate_artifact_path(
        &scenario.scenario_id,
        "kernel_output_root",
        &isolation.kernel_output_root,
        errors,
    );
    validate_artifact_path(
        &scenario.scenario_id,
        "frankenfs_output_root",
        &isolation.frankenfs_output_root,
        errors,
    );
    if isolation.kernel_image_path == isolation.frankenfs_image_path {
        errors.push(format!(
            "scenario {} kernel and FrankenFS image paths must be distinct",
            scenario.scenario_id
        ));
    }
    if isolation.kernel_mountpoint == isolation.frankenfs_mountpoint {
        errors.push(format!(
            "scenario {} kernel and FrankenFS mountpoints must be distinct",
            scenario.scenario_id
        ));
    }
    if isolation.kernel_output_root == isolation.frankenfs_output_root {
        errors.push(format!(
            "scenario {} kernel and FrankenFS output roots must be distinct",
            scenario.scenario_id
        ));
    }
    validate_observation_log_roots(
        scenario,
        &scenario.kernel_observation,
        &isolation.kernel_output_root,
        MountedDifferentialSide::Kernel,
        errors,
    );
    validate_observation_log_roots(
        scenario,
        &scenario.frankenfs_observation,
        &isolation.frankenfs_output_root,
        MountedDifferentialSide::Frankenfs,
        errors,
    );
    for required in [
        &scenario.kernel_observation.stdout_path,
        &scenario.kernel_observation.stderr_path,
        &scenario.frankenfs_observation.stdout_path,
        &scenario.frankenfs_observation.stderr_path,
    ] {
        if !scenario.artifact_paths.iter().any(|path| path == required) {
            errors.push(format!(
                "scenario {} artifact_paths must preserve raw log {}",
                scenario.scenario_id, required
            ));
        }
    }
}

fn validate_observation_log_roots(
    scenario: &MountedDifferentialScenario,
    observation: &MountedDifferentialObservation,
    root: &str,
    side: MountedDifferentialSide,
    errors: &mut Vec<String>,
) {
    if !path_has_prefix(&observation.stdout_path, root) {
        errors.push(format!(
            "scenario {} {:?} stdout_path crosses lane root",
            scenario.scenario_id, side
        ));
    }
    if !path_has_prefix(&observation.stderr_path, root) {
        errors.push(format!(
            "scenario {} {:?} stderr_path crosses lane root",
            scenario.scenario_id, side
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
        validate_artifact_path(&scenario.scenario_id, "artifact path", path, errors);
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
    if skip_class == MountedDifferentialHostSkipClass::MkfsExt4Missing
        && scenario.filesystem != MountedDifferentialFilesystem::Ext4
    {
        errors.push(format!(
            "scenario {} mkfs.ext4 missing diagnosis used on non-ext4 scenario",
            scenario.scenario_id
        ));
    }
    if skip_class == MountedDifferentialHostSkipClass::MkfsBtrfsMissing
        && scenario.filesystem != MountedDifferentialFilesystem::Btrfs
    {
        errors.push(format!(
            "scenario {} mkfs.btrfs missing diagnosis used on non-btrfs scenario",
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

fn validate_artifact_path(scenario_id: &str, field: &str, path: &str, errors: &mut Vec<String>) {
    if path.trim().is_empty() || path.contains("..") {
        errors.push(format!("scenario {scenario_id} has invalid {field} {path}"));
    }
}

fn path_has_prefix(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
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
        scenario_id: &str,
        side: MountedDifferentialSide,
        result: MountedDifferentialObservationResult,
        errno: Option<&str>,
    ) -> MountedDifferentialObservation {
        let lane = match side {
            MountedDifferentialSide::Kernel => "kernel",
            MountedDifferentialSide::Frankenfs => "frankenfs",
        };
        MountedDifferentialObservation {
            side,
            result,
            errno: errno.map(str::to_owned),
            stdout_path: format!("artifacts/{scenario_id}/{lane}/stdout.log"),
            stderr_path: format!("artifacts/{scenario_id}/{lane}/stderr.log"),
            image_hash_before: HASH_A.to_owned(),
            image_hash_after: HASH_B.to_owned(),
            mount_options: if result == MountedDifferentialObservationResult::Skip {
                Vec::new()
            } else {
                vec!["rw".to_owned(), "default_permissions".to_owned()]
            },
            uid: 1000,
            gid: 1000,
        }
    }

    fn baseline_manifest(
        scenario_id: &str,
        _operation_id: &str,
        filesystem: MountedDifferentialFilesystem,
        errno_rules: Vec<MountedDifferentialErrnoNormalizationRule>,
        host_skip_class: Option<MountedDifferentialHostSkipClass>,
    ) -> MountedDifferentialBaselineManifest {
        let mkfs_command = match filesystem {
            MountedDifferentialFilesystem::Ext4 => {
                format!("mkfs.ext4 -F -U test-seed artifacts/{scenario_id}/kernel.img")
            }
            MountedDifferentialFilesystem::Btrfs => {
                format!("mkfs.btrfs -f -U test-seed artifacts/{scenario_id}/kernel.img")
            }
        };
        let root_owned = host_skip_class
            == Some(MountedDifferentialHostSkipClass::BtrfsDefaultPermissionsRootOwned);
        let dev_fuse = if host_skip_class == Some(MountedDifferentialHostSkipClass::FuseMissing) {
            CapabilityState::Missing
        } else {
            CapabilityState::PermissionDenied
        };
        let fusermount = CapabilityState::PermissionDenied;
        let kernel_mount = CapabilityState::PermissionDenied;
        let mkfs_helper = match host_skip_class {
            Some(
                MountedDifferentialHostSkipClass::MkfsExt4Missing
                | MountedDifferentialHostSkipClass::MkfsBtrfsMissing,
            ) => CapabilityState::Missing,
            _ => CapabilityState::Available,
        };
        MountedDifferentialBaselineManifest {
            baseline_id: format!("baseline_{scenario_id}"),
            kernel_release: "6.19.0-test".to_owned(),
            filesystem,
            mkfs_command,
            image_seed: format!("seed-{scenario_id}"),
            image_hash: HASH_A.to_owned(),
            mount_options: vec!["rw".to_owned(), "default_permissions".to_owned()],
            uid: 1000,
            gid: 1000,
            root_ownership: MountedDifferentialRootOwnership {
                uid: if root_owned { 0 } else { 1000 },
                gid: if root_owned { 0 } else { 1000 },
                mode: "0755".to_owned(),
                default_permissions: true,
                root_owned,
            },
            capability_probe: MountedDifferentialCapabilityProbe {
                probe_id: format!("capability_{scenario_id}"),
                dev_fuse,
                fusermount,
                kernel_mount,
                mkfs_helper,
                stdout_path: format!("artifacts/{scenario_id}/capability/stdout.log"),
                stderr_path: format!("artifacts/{scenario_id}/capability/stderr.log"),
            },
            allowed_errno_normalization: errno_rules,
            cleanup_requirements: MountedDifferentialCleanupRequirements {
                unmount: MountedDifferentialCleanupRequirement::Required,
                mountpoints: MountedDifferentialCleanupRequirement::Required,
                images_on_success: MountedDifferentialCleanupSuccessImagePolicy::Remove,
                images_on_failure: MountedDifferentialCleanupFailureImagePolicy::Preserve,
                raw_logs: MountedDifferentialRawLogPolicy::Preserve,
                cleanup_status_path: format!("artifacts/{scenario_id}/cleanup.json"),
            },
        }
    }

    fn lane_isolation(scenario_id: &str) -> MountedDifferentialLaneIsolation {
        MountedDifferentialLaneIsolation {
            kernel_image_path: format!("artifacts/{scenario_id}/kernel/image.img"),
            frankenfs_image_path: format!("artifacts/{scenario_id}/frankenfs/image.img"),
            kernel_mountpoint: format!("artifacts/{scenario_id}/kernel/mnt"),
            frankenfs_mountpoint: format!("artifacts/{scenario_id}/frankenfs/mnt"),
            kernel_output_root: format!("artifacts/{scenario_id}/kernel"),
            frankenfs_output_root: format!("artifacts/{scenario_id}/frankenfs"),
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
            baseline_manifest: baseline_manifest(
                scenario_id,
                "open_readback",
                filesystem,
                Vec::new(),
                None,
            ),
            lane_isolation: lane_isolation(scenario_id),
            normalized_diff: Vec::new(),
            cleanup_status: CleanupStatus::Clean,
            reproduction_command: format!("{RUNNER_PATH} --scenario {scenario_id}"),
            artifact_paths: vec![
                format!("artifacts/{scenario_id}.json"),
                format!("artifacts/{scenario_id}/kernel/stdout.log"),
                format!("artifacts/{scenario_id}/kernel/stderr.log"),
                format!("artifacts/{scenario_id}/frankenfs/stdout.log"),
                format!("artifacts/{scenario_id}/frankenfs/stderr.log"),
            ],
        }
    }

    fn host_skip_scenario(
        scenario_id: &str,
        filesystem: MountedDifferentialFilesystem,
        skip_class: MountedDifferentialHostSkipClass,
    ) -> MountedDifferentialScenario {
        let mut scenario = base_scenario(
            scenario_id,
            filesystem,
            MountedDifferentialClassification::HostSkip,
            observation(
                scenario_id,
                MountedDifferentialSide::Kernel,
                MountedDifferentialObservationResult::Skip,
                Some(skip_class.label()),
            ),
            observation(
                scenario_id,
                MountedDifferentialSide::Frankenfs,
                MountedDifferentialObservationResult::Skip,
                Some(skip_class.label()),
            ),
        );
        scenario.operation_id = format!("{}_probe", skip_class.label());
        scenario.scenario_kind = MountedDifferentialScenarioKind::HostSkip;
        scenario.host_skip_class = Some(skip_class);
        scenario.baseline_manifest = baseline_manifest(
            scenario_id,
            &scenario.operation_id,
            filesystem,
            Vec::new(),
            Some(skip_class),
        );
        scenario
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
                "mounted_diff_ext4_create_readback",
                MountedDifferentialSide::Kernel,
                MountedDifferentialObservationResult::Ok,
                None,
            ),
            observation(
                "mounted_diff_ext4_create_readback",
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
                "mounted_diff_ext4_fiemap_transport_errno",
                MountedDifferentialSide::Kernel,
                MountedDifferentialObservationResult::Errno,
                Some("EOPNOTSUPP"),
            ),
            observation(
                "mounted_diff_ext4_fiemap_transport_errno",
                MountedDifferentialSide::Frankenfs,
                MountedDifferentialObservationResult::Errno,
                Some("ENOTTY"),
            ),
        );
        allowed.operation_id = "fiemap_probe".to_owned();
        allowed.allowlist_id = Some(allowlist.allowlist_id.clone());
        allowed.baseline_manifest = baseline_manifest(
            "mounted_diff_ext4_fiemap_transport_errno",
            "fiemap_probe",
            MountedDifferentialFilesystem::Ext4,
            vec![MountedDifferentialErrnoNormalizationRule {
                rule_id: "errno_ext4_fiemap_transport".to_owned(),
                operation_id: "fiemap_probe".to_owned(),
                kernel_errno: "EOPNOTSUPP".to_owned(),
                frankenfs_errno: "ENOTTY".to_owned(),
                normalized_errno: "fiemap_transport_unsupported".to_owned(),
                rationale: "transport and userspace dispatch reject the same unsupported probe"
                    .to_owned(),
                owner_bead: "bd-29cpd".to_owned(),
            }],
            None,
        );
        allowed.normalized_diff = vec![MountedDifferentialDiff {
            field: "result".to_owned(),
            kernel_value: "EOPNOTSUPP".to_owned(),
            frankenfs_value: "ENOTTY".to_owned(),
        }];

        let fuse_missing = host_skip_scenario(
            "mounted_diff_ext4_fuse_missing",
            MountedDifferentialFilesystem::Ext4,
            MountedDifferentialHostSkipClass::FuseMissing,
        );
        let fuse_permission = host_skip_scenario(
            "mounted_diff_ext4_fuse_permission_skip",
            MountedDifferentialFilesystem::Ext4,
            MountedDifferentialHostSkipClass::FusePermissionDenied,
        );
        let kernel_mount = host_skip_scenario(
            "mounted_diff_ext4_kernel_mount_permission_skip",
            MountedDifferentialFilesystem::Ext4,
            MountedDifferentialHostSkipClass::KernelMountPermissionDenied,
        );
        let mkfs_ext4 = host_skip_scenario(
            "mounted_diff_ext4_mkfs_missing",
            MountedDifferentialFilesystem::Ext4,
            MountedDifferentialHostSkipClass::MkfsExt4Missing,
        );
        let mkfs_btrfs = host_skip_scenario(
            "mounted_diff_btrfs_mkfs_missing",
            MountedDifferentialFilesystem::Btrfs,
            MountedDifferentialHostSkipClass::MkfsBtrfsMissing,
        );
        let btrfs_root_owned = host_skip_scenario(
            "mounted_diff_btrfs_default_permissions_root_owned",
            MountedDifferentialFilesystem::Btrfs,
            MountedDifferentialHostSkipClass::BtrfsDefaultPermissionsRootOwned,
        );
        let unsupported_scope_skip = host_skip_scenario(
            "mounted_diff_ext4_unsupported_scope_skip",
            MountedDifferentialFilesystem::Ext4,
            MountedDifferentialHostSkipClass::UnsupportedScope,
        );

        let mut unsupported = base_scenario(
            "mounted_diff_btrfs_unsupported_clone_range",
            MountedDifferentialFilesystem::Btrfs,
            MountedDifferentialClassification::Unsupported,
            observation(
                "mounted_diff_btrfs_unsupported_clone_range",
                MountedDifferentialSide::Kernel,
                MountedDifferentialObservationResult::Errno,
                Some("EOPNOTSUPP"),
            ),
            observation(
                "mounted_diff_btrfs_unsupported_clone_range",
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
                fusermount: CapabilityState::PermissionDenied,
                kernel_mount: CapabilityState::PermissionDenied,
                mkfs_ext4: CapabilityState::Available,
                mkfs_btrfs: CapabilityState::Available,
            },
            allowlist: vec![allowlist],
            scenarios: vec![
                pass,
                allowed,
                fuse_missing,
                fuse_permission,
                kernel_mount,
                mkfs_ext4,
                mkfs_btrfs,
                btrfs_root_owned,
                unsupported_scope_skip,
                unsupported,
            ],
        }
    }

    #[test]
    fn valid_report_covers_strict_allowlist_and_host_skip_contract() {
        let validation = validate_mounted_differential_oracle_report(&valid_report());
        assert!(validation.valid, "{:?}", validation.errors);
        assert_eq!(validation.scenario_count, 10);
        assert_eq!(validation.filesystems, vec!["btrfs", "ext4"]);
        assert_eq!(validation.classification_counts["allowed_diff"], 1);
        assert_eq!(validation.classification_counts["host_skip"], 7);
        assert_eq!(
            validation.host_skip_classes,
            vec![
                "btrfs_default_permissions_root_owned",
                "fuse_missing",
                "fuse_permission_denied",
                "kernel_mount_permission_denied",
                "mkfs_btrfs_missing",
                "mkfs_ext4_missing",
                "unsupported_scope",
            ]
        );
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
        report.scenarios[7].filesystem = MountedDifferentialFilesystem::Ext4;
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
    fn baseline_manifest_and_lane_isolation_fail_closed() {
        let mut report = valid_report();
        report.scenarios[0].baseline_manifest.mkfs_command = "mkfs.btrfs -f wrong.img".to_owned();
        report.scenarios[0]
            .baseline_manifest
            .cleanup_requirements
            .raw_logs = MountedDifferentialRawLogPolicy::Discard;
        report.scenarios[0].lane_isolation.frankenfs_mountpoint =
            report.scenarios[0].lane_isolation.kernel_mountpoint.clone();
        report.scenarios[0].frankenfs_observation.stdout_path =
            report.scenarios[0].kernel_observation.stdout_path.clone();
        let validation = validate_mounted_differential_oracle_report(&report);
        assert!(!validation.valid);
        assert!(
            validation
                .errors
                .iter()
                .any(|error| error.contains("mkfs_command must include mkfs.ext4"))
        );
        assert!(
            validation
                .errors
                .iter()
                .any(|error| error.contains("preserve raw logs"))
        );
        assert!(
            validation
                .errors
                .iter()
                .any(|error| error.contains("mountpoints must be distinct"))
        );
        assert!(
            validation
                .errors
                .iter()
                .any(|error| error.contains("stdout_path crosses lane root"))
        );
    }

    #[test]
    fn unsupported_scope_requires_owner_or_non_goal() {
        let mut report = valid_report();
        report.scenarios[9].owner_bead = None;
        report.scenarios[9].non_goal_reason = None;
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
    fn render_mounted_differential_oracle_markdown_diff_gate_blocks_snapshot() {
        let mut report = valid_report();
        report.scenarios[1].classification = MountedDifferentialClassification::Diff;
        report.scenarios[1].allowlist_id = None;
        let validation = validate_mounted_differential_oracle_report(&report);
        let markdown = render_mounted_differential_oracle_markdown(&validation);
        assert!(markdown.contains("Mounted Differential Oracle Report"));
        assert!(markdown.contains("bd-rchk0.5.2.1"));
        assert!(markdown.contains("`diff`: 1"));
        assert!(markdown.contains("Host Skip Classes"));
        assert!(markdown.contains("Release Gate Blocks"));
        insta::assert_snapshot!(
            "render_mounted_differential_oracle_markdown_diff_gate_blocks_snapshot",
            markdown
        );
    }
}
