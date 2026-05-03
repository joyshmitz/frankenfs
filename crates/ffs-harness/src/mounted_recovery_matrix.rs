#![forbid(unsafe_code)]

//! Mounted recovery matrix validation for `bd-rchk0.3.3`.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path};

pub const RECOVERY_MATRIX_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_RECOVERY_MATRIX_PATH: &str = "tests/workload-matrix/mounted_recovery_matrix.json";
const DEFAULT_RECOVERY_MATRIX_JSON: &str =
    include_str!("../../../tests/workload-matrix/mounted_recovery_matrix.json");

const REQUIRED_FILESYSTEMS: [&str; 2] = ["ext4", "btrfs"];
const REQUIRED_LIFECYCLE_EVENTS: [&str; 7] = [
    "clean_unmount",
    "forced_unmount",
    "process_termination",
    "fsync_file_boundary",
    "fsync_dir_boundary",
    "reopen_verify",
    "cleanup",
];
const REQUIRED_CLASSIFICATIONS: [&str; 5] = [
    "pass",
    "product_failure",
    "harness_bug",
    "host_limitation",
    "unsupported_v1_scope",
];
const REQUIRED_ERROR_CLASSES: [&str; 5] = [
    "none",
    "product_failure",
    "harness_bug",
    "host_limitation",
    "unsupported_v1_scope",
];
const REQUIRED_RESULT_FORMATS: [&str; 2] = ["json", "csv"];
const REQUIRED_RESULT_FIELDS: [&str; 12] = [
    "scenario_id",
    "filesystem",
    "lifecycle_event",
    "pre_crash_operations",
    "crash_or_unmount_point",
    "recovery_command",
    "expected_survivors",
    "actual_state_artifact",
    "stdout_path",
    "stderr_path",
    "classification",
    "cleanup_status",
];
const REQUIRED_ARTIFACT_PATHS: [&str; 5] = [
    "mounted_recovery_matrix_validation.json",
    "mounted_recovery_results.json",
    "mounted_recovery_results.csv",
    "stdout/",
    "stderr/",
];
const SAFE_CONTROL_METHODS: [&str; 5] = [
    "none",
    "fusermount_unmount",
    "fusermount_lazy_unmount",
    "terminate_mount_daemon",
    "cleanup_temp_mount",
];
const ALLOWED_CLEANUP_STATUSES: [&str; 3] = ["clean", "preserved_artifacts", "failed"];
const ALLOWED_SIGNALS: [&str; 3] = ["none", "SIGTERM", "SIGKILL"];
const UNSAFE_COMMAND_FRAGMENTS: [&str; 13] = [
    "rm -rf",
    "git reset --hard",
    "git clean -fd",
    "mkfs",
    " dd ",
    " of=/dev",
    "kill -9 -1",
    "killall",
    "pkill -9",
    "reboot",
    "shutdown",
    "umount -a",
    "chmod -r /",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedRecoveryMatrix {
    pub schema_version: u32,
    pub bead_id: String,
    pub runner: String,
    pub results_contract: RecoveryResultsContract,
    pub scenarios: Vec<MountedRecoveryScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryResultsContract {
    pub formats: Vec<String>,
    pub required_fields: Vec<String>,
    pub artifact_paths: Vec<String>,
    pub classifications: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedRecoveryScenario {
    pub scenario_id: String,
    pub filesystem: String,
    pub lifecycle_event: String,
    pub pre_crash_operations: Vec<String>,
    pub crash_or_unmount_point: String,
    pub recovery_command: String,
    pub expected_survivors: Vec<SurvivorExpectation>,
    pub actual_state_artifact: String,
    pub stdout_path: String,
    pub stderr_path: String,
    pub classification: String,
    pub error_class: String,
    pub cleanup_status: String,
    pub process_control: ProcessControlBoundary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurvivorExpectation {
    pub path: String,
    pub kind: String,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessControlBoundary {
    pub method: String,
    pub signal: String,
    pub target_scope: String,
    pub forced_unmount_allowed: bool,
    pub destructive_host_command: bool,
    pub preserve_partial_artifacts: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedRecoveryMatrixReport {
    pub schema_version: u32,
    pub bead_id: String,
    pub scenario_count: usize,
    pub filesystems: Vec<String>,
    pub lifecycle_events: Vec<String>,
    pub classifications: Vec<String>,
    pub error_classes: Vec<String>,
    pub cleanup_statuses: Vec<String>,
    pub process_control_methods: Vec<String>,
    pub valid: bool,
    pub errors: Vec<String>,
}

pub fn load_mounted_recovery_matrix(path: &Path) -> Result<MountedRecoveryMatrix> {
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    parse_mounted_recovery_matrix(&text)
        .with_context(|| format!("invalid mounted recovery matrix {}", path.display()))
}

pub fn parse_mounted_recovery_matrix(text: &str) -> Result<MountedRecoveryMatrix> {
    serde_json::from_str(text).context("failed to parse mounted recovery matrix JSON")
}

pub fn validate_default_mounted_recovery_matrix() -> Result<MountedRecoveryMatrixReport> {
    let matrix = parse_mounted_recovery_matrix(DEFAULT_RECOVERY_MATRIX_JSON)?;
    let report = validate_mounted_recovery_matrix(&matrix);
    fail_on_mounted_recovery_matrix_errors(&report)?;
    Ok(report)
}

#[must_use]
pub fn validate_mounted_recovery_matrix(
    matrix: &MountedRecoveryMatrix,
) -> MountedRecoveryMatrixReport {
    let mut errors = Vec::new();
    let mut scenario_ids = BTreeSet::new();
    let mut filesystems = BTreeSet::new();
    let mut lifecycle_events = BTreeSet::new();
    let mut classifications = BTreeSet::new();
    let mut error_classes = BTreeSet::new();
    let mut cleanup_statuses = BTreeSet::new();
    let mut process_control_methods = BTreeSet::new();
    let mut pre_crash_operations = BTreeSet::new();
    let mut partial_artifact_scenario_count = 0_usize;

    validate_top_level(matrix, &mut errors);
    validate_results_contract(&matrix.results_contract, &mut errors);

    for scenario in &matrix.scenarios {
        validate_scenario(
            scenario,
            &mut scenario_ids,
            &mut filesystems,
            &mut lifecycle_events,
            &mut classifications,
            &mut error_classes,
            &mut cleanup_statuses,
            &mut process_control_methods,
            &mut pre_crash_operations,
            &mut partial_artifact_scenario_count,
            &mut errors,
        );
    }

    validate_coverage(
        &filesystems,
        &lifecycle_events,
        &pre_crash_operations,
        partial_artifact_scenario_count,
        &mut errors,
    );

    MountedRecoveryMatrixReport {
        schema_version: matrix.schema_version,
        bead_id: matrix.bead_id.clone(),
        scenario_count: matrix.scenarios.len(),
        filesystems: filesystems.into_iter().collect(),
        lifecycle_events: lifecycle_events.into_iter().collect(),
        classifications: classifications.into_iter().collect(),
        error_classes: error_classes.into_iter().collect(),
        cleanup_statuses: cleanup_statuses.into_iter().collect(),
        process_control_methods: process_control_methods.into_iter().collect(),
        valid: errors.is_empty(),
        errors,
    }
}

fn validate_top_level(matrix: &MountedRecoveryMatrix, errors: &mut Vec<String>) {
    if matrix.schema_version != RECOVERY_MATRIX_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version must be {RECOVERY_MATRIX_SCHEMA_VERSION}, got {}",
            matrix.schema_version
        ));
    }
    if matrix.bead_id != "bd-rchk0.3.3" {
        errors.push(format!(
            "bead_id must be bd-rchk0.3.3, got {}",
            matrix.bead_id
        ));
    }
    if matrix.runner != "scripts/e2e/ffs_mounted_recovery_matrix_e2e.sh" {
        errors.push(format!("unexpected runner {}", matrix.runner));
    }
    if matrix.scenarios.is_empty() {
        errors.push("matrix must contain at least one scenario".to_owned());
    }
}

fn validate_results_contract(contract: &RecoveryResultsContract, errors: &mut Vec<String>) {
    for required in REQUIRED_RESULT_FORMATS {
        if !contract.formats.iter().any(|format| format == required) {
            errors.push(format!("results_contract missing {required} format"));
        }
    }
    for required in REQUIRED_RESULT_FIELDS {
        if !contract
            .required_fields
            .iter()
            .any(|field| field == required)
        {
            errors.push(format!(
                "results_contract missing required field {required}"
            ));
        }
    }
    for required in REQUIRED_ARTIFACT_PATHS {
        if !contract.artifact_paths.iter().any(|path| path == required) {
            errors.push(format!("results_contract missing artifact path {required}"));
        }
    }
    for required in REQUIRED_CLASSIFICATIONS {
        if !contract
            .classifications
            .iter()
            .any(|classification| classification == required)
        {
            errors.push(format!(
                "results_contract missing classification {required}"
            ));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_scenario(
    scenario: &MountedRecoveryScenario,
    scenario_ids: &mut BTreeSet<String>,
    filesystems: &mut BTreeSet<String>,
    lifecycle_events: &mut BTreeSet<String>,
    classifications: &mut BTreeSet<String>,
    error_classes: &mut BTreeSet<String>,
    cleanup_statuses: &mut BTreeSet<String>,
    process_control_methods: &mut BTreeSet<String>,
    pre_crash_operations: &mut BTreeSet<String>,
    partial_artifact_scenario_count: &mut usize,
    errors: &mut Vec<String>,
) {
    validate_scenario_identity(scenario, scenario_ids, errors);
    validate_scenario_classifiers(
        scenario,
        filesystems,
        lifecycle_events,
        classifications,
        error_classes,
        cleanup_statuses,
        errors,
    );
    validate_pre_crash_operations(scenario, pre_crash_operations, errors);
    validate_recovery_command(scenario, errors);
    validate_survivors(scenario, errors);
    validate_artifact_paths(scenario, errors);
    validate_process_control(
        scenario,
        process_control_methods,
        partial_artifact_scenario_count,
        errors,
    );
}

fn validate_scenario_identity(
    scenario: &MountedRecoveryScenario,
    scenario_ids: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    if !scenario_ids.insert(scenario.scenario_id.clone()) {
        errors.push(format!("duplicate scenario_id {}", scenario.scenario_id));
    }
    if !scenario.scenario_id.starts_with("mounted_recovery_") {
        errors.push(format!(
            "scenario_id {} must start with mounted_recovery_",
            scenario.scenario_id
        ));
    }
}

fn validate_scenario_classifiers(
    scenario: &MountedRecoveryScenario,
    filesystems: &mut BTreeSet<String>,
    lifecycle_events: &mut BTreeSet<String>,
    classifications: &mut BTreeSet<String>,
    error_classes: &mut BTreeSet<String>,
    cleanup_statuses: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    if !REQUIRED_FILESYSTEMS.contains(&scenario.filesystem.as_str()) {
        errors.push(format!(
            "scenario {} has unsupported filesystem {}",
            scenario.scenario_id, scenario.filesystem
        ));
    }
    filesystems.insert(scenario.filesystem.clone());

    if !REQUIRED_LIFECYCLE_EVENTS.contains(&scenario.lifecycle_event.as_str()) {
        errors.push(format!(
            "scenario {} has unsupported lifecycle_event {}",
            scenario.scenario_id, scenario.lifecycle_event
        ));
    }
    lifecycle_events.insert(scenario.lifecycle_event.clone());

    if !REQUIRED_CLASSIFICATIONS.contains(&scenario.classification.as_str()) {
        errors.push(format!(
            "scenario {} has invalid classification {}",
            scenario.scenario_id, scenario.classification
        ));
    }
    classifications.insert(scenario.classification.clone());

    if !REQUIRED_ERROR_CLASSES.contains(&scenario.error_class.as_str()) {
        errors.push(format!(
            "scenario {} has invalid error_class {}",
            scenario.scenario_id, scenario.error_class
        ));
    }
    error_classes.insert(scenario.error_class.clone());

    if scenario.classification == "pass" && scenario.error_class != "none" {
        errors.push(format!(
            "scenario {} pass classification must use error_class none",
            scenario.scenario_id
        ));
    }
    if scenario.classification != "pass" && scenario.error_class != scenario.classification {
        errors.push(format!(
            "scenario {} non-pass classification must match error_class",
            scenario.scenario_id
        ));
    }

    if !ALLOWED_CLEANUP_STATUSES.contains(&scenario.cleanup_status.as_str()) {
        errors.push(format!(
            "scenario {} has invalid cleanup_status {}",
            scenario.scenario_id, scenario.cleanup_status
        ));
    }
    cleanup_statuses.insert(scenario.cleanup_status.clone());
}

fn validate_pre_crash_operations(
    scenario: &MountedRecoveryScenario,
    pre_crash_operations: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    if scenario.pre_crash_operations.is_empty() {
        errors.push(format!(
            "scenario {} must list pre_crash_operations",
            scenario.scenario_id
        ));
    }
    for operation in &scenario.pre_crash_operations {
        if operation.trim().is_empty() {
            errors.push(format!(
                "scenario {} contains empty pre_crash_operation",
                scenario.scenario_id
            ));
        } else {
            pre_crash_operations.insert(operation.clone());
        }
    }
    if scenario.crash_or_unmount_point.trim().is_empty() {
        errors.push(format!(
            "scenario {} missing crash_or_unmount_point",
            scenario.scenario_id
        ));
    }
}

fn validate_recovery_command(scenario: &MountedRecoveryScenario, errors: &mut Vec<String>) {
    if scenario.recovery_command.trim().is_empty() {
        errors.push(format!(
            "scenario {} missing recovery_command",
            scenario.scenario_id
        ));
    }
    if contains_unsafe_command_fragment(&scenario.recovery_command) {
        errors.push(format!(
            "scenario {} recovery_command contains unsafe host command",
            scenario.scenario_id
        ));
    }
}

fn validate_survivors(scenario: &MountedRecoveryScenario, errors: &mut Vec<String>) {
    if scenario.expected_survivors.is_empty() {
        errors.push(format!(
            "scenario {} missing expected_survivors",
            scenario.scenario_id
        ));
    }
    for survivor in &scenario.expected_survivors {
        if survivor.path.trim().is_empty() || !survivor.path.starts_with('/') {
            errors.push(format!(
                "scenario {} survivor path must be absolute in mounted image: {}",
                scenario.scenario_id, survivor.path
            ));
        }
        if !["file", "directory", "metadata", "xattr"].contains(&survivor.kind.as_str()) {
            errors.push(format!(
                "scenario {} survivor {} has invalid kind {}",
                scenario.scenario_id, survivor.path, survivor.kind
            ));
        }
        if survivor.checks.is_empty() {
            errors.push(format!(
                "scenario {} survivor {} missing checks",
                scenario.scenario_id, survivor.path
            ));
        }
    }
}

fn validate_artifact_paths(scenario: &MountedRecoveryScenario, errors: &mut Vec<String>) {
    for (field, path) in [
        ("actual_state_artifact", &scenario.actual_state_artifact),
        ("stdout_path", &scenario.stdout_path),
        ("stderr_path", &scenario.stderr_path),
    ] {
        if let Err(error) = validate_relative_artifact_path(path) {
            errors.push(format!(
                "scenario {} invalid {field}: {error}",
                scenario.scenario_id
            ));
        }
    }
}

fn validate_process_control(
    scenario: &MountedRecoveryScenario,
    process_control_methods: &mut BTreeSet<String>,
    partial_artifact_scenario_count: &mut usize,
    errors: &mut Vec<String>,
) {
    let control = &scenario.process_control;
    process_control_methods.insert(control.method.clone());

    if !SAFE_CONTROL_METHODS.contains(&control.method.as_str()) {
        errors.push(format!(
            "scenario {} has unsafe process_control method {}",
            scenario.scenario_id, control.method
        ));
    }
    if !ALLOWED_SIGNALS.contains(&control.signal.as_str()) {
        errors.push(format!(
            "scenario {} has invalid process_control signal {}",
            scenario.scenario_id, control.signal
        ));
    }
    if control.destructive_host_command {
        errors.push(format!(
            "scenario {} enables destructive_host_command",
            scenario.scenario_id
        ));
    }
    if control.target_scope.trim().is_empty()
        || !(control.target_scope.contains("temp") || control.target_scope.contains("mount_daemon"))
    {
        errors.push(format!(
            "scenario {} process_control target_scope must be temporary or mount-daemon scoped",
            scenario.scenario_id
        ));
    }
    if control.preserve_partial_artifacts {
        *partial_artifact_scenario_count += 1;
    }

    match scenario.lifecycle_event.as_str() {
        "clean_unmount" if control.method != "fusermount_unmount" => {
            errors.push(format!(
                "scenario {} clean_unmount must use fusermount_unmount",
                scenario.scenario_id
            ));
        }
        "forced_unmount" => {
            if control.method != "fusermount_lazy_unmount" || !control.forced_unmount_allowed {
                errors.push(format!(
                    "scenario {} forced_unmount must use allowed fusermount_lazy_unmount",
                    scenario.scenario_id
                ));
            }
            if !control.preserve_partial_artifacts {
                errors.push(format!(
                    "scenario {} forced_unmount must preserve partial artifacts",
                    scenario.scenario_id
                ));
            }
        }
        "process_termination" => {
            if control.method != "terminate_mount_daemon" {
                errors.push(format!(
                    "scenario {} process_termination must target mount daemon",
                    scenario.scenario_id
                ));
            }
            if control.signal == "none" {
                errors.push(format!(
                    "scenario {} process_termination requires SIGTERM or SIGKILL",
                    scenario.scenario_id
                ));
            }
            if !control.preserve_partial_artifacts {
                errors.push(format!(
                    "scenario {} process_termination must preserve partial artifacts",
                    scenario.scenario_id
                ));
            }
        }
        "cleanup" if control.method != "cleanup_temp_mount" => {
            errors.push(format!(
                "scenario {} cleanup must use cleanup_temp_mount",
                scenario.scenario_id
            ));
        }
        _ => {}
    }
}

fn validate_coverage(
    filesystems: &BTreeSet<String>,
    lifecycle_events: &BTreeSet<String>,
    pre_crash_operations: &BTreeSet<String>,
    partial_artifact_scenario_count: usize,
    errors: &mut Vec<String>,
) {
    for required in REQUIRED_FILESYSTEMS {
        if !filesystems.contains(required) {
            errors.push(format!("matrix missing filesystem {required}"));
        }
    }
    for required in REQUIRED_LIFECYCLE_EVENTS {
        if !lifecycle_events.contains(required) {
            errors.push(format!("matrix missing lifecycle event {required}"));
        }
    }
    for required in ["fsync_file", "fsync_dir"] {
        if !pre_crash_operations.contains(required) {
            errors.push(format!("matrix missing pre-crash operation {required}"));
        }
    }
    if partial_artifact_scenario_count == 0 {
        errors.push("matrix missing partial-artifact preservation scenario".to_owned());
    }
}

fn validate_relative_artifact_path(raw: &str) -> Result<()> {
    if raw.trim().is_empty() {
        bail!("path is empty");
    }
    let path = Path::new(raw);
    if path.is_absolute() {
        bail!("path must be relative");
    }
    for component in path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => bail!("path must not contain parent traversal"),
            Component::RootDir | Component::Prefix(_) => bail!("path must be relative"),
        }
    }
    Ok(())
}

fn contains_unsafe_command_fragment(command: &str) -> bool {
    let lowered = command.to_ascii_lowercase();
    let collapsed = format!(
        " {} ",
        lowered.split_whitespace().collect::<Vec<_>>().join(" ")
    );
    UNSAFE_COMMAND_FRAGMENTS
        .iter()
        .any(|fragment| collapsed.contains(fragment))
}

pub fn fail_on_mounted_recovery_matrix_errors(report: &MountedRecoveryMatrixReport) -> Result<()> {
    if report.valid {
        Ok(())
    } else {
        bail!(
            "mounted recovery matrix failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_matrix() -> MountedRecoveryMatrix {
        parse_mounted_recovery_matrix(DEFAULT_RECOVERY_MATRIX_JSON)
            .expect("default recovery matrix parses")
    }

    #[test]
    fn default_matrix_validates_recovery_contract() {
        let report = validate_default_mounted_recovery_matrix().expect("default matrix validates");
        assert_eq!(report.bead_id, "bd-rchk0.3.3");
        assert_eq!(report.filesystems, vec!["btrfs", "ext4"]);
        for event in REQUIRED_LIFECYCLE_EVENTS {
            assert!(
                report.lifecycle_events.contains(&event.to_owned()),
                "missing lifecycle event {event}"
            );
        }
        assert!(
            report
                .process_control_methods
                .contains(&"terminate_mount_daemon".to_owned())
        );
    }

    #[test]
    fn unsafe_recovery_command_is_rejected() {
        let mut matrix = valid_matrix();
        matrix.scenarios[0].recovery_command = "rm -rf /tmp/frankenfs".to_owned();
        let report = validate_mounted_recovery_matrix(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("unsafe host command"))
        );
    }

    #[test]
    fn process_termination_must_preserve_partial_artifacts() {
        let mut matrix = valid_matrix();
        let scenario = matrix
            .scenarios
            .iter_mut()
            .find(|scenario| scenario.lifecycle_event == "process_termination")
            .expect("process termination scenario exists");
        scenario.process_control.preserve_partial_artifacts = false;
        let report = validate_mounted_recovery_matrix(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("process_termination must preserve"))
        );
    }

    #[test]
    fn absolute_artifact_paths_are_rejected() {
        let mut matrix = valid_matrix();
        matrix.scenarios[0].actual_state_artifact = "/tmp/actual.json".to_owned();
        let report = validate_mounted_recovery_matrix(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("path must be relative"))
        );
    }

    #[test]
    fn pass_classification_must_use_none_error_class() {
        let mut matrix = valid_matrix();
        matrix.scenarios[0].error_class = "product_failure".to_owned();
        let report = validate_mounted_recovery_matrix(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("pass classification"))
        );
    }

    #[test]
    fn duplicate_scenario_ids_are_rejected() {
        let mut matrix = valid_matrix();
        let duplicate = matrix.scenarios[0].scenario_id.clone();
        matrix.scenarios[1].scenario_id = duplicate;
        let report = validate_mounted_recovery_matrix(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("duplicate scenario_id"))
        );
    }
}
