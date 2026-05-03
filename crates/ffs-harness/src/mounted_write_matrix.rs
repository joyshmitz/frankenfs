#![forbid(unsafe_code)]

//! Mounted write workload matrix validation for `bd-rchk0.3.2`.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub const MATRIX_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_MATRIX_PATH: &str = "tests/workload-matrix/mounted_write_workload_matrix.json";
const DEFAULT_MATRIX_JSON: &str =
    include_str!("../../../tests/workload-matrix/mounted_write_workload_matrix.json");

const REQUIRED_FILESYSTEMS: [&str; 2] = ["ext4", "btrfs"];
const REQUIRED_OPERATIONS: [&str; 11] = [
    "create",
    "mkdir",
    "unlink",
    "rmdir",
    "rename",
    "write_readback",
    "chmod",
    "hardlink",
    "symlink",
    "xattr_set_get",
    "fallocate_keep_size",
];
const REQUIRED_FSYNC_PATTERNS: [&str; 4] = ["every_write", "metadata_only", "final_only", "none"];
const REQUIRED_RESULT_FORMATS: [&str; 2] = ["json", "csv"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedWriteMatrix {
    pub schema_version: u32,
    pub bead_id: String,
    pub runner: String,
    pub results_contract: ResultsContract,
    pub scenarios: Vec<MountedWriteScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultsContract {
    pub formats: Vec<String>,
    pub required_fields: Vec<String>,
    pub artifact_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedWriteScenario {
    pub scenario_id: String,
    pub filesystem: String,
    pub image_setup: String,
    pub mount_flags: Vec<String>,
    pub fs_specific_options: Vec<String>,
    pub workload: WorkloadSpec,
    pub expected_outcome: ExpectedOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadSpec {
    pub operation_sequence: Vec<String>,
    pub write_sizes: Vec<u64>,
    pub fsync_pattern: String,
    pub concurrency: u32,
    pub unsupported_operations: Vec<String>,
    pub no_partial_mutation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedOutcome {
    pub outcome_class: String,
    pub detail: String,
    pub no_partial_mutation: bool,
    pub follow_up_bead: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedWriteMatrixReport {
    pub schema_version: u32,
    pub bead_id: String,
    pub scenario_count: usize,
    pub filesystems: Vec<String>,
    pub operation_kinds: Vec<String>,
    pub fsync_patterns: Vec<String>,
    pub output_formats: Vec<String>,
    pub max_concurrency: u32,
    pub write_sizes: Vec<u64>,
    pub valid: bool,
    pub errors: Vec<String>,
}

pub fn load_mounted_write_matrix(path: &Path) -> Result<MountedWriteMatrix> {
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    parse_mounted_write_matrix(&text)
        .with_context(|| format!("invalid mounted write matrix {}", path.display()))
}

pub fn parse_mounted_write_matrix(text: &str) -> Result<MountedWriteMatrix> {
    serde_json::from_str(text).context("failed to parse mounted write matrix JSON")
}

pub fn validate_default_mounted_write_matrix() -> Result<MountedWriteMatrixReport> {
    let matrix = parse_mounted_write_matrix(DEFAULT_MATRIX_JSON)?;
    let report = validate_mounted_write_matrix(&matrix);
    fail_on_mounted_write_matrix_errors(&report)?;
    Ok(report)
}

#[must_use]
pub fn validate_mounted_write_matrix(matrix: &MountedWriteMatrix) -> MountedWriteMatrixReport {
    let mut errors = Vec::new();
    let mut scenario_ids = BTreeSet::new();
    let mut filesystems = BTreeSet::new();
    let mut operation_kinds = BTreeSet::new();
    let mut fsync_patterns = BTreeSet::new();
    let mut write_sizes = BTreeSet::new();
    let mut max_concurrency = 0_u32;

    validate_top_level(matrix, &mut errors);
    validate_result_contract(&matrix.results_contract, &mut errors);

    for scenario in &matrix.scenarios {
        validate_scenario(
            scenario,
            &mut scenario_ids,
            &mut filesystems,
            &mut operation_kinds,
            &mut fsync_patterns,
            &mut write_sizes,
            &mut max_concurrency,
            &mut errors,
        );
    }

    validate_coverage(
        &filesystems,
        &operation_kinds,
        &fsync_patterns,
        &write_sizes,
        max_concurrency,
        &mut errors,
    );

    MountedWriteMatrixReport {
        schema_version: matrix.schema_version,
        bead_id: matrix.bead_id.clone(),
        scenario_count: matrix.scenarios.len(),
        filesystems: filesystems.into_iter().collect(),
        operation_kinds: operation_kinds.into_iter().collect(),
        fsync_patterns: fsync_patterns.into_iter().collect(),
        output_formats: matrix.results_contract.formats.clone(),
        max_concurrency,
        write_sizes: write_sizes.into_iter().collect(),
        valid: errors.is_empty(),
        errors,
    }
}

fn validate_top_level(matrix: &MountedWriteMatrix, errors: &mut Vec<String>) {
    if matrix.schema_version != MATRIX_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version must be {MATRIX_SCHEMA_VERSION}, got {}",
            matrix.schema_version
        ));
    }
    if matrix.bead_id != "bd-rchk0.3.2" {
        errors.push(format!(
            "bead_id must be bd-rchk0.3.2, got {}",
            matrix.bead_id
        ));
    }
    if matrix.runner != "scripts/e2e/ffs_mounted_write_workload_matrix.sh" {
        errors.push(format!("unexpected runner {}", matrix.runner));
    }
    if matrix.scenarios.is_empty() {
        errors.push("matrix must contain at least one scenario".to_owned());
    }
}

fn validate_result_contract(contract: &ResultsContract, errors: &mut Vec<String>) {
    for required in REQUIRED_RESULT_FORMATS {
        if !contract.formats.iter().any(|format| format == required) {
            errors.push(format!("results_contract missing {required} format"));
        }
    }
    for required in [
        "scenario_id",
        "actual_outcome",
        "stdout_path",
        "stderr_path",
    ] {
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
    for required in [
        "mounted_write_workload_results.json",
        "mounted_write_workload_results.csv",
    ] {
        if !contract.artifact_paths.iter().any(|path| path == required) {
            errors.push(format!("results_contract missing artifact path {required}"));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_scenario(
    scenario: &MountedWriteScenario,
    scenario_ids: &mut BTreeSet<String>,
    filesystems: &mut BTreeSet<String>,
    operation_kinds: &mut BTreeSet<String>,
    fsync_patterns: &mut BTreeSet<String>,
    write_sizes: &mut BTreeSet<u64>,
    max_concurrency: &mut u32,
    errors: &mut Vec<String>,
) {
    if !scenario_ids.insert(scenario.scenario_id.clone()) {
        errors.push(format!("duplicate scenario_id {}", scenario.scenario_id));
    }
    if !scenario.scenario_id.starts_with("mounted_write_") {
        errors.push(format!(
            "scenario_id {} must start with mounted_write_",
            scenario.scenario_id
        ));
    }
    if !REQUIRED_FILESYSTEMS.contains(&scenario.filesystem.as_str()) {
        errors.push(format!(
            "scenario {} has unsupported filesystem {}",
            scenario.scenario_id, scenario.filesystem
        ));
    }
    filesystems.insert(scenario.filesystem.clone());
    if scenario.image_setup.trim().is_empty() {
        errors.push(format!(
            "scenario {} missing image_setup",
            scenario.scenario_id
        ));
    }
    if scenario.mount_flags.is_empty() {
        errors.push(format!(
            "scenario {} missing mount_flags",
            scenario.scenario_id
        ));
    }
    if scenario.fs_specific_options.is_empty() {
        errors.push(format!(
            "scenario {} missing fs_specific_options",
            scenario.scenario_id
        ));
    }
    validate_workload(
        scenario,
        operation_kinds,
        fsync_patterns,
        write_sizes,
        max_concurrency,
        errors,
    );
    validate_expected_outcome(scenario, errors);
}

fn validate_workload(
    scenario: &MountedWriteScenario,
    operation_kinds: &mut BTreeSet<String>,
    fsync_patterns: &mut BTreeSet<String>,
    write_sizes: &mut BTreeSet<u64>,
    max_concurrency: &mut u32,
    errors: &mut Vec<String>,
) {
    let workload = &scenario.workload;
    if workload.operation_sequence.is_empty() {
        errors.push(format!(
            "scenario {} must list operation_sequence",
            scenario.scenario_id
        ));
    }
    for operation in &workload.operation_sequence {
        operation_kinds.insert(operation.clone());
    }
    for operation in &workload.unsupported_operations {
        operation_kinds.insert(operation.clone());
    }
    if workload.write_sizes.is_empty() {
        errors.push(format!(
            "scenario {} missing write_sizes",
            scenario.scenario_id
        ));
    }
    for size in &workload.write_sizes {
        if *size == 0 {
            errors.push(format!(
                "scenario {} contains zero write size",
                scenario.scenario_id
            ));
        }
        write_sizes.insert(*size);
    }
    if !REQUIRED_FSYNC_PATTERNS.contains(&workload.fsync_pattern.as_str()) {
        errors.push(format!(
            "scenario {} has invalid fsync_pattern {}",
            scenario.scenario_id, workload.fsync_pattern
        ));
    }
    fsync_patterns.insert(workload.fsync_pattern.clone());
    if workload.concurrency == 0 {
        errors.push(format!(
            "scenario {} has zero concurrency",
            scenario.scenario_id
        ));
    }
    *max_concurrency = (*max_concurrency).max(workload.concurrency);
    if !workload.unsupported_operations.is_empty() && !workload.no_partial_mutation {
        errors.push(format!(
            "scenario {} has unsupported operations without no_partial_mutation",
            scenario.scenario_id
        ));
    }
}

fn validate_expected_outcome(scenario: &MountedWriteScenario, errors: &mut Vec<String>) {
    let outcome = &scenario.expected_outcome;
    if !["pass", "skip", "unsupported_rejected"].contains(&outcome.outcome_class.as_str()) {
        errors.push(format!(
            "scenario {} has invalid outcome_class {}",
            scenario.scenario_id, outcome.outcome_class
        ));
    }
    if outcome.detail.trim().is_empty() {
        errors.push(format!(
            "scenario {} missing outcome detail",
            scenario.scenario_id
        ));
    }
    if !scenario.workload.unsupported_operations.is_empty() {
        if outcome.outcome_class != "unsupported_rejected" {
            errors.push(format!(
                "scenario {} unsupported operations must expect unsupported_rejected",
                scenario.scenario_id
            ));
        }
        if !outcome.no_partial_mutation {
            errors.push(format!(
                "scenario {} unsupported operations need no_partial_mutation outcome",
                scenario.scenario_id
            ));
        }
        if !outcome.follow_up_bead.starts_with("bd-") {
            errors.push(format!(
                "scenario {} unsupported operation needs follow-up bead",
                scenario.scenario_id
            ));
        }
    }
}

fn validate_coverage(
    filesystems: &BTreeSet<String>,
    operation_kinds: &BTreeSet<String>,
    fsync_patterns: &BTreeSet<String>,
    write_sizes: &BTreeSet<u64>,
    max_concurrency: u32,
    errors: &mut Vec<String>,
) {
    for required in REQUIRED_FILESYSTEMS {
        if !filesystems.contains(required) {
            errors.push(format!("matrix missing filesystem {required}"));
        }
    }
    for required in REQUIRED_OPERATIONS {
        if !operation_kinds.contains(required) {
            errors.push(format!("matrix missing operation {required}"));
        }
    }
    if !operation_kinds.iter().any(|operation| {
        operation.contains("unsupported")
            || operation.contains("eacces")
            || operation.contains("mknod")
    }) {
        errors.push("matrix missing explicit unsupported-mode rejection".to_owned());
    }
    for required in REQUIRED_FSYNC_PATTERNS {
        if !fsync_patterns.contains(required) {
            errors.push(format!("matrix missing fsync pattern {required}"));
        }
    }
    for required in [4096_u64, 65_536, 1_048_576] {
        if !write_sizes.contains(&required) {
            errors.push(format!("matrix missing write size {required}"));
        }
    }
    if max_concurrency < 4 {
        errors.push(format!(
            "matrix max_concurrency {max_concurrency} is below 4"
        ));
    }
}

pub fn fail_on_mounted_write_matrix_errors(report: &MountedWriteMatrixReport) -> Result<()> {
    if report.valid {
        Ok(())
    } else {
        bail!(
            "mounted write matrix failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_matrix() -> MountedWriteMatrix {
        parse_mounted_write_matrix(DEFAULT_MATRIX_JSON).expect("default matrix parses")
    }

    #[test]
    fn default_matrix_validates_required_write_workload_contract() {
        let report = validate_default_mounted_write_matrix().expect("default matrix validates");
        assert_eq!(report.scenario_count, 8);
        assert_eq!(report.filesystems, vec!["btrfs", "ext4"]);
        assert!(
            report
                .operation_kinds
                .contains(&"fallocate_keep_size".to_owned())
        );
        assert!(report.operation_kinds.contains(&"xattr_set_get".to_owned()));
        assert!(report.output_formats.contains(&"json".to_owned()));
        assert!(report.output_formats.contains(&"csv".to_owned()));
        assert!(report.max_concurrency >= 4);
    }

    #[test]
    fn result_contract_requires_csv_and_json() {
        let mut matrix = valid_matrix();
        matrix
            .results_contract
            .formats
            .retain(|format| format != "csv");
        let report = validate_mounted_write_matrix(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("csv format"))
        );
    }

    #[test]
    fn unsupported_operations_require_no_partial_mutation() {
        let mut matrix = valid_matrix();
        let scenario = matrix
            .scenarios
            .iter_mut()
            .find(|scenario| !scenario.workload.unsupported_operations.is_empty())
            .expect("unsupported scenario exists");
        scenario.workload.no_partial_mutation = false;
        scenario.expected_outcome.no_partial_mutation = false;
        let report = validate_mounted_write_matrix(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("no_partial_mutation"))
        );
    }

    #[test]
    fn required_operation_coverage_is_enforced() {
        let mut matrix = valid_matrix();
        for scenario in &mut matrix.scenarios {
            scenario
                .workload
                .operation_sequence
                .retain(|operation| operation != "xattr_set_get");
        }
        let report = validate_mounted_write_matrix(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("xattr_set_get"))
        );
    }

    #[test]
    fn duplicate_scenario_ids_are_rejected() {
        let mut matrix = valid_matrix();
        let duplicate = matrix.scenarios[0].scenario_id.clone();
        matrix.scenarios[1].scenario_id = duplicate;
        let report = validate_mounted_write_matrix(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("duplicate scenario_id"))
        );
    }
}
