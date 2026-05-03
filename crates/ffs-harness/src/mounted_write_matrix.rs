#![forbid(unsafe_code)]

//! Mounted write workload matrix validation for `bd-rchk0.3.2`.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub const MATRIX_SCHEMA_VERSION: u32 = 3;
pub const DEFAULT_MATRIX_PATH: &str = "tests/workload-matrix/mounted_write_workload_matrix.json";
const DEFAULT_MATRIX_JSON: &str =
    include_str!("../../../tests/workload-matrix/mounted_write_workload_matrix.json");

const REQUIRED_FILESYSTEMS: [&str; 2] = ["ext4", "btrfs"];
const REQUIRED_OPERATIONS: [&str; 19] = [
    "create",
    "mkdir",
    "unlink",
    "rmdir",
    "rename",
    "write_readback",
    "setattr",
    "hardlink",
    "symlink",
    "xattr_set_get",
    "xattr_create",
    "xattr_replace",
    "xattr_list_get",
    "fallocate_keep_size",
    "fallocate_zero_range",
    "fallocate_punch_hole",
    "read_only_write_erofs",
    "rw_repair_rejected_before_serialization",
    "host_capability_skip",
];
const REQUIRED_FSYNC_PATTERNS: [&str; 4] = ["every_write", "metadata_only", "final_only", "none"];
const REQUIRED_RESULT_FORMATS: [&str; 2] = ["json", "csv"];

const REQUIRED_MULTI_HANDLE_KINDS: [&str; 6] = [
    "two_handle_read_after_write",
    "open_unlink",
    "rename_while_open",
    "truncate_while_open",
    "metadata_attr_while_open",
    "xattr_visibility",
];

const ALLOWED_MULTI_HANDLE_KINDS: [&str; 9] = [
    "two_handle_read_after_write",
    "open_unlink",
    "rename_while_open",
    "truncate_while_open",
    "metadata_attr_while_open",
    "xattr_visibility",
    "readdir_after_mutation",
    "symlink_read_after_rename",
    "rejected_op_no_partial_mutation",
];

const ALLOWED_HANDLE_OPEN_FLAGS: [&str; 8] = [
    "O_RDONLY",
    "O_WRONLY",
    "O_RDWR",
    "O_APPEND",
    "O_DIRECTORY",
    "O_NOFOLLOW",
    "O_PATH",
    "O_TRUNC",
];

const ALLOWED_REOPEN_KINDS: [&str; 4] = ["none", "close_open", "remount", "image_reopen"];

const ALLOWED_CLEANUP_POLICIES: [&str; 3] = [
    "teardown_image",
    "preserve_artifacts_on_failure",
    "preserve_artifacts_always",
];

const REQUIRED_MULTI_HANDLE_ARTIFACTS: [&str; 4] = [
    "scenario_id",
    "operation_trace_path",
    "expected_visibility",
    "observed_visibility",
];

const REQUIRED_MULTI_HANDLE_RESULT_FIELDS: [&str; 6] = [
    "scenario_id",
    "handle_ids",
    "operation_trace",
    "expected_visibility",
    "observed_visibility",
    "reopen_state",
];

const REQUIRED_MULTI_HANDLE_RESULT_ARTIFACTS: [&str; 1] = ["mounted_multihandle_results.json"];

const REQUIRED_SCENARIO_PROOF_CLASSES: [&str; 5] = [
    "positive",
    "refusal",
    "crash_reopen",
    "no_partial_mutation",
    "host_skip",
];

const ALLOWED_SCENARIO_PROOF_CLASSES: [&str; 5] = [
    "positive",
    "refusal",
    "crash_reopen",
    "no_partial_mutation",
    "host_skip",
];

const ALLOWED_ERROR_CLASSES: [&str; 6] = [
    "none",
    "EACCES",
    "EOPNOTSUPP",
    "EPERM",
    "EROFS",
    "HOST_CAPABILITY_SKIP",
];

const REQUIRED_SCENARIO_PROOF_ARTIFACTS: [&str; 7] = [
    "scenario_id",
    "image_fixture_hash",
    "operation_trace_path",
    "expected_survivor_set",
    "expected_error_class",
    "reopen_state",
    "cleanup_status",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedWriteMatrix {
    pub schema_version: u32,
    pub bead_id: String,
    pub runner: String,
    pub results_contract: ResultsContract,
    pub scenarios: Vec<MountedWriteScenario>,
    #[serde(default)]
    pub multi_handle_scenarios: Vec<MultiHandleScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiHandleScenario {
    pub scenario_id: String,
    pub kind: String,
    pub filesystem: String,
    pub image_setup: String,
    pub mount_flags: Vec<String>,
    pub fs_specific_options: Vec<String>,
    pub handles: Vec<HandleSpec>,
    pub operation_trace: Vec<HandleOperation>,
    pub cache_visibility: CacheVisibility,
    pub reopen: ReopenExpectation,
    pub survivor_set: SurvivorSet,
    pub cleanup_policy: String,
    pub artifact_requirements: Vec<String>,
    pub expected_outcome: MultiHandleOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleSpec {
    pub handle_id: String,
    pub purpose: String,
    pub open_flags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleOperation {
    pub step: u32,
    pub handle_id: String,
    pub op: String,
    pub args: Vec<String>,
    pub expected_result: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheVisibility {
    pub other_handle_state: String,
    pub stat_must_match: bool,
    pub data_must_match: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReopenExpectation {
    pub kind: String,
    pub expected_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurvivorSet {
    pub present_paths: Vec<String>,
    pub absent_paths: Vec<String>,
    pub xattr_state: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiHandleOutcome {
    pub outcome_class: String,
    pub no_partial_mutation: bool,
    pub follow_up_bead: String,
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
    pub proof: ScenarioProof,
    pub expected_outcome: ExpectedOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioProof {
    pub scenario_class: String,
    pub image_fixture_hash: String,
    pub expected_survivor_set: SurvivorSet,
    pub expected_error_class: String,
    pub required_cleanup: String,
    pub reopen: ReopenExpectation,
    pub artifact_requirements: Vec<String>,
    pub remediation_id: String,
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
    pub scenario_classes: Vec<String>,
    pub expected_error_classes: Vec<String>,
    pub no_partial_mutation_scenarios: usize,
    pub multi_handle_scenario_count: usize,
    pub multi_handle_kinds: Vec<String>,
    pub multi_handle_filesystems: Vec<String>,
    pub multi_handle_max_handles: u32,
    pub multi_handle_unsupported_count: usize,
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
    let mut scenario_classes = BTreeSet::new();
    let mut expected_error_classes = BTreeSet::new();
    let mut no_partial_mutation_scenarios = 0_usize;
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
            &mut scenario_classes,
            &mut expected_error_classes,
            &mut no_partial_mutation_scenarios,
            &mut max_concurrency,
            &mut errors,
        );
    }

    validate_coverage(
        &filesystems,
        &operation_kinds,
        &fsync_patterns,
        &write_sizes,
        &scenario_classes,
        max_concurrency,
        &mut errors,
    );

    let mut multi_handle_kinds = BTreeSet::new();
    let mut multi_handle_filesystems = BTreeSet::new();
    let mut multi_handle_max_handles = 0_u32;
    let mut multi_handle_unsupported_count = 0_usize;

    for scenario in &matrix.multi_handle_scenarios {
        validate_multi_handle_scenario(
            scenario,
            &mut scenario_ids,
            &mut multi_handle_kinds,
            &mut multi_handle_filesystems,
            &mut multi_handle_max_handles,
            &mut multi_handle_unsupported_count,
            &mut errors,
        );
    }

    validate_multi_handle_coverage(
        &matrix.multi_handle_scenarios,
        &multi_handle_kinds,
        &multi_handle_filesystems,
        multi_handle_unsupported_count,
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
        scenario_classes: scenario_classes.into_iter().collect(),
        expected_error_classes: expected_error_classes.into_iter().collect(),
        no_partial_mutation_scenarios,
        multi_handle_scenario_count: matrix.multi_handle_scenarios.len(),
        multi_handle_kinds: multi_handle_kinds.into_iter().collect(),
        multi_handle_filesystems: multi_handle_filesystems.into_iter().collect(),
        multi_handle_max_handles,
        multi_handle_unsupported_count,
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
        "scenario_class",
        "image_fixture_hash",
        "expected_survivor_set",
        "expected_error_class",
        "reopen_state",
        "artifact_paths",
        "remediation_id",
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
    for required in REQUIRED_MULTI_HANDLE_RESULT_FIELDS {
        if !contract
            .required_fields
            .iter()
            .any(|field| field == required)
        {
            errors.push(format!(
                "results_contract missing multi-handle required field {required}"
            ));
        }
    }
    for required in REQUIRED_MULTI_HANDLE_RESULT_ARTIFACTS {
        if !contract.artifact_paths.iter().any(|path| path == required) {
            errors.push(format!(
                "results_contract missing multi-handle artifact path {required}"
            ));
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
    scenario_classes: &mut BTreeSet<String>,
    expected_error_classes: &mut BTreeSet<String>,
    no_partial_mutation_scenarios: &mut usize,
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
    validate_scenario_proof(
        scenario,
        scenario_classes,
        expected_error_classes,
        no_partial_mutation_scenarios,
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
    if scenario.proof.expected_error_class != "none"
        && !["skip", "unsupported_rejected"].contains(&outcome.outcome_class.as_str())
    {
        errors.push(format!(
            "scenario {} declares expected_error_class {} but outcome_class {} is not skip or unsupported_rejected",
            scenario.scenario_id, scenario.proof.expected_error_class, outcome.outcome_class
        ));
    }
    if scenario.proof.scenario_class == "host_skip" && outcome.outcome_class != "skip" {
        errors.push(format!(
            "scenario {} host_skip proof class must expect skip",
            scenario.scenario_id
        ));
    }
}

fn validate_scenario_proof(
    scenario: &MountedWriteScenario,
    scenario_classes: &mut BTreeSet<String>,
    expected_error_classes: &mut BTreeSet<String>,
    no_partial_mutation_scenarios: &mut usize,
    errors: &mut Vec<String>,
) {
    let proof = &scenario.proof;
    if !ALLOWED_SCENARIO_PROOF_CLASSES.contains(&proof.scenario_class.as_str()) {
        errors.push(format!(
            "scenario {} has unsupported proof scenario_class {}",
            scenario.scenario_id, proof.scenario_class
        ));
    }
    scenario_classes.insert(proof.scenario_class.clone());
    if !is_sha256_fixture_hash(&proof.image_fixture_hash) {
        errors.push(format!(
            "scenario {} image_fixture_hash must be sha256:<64 lowercase hex chars>",
            scenario.scenario_id
        ));
    }
    if !ALLOWED_ERROR_CLASSES.contains(&proof.expected_error_class.as_str()) {
        errors.push(format!(
            "scenario {} has unsupported expected_error_class {}",
            scenario.scenario_id, proof.expected_error_class
        ));
    }
    expected_error_classes.insert(proof.expected_error_class.clone());
    if !ALLOWED_CLEANUP_POLICIES.contains(&proof.required_cleanup.as_str()) {
        errors.push(format!(
            "scenario {} has unsupported required_cleanup {}",
            scenario.scenario_id, proof.required_cleanup
        ));
    }
    if !ALLOWED_REOPEN_KINDS.contains(&proof.reopen.kind.as_str()) {
        errors.push(format!(
            "scenario {} has unsupported proof reopen.kind {}",
            scenario.scenario_id, proof.reopen.kind
        ));
    }
    if proof.reopen.expected_state.trim().is_empty() {
        errors.push(format!(
            "scenario {} missing proof reopen.expected_state",
            scenario.scenario_id
        ));
    }
    if proof.expected_survivor_set.present_paths.is_empty()
        && proof.expected_survivor_set.absent_paths.is_empty()
    {
        errors.push(format!(
            "scenario {} proof expected_survivor_set must declare at least one present or absent path",
            scenario.scenario_id
        ));
    }
    for required in REQUIRED_SCENARIO_PROOF_ARTIFACTS {
        if !proof
            .artifact_requirements
            .iter()
            .any(|requirement| requirement == required)
        {
            errors.push(format!(
                "scenario {} proof artifact_requirements missing {}",
                scenario.scenario_id, required
            ));
        }
    }
    if proof.scenario_class == "refusal" || proof.scenario_class == "no_partial_mutation" {
        *no_partial_mutation_scenarios += 1;
        if proof.expected_error_class == "none" {
            errors.push(format!(
                "scenario {} refusal/no_partial_mutation proof must declare a concrete expected_error_class",
                scenario.scenario_id
            ));
        }
        if !scenario.workload.no_partial_mutation || !scenario.expected_outcome.no_partial_mutation
        {
            errors.push(format!(
                "scenario {} refusal/no_partial_mutation proof must set no_partial_mutation in workload and outcome",
                scenario.scenario_id
            ));
        }
        if !proof.remediation_id.starts_with("bd-") {
            errors.push(format!(
                "scenario {} refusal/no_partial_mutation proof needs remediation_id starting with bd-",
                scenario.scenario_id
            ));
        }
    }
    if proof.scenario_class == "host_skip" {
        if proof.expected_error_class != "HOST_CAPABILITY_SKIP" {
            errors.push(format!(
                "scenario {} host_skip proof must use HOST_CAPABILITY_SKIP expected_error_class",
                scenario.scenario_id
            ));
        }
        if proof.remediation_id.trim().is_empty() {
            errors.push(format!(
                "scenario {} host_skip proof must declare remediation_id",
                scenario.scenario_id
            ));
        }
    }
}

fn is_sha256_fixture_hash(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_coverage(
    filesystems: &BTreeSet<String>,
    operation_kinds: &BTreeSet<String>,
    fsync_patterns: &BTreeSet<String>,
    write_sizes: &BTreeSet<u64>,
    scenario_classes: &BTreeSet<String>,
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
    for required in REQUIRED_SCENARIO_PROOF_CLASSES {
        if !scenario_classes.contains(required) {
            errors.push(format!("matrix missing scenario proof class {required}"));
        }
    }
    if max_concurrency < 4 {
        errors.push(format!(
            "matrix max_concurrency {max_concurrency} is below 4"
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_multi_handle_scenario(
    scenario: &MultiHandleScenario,
    scenario_ids: &mut BTreeSet<String>,
    multi_handle_kinds: &mut BTreeSet<String>,
    multi_handle_filesystems: &mut BTreeSet<String>,
    multi_handle_max_handles: &mut u32,
    multi_handle_unsupported_count: &mut usize,
    errors: &mut Vec<String>,
) {
    validate_multi_handle_identity(scenario, scenario_ids, multi_handle_kinds, errors);
    validate_multi_handle_environment(scenario, multi_handle_filesystems, errors);
    let handle_ids = validate_multi_handle_handles(scenario, multi_handle_max_handles, errors);
    validate_multi_handle_operation_trace(scenario, &handle_ids, errors);
    validate_multi_handle_expectations(scenario, errors);
    validate_multi_handle_outcome(scenario, multi_handle_unsupported_count, errors);
}

fn validate_multi_handle_identity(
    scenario: &MultiHandleScenario,
    scenario_ids: &mut BTreeSet<String>,
    multi_handle_kinds: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    if !scenario_ids.insert(scenario.scenario_id.clone()) {
        errors.push(format!("duplicate scenario_id {}", scenario.scenario_id));
    }
    if !scenario
        .scenario_id
        .starts_with("mounted_write_multihandle_")
    {
        errors.push(format!(
            "multi-handle scenario_id {} must start with mounted_write_multihandle_",
            scenario.scenario_id
        ));
    }
    if !ALLOWED_MULTI_HANDLE_KINDS.contains(&scenario.kind.as_str()) {
        errors.push(format!(
            "multi-handle scenario {} has unsupported kind {}",
            scenario.scenario_id, scenario.kind
        ));
    }
    multi_handle_kinds.insert(scenario.kind.clone());
}

fn validate_multi_handle_environment(
    scenario: &MultiHandleScenario,
    multi_handle_filesystems: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    if !REQUIRED_FILESYSTEMS.contains(&scenario.filesystem.as_str()) {
        errors.push(format!(
            "multi-handle scenario {} has unsupported filesystem {}",
            scenario.scenario_id, scenario.filesystem
        ));
    }
    multi_handle_filesystems.insert(scenario.filesystem.clone());
    if scenario.image_setup.trim().is_empty() {
        errors.push(format!(
            "multi-handle scenario {} missing image_setup",
            scenario.scenario_id
        ));
    }
    if scenario.mount_flags.is_empty() {
        errors.push(format!(
            "multi-handle scenario {} missing mount_flags",
            scenario.scenario_id
        ));
    }
    if scenario.fs_specific_options.is_empty() {
        errors.push(format!(
            "multi-handle scenario {} missing fs_specific_options",
            scenario.scenario_id
        ));
    }
}

fn validate_multi_handle_handles(
    scenario: &MultiHandleScenario,
    multi_handle_max_handles: &mut u32,
    errors: &mut Vec<String>,
) -> BTreeSet<String> {
    if scenario.handles.len() < 2 {
        errors.push(format!(
            "multi-handle scenario {} must declare at least two handles",
            scenario.scenario_id
        ));
    }
    let mut handle_ids = BTreeSet::new();
    for handle in &scenario.handles {
        if handle.handle_id.trim().is_empty() {
            errors.push(format!(
                "multi-handle scenario {} has handle with empty handle_id",
                scenario.scenario_id
            ));
        }
        if !handle_ids.insert(handle.handle_id.clone()) {
            errors.push(format!(
                "multi-handle scenario {} has duplicate handle_id {}",
                scenario.scenario_id, handle.handle_id
            ));
        }
        if handle.purpose.trim().is_empty() {
            errors.push(format!(
                "multi-handle scenario {} handle {} missing purpose",
                scenario.scenario_id, handle.handle_id
            ));
        }
        if handle.open_flags.is_empty() {
            errors.push(format!(
                "multi-handle scenario {} handle {} missing open_flags",
                scenario.scenario_id, handle.handle_id
            ));
        }
        for flag in &handle.open_flags {
            if !ALLOWED_HANDLE_OPEN_FLAGS.contains(&flag.as_str()) {
                errors.push(format!(
                    "multi-handle scenario {} handle {} has unsupported open_flag {}",
                    scenario.scenario_id, handle.handle_id, flag
                ));
            }
        }
    }
    let handle_count = u32::try_from(scenario.handles.len()).unwrap_or(u32::MAX);
    if handle_count > *multi_handle_max_handles {
        *multi_handle_max_handles = handle_count;
    }
    handle_ids
}

fn validate_multi_handle_operation_trace(
    scenario: &MultiHandleScenario,
    handle_ids: &BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    if scenario.operation_trace.is_empty() {
        errors.push(format!(
            "multi-handle scenario {} missing operation_trace",
            scenario.scenario_id
        ));
    }
    let mut last_step = 0_u32;
    let mut steps_seen = BTreeSet::new();
    for op in &scenario.operation_trace {
        if !steps_seen.insert(op.step) {
            errors.push(format!(
                "multi-handle scenario {} operation_trace has duplicate step {}",
                scenario.scenario_id, op.step
            ));
        }
        if op.step <= last_step && last_step != 0 {
            errors.push(format!(
                "multi-handle scenario {} operation_trace steps must be strictly increasing (saw {} after {})",
                scenario.scenario_id, op.step, last_step
            ));
        }
        last_step = op.step;
        if !handle_ids.contains(&op.handle_id) {
            errors.push(format!(
                "multi-handle scenario {} operation_trace references unknown handle {}",
                scenario.scenario_id, op.handle_id
            ));
        }
        if op.op.trim().is_empty() {
            errors.push(format!(
                "multi-handle scenario {} step {} missing op",
                scenario.scenario_id, op.step
            ));
        }
        if op.expected_result.trim().is_empty() {
            errors.push(format!(
                "multi-handle scenario {} step {} missing expected_result",
                scenario.scenario_id, op.step
            ));
        }
    }
}

fn validate_multi_handle_expectations(scenario: &MultiHandleScenario, errors: &mut Vec<String>) {
    if scenario
        .cache_visibility
        .other_handle_state
        .trim()
        .is_empty()
    {
        errors.push(format!(
            "multi-handle scenario {} missing cache_visibility.other_handle_state",
            scenario.scenario_id
        ));
    }
    if !ALLOWED_REOPEN_KINDS.contains(&scenario.reopen.kind.as_str()) {
        errors.push(format!(
            "multi-handle scenario {} has unsupported reopen.kind {}",
            scenario.scenario_id, scenario.reopen.kind
        ));
    }
    if scenario.reopen.expected_state.trim().is_empty() {
        errors.push(format!(
            "multi-handle scenario {} missing reopen.expected_state",
            scenario.scenario_id
        ));
    }
    if scenario.survivor_set.present_paths.is_empty()
        && scenario.survivor_set.absent_paths.is_empty()
    {
        errors.push(format!(
            "multi-handle scenario {} survivor_set must declare at least one present or absent path",
            scenario.scenario_id
        ));
    }
    if !ALLOWED_CLEANUP_POLICIES.contains(&scenario.cleanup_policy.as_str()) {
        errors.push(format!(
            "multi-handle scenario {} has unsupported cleanup_policy {}",
            scenario.scenario_id, scenario.cleanup_policy
        ));
    }
    for required in REQUIRED_MULTI_HANDLE_ARTIFACTS {
        if !scenario
            .artifact_requirements
            .iter()
            .any(|requirement| requirement == required)
        {
            errors.push(format!(
                "multi-handle scenario {} artifact_requirements missing {}",
                scenario.scenario_id, required
            ));
        }
    }
}

fn validate_multi_handle_outcome(
    scenario: &MultiHandleScenario,
    multi_handle_unsupported_count: &mut usize,
    errors: &mut Vec<String>,
) {
    if !["pass", "skip", "unsupported_rejected"]
        .contains(&scenario.expected_outcome.outcome_class.as_str())
    {
        errors.push(format!(
            "multi-handle scenario {} has invalid outcome_class {}",
            scenario.scenario_id, scenario.expected_outcome.outcome_class
        ));
    }
    if scenario.expected_outcome.outcome_class == "unsupported_rejected" {
        *multi_handle_unsupported_count += 1;
        if !scenario.expected_outcome.no_partial_mutation {
            errors.push(format!(
                "multi-handle scenario {} unsupported_rejected outcome must guarantee no_partial_mutation",
                scenario.scenario_id
            ));
        }
        if !scenario.expected_outcome.follow_up_bead.starts_with("bd-") {
            errors.push(format!(
                "multi-handle scenario {} unsupported_rejected outcome needs follow_up_bead starting with bd-",
                scenario.scenario_id
            ));
        }
    }
}

fn validate_multi_handle_coverage(
    scenarios: &[MultiHandleScenario],
    kinds: &BTreeSet<String>,
    filesystems: &BTreeSet<String>,
    unsupported_count: usize,
    errors: &mut Vec<String>,
) {
    if scenarios.is_empty() {
        errors.push(
            "matrix must declare multi_handle_scenarios; rw readiness cannot rely on single-handle status codes alone".to_owned(),
        );
        return;
    }
    for required in REQUIRED_MULTI_HANDLE_KINDS {
        if !kinds.contains(required) {
            errors.push(format!(
                "multi_handle_scenarios missing required kind {required}"
            ));
        }
    }
    for required in REQUIRED_FILESYSTEMS {
        if !filesystems.contains(required) {
            errors.push(format!(
                "multi_handle_scenarios missing filesystem {required}"
            ));
        }
    }
    if unsupported_count == 0 {
        errors.push(
            "multi_handle_scenarios must include at least one rejected operation that proves no partial mutation"
                .to_owned(),
        );
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
        assert_eq!(report.scenario_count, 13);
        assert_eq!(report.filesystems, vec!["btrfs", "ext4"]);
        assert!(report
            .operation_kinds
            .contains(&"fallocate_keep_size".to_owned()));
        assert!(report
            .operation_kinds
            .contains(&"fallocate_zero_range".to_owned()));
        assert!(report
            .operation_kinds
            .contains(&"fallocate_punch_hole".to_owned()));
        assert!(report.operation_kinds.contains(&"xattr_set_get".to_owned()));
        assert!(report.operation_kinds.contains(&"xattr_create".to_owned()));
        assert!(report.operation_kinds.contains(&"xattr_replace".to_owned()));
        assert!(report
            .operation_kinds
            .contains(&"xattr_list_get".to_owned()));
        assert!(report
            .operation_kinds
            .contains(&"read_only_write_erofs".to_owned()));
        assert!(report
            .operation_kinds
            .contains(&"rw_repair_rejected_before_serialization".to_owned()));
        assert!(report
            .operation_kinds
            .contains(&"host_capability_skip".to_owned()));
        for scenario_class in REQUIRED_SCENARIO_PROOF_CLASSES {
            assert!(
                report.scenario_classes.contains(&scenario_class.to_owned()),
                "missing proof class {scenario_class}"
            );
        }
        assert!(report.expected_error_classes.contains(&"EROFS".to_owned()));
        assert!(report
            .expected_error_classes
            .contains(&"HOST_CAPABILITY_SKIP".to_owned()));
        assert!(report.no_partial_mutation_scenarios >= 3);
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
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("csv format")));
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
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("no_partial_mutation")));
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
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("xattr_set_get")));
    }

    #[test]
    fn result_contract_requires_proof_fields() {
        let mut matrix = valid_matrix();
        matrix
            .results_contract
            .required_fields
            .retain(|field| field != "expected_error_class");
        let report = validate_mounted_write_matrix(&matrix);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("required field expected_error_class")));
    }

    #[test]
    fn scenario_proof_hash_must_be_lowercase_sha256() {
        let mut matrix = valid_matrix();
        matrix.scenarios[0].proof.image_fixture_hash =
            "sha256:ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_owned();
        let report = validate_mounted_write_matrix(&matrix);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("image_fixture_hash")));
    }

    #[test]
    fn scenario_proof_survivor_set_must_not_be_empty() {
        let mut matrix = valid_matrix();
        matrix.scenarios[0]
            .proof
            .expected_survivor_set
            .present_paths
            .clear();
        matrix.scenarios[0]
            .proof
            .expected_survivor_set
            .absent_paths
            .clear();
        let report = validate_mounted_write_matrix(&matrix);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("expected_survivor_set")));
    }

    #[test]
    fn scenario_proof_artifact_requirements_are_required() {
        let mut matrix = valid_matrix();
        matrix.scenarios[0]
            .proof
            .artifact_requirements
            .retain(|requirement| requirement != "reopen_state");
        let report = validate_mounted_write_matrix(&matrix);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("artifact_requirements missing reopen_state")));
    }

    #[test]
    fn required_host_skip_proof_class_is_enforced() {
        let mut matrix = valid_matrix();
        matrix
            .scenarios
            .retain(|scenario| scenario.proof.scenario_class != "host_skip");
        let report = validate_mounted_write_matrix(&matrix);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("matrix missing scenario proof class host_skip")));
    }

    #[test]
    fn duplicate_scenario_ids_are_rejected() {
        let mut matrix = valid_matrix();
        let duplicate = matrix.scenarios[0].scenario_id.clone();
        matrix.scenarios[1].scenario_id = duplicate;
        let report = validate_mounted_write_matrix(&matrix);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("duplicate scenario_id")));
    }

    #[test]
    fn default_matrix_carries_required_multi_handle_coverage() {
        let report = validate_default_mounted_write_matrix().expect("default matrix validates");
        assert_eq!(report.schema_version, MATRIX_SCHEMA_VERSION);
        assert!(
            report.multi_handle_scenario_count >= REQUIRED_MULTI_HANDLE_KINDS.len(),
            "need at least one scenario per required kind, got {}",
            report.multi_handle_scenario_count
        );
        for kind in REQUIRED_MULTI_HANDLE_KINDS {
            assert!(
                report.multi_handle_kinds.iter().any(|k| k == kind),
                "missing multi-handle kind {kind}"
            );
        }
        assert_eq!(report.multi_handle_filesystems, vec!["btrfs", "ext4"]);
        assert!(report.multi_handle_max_handles >= 2);
        assert!(report.multi_handle_unsupported_count >= 1);
    }

    #[test]
    fn empty_multi_handle_scenarios_are_rejected() {
        let mut matrix = valid_matrix();
        matrix.multi_handle_scenarios.clear();
        let report = validate_mounted_write_matrix(&matrix);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("multi_handle_scenarios")));
    }

    fn first_multi_handle_scenario(matrix: &mut MountedWriteMatrix) -> &mut MultiHandleScenario {
        matrix
            .multi_handle_scenarios
            .first_mut()
            .expect("at least one multi-handle scenario in fixture")
    }

    #[test]
    fn multi_handle_scenario_must_have_at_least_two_handles() {
        let mut matrix = valid_matrix();
        let scenario = first_multi_handle_scenario(&mut matrix);
        scenario.handles.truncate(1);
        let report = validate_mounted_write_matrix(&matrix);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("at least two handles")));
    }

    #[test]
    fn multi_handle_scenario_id_prefix_is_enforced() {
        let mut matrix = valid_matrix();
        let scenario = first_multi_handle_scenario(&mut matrix);
        scenario.scenario_id = "mounted_write_does_not_match".to_owned();
        let report = validate_mounted_write_matrix(&matrix);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("must start with mounted_write_multihandle_")));
    }

    #[test]
    fn multi_handle_operation_must_reference_known_handle() {
        let mut matrix = valid_matrix();
        let scenario = first_multi_handle_scenario(&mut matrix);
        scenario.operation_trace[0].handle_id = "h_unknown".to_owned();
        let report = validate_mounted_write_matrix(&matrix);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("references unknown handle")));
    }

    #[test]
    fn multi_handle_operation_steps_must_strictly_increase() {
        let mut matrix = valid_matrix();
        let scenario = first_multi_handle_scenario(&mut matrix);
        assert!(scenario.operation_trace.len() >= 2);
        scenario.operation_trace[1].step = scenario.operation_trace[0].step;
        let report = validate_mounted_write_matrix(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("duplicate step")
                    || error.contains("strictly increasing"))
        );
    }

    #[test]
    fn multi_handle_open_flags_are_validated() {
        let mut matrix = valid_matrix();
        let scenario = first_multi_handle_scenario(&mut matrix);
        scenario.handles[0].open_flags = vec!["O_BANANA".to_owned()];
        let report = validate_mounted_write_matrix(&matrix);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("unsupported open_flag")));
    }

    #[test]
    fn multi_handle_reopen_kind_is_validated() {
        let mut matrix = valid_matrix();
        let scenario = first_multi_handle_scenario(&mut matrix);
        scenario.reopen.kind = "remount_lazy_unsupported".to_owned();
        let report = validate_mounted_write_matrix(&matrix);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("unsupported reopen.kind")));
    }

    #[test]
    fn multi_handle_cleanup_policy_is_validated() {
        let mut matrix = valid_matrix();
        let scenario = first_multi_handle_scenario(&mut matrix);
        scenario.cleanup_policy = "abandon".to_owned();
        let report = validate_mounted_write_matrix(&matrix);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("unsupported cleanup_policy")));
    }

    #[test]
    fn multi_handle_artifact_requirements_are_required() {
        let mut matrix = valid_matrix();
        let scenario = first_multi_handle_scenario(&mut matrix);
        scenario.artifact_requirements.clear();
        let report = validate_mounted_write_matrix(&matrix);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("artifact_requirements missing")));
    }

    #[test]
    fn multi_handle_unsupported_outcome_requires_follow_up_bead() {
        let mut matrix = valid_matrix();
        let scenario = matrix
            .multi_handle_scenarios
            .iter_mut()
            .find(|s| s.expected_outcome.outcome_class == "unsupported_rejected")
            .expect("rejected multi-handle scenario in fixture");
        scenario.expected_outcome.follow_up_bead = String::new();
        let report = validate_mounted_write_matrix(&matrix);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("follow_up_bead")));
    }

    #[test]
    fn multi_handle_unsupported_outcome_requires_no_partial_mutation() {
        let mut matrix = valid_matrix();
        let scenario = matrix
            .multi_handle_scenarios
            .iter_mut()
            .find(|s| s.expected_outcome.outcome_class == "unsupported_rejected")
            .expect("rejected multi-handle scenario in fixture");
        scenario.expected_outcome.no_partial_mutation = false;
        let report = validate_mounted_write_matrix(&matrix);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("must guarantee no_partial_mutation")));
    }

    #[test]
    fn multi_handle_required_kinds_are_enforced() {
        let mut matrix = valid_matrix();
        matrix
            .multi_handle_scenarios
            .retain(|s| s.kind != "open_unlink");
        let report = validate_mounted_write_matrix(&matrix);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("missing required kind open_unlink")));
    }

    #[test]
    fn multi_handle_results_contract_requires_handle_fields() {
        let mut matrix = valid_matrix();
        matrix
            .results_contract
            .required_fields
            .retain(|field| field != "handle_ids");
        let report = validate_mounted_write_matrix(&matrix);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("multi-handle required field handle_ids")));
    }

    #[test]
    fn multi_handle_results_contract_requires_artifact_path() {
        let mut matrix = valid_matrix();
        matrix
            .results_contract
            .artifact_paths
            .retain(|path| path != "mounted_multihandle_results.json");
        let report = validate_mounted_write_matrix(&matrix);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("multi-handle artifact path")));
    }

    #[test]
    fn multi_handle_duplicate_handle_id_is_rejected() {
        let mut matrix = valid_matrix();
        let scenario = first_multi_handle_scenario(&mut matrix);
        let dup = scenario.handles[0].handle_id.clone();
        scenario.handles[1].handle_id = dup;
        let report = validate_mounted_write_matrix(&matrix);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("duplicate handle_id")));
    }

    #[test]
    fn multi_handle_survivor_set_must_not_be_empty() {
        let mut matrix = valid_matrix();
        let scenario = first_multi_handle_scenario(&mut matrix);
        scenario.survivor_set.present_paths.clear();
        scenario.survivor_set.absent_paths.clear();
        let report = validate_mounted_write_matrix(&matrix);
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("survivor_set")));
    }
}
