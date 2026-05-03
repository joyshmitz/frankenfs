#![allow(clippy::module_name_repetitions)]

//! Replayable invariant-oracle trace validation for `bd-rchk0.5.1.1`.
//!
//! This module intentionally models externally meaningful filesystem state:
//! paths, file sizes, durable paths, operation ordering, and structured failure
//! evidence. It is not a parallel implementation of FrankenFS internals.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub const INVARIANT_ORACLE_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_INVARIANT_ORACLE_ARTIFACT: &str = "artifacts/invariant/oracle_report.json";
pub const INVARIANT_ORACLE_REPRODUCTION_COMMAND: &str = "ffs-harness validate-invariant-oracle --trace artifacts/invariant/trace.json --out artifacts/invariant/oracle_report.json";

const ROOT_PATH: &str = "/";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantTrace {
    pub schema_version: u32,
    pub trace_id: String,
    pub seed: u64,
    pub reproduction_command: String,
    pub operations: Vec<InvariantTraceOperation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantTraceOperation {
    pub operation_id: String,
    pub operation_index: usize,
    pub action: InvariantAction,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_written: Option<u64>,
    pub precondition: String,
    pub expected_model_delta: String,
    pub observed_subsystem_event: String,
    #[serde(default)]
    pub artifact_refs: Vec<String>,
    pub expected_state: InvariantModelState,
    pub observed_state: InvariantModelState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_violation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_class: Option<InvariantFailureClass>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantAction {
    CreateFile,
    WriteFile,
    FsyncFile,
    Mkdir,
    UnsupportedOperation,
    ModelInvariantProbe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantFailureClass {
    ModelBug,
    ProductionBug,
    UnsupportedOperation,
    HarnessBug,
}

impl InvariantFailureClass {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ModelBug => "model_bug",
            Self::ProductionBug => "production_bug",
            Self::UnsupportedOperation => "unsupported_operation",
            Self::HarnessBug => "harness_bug",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantModelState {
    #[serde(default)]
    pub directories: Vec<String>,
    #[serde(default)]
    pub files: Vec<InvariantFileState>,
    #[serde(default)]
    pub durable_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantFileState {
    pub path: String,
    pub size: u64,
    pub content_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantOracleReport {
    pub schema_version: u32,
    pub trace_id: String,
    pub seed: u64,
    pub operation_count: usize,
    pub deterministic_replay_id: String,
    pub valid: bool,
    pub expected_failure_count: usize,
    pub unexpected_failure_count: usize,
    pub failure_class_counts: BTreeMap<String, usize>,
    pub violations: Vec<InvariantViolationReport>,
    pub errors: Vec<String>,
    pub reproduction_command: String,
    pub required_artifacts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantViolationReport {
    pub trace_id: String,
    pub operation_index: usize,
    pub operation_id: String,
    pub violated_invariant: String,
    pub expected: bool,
    pub failure_class: InvariantFailureClass,
    pub expected_state: InvariantModelState,
    pub observed_state: InvariantModelState,
    pub minimized_trace: MinimizedInvariantTrace,
    pub reproduction_command: String,
    pub artifact_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinimizedInvariantTrace {
    pub original_trace_len: usize,
    pub minimized_trace_len: usize,
    pub operation_ids: Vec<String>,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReplayState {
    directories: BTreeSet<String>,
    files: BTreeMap<String, ReplayFile>,
    durable_paths: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReplayFile {
    size: u64,
    content_hash: String,
}

pub fn load_invariant_trace(path: &Path) -> Result<InvariantTrace> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read invariant trace {}", path.display()))?;
    parse_invariant_trace(&text)
        .with_context(|| format!("invalid invariant trace {}", path.display()))
}

pub fn parse_invariant_trace(text: &str) -> Result<InvariantTrace> {
    serde_json::from_str(text).context("failed to parse invariant trace JSON")
}

#[must_use]
pub fn validate_invariant_trace(trace: &InvariantTrace) -> InvariantOracleReport {
    let mut errors = Vec::new();
    let mut operation_ids = BTreeSet::new();
    let mut state = ReplayState::new();
    let mut violations = Vec::new();

    validate_trace_header(trace, &mut errors);

    for (sequence_index, operation) in trace.operations.iter().enumerate() {
        validate_operation_shape(operation, sequence_index, &mut operation_ids, &mut errors);

        let replay_violations = state.apply(operation);
        let replay_state = state.to_model_state();
        if replay_state != operation.expected_state {
            violations.push(build_violation(
                trace,
                operation,
                "model_replay_matches_expected_state",
                InvariantFailureClass::ModelBug,
                replay_state,
                operation.expected_state.clone(),
                true,
            ));
        }

        for invariant in replay_violations {
            violations.push(build_violation(
                trace,
                operation,
                invariant,
                InvariantFailureClass::ModelBug,
                operation.expected_state.clone(),
                operation.observed_state.clone(),
                false,
            ));
        }

        for invariant in compare_states(&operation.expected_state, &operation.observed_state) {
            let failure_class = operation.failure_class.unwrap_or_else(|| {
                if operation.action == InvariantAction::UnsupportedOperation {
                    InvariantFailureClass::UnsupportedOperation
                } else {
                    InvariantFailureClass::ProductionBug
                }
            });
            violations.push(build_violation(
                trace,
                operation,
                invariant,
                failure_class,
                operation.expected_state.clone(),
                operation.observed_state.clone(),
                false,
            ));
        }

        validate_expected_violation(operation, &violations, &mut errors);
    }

    let unexpected_failure_count = violations
        .iter()
        .filter(|violation| !violation.expected)
        .count();
    let expected_failure_count = violations.len() - unexpected_failure_count;
    let failure_class_counts = count_failure_classes(&violations);

    InvariantOracleReport {
        schema_version: INVARIANT_ORACLE_SCHEMA_VERSION,
        trace_id: trace.trace_id.clone(),
        seed: trace.seed,
        operation_count: trace.operations.len(),
        deterministic_replay_id: deterministic_replay_id(trace),
        valid: errors.is_empty() && unexpected_failure_count == 0,
        expected_failure_count,
        unexpected_failure_count,
        failure_class_counts,
        violations,
        errors,
        reproduction_command: trace.reproduction_command.clone(),
        required_artifacts: collect_required_artifacts(trace),
    }
}

pub fn fail_on_invariant_oracle_errors(report: &InvariantOracleReport) -> Result<()> {
    if !report.errors.is_empty() || report.unexpected_failure_count > 0 {
        for error in &report.errors {
            eprintln!("invariant oracle validation error: {error}");
        }
        for violation in report
            .violations
            .iter()
            .filter(|violation| !violation.expected)
        {
            eprintln!(
                "unexpected invariant violation: trace={} op={} invariant={} class={}",
                violation.trace_id,
                violation.operation_id,
                violation.violated_invariant,
                violation.failure_class.label()
            );
        }
        bail!(
            "invariant oracle validation failed: errors={} unexpected_failures={}",
            report.errors.len(),
            report.unexpected_failure_count
        );
    }
    Ok(())
}

#[must_use]
pub fn render_invariant_oracle_markdown(report: &InvariantOracleReport) -> String {
    let mut out = String::new();
    out.push_str("# Invariant Oracle Report\n\n");
    let _ = writeln!(out, "- Trace: `{}`", report.trace_id);
    let _ = writeln!(out, "- Seed: `{}`", report.seed);
    let _ = writeln!(
        out,
        "- Deterministic replay id: `{}`",
        report.deterministic_replay_id
    );
    let _ = writeln!(
        out,
        "- Operations: {} expected_failures={} unexpected_failures={} errors={}",
        report.operation_count,
        report.expected_failure_count,
        report.unexpected_failure_count,
        report.errors.len()
    );
    let _ = writeln!(out, "- Reproduction: `{}`", report.reproduction_command);
    out.push('\n');

    if report.violations.is_empty() {
        out.push_str("No invariant violations were reported.\n");
    } else {
        out.push_str("## Violations\n\n");
        for violation in &report.violations {
            let _ = writeln!(
                out,
                "- op `{}` index={} invariant=`{}` class=`{}` expected={} minimized={}/{}",
                violation.operation_id,
                violation.operation_index,
                violation.violated_invariant,
                violation.failure_class.label(),
                violation.expected,
                violation.minimized_trace.minimized_trace_len,
                violation.minimized_trace.original_trace_len
            );
        }
    }

    out
}

fn validate_trace_header(trace: &InvariantTrace, errors: &mut Vec<String>) {
    if trace.schema_version != INVARIANT_ORACLE_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version must be {INVARIANT_ORACLE_SCHEMA_VERSION}, got {}",
            trace.schema_version
        ));
    }
    validate_nonempty("trace_id", &trace.trace_id, errors);
    validate_nonempty("reproduction_command", &trace.reproduction_command, errors);
    if !trace
        .reproduction_command
        .contains("validate-invariant-oracle")
    {
        errors.push(
            "reproduction_command must include validate-invariant-oracle invocation".to_owned(),
        );
    }
    if trace.operations.is_empty() {
        errors.push("trace must contain at least one operation".to_owned());
    }
}

fn validate_operation_shape(
    operation: &InvariantTraceOperation,
    sequence_index: usize,
    operation_ids: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    validate_nonempty("operation_id", &operation.operation_id, errors);
    validate_nonempty("precondition", &operation.precondition, errors);
    validate_nonempty(
        "expected_model_delta",
        &operation.expected_model_delta,
        errors,
    );
    validate_nonempty(
        "observed_subsystem_event",
        &operation.observed_subsystem_event,
        errors,
    );
    validate_path("operation.path", &operation.path, errors);
    if !operation_ids.insert(operation.operation_id.clone()) {
        errors.push(format!("duplicate operation_id {}", operation.operation_id));
    }
    if operation.operation_index != sequence_index {
        errors.push(format!(
            "operation {} operation_index {} must match sequence index {sequence_index}",
            operation.operation_id, operation.operation_index
        ));
    }
    if operation.failure_class.is_some() && operation.expected_violation.is_none() {
        errors.push(format!(
            "operation {} failure_class requires expected_violation",
            operation.operation_id
        ));
    }
    if operation.action == InvariantAction::WriteFile && operation.bytes_written.is_none() {
        errors.push(format!(
            "operation {} write_file requires bytes_written",
            operation.operation_id
        ));
    }
    validate_state_paths("expected_state", &operation.expected_state, errors);
    validate_state_paths("observed_state", &operation.observed_state, errors);
}

fn validate_expected_violation(
    operation: &InvariantTraceOperation,
    violations: &[InvariantViolationReport],
    errors: &mut Vec<String>,
) {
    let Some(expected_violation) = &operation.expected_violation else {
        return;
    };
    let matched = violations.iter().any(|violation| {
        violation.operation_id == operation.operation_id
            && violation.violated_invariant == *expected_violation
    });
    if !matched {
        errors.push(format!(
            "operation {} expected violation {} did not fire",
            operation.operation_id, expected_violation
        ));
    }
}

fn validate_nonempty(field: &str, value: &str, errors: &mut Vec<String>) {
    if value.trim().is_empty() {
        errors.push(format!("{field} must be nonempty"));
    }
}

fn validate_state_paths(prefix: &str, state: &InvariantModelState, errors: &mut Vec<String>) {
    for path in &state.directories {
        validate_path(&format!("{prefix}.directories"), path, errors);
    }
    for path in &state.durable_paths {
        validate_path(&format!("{prefix}.durable_paths"), path, errors);
    }
    for file in &state.files {
        validate_path(&format!("{prefix}.files.path"), &file.path, errors);
        if !is_sha256_hex(&file.content_hash) {
            errors.push(format!(
                "{prefix}.files {} content_hash must be SHA-256 hex",
                file.path
            ));
        }
    }
}

fn validate_path(field: &str, path: &str, errors: &mut Vec<String>) {
    if !path.starts_with(ROOT_PATH) {
        errors.push(format!("{field} {path} must be absolute"));
    }
    if path.contains("..") {
        errors.push(format!("{field} {path} must not contain parent traversal"));
    }
}

impl ReplayState {
    fn new() -> Self {
        Self {
            directories: BTreeSet::from([ROOT_PATH.to_owned()]),
            files: BTreeMap::new(),
            durable_paths: BTreeSet::new(),
        }
    }

    fn apply(&mut self, operation: &InvariantTraceOperation) -> Vec<&'static str> {
        let mut violations = Vec::new();
        match operation.action {
            InvariantAction::CreateFile => {
                if !self.parent_dir_exists(&operation.path) {
                    violations.push("parent_directory_exists");
                }
                self.files.insert(
                    operation.path.clone(),
                    ReplayFile {
                        size: 0,
                        content_hash: EMPTY_SHA256.to_owned(),
                    },
                );
            }
            InvariantAction::WriteFile => {
                let Some(file) = self.files.get_mut(&operation.path) else {
                    violations.push("file_exists_before_write");
                    return violations;
                };
                let bytes_written = operation.bytes_written.unwrap_or(0);
                file.size = file.size.saturating_add(bytes_written);
                file.content_hash = synthetic_content_hash(&operation.path, file.size);
            }
            InvariantAction::FsyncFile => {
                if self.files.contains_key(&operation.path) {
                    self.durable_paths.insert(operation.path.clone());
                } else {
                    violations.push("fsync_target_exists");
                }
            }
            InvariantAction::Mkdir => {
                if !self.parent_dir_exists(&operation.path) {
                    violations.push("parent_directory_exists");
                }
                self.directories.insert(operation.path.clone());
            }
            InvariantAction::UnsupportedOperation | InvariantAction::ModelInvariantProbe => {}
        }
        violations
    }

    fn parent_dir_exists(&self, path: &str) -> bool {
        if path == ROOT_PATH {
            return true;
        }
        let Some((parent, _name)) = path.rsplit_once('/') else {
            return false;
        };
        let parent = if parent.is_empty() { ROOT_PATH } else { parent };
        self.directories.contains(parent)
    }

    fn to_model_state(&self) -> InvariantModelState {
        InvariantModelState {
            directories: self.directories.iter().cloned().collect(),
            files: self
                .files
                .iter()
                .map(|(path, file)| InvariantFileState {
                    path: path.clone(),
                    size: file.size,
                    content_hash: file.content_hash.clone(),
                })
                .collect(),
            durable_paths: self.durable_paths.iter().cloned().collect(),
        }
    }
}

fn compare_states(
    expected: &InvariantModelState,
    observed: &InvariantModelState,
) -> Vec<&'static str> {
    let expected_dirs: BTreeSet<&str> = expected.directories.iter().map(String::as_str).collect();
    let observed_dirs: BTreeSet<&str> = observed.directories.iter().map(String::as_str).collect();
    let expected_durable: BTreeSet<&str> =
        expected.durable_paths.iter().map(String::as_str).collect();
    let observed_durable: BTreeSet<&str> =
        observed.durable_paths.iter().map(String::as_str).collect();
    let expected_files = file_map(expected);
    let observed_files = file_map(observed);

    let mut invariants = Vec::new();
    if !observed_dirs.contains(ROOT_PATH) {
        invariants.push("root_directory_exists");
    }
    if expected_dirs != observed_dirs {
        invariants.push("directory_set_matches_model");
    }
    if expected_durable != observed_durable {
        invariants.push("durability_set_matches_model");
    }
    for (path, expected_file) in &expected_files {
        let Some(observed_file) = observed_files.get(path) else {
            invariants.push("observed_file_exists");
            continue;
        };
        if expected_file.size != observed_file.size {
            invariants.push("file_size_matches_model");
        } else if expected_file.content_hash != observed_file.content_hash {
            invariants.push("file_content_hash_matches_model");
        }
    }
    for path in observed_files.keys() {
        if !expected_files.contains_key(path) {
            invariants.push("observed_no_extra_files");
        }
    }
    invariants.sort_unstable();
    invariants.dedup();
    invariants
}

fn file_map(state: &InvariantModelState) -> BTreeMap<&str, &InvariantFileState> {
    state
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect()
}

fn build_violation(
    trace: &InvariantTrace,
    operation: &InvariantTraceOperation,
    invariant: &str,
    failure_class: InvariantFailureClass,
    expected_state: InvariantModelState,
    observed_state: InvariantModelState,
    force_expected: bool,
) -> InvariantViolationReport {
    let expected = force_expected
        || operation
            .expected_violation
            .as_ref()
            .is_some_and(|expected| expected == invariant);
    InvariantViolationReport {
        trace_id: trace.trace_id.clone(),
        operation_index: operation.operation_index,
        operation_id: operation.operation_id.clone(),
        violated_invariant: invariant.to_owned(),
        expected,
        failure_class,
        expected_state,
        observed_state,
        minimized_trace: minimize_trace(trace, operation.operation_index),
        reproduction_command: trace.reproduction_command.clone(),
        artifact_refs: operation.artifact_refs.clone(),
    }
}

fn minimize_trace(trace: &InvariantTrace, operation_index: usize) -> MinimizedInvariantTrace {
    let limit = operation_index
        .saturating_add(1)
        .min(trace.operations.len());
    MinimizedInvariantTrace {
        original_trace_len: trace.operations.len(),
        minimized_trace_len: limit,
        operation_ids: trace
            .operations
            .iter()
            .take(limit)
            .map(|operation| operation.operation_id.clone())
            .collect(),
        reproduction_command: trace.reproduction_command.clone(),
    }
}

fn deterministic_replay_id(trace: &InvariantTrace) -> String {
    let mut hasher = Sha256::new();
    hash_part(&mut hasher, &trace.trace_id);
    hash_part(&mut hasher, &trace.seed.to_string());
    let mut state = ReplayState::new();
    for operation in &trace.operations {
        hash_part(&mut hasher, &operation.operation_id);
        hash_part(&mut hasher, &operation.operation_index.to_string());
        hash_part(&mut hasher, action_label(operation.action));
        hash_part(&mut hasher, &operation.path);
        hash_part(
            &mut hasher,
            &operation.bytes_written.unwrap_or_default().to_string(),
        );
        state.apply(operation);
        hash_model_state(&mut hasher, &state.to_model_state());
    }
    hex::encode(hasher.finalize())
}

fn action_label(action: InvariantAction) -> &'static str {
    match action {
        InvariantAction::CreateFile => "create_file",
        InvariantAction::WriteFile => "write_file",
        InvariantAction::FsyncFile => "fsync_file",
        InvariantAction::Mkdir => "mkdir",
        InvariantAction::UnsupportedOperation => "unsupported_operation",
        InvariantAction::ModelInvariantProbe => "model_invariant_probe",
    }
}

fn hash_model_state(hasher: &mut Sha256, state: &InvariantModelState) {
    hash_part(hasher, "directories");
    hash_part(hasher, &state.directories.len().to_string());
    for directory in &state.directories {
        hash_part(hasher, directory);
    }
    hash_part(hasher, "files");
    hash_part(hasher, &state.files.len().to_string());
    for file in &state.files {
        hash_part(hasher, &file.path);
        hash_part(hasher, &file.size.to_string());
        hash_part(hasher, &file.content_hash);
    }
    hash_part(hasher, "durable_paths");
    hash_part(hasher, &state.durable_paths.len().to_string());
    for durable_path in &state.durable_paths {
        hash_part(hasher, durable_path);
    }
}

fn hash_part(hasher: &mut Sha256, value: &str) {
    hasher.update(value.len().to_string().as_bytes());
    hasher.update(b":");
    hasher.update(value.as_bytes());
    hasher.update(b";");
}

fn synthetic_content_hash(path: &str, size: u64) -> String {
    let mut hasher = Sha256::new();
    hash_part(&mut hasher, path);
    hash_part(&mut hasher, &size.to_string());
    hex::encode(hasher.finalize())
}

fn is_sha256_hex(raw: &str) -> bool {
    raw.len() == 64 && raw.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn count_failure_classes(violations: &[InvariantViolationReport]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for violation in violations {
        *counts
            .entry(violation.failure_class.label().to_owned())
            .or_insert(0) += 1;
    }
    counts
}

fn collect_required_artifacts(trace: &InvariantTrace) -> Vec<String> {
    let mut artifacts = BTreeSet::new();
    for operation in &trace.operations {
        artifacts.extend(operation.artifact_refs.iter().cloned());
    }
    artifacts.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(files: &[(&str, u64)], durable: &[&str]) -> InvariantModelState {
        InvariantModelState {
            directories: vec![ROOT_PATH.to_owned()],
            files: files
                .iter()
                .map(|(path, size)| InvariantFileState {
                    path: (*path).to_owned(),
                    size: *size,
                    content_hash: if *size == 0 {
                        EMPTY_SHA256.to_owned()
                    } else {
                        synthetic_content_hash(path, *size)
                    },
                })
                .collect(),
            durable_paths: durable.iter().map(|path| (*path).to_owned()).collect(),
        }
    }

    fn op(
        operation_index: usize,
        action: InvariantAction,
        path: &str,
        bytes_written: Option<u64>,
        expected_state: InvariantModelState,
        observed_state: InvariantModelState,
    ) -> InvariantTraceOperation {
        InvariantTraceOperation {
            operation_id: format!("op-{operation_index}"),
            operation_index,
            action,
            path: path.to_owned(),
            bytes_written,
            precondition: "model precondition recorded".to_owned(),
            expected_model_delta: "model delta recorded".to_owned(),
            observed_subsystem_event: "OpenFs operation event".to_owned(),
            artifact_refs: vec![format!("logs/op-{operation_index}.jsonl")],
            expected_state,
            observed_state,
            expected_violation: None,
            failure_class: None,
        }
    }

    fn valid_trace() -> InvariantTrace {
        InvariantTrace {
            schema_version: INVARIANT_ORACLE_SCHEMA_VERSION,
            trace_id: "trace-valid-write".to_owned(),
            seed: 42,
            reproduction_command:
                "ffs-harness validate-invariant-oracle --trace artifacts/invariant/trace.json"
                    .to_owned(),
            operations: vec![
                op(
                    0,
                    InvariantAction::CreateFile,
                    "/alpha",
                    None,
                    state(&[("/alpha", 0)], &[]),
                    state(&[("/alpha", 0)], &[]),
                ),
                op(
                    1,
                    InvariantAction::WriteFile,
                    "/alpha",
                    Some(5),
                    state(&[("/alpha", 5)], &[]),
                    state(&[("/alpha", 5)], &[]),
                ),
                op(
                    2,
                    InvariantAction::FsyncFile,
                    "/alpha",
                    None,
                    state(&[("/alpha", 5)], &["/alpha"]),
                    state(&[("/alpha", 5)], &["/alpha"]),
                ),
            ],
        }
    }

    #[test]
    fn parses_trace_schema_and_replays_deterministically() {
        let trace = valid_trace();
        let text = serde_json::to_string(&trace).expect("serialize trace");
        let parsed = parse_invariant_trace(&text).expect("parse trace");
        let first = validate_invariant_trace(&parsed);
        let second = validate_invariant_trace(&parsed);
        assert!(first.valid, "{:?}", first.errors);
        assert_eq!(
            first.deterministic_replay_id,
            second.deterministic_replay_id
        );
        assert_eq!(first.operation_count, 3);
    }

    #[test]
    fn false_positive_guard_allows_zero_write_and_repeated_fsync() {
        let mut trace = valid_trace();
        trace.operations.push(op(
            3,
            InvariantAction::WriteFile,
            "/alpha",
            Some(0),
            state(&[("/alpha", 5)], &["/alpha"]),
            state(&[("/alpha", 5)], &["/alpha"]),
        ));
        trace.operations.push(op(
            4,
            InvariantAction::FsyncFile,
            "/alpha",
            None,
            state(&[("/alpha", 5)], &["/alpha"]),
            state(&[("/alpha", 5)], &["/alpha"]),
        ));
        let report = validate_invariant_trace(&trace);
        assert!(report.valid, "{report:?}");
        assert!(report.violations.is_empty());
    }

    #[test]
    fn expected_invariant_failure_is_reported_without_failing_trace() {
        let mut trace = valid_trace();
        let mut bad = op(
            3,
            InvariantAction::ModelInvariantProbe,
            "/alpha",
            None,
            state(&[("/alpha", 5)], &["/alpha"]),
            state(&[("/alpha", 4)], &["/alpha"]),
        );
        bad.expected_violation = Some("file_size_matches_model".to_owned());
        bad.failure_class = Some(InvariantFailureClass::ProductionBug);
        trace.operations.push(bad);

        let report = validate_invariant_trace(&trace);
        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.expected_failure_count, 1);
        assert_eq!(report.unexpected_failure_count, 0);
        assert_eq!(
            report.violations[0].violated_invariant,
            "file_size_matches_model"
        );
        assert_eq!(
            report.violations[0].failure_class,
            InvariantFailureClass::ProductionBug
        );
    }

    #[test]
    fn unexpected_invariant_failure_fails_trace() {
        let mut trace = valid_trace();
        trace.operations.push(op(
            3,
            InvariantAction::ModelInvariantProbe,
            "/alpha",
            None,
            state(&[("/alpha", 5)], &["/alpha"]),
            state(&[("/alpha", 4)], &["/alpha"]),
        ));
        let report = validate_invariant_trace(&trace);
        assert!(!report.valid);
        assert_eq!(report.unexpected_failure_count, 1);
    }

    #[test]
    fn minimizer_keeps_prefix_through_failing_operation() {
        let mut trace = valid_trace();
        let mut bad = op(
            3,
            InvariantAction::ModelInvariantProbe,
            "/alpha",
            None,
            state(&[("/alpha", 5)], &["/alpha"]),
            state(&[("/alpha", 9)], &["/alpha"]),
        );
        bad.expected_violation = Some("file_size_matches_model".to_owned());
        bad.failure_class = Some(InvariantFailureClass::ProductionBug);
        trace.operations.push(bad);
        let report = validate_invariant_trace(&trace);
        let minimized = &report.violations[0].minimized_trace;
        assert_eq!(minimized.original_trace_len, 4);
        assert_eq!(minimized.minimized_trace_len, 4);
        assert_eq!(
            minimized.operation_ids,
            vec!["op-0", "op-1", "op-2", "op-3"]
        );
    }

    #[test]
    fn model_bug_and_unsupported_operation_classes_are_distinguishable() {
        let mut trace = valid_trace();
        let mut unsupported = op(
            3,
            InvariantAction::UnsupportedOperation,
            "/alpha",
            None,
            state(&[("/alpha", 5)], &["/alpha"]),
            state(&[("/alpha", 5), ("/extra", 1)], &["/alpha"]),
        );
        unsupported.expected_violation = Some("observed_no_extra_files".to_owned());
        unsupported.failure_class = Some(InvariantFailureClass::UnsupportedOperation);
        trace.operations.push(unsupported);
        let report = validate_invariant_trace(&trace);
        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.failure_class_counts["unsupported_operation"], 1);
    }

    #[test]
    fn structured_markdown_includes_violation_and_reproduction() {
        let mut trace = valid_trace();
        let mut bad = op(
            3,
            InvariantAction::ModelInvariantProbe,
            "/alpha",
            None,
            state(&[("/alpha", 5)], &["/alpha"]),
            state(&[("/alpha", 4)], &["/alpha"]),
        );
        bad.expected_violation = Some("file_size_matches_model".to_owned());
        bad.failure_class = Some(InvariantFailureClass::ProductionBug);
        trace.operations.push(bad);
        let report = validate_invariant_trace(&trace);
        let markdown = render_invariant_oracle_markdown(&report);
        assert!(markdown.contains("Invariant Oracle Report"));
        assert!(markdown.contains("file_size_matches_model"));
        assert!(markdown.contains("validate-invariant-oracle"));
    }
}
