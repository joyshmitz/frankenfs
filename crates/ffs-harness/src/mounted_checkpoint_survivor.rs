#![forbid(unsafe_code)]

//! Mounted crash/unmount/reopen checkpointed survivor oracle.
//!
//! Tracks bd-zm0wr: each mounted lifecycle scenario carries a checkpoint
//! schema (pre-operation image hash, operation trace with fsync/fsyncdir
//! markers, crash/unmount point, expected survivor set, recovery command,
//! partial-artifact preservation policy) so a killed harness leaves
//! enough evidence to classify the failure as product, harness, host
//! limitation, or unsupported scope without rerunning immediately.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt::Write as _, fs, path::Path};

pub const MOUNTED_CHECKPOINT_SURVIVOR_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_MOUNTED_CHECKPOINT_SURVIVOR_PATH: &str =
    "tests/mounted-checkpoint-survivor/mounted_checkpoint_survivor.json";
const DEFAULT_MOUNTED_CHECKPOINT_SURVIVOR_JSON: &str =
    include_str!("../../../tests/mounted-checkpoint-survivor/mounted_checkpoint_survivor.json");

const ALLOWED_LIFECYCLE_KINDS: [&str; 6] = [
    "clean_unmount",
    "forced_unmount",
    "process_termination_pre_fsync",
    "process_termination_post_fsync",
    "fsyncdir_boundary",
    "reopen_after_write",
];

const ALLOWED_RECOVERY_CLASSIFICATIONS: [&str; 5] = [
    "product_failure",
    "harness_bug",
    "host_limitation",
    "unsupported_scope",
    "expected_survivor_set",
];

const ALLOWED_PARTIAL_ARTIFACT_POLICIES: [&str; 3] =
    ["preserve_on_failure", "preserve_always", "discard_on_pass"];

const ALLOWED_PROCESS_CONTROL: [&str; 4] = [
    "clean_signal",
    "sigterm_then_sigkill",
    "kill_minus_nine_refused",
    "harness_internal_pause",
];

const ALLOWED_TRACE_OPS: [&str; 7] = [
    "create",
    "write",
    "fsync",
    "fsyncdir",
    "rename",
    "unlink",
    "checkpoint_marker",
];

const REQUIRED_LIFECYCLE_KINDS: [&str; 4] = [
    "clean_unmount",
    "process_termination_pre_fsync",
    "process_termination_post_fsync",
    "reopen_after_write",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedCheckpointSurvivorMatrix {
    pub schema_version: u32,
    pub matrix_id: String,
    pub bead_id: String,
    pub scenarios: Vec<MountedCheckpointScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedCheckpointScenario {
    pub scenario_id: String,
    pub checkpoint_id: String,
    pub kind: String,
    pub mount_options: Vec<String>,
    pub pre_operation_image_hash: String,
    pub post_operation_image_hash: String,
    pub operation_trace: Vec<TraceStep>,
    pub crash_or_unmount_point_step: u32,
    pub expected_survivor_set: SurvivorSet,
    pub recovery_command: String,
    pub recovery_classification: String,
    pub partial_artifact_policy: String,
    pub process_control: String,
    pub artifact_paths: Vec<String>,
    pub cleanup_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceStep {
    pub step: u32,
    pub op: String,
    pub args: Vec<String>,
    pub fsync_boundary: bool,
    pub fsyncdir_boundary: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurvivorSet {
    pub present_paths: Vec<String>,
    pub absent_paths: Vec<String>,
    pub xattr_state: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedCheckpointSurvivorReport {
    pub schema_version: u32,
    pub matrix_id: String,
    pub bead_id: String,
    pub scenario_count: usize,
    pub kinds_seen: Vec<String>,
    pub valid: bool,
    pub errors: Vec<String>,
}

pub fn parse_mounted_checkpoint_survivor(text: &str) -> Result<MountedCheckpointSurvivorMatrix> {
    serde_json::from_str(text)
        .map_err(|err| anyhow::anyhow!("failed to parse mounted checkpoint survivor JSON: {err}"))
}

pub fn load_mounted_checkpoint_survivor(path: &Path) -> Result<MountedCheckpointSurvivorMatrix> {
    let text = fs::read_to_string(path).map_err(|err| {
        anyhow::anyhow!(
            "failed to read mounted checkpoint survivor matrix `{}`: {err}",
            path.display()
        )
    })?;
    parse_mounted_checkpoint_survivor(&text)
}

pub fn validate_default_mounted_checkpoint_survivor() -> Result<MountedCheckpointSurvivorReport> {
    let matrix = parse_mounted_checkpoint_survivor(DEFAULT_MOUNTED_CHECKPOINT_SURVIVOR_JSON)?;
    let report = validate_mounted_checkpoint_survivor(&matrix);
    fail_on_mounted_checkpoint_survivor_errors(&report)?;
    Ok(report)
}

pub fn fail_on_mounted_checkpoint_survivor_errors(
    report: &MountedCheckpointSurvivorReport,
) -> Result<()> {
    if report.valid {
        return Ok(());
    }
    bail!(
        "mounted checkpoint survivor matrix failed with {} error(s): {}",
        report.errors.len(),
        report.errors.join("; ")
    );
}

#[must_use]
pub fn validate_mounted_checkpoint_survivor(
    matrix: &MountedCheckpointSurvivorMatrix,
) -> MountedCheckpointSurvivorReport {
    let mut errors = Vec::new();
    let mut ids = BTreeSet::new();
    let mut checkpoints = BTreeSet::new();
    let mut kinds = BTreeSet::new();

    validate_top_level(matrix, &mut errors);
    for scenario in &matrix.scenarios {
        validate_scenario(
            scenario,
            &mut ids,
            &mut checkpoints,
            &mut kinds,
            &mut errors,
        );
    }
    validate_required_kinds(&kinds, &mut errors);

    MountedCheckpointSurvivorReport {
        schema_version: matrix.schema_version,
        matrix_id: matrix.matrix_id.clone(),
        bead_id: matrix.bead_id.clone(),
        scenario_count: matrix.scenarios.len(),
        kinds_seen: kinds.into_iter().collect(),
        valid: errors.is_empty(),
        errors,
    }
}

fn validate_top_level(matrix: &MountedCheckpointSurvivorMatrix, errors: &mut Vec<String>) {
    if matrix.schema_version != MOUNTED_CHECKPOINT_SURVIVOR_SCHEMA_VERSION {
        errors.push(format!(
            "mounted checkpoint survivor schema_version must be {MOUNTED_CHECKPOINT_SURVIVOR_SCHEMA_VERSION}, got {}",
            matrix.schema_version
        ));
    }
    if matrix.matrix_id.trim().is_empty() {
        errors.push("mounted checkpoint survivor missing matrix_id".to_owned());
    }
    if !matrix.bead_id.starts_with("bd-") {
        errors.push(format!(
            "mounted checkpoint survivor bead_id must look like bd-..., got `{}`",
            matrix.bead_id
        ));
    }
    if matrix.scenarios.is_empty() {
        errors.push(
            "mounted checkpoint survivor matrix must declare at least one scenario".to_owned(),
        );
    }
}

fn validate_scenario(
    scenario: &MountedCheckpointScenario,
    ids: &mut BTreeSet<String>,
    checkpoints: &mut BTreeSet<String>,
    kinds: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    if !ids.insert(scenario.scenario_id.clone()) {
        errors.push(format!(
            "duplicate mounted checkpoint scenario_id `{}`",
            scenario.scenario_id
        ));
    }
    if !scenario.scenario_id.starts_with("mounted_checkpoint_") {
        errors.push(format!(
            "scenario_id `{}` must start with mounted_checkpoint_",
            scenario.scenario_id
        ));
    }
    if scenario.checkpoint_id.trim().is_empty() {
        errors.push(format!(
            "scenario `{}` missing checkpoint_id",
            scenario.scenario_id
        ));
    }
    if !checkpoints.insert(scenario.checkpoint_id.clone()) {
        errors.push(format!(
            "scenario `{}` checkpoint_id `{}` is not unique across the matrix",
            scenario.scenario_id, scenario.checkpoint_id
        ));
    }

    if ALLOWED_LIFECYCLE_KINDS.contains(&scenario.kind.as_str()) {
        kinds.insert(scenario.kind.clone());
    } else {
        errors.push(format!(
            "scenario `{}` has unsupported kind `{}`",
            scenario.scenario_id, scenario.kind
        ));
    }

    validate_scenario_hashes(scenario, errors);
    validate_operation_trace(scenario, errors);
    validate_survivor_set(scenario, errors);
    validate_recovery_and_artifacts(scenario, errors);
    validate_kind_specific_invariants(scenario, errors);
}

fn validate_scenario_hashes(scenario: &MountedCheckpointScenario, errors: &mut Vec<String>) {
    if !is_valid_sha256(&scenario.pre_operation_image_hash) {
        errors.push(format!(
            "scenario `{}` pre_operation_image_hash must be sha256:<64-hex>",
            scenario.scenario_id
        ));
    }
    let needs_post_hash = scenario.kind != "process_termination_pre_fsync"
        || is_expected_survivor_set_classification(&scenario.recovery_classification);
    if needs_post_hash && !is_valid_sha256(&scenario.post_operation_image_hash) {
        errors.push(format!(
            "scenario `{}` post_operation_image_hash must be sha256:<64-hex> for this lifecycle",
            scenario.scenario_id
        ));
    }
}

fn validate_operation_trace(scenario: &MountedCheckpointScenario, errors: &mut Vec<String>) {
    if scenario.operation_trace.is_empty() {
        errors.push(format!(
            "scenario `{}` operation_trace must not be empty",
            scenario.scenario_id
        ));
        return;
    }
    let mut last_step = 0_u32;
    let mut steps_seen = BTreeSet::new();
    let mut fsync_count = 0_usize;
    let mut fsyncdir_count = 0_usize;
    for step in &scenario.operation_trace {
        if !steps_seen.insert(step.step) {
            errors.push(format!(
                "scenario `{}` operation_trace has duplicate step {}",
                scenario.scenario_id, step.step
            ));
        }
        if last_step != 0 && step.step <= last_step {
            errors.push(format!(
                "scenario `{}` operation_trace must be strictly increasing",
                scenario.scenario_id
            ));
        }
        last_step = step.step;
        if !ALLOWED_TRACE_OPS.contains(&step.op.as_str()) {
            errors.push(format!(
                "scenario `{}` step {} has unsupported op `{}`",
                scenario.scenario_id, step.step, step.op
            ));
        }
        if step.fsync_boundary {
            fsync_count += 1;
        }
        if step.fsyncdir_boundary {
            fsyncdir_count += 1;
        }
    }
    if scenario.crash_or_unmount_point_step == 0 && scenario.kind != "clean_unmount" {
        errors.push(format!(
            "scenario `{}` crash_or_unmount_point_step must be positive for non-clean lifecycles",
            scenario.scenario_id
        ));
    }
    if scenario.crash_or_unmount_point_step != 0
        && !steps_seen.contains(&scenario.crash_or_unmount_point_step)
    {
        errors.push(format!(
            "scenario `{}` crash_or_unmount_point_step {} does not match any operation_trace step",
            scenario.scenario_id, scenario.crash_or_unmount_point_step
        ));
    }
    if scenario.kind == "fsyncdir_boundary" && fsyncdir_count == 0 {
        errors.push(format!(
            "scenario `{}` fsyncdir_boundary kind must include an fsyncdir step",
            scenario.scenario_id
        ));
    }
    if scenario.kind == "process_termination_post_fsync" && fsync_count == 0 {
        errors.push(format!(
            "scenario `{}` process_termination_post_fsync must include an fsync step before the crash",
            scenario.scenario_id
        ));
    }
}

fn validate_survivor_set(scenario: &MountedCheckpointScenario, errors: &mut Vec<String>) {
    if scenario.expected_survivor_set.present_paths.is_empty()
        && scenario.expected_survivor_set.absent_paths.is_empty()
    {
        errors.push(format!(
            "scenario `{}` expected_survivor_set must declare at least one present or absent path",
            scenario.scenario_id
        ));
    }
}

fn validate_recovery_and_artifacts(scenario: &MountedCheckpointScenario, errors: &mut Vec<String>) {
    if scenario.recovery_command.trim().is_empty() {
        errors.push(format!(
            "scenario `{}` recovery_command must not be empty",
            scenario.scenario_id
        ));
    }
    if !ALLOWED_RECOVERY_CLASSIFICATIONS.contains(&scenario.recovery_classification.as_str()) {
        errors.push(format!(
            "scenario `{}` has unsupported recovery_classification `{}`",
            scenario.scenario_id, scenario.recovery_classification
        ));
    }
    if !ALLOWED_PARTIAL_ARTIFACT_POLICIES.contains(&scenario.partial_artifact_policy.as_str()) {
        errors.push(format!(
            "scenario `{}` has unsupported partial_artifact_policy `{}`",
            scenario.scenario_id, scenario.partial_artifact_policy
        ));
    }
    if !ALLOWED_PROCESS_CONTROL.contains(&scenario.process_control.as_str()) {
        errors.push(format!(
            "scenario `{}` has unsupported process_control `{}`",
            scenario.scenario_id, scenario.process_control
        ));
    }
    if scenario.artifact_paths.is_empty() {
        errors.push(format!(
            "scenario `{}` must declare at least one artifact_path",
            scenario.scenario_id
        ));
    }
    if scenario.cleanup_policy.trim().is_empty() {
        errors.push(format!(
            "scenario `{}` cleanup_policy must not be empty",
            scenario.scenario_id
        ));
    }
}

fn validate_kind_specific_invariants(
    scenario: &MountedCheckpointScenario,
    errors: &mut Vec<String>,
) {
    if scenario.kind == "clean_unmount" {
        if scenario.process_control != "clean_signal" {
            errors.push(format!(
                "scenario `{}` clean_unmount must use process_control=clean_signal",
                scenario.scenario_id
            ));
        }
        if !is_expected_survivor_set_classification(&scenario.recovery_classification) {
            errors.push(format!(
                "scenario `{}` clean_unmount must classify as expected_survivor_set",
                scenario.scenario_id
            ));
        }
    }
    if scenario.process_control == "kill_minus_nine_refused"
        && is_expected_survivor_set_classification(&scenario.recovery_classification)
    {
        errors.push(format!(
            "scenario `{}` kill_minus_nine_refused cannot also claim expected_survivor_set; record the refusal classification instead",
            scenario.scenario_id
        ));
    }
    let crash_lifecycle = matches!(
        scenario.kind.as_str(),
        "process_termination_pre_fsync" | "process_termination_post_fsync"
    );
    if crash_lifecycle && scenario.partial_artifact_policy == "discard_on_pass" {
        errors.push(format!(
            "scenario `{}` crash lifecycle must preserve partial artifacts (preserve_on_failure or preserve_always)",
            scenario.scenario_id
        ));
    }
}

fn validate_required_kinds(seen: &BTreeSet<String>, errors: &mut Vec<String>) {
    for required in REQUIRED_LIFECYCLE_KINDS {
        if !seen.contains(required) {
            errors.push(format!(
                "mounted checkpoint survivor matrix missing required kind `{required}`"
            ));
        }
    }
}

fn is_valid_sha256(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("sha256:") else {
        return false;
    };
    suffix.len() == 64 && suffix.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn is_expected_survivor_set_classification(value: &str) -> bool {
    matches!(value, "expected_survivor_set")
}

#[must_use]
pub fn render_mounted_checkpoint_survivor_markdown(
    report: &MountedCheckpointSurvivorReport,
) -> String {
    let mut out = String::new();
    let _ = writeln!(&mut out, "# Mounted Checkpoint Survivor");
    let _ = writeln!(&mut out);
    let _ = writeln!(&mut out, "- matrix: `{}`", report.matrix_id);
    let _ = writeln!(&mut out, "- schema version: `{}`", report.schema_version);
    let _ = writeln!(&mut out, "- bead: `{}`", report.bead_id);
    let _ = writeln!(&mut out, "- valid: `{}`", report.valid);
    let _ = writeln!(&mut out, "- scenarios: `{}`", report.scenario_count);
    let _ = writeln!(&mut out);
    let _ = writeln!(&mut out, "## Lifecycle Kinds");
    for kind in &report.kinds_seen {
        let _ = writeln!(&mut out, "- `{kind}`");
    }
    if !report.errors.is_empty() {
        let _ = writeln!(&mut out);
        let _ = writeln!(&mut out, "## Errors");
        for error in &report.errors {
            let _ = writeln!(&mut out, "- {error}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    fn fixture_matrix() -> Result<MountedCheckpointSurvivorMatrix> {
        parse_mounted_checkpoint_survivor(DEFAULT_MOUNTED_CHECKPOINT_SURVIVOR_JSON)
            .context("default mounted checkpoint survivor matrix parses")
    }

    fn first_scenario_mut(
        matrix: &mut MountedCheckpointSurvivorMatrix,
    ) -> Result<&mut MountedCheckpointScenario> {
        matrix
            .scenarios
            .first_mut()
            .context("fixture matrix includes at least one scenario")
    }

    fn first_two_scenarios_mut(
        matrix: &mut MountedCheckpointSurvivorMatrix,
    ) -> Result<(
        &mut MountedCheckpointScenario,
        &mut MountedCheckpointScenario,
    )> {
        let (first, rest) = matrix
            .scenarios
            .split_first_mut()
            .context("fixture matrix includes at least one scenario")?;
        let second = rest
            .first_mut()
            .context("fixture matrix includes at least two scenarios")?;
        Ok((first, second))
    }

    fn scenario_by_kind_mut<'a>(
        matrix: &'a mut MountedCheckpointSurvivorMatrix,
        kind: &str,
    ) -> Result<&'a mut MountedCheckpointScenario> {
        matrix
            .scenarios
            .iter_mut()
            .find(|scenario| scenario.kind == kind)
            .with_context(|| format!("fixture matrix includes kind {kind}"))
    }

    fn scenario_by_process_control_mut<'a>(
        matrix: &'a mut MountedCheckpointSurvivorMatrix,
        process_control: &str,
    ) -> Result<&'a mut MountedCheckpointScenario> {
        matrix
            .scenarios
            .iter_mut()
            .find(|scenario| scenario.process_control == process_control)
            .with_context(|| format!("fixture matrix includes process_control {process_control}"))
    }

    fn first_two_trace_steps_mut(
        scenario: &mut MountedCheckpointScenario,
    ) -> Result<(&mut TraceStep, &mut TraceStep)> {
        let (first, rest) = scenario
            .operation_trace
            .split_first_mut()
            .context("fixture scenario includes at least one trace step")?;
        let second = rest
            .first_mut()
            .context("fixture scenario includes at least two trace steps")?;
        Ok((first, second))
    }

    #[test]
    fn default_matrix_report_snapshot() -> Result<()> {
        let report = validate_default_mounted_checkpoint_survivor()?;
        let json = serde_json::to_string_pretty(&report)?;
        insta::assert_snapshot!("default_matrix_report_snapshot", json);
        Ok(())
    }

    #[test]
    fn mounted_checkpoint_survivor_report_json_shape() -> Result<()> {
        let report = validate_default_mounted_checkpoint_survivor()?;

        let json = serde_json::to_string_pretty(&report)?;
        insta::assert_snapshot!("mounted_checkpoint_survivor_report_json_shape", json);
        let parsed: MountedCheckpointSurvivorReport = serde_json::from_str(&json)?;
        assert_eq!(parsed, report);
        Ok(())
    }

    #[test]
    fn render_mounted_checkpoint_survivor_markdown_default_matrix() -> Result<()> {
        let report = validate_default_mounted_checkpoint_survivor()?;
        let markdown = render_mounted_checkpoint_survivor_markdown(&report);
        insta::assert_snapshot!(
            "render_mounted_checkpoint_survivor_markdown_default_matrix",
            markdown
        );
        Ok(())
    }

    #[test]
    fn fail_on_errors_rejects_invalid_report() -> Result<()> {
        let mut matrix = fixture_matrix()?;
        first_scenario_mut(&mut matrix)?.artifact_paths.clear();
        let report = validate_mounted_checkpoint_survivor(&matrix);
        let Err(err) = fail_on_mounted_checkpoint_survivor_errors(&report) else {
            anyhow::bail!("invalid report fails closed");
        };
        assert!(
            err.to_string()
                .contains("mounted checkpoint survivor matrix failed")
        );
        assert!(err.to_string().contains("artifact_path"));
        Ok(())
    }

    #[test]
    fn default_matrix_validates_required_kinds() -> Result<()> {
        let report = validate_default_mounted_checkpoint_survivor()?;
        assert_eq!(report.bead_id, "bd-zm0wr");
        for kind in REQUIRED_LIFECYCLE_KINDS {
            assert!(
                report.kinds_seen.iter().any(|k| k == kind),
                "missing required kind {kind}"
            );
        }
        Ok(())
    }

    #[test]
    fn missing_clean_unmount_kind_is_rejected() -> Result<()> {
        let mut matrix = fixture_matrix()?;
        matrix.scenarios.retain(|s| s.kind != "clean_unmount");
        let report = validate_mounted_checkpoint_survivor(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required kind `clean_unmount`"))
        );
        Ok(())
    }

    #[test]
    fn missing_post_fsync_kind_is_rejected() -> Result<()> {
        let mut matrix = fixture_matrix()?;
        matrix
            .scenarios
            .retain(|s| s.kind != "process_termination_post_fsync");
        let report = validate_mounted_checkpoint_survivor(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required kind `process_termination_post_fsync`"))
        );
        Ok(())
    }

    #[test]
    fn duplicate_scenario_id_is_rejected() -> Result<()> {
        let mut matrix = fixture_matrix()?;
        let (first, second) = first_two_scenarios_mut(&mut matrix)?;
        second.scenario_id = first.scenario_id.clone();
        let report = validate_mounted_checkpoint_survivor(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("duplicate mounted checkpoint scenario_id"))
        );
        Ok(())
    }

    #[test]
    fn duplicate_checkpoint_id_is_rejected() -> Result<()> {
        let mut matrix = fixture_matrix()?;
        let (first, second) = first_two_scenarios_mut(&mut matrix)?;
        second.checkpoint_id = first.checkpoint_id.clone();
        let report = validate_mounted_checkpoint_survivor(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("checkpoint_id") && err.contains("not unique"))
        );
        Ok(())
    }

    #[test]
    fn scenario_id_prefix_is_enforced() -> Result<()> {
        let mut matrix = fixture_matrix()?;
        first_scenario_mut(&mut matrix)?.scenario_id = "checkpoint_001".to_owned();
        let report = validate_mounted_checkpoint_survivor(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must start with mounted_checkpoint_"))
        );
        Ok(())
    }

    #[test]
    fn unsupported_kind_is_rejected() -> Result<()> {
        let mut matrix = fixture_matrix()?;
        first_scenario_mut(&mut matrix)?.kind = "remote_alien_termination".to_owned();
        let report = validate_mounted_checkpoint_survivor(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported kind"))
        );
        Ok(())
    }

    #[test]
    fn malformed_pre_operation_image_hash_is_rejected() -> Result<()> {
        let mut matrix = fixture_matrix()?;
        first_scenario_mut(&mut matrix)?.pre_operation_image_hash = "md5:not-supported".to_owned();
        let report = validate_mounted_checkpoint_survivor(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("pre_operation_image_hash must be sha256"))
        );
        Ok(())
    }

    #[test]
    fn operation_trace_must_be_non_empty() -> Result<()> {
        let mut matrix = fixture_matrix()?;
        first_scenario_mut(&mut matrix)?.operation_trace.clear();
        let report = validate_mounted_checkpoint_survivor(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("operation_trace must not be empty"))
        );
        Ok(())
    }

    #[test]
    fn operation_trace_steps_must_increase() -> Result<()> {
        let mut matrix = fixture_matrix()?;
        let scenario = first_scenario_mut(&mut matrix)?;
        let (first, second) = first_two_trace_steps_mut(scenario)?;
        second.step = first.step;
        let report = validate_mounted_checkpoint_survivor(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("strictly increasing") || err.contains("duplicate step"))
        );
        Ok(())
    }

    #[test]
    fn crash_point_must_match_a_trace_step() -> Result<()> {
        let mut matrix = fixture_matrix()?;
        let scenario = scenario_by_kind_mut(&mut matrix, "process_termination_post_fsync")?;
        scenario.crash_or_unmount_point_step = 9999;
        let report = validate_mounted_checkpoint_survivor(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("does not match any operation_trace step"))
        );
        Ok(())
    }

    #[test]
    fn fsyncdir_boundary_kind_must_include_fsyncdir_step() -> Result<()> {
        let mut matrix = fixture_matrix()?;
        let scenario = scenario_by_kind_mut(&mut matrix, "fsyncdir_boundary")?;
        for step in &mut scenario.operation_trace {
            step.fsyncdir_boundary = false;
        }
        let report = validate_mounted_checkpoint_survivor(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("fsyncdir_boundary kind must include an fsyncdir step"))
        );
        Ok(())
    }

    #[test]
    fn post_fsync_kind_requires_fsync_step() -> Result<()> {
        let mut matrix = fixture_matrix()?;
        let scenario = scenario_by_kind_mut(&mut matrix, "process_termination_post_fsync")?;
        for step in &mut scenario.operation_trace {
            step.fsync_boundary = false;
        }
        let report = validate_mounted_checkpoint_survivor(&matrix);
        assert!(
            report.errors.iter().any(
                |err| err.contains("process_termination_post_fsync must include an fsync step")
            )
        );
        Ok(())
    }

    #[test]
    fn clean_unmount_must_use_clean_signal() -> Result<()> {
        let mut matrix = fixture_matrix()?;
        let scenario = scenario_by_kind_mut(&mut matrix, "clean_unmount")?;
        scenario.process_control = "sigterm_then_sigkill".to_owned();
        let report = validate_mounted_checkpoint_survivor(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("clean_unmount must use process_control=clean_signal"))
        );
        Ok(())
    }

    #[test]
    fn clean_unmount_must_classify_as_expected() -> Result<()> {
        let mut matrix = fixture_matrix()?;
        let scenario = scenario_by_kind_mut(&mut matrix, "clean_unmount")?;
        scenario.recovery_classification = "host_limitation".to_owned();
        let report = validate_mounted_checkpoint_survivor(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("clean_unmount must classify as expected_survivor_set"))
        );
        Ok(())
    }

    #[test]
    fn kill_minus_nine_refusal_cannot_claim_expected_survivors() -> Result<()> {
        let mut matrix = fixture_matrix()?;
        let scenario = scenario_by_process_control_mut(&mut matrix, "kill_minus_nine_refused")?;
        scenario.recovery_classification = "expected_survivor_set".to_owned();
        let report = validate_mounted_checkpoint_survivor(&matrix);
        assert!(report.errors.iter().any(|err| {
            err.contains("kill_minus_nine_refused cannot also claim expected_survivor_set")
        }));
        Ok(())
    }

    #[test]
    fn crash_lifecycle_must_preserve_partial_artifacts() -> Result<()> {
        let mut matrix = fixture_matrix()?;
        let scenario = scenario_by_kind_mut(&mut matrix, "process_termination_post_fsync")?;
        scenario.partial_artifact_policy = "discard_on_pass".to_owned();
        let report = validate_mounted_checkpoint_survivor(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("crash lifecycle must preserve partial artifacts"))
        );
        Ok(())
    }

    #[test]
    fn empty_recovery_command_is_rejected() -> Result<()> {
        let mut matrix = fixture_matrix()?;
        first_scenario_mut(&mut matrix)?.recovery_command = String::new();
        let report = validate_mounted_checkpoint_survivor(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("recovery_command must not be empty"))
        );
        Ok(())
    }

    #[test]
    fn unsupported_partial_artifact_policy_is_rejected() -> Result<()> {
        let mut matrix = fixture_matrix()?;
        first_scenario_mut(&mut matrix)?.partial_artifact_policy = "throw_them_away".to_owned();
        let report = validate_mounted_checkpoint_survivor(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported partial_artifact_policy"))
        );
        Ok(())
    }

    #[test]
    fn empty_artifact_paths_is_rejected() -> Result<()> {
        let mut matrix = fixture_matrix()?;
        first_scenario_mut(&mut matrix)?.artifact_paths.clear();
        let report = validate_mounted_checkpoint_survivor(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("at least one artifact_path"))
        );
        Ok(())
    }

    #[test]
    fn empty_survivor_set_is_rejected() -> Result<()> {
        let mut matrix = fixture_matrix()?;
        let scenario = first_scenario_mut(&mut matrix)?;
        scenario.expected_survivor_set.present_paths.clear();
        scenario.expected_survivor_set.absent_paths.clear();
        let report = validate_mounted_checkpoint_survivor(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("expected_survivor_set must declare"))
        );
        Ok(())
    }

    #[test]
    fn empty_scenarios_list_is_rejected() -> Result<()> {
        let mut matrix = fixture_matrix()?;
        matrix.scenarios.clear();
        let report = validate_mounted_checkpoint_survivor(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("at least one scenario"))
        );
        Ok(())
    }
}
