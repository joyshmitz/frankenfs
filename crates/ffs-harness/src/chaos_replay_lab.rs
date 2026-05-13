#![forbid(unsafe_code)]

//! Chaos/replay laboratory schedule schema.
//!
//! Tracks bd-rchk0.5.5: defines a deterministic chaos schedule corpus that
//! drives crash-consistency testing under adversarial operation orderings.
//! Each schedule binds a deterministic seed, lane (core_labruntime /
//! mounted_e2e / fixture_dry_run / host_skip), crash-point taxonomy, an
//! operation trace with declared fsync/fsyncdir/commit boundaries, expected
//! survivor classification, repair interaction policy, minimization status,
//! and a replay command. A schedule cannot pass authoritative gates without
//! a fresh deterministic seed, a non-empty operation trace, an explicit
//! crash point, and a survivor expectation.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt::Write as _, fs, path::Path};

pub const CHAOS_REPLAY_LAB_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_CHAOS_REPLAY_LAB_PATH: &str = "tests/chaos-replay-lab/chaos_replay_lab.json";
const DEFAULT_CHAOS_REPLAY_LAB_JSON: &str =
    include_str!("../../../tests/chaos-replay-lab/chaos_replay_lab.json");

const ALLOWED_LANES: [&str; 4] = [
    "core_labruntime",
    "mounted_e2e",
    "fixture_dry_run",
    "host_skip",
];

const ALLOWED_CRASH_TAXONOMY: [&str; 7] = [
    "pre_commit_crash",
    "post_commit_pre_flush_crash",
    "replay_interruption",
    "repair_interruption",
    "concurrent_writer_conflict",
    "metadata_data_ordering_boundary",
    "mount_teardown_race",
];

const ALLOWED_TRACE_OPS: [&str; 9] = [
    "create",
    "write",
    "fsync",
    "fsyncdir",
    "rename",
    "unlink",
    "begin_commit",
    "end_commit",
    "checkpoint_marker",
];

const ALLOWED_REPAIR_POLICIES: [&str; 4] = [
    "no_repair",
    "scrub_detect_only",
    "ledger_repair",
    "interrupted_repair",
];

const ALLOWED_MINIMIZATION_STATUSES: [&str; 4] = [
    "not_minimized",
    "minimized",
    "minimization_in_progress",
    "minimization_blocked",
];

const ALLOWED_SURVIVOR_KINDS: [&str; 4] = [
    "exact_match_pre_crash",
    "exact_match_post_commit",
    "allowed_repaired_divergence",
    "host_skip",
];

const REQUIRED_CRASH_TAXONOMY_COVERAGE: [&str; 5] = [
    "pre_commit_crash",
    "post_commit_pre_flush_crash",
    "replay_interruption",
    "repair_interruption",
    "metadata_data_ordering_boundary",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChaosReplayLab {
    pub schema_version: u32,
    pub lab_id: String,
    pub bead_id: String,
    pub schedules: Vec<ChaosSchedule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChaosSchedule {
    pub schedule_id: String,
    pub seed: u64,
    pub lane: String,
    pub crash_taxonomy: String,
    pub operation_trace: Vec<ScheduleStep>,
    pub crash_point_after_step: u32,
    pub expected_survivor_kind: String,
    pub expected_survivor_paths: Vec<String>,
    pub expected_absent_paths: Vec<String>,
    pub repair_policy: String,
    pub minimization_status: String,
    pub raw_log_path: String,
    pub replay_command: String,
    #[serde(default)]
    pub host_skip_reason: String,
    #[serde(default)]
    pub follow_up_bead: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleStep {
    pub step: u32,
    pub op: String,
    pub args: Vec<String>,
    pub fsync_boundary: bool,
    pub fsyncdir_boundary: bool,
    pub commit_boundary: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChaosReplayLabReport {
    pub schema_version: u32,
    pub lab_id: String,
    pub bead_id: String,
    pub schedule_count: usize,
    pub crash_taxonomies_seen: Vec<String>,
    pub minimized_count: usize,
    pub valid: bool,
    pub errors: Vec<String>,
}

pub fn parse_chaos_replay_lab(text: &str) -> Result<ChaosReplayLab> {
    serde_json::from_str(text)
        .map_err(|err| anyhow::anyhow!("failed to parse chaos replay lab JSON: {err}"))
}

pub fn load_chaos_replay_lab(path: &Path) -> Result<ChaosReplayLab> {
    let text = fs::read_to_string(path)
        .map_err(|err| anyhow::anyhow!("failed to read {}: {err}", path.display()))?;
    parse_chaos_replay_lab(&text)
        .map_err(|err| anyhow::anyhow!("invalid chaos replay lab {}: {err}", path.display()))
}

pub fn validate_default_chaos_replay_lab() -> Result<ChaosReplayLabReport> {
    let lab = parse_chaos_replay_lab(DEFAULT_CHAOS_REPLAY_LAB_JSON)?;
    let report = validate_chaos_replay_lab(&lab);
    fail_on_chaos_replay_lab_errors(&report)?;
    Ok(report)
}

pub fn fail_on_chaos_replay_lab_errors(report: &ChaosReplayLabReport) -> Result<()> {
    if report.valid {
        return Ok(());
    }
    bail!(
        "chaos replay lab failed with {} error(s): {}",
        report.errors.len(),
        report.errors.join("; ")
    );
}

#[must_use]
pub fn validate_chaos_replay_lab(lab: &ChaosReplayLab) -> ChaosReplayLabReport {
    let mut errors = Vec::new();
    let mut ids = BTreeSet::new();
    let mut seeds_seen = BTreeSet::new();
    let mut taxonomies = BTreeSet::new();
    let mut minimized = 0_usize;

    validate_top_level(lab, &mut errors);
    for schedule in &lab.schedules {
        validate_schedule(
            schedule,
            &mut ids,
            &mut seeds_seen,
            &mut taxonomies,
            &mut minimized,
            &mut errors,
        );
    }
    validate_required_taxonomy_coverage(&taxonomies, &mut errors);

    ChaosReplayLabReport {
        schema_version: lab.schema_version,
        lab_id: lab.lab_id.clone(),
        bead_id: lab.bead_id.clone(),
        schedule_count: lab.schedules.len(),
        crash_taxonomies_seen: taxonomies.into_iter().collect(),
        minimized_count: minimized,
        valid: errors.is_empty(),
        errors,
    }
}

fn validate_top_level(lab: &ChaosReplayLab, errors: &mut Vec<String>) {
    if lab.schema_version != CHAOS_REPLAY_LAB_SCHEMA_VERSION {
        errors.push(format!(
            "chaos replay lab schema_version must be {CHAOS_REPLAY_LAB_SCHEMA_VERSION}, got {}",
            lab.schema_version
        ));
    }
    if lab.lab_id.trim().is_empty() {
        errors.push("chaos replay lab missing lab_id".to_owned());
    }
    if !lab.bead_id.starts_with("bd-") {
        errors.push(format!(
            "chaos replay lab bead_id must look like bd-..., got `{}`",
            lab.bead_id
        ));
    }
    if lab.schedules.is_empty() {
        errors.push("chaos replay lab must declare at least one schedule".to_owned());
    }
}

fn validate_schedule(
    schedule: &ChaosSchedule,
    ids: &mut BTreeSet<String>,
    seeds_seen: &mut BTreeSet<u64>,
    taxonomies: &mut BTreeSet<String>,
    minimized: &mut usize,
    errors: &mut Vec<String>,
) {
    if !ids.insert(schedule.schedule_id.clone()) {
        errors.push(format!(
            "duplicate chaos schedule_id `{}`",
            schedule.schedule_id
        ));
    }
    if !schedule.schedule_id.starts_with("chaos_") {
        errors.push(format!(
            "schedule_id `{}` must start with chaos_",
            schedule.schedule_id
        ));
    }
    if schedule.seed == 0 {
        errors.push(format!(
            "schedule `{}` seed must be positive (deterministic replay requires a non-zero seed)",
            schedule.schedule_id
        ));
    }
    if !seeds_seen.insert(schedule.seed) {
        errors.push(format!(
            "schedule `{}` seed `{}` is not unique across the lab",
            schedule.schedule_id, schedule.seed
        ));
    }
    if !ALLOWED_LANES.contains(&schedule.lane.as_str()) {
        errors.push(format!(
            "schedule `{}` has unsupported lane `{}`",
            schedule.schedule_id, schedule.lane
        ));
    }
    if ALLOWED_CRASH_TAXONOMY.contains(&schedule.crash_taxonomy.as_str()) {
        taxonomies.insert(schedule.crash_taxonomy.clone());
    } else {
        errors.push(format!(
            "schedule `{}` has unsupported crash_taxonomy `{}`",
            schedule.schedule_id, schedule.crash_taxonomy
        ));
    }
    if !ALLOWED_REPAIR_POLICIES.contains(&schedule.repair_policy.as_str()) {
        errors.push(format!(
            "schedule `{}` has unsupported repair_policy `{}`",
            schedule.schedule_id, schedule.repair_policy
        ));
    }
    if !ALLOWED_MINIMIZATION_STATUSES.contains(&schedule.minimization_status.as_str()) {
        errors.push(format!(
            "schedule `{}` has unsupported minimization_status `{}`",
            schedule.schedule_id, schedule.minimization_status
        ));
    }
    if schedule.minimization_status == "minimized" {
        *minimized += 1;
    }
    if !ALLOWED_SURVIVOR_KINDS.contains(&schedule.expected_survivor_kind.as_str()) {
        errors.push(format!(
            "schedule `{}` has unsupported expected_survivor_kind `{}`",
            schedule.schedule_id, schedule.expected_survivor_kind
        ));
    }

    validate_schedule_trace(schedule, errors);
    validate_schedule_lane_consistency(schedule, errors);
    validate_schedule_required_text(schedule, errors);
    validate_schedule_repair_policy_consistency(schedule, errors);
}

fn validate_schedule_trace(schedule: &ChaosSchedule, errors: &mut Vec<String>) {
    if schedule.operation_trace.is_empty() && schedule.lane != "host_skip" {
        errors.push(format!(
            "schedule `{}` operation_trace must not be empty for non-skip lanes",
            schedule.schedule_id
        ));
    }
    let mut last_step = 0_u32;
    let mut steps_seen = BTreeSet::new();
    let mut commit_count = 0_u32;
    for step in &schedule.operation_trace {
        if !steps_seen.insert(step.step) {
            errors.push(format!(
                "schedule `{}` trace has duplicate step `{}`",
                schedule.schedule_id, step.step
            ));
        }
        if last_step != 0 && step.step <= last_step {
            errors.push(format!(
                "schedule `{}` trace must be strictly increasing",
                schedule.schedule_id
            ));
        }
        last_step = step.step;
        if !ALLOWED_TRACE_OPS.contains(&step.op.as_str()) {
            errors.push(format!(
                "schedule `{}` step `{}` has unsupported op `{}`",
                schedule.schedule_id, step.step, step.op
            ));
        }
        if step.commit_boundary {
            commit_count += 1;
        }
    }
    if !schedule.operation_trace.is_empty() {
        if schedule.crash_point_after_step == 0 {
            errors.push(format!(
                "schedule `{}` crash_point_after_step must be positive",
                schedule.schedule_id
            ));
        } else if !steps_seen.contains(&schedule.crash_point_after_step) {
            errors.push(format!(
                "schedule `{}` crash_point_after_step `{}` does not match any trace step",
                schedule.schedule_id, schedule.crash_point_after_step
            ));
        }
    }
    if matches!(
        schedule.crash_taxonomy.as_str(),
        "post_commit_pre_flush_crash" | "metadata_data_ordering_boundary"
    ) && commit_count == 0
    {
        errors.push(format!(
            "schedule `{}` crash_taxonomy `{}` requires at least one commit boundary in the trace",
            schedule.schedule_id, schedule.crash_taxonomy
        ));
    }
}

fn validate_schedule_lane_consistency(schedule: &ChaosSchedule, errors: &mut Vec<String>) {
    if schedule.lane == "host_skip" {
        if schedule.expected_survivor_kind != "host_skip" {
            errors.push(format!(
                "schedule `{}` host_skip lane must classify expected_survivor_kind=host_skip",
                schedule.schedule_id
            ));
        }
        if schedule.host_skip_reason.trim().is_empty() {
            errors.push(format!(
                "schedule `{}` host_skip lane must declare host_skip_reason",
                schedule.schedule_id
            ));
        }
    } else if !schedule.host_skip_reason.trim().is_empty() {
        errors.push(format!(
            "schedule `{}` non-host_skip lane must leave host_skip_reason empty",
            schedule.schedule_id
        ));
    }
}

fn validate_schedule_required_text(schedule: &ChaosSchedule, errors: &mut Vec<String>) {
    if schedule.lane != "host_skip"
        && schedule.expected_survivor_paths.is_empty()
        && schedule.expected_absent_paths.is_empty()
    {
        errors.push(format!(
            "schedule `{}` must declare at least one expected_survivor_path or expected_absent_path",
            schedule.schedule_id
        ));
    }
    if schedule.raw_log_path.trim().is_empty() {
        errors.push(format!(
            "schedule `{}` missing raw_log_path",
            schedule.schedule_id
        ));
    }
    if schedule.replay_command.trim().is_empty() {
        errors.push(format!(
            "schedule `{}` missing replay_command",
            schedule.schedule_id
        ));
    }
    if !schedule.follow_up_bead.is_empty() && !schedule.follow_up_bead.starts_with("bd-") {
        errors.push(format!(
            "schedule `{}` follow_up_bead must look like bd-..., got `{}`",
            schedule.schedule_id, schedule.follow_up_bead
        ));
    }
}

fn validate_schedule_repair_policy_consistency(schedule: &ChaosSchedule, errors: &mut Vec<String>) {
    if schedule.crash_taxonomy == "repair_interruption"
        && schedule.repair_policy != "interrupted_repair"
    {
        errors.push(format!(
            "schedule `{}` repair_interruption crash_taxonomy requires repair_policy=interrupted_repair",
            schedule.schedule_id
        ));
    }
    if schedule.expected_survivor_kind == "allowed_repaired_divergence"
        && schedule.repair_policy == "no_repair"
    {
        errors.push(format!(
            "schedule `{}` allowed_repaired_divergence requires a repair_policy other than no_repair",
            schedule.schedule_id
        ));
    }
}

fn validate_required_taxonomy_coverage(seen: &BTreeSet<String>, errors: &mut Vec<String>) {
    for required in REQUIRED_CRASH_TAXONOMY_COVERAGE {
        if !seen.contains(required) {
            errors.push(format!(
                "chaos replay lab missing required crash_taxonomy `{required}`"
            ));
        }
    }
}

#[must_use]
pub fn render_chaos_replay_lab_markdown(report: &ChaosReplayLabReport) -> String {
    let mut output = String::new();
    output.push_str("# Chaos Replay Lab\n\n");
    let _ = writeln!(output, "- lab: `{}`", report.lab_id);
    let _ = writeln!(output, "- schema version: `{}`", report.schema_version);
    let _ = writeln!(output, "- bead: `{}`", report.bead_id);
    let _ = writeln!(output, "- valid: `{}`", report.valid);
    let _ = writeln!(output, "- schedules: `{}`", report.schedule_count);
    let _ = writeln!(
        output,
        "- minimized schedules: `{}`",
        report.minimized_count
    );
    output.push_str("\n## Crash Taxonomies\n");
    for taxonomy in &report.crash_taxonomies_seen {
        let _ = writeln!(output, "- `{taxonomy}`");
    }
    if !report.errors.is_empty() {
        output.push_str("\n## Errors\n");
        for error in &report.errors {
            let _ = writeln!(output, "- {error}");
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_lab() -> Result<ChaosReplayLab> {
        parse_chaos_replay_lab(DEFAULT_CHAOS_REPLAY_LAB_JSON)
    }

    fn first_schedule_mut(lab: &mut ChaosReplayLab) -> Result<&mut ChaosSchedule> {
        let [first, ..] = lab.schedules.as_mut_slice() else {
            bail!("fixture lab must contain at least one schedule");
        };
        Ok(first)
    }

    fn first_two_schedules_mut(
        lab: &mut ChaosReplayLab,
    ) -> Result<(&mut ChaosSchedule, &mut ChaosSchedule)> {
        let [first, second, ..] = lab.schedules.as_mut_slice() else {
            bail!("fixture lab must contain at least two schedules");
        };
        Ok((first, second))
    }

    fn schedule_matching_mut<'a, F>(
        lab: &'a mut ChaosReplayLab,
        description: &str,
        mut predicate: F,
    ) -> Result<&'a mut ChaosSchedule>
    where
        F: FnMut(&ChaosSchedule) -> bool,
    {
        lab.schedules
            .iter_mut()
            .find(|schedule| predicate(schedule))
            .ok_or_else(|| anyhow::anyhow!("fixture lab missing {description} schedule"))
    }

    fn first_two_steps_mut(
        schedule: &mut ChaosSchedule,
    ) -> Result<(&mut ScheduleStep, &mut ScheduleStep)> {
        let [first, second, ..] = schedule.operation_trace.as_mut_slice() else {
            bail!("fixture schedule must contain at least two operation steps");
        };
        Ok((first, second))
    }

    #[test]
    fn default_lab_validates_required_taxonomy_coverage() -> Result<()> {
        let report = validate_default_chaos_replay_lab()?;
        assert_eq!(report.bead_id, "bd-rchk0.5.5");
        for taxonomy in REQUIRED_CRASH_TAXONOMY_COVERAGE {
            assert!(
                report.crash_taxonomies_seen.iter().any(|t| t == taxonomy),
                "missing taxonomy {taxonomy}"
            );
        }
        Ok(())
    }

    #[test]
    fn missing_pre_commit_crash_is_rejected() -> Result<()> {
        let mut lab = fixture_lab()?;
        lab.schedules
            .retain(|s| s.crash_taxonomy != "pre_commit_crash");
        let report = validate_chaos_replay_lab(&lab);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required crash_taxonomy `pre_commit_crash`"))
        );
        Ok(())
    }

    #[test]
    fn missing_repair_interruption_is_rejected() -> Result<()> {
        let mut lab = fixture_lab()?;
        lab.schedules
            .retain(|s| s.crash_taxonomy != "repair_interruption");
        let report = validate_chaos_replay_lab(&lab);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required crash_taxonomy `repair_interruption`"))
        );
        Ok(())
    }

    #[test]
    fn duplicate_schedule_id_is_rejected() -> Result<()> {
        let mut lab = fixture_lab()?;
        let (first, second) = first_two_schedules_mut(&mut lab)?;
        let dup = first.schedule_id.clone();
        second.schedule_id = dup;
        let report = validate_chaos_replay_lab(&lab);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("duplicate chaos schedule_id"))
        );
        Ok(())
    }

    #[test]
    fn schedule_id_prefix_is_enforced() -> Result<()> {
        let mut lab = fixture_lab()?;
        first_schedule_mut(&mut lab)?.schedule_id = "schedule_001".to_owned();
        let report = validate_chaos_replay_lab(&lab);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must start with chaos_"))
        );
        Ok(())
    }

    #[test]
    fn zero_seed_is_rejected() -> Result<()> {
        let mut lab = fixture_lab()?;
        first_schedule_mut(&mut lab)?.seed = 0;
        let report = validate_chaos_replay_lab(&lab);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("seed must be positive"))
        );
        Ok(())
    }

    #[test]
    fn duplicate_seed_is_rejected() -> Result<()> {
        let mut lab = fixture_lab()?;
        let (first, second) = first_two_schedules_mut(&mut lab)?;
        let seed = first.seed;
        second.seed = seed;
        let report = validate_chaos_replay_lab(&lab);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("is not unique across the lab"))
        );
        Ok(())
    }

    #[test]
    fn unsupported_lane_is_rejected() -> Result<()> {
        let mut lab = fixture_lab()?;
        first_schedule_mut(&mut lab)?.lane = "rust_belt".to_owned();
        let report = validate_chaos_replay_lab(&lab);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported lane"))
        );
        Ok(())
    }

    #[test]
    fn unsupported_crash_taxonomy_is_rejected() -> Result<()> {
        let mut lab = fixture_lab()?;
        first_schedule_mut(&mut lab)?.crash_taxonomy = "vibes_taxonomy".to_owned();
        let report = validate_chaos_replay_lab(&lab);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported crash_taxonomy"))
        );
        Ok(())
    }

    #[test]
    fn unsupported_repair_policy_is_rejected() -> Result<()> {
        let mut lab = fixture_lab()?;
        first_schedule_mut(&mut lab)?.repair_policy = "duct_tape".to_owned();
        let report = validate_chaos_replay_lab(&lab);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported repair_policy"))
        );
        Ok(())
    }

    #[test]
    fn unsupported_minimization_status_is_rejected() -> Result<()> {
        let mut lab = fixture_lab()?;
        first_schedule_mut(&mut lab)?.minimization_status = "guesswork".to_owned();
        let report = validate_chaos_replay_lab(&lab);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported minimization_status"))
        );
        Ok(())
    }

    #[test]
    fn empty_operation_trace_is_rejected_for_non_skip_lane() -> Result<()> {
        let mut lab = fixture_lab()?;
        let schedule = schedule_matching_mut(&mut lab, "non-skip", |s| s.lane != "host_skip")?;
        schedule.operation_trace.clear();
        let report = validate_chaos_replay_lab(&lab);
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
        let mut lab = fixture_lab()?;
        let schedule = first_schedule_mut(&mut lab)?;
        let (first, second) = first_two_steps_mut(schedule)?;
        second.step = first.step;
        let report = validate_chaos_replay_lab(&lab);
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
        let mut lab = fixture_lab()?;
        first_schedule_mut(&mut lab)?.crash_point_after_step = 9999;
        let report = validate_chaos_replay_lab(&lab);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("does not match any trace step"))
        );
        Ok(())
    }

    #[test]
    fn post_commit_taxonomy_requires_commit_boundary() -> Result<()> {
        let mut lab = fixture_lab()?;
        let schedule = schedule_matching_mut(&mut lab, "post-commit", |s| {
            s.crash_taxonomy == "post_commit_pre_flush_crash"
        })?;
        for step in &mut schedule.operation_trace {
            step.commit_boundary = false;
        }
        let report = validate_chaos_replay_lab(&lab);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("requires at least one commit boundary in the trace"))
        );
        Ok(())
    }

    #[test]
    fn host_skip_lane_must_classify_as_host_skip() -> Result<()> {
        let mut lab = fixture_lab()?;
        let schedule = schedule_matching_mut(&mut lab, "host_skip", |s| s.lane == "host_skip")?;
        schedule.expected_survivor_kind = "exact_match_post_commit".to_owned();
        let report = validate_chaos_replay_lab(&lab);
        assert!(report.errors.iter().any(|err| {
            err.contains("host_skip lane must classify expected_survivor_kind=host_skip")
        }));
        Ok(())
    }

    #[test]
    fn host_skip_lane_requires_skip_reason() -> Result<()> {
        let mut lab = fixture_lab()?;
        let schedule = schedule_matching_mut(&mut lab, "host_skip", |s| s.lane == "host_skip")?;
        schedule.host_skip_reason = String::new();
        let report = validate_chaos_replay_lab(&lab);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must declare host_skip_reason"))
        );
        Ok(())
    }

    #[test]
    fn non_host_skip_must_leave_skip_reason_empty() -> Result<()> {
        let mut lab = fixture_lab()?;
        let schedule = schedule_matching_mut(&mut lab, "non-skip", |s| s.lane != "host_skip")?;
        schedule.host_skip_reason = "leftover".to_owned();
        let report = validate_chaos_replay_lab(&lab);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("non-host_skip lane must leave host_skip_reason empty"))
        );
        Ok(())
    }

    #[test]
    fn empty_survivor_set_is_rejected() -> Result<()> {
        let mut lab = fixture_lab()?;
        let schedule = schedule_matching_mut(&mut lab, "non-skip", |s| s.lane != "host_skip")?;
        schedule.expected_survivor_paths.clear();
        schedule.expected_absent_paths.clear();
        let report = validate_chaos_replay_lab(&lab);
        assert!(report.errors.iter().any(|err| {
            err.contains("must declare at least one expected_survivor_path or expected_absent_path")
        }));
        Ok(())
    }

    #[test]
    fn missing_raw_log_path_is_rejected() -> Result<()> {
        let mut lab = fixture_lab()?;
        first_schedule_mut(&mut lab)?.raw_log_path = String::new();
        let report = validate_chaos_replay_lab(&lab);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing raw_log_path"))
        );
        Ok(())
    }

    #[test]
    fn missing_replay_command_is_rejected() -> Result<()> {
        let mut lab = fixture_lab()?;
        first_schedule_mut(&mut lab)?.replay_command = String::new();
        let report = validate_chaos_replay_lab(&lab);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing replay_command"))
        );
        Ok(())
    }

    #[test]
    fn malformed_follow_up_bead_is_rejected() -> Result<()> {
        let mut lab = fixture_lab()?;
        first_schedule_mut(&mut lab)?.follow_up_bead = "PROJ-99".to_owned();
        let report = validate_chaos_replay_lab(&lab);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("follow_up_bead must look like bd-"))
        );
        Ok(())
    }

    #[test]
    fn repair_interruption_taxonomy_requires_interrupted_repair_policy() -> Result<()> {
        let mut lab = fixture_lab()?;
        let schedule = schedule_matching_mut(&mut lab, "repair interruption", |s| {
            s.crash_taxonomy == "repair_interruption"
        })?;
        schedule.repair_policy = "ledger_repair".to_owned();
        let report = validate_chaos_replay_lab(&lab);
        assert!(report.errors.iter().any(|err| err.contains(
            "repair_interruption crash_taxonomy requires repair_policy=interrupted_repair"
        )));
        Ok(())
    }

    #[test]
    fn allowed_repaired_divergence_requires_real_repair_policy() -> Result<()> {
        let mut lab = fixture_lab()?;
        let schedule = schedule_matching_mut(&mut lab, "repaired divergence", |s| {
            s.expected_survivor_kind == "allowed_repaired_divergence"
        })?;
        schedule.repair_policy = "no_repair".to_owned();
        let report = validate_chaos_replay_lab(&lab);
        assert!(report.errors.iter().any(|err| err.contains(
            "allowed_repaired_divergence requires a repair_policy other than no_repair"
        )));
        Ok(())
    }

    #[test]
    fn empty_schedules_list_is_rejected() -> Result<()> {
        let mut lab = fixture_lab()?;
        lab.schedules.clear();
        let report = validate_chaos_replay_lab(&lab);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("at least one schedule"))
        );
        Ok(())
    }

    #[test]
    fn render_chaos_replay_lab_markdown_default_lab() -> Result<()> {
        let report = validate_default_chaos_replay_lab()?;
        let markdown = render_chaos_replay_lab_markdown(&report);
        insta::assert_snapshot!("render_chaos_replay_lab_markdown_default_lab", markdown);
        Ok(())
    }

    #[test]
    fn chaos_replay_lab_report_json_shape() -> Result<()> {
        let report = validate_default_chaos_replay_lab()?;
        let json = serde_json::to_string_pretty(&report)?;

        insta::assert_snapshot!("chaos_replay_lab_report_json_shape", json);
        let parsed: ChaosReplayLabReport = serde_json::from_str(&json)?;
        assert_eq!(parsed, report);
        Ok(())
    }

    #[test]
    fn fail_on_errors_rejects_invalid_report() -> Result<()> {
        let mut report = validate_default_chaos_replay_lab()?;
        report.valid = false;
        report
            .errors
            .push("fixture mutation erased replay command".to_owned());
        let Err(err) = fail_on_chaos_replay_lab_errors(&report) else {
            bail!("invalid report must fail closed");
        };
        assert!(err.to_string().contains("chaos replay lab failed"));
        Ok(())
    }
}
