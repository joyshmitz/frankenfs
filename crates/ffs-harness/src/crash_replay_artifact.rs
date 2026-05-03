#![forbid(unsafe_code)]

//! Crash replay proof artifact schema with survivor-set verification.
//!
//! Tracks bd-nk49l: every crash replay artifact must declare schedule
//! identity, seed, lane type, crash taxonomy, pre-crash and post-replay image
//! hashes, expected and observed survivor sets, oracle verdict, minimization
//! status, raw-log path, and reproduction command. The verdict comparator
//! classifies survivor-set divergences so release gates and proof-bundle
//! consumers can fail closed without re-reading raw logs.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const CRASH_REPLAY_ARTIFACT_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_CRASH_REPLAY_ARTIFACT_PATH: &str =
    "tests/crash-replay-artifact/crash_replay_artifact.json";
const DEFAULT_CRASH_REPLAY_ARTIFACT_JSON: &str =
    include_str!("../../../tests/crash-replay-artifact/crash_replay_artifact.json");

const ALLOWED_LANE_TYPES: [&str; 4] = [
    "core_labruntime",
    "mounted_e2e",
    "fixture_dry_run",
    "host_skip",
];

const ALLOWED_CRASH_TAXONOMY: [&str; 8] = [
    "pre_commit_crash",
    "post_commit_pre_flush_crash",
    "replay_interruption",
    "repair_interruption",
    "concurrent_writer_conflict",
    "metadata_data_ordering_boundary",
    "mount_teardown_race",
    "no_crash_baseline",
];

const ALLOWED_ORACLE_VERDICTS: [&str; 8] = [
    "exact_match",
    "allowed_repaired_divergence",
    "missing_file",
    "unexpected_extra_file",
    "metadata_only_mismatch",
    "unsupported_host_skip",
    "replay_failure",
    "inconclusive",
];

const ALLOWED_MINIMIZATION_STATUSES: [&str; 4] = [
    "not_minimized",
    "minimized",
    "minimization_in_progress",
    "minimization_blocked",
];

const FAIL_CLOSED_VERDICTS: [&str; 4] = [
    "missing_file",
    "unexpected_extra_file",
    "metadata_only_mismatch",
    "replay_failure",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrashReplayArtifact {
    pub schema_version: u32,
    pub artifact_id: String,
    pub bead_id: String,
    pub schedule_id: String,
    pub seed: u64,
    pub lane_type: String,
    pub crash_taxonomy: String,
    pub pre_crash_image_hash: String,
    pub post_replay_image_hash: String,
    pub expected_survivors: SurvivorSet,
    pub observed_survivors: SurvivorSet,
    pub operation_trace: Vec<CrashOperationStep>,
    pub repair_actions: Vec<String>,
    pub oracle_verdict: String,
    pub minimization_status: String,
    pub raw_log_path: String,
    pub reproduction_command: String,
    #[serde(default)]
    pub follow_up_bead: String,
    #[serde(default)]
    pub follow_up_skip_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurvivorSet {
    pub present_paths: Vec<SurvivorEntry>,
    pub absent_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurvivorEntry {
    pub path: String,
    pub byte_size: u64,
    pub xattr_keys: Vec<String>,
    pub mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrashOperationStep {
    pub step: u32,
    pub op: String,
    pub args: Vec<String>,
    pub crash_point_after: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrashReplayArtifactReport {
    pub schema_version: u32,
    pub artifact_id: String,
    pub bead_id: String,
    pub lane_type: String,
    pub oracle_verdict: String,
    pub fail_closed: bool,
    pub valid: bool,
    pub errors: Vec<String>,
}

pub fn parse_crash_replay_artifact(text: &str) -> Result<CrashReplayArtifact> {
    serde_json::from_str(text)
        .map_err(|err| anyhow::anyhow!("failed to parse crash replay artifact JSON: {err}"))
}

pub fn validate_default_crash_replay_artifact() -> Result<CrashReplayArtifactReport> {
    let artifact = parse_crash_replay_artifact(DEFAULT_CRASH_REPLAY_ARTIFACT_JSON)?;
    let report = validate_crash_replay_artifact(&artifact);
    if !report.valid {
        bail!(
            "crash replay artifact failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        );
    }
    Ok(report)
}

#[must_use]
pub fn validate_crash_replay_artifact(artifact: &CrashReplayArtifact) -> CrashReplayArtifactReport {
    let mut errors = Vec::new();
    validate_artifact_top_level(artifact, &mut errors);
    validate_artifact_vocabulary(artifact, &mut errors);
    validate_artifact_required_text(artifact, &mut errors);
    validate_artifact_image_hashes(artifact, &mut errors);
    validate_artifact_operation_trace(artifact, &mut errors);
    validate_artifact_follow_up(artifact, &mut errors);
    let fail_closed = FAIL_CLOSED_VERDICTS.contains(&artifact.oracle_verdict.as_str());
    CrashReplayArtifactReport {
        schema_version: artifact.schema_version,
        artifact_id: artifact.artifact_id.clone(),
        bead_id: artifact.bead_id.clone(),
        lane_type: artifact.lane_type.clone(),
        oracle_verdict: artifact.oracle_verdict.clone(),
        fail_closed,
        valid: errors.is_empty(),
        errors,
    }
}

fn validate_artifact_top_level(artifact: &CrashReplayArtifact, errors: &mut Vec<String>) {
    if artifact.schema_version != CRASH_REPLAY_ARTIFACT_SCHEMA_VERSION {
        errors.push(format!(
            "crash replay artifact schema_version must be {CRASH_REPLAY_ARTIFACT_SCHEMA_VERSION}, got {}",
            artifact.schema_version
        ));
    }
    if artifact.artifact_id.trim().is_empty() {
        errors.push("crash replay artifact missing artifact_id".to_owned());
    }
    if !artifact.bead_id.starts_with("bd-") {
        errors.push(format!(
            "crash replay artifact bead_id must look like bd-..., got `{}`",
            artifact.bead_id
        ));
    }
    if artifact.schedule_id.trim().is_empty() {
        errors.push("crash replay artifact missing schedule_id".to_owned());
    }
    if artifact.seed == 0 {
        errors.push("crash replay artifact seed must be positive".to_owned());
    }
}

fn validate_artifact_vocabulary(artifact: &CrashReplayArtifact, errors: &mut Vec<String>) {
    if !ALLOWED_LANE_TYPES.contains(&artifact.lane_type.as_str()) {
        errors.push(format!(
            "crash replay artifact `{}` has unsupported lane_type `{}`",
            artifact.artifact_id, artifact.lane_type
        ));
    }
    if !ALLOWED_CRASH_TAXONOMY.contains(&artifact.crash_taxonomy.as_str()) {
        errors.push(format!(
            "crash replay artifact `{}` has unsupported crash_taxonomy `{}`",
            artifact.artifact_id, artifact.crash_taxonomy
        ));
    }
    if !ALLOWED_ORACLE_VERDICTS.contains(&artifact.oracle_verdict.as_str()) {
        errors.push(format!(
            "crash replay artifact `{}` has unsupported oracle_verdict `{}`",
            artifact.artifact_id, artifact.oracle_verdict
        ));
    }
    if !ALLOWED_MINIMIZATION_STATUSES.contains(&artifact.minimization_status.as_str()) {
        errors.push(format!(
            "crash replay artifact `{}` has unsupported minimization_status `{}`",
            artifact.artifact_id, artifact.minimization_status
        ));
    }
}

fn validate_artifact_required_text(artifact: &CrashReplayArtifact, errors: &mut Vec<String>) {
    let required = [
        ("raw_log_path", &artifact.raw_log_path),
        ("reproduction_command", &artifact.reproduction_command),
    ];
    for (field, value) in required {
        if value.trim().is_empty() {
            errors.push(format!(
                "crash replay artifact `{}` missing {field}",
                artifact.artifact_id
            ));
        }
    }
}

fn validate_artifact_image_hashes(artifact: &CrashReplayArtifact, errors: &mut Vec<String>) {
    if !is_valid_sha256(&artifact.pre_crash_image_hash) {
        errors.push(format!(
            "crash replay artifact `{}` pre_crash_image_hash must be sha256:<64-hex>",
            artifact.artifact_id
        ));
    }
    let post_required = artifact.lane_type != "host_skip"
        && artifact.oracle_verdict != "unsupported_host_skip"
        && artifact.oracle_verdict != "replay_failure";
    if post_required && !is_valid_sha256(&artifact.post_replay_image_hash) {
        errors.push(format!(
            "crash replay artifact `{}` post_replay_image_hash must be sha256:<64-hex>",
            artifact.artifact_id
        ));
    }
}

fn validate_artifact_operation_trace(artifact: &CrashReplayArtifact, errors: &mut Vec<String>) {
    if artifact.lane_type != "host_skip"
        && artifact.oracle_verdict != "unsupported_host_skip"
        && artifact.operation_trace.is_empty()
    {
        errors.push(format!(
            "crash replay artifact `{}` must declare operation_trace for non-skip lanes",
            artifact.artifact_id
        ));
    }
    let mut last_step = 0_u32;
    let mut crash_points = 0_u32;
    for step in &artifact.operation_trace {
        if step.step <= last_step && last_step != 0 {
            errors.push(format!(
                "crash replay artifact `{}` operation_trace steps must be strictly increasing",
                artifact.artifact_id
            ));
        }
        last_step = step.step;
        if step.op.trim().is_empty() {
            errors.push(format!(
                "crash replay artifact `{}` operation_trace step {} missing op",
                artifact.artifact_id, step.step
            ));
        }
        if step.crash_point_after {
            crash_points += 1;
        }
    }
    if artifact.crash_taxonomy != "no_crash_baseline"
        && !artifact.operation_trace.is_empty()
        && crash_points == 0
    {
        errors.push(format!(
            "crash replay artifact `{}` operation_trace must declare a crash_point_after step",
            artifact.artifact_id
        ));
    }
}

fn validate_artifact_follow_up(artifact: &CrashReplayArtifact, errors: &mut Vec<String>) {
    if artifact.oracle_verdict == "exact_match"
        || artifact.oracle_verdict == "allowed_repaired_divergence"
    {
        if !artifact.follow_up_bead.is_empty() {
            errors.push(format!(
                "crash replay artifact `{}` passing verdict must leave follow_up_bead empty",
                artifact.artifact_id
            ));
        }
        return;
    }
    if artifact.oracle_verdict == "unsupported_host_skip" {
        if artifact.follow_up_skip_reason.trim().is_empty() {
            errors.push(format!(
                "crash replay artifact `{}` host skip verdict must declare follow_up_skip_reason",
                artifact.artifact_id
            ));
        }
        return;
    }
    if artifact.follow_up_bead.trim().is_empty() && artifact.follow_up_skip_reason.trim().is_empty()
    {
        errors.push(format!(
            "crash replay artifact `{}` failing verdict must declare follow_up_bead or follow_up_skip_reason",
            artifact.artifact_id
        ));
    }
    if !artifact.follow_up_bead.is_empty() && !artifact.follow_up_bead.starts_with("bd-") {
        errors.push(format!(
            "crash replay artifact `{}` follow_up_bead must look like bd-..., got `{}`",
            artifact.artifact_id, artifact.follow_up_bead
        ));
    }
}

#[must_use]
pub fn classify_survivor_divergence(
    expected: &SurvivorSet,
    observed: &SurvivorSet,
) -> SurvivorDivergence {
    let expected_paths: BTreeMap<&str, &SurvivorEntry> = expected
        .present_paths
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    let observed_paths: BTreeMap<&str, &SurvivorEntry> = observed
        .present_paths
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();

    let expected_keys: BTreeSet<&&str> = expected_paths.keys().collect();
    let observed_keys: BTreeSet<&&str> = observed_paths.keys().collect();

    let missing: Vec<String> = expected_keys
        .difference(&observed_keys)
        .map(|path| (**path).to_owned())
        .collect();
    let extra: Vec<String> = observed_keys
        .difference(&expected_keys)
        .map(|path| (**path).to_owned())
        .collect();

    if !missing.is_empty() {
        return SurvivorDivergence::MissingFile { missing };
    }
    if !extra.is_empty() {
        return SurvivorDivergence::UnexpectedExtraFile { extra };
    }

    let mut metadata_only_paths = Vec::new();
    let mut data_mismatch_paths = Vec::new();
    for (path, expected_entry) in &expected_paths {
        let Some(observed_entry) = observed_paths.get(path) else {
            continue;
        };
        let bytes_match = expected_entry.byte_size == observed_entry.byte_size;
        let xattrs_match = expected_entry.xattr_keys == observed_entry.xattr_keys;
        let mode_match = expected_entry.mode == observed_entry.mode;
        if !bytes_match {
            data_mismatch_paths.push((*path).to_owned());
        } else if !(xattrs_match && mode_match) {
            metadata_only_paths.push((*path).to_owned());
        }
    }
    if !data_mismatch_paths.is_empty() {
        return SurvivorDivergence::MissingFile {
            missing: data_mismatch_paths,
        };
    }
    if !metadata_only_paths.is_empty() {
        return SurvivorDivergence::MetadataOnlyMismatch {
            paths: metadata_only_paths,
        };
    }

    let expected_absent: BTreeSet<&str> =
        expected.absent_paths.iter().map(String::as_str).collect();
    let observed_absent: BTreeSet<&str> =
        observed.absent_paths.iter().map(String::as_str).collect();
    let missing_absent: Vec<String> = expected_absent
        .difference(&observed_absent)
        .map(|path| (*path).to_owned())
        .collect();
    if !missing_absent.is_empty() {
        return SurvivorDivergence::UnexpectedExtraFile {
            extra: missing_absent,
        };
    }

    SurvivorDivergence::ExactMatch
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SurvivorDivergence {
    ExactMatch,
    MissingFile { missing: Vec<String> },
    UnexpectedExtraFile { extra: Vec<String> },
    MetadataOnlyMismatch { paths: Vec<String> },
}

impl SurvivorDivergence {
    #[must_use]
    pub fn verdict_token(&self) -> &'static str {
        match self {
            Self::ExactMatch => "exact_match",
            Self::MissingFile { .. } => "missing_file",
            Self::UnexpectedExtraFile { .. } => "unexpected_extra_file",
            Self::MetadataOnlyMismatch { .. } => "metadata_only_mismatch",
        }
    }
}

fn is_valid_sha256(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("sha256:") else {
        return false;
    };
    suffix.len() == 64 && suffix.chars().all(|ch| ch.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_artifact() -> CrashReplayArtifact {
        parse_crash_replay_artifact(DEFAULT_CRASH_REPLAY_ARTIFACT_JSON)
            .expect("default crash replay artifact parses")
    }

    #[test]
    fn default_artifact_validates() {
        let report = validate_default_crash_replay_artifact()
            .expect("default crash replay artifact validates");
        assert_eq!(report.schema_version, CRASH_REPLAY_ARTIFACT_SCHEMA_VERSION);
        assert_eq!(report.bead_id, "bd-nk49l");
        assert_eq!(report.oracle_verdict, "exact_match");
        assert!(!report.fail_closed);
    }

    #[test]
    fn missing_schedule_id_is_rejected() {
        let mut artifact = fixture_artifact();
        artifact.schedule_id = String::new();
        let report = validate_crash_replay_artifact(&artifact);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing schedule_id"))
        );
    }

    #[test]
    fn zero_seed_is_rejected() {
        let mut artifact = fixture_artifact();
        artifact.seed = 0;
        let report = validate_crash_replay_artifact(&artifact);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("seed must be positive"))
        );
    }

    #[test]
    fn unsupported_lane_type_is_rejected() {
        let mut artifact = fixture_artifact();
        artifact.lane_type = "speculative_simulation".to_owned();
        let report = validate_crash_replay_artifact(&artifact);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported lane_type"))
        );
    }

    #[test]
    fn unsupported_crash_taxonomy_is_rejected() {
        let mut artifact = fixture_artifact();
        artifact.crash_taxonomy = "vibes_taxonomy".to_owned();
        let report = validate_crash_replay_artifact(&artifact);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported crash_taxonomy"))
        );
    }

    #[test]
    fn unsupported_oracle_verdict_is_rejected() {
        let mut artifact = fixture_artifact();
        artifact.oracle_verdict = "kinda_passed".to_owned();
        let report = validate_crash_replay_artifact(&artifact);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported oracle_verdict"))
        );
    }

    #[test]
    fn unsupported_minimization_status_is_rejected() {
        let mut artifact = fixture_artifact();
        artifact.minimization_status = "guesswork".to_owned();
        let report = validate_crash_replay_artifact(&artifact);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported minimization_status"))
        );
    }

    #[test]
    fn malformed_pre_crash_hash_is_rejected() {
        let mut artifact = fixture_artifact();
        artifact.pre_crash_image_hash = "md5:not-supported".to_owned();
        let report = validate_crash_replay_artifact(&artifact);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("pre_crash_image_hash must be sha256"))
        );
    }

    #[test]
    fn missing_post_replay_hash_is_rejected_for_non_skip_lane() {
        let mut artifact = fixture_artifact();
        artifact.post_replay_image_hash = String::new();
        let report = validate_crash_replay_artifact(&artifact);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("post_replay_image_hash must be sha256"))
        );
    }

    #[test]
    fn host_skip_lane_does_not_require_post_replay_hash() {
        let mut artifact = fixture_artifact();
        artifact.lane_type = "host_skip".to_owned();
        artifact.oracle_verdict = "unsupported_host_skip".to_owned();
        artifact.post_replay_image_hash = String::new();
        artifact.follow_up_bead = String::new();
        artifact.follow_up_skip_reason = "host has no /dev/fuse".to_owned();
        let report = validate_crash_replay_artifact(&artifact);
        assert!(
            report.valid,
            "host skip should not require post_replay_image_hash: {:?}",
            report.errors
        );
    }

    #[test]
    fn empty_operation_trace_is_rejected_for_non_skip_lane() {
        let mut artifact = fixture_artifact();
        artifact.operation_trace.clear();
        let report = validate_crash_replay_artifact(&artifact);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must declare operation_trace"))
        );
    }

    #[test]
    fn operation_trace_steps_must_increase() {
        let mut artifact = fixture_artifact();
        if artifact.operation_trace.len() >= 2 {
            artifact.operation_trace[1].step = artifact.operation_trace[0].step;
        }
        let report = validate_crash_replay_artifact(&artifact);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("strictly increasing"))
        );
    }

    #[test]
    fn missing_crash_point_marker_is_rejected() {
        let mut artifact = fixture_artifact();
        for step in &mut artifact.operation_trace {
            step.crash_point_after = false;
        }
        let report = validate_crash_replay_artifact(&artifact);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("declare a crash_point_after step"))
        );
    }

    #[test]
    fn failing_verdict_requires_follow_up_bead_or_skip_reason() {
        let mut artifact = fixture_artifact();
        artifact.oracle_verdict = "missing_file".to_owned();
        artifact.follow_up_bead = String::new();
        artifact.follow_up_skip_reason = String::new();
        let report = validate_crash_replay_artifact(&artifact);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must declare follow_up_bead or follow_up_skip_reason"))
        );
    }

    #[test]
    fn passing_verdict_must_not_carry_follow_up_bead() {
        let mut artifact = fixture_artifact();
        artifact.follow_up_bead = "bd-followup".to_owned();
        let report = validate_crash_replay_artifact(&artifact);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("passing verdict must leave follow_up_bead empty"))
        );
    }

    #[test]
    fn malformed_follow_up_bead_is_rejected() {
        let mut artifact = fixture_artifact();
        artifact.oracle_verdict = "missing_file".to_owned();
        artifact.follow_up_bead = "PROJ-99".to_owned();
        let report = validate_crash_replay_artifact(&artifact);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("follow_up_bead must look like bd-"))
        );
    }

    #[test]
    fn fail_closed_flag_is_set_for_replay_failure() {
        let mut artifact = fixture_artifact();
        artifact.oracle_verdict = "replay_failure".to_owned();
        artifact.follow_up_bead = "bd-replay-followup".to_owned();
        let report = validate_crash_replay_artifact(&artifact);
        assert!(report.fail_closed);
    }

    fn entry(path: &str, byte_size: u64, xattrs: &[&str], mode: &str) -> SurvivorEntry {
        SurvivorEntry {
            path: path.to_owned(),
            byte_size,
            xattr_keys: xattrs.iter().map(|s| (*s).to_owned()).collect(),
            mode: mode.to_owned(),
        }
    }

    fn survivor_set(present: &[SurvivorEntry], absent: &[&str]) -> SurvivorSet {
        SurvivorSet {
            present_paths: present.to_vec(),
            absent_paths: absent.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn classify_survivor_exact_match() {
        let expected = survivor_set(&[entry("/a", 16, &[], "0644")], &["/b"]);
        let observed = expected.clone();
        assert_eq!(
            classify_survivor_divergence(&expected, &observed),
            SurvivorDivergence::ExactMatch
        );
    }

    #[test]
    fn classify_survivor_missing_file() {
        let expected = survivor_set(
            &[entry("/a", 16, &[], "0644"), entry("/b", 8, &[], "0644")],
            &[],
        );
        let observed = survivor_set(&[entry("/a", 16, &[], "0644")], &[]);
        let divergence = classify_survivor_divergence(&expected, &observed);
        assert_eq!(divergence.verdict_token(), "missing_file");
    }

    #[test]
    fn classify_survivor_unexpected_extra() {
        let expected = survivor_set(&[entry("/a", 16, &[], "0644")], &[]);
        let observed = survivor_set(
            &[entry("/a", 16, &[], "0644"), entry("/b", 8, &[], "0644")],
            &[],
        );
        let divergence = classify_survivor_divergence(&expected, &observed);
        assert_eq!(divergence.verdict_token(), "unexpected_extra_file");
    }

    #[test]
    fn classify_survivor_metadata_only_mismatch() {
        let expected = survivor_set(&[entry("/a", 16, &["user.k"], "0644")], &[]);
        let observed = survivor_set(&[entry("/a", 16, &[], "0644")], &[]);
        let divergence = classify_survivor_divergence(&expected, &observed);
        assert_eq!(divergence.verdict_token(), "metadata_only_mismatch");
    }

    #[test]
    fn classify_survivor_data_mismatch_is_missing_file_class() {
        let expected = survivor_set(&[entry("/a", 16, &[], "0644")], &[]);
        let observed = survivor_set(&[entry("/a", 32, &[], "0644")], &[]);
        let divergence = classify_survivor_divergence(&expected, &observed);
        assert_eq!(divergence.verdict_token(), "missing_file");
    }

    #[test]
    fn classify_survivor_absent_path_violation_is_extra_file() {
        let expected = survivor_set(&[entry("/a", 16, &[], "0644")], &["/b"]);
        let observed = survivor_set(&[entry("/a", 16, &[], "0644")], &[]);
        let divergence = classify_survivor_divergence(&expected, &observed);
        assert_eq!(divergence.verdict_token(), "unexpected_extra_file");
    }
}
