#![forbid(unsafe_code)]

//! Low-privilege local trust demo manifest.
//!
//! Tracks bd-rchk0.5.13: a deterministic local-demo manifest that runs without
//! FUSE permissions and still proves real behavior. Each lane row binds a
//! lane id, capability requirement (none, fuse, sudo, btrfs_progs, host_skip),
//! supported execution kind (parser_unit, invariant_oracle, repair_dry_run,
//! release_gate_eval, mounted_smoke), expected proof artifact path, fixture
//! source, expected outcome (executed, host_skipped, capability_blocked), and
//! capability check command. Mounted lanes that cannot run on the current
//! host MUST be recorded as structured host skips, not silently absent.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const LOW_PRIVILEGE_DEMO_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_LOW_PRIVILEGE_DEMO_PATH: &str =
    "tests/low-privilege-demo/low_privilege_demo_manifest.json";
const DEFAULT_LOW_PRIVILEGE_DEMO_JSON: &str =
    include_str!("../../../tests/low-privilege-demo/low_privilege_demo_manifest.json");

const ALLOWED_CAPABILITY_REQUIREMENTS: [&str; 5] =
    ["none", "fuse", "sudo", "btrfs_progs", "host_skip"];

const ALLOWED_EXECUTION_KINDS: [&str; 5] = [
    "parser_unit",
    "invariant_oracle",
    "repair_dry_run",
    "release_gate_eval",
    "mounted_smoke",
];

const ALLOWED_OUTCOMES: [&str; 3] = ["executed", "host_skipped", "capability_blocked"];

const REQUIRED_LOW_PRIVILEGE_KINDS: [&str; 3] =
    ["parser_unit", "invariant_oracle", "repair_dry_run"];

const REQUIRED_HOST_SKIPPED_LANES: [&str; 1] = ["mounted_smoke"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowPrivilegeDemoManifest {
    pub schema_version: u32,
    pub manifest_id: String,
    pub bead_id: String,
    pub git_sha: String,
    pub toolchain: String,
    pub kernel: String,
    pub command_line: String,
    pub working_directory_policy: String,
    pub lanes: Vec<LowPrivilegeDemoLane>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowPrivilegeDemoLane {
    pub lane_id: String,
    pub execution_kind: String,
    pub capability_requirement: String,
    pub fixture_source: String,
    pub fixture_hash: String,
    pub capability_check_command: String,
    pub expected_outcome: String,
    pub expected_artifact_path: String,
    #[serde(default)]
    pub host_skip_reason: String,
    pub reproduction_command: String,
    pub cleanup_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowPrivilegeDemoReport {
    pub schema_version: u32,
    pub manifest_id: String,
    pub bead_id: String,
    pub lane_count: usize,
    pub low_privilege_kinds: Vec<String>,
    pub host_skipped_lanes: Vec<String>,
    pub valid: bool,
    pub errors: Vec<String>,
}

pub fn parse_low_privilege_demo_manifest(text: &str) -> Result<LowPrivilegeDemoManifest> {
    serde_json::from_str(text)
        .map_err(|err| anyhow::anyhow!("failed to parse low-privilege demo manifest JSON: {err}"))
}

pub fn validate_default_low_privilege_demo_manifest() -> Result<LowPrivilegeDemoReport> {
    let manifest = parse_low_privilege_demo_manifest(DEFAULT_LOW_PRIVILEGE_DEMO_JSON)?;
    let report = validate_low_privilege_demo_manifest(&manifest);
    if !report.valid {
        bail!(
            "low-privilege demo manifest failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        );
    }
    Ok(report)
}

#[must_use]
pub fn validate_low_privilege_demo_manifest(
    manifest: &LowPrivilegeDemoManifest,
) -> LowPrivilegeDemoReport {
    let mut errors = Vec::new();
    let mut ids = BTreeSet::new();
    let mut low_privilege_kinds = BTreeSet::new();
    let mut host_skipped_lanes = BTreeSet::new();

    validate_top_level(manifest, &mut errors);
    for lane in &manifest.lanes {
        validate_lane(
            lane,
            &mut ids,
            &mut low_privilege_kinds,
            &mut host_skipped_lanes,
            &mut errors,
        );
    }
    validate_required_low_privilege_coverage(&low_privilege_kinds, &mut errors);
    validate_required_host_skipped_coverage(&host_skipped_lanes, &mut errors);

    LowPrivilegeDemoReport {
        schema_version: manifest.schema_version,
        manifest_id: manifest.manifest_id.clone(),
        bead_id: manifest.bead_id.clone(),
        lane_count: manifest.lanes.len(),
        low_privilege_kinds: low_privilege_kinds.into_iter().collect(),
        host_skipped_lanes: host_skipped_lanes.into_iter().collect(),
        valid: errors.is_empty(),
        errors,
    }
}

fn validate_top_level(manifest: &LowPrivilegeDemoManifest, errors: &mut Vec<String>) {
    if manifest.schema_version != LOW_PRIVILEGE_DEMO_SCHEMA_VERSION {
        errors.push(format!(
            "low-privilege demo manifest schema_version must be {LOW_PRIVILEGE_DEMO_SCHEMA_VERSION}, got {}",
            manifest.schema_version
        ));
    }
    if manifest.manifest_id.trim().is_empty() {
        errors.push("low-privilege demo manifest missing manifest_id".to_owned());
    }
    if !manifest.bead_id.starts_with("bd-") {
        errors.push(format!(
            "low-privilege demo manifest bead_id must look like bd-..., got `{}`",
            manifest.bead_id
        ));
    }
    if manifest.git_sha.trim().is_empty() {
        errors.push("low-privilege demo manifest missing git_sha".to_owned());
    }
    if manifest.toolchain.trim().is_empty() {
        errors.push("low-privilege demo manifest missing toolchain".to_owned());
    }
    if manifest.kernel.trim().is_empty() {
        errors.push("low-privilege demo manifest missing kernel".to_owned());
    }
    if manifest.command_line.trim().is_empty() {
        errors.push("low-privilege demo manifest missing command_line".to_owned());
    }
    if manifest.working_directory_policy.trim().is_empty() {
        errors.push("low-privilege demo manifest missing working_directory_policy".to_owned());
    }
    if manifest.lanes.is_empty() {
        errors.push("low-privilege demo manifest must declare at least one lane".to_owned());
    }
}

fn validate_lane(
    lane: &LowPrivilegeDemoLane,
    ids: &mut BTreeSet<String>,
    low_privilege_kinds: &mut BTreeSet<String>,
    host_skipped_lanes: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    if !ids.insert(lane.lane_id.clone()) {
        errors.push(format!(
            "duplicate low-privilege demo lane_id `{}`",
            lane.lane_id
        ));
    }
    if !lane.lane_id.starts_with("lpd_") {
        errors.push(format!("lane_id `{}` must start with lpd_", lane.lane_id));
    }

    if !ALLOWED_EXECUTION_KINDS.contains(&lane.execution_kind.as_str()) {
        errors.push(format!(
            "lane `{}` has unsupported execution_kind `{}`",
            lane.lane_id, lane.execution_kind
        ));
    }
    if !ALLOWED_CAPABILITY_REQUIREMENTS.contains(&lane.capability_requirement.as_str()) {
        errors.push(format!(
            "lane `{}` has unsupported capability_requirement `{}`",
            lane.lane_id, lane.capability_requirement
        ));
    }
    if !ALLOWED_OUTCOMES.contains(&lane.expected_outcome.as_str()) {
        errors.push(format!(
            "lane `{}` has unsupported expected_outcome `{}`",
            lane.lane_id, lane.expected_outcome
        ));
    }

    validate_lane_required_text(lane, errors);
    validate_lane_capability_consistency(lane, low_privilege_kinds, host_skipped_lanes, errors);
}

fn validate_lane_required_text(lane: &LowPrivilegeDemoLane, errors: &mut Vec<String>) {
    if lane.fixture_source.trim().is_empty() {
        errors.push(format!("lane `{}` missing fixture_source", lane.lane_id));
    }
    if !is_valid_sha256(&lane.fixture_hash) {
        errors.push(format!(
            "lane `{}` fixture_hash must be sha256:<64-hex>",
            lane.lane_id
        ));
    }
    if lane.capability_check_command.trim().is_empty() {
        errors.push(format!(
            "lane `{}` missing capability_check_command",
            lane.lane_id
        ));
    }
    if lane.expected_artifact_path.trim().is_empty() {
        errors.push(format!(
            "lane `{}` missing expected_artifact_path",
            lane.lane_id
        ));
    }
    if lane.reproduction_command.trim().is_empty() {
        errors.push(format!(
            "lane `{}` missing reproduction_command",
            lane.lane_id
        ));
    }
    if lane.cleanup_status.trim().is_empty() {
        errors.push(format!("lane `{}` missing cleanup_status", lane.lane_id));
    }
}

fn validate_lane_capability_consistency(
    lane: &LowPrivilegeDemoLane,
    low_privilege_kinds: &mut BTreeSet<String>,
    host_skipped_lanes: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    let needs_capability =
        lane.capability_requirement != "none" && lane.capability_requirement != "host_skip";
    let executes_low_privilege =
        lane.capability_requirement == "none" && lane.expected_outcome == "executed";

    if executes_low_privilege {
        low_privilege_kinds.insert(lane.execution_kind.clone());
    }
    if lane.expected_outcome == "host_skipped" {
        host_skipped_lanes.insert(lane.execution_kind.clone());
    }

    if lane.capability_requirement == "none" && lane.expected_outcome == "host_skipped" {
        errors.push(format!(
            "lane `{}` capability=none cannot expect host_skipped outcome",
            lane.lane_id
        ));
    }
    if lane.capability_requirement == "none" && lane.expected_outcome == "capability_blocked" {
        errors.push(format!(
            "lane `{}` capability=none cannot expect capability_blocked outcome",
            lane.lane_id
        ));
    }
    if lane.expected_outcome == "host_skipped" && lane.host_skip_reason.trim().is_empty() {
        errors.push(format!(
            "lane `{}` host_skipped outcome must declare host_skip_reason",
            lane.lane_id
        ));
    }
    if lane.expected_outcome != "host_skipped" && !lane.host_skip_reason.trim().is_empty() {
        errors.push(format!(
            "lane `{}` non-host_skipped outcome must leave host_skip_reason empty",
            lane.lane_id
        ));
    }
    if lane.execution_kind == "mounted_smoke" && lane.capability_requirement == "none" {
        errors.push(format!(
            "lane `{}` mounted_smoke cannot claim capability=none",
            lane.lane_id
        ));
    }
    if lane.execution_kind == "parser_unit" && needs_capability {
        errors.push(format!(
            "lane `{}` parser_unit must run at capability=none",
            lane.lane_id
        ));
    }
}

fn validate_required_low_privilege_coverage(seen: &BTreeSet<String>, errors: &mut Vec<String>) {
    for required in REQUIRED_LOW_PRIVILEGE_KINDS {
        if !seen.contains(required) {
            errors.push(format!(
                "low-privilege demo manifest must execute `{required}` at capability=none"
            ));
        }
    }
}

fn validate_required_host_skipped_coverage(seen: &BTreeSet<String>, errors: &mut Vec<String>) {
    for required in REQUIRED_HOST_SKIPPED_LANES {
        if !seen.contains(required) {
            errors.push(format!(
                "low-privilege demo manifest must record a host-skipped `{required}` lane"
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_manifest() -> LowPrivilegeDemoManifest {
        parse_low_privilege_demo_manifest(DEFAULT_LOW_PRIVILEGE_DEMO_JSON)
            .expect("default low-privilege demo manifest parses")
    }

    #[test]
    fn default_manifest_validates_required_coverage() {
        let report = validate_default_low_privilege_demo_manifest()
            .expect("default low-privilege demo manifest validates");
        assert_eq!(report.bead_id, "bd-rchk0.5.13");
        for kind in REQUIRED_LOW_PRIVILEGE_KINDS {
            assert!(
                report.low_privilege_kinds.iter().any(|k| k == kind),
                "missing low-privilege kind {kind}"
            );
        }
        for kind in REQUIRED_HOST_SKIPPED_LANES {
            assert!(
                report.host_skipped_lanes.iter().any(|k| k == kind),
                "missing host-skipped kind {kind}"
            );
        }
    }

    #[test]
    fn missing_low_privilege_kind_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.lanes.retain(|lane| {
            !(lane.execution_kind == "parser_unit" && lane.expected_outcome == "executed")
        });
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must execute `parser_unit` at capability=none"))
        );
    }

    #[test]
    fn missing_repair_dry_run_kind_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.lanes.retain(|lane| {
            !(lane.execution_kind == "repair_dry_run" && lane.expected_outcome == "executed")
        });
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must execute `repair_dry_run`"))
        );
    }

    #[test]
    fn missing_host_skipped_mounted_lane_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.lanes.retain(|lane| {
            !(lane.execution_kind == "mounted_smoke" && lane.expected_outcome == "host_skipped")
        });
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must record a host-skipped `mounted_smoke` lane"))
        );
    }

    #[test]
    fn duplicate_lane_id_is_rejected() {
        let mut manifest = fixture_manifest();
        let dup = manifest.lanes[0].lane_id.clone();
        manifest.lanes[1].lane_id = dup;
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("duplicate low-privilege demo lane_id"))
        );
    }

    #[test]
    fn lane_id_prefix_is_enforced() {
        let mut manifest = fixture_manifest();
        manifest.lanes[0].lane_id = "demo_001".to_owned();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must start with lpd_"))
        );
    }

    #[test]
    fn unsupported_execution_kind_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.lanes[0].execution_kind = "telepathy_lane".to_owned();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported execution_kind"))
        );
    }

    #[test]
    fn unsupported_capability_requirement_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.lanes[0].capability_requirement = "magic".to_owned();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported capability_requirement"))
        );
    }

    #[test]
    fn unsupported_expected_outcome_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.lanes[0].expected_outcome = "kinda_ran".to_owned();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported expected_outcome"))
        );
    }

    #[test]
    fn capability_none_cannot_expect_host_skipped() {
        let mut manifest = fixture_manifest();
        let lane = manifest
            .lanes
            .iter_mut()
            .find(|l| l.capability_requirement == "none")
            .expect("low-privilege lane exists");
        lane.expected_outcome = "host_skipped".to_owned();
        lane.host_skip_reason = "would never happen".to_owned();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("capability=none cannot expect host_skipped outcome"))
        );
    }

    #[test]
    fn capability_none_cannot_expect_capability_blocked() {
        let mut manifest = fixture_manifest();
        let lane = manifest
            .lanes
            .iter_mut()
            .find(|l| l.capability_requirement == "none")
            .expect("low-privilege lane exists");
        lane.expected_outcome = "capability_blocked".to_owned();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(report.errors.iter().any(|err| err
            .contains("capability=none cannot expect capability_blocked outcome")));
    }

    #[test]
    fn host_skipped_outcome_requires_skip_reason() {
        let mut manifest = fixture_manifest();
        let lane = manifest
            .lanes
            .iter_mut()
            .find(|l| l.expected_outcome == "host_skipped")
            .expect("host-skipped lane exists");
        lane.host_skip_reason = String::new();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("host_skipped outcome must declare host_skip_reason"))
        );
    }

    #[test]
    fn non_host_skipped_must_leave_skip_reason_empty() {
        let mut manifest = fixture_manifest();
        let lane = manifest
            .lanes
            .iter_mut()
            .find(|l| l.expected_outcome == "executed")
            .expect("executed lane exists");
        lane.host_skip_reason = "leftover prose".to_owned();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err
                    .contains("non-host_skipped outcome must leave host_skip_reason empty"))
        );
    }

    #[test]
    fn mounted_smoke_cannot_claim_capability_none() {
        let mut manifest = fixture_manifest();
        let lane = manifest
            .lanes
            .iter_mut()
            .find(|l| l.execution_kind == "mounted_smoke")
            .expect("mounted lane exists");
        lane.capability_requirement = "none".to_owned();
        lane.expected_outcome = "executed".to_owned();
        lane.host_skip_reason = String::new();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("mounted_smoke cannot claim capability=none"))
        );
    }

    #[test]
    fn parser_unit_must_run_at_capability_none() {
        let mut manifest = fixture_manifest();
        let lane = manifest
            .lanes
            .iter_mut()
            .find(|l| l.execution_kind == "parser_unit")
            .expect("parser unit lane exists");
        lane.capability_requirement = "fuse".to_owned();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("parser_unit must run at capability=none"))
        );
    }

    #[test]
    fn malformed_fixture_hash_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.lanes[0].fixture_hash = "md5:not-supported".to_owned();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("fixture_hash must be sha256"))
        );
    }

    #[test]
    fn missing_environment_metadata_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.git_sha = String::new();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing git_sha"))
        );
    }

    #[test]
    fn missing_kernel_metadata_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.kernel = String::new();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing kernel"))
        );
    }

    #[test]
    fn missing_reproduction_command_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.lanes[0].reproduction_command = String::new();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing reproduction_command"))
        );
    }

    #[test]
    fn missing_capability_check_command_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.lanes[0].capability_check_command = String::new();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing capability_check_command"))
        );
    }

    #[test]
    fn empty_lanes_list_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.lanes.clear();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("at least one lane"))
        );
    }
}
