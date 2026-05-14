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
use std::{collections::BTreeSet, fmt::Write as _, fs, path::Path};

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

pub fn load_low_privilege_demo_manifest(path: &Path) -> Result<LowPrivilegeDemoManifest> {
    let text = fs::read_to_string(path).map_err(|err| {
        anyhow::anyhow!(
            "failed to read low-privilege demo manifest `{}`: {err}",
            path.display()
        )
    })?;
    parse_low_privilege_demo_manifest(&text)
}

pub fn validate_default_low_privilege_demo_manifest() -> Result<LowPrivilegeDemoReport> {
    let manifest = parse_low_privilege_demo_manifest(DEFAULT_LOW_PRIVILEGE_DEMO_JSON)?;
    let report = validate_low_privilege_demo_manifest(&manifest);
    fail_on_low_privilege_demo_errors(&report)?;
    Ok(report)
}

pub fn fail_on_low_privilege_demo_errors(report: &LowPrivilegeDemoReport) -> Result<()> {
    if report.valid {
        return Ok(());
    }
    bail!(
        "low-privilege demo manifest failed with {} error(s): {}",
        report.errors.len(),
        report.errors.join("; ")
    );
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

#[must_use]
pub fn render_low_privilege_demo_markdown(report: &LowPrivilegeDemoReport) -> String {
    let mut out = String::new();
    let _ = writeln!(&mut out, "# Low-Privilege Demo");
    let _ = writeln!(&mut out);
    let _ = writeln!(&mut out, "- manifest: `{}`", report.manifest_id);
    let _ = writeln!(&mut out, "- schema version: `{}`", report.schema_version);
    let _ = writeln!(&mut out, "- bead: `{}`", report.bead_id);
    let _ = writeln!(&mut out, "- valid: `{}`", report.valid);
    let _ = writeln!(&mut out, "- lanes: `{}`", report.lane_count);
    let _ = writeln!(
        &mut out,
        "- low-privilege kinds: `{}`",
        report.low_privilege_kinds.join(", ")
    );
    let _ = writeln!(
        &mut out,
        "- host-skipped lanes: `{}`",
        report.host_skipped_lanes.join(", ")
    );
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

    fn fixture_manifest() -> Result<LowPrivilegeDemoManifest> {
        parse_low_privilege_demo_manifest(DEFAULT_LOW_PRIVILEGE_DEMO_JSON)
            .context("default low-privilege demo manifest parses")
    }

    fn first_lane_mut(
        manifest: &mut LowPrivilegeDemoManifest,
    ) -> Result<&mut LowPrivilegeDemoLane> {
        manifest
            .lanes
            .first_mut()
            .context("fixture manifest includes at least one lane")
    }

    fn first_two_lanes_mut(
        manifest: &mut LowPrivilegeDemoManifest,
    ) -> Result<(&mut LowPrivilegeDemoLane, &mut LowPrivilegeDemoLane)> {
        let (first, rest) = manifest
            .lanes
            .split_first_mut()
            .context("fixture manifest includes at least one lane")?;
        let second = rest
            .first_mut()
            .context("fixture manifest includes at least two lanes")?;
        Ok((first, second))
    }

    fn lane_by_capability_mut<'a>(
        manifest: &'a mut LowPrivilegeDemoManifest,
        capability_requirement: &str,
    ) -> Result<&'a mut LowPrivilegeDemoLane> {
        manifest
            .lanes
            .iter_mut()
            .find(|lane| lane.capability_requirement == capability_requirement)
            .with_context(|| {
                format!("fixture manifest includes capability_requirement {capability_requirement}")
            })
    }

    fn lane_by_outcome_mut<'a>(
        manifest: &'a mut LowPrivilegeDemoManifest,
        expected_outcome: &str,
    ) -> Result<&'a mut LowPrivilegeDemoLane> {
        manifest
            .lanes
            .iter_mut()
            .find(|lane| lane.expected_outcome == expected_outcome)
            .with_context(|| {
                format!("fixture manifest includes expected_outcome {expected_outcome}")
            })
    }

    fn lane_by_execution_kind_mut<'a>(
        manifest: &'a mut LowPrivilegeDemoManifest,
        execution_kind: &str,
    ) -> Result<&'a mut LowPrivilegeDemoLane> {
        manifest
            .lanes
            .iter_mut()
            .find(|lane| lane.execution_kind == execution_kind)
            .with_context(|| format!("fixture manifest includes execution_kind {execution_kind}"))
    }

    #[test]
    fn default_manifest_validates_required_coverage() -> Result<()> {
        let report = validate_default_low_privilege_demo_manifest()?;
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
        Ok(())
    }

    #[test]
    fn low_privilege_demo_report_json_shape() -> Result<()> {
        let report = validate_default_low_privilege_demo_manifest()?;
        let json = serde_json::to_string_pretty(&report)?;

        insta::assert_snapshot!("low_privilege_demo_report_json_shape", json);
        let parsed: LowPrivilegeDemoReport = serde_json::from_str(&json)?;
        assert_eq!(parsed, report);
        Ok(())
    }

    #[test]
    fn render_low_privilege_demo_markdown_default_manifest() -> Result<()> {
        let report = validate_default_low_privilege_demo_manifest()?;
        let markdown = render_low_privilege_demo_markdown(&report);

        assert!(markdown.contains("# Low-Privilege Demo"));
        assert!(markdown.contains("low-privilege kinds"));
        assert!(markdown.contains("host-skipped lanes"));
        Ok(())
    }

    #[test]
    fn fail_on_errors_rejects_invalid_report() -> Result<()> {
        let mut manifest = fixture_manifest()?;
        manifest.schema_version += 1;
        let report = validate_low_privilege_demo_manifest(&manifest);

        assert!(!report.valid);
        assert!(fail_on_low_privilege_demo_errors(&report).is_err());
        Ok(())
    }

    #[test]
    fn missing_low_privilege_kind_is_rejected() -> Result<()> {
        let mut manifest = fixture_manifest()?;
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
        Ok(())
    }

    #[test]
    fn missing_repair_dry_run_kind_is_rejected() -> Result<()> {
        let mut manifest = fixture_manifest()?;
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
        Ok(())
    }

    #[test]
    fn missing_host_skipped_mounted_lane_is_rejected() -> Result<()> {
        let mut manifest = fixture_manifest()?;
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
        Ok(())
    }

    #[test]
    fn duplicate_lane_id_is_rejected() -> Result<()> {
        let mut manifest = fixture_manifest()?;
        let (first, second) = first_two_lanes_mut(&mut manifest)?;
        second.lane_id = first.lane_id.clone();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("duplicate low-privilege demo lane_id"))
        );
        Ok(())
    }

    #[test]
    fn lane_id_prefix_is_enforced() -> Result<()> {
        let mut manifest = fixture_manifest()?;
        first_lane_mut(&mut manifest)?.lane_id = "demo_001".to_owned();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must start with lpd_"))
        );
        Ok(())
    }

    #[test]
    fn unsupported_execution_kind_is_rejected() -> Result<()> {
        let mut manifest = fixture_manifest()?;
        first_lane_mut(&mut manifest)?.execution_kind = "telepathy_lane".to_owned();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported execution_kind"))
        );
        Ok(())
    }

    #[test]
    fn unsupported_capability_requirement_is_rejected() -> Result<()> {
        let mut manifest = fixture_manifest()?;
        first_lane_mut(&mut manifest)?.capability_requirement = "magic".to_owned();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported capability_requirement"))
        );
        Ok(())
    }

    #[test]
    fn unsupported_expected_outcome_is_rejected() -> Result<()> {
        let mut manifest = fixture_manifest()?;
        first_lane_mut(&mut manifest)?.expected_outcome = "kinda_ran".to_owned();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported expected_outcome"))
        );
        Ok(())
    }

    #[test]
    fn capability_none_cannot_expect_host_skipped() -> Result<()> {
        let mut manifest = fixture_manifest()?;
        let lane = lane_by_capability_mut(&mut manifest, "none")?;
        lane.expected_outcome = "host_skipped".to_owned();
        lane.host_skip_reason = "would never happen".to_owned();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("capability=none cannot expect host_skipped outcome"))
        );
        Ok(())
    }

    #[test]
    fn capability_none_cannot_expect_capability_blocked() -> Result<()> {
        let mut manifest = fixture_manifest()?;
        let lane = lane_by_capability_mut(&mut manifest, "none")?;
        lane.expected_outcome = "capability_blocked".to_owned();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(report
            .errors
            .iter()
            .any(|err| err.contains("capability=none cannot expect capability_blocked outcome")));
        Ok(())
    }

    #[test]
    fn host_skipped_outcome_requires_skip_reason() -> Result<()> {
        let mut manifest = fixture_manifest()?;
        let lane = lane_by_outcome_mut(&mut manifest, "host_skipped")?;
        lane.host_skip_reason = String::new();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("host_skipped outcome must declare host_skip_reason"))
        );
        Ok(())
    }

    #[test]
    fn non_host_skipped_must_leave_skip_reason_empty() -> Result<()> {
        let mut manifest = fixture_manifest()?;
        let lane = lane_by_outcome_mut(&mut manifest, "executed")?;
        lane.host_skip_reason = "leftover prose".to_owned();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err
                    .contains("non-host_skipped outcome must leave host_skip_reason empty"))
        );
        Ok(())
    }

    #[test]
    fn mounted_smoke_cannot_claim_capability_none() -> Result<()> {
        let mut manifest = fixture_manifest()?;
        let lane = lane_by_execution_kind_mut(&mut manifest, "mounted_smoke")?;
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
        Ok(())
    }

    #[test]
    fn parser_unit_must_run_at_capability_none() -> Result<()> {
        let mut manifest = fixture_manifest()?;
        let lane = lane_by_execution_kind_mut(&mut manifest, "parser_unit")?;
        lane.capability_requirement = "fuse".to_owned();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("parser_unit must run at capability=none"))
        );
        Ok(())
    }

    #[test]
    fn malformed_fixture_hash_is_rejected() -> Result<()> {
        let mut manifest = fixture_manifest()?;
        first_lane_mut(&mut manifest)?.fixture_hash = "md5:not-supported".to_owned();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("fixture_hash must be sha256"))
        );
        Ok(())
    }

    #[test]
    fn missing_environment_metadata_is_rejected() -> Result<()> {
        let mut manifest = fixture_manifest()?;
        manifest.git_sha = String::new();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing git_sha"))
        );
        Ok(())
    }

    #[test]
    fn missing_kernel_metadata_is_rejected() -> Result<()> {
        let mut manifest = fixture_manifest()?;
        manifest.kernel = String::new();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing kernel"))
        );
        Ok(())
    }

    #[test]
    fn missing_reproduction_command_is_rejected() -> Result<()> {
        let mut manifest = fixture_manifest()?;
        first_lane_mut(&mut manifest)?.reproduction_command = String::new();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing reproduction_command"))
        );
        Ok(())
    }

    #[test]
    fn missing_capability_check_command_is_rejected() -> Result<()> {
        let mut manifest = fixture_manifest()?;
        first_lane_mut(&mut manifest)?.capability_check_command = String::new();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing capability_check_command"))
        );
        Ok(())
    }

    #[test]
    fn empty_lanes_list_is_rejected() -> Result<()> {
        let mut manifest = fixture_manifest()?;
        manifest.lanes.clear();
        let report = validate_low_privilege_demo_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("at least one lane"))
        );
        Ok(())
    }
}
