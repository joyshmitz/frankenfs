#![forbid(unsafe_code)]

//! Low-privilege demo sandbox + fixture provenance.
//!
//! Tracks bd-3crxf: refines `low_privilege_demo` with explicit fixture
//! provenance, allowed-workspace-root sandboxing, forbidden host side-effect
//! list, lane-skip semantics, proof-bundle schema id, and a generated README
//! quickstart wording id. The validator fails closed when a manifest cannot
//! prove that running the demo will leave no traces outside its sandbox or
//! when it claims mounted readiness from a FUSE-skipped lane.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const LOW_PRIVILEGE_DEMO_SANDBOX_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_LOW_PRIVILEGE_DEMO_SANDBOX_PATH: &str =
    "tests/low-privilege-demo-sandbox/low_privilege_demo_sandbox.json";
const DEFAULT_LOW_PRIVILEGE_DEMO_SANDBOX_JSON: &str = include_str!(
    "../../../tests/low-privilege-demo-sandbox/low_privilege_demo_sandbox.json"
);

const ALLOWED_LANE_OUTCOMES: [&str; 3] = ["executed", "host_skipped", "capability_blocked"];

const ALLOWED_FIXTURE_PROVENANCE: [&str; 4] =
    ["committed_in_repo", "generated_from_seed", "downloaded_with_hash", "synthesized_in_test"];

const FORBIDDEN_OUTPUT_ROOTS: [&str; 6] = [
    "/etc",
    "/root",
    "/var",
    "/usr",
    "/home/ubuntu",
    "/dev",
];

const REQUIRED_FORBIDDEN_SIDE_EFFECTS: [&str; 5] = [
    "no_writes_outside_workspace_root",
    "no_kernel_module_load",
    "no_root_owned_writes",
    "no_network_egress_outside_capability_probe",
    "no_modification_of_committed_fixtures",
];

const REQUIRED_LANES: [&str; 4] = [
    "parser_unit",
    "invariant_oracle",
    "repair_dry_run",
    "mounted_smoke_host_skipped",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowPrivilegeDemoSandbox {
    pub schema_version: u32,
    pub manifest_id: String,
    pub bead_id: String,
    pub allowed_workspace_root: String,
    pub forbidden_side_effects: Vec<String>,
    pub proof_bundle_schema_id: String,
    pub readme_quickstart_wording_id: String,
    pub cleanup_policy: String,
    pub fixtures: Vec<DemoFixture>,
    pub lanes: Vec<DemoLane>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemoFixture {
    pub fixture_id: String,
    pub path: String,
    pub sha256: String,
    pub provenance: String,
    pub mutable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemoLane {
    pub lane_id: String,
    pub name: String,
    pub expected_outcome: String,
    pub uses_fixture_id: String,
    pub output_path: String,
    #[serde(default)]
    pub host_skip_reason: String,
    #[serde(default)]
    pub claims_mounted_readiness: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowPrivilegeDemoSandboxReport {
    pub schema_version: u32,
    pub manifest_id: String,
    pub bead_id: String,
    pub fixture_count: usize,
    pub lane_count: usize,
    pub host_skipped_lanes: usize,
    pub valid: bool,
    pub errors: Vec<String>,
}

pub fn parse_low_privilege_demo_sandbox(text: &str) -> Result<LowPrivilegeDemoSandbox> {
    serde_json::from_str(text)
        .map_err(|err| anyhow::anyhow!("failed to parse low-privilege demo sandbox JSON: {err}"))
}

pub fn validate_default_low_privilege_demo_sandbox() -> Result<LowPrivilegeDemoSandboxReport> {
    let manifest = parse_low_privilege_demo_sandbox(DEFAULT_LOW_PRIVILEGE_DEMO_SANDBOX_JSON)?;
    let report = validate_low_privilege_demo_sandbox(&manifest);
    if !report.valid {
        bail!(
            "low-privilege demo sandbox failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        );
    }
    Ok(report)
}

#[must_use]
pub fn validate_low_privilege_demo_sandbox(
    manifest: &LowPrivilegeDemoSandbox,
) -> LowPrivilegeDemoSandboxReport {
    let mut errors = Vec::new();
    let mut fixture_ids = BTreeSet::new();
    let mut lane_ids = BTreeSet::new();
    let mut lane_names = BTreeSet::new();
    let mut host_skipped = 0_usize;

    validate_top_level(manifest, &mut errors);
    for fixture in &manifest.fixtures {
        validate_fixture(fixture, &mut fixture_ids, &mut errors);
    }
    for lane in &manifest.lanes {
        validate_lane(
            lane,
            manifest,
            &fixture_ids,
            &mut lane_ids,
            &mut lane_names,
            &mut host_skipped,
            &mut errors,
        );
    }
    validate_required_lanes(&lane_names, &mut errors);
    validate_required_side_effects(manifest, &mut errors);

    LowPrivilegeDemoSandboxReport {
        schema_version: manifest.schema_version,
        manifest_id: manifest.manifest_id.clone(),
        bead_id: manifest.bead_id.clone(),
        fixture_count: manifest.fixtures.len(),
        lane_count: manifest.lanes.len(),
        host_skipped_lanes: host_skipped,
        valid: errors.is_empty(),
        errors,
    }
}

fn validate_top_level(
    manifest: &LowPrivilegeDemoSandbox,
    errors: &mut Vec<String>,
) {
    if manifest.schema_version != LOW_PRIVILEGE_DEMO_SANDBOX_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version must be {LOW_PRIVILEGE_DEMO_SANDBOX_SCHEMA_VERSION}, got {}",
            manifest.schema_version
        ));
    }
    if manifest.manifest_id.trim().is_empty() {
        errors.push("low-privilege demo sandbox missing manifest_id".to_owned());
    }
    if !manifest.bead_id.starts_with("bd-") {
        errors.push(format!(
            "bead_id must look like bd-..., got `{}`",
            manifest.bead_id
        ));
    }
    if manifest.allowed_workspace_root.trim().is_empty() {
        errors.push("allowed_workspace_root must not be empty".to_owned());
    }
    if !manifest.allowed_workspace_root.starts_with('/')
        && !manifest.allowed_workspace_root.starts_with("./")
        && manifest.allowed_workspace_root != "<tempdir>"
    {
        errors.push(format!(
            "allowed_workspace_root `{}` must be an absolute path, ./relative path, or <tempdir>",
            manifest.allowed_workspace_root
        ));
    }
    if FORBIDDEN_OUTPUT_ROOTS
        .iter()
        .any(|forbidden| manifest.allowed_workspace_root.starts_with(*forbidden))
    {
        errors.push(format!(
            "allowed_workspace_root `{}` must not begin under a forbidden host root",
            manifest.allowed_workspace_root
        ));
    }
    if manifest.proof_bundle_schema_id.trim().is_empty() {
        errors.push("proof_bundle_schema_id must not be empty".to_owned());
    }
    if manifest.readme_quickstart_wording_id.trim().is_empty() {
        errors.push("readme_quickstart_wording_id must not be empty".to_owned());
    }
    if manifest.cleanup_policy.trim().is_empty() {
        errors.push("cleanup_policy must not be empty".to_owned());
    }
    if manifest.fixtures.is_empty() {
        errors.push("low-privilege demo sandbox must declare at least one fixture".to_owned());
    }
    if manifest.lanes.is_empty() {
        errors.push("low-privilege demo sandbox must declare at least one lane".to_owned());
    }
}

fn validate_fixture(
    fixture: &DemoFixture,
    fixture_ids: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    if !fixture_ids.insert(fixture.fixture_id.clone()) {
        errors.push(format!(
            "duplicate demo fixture_id `{}`",
            fixture.fixture_id
        ));
    }
    if !fixture.fixture_id.starts_with("fix_") {
        errors.push(format!(
            "fixture_id `{}` must start with fix_",
            fixture.fixture_id
        ));
    }
    if fixture.path.trim().is_empty() {
        errors.push(format!(
            "fixture `{}` missing path",
            fixture.fixture_id
        ));
    }
    if !is_valid_sha256(&fixture.sha256) {
        errors.push(format!(
            "fixture `{}` sha256 must be sha256:<64-hex>",
            fixture.fixture_id
        ));
    }
    if !ALLOWED_FIXTURE_PROVENANCE.contains(&fixture.provenance.as_str()) {
        errors.push(format!(
            "fixture `{}` has unsupported provenance `{}`",
            fixture.fixture_id, fixture.provenance
        ));
    }
    if fixture.mutable && fixture.provenance == "committed_in_repo" {
        errors.push(format!(
            "fixture `{}` committed_in_repo provenance cannot be mutable",
            fixture.fixture_id
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_lane(
    lane: &DemoLane,
    manifest: &LowPrivilegeDemoSandbox,
    fixture_ids: &BTreeSet<String>,
    lane_ids: &mut BTreeSet<String>,
    lane_names: &mut BTreeSet<String>,
    host_skipped: &mut usize,
    errors: &mut Vec<String>,
) {
    if !lane_ids.insert(lane.lane_id.clone()) {
        errors.push(format!("duplicate demo lane_id `{}`", lane.lane_id));
    }
    if !lane.lane_id.starts_with("lpds_") {
        errors.push(format!(
            "lane_id `{}` must start with lpds_",
            lane.lane_id
        ));
    }
    if lane.name.trim().is_empty() {
        errors.push(format!("lane `{}` missing name", lane.lane_id));
    } else {
        lane_names.insert(lane.name.clone());
    }
    if !ALLOWED_LANE_OUTCOMES.contains(&lane.expected_outcome.as_str()) {
        errors.push(format!(
            "lane `{}` has unsupported expected_outcome `{}`",
            lane.lane_id, lane.expected_outcome
        ));
    }
    if lane.expected_outcome == "host_skipped" {
        *host_skipped += 1;
    }
    if lane.uses_fixture_id.trim().is_empty() {
        errors.push(format!(
            "lane `{}` missing uses_fixture_id",
            lane.lane_id
        ));
    } else if !fixture_ids.contains(&lane.uses_fixture_id) {
        errors.push(format!(
            "lane `{}` uses_fixture_id `{}` does not match any declared fixture",
            lane.lane_id, lane.uses_fixture_id
        ));
    }
    if lane.output_path.trim().is_empty() {
        errors.push(format!("lane `{}` missing output_path", lane.lane_id));
    } else if !lane
        .output_path
        .starts_with(manifest.allowed_workspace_root.as_str())
        && !lane.output_path.starts_with("./")
        && !lane.output_path.starts_with("<tempdir>")
    {
        errors.push(format!(
            "lane `{}` output_path `{}` must live under the allowed_workspace_root",
            lane.lane_id, lane.output_path
        ));
    }
    if FORBIDDEN_OUTPUT_ROOTS
        .iter()
        .any(|forbidden| lane.output_path.starts_with(*forbidden))
    {
        errors.push(format!(
            "lane `{}` output_path `{}` must not begin under a forbidden host root",
            lane.lane_id, lane.output_path
        ));
    }
    if lane.expected_outcome == "host_skipped" {
        if lane.host_skip_reason.trim().is_empty() {
            errors.push(format!(
                "lane `{}` host_skipped outcome must declare host_skip_reason",
                lane.lane_id
            ));
        }
        if lane.claims_mounted_readiness {
            errors.push(format!(
                "lane `{}` host_skipped outcome must not claim mounted readiness",
                lane.lane_id
            ));
        }
    } else if !lane.host_skip_reason.trim().is_empty() {
        errors.push(format!(
            "lane `{}` non-host_skipped outcome must leave host_skip_reason empty",
            lane.lane_id
        ));
    }
    if lane.expected_outcome == "capability_blocked"
        && lane.host_skip_reason.trim().is_empty()
    {
        errors.push(format!(
            "lane `{}` capability_blocked outcome must declare host_skip_reason",
            lane.lane_id
        ));
    }
}

fn validate_required_lanes(seen: &BTreeSet<String>, errors: &mut Vec<String>) {
    for required in REQUIRED_LANES {
        if !seen.contains(required) {
            errors.push(format!(
                "low-privilege demo sandbox missing required lane named `{required}`"
            ));
        }
    }
}

fn validate_required_side_effects(
    manifest: &LowPrivilegeDemoSandbox,
    errors: &mut Vec<String>,
) {
    let seen: BTreeSet<&str> = manifest
        .forbidden_side_effects
        .iter()
        .map(String::as_str)
        .collect();
    for required in REQUIRED_FORBIDDEN_SIDE_EFFECTS {
        if !seen.contains(required) {
            errors.push(format!(
                "forbidden_side_effects must include `{required}`"
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

    fn fixture_manifest() -> LowPrivilegeDemoSandbox {
        parse_low_privilege_demo_sandbox(DEFAULT_LOW_PRIVILEGE_DEMO_SANDBOX_JSON)
            .expect("default low-privilege demo sandbox parses")
    }

    #[test]
    fn default_manifest_validates_required_lanes_and_side_effects() {
        let report = validate_default_low_privilege_demo_sandbox()
            .expect("default low-privilege demo sandbox validates");
        assert_eq!(report.bead_id, "bd-3crxf");
        assert!(report.host_skipped_lanes >= 1);
    }

    #[test]
    fn missing_required_lane_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.lanes.retain(|l| l.name != "mounted_smoke_host_skipped");
        let report = validate_low_privilege_demo_sandbox(&manifest);
        assert!(report.errors.iter().any(|err| err
            .contains("missing required lane named `mounted_smoke_host_skipped`")));
    }

    #[test]
    fn missing_required_side_effect_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest
            .forbidden_side_effects
            .retain(|effect| effect != "no_kernel_module_load");
        let report = validate_low_privilege_demo_sandbox(&manifest);
        assert!(report.errors.iter().any(|err| err
            .contains("forbidden_side_effects must include `no_kernel_module_load`")));
    }

    #[test]
    fn duplicate_fixture_id_is_rejected() {
        let mut manifest = fixture_manifest();
        let dup = manifest.fixtures[0].fixture_id.clone();
        manifest.fixtures[1].fixture_id = dup;
        let report = validate_low_privilege_demo_sandbox(&manifest);
        assert!(report.errors.iter().any(|err| err.contains("duplicate demo fixture_id")));
    }

    #[test]
    fn fixture_id_prefix_is_enforced() {
        let mut manifest = fixture_manifest();
        manifest.fixtures[0].fixture_id = "demo_001".to_owned();
        let report = validate_low_privilege_demo_sandbox(&manifest);
        assert!(report.errors.iter().any(|err| err.contains("must start with fix_")));
    }

    #[test]
    fn malformed_fixture_sha256_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.fixtures[0].sha256 = "md5:not-supported".to_owned();
        let report = validate_low_privilege_demo_sandbox(&manifest);
        assert!(report.errors.iter().any(|err| err.contains("sha256 must be sha256")));
    }

    #[test]
    fn unsupported_fixture_provenance_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.fixtures[0].provenance = "from_random_url".to_owned();
        let report = validate_low_privilege_demo_sandbox(&manifest);
        assert!(report.errors.iter().any(|err| err.contains("unsupported provenance")));
    }

    #[test]
    fn committed_in_repo_fixture_cannot_be_mutable() {
        let mut manifest = fixture_manifest();
        let fixture = manifest
            .fixtures
            .iter_mut()
            .find(|f| f.provenance == "committed_in_repo")
            .expect("committed fixture exists");
        fixture.mutable = true;
        let report = validate_low_privilege_demo_sandbox(&manifest);
        assert!(report.errors.iter().any(|err| err
            .contains("committed_in_repo provenance cannot be mutable")));
    }

    #[test]
    fn duplicate_lane_id_is_rejected() {
        let mut manifest = fixture_manifest();
        let dup = manifest.lanes[0].lane_id.clone();
        manifest.lanes[1].lane_id = dup;
        let report = validate_low_privilege_demo_sandbox(&manifest);
        assert!(report.errors.iter().any(|err| err.contains("duplicate demo lane_id")));
    }

    #[test]
    fn lane_id_prefix_is_enforced() {
        let mut manifest = fixture_manifest();
        manifest.lanes[0].lane_id = "lane_001".to_owned();
        let report = validate_low_privilege_demo_sandbox(&manifest);
        assert!(report.errors.iter().any(|err| err.contains("must start with lpds_")));
    }

    #[test]
    fn lane_must_reference_known_fixture() {
        let mut manifest = fixture_manifest();
        manifest.lanes[0].uses_fixture_id = "fix_does_not_exist".to_owned();
        let report = validate_low_privilege_demo_sandbox(&manifest);
        assert!(report.errors.iter().any(|err| err
            .contains("does not match any declared fixture")));
    }

    #[test]
    fn forbidden_workspace_root_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.allowed_workspace_root = "/etc/frankenfs-demo".to_owned();
        let report = validate_low_privilege_demo_sandbox(&manifest);
        assert!(report.errors.iter().any(|err| err
            .contains("must not begin under a forbidden host root")));
    }

    #[test]
    fn lane_output_path_must_live_under_workspace_root() {
        let mut manifest = fixture_manifest();
        manifest.lanes[0].output_path = "/tmp/different-root/output.json".to_owned();
        let report = validate_low_privilege_demo_sandbox(&manifest);
        assert!(report.errors.iter().any(|err| err
            .contains("must live under the allowed_workspace_root")));
    }

    #[test]
    fn lane_output_path_cannot_be_under_forbidden_root() {
        let mut manifest = fixture_manifest();
        manifest.lanes[0].output_path = "/etc/frankenfs/output.json".to_owned();
        let report = validate_low_privilege_demo_sandbox(&manifest);
        assert!(report.errors.iter().any(|err| err
            .contains("must not begin under a forbidden host root")));
    }

    #[test]
    fn host_skipped_lane_must_declare_skip_reason() {
        let mut manifest = fixture_manifest();
        let lane = manifest
            .lanes
            .iter_mut()
            .find(|l| l.expected_outcome == "host_skipped")
            .expect("host skipped lane exists");
        lane.host_skip_reason = String::new();
        let report = validate_low_privilege_demo_sandbox(&manifest);
        assert!(report.errors.iter().any(|err| err
            .contains("host_skipped outcome must declare host_skip_reason")));
    }

    #[test]
    fn host_skipped_lane_cannot_claim_mounted_readiness() {
        let mut manifest = fixture_manifest();
        let lane = manifest
            .lanes
            .iter_mut()
            .find(|l| l.expected_outcome == "host_skipped")
            .expect("host skipped lane exists");
        lane.claims_mounted_readiness = true;
        let report = validate_low_privilege_demo_sandbox(&manifest);
        assert!(report.errors.iter().any(|err| err
            .contains("must not claim mounted readiness")));
    }

    #[test]
    fn non_host_skipped_lane_must_leave_skip_reason_empty() {
        let mut manifest = fixture_manifest();
        let lane = manifest
            .lanes
            .iter_mut()
            .find(|l| l.expected_outcome == "executed")
            .expect("executed lane exists");
        lane.host_skip_reason = "leftover".to_owned();
        let report = validate_low_privilege_demo_sandbox(&manifest);
        assert!(report.errors.iter().any(|err| err
            .contains("non-host_skipped outcome must leave host_skip_reason empty")));
    }

    #[test]
    fn missing_proof_bundle_schema_id_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.proof_bundle_schema_id = String::new();
        let report = validate_low_privilege_demo_sandbox(&manifest);
        assert!(report.errors.iter().any(|err| err
            .contains("proof_bundle_schema_id must not be empty")));
    }

    #[test]
    fn missing_readme_wording_id_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.readme_quickstart_wording_id = String::new();
        let report = validate_low_privilege_demo_sandbox(&manifest);
        assert!(report.errors.iter().any(|err| err
            .contains("readme_quickstart_wording_id must not be empty")));
    }

    #[test]
    fn empty_fixtures_list_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.fixtures.clear();
        let report = validate_low_privilege_demo_sandbox(&manifest);
        assert!(report.errors.iter().any(|err| err.contains("at least one fixture")));
    }

    #[test]
    fn empty_lanes_list_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.lanes.clear();
        let report = validate_low_privilege_demo_sandbox(&manifest);
        assert!(report.errors.iter().any(|err| err.contains("at least one lane")));
    }
}
