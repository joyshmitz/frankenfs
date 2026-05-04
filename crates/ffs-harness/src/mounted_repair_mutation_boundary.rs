#![forbid(unsafe_code)]

//! Mounted repair mutation-boundary conformance fixtures.
//!
//! Tracks bd-wjsuj: refines mounted_repair_policy with the exact mutation
//! boundary each lifecycle is allowed to cross. Default ro scrub detects
//! only; explicit ro `--background-repair` with a ledger may mutate only the
//! controlled image/ledger path; rw `--background-repair` must refuse with
//! zero client-visible side effects until serialization is proven. Each
//! fixture binds before/after image hashes, ledger row counts, expected
//! mutation_scope, visible namespace expectations, and host-path-touched
//! invariants so release gates cannot promote mounted automatic repair
//! readiness without a fresh refusal proof.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MOUNTED_REPAIR_MUTATION_BOUNDARY_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_MOUNTED_REPAIR_MUTATION_BOUNDARY_PATH: &str =
    "tests/mounted-repair-mutation-boundary/mounted_repair_mutation_boundary.json";
const DEFAULT_MOUNTED_REPAIR_MUTATION_BOUNDARY_JSON: &str = include_str!(
    "../../../tests/mounted-repair-mutation-boundary/mounted_repair_mutation_boundary.json"
);

const ALLOWED_KINDS: [&str; 6] = [
    "default_ro_detection_only",
    "ro_repair_with_ledger_allowed",
    "rw_repair_refused",
    "missing_ledger_refused",
    "stale_ledger_refused",
    "host_capability_skip",
];

const ALLOWED_MUTATION_SCOPES: [&str; 4] = [
    "no_mutation",
    "ledger_only",
    "image_repair_path_and_ledger",
    "refused_no_partial_mutation",
];

const ALLOWED_OUTCOMES: [&str; 5] = [
    "detection_only",
    "ledger_repair_applied",
    "rw_refused",
    "ledger_refused",
    "host_skipped",
];

const ALLOWED_CLEANUP_STATUSES: [&str; 4] = [
    "teardown_image",
    "preserve_artifacts_on_failure",
    "preserve_artifacts_always",
    "cleanup_failure",
];

const REQUIRED_KINDS: [&str; 4] = [
    "default_ro_detection_only",
    "ro_repair_with_ledger_allowed",
    "rw_repair_refused",
    "stale_ledger_refused",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedRepairMutationBoundary {
    pub schema_version: u32,
    pub matrix_id: String,
    pub bead_id: String,
    pub scenarios: Vec<MutationBoundaryScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationBoundaryScenario {
    pub scenario_id: String,
    pub kind: String,
    pub mount_mode: String,
    pub background_repair: bool,
    pub background_scrub_ledger: bool,
    pub ledger_state: String,
    pub pre_image_hash: String,
    pub expected_post_image_hash: String,
    pub expected_mutation_scope: String,
    pub expected_outcome: String,
    pub pre_ledger_row_count: u32,
    pub expected_post_ledger_row_count: u32,
    pub expected_visible_namespace: VisibleNamespace,
    pub host_paths_touched: Vec<String>,
    pub cleanup_status: String,
    pub artifact_paths: Vec<String>,
    pub reproduction_command: String,
    #[serde(default)]
    pub host_skip_reason: String,
    #[serde(default)]
    pub follow_up_bead: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VisibleNamespace {
    pub present_paths: Vec<String>,
    pub absent_paths: Vec<String>,
    pub xattr_state: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedRepairMutationBoundaryReport {
    pub schema_version: u32,
    pub matrix_id: String,
    pub bead_id: String,
    pub scenario_count: usize,
    pub kinds_seen: Vec<String>,
    pub valid: bool,
    pub errors: Vec<String>,
}

pub fn parse_mounted_repair_mutation_boundary(
    text: &str,
) -> Result<MountedRepairMutationBoundary> {
    serde_json::from_str(text).map_err(|err| {
        anyhow::anyhow!("failed to parse mounted repair mutation boundary JSON: {err}")
    })
}

pub fn validate_default_mounted_repair_mutation_boundary()
-> Result<MountedRepairMutationBoundaryReport> {
    let matrix =
        parse_mounted_repair_mutation_boundary(DEFAULT_MOUNTED_REPAIR_MUTATION_BOUNDARY_JSON)?;
    let report = validate_mounted_repair_mutation_boundary(&matrix);
    if !report.valid {
        bail!(
            "mounted repair mutation boundary failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        );
    }
    Ok(report)
}

#[must_use]
pub fn validate_mounted_repair_mutation_boundary(
    matrix: &MountedRepairMutationBoundary,
) -> MountedRepairMutationBoundaryReport {
    let mut errors = Vec::new();
    let mut ids = BTreeSet::new();
    let mut kinds = BTreeSet::new();

    validate_top_level(matrix, &mut errors);
    for scenario in &matrix.scenarios {
        validate_scenario(scenario, &mut ids, &mut kinds, &mut errors);
    }
    validate_required_kinds(&kinds, &mut errors);

    MountedRepairMutationBoundaryReport {
        schema_version: matrix.schema_version,
        matrix_id: matrix.matrix_id.clone(),
        bead_id: matrix.bead_id.clone(),
        scenario_count: matrix.scenarios.len(),
        kinds_seen: kinds.into_iter().collect(),
        valid: errors.is_empty(),
        errors,
    }
}

fn validate_top_level(
    matrix: &MountedRepairMutationBoundary,
    errors: &mut Vec<String>,
) {
    if matrix.schema_version != MOUNTED_REPAIR_MUTATION_BOUNDARY_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version must be {MOUNTED_REPAIR_MUTATION_BOUNDARY_SCHEMA_VERSION}, got {}",
            matrix.schema_version
        ));
    }
    if matrix.matrix_id.trim().is_empty() {
        errors.push("mounted repair mutation boundary missing matrix_id".to_owned());
    }
    if !matrix.bead_id.starts_with("bd-") {
        errors.push(format!(
            "mounted repair mutation boundary bead_id must look like bd-..., got `{}`",
            matrix.bead_id
        ));
    }
    if matrix.scenarios.is_empty() {
        errors.push(
            "mounted repair mutation boundary must declare at least one scenario".to_owned(),
        );
    }
}

fn validate_scenario(
    scenario: &MutationBoundaryScenario,
    ids: &mut BTreeSet<String>,
    kinds: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    if !ids.insert(scenario.scenario_id.clone()) {
        errors.push(format!(
            "duplicate mutation boundary scenario_id `{}`",
            scenario.scenario_id
        ));
    }
    if !scenario.scenario_id.starts_with("repair_boundary_") {
        errors.push(format!(
            "scenario_id `{}` must start with repair_boundary_",
            scenario.scenario_id
        ));
    }
    if ALLOWED_KINDS.contains(&scenario.kind.as_str()) {
        kinds.insert(scenario.kind.clone());
    } else {
        errors.push(format!(
            "scenario `{}` has unsupported kind `{}`",
            scenario.scenario_id, scenario.kind
        ));
    }
    if !["read_only", "read_write"].contains(&scenario.mount_mode.as_str()) {
        errors.push(format!(
            "scenario `{}` has unsupported mount_mode `{}`",
            scenario.scenario_id, scenario.mount_mode
        ));
    }

    validate_scenario_hashes(scenario, errors);
    validate_scenario_mutation_scope(scenario, errors);
    validate_scenario_outcome(scenario, errors);
    validate_scenario_ledger(scenario, errors);
    validate_scenario_envelope(scenario, errors);
    validate_kind_specific_invariants(scenario, errors);
}

fn validate_scenario_hashes(
    scenario: &MutationBoundaryScenario,
    errors: &mut Vec<String>,
) {
    if !is_valid_sha256(&scenario.pre_image_hash) {
        errors.push(format!(
            "scenario `{}` pre_image_hash must be sha256:<64-hex>",
            scenario.scenario_id
        ));
    }
    let expects_image_change = scenario.expected_mutation_scope == "image_repair_path_and_ledger";
    if expects_image_change {
        if !is_valid_sha256(&scenario.expected_post_image_hash) {
            errors.push(format!(
                "scenario `{}` image-mutating outcome must declare a valid expected_post_image_hash",
                scenario.scenario_id
            ));
        }
        if scenario.expected_post_image_hash == scenario.pre_image_hash {
            errors.push(format!(
                "scenario `{}` image-mutating outcome must change the image hash",
                scenario.scenario_id
            ));
        }
    } else if scenario.expected_post_image_hash != scenario.pre_image_hash {
        errors.push(format!(
            "scenario `{}` non-image-mutating outcome must keep expected_post_image_hash equal to pre_image_hash",
            scenario.scenario_id
        ));
    }
}

fn validate_scenario_mutation_scope(
    scenario: &MutationBoundaryScenario,
    errors: &mut Vec<String>,
) {
    if !ALLOWED_MUTATION_SCOPES.contains(&scenario.expected_mutation_scope.as_str()) {
        errors.push(format!(
            "scenario `{}` has unsupported expected_mutation_scope `{}`",
            scenario.scenario_id, scenario.expected_mutation_scope
        ));
    }
}

fn validate_scenario_outcome(
    scenario: &MutationBoundaryScenario,
    errors: &mut Vec<String>,
) {
    if !ALLOWED_OUTCOMES.contains(&scenario.expected_outcome.as_str()) {
        errors.push(format!(
            "scenario `{}` has unsupported expected_outcome `{}`",
            scenario.scenario_id, scenario.expected_outcome
        ));
    }
    if scenario.expected_outcome == "host_skipped" && scenario.host_skip_reason.trim().is_empty() {
        errors.push(format!(
            "scenario `{}` host_skipped outcome must declare host_skip_reason",
            scenario.scenario_id
        ));
    }
    if scenario.expected_outcome != "host_skipped" && !scenario.host_skip_reason.trim().is_empty() {
        errors.push(format!(
            "scenario `{}` non-host_skipped outcome must leave host_skip_reason empty",
            scenario.scenario_id
        ));
    }
    if matches!(
        scenario.expected_outcome.as_str(),
        "rw_refused" | "ledger_refused"
    ) && !scenario.follow_up_bead.starts_with("bd-")
    {
        errors.push(format!(
            "scenario `{}` refusal outcome must link a follow_up_bead (bd-...)",
            scenario.scenario_id
        ));
    }
}

fn validate_scenario_ledger(
    scenario: &MutationBoundaryScenario,
    errors: &mut Vec<String>,
) {
    if !["present", "missing", "stale", "absent_default"].contains(&scenario.ledger_state.as_str())
    {
        errors.push(format!(
            "scenario `{}` has unsupported ledger_state `{}`",
            scenario.scenario_id, scenario.ledger_state
        ));
    }
    let expects_ledger_growth = scenario.expected_mutation_scope != "no_mutation"
        && scenario.expected_mutation_scope != "refused_no_partial_mutation";
    if expects_ledger_growth
        && scenario.expected_post_ledger_row_count <= scenario.pre_ledger_row_count
    {
        errors.push(format!(
            "scenario `{}` mutating scope must grow the ledger row count",
            scenario.scenario_id
        ));
    }
    if !expects_ledger_growth
        && scenario.expected_post_ledger_row_count != scenario.pre_ledger_row_count
    {
        errors.push(format!(
            "scenario `{}` non-mutating scope must leave ledger row count unchanged",
            scenario.scenario_id
        ));
    }
}

fn validate_scenario_envelope(
    scenario: &MutationBoundaryScenario,
    errors: &mut Vec<String>,
) {
    if !ALLOWED_CLEANUP_STATUSES.contains(&scenario.cleanup_status.as_str()) {
        errors.push(format!(
            "scenario `{}` has unsupported cleanup_status `{}`",
            scenario.scenario_id, scenario.cleanup_status
        ));
    }
    if scenario.artifact_paths.is_empty() {
        errors.push(format!(
            "scenario `{}` must declare at least one artifact_path",
            scenario.scenario_id
        ));
    }
    if scenario.reproduction_command.trim().is_empty() {
        errors.push(format!(
            "scenario `{}` missing reproduction_command",
            scenario.scenario_id
        ));
    }
    let allowed_host_path_prefixes = ["artifacts/", "<tempdir>/", "./"];
    for path in &scenario.host_paths_touched {
        if !allowed_host_path_prefixes
            .iter()
            .any(|prefix| path.starts_with(*prefix))
        {
            errors.push(format!(
                "scenario `{}` host_paths_touched `{}` must live under artifacts/, <tempdir>/, or ./",
                scenario.scenario_id, path
            ));
        }
    }
}

fn validate_kind_specific_invariants(
    scenario: &MutationBoundaryScenario,
    errors: &mut Vec<String>,
) {
    match scenario.kind.as_str() {
        "default_ro_detection_only" => {
            if scenario.mount_mode != "read_only"
                || scenario.background_repair
                || !scenario.background_scrub_ledger
            {
                errors.push(format!(
                    "scenario `{}` default_ro_detection_only requires read_only + background_scrub_ledger and forbids background_repair",
                    scenario.scenario_id
                ));
            }
            if scenario.expected_mutation_scope != "no_mutation" {
                errors.push(format!(
                    "scenario `{}` default_ro_detection_only must report no_mutation",
                    scenario.scenario_id
                ));
            }
            if scenario.expected_outcome != "detection_only" {
                errors.push(format!(
                    "scenario `{}` default_ro_detection_only must classify as detection_only",
                    scenario.scenario_id
                ));
            }
        }
        "ro_repair_with_ledger_allowed" => {
            if scenario.mount_mode != "read_only" || !scenario.background_repair {
                errors.push(format!(
                    "scenario `{}` ro_repair_with_ledger_allowed requires read_only + background_repair",
                    scenario.scenario_id
                ));
            }
            if scenario.expected_mutation_scope != "image_repair_path_and_ledger" {
                errors.push(format!(
                    "scenario `{}` ro_repair_with_ledger_allowed must declare expected_mutation_scope=image_repair_path_and_ledger",
                    scenario.scenario_id
                ));
            }
            if scenario.expected_outcome != "ledger_repair_applied" {
                errors.push(format!(
                    "scenario `{}` ro_repair_with_ledger_allowed must classify as ledger_repair_applied",
                    scenario.scenario_id
                ));
            }
        }
        "rw_repair_refused" => {
            if scenario.mount_mode != "read_write" || !scenario.background_repair {
                errors.push(format!(
                    "scenario `{}` rw_repair_refused requires read_write + background_repair",
                    scenario.scenario_id
                ));
            }
            if scenario.expected_mutation_scope != "refused_no_partial_mutation" {
                errors.push(format!(
                    "scenario `{}` rw_repair_refused must declare expected_mutation_scope=refused_no_partial_mutation",
                    scenario.scenario_id
                ));
            }
            if scenario.expected_outcome != "rw_refused" {
                errors.push(format!(
                    "scenario `{}` rw_repair_refused must classify as rw_refused",
                    scenario.scenario_id
                ));
            }
        }
        "missing_ledger_refused" | "stale_ledger_refused" => {
            if scenario.expected_mutation_scope != "refused_no_partial_mutation" {
                errors.push(format!(
                    "scenario `{}` ledger refusal must declare refused_no_partial_mutation",
                    scenario.scenario_id
                ));
            }
            if scenario.expected_outcome != "ledger_refused" {
                errors.push(format!(
                    "scenario `{}` ledger refusal must classify as ledger_refused",
                    scenario.scenario_id
                ));
            }
        }
        "host_capability_skip" => {
            if scenario.expected_outcome != "host_skipped" {
                errors.push(format!(
                    "scenario `{}` host_capability_skip must classify as host_skipped",
                    scenario.scenario_id
                ));
            }
            if scenario.expected_mutation_scope != "no_mutation" {
                errors.push(format!(
                    "scenario `{}` host_capability_skip must declare no_mutation",
                    scenario.scenario_id
                ));
            }
        }
        _ => {}
    }
}

fn validate_required_kinds(seen: &BTreeSet<String>, errors: &mut Vec<String>) {
    for required in REQUIRED_KINDS {
        if !seen.contains(required) {
            errors.push(format!(
                "mounted repair mutation boundary missing required kind `{required}`"
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

    fn fixture_matrix() -> MountedRepairMutationBoundary {
        parse_mounted_repair_mutation_boundary(DEFAULT_MOUNTED_REPAIR_MUTATION_BOUNDARY_JSON)
            .expect("default mounted repair mutation boundary parses")
    }

    #[test]
    fn default_matrix_validates_required_kinds() {
        let report = validate_default_mounted_repair_mutation_boundary()
            .expect("default mounted repair mutation boundary validates");
        assert_eq!(report.bead_id, "bd-wjsuj");
        for kind in REQUIRED_KINDS {
            assert!(
                report.kinds_seen.iter().any(|k| k == kind),
                "missing kind {kind}"
            );
        }
    }

    #[test]
    fn missing_rw_refusal_kind_is_rejected() {
        let mut matrix = fixture_matrix();
        matrix.scenarios.retain(|s| s.kind != "rw_repair_refused");
        let report = validate_mounted_repair_mutation_boundary(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required kind `rw_repair_refused`"))
        );
    }

    #[test]
    fn missing_stale_ledger_kind_is_rejected() {
        let mut matrix = fixture_matrix();
        matrix.scenarios.retain(|s| s.kind != "stale_ledger_refused");
        let report = validate_mounted_repair_mutation_boundary(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required kind `stale_ledger_refused`"))
        );
    }

    #[test]
    fn duplicate_scenario_id_is_rejected() {
        let mut matrix = fixture_matrix();
        let dup = matrix.scenarios[0].scenario_id.clone();
        matrix.scenarios[1].scenario_id = dup;
        let report = validate_mounted_repair_mutation_boundary(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("duplicate mutation boundary scenario_id"))
        );
    }

    #[test]
    fn scenario_id_prefix_is_enforced() {
        let mut matrix = fixture_matrix();
        matrix.scenarios[0].scenario_id = "repair_001".to_owned();
        let report = validate_mounted_repair_mutation_boundary(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must start with repair_boundary_"))
        );
    }

    #[test]
    fn default_ro_detection_must_report_no_mutation() {
        let mut matrix = fixture_matrix();
        let scenario = matrix
            .scenarios
            .iter_mut()
            .find(|s| s.kind == "default_ro_detection_only")
            .expect("default_ro_detection_only fixture exists");
        scenario.expected_mutation_scope = "ledger_only".to_owned();
        scenario.expected_post_ledger_row_count = scenario.pre_ledger_row_count + 1;
        let report = validate_mounted_repair_mutation_boundary(&matrix);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("default_ro_detection_only must report no_mutation"))
        );
    }

    #[test]
    fn default_ro_detection_cannot_pass_background_repair() {
        let mut matrix = fixture_matrix();
        let scenario = matrix
            .scenarios
            .iter_mut()
            .find(|s| s.kind == "default_ro_detection_only")
            .expect("default detection fixture exists");
        scenario.background_repair = true;
        let report = validate_mounted_repair_mutation_boundary(&matrix);
        assert!(report.errors.iter().any(|err| err
            .contains("default_ro_detection_only requires read_only + background_scrub_ledger")));
    }

    #[test]
    fn ro_repair_with_ledger_must_change_image_hash() {
        let mut matrix = fixture_matrix();
        let scenario = matrix
            .scenarios
            .iter_mut()
            .find(|s| s.kind == "ro_repair_with_ledger_allowed")
            .expect("ro repair fixture exists");
        scenario.expected_post_image_hash = scenario.pre_image_hash.clone();
        let report = validate_mounted_repair_mutation_boundary(&matrix);
        assert!(report.errors.iter().any(|err| err
            .contains("image-mutating outcome must change the image hash")));
    }

    #[test]
    fn ro_repair_with_ledger_must_grow_ledger() {
        let mut matrix = fixture_matrix();
        let scenario = matrix
            .scenarios
            .iter_mut()
            .find(|s| s.kind == "ro_repair_with_ledger_allowed")
            .expect("ro repair fixture exists");
        scenario.expected_post_ledger_row_count = scenario.pre_ledger_row_count;
        let report = validate_mounted_repair_mutation_boundary(&matrix);
        assert!(report.errors.iter().any(|err| err
            .contains("mutating scope must grow the ledger row count")));
    }

    #[test]
    fn rw_refusal_must_keep_image_hash_stable() {
        let mut matrix = fixture_matrix();
        let scenario = matrix
            .scenarios
            .iter_mut()
            .find(|s| s.kind == "rw_repair_refused")
            .expect("rw refusal fixture exists");
        scenario.expected_post_image_hash =
            "sha256:00000000000000000000000000000000000000000000000000000000000000ff".to_owned();
        let report = validate_mounted_repair_mutation_boundary(&matrix);
        assert!(report.errors.iter().any(|err| err
            .contains("non-image-mutating outcome must keep expected_post_image_hash equal to pre_image_hash")));
    }

    #[test]
    fn rw_refusal_must_keep_ledger_row_count_unchanged() {
        let mut matrix = fixture_matrix();
        let scenario = matrix
            .scenarios
            .iter_mut()
            .find(|s| s.kind == "rw_repair_refused")
            .expect("rw refusal fixture exists");
        scenario.expected_post_ledger_row_count = scenario.pre_ledger_row_count + 5;
        let report = validate_mounted_repair_mutation_boundary(&matrix);
        assert!(report.errors.iter().any(|err| err
            .contains("non-mutating scope must leave ledger row count unchanged")));
    }

    #[test]
    fn rw_refusal_must_link_follow_up_bead() {
        let mut matrix = fixture_matrix();
        let scenario = matrix
            .scenarios
            .iter_mut()
            .find(|s| s.kind == "rw_repair_refused")
            .expect("rw refusal fixture exists");
        scenario.follow_up_bead = String::new();
        let report = validate_mounted_repair_mutation_boundary(&matrix);
        assert!(report.errors.iter().any(|err| err
            .contains("refusal outcome must link a follow_up_bead")));
    }

    #[test]
    fn ledger_refusal_must_classify_correctly() {
        let mut matrix = fixture_matrix();
        let scenario = matrix
            .scenarios
            .iter_mut()
            .find(|s| s.kind == "stale_ledger_refused")
            .expect("stale ledger fixture exists");
        scenario.expected_outcome = "rw_refused".to_owned();
        let report = validate_mounted_repair_mutation_boundary(&matrix);
        assert!(report.errors.iter().any(|err| err
            .contains("ledger refusal must classify as ledger_refused")));
    }

    #[test]
    fn host_skip_outcome_requires_skip_reason() {
        let mut matrix = fixture_matrix();
        let scenario = matrix
            .scenarios
            .iter_mut()
            .find(|s| s.expected_outcome == "host_skipped")
            .expect("host skip fixture exists");
        scenario.host_skip_reason = String::new();
        let report = validate_mounted_repair_mutation_boundary(&matrix);
        assert!(report.errors.iter().any(|err| err
            .contains("host_skipped outcome must declare host_skip_reason")));
    }

    #[test]
    fn host_paths_touched_must_be_sandboxed() {
        let mut matrix = fixture_matrix();
        matrix.scenarios[0]
            .host_paths_touched
            .push("/etc/passwd".to_owned());
        let report = validate_mounted_repair_mutation_boundary(&matrix);
        assert!(report.errors.iter().any(|err| err
            .contains("host_paths_touched") && err.contains("artifacts/")));
    }

    #[test]
    fn unsupported_mount_mode_is_rejected() {
        let mut matrix = fixture_matrix();
        matrix.scenarios[0].mount_mode = "rwx".to_owned();
        let report = validate_mounted_repair_mutation_boundary(&matrix);
        assert!(report.errors.iter().any(|err| err
            .contains("unsupported mount_mode")));
    }

    #[test]
    fn unsupported_mutation_scope_is_rejected() {
        let mut matrix = fixture_matrix();
        matrix.scenarios[0].expected_mutation_scope = "anything_goes".to_owned();
        let report = validate_mounted_repair_mutation_boundary(&matrix);
        assert!(report.errors.iter().any(|err| err
            .contains("unsupported expected_mutation_scope")));
    }

    #[test]
    fn unsupported_ledger_state_is_rejected() {
        let mut matrix = fixture_matrix();
        matrix.scenarios[0].ledger_state = "schroedinger".to_owned();
        let report = validate_mounted_repair_mutation_boundary(&matrix);
        assert!(report.errors.iter().any(|err| err
            .contains("unsupported ledger_state")));
    }

    #[test]
    fn missing_artifact_paths_is_rejected() {
        let mut matrix = fixture_matrix();
        matrix.scenarios[0].artifact_paths.clear();
        let report = validate_mounted_repair_mutation_boundary(&matrix);
        assert!(report.errors.iter().any(|err| err
            .contains("must declare at least one artifact_path")));
    }

    #[test]
    fn missing_reproduction_command_is_rejected() {
        let mut matrix = fixture_matrix();
        matrix.scenarios[0].reproduction_command = String::new();
        let report = validate_mounted_repair_mutation_boundary(&matrix);
        assert!(report.errors.iter().any(|err| err.contains("missing reproduction_command")));
    }

    #[test]
    fn empty_scenarios_list_is_rejected() {
        let mut matrix = fixture_matrix();
        matrix.scenarios.clear();
        let report = validate_mounted_repair_mutation_boundary(&matrix);
        assert!(report.errors.iter().any(|err| err.contains("at least one scenario")));
    }
}
