#![forbid(unsafe_code)]

//! Mounted repair policy conformance fixtures.
//!
//! Tracks bd-rchk7.3: freezes the user-visible repair policy at the mount
//! boundary so README/CLI/docs cannot soften it ahead of evidence. Required
//! scenarios cover (1) default read-only background scrub: detect-only,
//! (2) explicit read-only `--background-repair` with ledger: repair plus
//! symbol refresh, (3) read-write `--background-repair`: rejected until the
//! serialization workstream closes, and (4) ledger evidence lifecycle that
//! records detect → repair → refresh.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MOUNTED_REPAIR_POLICY_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_MOUNTED_REPAIR_POLICY_PATH: &str =
    "tests/mounted-repair-policy/mounted_repair_policy.json";
const DEFAULT_MOUNTED_REPAIR_POLICY_JSON: &str =
    include_str!("../../../tests/mounted-repair-policy/mounted_repair_policy.json");

const ALLOWED_KINDS: [&str; 4] = [
    "default_ro_scrub_detect_only",
    "ro_background_repair_with_ledger",
    "rw_background_repair_rejected",
    "ledger_evidence_lifecycle",
];

const ALLOWED_OUTCOMES: [&str; 4] = [
    "detect_only",
    "repaired_with_symbol_refresh",
    "refused_rw_background_repair",
    "ledger_lifecycle_observed",
];

const ALLOWED_LEDGER_TRANSITIONS: [&str; 5] = [
    "detect_recorded",
    "repair_planned",
    "repair_applied",
    "symbols_refreshed",
    "scrub_clean_after_repair",
];

const ALLOWED_REJECTION_REASONS: [&str; 3] = [
    "rw_serialization_unsupported",
    "missing_ledger",
    "stale_ledger_for_rw_repair",
];

const ALLOWED_CLEANUP_POLICIES: [&str; 3] = [
    "teardown_image",
    "preserve_artifacts_on_failure",
    "preserve_artifacts_always",
];

const REQUIRED_KINDS: [&str; 4] = [
    "default_ro_scrub_detect_only",
    "ro_background_repair_with_ledger",
    "rw_background_repair_rejected",
    "ledger_evidence_lifecycle",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedRepairPolicy {
    pub schema_version: u32,
    pub policy_id: String,
    pub bead_id: String,
    pub scenarios: Vec<MountedRepairScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedRepairScenario {
    pub scenario_id: String,
    pub kind: String,
    pub mount_mode: String,
    pub cli_flags: Vec<String>,
    pub ledger_present: bool,
    pub ledger_id: String,
    pub pre_image_hash: String,
    pub expected_outcome: String,
    #[serde(default)]
    pub rejection_reason: String,
    pub expected_ledger_transitions: Vec<String>,
    pub expected_post_image_hash: String,
    pub expected_symbol_generation_increment: u32,
    pub artifact_requirements: Vec<String>,
    pub cleanup_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedRepairPolicyReport {
    pub schema_version: u32,
    pub policy_id: String,
    pub bead_id: String,
    pub scenario_count: usize,
    pub kinds: Vec<String>,
    pub valid: bool,
    pub errors: Vec<String>,
}

pub fn parse_mounted_repair_policy(text: &str) -> Result<MountedRepairPolicy> {
    serde_json::from_str(text)
        .map_err(|err| anyhow::anyhow!("failed to parse mounted repair policy JSON: {err}"))
}

pub fn validate_default_mounted_repair_policy() -> Result<MountedRepairPolicyReport> {
    let policy = parse_mounted_repair_policy(DEFAULT_MOUNTED_REPAIR_POLICY_JSON)?;
    let report = validate_mounted_repair_policy(&policy);
    if !report.valid {
        bail!(
            "mounted repair policy failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        );
    }
    Ok(report)
}

#[must_use]
pub fn validate_mounted_repair_policy(policy: &MountedRepairPolicy) -> MountedRepairPolicyReport {
    let mut errors = Vec::new();
    let mut ids = BTreeSet::new();
    let mut kinds = BTreeSet::new();

    validate_top_level(policy, &mut errors);
    for scenario in &policy.scenarios {
        validate_scenario(scenario, &mut ids, &mut kinds, &mut errors);
    }
    validate_required_kinds(&kinds, &mut errors);

    MountedRepairPolicyReport {
        schema_version: policy.schema_version,
        policy_id: policy.policy_id.clone(),
        bead_id: policy.bead_id.clone(),
        scenario_count: policy.scenarios.len(),
        kinds: kinds.into_iter().collect(),
        valid: errors.is_empty(),
        errors,
    }
}

fn validate_top_level(policy: &MountedRepairPolicy, errors: &mut Vec<String>) {
    if policy.schema_version != MOUNTED_REPAIR_POLICY_SCHEMA_VERSION {
        errors.push(format!(
            "mounted repair policy schema_version must be {MOUNTED_REPAIR_POLICY_SCHEMA_VERSION}, got {}",
            policy.schema_version
        ));
    }
    if policy.policy_id.trim().is_empty() {
        errors.push("mounted repair policy missing policy_id".to_owned());
    }
    if !policy.bead_id.starts_with("bd-") {
        errors.push(format!(
            "mounted repair policy bead_id must look like bd-..., got `{}`",
            policy.bead_id
        ));
    }
    if policy.scenarios.is_empty() {
        errors.push("mounted repair policy must declare at least one scenario".to_owned());
    }
}

fn validate_scenario(
    scenario: &MountedRepairScenario,
    ids: &mut BTreeSet<String>,
    kinds: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    if !ids.insert(scenario.scenario_id.clone()) {
        errors.push(format!(
            "duplicate mounted repair policy scenario_id `{}`",
            scenario.scenario_id
        ));
    }
    if !scenario.scenario_id.starts_with("mounted_repair_") {
        errors.push(format!(
            "scenario_id `{}` must start with mounted_repair_",
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

    validate_scenario_mode_and_flags(scenario, errors);
    validate_scenario_outcome(scenario, errors);
    validate_scenario_ledger(scenario, errors);
    validate_scenario_envelope(scenario, errors);
}

fn validate_scenario_mode_and_flags(scenario: &MountedRepairScenario, errors: &mut Vec<String>) {
    if !["read_only", "read_write"].contains(&scenario.mount_mode.as_str()) {
        errors.push(format!(
            "scenario `{}` has unsupported mount_mode `{}`",
            scenario.scenario_id, scenario.mount_mode
        ));
    }
    let has_background_repair = scenario
        .cli_flags
        .iter()
        .any(|flag| flag == "--background-repair");
    let has_background_scrub = scenario
        .cli_flags
        .iter()
        .any(|flag| flag == "--background-scrub-ledger");

    match scenario.kind.as_str() {
        "default_ro_scrub_detect_only" => {
            if scenario.mount_mode != "read_only" {
                errors.push(format!(
                    "scenario `{}` default_ro_scrub_detect_only must be read_only",
                    scenario.scenario_id
                ));
            }
            if has_background_repair {
                errors.push(format!(
                    "scenario `{}` default_ro_scrub_detect_only must not pass --background-repair",
                    scenario.scenario_id
                ));
            }
            if !has_background_scrub {
                errors.push(format!(
                    "scenario `{}` default_ro_scrub_detect_only must pass --background-scrub-ledger",
                    scenario.scenario_id
                ));
            }
        }
        "ro_background_repair_with_ledger" => {
            if scenario.mount_mode != "read_only" {
                errors.push(format!(
                    "scenario `{}` ro_background_repair_with_ledger must be read_only",
                    scenario.scenario_id
                ));
            }
            if !has_background_repair {
                errors.push(format!(
                    "scenario `{}` ro_background_repair_with_ledger must pass --background-repair",
                    scenario.scenario_id
                ));
            }
            if !scenario.ledger_present {
                errors.push(format!(
                    "scenario `{}` ro_background_repair_with_ledger requires ledger_present=true",
                    scenario.scenario_id
                ));
            }
        }
        "rw_background_repair_rejected" => {
            if scenario.mount_mode != "read_write" {
                errors.push(format!(
                    "scenario `{}` rw_background_repair_rejected must be read_write",
                    scenario.scenario_id
                ));
            }
            if !has_background_repair {
                errors.push(format!(
                    "scenario `{}` rw_background_repair_rejected must pass --background-repair",
                    scenario.scenario_id
                ));
            }
        }
        "ledger_evidence_lifecycle" if !scenario.ledger_present => errors.push(format!(
            "scenario `{}` ledger_evidence_lifecycle requires ledger_present=true",
            scenario.scenario_id
        )),
        _ => {}
    }
}

fn validate_scenario_outcome(scenario: &MountedRepairScenario, errors: &mut Vec<String>) {
    if !ALLOWED_OUTCOMES.contains(&scenario.expected_outcome.as_str()) {
        errors.push(format!(
            "scenario `{}` has unsupported expected_outcome `{}`",
            scenario.scenario_id, scenario.expected_outcome
        ));
    }
    let must_match_kind = match scenario.kind.as_str() {
        "default_ro_scrub_detect_only" => Some("detect_only"),
        "ro_background_repair_with_ledger" => Some("repaired_with_symbol_refresh"),
        "rw_background_repair_rejected" => Some("refused_rw_background_repair"),
        "ledger_evidence_lifecycle" => Some("ledger_lifecycle_observed"),
        _ => None,
    };
    if let Some(expected) = must_match_kind
        && scenario.expected_outcome != expected
    {
        errors.push(format!(
            "scenario `{}` kind `{}` requires expected_outcome=`{}`",
            scenario.scenario_id, scenario.kind, expected
        ));
    }
    let is_rejection = scenario.expected_outcome == "refused_rw_background_repair";
    if is_rejection {
        if !ALLOWED_REJECTION_REASONS.contains(&scenario.rejection_reason.as_str()) {
            errors.push(format!(
                "scenario `{}` refusal must declare a supported rejection_reason",
                scenario.scenario_id
            ));
        }
    } else if !scenario.rejection_reason.trim().is_empty() {
        errors.push(format!(
            "scenario `{}` non-rejection outcome must leave rejection_reason empty",
            scenario.scenario_id
        ));
    }
}

fn validate_scenario_ledger(scenario: &MountedRepairScenario, errors: &mut Vec<String>) {
    let needs_ledger_id = scenario.ledger_present && !scenario.ledger_id.trim().is_empty();
    if scenario.ledger_present && scenario.ledger_id.trim().is_empty() {
        errors.push(format!(
            "scenario `{}` ledger_present=true requires ledger_id",
            scenario.scenario_id
        ));
    }
    if !scenario.ledger_present && !scenario.ledger_id.trim().is_empty() {
        errors.push(format!(
            "scenario `{}` ledger_present=false must leave ledger_id empty",
            scenario.scenario_id
        ));
    }
    let _ = needs_ledger_id;
    if !is_valid_sha256(&scenario.pre_image_hash) {
        errors.push(format!(
            "scenario `{}` pre_image_hash must be sha256:<64-hex>",
            scenario.scenario_id
        ));
    }

    let needs_post_hash = scenario.expected_outcome == "repaired_with_symbol_refresh"
        || scenario.expected_outcome == "ledger_lifecycle_observed"
        || scenario.expected_outcome == "detect_only";
    if needs_post_hash && !is_valid_sha256(&scenario.expected_post_image_hash) {
        errors.push(format!(
            "scenario `{}` expected_post_image_hash must be sha256:<64-hex>",
            scenario.scenario_id
        ));
    }
    if !needs_post_hash && !scenario.expected_post_image_hash.trim().is_empty() {
        errors.push(format!(
            "scenario `{}` rejection outcome must leave expected_post_image_hash empty",
            scenario.scenario_id
        ));
    }

    for transition in &scenario.expected_ledger_transitions {
        if !ALLOWED_LEDGER_TRANSITIONS.contains(&transition.as_str()) {
            errors.push(format!(
                "scenario `{}` has unsupported ledger transition `{}`",
                scenario.scenario_id, transition
            ));
        }
    }
    let needs_repair_transitions = scenario.expected_outcome == "repaired_with_symbol_refresh"
        || scenario.expected_outcome == "ledger_lifecycle_observed";
    if needs_repair_transitions {
        for required in [
            "detect_recorded",
            "repair_applied",
            "symbols_refreshed",
            "scrub_clean_after_repair",
        ] {
            if !scenario
                .expected_ledger_transitions
                .iter()
                .any(|transition| transition == required)
            {
                errors.push(format!(
                    "scenario `{}` repair lifecycle missing transition `{required}`",
                    scenario.scenario_id
                ));
            }
        }
        if scenario.expected_symbol_generation_increment == 0 {
            errors.push(format!(
                "scenario `{}` repair lifecycle requires expected_symbol_generation_increment > 0",
                scenario.scenario_id
            ));
        }
    } else if scenario.expected_symbol_generation_increment != 0
        && scenario.expected_outcome == "refused_rw_background_repair"
    {
        errors.push(format!(
            "scenario `{}` rejection must leave expected_symbol_generation_increment=0",
            scenario.scenario_id
        ));
    }
    if scenario.expected_outcome == "detect_only" {
        if scenario
            .expected_ledger_transitions
            .iter()
            .any(|transition| transition == "repair_applied" || transition == "symbols_refreshed")
        {
            errors.push(format!(
                "scenario `{}` detect_only must not record repair_applied/symbols_refreshed",
                scenario.scenario_id
            ));
        }
        if scenario.expected_symbol_generation_increment != 0 {
            errors.push(format!(
                "scenario `{}` detect_only must leave expected_symbol_generation_increment=0",
                scenario.scenario_id
            ));
        }
    }
}

fn validate_scenario_envelope(scenario: &MountedRepairScenario, errors: &mut Vec<String>) {
    if !ALLOWED_CLEANUP_POLICIES.contains(&scenario.cleanup_policy.as_str()) {
        errors.push(format!(
            "scenario `{}` has unsupported cleanup_policy `{}`",
            scenario.scenario_id, scenario.cleanup_policy
        ));
    }
    for required in [
        "scenario_id",
        "cli_flags",
        "ledger_id",
        "pre_image_hash",
        "expected_outcome",
        "expected_ledger_transitions",
    ] {
        if !scenario
            .artifact_requirements
            .iter()
            .any(|requirement| requirement == required)
        {
            errors.push(format!(
                "scenario `{}` artifact_requirements missing `{required}`",
                scenario.scenario_id
            ));
        }
    }
}

fn validate_required_kinds(seen: &BTreeSet<String>, errors: &mut Vec<String>) {
    for required in REQUIRED_KINDS {
        if !seen.contains(required) {
            errors.push(format!(
                "mounted repair policy missing required kind `{required}`"
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

    fn fixture_policy() -> MountedRepairPolicy {
        parse_mounted_repair_policy(DEFAULT_MOUNTED_REPAIR_POLICY_JSON)
            .expect("default mounted repair policy parses")
    }

    #[test]
    fn default_policy_validates_required_kinds() {
        let report = validate_default_mounted_repair_policy()
            .expect("default mounted repair policy validates");
        assert_eq!(report.bead_id, "bd-rchk7.3");
        for kind in REQUIRED_KINDS {
            assert!(
                report.kinds.iter().any(|k| k == kind),
                "missing required kind {kind}"
            );
        }
    }

    #[test]
    fn missing_default_scrub_kind_is_rejected() {
        let mut policy = fixture_policy();
        policy
            .scenarios
            .retain(|s| s.kind != "default_ro_scrub_detect_only");
        let report = validate_mounted_repair_policy(&policy);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required kind `default_ro_scrub_detect_only`"))
        );
    }

    #[test]
    fn missing_rw_rejection_kind_is_rejected() {
        let mut policy = fixture_policy();
        policy
            .scenarios
            .retain(|s| s.kind != "rw_background_repair_rejected");
        let report = validate_mounted_repair_policy(&policy);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required kind `rw_background_repair_rejected`"))
        );
    }

    #[test]
    fn duplicate_scenario_id_is_rejected() {
        let mut policy = fixture_policy();
        let dup = policy.scenarios[0].scenario_id.clone();
        policy.scenarios[1].scenario_id = dup;
        let report = validate_mounted_repair_policy(&policy);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("duplicate mounted repair policy scenario_id"))
        );
    }

    #[test]
    fn scenario_id_prefix_is_enforced() {
        let mut policy = fixture_policy();
        policy.scenarios[0].scenario_id = "policy_001".to_owned();
        let report = validate_mounted_repair_policy(&policy);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must start with mounted_repair_"))
        );
    }

    #[test]
    fn default_scrub_must_be_read_only() {
        let mut policy = fixture_policy();
        let scenario = policy
            .scenarios
            .iter_mut()
            .find(|s| s.kind == "default_ro_scrub_detect_only")
            .expect("default scrub fixture exists");
        scenario.mount_mode = "read_write".to_owned();
        let report = validate_mounted_repair_policy(&policy);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("default_ro_scrub_detect_only must be read_only"))
        );
    }

    #[test]
    fn default_scrub_cannot_pass_background_repair() {
        let mut policy = fixture_policy();
        let scenario = policy
            .scenarios
            .iter_mut()
            .find(|s| s.kind == "default_ro_scrub_detect_only")
            .expect("default scrub fixture exists");
        scenario.cli_flags.push("--background-repair".to_owned());
        let report = validate_mounted_repair_policy(&policy);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must not pass --background-repair"))
        );
    }

    #[test]
    fn ro_background_repair_requires_ledger_present() {
        let mut policy = fixture_policy();
        let scenario = policy
            .scenarios
            .iter_mut()
            .find(|s| s.kind == "ro_background_repair_with_ledger")
            .expect("ro repair fixture exists");
        scenario.ledger_present = false;
        scenario.ledger_id = String::new();
        let report = validate_mounted_repair_policy(&policy);
        assert!(report.errors.iter().any(|err| {
            err.contains("ro_background_repair_with_ledger requires ledger_present=true")
        }));
    }

    #[test]
    fn rw_repair_must_be_read_write() {
        let mut policy = fixture_policy();
        let scenario = policy
            .scenarios
            .iter_mut()
            .find(|s| s.kind == "rw_background_repair_rejected")
            .expect("rw rejection fixture exists");
        scenario.mount_mode = "read_only".to_owned();
        let report = validate_mounted_repair_policy(&policy);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("rw_background_repair_rejected must be read_write"))
        );
    }

    #[test]
    fn outcome_must_match_kind() {
        let mut policy = fixture_policy();
        let scenario = policy
            .scenarios
            .iter_mut()
            .find(|s| s.kind == "default_ro_scrub_detect_only")
            .expect("default scrub fixture exists");
        scenario.expected_outcome = "repaired_with_symbol_refresh".to_owned();
        let report = validate_mounted_repair_policy(&policy);
        assert!(report.errors.iter().any(|err| {
            err.contains("default_ro_scrub_detect_only` requires expected_outcome=`detect_only`")
        }));
    }

    #[test]
    fn rejection_outcome_requires_rejection_reason() {
        let mut policy = fixture_policy();
        let scenario = policy
            .scenarios
            .iter_mut()
            .find(|s| s.expected_outcome == "refused_rw_background_repair")
            .expect("rw rejection fixture exists");
        scenario.rejection_reason = String::new();
        let report = validate_mounted_repair_policy(&policy);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("refusal must declare a supported rejection_reason"))
        );
    }

    #[test]
    fn unsupported_rejection_reason_is_rejected() {
        let mut policy = fixture_policy();
        let scenario = policy
            .scenarios
            .iter_mut()
            .find(|s| s.expected_outcome == "refused_rw_background_repair")
            .expect("rw rejection fixture exists");
        scenario.rejection_reason = "spooky_action".to_owned();
        let report = validate_mounted_repair_policy(&policy);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("supported rejection_reason"))
        );
    }

    #[test]
    fn non_rejection_outcome_must_leave_rejection_empty() {
        let mut policy = fixture_policy();
        let scenario = policy
            .scenarios
            .iter_mut()
            .find(|s| s.expected_outcome == "detect_only")
            .expect("detect-only fixture exists");
        scenario.rejection_reason = "rw_serialization_unsupported".to_owned();
        let report = validate_mounted_repair_policy(&policy);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("non-rejection outcome must leave rejection_reason empty"))
        );
    }

    #[test]
    fn ledger_present_requires_ledger_id() {
        let mut policy = fixture_policy();
        let scenario = policy
            .scenarios
            .iter_mut()
            .find(|s| s.ledger_present)
            .expect("ledger fixture exists");
        scenario.ledger_id = String::new();
        let report = validate_mounted_repair_policy(&policy);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("ledger_present=true requires ledger_id"))
        );
    }

    #[test]
    fn malformed_pre_image_hash_is_rejected() {
        let mut policy = fixture_policy();
        policy.scenarios[0].pre_image_hash = "md5:not-supported".to_owned();
        let report = validate_mounted_repair_policy(&policy);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("pre_image_hash must be sha256"))
        );
    }

    #[test]
    fn repair_lifecycle_requires_full_transition_set() {
        let mut policy = fixture_policy();
        let scenario = policy
            .scenarios
            .iter_mut()
            .find(|s| s.expected_outcome == "repaired_with_symbol_refresh")
            .expect("repair fixture exists");
        scenario
            .expected_ledger_transitions
            .retain(|transition| transition != "symbols_refreshed");
        let report = validate_mounted_repair_policy(&policy);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing transition `symbols_refreshed`"))
        );
    }

    #[test]
    fn repair_lifecycle_requires_symbol_increment() {
        let mut policy = fixture_policy();
        let scenario = policy
            .scenarios
            .iter_mut()
            .find(|s| s.expected_outcome == "repaired_with_symbol_refresh")
            .expect("repair fixture exists");
        scenario.expected_symbol_generation_increment = 0;
        let report = validate_mounted_repair_policy(&policy);
        assert!(report.errors.iter().any(|err| {
            err.contains("repair lifecycle requires expected_symbol_generation_increment > 0")
        }));
    }

    #[test]
    fn detect_only_must_not_record_repair_transition() {
        let mut policy = fixture_policy();
        let scenario = policy
            .scenarios
            .iter_mut()
            .find(|s| s.expected_outcome == "detect_only")
            .expect("detect-only fixture exists");
        scenario
            .expected_ledger_transitions
            .push("repair_applied".to_owned());
        let report = validate_mounted_repair_policy(&policy);
        assert!(report.errors.iter().any(|err| {
            err.contains("detect_only must not record repair_applied/symbols_refreshed")
        }));
    }

    #[test]
    fn missing_artifact_requirement_is_rejected() {
        let mut policy = fixture_policy();
        policy.scenarios[0]
            .artifact_requirements
            .retain(|r| r != "expected_ledger_transitions");
        let report = validate_mounted_repair_policy(&policy);
        assert!(report.errors.iter().any(|err| {
            err.contains("artifact_requirements missing `expected_ledger_transitions`")
        }));
    }

    #[test]
    fn empty_scenarios_list_is_rejected() {
        let mut policy = fixture_policy();
        policy.scenarios.clear();
        let report = validate_mounted_repair_policy(&policy);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("at least one scenario"))
        );
    }
}
