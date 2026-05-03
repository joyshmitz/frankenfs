#![forbid(unsafe_code)]

//! Two-key gate for enabling rw `--background-repair`.
//!
//! Tracks bd-bqgy8: this is the final fail-closed evaluator for the
//! highest-risk operator-facing switch. Enabling rw background repair
//! requires *both* implementation evidence (serialization, mounted-write
//! matrix, race tests, repair corpus, release-gate posture) *and* explicit
//! operator intent (CLI opt-in plus a confirmed rollback/disable path).
//! Any stale, missing, downgraded, or contradicted artifact must produce a
//! stable refusal token so docs and feature-state code cannot hand-upgrade
//! ahead of evidence.

use serde::{Deserialize, Serialize};

pub const RW_BACKGROUND_REPAIR_GATE_SCHEMA_VERSION: u32 = 1;

/// Required evidence lanes the gate consults.
pub const REQUIRED_EVIDENCE_LANES: [&str; 6] = [
    "serialization_gate",
    "mounted_write_matrix",
    "race_tests",
    "repair_corpus",
    "release_gate",
    "remediation_catalog",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RwBackgroundRepairGate {
    pub schema_version: u32,
    pub gate_version: String,
    pub bead_id: String,
    pub default_state: String,
    pub operator_opt_in: bool,
    pub rollback_command: String,
    pub rollback_artifact_present: bool,
    pub serialization_gate: ArtifactPosture,
    pub mounted_write_matrix: ArtifactPosture,
    pub race_tests: ArtifactPosture,
    pub repair_corpus: ArtifactPosture,
    pub release_gate: ArtifactPosture,
    pub remediation_catalog: RemediationLink,
    pub writeback_cache_state: String,
    pub image_writable: bool,
    pub conflicting_flags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactPosture {
    pub artifact_id: String,
    pub fresh: bool,
    pub passed: bool,
    pub downgraded: bool,
    pub artifact_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationLink {
    pub remediation_id: String,
    pub linked_bead: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum RwBackgroundRepairDecision {
    Accept,
    Refuse {
        reason: String,
        controlling_artifact: String,
        remediation: String,
    },
}

#[must_use]
pub fn evaluate_rw_background_repair_gate(
    gate: &RwBackgroundRepairGate,
) -> RwBackgroundRepairDecision {
    if let Some(decision) = check_default_and_opt_in(gate) {
        return decision;
    }
    if let Some(decision) = check_image_and_writeback(gate) {
        return decision;
    }
    if let Some(decision) = check_artifact_posture(
        "serialization_gate",
        &gate.serialization_gate,
        "stale_serialization_gate",
    ) {
        return decision;
    }
    if let Some(decision) = check_artifact_posture(
        "mounted_write_matrix",
        &gate.mounted_write_matrix,
        "stale_mounted_write_matrix",
    ) {
        return decision;
    }
    if let Some(decision) =
        check_artifact_posture("race_tests", &gate.race_tests, "stale_race_tests")
    {
        return decision;
    }
    if let Some(decision) =
        check_artifact_posture("repair_corpus", &gate.repair_corpus, "stale_repair_corpus")
    {
        return decision;
    }
    if let Some(decision) = check_artifact_posture(
        "release_gate",
        &gate.release_gate,
        "downgraded_release_gate",
    ) {
        return decision;
    }
    if let Some(decision) = check_remediation_catalog(gate) {
        return decision;
    }
    if let Some(decision) = check_rollback_path(gate) {
        return decision;
    }
    if let Some(decision) = check_conflicting_flags(gate) {
        return decision;
    }
    RwBackgroundRepairDecision::Accept
}

fn check_default_and_opt_in(gate: &RwBackgroundRepairGate) -> Option<RwBackgroundRepairDecision> {
    if gate.default_state != "disabled" {
        return Some(refuse(
            "default_state_must_be_disabled",
            "rw_background_repair_default",
            "config default for rw background repair must remain disabled",
        ));
    }
    if !gate.operator_opt_in {
        return Some(refuse(
            "missing_operator_opt_in",
            "rw_background_repair_default",
            "operator must pass --background-repair-opt-in before enablement is considered",
        ));
    }
    None
}

fn check_image_and_writeback(gate: &RwBackgroundRepairGate) -> Option<RwBackgroundRepairDecision> {
    if !gate.image_writable {
        return Some(refuse(
            "unwritable_image",
            "rw_background_repair_image",
            "image is not writable; rebuild the image with rw permissions before enabling",
        ));
    }
    if gate.writeback_cache_state == "unsafe" || gate.writeback_cache_state == "stale" {
        return Some(refuse(
            "unsafe_writeback_cache_state",
            "writeback_cache_audit",
            "writeback_cache audit must be `safe` before rw background repair is allowed",
        ));
    }
    if gate.writeback_cache_state != "disabled"
        && gate.writeback_cache_state != "safe"
        && gate.writeback_cache_state != "audited_disabled"
    {
        return Some(refuse(
            "unsafe_writeback_cache_state",
            "writeback_cache_audit",
            "writeback_cache state must be one of: disabled, safe, audited_disabled",
        ));
    }
    None
}

fn check_artifact_posture(
    lane: &str,
    posture: &ArtifactPosture,
    refusal_token: &str,
) -> Option<RwBackgroundRepairDecision> {
    if posture.artifact_id.trim().is_empty() {
        return Some(refuse(
            "missing_evidence_artifact",
            lane,
            "controlling evidence artifact id is missing",
        ));
    }
    if !posture.fresh {
        return Some(refuse(
            refusal_token,
            lane,
            "regenerate this artifact before enabling rw background repair",
        ));
    }
    if !posture.passed {
        return Some(refuse(
            refusal_token,
            lane,
            "artifact did not pass; do not enable until the lane is green again",
        ));
    }
    if posture.downgraded {
        return Some(refuse(
            "downgraded_release_gate",
            lane,
            "controlling lane was downgraded; rerun with the authoritative configuration",
        ));
    }
    None
}

fn check_remediation_catalog(gate: &RwBackgroundRepairGate) -> Option<RwBackgroundRepairDecision> {
    if gate.remediation_catalog.remediation_id.trim().is_empty() {
        return Some(refuse(
            "missing_remediation_entry",
            "remediation_catalog",
            "every refusal path must point to a remediation entry; add one before enabling",
        ));
    }
    if !gate.remediation_catalog.remediation_id.starts_with("rem_") {
        return Some(refuse(
            "missing_remediation_entry",
            "remediation_catalog",
            "remediation_id must use the `rem_` prefix from remediation_catalog",
        ));
    }
    if !gate.remediation_catalog.linked_bead.starts_with("bd-") {
        return Some(refuse(
            "missing_remediation_entry",
            "remediation_catalog",
            "remediation linked_bead must look like bd-...",
        ));
    }
    None
}

fn check_rollback_path(gate: &RwBackgroundRepairGate) -> Option<RwBackgroundRepairDecision> {
    if gate.rollback_command.trim().is_empty() {
        return Some(refuse(
            "missing_rollback_path",
            "rw_background_repair_rollback",
            "declare a rollback/disable command before enabling",
        ));
    }
    if !gate.rollback_artifact_present {
        return Some(refuse(
            "missing_rollback_path",
            "rw_background_repair_rollback",
            "stage a rollback artifact (snapshot, image clone) before enabling",
        ));
    }
    None
}

fn check_conflicting_flags(gate: &RwBackgroundRepairGate) -> Option<RwBackgroundRepairDecision> {
    let banned = [
        "background-repair-force",
        "background-repair-skip-gate",
        "background-repair-disable-rollback",
        "background-repair-ignore-stale",
    ];
    if gate
        .conflicting_flags
        .iter()
        .any(|flag| banned.contains(&flag.as_str()))
    {
        return Some(refuse(
            "conflicting_cli_flags",
            "rw_background_repair_cli",
            "remove conflicting CLI flags before enabling rw background repair",
        ));
    }
    None
}

fn refuse(reason: &str, controlling: &str, remediation: &str) -> RwBackgroundRepairDecision {
    RwBackgroundRepairDecision::Refuse {
        reason: reason.to_owned(),
        controlling_artifact: controlling.to_owned(),
        remediation: remediation.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn happy_artifact(id: &str) -> ArtifactPosture {
        ArtifactPosture {
            artifact_id: id.to_owned(),
            fresh: true,
            passed: true,
            downgraded: false,
            artifact_path: format!("artifacts/qa/{id}.json"),
        }
    }

    fn happy_gate() -> RwBackgroundRepairGate {
        RwBackgroundRepairGate {
            schema_version: RW_BACKGROUND_REPAIR_GATE_SCHEMA_VERSION,
            gate_version: "v1".to_owned(),
            bead_id: "bd-bqgy8".to_owned(),
            default_state: "disabled".to_owned(),
            operator_opt_in: true,
            rollback_command: "ffs --disable-background-repair".to_owned(),
            rollback_artifact_present: true,
            serialization_gate: happy_artifact("serialization_gate"),
            mounted_write_matrix: happy_artifact("mounted_write_matrix"),
            race_tests: happy_artifact("race_tests"),
            repair_corpus: happy_artifact("repair_corpus"),
            release_gate: happy_artifact("release_gate"),
            remediation_catalog: RemediationLink {
                remediation_id: "rem_unsafe_repair_refused".to_owned(),
                linked_bead: "bd-rchk0.5.3".to_owned(),
            },
            writeback_cache_state: "audited_disabled".to_owned(),
            image_writable: true,
            conflicting_flags: Vec::new(),
        }
    }

    fn refusal_reason(decision: &RwBackgroundRepairDecision) -> Option<&str> {
        if let RwBackgroundRepairDecision::Refuse { reason, .. } = decision {
            Some(reason.as_str())
        } else {
            None
        }
    }

    #[test]
    fn happy_gate_accepts_rw_background_repair() {
        let decision = evaluate_rw_background_repair_gate(&happy_gate());
        assert!(matches!(decision, RwBackgroundRepairDecision::Accept));
    }

    #[test]
    fn default_state_must_be_disabled() {
        let mut gate = happy_gate();
        gate.default_state = "experimental_enabled".to_owned();
        let decision = evaluate_rw_background_repair_gate(&gate);
        assert_eq!(
            refusal_reason(&decision),
            Some("default_state_must_be_disabled")
        );
    }

    #[test]
    fn missing_operator_opt_in_is_rejected() {
        let mut gate = happy_gate();
        gate.operator_opt_in = false;
        let decision = evaluate_rw_background_repair_gate(&gate);
        assert_eq!(refusal_reason(&decision), Some("missing_operator_opt_in"));
    }

    #[test]
    fn unwritable_image_is_rejected() {
        let mut gate = happy_gate();
        gate.image_writable = false;
        let decision = evaluate_rw_background_repair_gate(&gate);
        assert_eq!(refusal_reason(&decision), Some("unwritable_image"));
    }

    #[test]
    fn unsafe_writeback_cache_is_rejected() {
        let mut gate = happy_gate();
        gate.writeback_cache_state = "unsafe".to_owned();
        let decision = evaluate_rw_background_repair_gate(&gate);
        assert_eq!(
            refusal_reason(&decision),
            Some("unsafe_writeback_cache_state")
        );
    }

    #[test]
    fn stale_writeback_cache_is_rejected() {
        let mut gate = happy_gate();
        gate.writeback_cache_state = "stale".to_owned();
        let decision = evaluate_rw_background_repair_gate(&gate);
        assert_eq!(
            refusal_reason(&decision),
            Some("unsafe_writeback_cache_state")
        );
    }

    #[test]
    fn stale_serialization_gate_is_rejected() {
        let mut gate = happy_gate();
        gate.serialization_gate.fresh = false;
        let decision = evaluate_rw_background_repair_gate(&gate);
        assert_eq!(refusal_reason(&decision), Some("stale_serialization_gate"));
    }

    #[test]
    fn failed_serialization_gate_is_rejected() {
        let mut gate = happy_gate();
        gate.serialization_gate.passed = false;
        let decision = evaluate_rw_background_repair_gate(&gate);
        assert_eq!(refusal_reason(&decision), Some("stale_serialization_gate"));
    }

    #[test]
    fn stale_mounted_write_matrix_is_rejected() {
        let mut gate = happy_gate();
        gate.mounted_write_matrix.fresh = false;
        let decision = evaluate_rw_background_repair_gate(&gate);
        assert_eq!(
            refusal_reason(&decision),
            Some("stale_mounted_write_matrix")
        );
    }

    #[test]
    fn stale_race_tests_is_rejected() {
        let mut gate = happy_gate();
        gate.race_tests.fresh = false;
        let decision = evaluate_rw_background_repair_gate(&gate);
        assert_eq!(refusal_reason(&decision), Some("stale_race_tests"));
    }

    #[test]
    fn stale_repair_corpus_is_rejected() {
        let mut gate = happy_gate();
        gate.repair_corpus.fresh = false;
        let decision = evaluate_rw_background_repair_gate(&gate);
        assert_eq!(refusal_reason(&decision), Some("stale_repair_corpus"));
    }

    #[test]
    fn downgraded_release_gate_is_rejected() {
        let mut gate = happy_gate();
        gate.release_gate.downgraded = true;
        let decision = evaluate_rw_background_repair_gate(&gate);
        assert_eq!(refusal_reason(&decision), Some("downgraded_release_gate"));
    }

    #[test]
    fn missing_remediation_entry_is_rejected() {
        let mut gate = happy_gate();
        gate.remediation_catalog.remediation_id = String::new();
        let decision = evaluate_rw_background_repair_gate(&gate);
        assert_eq!(refusal_reason(&decision), Some("missing_remediation_entry"));
    }

    #[test]
    fn malformed_remediation_id_is_rejected() {
        let mut gate = happy_gate();
        gate.remediation_catalog.remediation_id = "fix-it".to_owned();
        let decision = evaluate_rw_background_repair_gate(&gate);
        assert_eq!(refusal_reason(&decision), Some("missing_remediation_entry"));
    }

    #[test]
    fn malformed_remediation_linked_bead_is_rejected() {
        let mut gate = happy_gate();
        gate.remediation_catalog.linked_bead = "PROJ-99".to_owned();
        let decision = evaluate_rw_background_repair_gate(&gate);
        assert_eq!(refusal_reason(&decision), Some("missing_remediation_entry"));
    }

    #[test]
    fn missing_rollback_command_is_rejected() {
        let mut gate = happy_gate();
        gate.rollback_command = String::new();
        let decision = evaluate_rw_background_repair_gate(&gate);
        assert_eq!(refusal_reason(&decision), Some("missing_rollback_path"));
    }

    #[test]
    fn missing_rollback_artifact_is_rejected() {
        let mut gate = happy_gate();
        gate.rollback_artifact_present = false;
        let decision = evaluate_rw_background_repair_gate(&gate);
        assert_eq!(refusal_reason(&decision), Some("missing_rollback_path"));
    }

    #[test]
    fn conflicting_force_flag_is_rejected() {
        let mut gate = happy_gate();
        gate.conflicting_flags
            .push("background-repair-force".to_owned());
        let decision = evaluate_rw_background_repair_gate(&gate);
        assert_eq!(refusal_reason(&decision), Some("conflicting_cli_flags"));
    }

    #[test]
    fn conflicting_skip_gate_flag_is_rejected() {
        let mut gate = happy_gate();
        gate.conflicting_flags
            .push("background-repair-skip-gate".to_owned());
        let decision = evaluate_rw_background_repair_gate(&gate);
        assert_eq!(refusal_reason(&decision), Some("conflicting_cli_flags"));
    }

    #[test]
    fn unrelated_flag_is_ignored() {
        let mut gate = happy_gate();
        gate.conflicting_flags.push("noatime".to_owned());
        let decision = evaluate_rw_background_repair_gate(&gate);
        assert!(matches!(decision, RwBackgroundRepairDecision::Accept));
    }

    #[test]
    fn missing_evidence_artifact_id_is_rejected() {
        let mut gate = happy_gate();
        gate.serialization_gate.artifact_id = String::new();
        let decision = evaluate_rw_background_repair_gate(&gate);
        assert_eq!(refusal_reason(&decision), Some("missing_evidence_artifact"));
    }

    #[test]
    fn refuse_decision_carries_controlling_artifact_token() {
        let mut gate = happy_gate();
        gate.race_tests.fresh = false;
        let decision = evaluate_rw_background_repair_gate(&gate);
        if let RwBackgroundRepairDecision::Refuse {
            controlling_artifact,
            ..
        } = decision
        {
            assert_eq!(controlling_artifact, "race_tests");
        } else {
            panic!("expected refuse decision");
        }
    }

    #[test]
    fn required_evidence_lanes_have_six_entries() {
        assert_eq!(REQUIRED_EVIDENCE_LANES.len(), 6);
    }
}
