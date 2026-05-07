#![forbid(unsafe_code)]

//! Mounted lane fail-closed gate.
//!
//! Tracks bd-rchk4.4: local developer runs may still skip with structured
//! diagnostics, but CI/RCH gates that promise mounted coverage must exit
//! nonzero when the permissioned lane cannot mount. This evaluator returns
//! `Skip` for local non-permissioned runs and `Fail` for authoritative runs
//! whose capability probe is unavailable, stale, missing logs, or missing
//! remediation hints — so skipped required coverage stays visible and
//! actionable instead of silently going green.

use serde::{Deserialize, Serialize};

pub const MOUNTED_LANE_GATE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedLaneGate {
    pub schema_version: u32,
    pub gate_version: String,
    pub bead_id: String,
    pub run_kind: String,
    pub authoritative_lane_required: bool,
    pub capability_probe: CapabilityProbe,
    pub diagnostic_log_path: String,
    pub remediation_hint: String,
    pub max_probe_age_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityProbe {
    pub probe_id: String,
    pub status: String,
    pub probe_at_unix: u64,
    pub now_unix: u64,
    pub fuse_kernel_module_present: bool,
    pub helper_binary_present: bool,
    pub permissioned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum MountedLaneDecision {
    Pass {
        run_kind: String,
        capability: String,
    },
    Skip {
        reason: String,
        remediation_hint: String,
        diagnostic_log_path: String,
    },
    Fail {
        reason: String,
        remediation_hint: String,
        diagnostic_log_path: String,
    },
}

const ALLOWED_RUN_KINDS: [&str; 4] = ["local_developer", "ci", "rch_authoritative", "soak"];

const ALLOWED_PROBE_STATUSES: [&str; 4] = [
    "available",
    "unavailable_no_kernel_module",
    "unavailable_no_helper",
    "unavailable_unprivileged",
];

#[must_use]
pub fn evaluate_mounted_lane_gate(gate: &MountedLaneGate) -> MountedLaneDecision {
    if gate.schema_version != MOUNTED_LANE_GATE_SCHEMA_VERSION {
        return fail(
            "stale_gate_schema",
            "regenerate the mounted lane gate against the current schema",
            &gate.diagnostic_log_path,
        );
    }
    if !ALLOWED_RUN_KINDS.contains(&gate.run_kind.as_str()) {
        return fail(
            "unsupported_run_kind",
            "set run_kind to one of: local_developer, ci, rch_authoritative, soak",
            &gate.diagnostic_log_path,
        );
    }
    if !ALLOWED_PROBE_STATUSES.contains(&gate.capability_probe.status.as_str()) {
        return fail(
            "unsupported_probe_status",
            "rerun fuse-capability-probe; status must be one of the documented values",
            &gate.diagnostic_log_path,
        );
    }
    if gate.diagnostic_log_path.trim().is_empty() {
        return fail(
            "missing_diagnostic_log",
            "configure a diagnostic_log_path so skipped/failed runs preserve evidence",
            &gate.diagnostic_log_path,
        );
    }
    if gate.remediation_hint.trim().is_empty() {
        return fail(
            "missing_remediation_hint",
            "configure a remediation_hint so operators know how to recover",
            &gate.diagnostic_log_path,
        );
    }
    if gate.max_probe_age_seconds == 0 {
        return fail(
            "zero_probe_freshness_ttl",
            "set a positive max_probe_age_seconds; stale probes cannot upgrade authoritative gates",
            &gate.diagnostic_log_path,
        );
    }
    if gate.capability_probe.probe_at_unix > gate.capability_probe.now_unix {
        return classify_future_probe(gate);
    }
    let elapsed = gate
        .capability_probe
        .now_unix
        .saturating_sub(gate.capability_probe.probe_at_unix);
    let probe_stale =
        elapsed > gate.max_probe_age_seconds || gate.capability_probe.probe_id.trim().is_empty();
    let probe_available = gate.capability_probe.status == "available"
        && gate.capability_probe.fuse_kernel_module_present
        && gate.capability_probe.helper_binary_present;

    if probe_stale {
        return classify_stale_probe(gate);
    }
    if !probe_available {
        return classify_unavailable_probe(gate);
    }
    if gate.authoritative_lane_required && !gate.capability_probe.permissioned {
        return fail(
            "authoritative_requires_permissioned_lane",
            "authoritative runs must use the permissioned mount lane; configure sudo/loop or skip non-authoritatively",
            &gate.diagnostic_log_path,
        );
    }
    MountedLaneDecision::Pass {
        run_kind: gate.run_kind.clone(),
        capability: gate.capability_probe.status.clone(),
    }
}

fn classify_future_probe(gate: &MountedLaneGate) -> MountedLaneDecision {
    if gate.authoritative_lane_required {
        fail(
            "future_capability_probe",
            "rerun fuse-capability-probe; authoritative runs cannot trust a future-dated probe",
            &gate.diagnostic_log_path,
        )
    } else {
        skip(
            "future_capability_probe",
            "local run skipped; rerun fuse-capability-probe with a non-future timestamp",
            &gate.diagnostic_log_path,
        )
    }
}

fn classify_stale_probe(gate: &MountedLaneGate) -> MountedLaneDecision {
    if gate.authoritative_lane_required {
        fail(
            "stale_capability_probe",
            "rerun fuse-capability-probe; authoritative runs cannot trust a stale probe",
            &gate.diagnostic_log_path,
        )
    } else {
        skip(
            "stale_capability_probe",
            "local run skipped — rerun fuse-capability-probe before next authoritative run",
            &gate.diagnostic_log_path,
        )
    }
}

fn classify_unavailable_probe(gate: &MountedLaneGate) -> MountedLaneDecision {
    if gate.authoritative_lane_required {
        fail(
            "fuse_capability_unavailable",
            "authoritative mounted coverage required; install/configure FUSE before the next run",
            &gate.diagnostic_log_path,
        )
    } else {
        skip(
            "fuse_capability_unavailable",
            "local run skipped — install fuser/fuse kernel module to exercise the mounted lane locally",
            &gate.diagnostic_log_path,
        )
    }
}

fn fail(reason: &str, remediation: &str, log_path: &str) -> MountedLaneDecision {
    MountedLaneDecision::Fail {
        reason: reason.to_owned(),
        remediation_hint: remediation.to_owned(),
        diagnostic_log_path: log_path.to_owned(),
    }
}

fn skip(reason: &str, remediation: &str, log_path: &str) -> MountedLaneDecision {
    MountedLaneDecision::Skip {
        reason: reason.to_owned(),
        remediation_hint: remediation.to_owned(),
        diagnostic_log_path: log_path.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn happy_gate() -> MountedLaneGate {
        MountedLaneGate {
            schema_version: MOUNTED_LANE_GATE_SCHEMA_VERSION,
            gate_version: "v1".to_owned(),
            bead_id: "bd-rchk4.4".to_owned(),
            run_kind: "rch_authoritative".to_owned(),
            authoritative_lane_required: true,
            capability_probe: CapabilityProbe {
                probe_id: "probe-001".to_owned(),
                status: "available".to_owned(),
                probe_at_unix: 1_000,
                now_unix: 1_300,
                fuse_kernel_module_present: true,
                helper_binary_present: true,
                permissioned: true,
            },
            diagnostic_log_path: "artifacts/mounted-lane/diagnostic.log".to_owned(),
            remediation_hint: "rerun fuse-capability-probe and retry the mounted matrix".to_owned(),
            max_probe_age_seconds: 600,
        }
    }

    fn reason(decision: &MountedLaneDecision) -> Option<&str> {
        match decision {
            MountedLaneDecision::Fail { reason, .. } | MountedLaneDecision::Skip { reason, .. } => {
                Some(reason.as_str())
            }
            MountedLaneDecision::Pass { .. } => None,
        }
    }

    fn severity(decision: &MountedLaneDecision) -> u8 {
        match decision {
            MountedLaneDecision::Pass { .. } => 0,
            MountedLaneDecision::Skip { .. } => 1,
            MountedLaneDecision::Fail { .. } => 2,
        }
    }

    prop_compose! {
        fn allowed_probe_status()(index in 0_usize..ALLOWED_PROBE_STATUSES.len()) -> String {
            ALLOWED_PROBE_STATUSES[index].to_owned()
        }
    }

    proptest! {
        #[test]
        fn authoritative_escalation_never_weakens_decision(
            status in allowed_probe_status(),
            fuse_kernel_module_present in any::<bool>(),
            helper_binary_present in any::<bool>(),
            permissioned in any::<bool>(),
            probe_at_unix in 0_u64..1_000_000,
            elapsed_seconds in 0_u64..2_000,
            max_probe_age_seconds in 1_u64..1_000,
            missing_probe_id in any::<bool>(),
        ) {
            let mut local_gate = happy_gate();
            local_gate.run_kind = "local_developer".to_owned();
            local_gate.authoritative_lane_required = false;
            local_gate.max_probe_age_seconds = max_probe_age_seconds;
            local_gate.capability_probe.status = status;
            local_gate.capability_probe.fuse_kernel_module_present = fuse_kernel_module_present;
            local_gate.capability_probe.helper_binary_present = helper_binary_present;
            local_gate.capability_probe.permissioned = permissioned;
            local_gate.capability_probe.probe_at_unix = probe_at_unix;
            local_gate.capability_probe.now_unix = probe_at_unix + elapsed_seconds;
            if missing_probe_id {
                local_gate.capability_probe.probe_id.clear();
            }

            let mut authoritative_gate = local_gate.clone();
            authoritative_gate.run_kind = "rch_authoritative".to_owned();
            authoritative_gate.authoritative_lane_required = true;

            let local_decision = evaluate_mounted_lane_gate(&local_gate);
            let authoritative_decision = evaluate_mounted_lane_gate(&authoritative_gate);
            prop_assert!(
                severity(&authoritative_decision) >= severity(&local_decision),
                "authoritative decision weakened: local={local_decision:?} authoritative={authoritative_decision:?}"
            );
        }
    }

    #[test]
    fn happy_authoritative_run_passes() {
        let decision = evaluate_mounted_lane_gate(&happy_gate());
        assert!(matches!(decision, MountedLaneDecision::Pass { .. }));
    }

    #[test]
    fn local_run_with_unavailable_probe_skips() {
        let mut gate = happy_gate();
        gate.run_kind = "local_developer".to_owned();
        gate.authoritative_lane_required = false;
        gate.capability_probe.status = "unavailable_no_kernel_module".to_owned();
        gate.capability_probe.fuse_kernel_module_present = false;
        let decision = evaluate_mounted_lane_gate(&gate);
        assert!(matches!(decision, MountedLaneDecision::Skip { .. }));
        assert_eq!(reason(&decision), Some("fuse_capability_unavailable"));
    }

    #[test]
    fn authoritative_run_with_unavailable_probe_fails() {
        let mut gate = happy_gate();
        gate.capability_probe.status = "unavailable_no_helper".to_owned();
        gate.capability_probe.helper_binary_present = false;
        let decision = evaluate_mounted_lane_gate(&gate);
        assert!(matches!(decision, MountedLaneDecision::Fail { .. }));
        assert_eq!(reason(&decision), Some("fuse_capability_unavailable"));
    }

    #[test]
    fn authoritative_run_requires_permissioned_lane() {
        let mut gate = happy_gate();
        gate.capability_probe.permissioned = false;
        let decision = evaluate_mounted_lane_gate(&gate);
        assert!(matches!(decision, MountedLaneDecision::Fail { .. }));
        assert_eq!(
            reason(&decision),
            Some("authoritative_requires_permissioned_lane")
        );
    }

    #[test]
    fn local_run_does_not_require_permissioned_lane() {
        let mut gate = happy_gate();
        gate.run_kind = "local_developer".to_owned();
        gate.authoritative_lane_required = false;
        gate.capability_probe.permissioned = false;
        let decision = evaluate_mounted_lane_gate(&gate);
        assert!(matches!(decision, MountedLaneDecision::Pass { .. }));
    }

    #[test]
    fn stale_probe_fails_authoritative_run() {
        let mut gate = happy_gate();
        gate.capability_probe.now_unix = 9_999;
        let decision = evaluate_mounted_lane_gate(&gate);
        assert!(matches!(decision, MountedLaneDecision::Fail { .. }));
        assert_eq!(reason(&decision), Some("stale_capability_probe"));
    }

    #[test]
    fn stale_probe_skips_local_run() {
        let mut gate = happy_gate();
        gate.run_kind = "local_developer".to_owned();
        gate.authoritative_lane_required = false;
        gate.capability_probe.now_unix = 9_999;
        let decision = evaluate_mounted_lane_gate(&gate);
        assert!(matches!(decision, MountedLaneDecision::Skip { .. }));
        assert_eq!(reason(&decision), Some("stale_capability_probe"));
    }

    #[test]
    fn future_probe_fails_authoritative_run() {
        let mut gate = happy_gate();
        gate.capability_probe.probe_at_unix = gate.capability_probe.now_unix + 1;
        let decision = evaluate_mounted_lane_gate(&gate);
        assert!(matches!(decision, MountedLaneDecision::Fail { .. }));
        assert_eq!(reason(&decision), Some("future_capability_probe"));
    }

    #[test]
    fn future_probe_skips_local_run() {
        let mut gate = happy_gate();
        gate.run_kind = "local_developer".to_owned();
        gate.authoritative_lane_required = false;
        gate.capability_probe.probe_at_unix = gate.capability_probe.now_unix + 1;
        let decision = evaluate_mounted_lane_gate(&gate);
        assert!(matches!(decision, MountedLaneDecision::Skip { .. }));
        assert_eq!(reason(&decision), Some("future_capability_probe"));
    }

    #[test]
    fn missing_probe_id_is_treated_as_stale() {
        let mut gate = happy_gate();
        gate.capability_probe.probe_id = String::new();
        let decision = evaluate_mounted_lane_gate(&gate);
        assert_eq!(reason(&decision), Some("stale_capability_probe"));
    }

    #[test]
    fn missing_diagnostic_log_fails_closed() {
        let mut gate = happy_gate();
        gate.diagnostic_log_path = String::new();
        let decision = evaluate_mounted_lane_gate(&gate);
        assert!(matches!(decision, MountedLaneDecision::Fail { .. }));
        assert_eq!(reason(&decision), Some("missing_diagnostic_log"));
    }

    #[test]
    fn missing_remediation_hint_fails_closed() {
        let mut gate = happy_gate();
        gate.remediation_hint = String::new();
        let decision = evaluate_mounted_lane_gate(&gate);
        assert!(matches!(decision, MountedLaneDecision::Fail { .. }));
        assert_eq!(reason(&decision), Some("missing_remediation_hint"));
    }

    #[test]
    fn zero_max_probe_age_fails_closed() {
        let mut gate = happy_gate();
        gate.max_probe_age_seconds = 0;
        let decision = evaluate_mounted_lane_gate(&gate);
        assert!(matches!(decision, MountedLaneDecision::Fail { .. }));
        assert_eq!(reason(&decision), Some("zero_probe_freshness_ttl"));
    }

    #[test]
    fn unsupported_run_kind_fails() {
        let mut gate = happy_gate();
        gate.run_kind = "vibes_run".to_owned();
        let decision = evaluate_mounted_lane_gate(&gate);
        assert!(matches!(decision, MountedLaneDecision::Fail { .. }));
        assert_eq!(reason(&decision), Some("unsupported_run_kind"));
    }

    #[test]
    fn unsupported_probe_status_fails() {
        let mut gate = happy_gate();
        gate.capability_probe.status = "kinda_available".to_owned();
        let decision = evaluate_mounted_lane_gate(&gate);
        assert!(matches!(decision, MountedLaneDecision::Fail { .. }));
        assert_eq!(reason(&decision), Some("unsupported_probe_status"));
    }

    #[test]
    fn stale_schema_version_fails() {
        let mut gate = happy_gate();
        gate.schema_version = 99;
        let decision = evaluate_mounted_lane_gate(&gate);
        assert_eq!(reason(&decision), Some("stale_gate_schema"));
    }

    #[test]
    fn ci_run_failure_carries_diagnostic_log_path() {
        let mut gate = happy_gate();
        gate.run_kind = "ci".to_owned();
        gate.capability_probe.status = "unavailable_unprivileged".to_owned();
        gate.capability_probe.permissioned = false;
        let decision = evaluate_mounted_lane_gate(&gate);
        assert!(
            matches!(decision, MountedLaneDecision::Fail { .. }),
            "expected Fail decision"
        );
        if let MountedLaneDecision::Fail {
            diagnostic_log_path,
            ..
        } = decision
        {
            assert_eq!(diagnostic_log_path, "artifacts/mounted-lane/diagnostic.log");
        }
    }

    #[test]
    fn local_skip_decision_carries_remediation_and_log() {
        let mut gate = happy_gate();
        gate.run_kind = "local_developer".to_owned();
        gate.authoritative_lane_required = false;
        gate.capability_probe.status = "unavailable_no_helper".to_owned();
        gate.capability_probe.helper_binary_present = false;
        let decision = evaluate_mounted_lane_gate(&gate);
        assert!(
            matches!(decision, MountedLaneDecision::Skip { .. }),
            "expected Skip decision"
        );
        if let MountedLaneDecision::Skip {
            remediation_hint,
            diagnostic_log_path,
            ..
        } = decision
        {
            assert!(remediation_hint.contains("fuser") || remediation_hint.contains("FUSE"));
            assert_eq!(diagnostic_log_path, "artifacts/mounted-lane/diagnostic.log");
        }
    }
}
