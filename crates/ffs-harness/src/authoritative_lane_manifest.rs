#![forbid(unsafe_code)]

//! Authoritative mounted-lane manifest with stale-capability rejection.
//!
//! Tracks bd-9vzzk: extends `mounted_lane_gate` with explicit lane identity,
//! environment kind, capability probe version + timestamp, kernel/FUSE
//! details, expected mount options, required test-matrix coverage,
//! skip/fail/pass policy, remediation hints, and freshness TTL. Authoritative
//! runs must satisfy every contract before README/runtime warnings can be
//! relaxed; local-developer runs may skip with structured diagnostics but
//! cannot be confused with authoritative coverage.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const AUTHORITATIVE_LANE_MANIFEST_SCHEMA_VERSION: u32 = 1;

const ALLOWED_ENVIRONMENT_KINDS: [&str; 4] = ["local_developer", "ci", "rch_authoritative", "soak"];

const AUTHORITATIVE_ENVIRONMENT_KINDS: [&str; 3] = ["ci", "rch_authoritative", "soak"];

const ALLOWED_DECISIONS: [&str; 4] = ["pass", "skip", "fail", "fail_closed_authoritative"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthoritativeLaneManifest {
    pub schema_version: u32,
    pub manifest_id: String,
    pub bead_id: String,
    pub lane_id: String,
    pub environment_kind: String,
    pub probe_version: String,
    pub probe_at_unix: u64,
    pub now_unix: u64,
    pub freshness_ttl_seconds: u64,
    pub kernel: String,
    pub fuse_kernel_version: String,
    pub helper_binary_version: String,
    pub expected_mount_options: Vec<String>,
    pub observed_mount_options: Vec<String>,
    pub required_matrix_id: String,
    pub required_scenario_count: u32,
    pub observed_scenario_count: u32,
    pub mounted_logs_present: bool,
    pub remediation_hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum AuthoritativeLaneDecision {
    Pass {
        lane_id: String,
        environment_kind: String,
    },
    Skip {
        lane_id: String,
        reason: String,
        remediation_hint: String,
    },
    Fail {
        lane_id: String,
        reason: String,
        remediation_hint: String,
    },
    FailClosedAuthoritative {
        lane_id: String,
        reason: String,
        remediation_hint: String,
    },
}

#[must_use]
pub fn evaluate_authoritative_lane(
    manifest: &AuthoritativeLaneManifest,
) -> AuthoritativeLaneDecision {
    if manifest.schema_version != AUTHORITATIVE_LANE_MANIFEST_SCHEMA_VERSION {
        return fail_closed(
            manifest,
            "stale_lane_manifest_schema",
            "regenerate the lane manifest against the current schema",
        );
    }
    if manifest.lane_id.trim().is_empty() {
        return fail_closed(manifest, "missing_lane_id", "set a non-empty lane_id");
    }
    if !manifest.bead_id.starts_with("bd-") {
        return fail_closed(
            manifest,
            "malformed_bead_id",
            "lane manifest bead_id must look like bd-...",
        );
    }
    if !ALLOWED_ENVIRONMENT_KINDS.contains(&manifest.environment_kind.as_str()) {
        return fail_closed(
            manifest,
            "unsupported_environment_kind",
            "environment_kind must be local_developer, ci, rch_authoritative, or soak",
        );
    }
    if manifest.remediation_hint.trim().is_empty() {
        return fail_closed(
            manifest,
            "missing_remediation_hint",
            "lane manifests require a remediation_hint so refused runs are actionable",
        );
    }
    let authoritative =
        AUTHORITATIVE_ENVIRONMENT_KINDS.contains(&manifest.environment_kind.as_str());

    if let Some(decision) = check_probe_freshness(manifest, authoritative) {
        return decision;
    }
    if let Some(decision) = check_environment_consistency(manifest) {
        return decision;
    }
    if let Some(decision) = check_mount_options(manifest, authoritative) {
        return decision;
    }
    if let Some(decision) = check_matrix_coverage(manifest, authoritative) {
        return decision;
    }
    if let Some(decision) = check_logs(manifest, authoritative) {
        return decision;
    }

    if authoritative {
        AuthoritativeLaneDecision::Pass {
            lane_id: manifest.lane_id.clone(),
            environment_kind: manifest.environment_kind.clone(),
        }
    } else {
        AuthoritativeLaneDecision::Skip {
            lane_id: manifest.lane_id.clone(),
            reason: "local_developer_run".to_owned(),
            remediation_hint: manifest.remediation_hint.clone(),
        }
    }
}

fn check_probe_freshness(
    manifest: &AuthoritativeLaneManifest,
    authoritative: bool,
) -> Option<AuthoritativeLaneDecision> {
    if manifest.probe_version.trim().is_empty() {
        return Some(fail_closed(
            manifest,
            "missing_probe_version",
            "rerun fuse-capability-probe with a versioned probe",
        ));
    }
    if manifest.probe_at_unix == 0 {
        return Some(fail_closed(
            manifest,
            "missing_probe_timestamp",
            "rerun fuse-capability-probe so probe_at_unix is recorded",
        ));
    }
    if manifest.freshness_ttl_seconds == 0 {
        return Some(fail_closed(
            manifest,
            "zero_freshness_ttl",
            "configure a positive freshness_ttl_seconds; stale probes cannot pass authoritative gates",
        ));
    }
    if manifest.probe_at_unix > manifest.now_unix {
        return Some(if authoritative {
            fail_closed(
                manifest,
                "future_capability_probe",
                "rerun fuse-capability-probe; authoritative runs cannot trust a future-dated probe",
            )
        } else {
            skip(
                manifest,
                "future_capability_probe",
                "local run skipped — rerun fuse-capability-probe with a non-future timestamp",
            )
        });
    }
    let elapsed = manifest.now_unix.saturating_sub(manifest.probe_at_unix);
    if elapsed > manifest.freshness_ttl_seconds {
        return Some(if authoritative {
            fail_closed(
                manifest,
                "stale_capability_probe",
                "rerun fuse-capability-probe; authoritative runs cannot trust a stale probe",
            )
        } else {
            skip(
                manifest,
                "stale_capability_probe",
                "local run skipped — rerun fuse-capability-probe before next authoritative run",
            )
        });
    }
    None
}

fn check_environment_consistency(
    manifest: &AuthoritativeLaneManifest,
) -> Option<AuthoritativeLaneDecision> {
    if manifest.kernel.trim().is_empty() {
        return Some(fail_closed(
            manifest,
            "missing_kernel_record",
            "record the kernel string before evaluating the lane manifest",
        ));
    }
    if manifest.fuse_kernel_version.trim().is_empty() {
        return Some(fail_closed(
            manifest,
            "missing_fuse_kernel_version",
            "record the fuse kernel module version before evaluating the lane manifest",
        ));
    }
    if manifest.helper_binary_version.trim().is_empty() {
        return Some(fail_closed(
            manifest,
            "missing_helper_binary_version",
            "record the fuser helper binary version before evaluating the lane manifest",
        ));
    }
    None
}

fn check_mount_options(
    manifest: &AuthoritativeLaneManifest,
    authoritative: bool,
) -> Option<AuthoritativeLaneDecision> {
    if manifest.expected_mount_options.is_empty() {
        return Some(fail_closed(
            manifest,
            "missing_expected_mount_options",
            "lane manifest must declare expected_mount_options to detect drift",
        ));
    }
    let expected: BTreeSet<&str> = manifest
        .expected_mount_options
        .iter()
        .map(String::as_str)
        .collect();
    let observed: BTreeSet<&str> = manifest
        .observed_mount_options
        .iter()
        .map(String::as_str)
        .collect();
    if observed.is_empty() && authoritative {
        return Some(fail_closed(
            manifest,
            "missing_observed_mount_options",
            "authoritative runs must record observed_mount_options",
        ));
    }
    if !observed.is_empty() && expected != observed {
        return Some(if authoritative {
            fail_closed(
                manifest,
                "mismatched_mount_options",
                "observed mount options diverge from the expected set; rebuild the lane manifest with the current host config",
            )
        } else {
            skip(
                manifest,
                "mismatched_mount_options",
                "local run skipped — observed mount options diverge from the expected set",
            )
        });
    }
    None
}

fn check_matrix_coverage(
    manifest: &AuthoritativeLaneManifest,
    authoritative: bool,
) -> Option<AuthoritativeLaneDecision> {
    if manifest.required_matrix_id.trim().is_empty() {
        return Some(fail_closed(
            manifest,
            "missing_required_matrix_id",
            "lane manifest must reference a required_matrix_id (mounted write/recovery matrix)",
        ));
    }
    if manifest.required_scenario_count == 0 {
        return Some(fail_closed(
            manifest,
            "zero_required_scenarios",
            "lane manifest required_scenario_count must be positive; otherwise it cannot fail closed",
        ));
    }
    if manifest.observed_scenario_count < manifest.required_scenario_count {
        return Some(if authoritative {
            fail_closed(
                manifest,
                "insufficient_scenario_coverage",
                "observed_scenario_count is below required_scenario_count; rerun the matrix before the lane can pass",
            )
        } else {
            skip(
                manifest,
                "insufficient_scenario_coverage",
                "local run skipped — observed_scenario_count is below required_scenario_count",
            )
        });
    }
    None
}

fn check_logs(
    manifest: &AuthoritativeLaneManifest,
    authoritative: bool,
) -> Option<AuthoritativeLaneDecision> {
    if authoritative && !manifest.mounted_logs_present {
        return Some(fail_closed(
            manifest,
            "missing_mounted_logs",
            "authoritative lane requires mounted_logs_present=true; preserve stdout/stderr/diagnostic logs",
        ));
    }
    None
}

fn fail_closed(
    manifest: &AuthoritativeLaneManifest,
    reason: &str,
    remediation: &str,
) -> AuthoritativeLaneDecision {
    AuthoritativeLaneDecision::FailClosedAuthoritative {
        lane_id: manifest.lane_id.clone(),
        reason: reason.to_owned(),
        remediation_hint: remediation.to_owned(),
    }
}

fn skip(
    manifest: &AuthoritativeLaneManifest,
    reason: &str,
    remediation: &str,
) -> AuthoritativeLaneDecision {
    AuthoritativeLaneDecision::Skip {
        lane_id: manifest.lane_id.clone(),
        reason: reason.to_owned(),
        remediation_hint: remediation.to_owned(),
    }
}

#[must_use]
pub fn allowed_decision_tokens() -> Vec<&'static str> {
    ALLOWED_DECISIONS.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn happy_manifest() -> AuthoritativeLaneManifest {
        AuthoritativeLaneManifest {
            schema_version: AUTHORITATIVE_LANE_MANIFEST_SCHEMA_VERSION,
            manifest_id: "lane_001".to_owned(),
            bead_id: "bd-9vzzk".to_owned(),
            lane_id: "mounted_authoritative_v1".to_owned(),
            environment_kind: "rch_authoritative".to_owned(),
            probe_version: "fuse-capability-probe-v1".to_owned(),
            probe_at_unix: 1_000,
            now_unix: 1_500,
            freshness_ttl_seconds: 3_600,
            kernel: "linux-6.x".to_owned(),
            fuse_kernel_version: "fuse-3.16".to_owned(),
            helper_binary_version: "fuser-0.16".to_owned(),
            expected_mount_options: vec!["rw".to_owned(), "default_permissions".to_owned()],
            observed_mount_options: vec!["rw".to_owned(), "default_permissions".to_owned()],
            required_matrix_id: "mounted_write_workload_matrix_v3".to_owned(),
            required_scenario_count: 10,
            observed_scenario_count: 12,
            mounted_logs_present: true,
            remediation_hint:
                "rerun fuse-capability-probe and the mounted matrix on a permissioned worker"
                    .to_owned(),
        }
    }

    fn reason(decision: &AuthoritativeLaneDecision) -> Option<&str> {
        match decision {
            AuthoritativeLaneDecision::Pass { .. } => None,
            AuthoritativeLaneDecision::Skip { reason, .. }
            | AuthoritativeLaneDecision::Fail { reason, .. }
            | AuthoritativeLaneDecision::FailClosedAuthoritative { reason, .. } => {
                Some(reason.as_str())
            }
        }
    }

    #[test]
    fn happy_authoritative_lane_passes() {
        let decision = evaluate_authoritative_lane(&happy_manifest());
        assert!(matches!(decision, AuthoritativeLaneDecision::Pass { .. }));
    }

    #[test]
    fn local_developer_run_skips_with_remediation() {
        let mut manifest = happy_manifest();
        manifest.environment_kind = "local_developer".to_owned();
        manifest.mounted_logs_present = false;
        let decision = evaluate_authoritative_lane(&manifest);
        assert_eq!(reason(&decision), Some("local_developer_run"));
        assert!(matches!(decision, AuthoritativeLaneDecision::Skip { .. }));
    }

    #[test]
    fn local_developer_with_insufficient_coverage_skips_actionably() {
        let mut manifest = happy_manifest();
        manifest.environment_kind = "local_developer".to_owned();
        manifest.observed_scenario_count = 0;
        manifest.mounted_logs_present = false;
        let decision = evaluate_authoritative_lane(&manifest);
        assert_eq!(reason(&decision), Some("insufficient_scenario_coverage"));
        assert!(matches!(decision, AuthoritativeLaneDecision::Skip { .. }));
    }

    #[test]
    fn stale_probe_fails_authoritative_run() {
        let mut manifest = happy_manifest();
        manifest.now_unix = manifest.probe_at_unix + manifest.freshness_ttl_seconds + 1;
        let decision = evaluate_authoritative_lane(&manifest);
        assert_eq!(reason(&decision), Some("stale_capability_probe"));
        assert!(matches!(
            decision,
            AuthoritativeLaneDecision::FailClosedAuthoritative { .. }
        ));
    }

    #[test]
    fn stale_probe_skips_local_run() {
        let mut manifest = happy_manifest();
        manifest.environment_kind = "local_developer".to_owned();
        manifest.now_unix = manifest.probe_at_unix + manifest.freshness_ttl_seconds + 1;
        let decision = evaluate_authoritative_lane(&manifest);
        assert_eq!(reason(&decision), Some("stale_capability_probe"));
        assert!(matches!(decision, AuthoritativeLaneDecision::Skip { .. }));
    }

    #[test]
    fn future_probe_fails_authoritative_run() {
        let mut manifest = happy_manifest();
        manifest.probe_at_unix = manifest.now_unix + 1;
        let decision = evaluate_authoritative_lane(&manifest);
        assert_eq!(reason(&decision), Some("future_capability_probe"));
        assert!(matches!(
            decision,
            AuthoritativeLaneDecision::FailClosedAuthoritative { .. }
        ));
    }

    #[test]
    fn future_probe_skips_local_run() {
        let mut manifest = happy_manifest();
        manifest.environment_kind = "local_developer".to_owned();
        manifest.probe_at_unix = manifest.now_unix + 1;
        let decision = evaluate_authoritative_lane(&manifest);
        assert_eq!(reason(&decision), Some("future_capability_probe"));
        assert!(matches!(decision, AuthoritativeLaneDecision::Skip { .. }));
    }

    #[test]
    fn missing_probe_version_fails_closed() {
        let mut manifest = happy_manifest();
        manifest.probe_version = String::new();
        let decision = evaluate_authoritative_lane(&manifest);
        assert_eq!(reason(&decision), Some("missing_probe_version"));
    }

    #[test]
    fn missing_probe_timestamp_fails_closed() {
        let mut manifest = happy_manifest();
        manifest.probe_at_unix = 0;
        let decision = evaluate_authoritative_lane(&manifest);
        assert_eq!(reason(&decision), Some("missing_probe_timestamp"));
    }

    #[test]
    fn zero_freshness_ttl_fails_closed() {
        let mut manifest = happy_manifest();
        manifest.freshness_ttl_seconds = 0;
        let decision = evaluate_authoritative_lane(&manifest);
        assert_eq!(reason(&decision), Some("zero_freshness_ttl"));
    }

    #[test]
    fn missing_kernel_fails_closed() {
        let mut manifest = happy_manifest();
        manifest.kernel = String::new();
        let decision = evaluate_authoritative_lane(&manifest);
        assert_eq!(reason(&decision), Some("missing_kernel_record"));
    }

    #[test]
    fn missing_fuse_kernel_version_fails_closed() {
        let mut manifest = happy_manifest();
        manifest.fuse_kernel_version = String::new();
        let decision = evaluate_authoritative_lane(&manifest);
        assert_eq!(reason(&decision), Some("missing_fuse_kernel_version"));
    }

    #[test]
    fn missing_helper_binary_version_fails_closed() {
        let mut manifest = happy_manifest();
        manifest.helper_binary_version = String::new();
        let decision = evaluate_authoritative_lane(&manifest);
        assert_eq!(reason(&decision), Some("missing_helper_binary_version"));
    }

    #[test]
    fn missing_expected_mount_options_fails_closed() {
        let mut manifest = happy_manifest();
        manifest.expected_mount_options.clear();
        let decision = evaluate_authoritative_lane(&manifest);
        assert_eq!(reason(&decision), Some("missing_expected_mount_options"));
    }

    #[test]
    fn missing_observed_mount_options_fails_authoritative() {
        let mut manifest = happy_manifest();
        manifest.observed_mount_options.clear();
        let decision = evaluate_authoritative_lane(&manifest);
        assert_eq!(reason(&decision), Some("missing_observed_mount_options"));
    }

    #[test]
    fn mismatched_mount_options_fails_closed_for_authoritative() {
        let mut manifest = happy_manifest();
        manifest.observed_mount_options = vec!["ro".to_owned(), "default_permissions".to_owned()];
        let decision = evaluate_authoritative_lane(&manifest);
        assert_eq!(reason(&decision), Some("mismatched_mount_options"));
        assert!(matches!(
            decision,
            AuthoritativeLaneDecision::FailClosedAuthoritative { .. }
        ));
    }

    #[test]
    fn mismatched_mount_options_skips_for_local() {
        let mut manifest = happy_manifest();
        manifest.environment_kind = "local_developer".to_owned();
        manifest.observed_mount_options = vec!["ro".to_owned(), "default_permissions".to_owned()];
        let decision = evaluate_authoritative_lane(&manifest);
        assert_eq!(reason(&decision), Some("mismatched_mount_options"));
        assert!(matches!(decision, AuthoritativeLaneDecision::Skip { .. }));
    }

    #[test]
    fn missing_required_matrix_id_fails_closed() {
        let mut manifest = happy_manifest();
        manifest.required_matrix_id = String::new();
        let decision = evaluate_authoritative_lane(&manifest);
        assert_eq!(reason(&decision), Some("missing_required_matrix_id"));
    }

    #[test]
    fn zero_required_scenarios_fails_closed() {
        let mut manifest = happy_manifest();
        manifest.required_scenario_count = 0;
        let decision = evaluate_authoritative_lane(&manifest);
        assert_eq!(reason(&decision), Some("zero_required_scenarios"));
    }

    #[test]
    fn insufficient_coverage_fails_authoritative() {
        let mut manifest = happy_manifest();
        manifest.observed_scenario_count = 5;
        let decision = evaluate_authoritative_lane(&manifest);
        assert_eq!(reason(&decision), Some("insufficient_scenario_coverage"));
        assert!(matches!(
            decision,
            AuthoritativeLaneDecision::FailClosedAuthoritative { .. }
        ));
    }

    #[test]
    fn missing_mounted_logs_fails_authoritative() {
        let mut manifest = happy_manifest();
        manifest.mounted_logs_present = false;
        let decision = evaluate_authoritative_lane(&manifest);
        assert_eq!(reason(&decision), Some("missing_mounted_logs"));
    }

    #[test]
    fn unsupported_environment_kind_fails_closed() {
        let mut manifest = happy_manifest();
        manifest.environment_kind = "vibes_run".to_owned();
        let decision = evaluate_authoritative_lane(&manifest);
        assert_eq!(reason(&decision), Some("unsupported_environment_kind"));
    }

    #[test]
    fn missing_remediation_hint_fails_closed() {
        let mut manifest = happy_manifest();
        manifest.remediation_hint = String::new();
        let decision = evaluate_authoritative_lane(&manifest);
        assert_eq!(reason(&decision), Some("missing_remediation_hint"));
    }

    #[test]
    fn malformed_bead_id_fails_closed() {
        let mut manifest = happy_manifest();
        manifest.bead_id = "PROJ-1".to_owned();
        let decision = evaluate_authoritative_lane(&manifest);
        assert_eq!(reason(&decision), Some("malformed_bead_id"));
    }

    #[test]
    fn stale_schema_version_fails_closed() {
        let mut manifest = happy_manifest();
        manifest.schema_version = 99;
        let decision = evaluate_authoritative_lane(&manifest);
        assert_eq!(reason(&decision), Some("stale_lane_manifest_schema"));
    }

    #[test]
    fn missing_lane_id_fails_closed() {
        let mut manifest = happy_manifest();
        manifest.lane_id = String::new();
        let decision = evaluate_authoritative_lane(&manifest);
        assert_eq!(reason(&decision), Some("missing_lane_id"));
    }

    #[test]
    fn allowed_decision_tokens_match_ordering() {
        let tokens = allowed_decision_tokens();
        assert!(tokens.contains(&"pass"));
        assert!(tokens.contains(&"fail_closed_authoritative"));
    }

    #[test]
    fn ci_environment_is_authoritative() {
        let mut manifest = happy_manifest();
        manifest.environment_kind = "ci".to_owned();
        manifest.mounted_logs_present = false;
        let decision = evaluate_authoritative_lane(&manifest);
        assert_eq!(reason(&decision), Some("missing_mounted_logs"));
    }
}
