#![forbid(unsafe_code)]

//! Writeback-cache negative-option audit gate.
//!
//! Tracks bd-rchk0.2.1.1: proves that the FUSE `writeback_cache` mount option
//! stays disabled unless every safety prerequisite is satisfied. The default
//! and unsafe paths must never accidentally forward `writeback_cache` to the
//! kernel, even when stale docs, config defaults, or unrelated mount flags are
//! present. Each rejection class carries a stable reason code so release gates
//! and the remediation catalog can fail closed without parsing prose.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const WRITEBACK_CACHE_AUDIT_SCHEMA_VERSION: u32 = 1;

/// Required invariant identifiers for the writeback-cache gate.
///
/// I1 = epoch barrier proof artifact present and not stale.
/// I2 = repair-write serialization gate has accepted rw lane.
/// I3 = mount mode is rw with explicit opt-in flag.
/// I4 = filesystem flavor and operation class are supported.
/// I5 = FUSE capability probe reports current host supports writeback_cache.
/// I6 = crash matrix / fsync evidence is fresh and passes.
pub const REQUIRED_INVARIANT_IDS: [&str; 6] = ["I1", "I2", "I3", "I4", "I5", "I6"];

pub const ALLOWED_REJECTION_REASONS: [&str; 8] = [
    "missing_epoch_barrier_artifact",
    "stale_epoch_barrier_artifact",
    "rw_repair_serialization_unsupported",
    "default_or_read_only_mount",
    "unsupported_filesystem_or_operation",
    "fuse_capability_unavailable",
    "stale_crash_matrix_or_missing_fsync_evidence",
    "conflicting_cli_flags",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WritebackCacheAuditGate {
    pub schema_version: u32,
    pub gate_version: String,
    pub bead_id: String,
    pub mount_options: WritebackMountOptions,
    pub repair_serialization_state: String,
    pub fuse_capability: FuseCapabilityState,
    pub epoch_barrier_artifact: ArtifactState,
    pub crash_matrix_artifact: ArtifactState,
    pub fsync_evidence_artifact: ArtifactState,
    pub filesystem_flavor: String,
    pub operation_class: String,
    pub explicit_opt_in: bool,
    pub conflicting_flags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WritebackMountOptions {
    pub raw_options: Vec<String>,
    pub fs_name: String,
    pub allow_other: bool,
    pub auto_unmount: bool,
    pub default_permissions: bool,
    pub mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuseCapabilityState {
    pub probe_status: String,
    pub kernel_supports_writeback_cache: bool,
    pub helper_binary_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactState {
    pub artifact_id: String,
    pub present: bool,
    pub fresh: bool,
    pub passed: bool,
    pub artifact_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum WritebackCacheAuditDecision {
    Accept,
    Reject {
        reason: String,
        invariants_failing: Vec<String>,
        remediation: String,
    },
}

#[must_use]
pub fn evaluate_writeback_cache_audit(
    gate: &WritebackCacheAuditGate,
) -> WritebackCacheAuditDecision {
    if let Some(decision) = check_raw_options_never_carry_writeback_cache(gate) {
        return decision;
    }
    if let Some(decision) = check_mount_mode_and_opt_in(gate) {
        return decision;
    }
    if let Some(decision) = check_filesystem_and_operation(gate) {
        return decision;
    }
    if let Some(decision) = check_fuse_capability(gate) {
        return decision;
    }
    if let Some(decision) = check_repair_serialization(gate) {
        return decision;
    }
    if let Some(decision) = check_epoch_barrier_artifact(gate) {
        return decision;
    }
    if let Some(decision) = check_crash_and_fsync_evidence(gate) {
        return decision;
    }
    if let Some(decision) = check_conflicting_flags(gate) {
        return decision;
    }
    WritebackCacheAuditDecision::Accept
}

fn check_raw_options_never_carry_writeback_cache(
    gate: &WritebackCacheAuditGate,
) -> Option<WritebackCacheAuditDecision> {
    if !gate.explicit_opt_in
        && gate
            .mount_options
            .raw_options
            .iter()
            .any(|option| option.to_ascii_lowercase().contains("writeback_cache"))
    {
        return Some(reject(
            "default_or_read_only_mount",
            ["I3"],
            "writeback_cache must never appear in raw mount options unless explicit_opt_in is true",
        ));
    }
    None
}

fn check_mount_mode_and_opt_in(
    gate: &WritebackCacheAuditGate,
) -> Option<WritebackCacheAuditDecision> {
    if gate.mount_options.mode != "rw" {
        return Some(reject(
            "default_or_read_only_mount",
            ["I3"],
            "writeback_cache requires an rw mount; default and ro mounts must keep it disabled",
        ));
    }
    if !gate.explicit_opt_in {
        return Some(reject(
            "default_or_read_only_mount",
            ["I3"],
            "operator must pass an explicit opt-in flag before writeback_cache is considered",
        ));
    }
    None
}

fn check_filesystem_and_operation(
    gate: &WritebackCacheAuditGate,
) -> Option<WritebackCacheAuditDecision> {
    let supported_flavors = ["ext4", "btrfs"];
    let supported_ops = ["mounted_write", "mounted_rename", "mounted_truncate"];
    if !supported_flavors.contains(&gate.filesystem_flavor.as_str()) {
        return Some(reject(
            "unsupported_filesystem_or_operation",
            ["I4"],
            "writeback_cache is only supported on ext4 and btrfs flavors",
        ));
    }
    if !supported_ops.contains(&gate.operation_class.as_str()) {
        return Some(reject(
            "unsupported_filesystem_or_operation",
            ["I4"],
            "operation class outside the supported writeback envelope",
        ));
    }
    None
}

fn check_fuse_capability(
    gate: &WritebackCacheAuditGate,
) -> Option<WritebackCacheAuditDecision> {
    if gate.fuse_capability.probe_status != "available" {
        return Some(reject(
            "fuse_capability_unavailable",
            ["I5"],
            "rerun fuse-capability-probe; writeback_cache requires the kernel module and helper",
        ));
    }
    if !gate.fuse_capability.kernel_supports_writeback_cache
        || !gate.fuse_capability.helper_binary_present
    {
        return Some(reject(
            "fuse_capability_unavailable",
            ["I5"],
            "kernel or helper binary does not advertise writeback_cache support",
        ));
    }
    None
}

fn check_repair_serialization(
    gate: &WritebackCacheAuditGate,
) -> Option<WritebackCacheAuditDecision> {
    if gate.repair_serialization_state != "rw_lane_accepted" {
        return Some(reject(
            "rw_repair_serialization_unsupported",
            ["I2"],
            "rw repair-write serialization must be accepted before writeback_cache is allowed",
        ));
    }
    None
}

fn check_epoch_barrier_artifact(
    gate: &WritebackCacheAuditGate,
) -> Option<WritebackCacheAuditDecision> {
    if !gate.epoch_barrier_artifact.present {
        return Some(reject(
            "missing_epoch_barrier_artifact",
            ["I1"],
            "epoch-barrier proof artifact is missing; regenerate before requesting writeback_cache",
        ));
    }
    if !gate.epoch_barrier_artifact.fresh || !gate.epoch_barrier_artifact.passed {
        return Some(reject(
            "stale_epoch_barrier_artifact",
            ["I1"],
            "epoch-barrier proof artifact is stale or failed; rerun the proof before mutation",
        ));
    }
    None
}

fn check_crash_and_fsync_evidence(
    gate: &WritebackCacheAuditGate,
) -> Option<WritebackCacheAuditDecision> {
    if !gate.crash_matrix_artifact.present
        || !gate.crash_matrix_artifact.fresh
        || !gate.crash_matrix_artifact.passed
    {
        return Some(reject(
            "stale_crash_matrix_or_missing_fsync_evidence",
            ["I6"],
            "regenerate the crash matrix evidence before enabling writeback_cache",
        ));
    }
    if !gate.fsync_evidence_artifact.present
        || !gate.fsync_evidence_artifact.fresh
        || !gate.fsync_evidence_artifact.passed
    {
        return Some(reject(
            "stale_crash_matrix_or_missing_fsync_evidence",
            ["I6"],
            "regenerate fsync evidence before enabling writeback_cache",
        ));
    }
    None
}

fn check_conflicting_flags(
    gate: &WritebackCacheAuditGate,
) -> Option<WritebackCacheAuditDecision> {
    let banned_flags = [
        "noflush",
        "writeback_cache_disable",
        "ffs_writeback_force",
        "ffs_writeback_force_off",
    ];
    if gate
        .conflicting_flags
        .iter()
        .any(|flag| banned_flags.contains(&flag.as_str()))
    {
        return Some(reject(
            "conflicting_cli_flags",
            ["I3"],
            "remove conflicting CLI flags before requesting writeback_cache",
        ));
    }
    None
}

fn reject(
    reason: &str,
    invariants_failing: impl IntoIterator<Item = &'static str>,
    remediation: &str,
) -> WritebackCacheAuditDecision {
    let invariants: Vec<String> = invariants_failing
        .into_iter()
        .map(|id| (*id).to_owned())
        .collect();
    WritebackCacheAuditDecision::Reject {
        reason: reason.to_owned(),
        invariants_failing: invariants,
        remediation: remediation.to_owned(),
    }
}

pub fn validate_writeback_cache_audit_gate(gate: &WritebackCacheAuditGate) -> Result<()> {
    if gate.schema_version != WRITEBACK_CACHE_AUDIT_SCHEMA_VERSION {
        bail!(
            "writeback cache audit schema_version must be {WRITEBACK_CACHE_AUDIT_SCHEMA_VERSION}, got {}",
            gate.schema_version
        );
    }
    if !gate.bead_id.starts_with("bd-") {
        bail!(
            "writeback cache audit bead_id must look like bd-..., got `{}`",
            gate.bead_id
        );
    }
    let unsupported_modes: BTreeSet<&str> = ["", "swap"].into_iter().collect();
    if unsupported_modes.contains(gate.mount_options.mode.as_str()) {
        bail!(
            "writeback cache audit mount mode `{}` is not supported",
            gate.mount_options.mode
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn happy_artifact(id: &str) -> ArtifactState {
        ArtifactState {
            artifact_id: id.to_owned(),
            present: true,
            fresh: true,
            passed: true,
            artifact_path: format!("artifacts/qa/{id}.json"),
        }
    }

    fn happy_gate() -> WritebackCacheAuditGate {
        WritebackCacheAuditGate {
            schema_version: WRITEBACK_CACHE_AUDIT_SCHEMA_VERSION,
            gate_version: "v1".to_owned(),
            bead_id: "bd-rchk0.2.1.1".to_owned(),
            mount_options: WritebackMountOptions {
                raw_options: vec!["rw".to_owned(), "default_permissions".to_owned()],
                fs_name: "frankenfs".to_owned(),
                allow_other: false,
                auto_unmount: true,
                default_permissions: true,
                mode: "rw".to_owned(),
            },
            repair_serialization_state: "rw_lane_accepted".to_owned(),
            fuse_capability: FuseCapabilityState {
                probe_status: "available".to_owned(),
                kernel_supports_writeback_cache: true,
                helper_binary_present: true,
            },
            epoch_barrier_artifact: happy_artifact("epoch_barrier_proof"),
            crash_matrix_artifact: happy_artifact("crash_matrix"),
            fsync_evidence_artifact: happy_artifact("fsync_evidence"),
            filesystem_flavor: "ext4".to_owned(),
            operation_class: "mounted_write".to_owned(),
            explicit_opt_in: true,
            conflicting_flags: Vec::new(),
        }
    }

    fn rejection_reason(decision: &WritebackCacheAuditDecision) -> Option<&str> {
        if let WritebackCacheAuditDecision::Reject { reason, .. } = decision {
            Some(reason.as_str())
        } else {
            None
        }
    }

    #[test]
    fn happy_gate_accepts_writeback_cache() {
        let decision = evaluate_writeback_cache_audit(&happy_gate());
        assert!(matches!(decision, WritebackCacheAuditDecision::Accept));
    }

    #[test]
    fn raw_options_writeback_cache_token_is_rejected_without_opt_in() {
        let mut gate = happy_gate();
        gate.explicit_opt_in = false;
        gate.mount_options
            .raw_options
            .push("writeback_cache".to_owned());
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(rejection_reason(&decision), Some("default_or_read_only_mount"));
    }

    #[test]
    fn read_only_mount_is_rejected() {
        let mut gate = happy_gate();
        gate.mount_options.mode = "ro".to_owned();
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(rejection_reason(&decision), Some("default_or_read_only_mount"));
    }

    #[test]
    fn missing_explicit_opt_in_is_rejected() {
        let mut gate = happy_gate();
        gate.explicit_opt_in = false;
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(rejection_reason(&decision), Some("default_or_read_only_mount"));
    }

    #[test]
    fn unsupported_filesystem_flavor_is_rejected() {
        let mut gate = happy_gate();
        gate.filesystem_flavor = "ntfs".to_owned();
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("unsupported_filesystem_or_operation")
        );
    }

    #[test]
    fn unsupported_operation_class_is_rejected() {
        let mut gate = happy_gate();
        gate.operation_class = "mounted_mknod".to_owned();
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("unsupported_filesystem_or_operation")
        );
    }

    #[test]
    fn fuse_probe_unavailable_is_rejected() {
        let mut gate = happy_gate();
        gate.fuse_capability.probe_status = "unavailable".to_owned();
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(rejection_reason(&decision), Some("fuse_capability_unavailable"));
    }

    #[test]
    fn missing_helper_binary_is_rejected() {
        let mut gate = happy_gate();
        gate.fuse_capability.helper_binary_present = false;
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(rejection_reason(&decision), Some("fuse_capability_unavailable"));
    }

    #[test]
    fn rw_repair_serialization_pending_is_rejected() {
        let mut gate = happy_gate();
        gate.repair_serialization_state = "pending_review".to_owned();
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("rw_repair_serialization_unsupported")
        );
    }

    #[test]
    fn missing_epoch_barrier_artifact_is_rejected() {
        let mut gate = happy_gate();
        gate.epoch_barrier_artifact.present = false;
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("missing_epoch_barrier_artifact")
        );
    }

    #[test]
    fn stale_epoch_barrier_artifact_is_rejected() {
        let mut gate = happy_gate();
        gate.epoch_barrier_artifact.fresh = false;
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("stale_epoch_barrier_artifact")
        );
    }

    #[test]
    fn failed_epoch_barrier_artifact_is_rejected() {
        let mut gate = happy_gate();
        gate.epoch_barrier_artifact.passed = false;
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("stale_epoch_barrier_artifact")
        );
    }

    #[test]
    fn missing_crash_matrix_is_rejected() {
        let mut gate = happy_gate();
        gate.crash_matrix_artifact.present = false;
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("stale_crash_matrix_or_missing_fsync_evidence")
        );
    }

    #[test]
    fn stale_fsync_evidence_is_rejected() {
        let mut gate = happy_gate();
        gate.fsync_evidence_artifact.fresh = false;
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("stale_crash_matrix_or_missing_fsync_evidence")
        );
    }

    #[test]
    fn conflicting_cli_flag_is_rejected() {
        let mut gate = happy_gate();
        gate.conflicting_flags.push("ffs_writeback_force".to_owned());
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(rejection_reason(&decision), Some("conflicting_cli_flags"));
    }

    #[test]
    fn unrelated_cli_flag_is_ignored() {
        let mut gate = happy_gate();
        gate.conflicting_flags.push("noatime".to_owned());
        let decision = evaluate_writeback_cache_audit(&gate);
        assert!(matches!(decision, WritebackCacheAuditDecision::Accept));
    }

    #[test]
    fn rejection_decision_lists_invariants_failing() {
        let mut gate = happy_gate();
        gate.fuse_capability.probe_status = "unavailable".to_owned();
        let decision = evaluate_writeback_cache_audit(&gate);
        if let WritebackCacheAuditDecision::Reject {
            invariants_failing, ..
        } = decision
        {
            assert!(invariants_failing.contains(&"I5".to_owned()));
        } else {
            panic!("expected reject decision");
        }
    }

    #[test]
    fn rejection_reason_is_stable_token() {
        let mut gate = happy_gate();
        gate.repair_serialization_state = "unknown".to_owned();
        let decision = evaluate_writeback_cache_audit(&gate);
        if let WritebackCacheAuditDecision::Reject { reason, .. } = decision {
            assert!(ALLOWED_REJECTION_REASONS.contains(&reason.as_str()));
        } else {
            panic!("expected reject decision");
        }
    }

    #[test]
    fn validate_gate_top_level_rejects_bad_schema_version() {
        let mut gate = happy_gate();
        gate.schema_version = 99;
        let result = validate_writeback_cache_audit_gate(&gate);
        assert!(result.is_err());
    }

    #[test]
    fn validate_gate_top_level_rejects_unsupported_mode() {
        let mut gate = happy_gate();
        gate.mount_options.mode = "swap".to_owned();
        let result = validate_writeback_cache_audit_gate(&gate);
        assert!(result.is_err());
    }

    #[test]
    fn validate_gate_top_level_rejects_malformed_bead_id() {
        let mut gate = happy_gate();
        gate.bead_id = "PROJ-42".to_owned();
        let result = validate_writeback_cache_audit_gate(&gate);
        assert!(result.is_err());
    }

    #[test]
    fn validate_gate_top_level_accepts_happy_path() {
        let result = validate_writeback_cache_audit_gate(&happy_gate());
        assert!(result.is_ok());
    }

    #[test]
    fn required_invariant_ids_cover_six_invariants() {
        assert_eq!(REQUIRED_INVARIANT_IDS.len(), 6);
        for id in &REQUIRED_INVARIANT_IDS {
            assert!(id.starts_with('I'));
        }
    }
}
