#![forbid(unsafe_code)]

//! Writeback-cache negative-option audit gate.
//!
//! Tracks bd-rchk0.2.1.1: proves that the FUSE `writeback_cache` mount option
//! stays disabled unless every safety prerequisite is satisfied. The default
//! and unsafe paths must never accidentally forward `writeback_cache` to the
//! kernel, even when stale docs, config defaults, or unrelated mount flags are
//! present. Each rejection class carries a stable reason code so release gates
//! and the remediation catalog can fail closed without parsing prose.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{fmt::Write as _, fs, path::Path};

pub const WRITEBACK_CACHE_AUDIT_SCHEMA_VERSION: u32 = 1;
pub const WRITEBACK_CACHE_AUDIT_REPORT_SCHEMA_VERSION: u32 = 1;

/// Required invariant identifiers for the writeback-cache gate.
///
/// I1 = Snapshot Visibility Boundary.
/// I2 = Alias Order Preservation.
/// I3 = Metadata-After-Data Dependency.
/// I4 = Sync Boundary Completeness.
/// I5 = Flush Non-Durability.
/// I6 = Cross-Epoch Order.
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

pub const REQUIRED_ARTIFACT_FIELDS: [&str; 15] = [
    "schema_version",
    "gate_version",
    "bead_id",
    "mount_options.raw_options",
    "mount_options.mode",
    "repair_serialization_state",
    "fuse_capability.probe_status",
    "fuse_capability.kernel_supports_writeback_cache",
    "fuse_capability.helper_binary_present",
    "epoch_barrier_artifact.artifact_path",
    "crash_matrix_artifact.artifact_path",
    "fsync_evidence_artifact.artifact_path",
    "filesystem_flavor",
    "operation_class",
    "explicit_opt_in",
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WritebackInvariant {
    pub id: String,
    pub name: String,
    pub gate_requirement: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WritebackCacheAuditReport {
    pub schema_version: u32,
    pub gate_version: String,
    pub bead_id: String,
    pub scenario_id: String,
    pub valid: bool,
    pub decision: WritebackCacheAuditDecision,
    pub invariant_map: Vec<WritebackInvariant>,
    pub failure_modes: Vec<String>,
    pub required_artifact_fields: Vec<String>,
    pub mount_options: WritebackMountOptions,
    pub artifact_paths: Vec<String>,
    pub reproduction_command: String,
}

pub fn load_writeback_cache_audit_gate(path: &Path) -> Result<WritebackCacheAuditGate> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "failed to parse writeback-cache audit gate {}",
            path.display()
        )
    })
}

pub fn build_writeback_cache_audit_report(
    gate: &WritebackCacheAuditGate,
    scenario_id: &str,
    reproduction_command: &str,
) -> Result<WritebackCacheAuditReport> {
    validate_writeback_cache_audit_gate(gate)?;
    let decision = evaluate_writeback_cache_audit(gate);
    Ok(WritebackCacheAuditReport {
        schema_version: WRITEBACK_CACHE_AUDIT_REPORT_SCHEMA_VERSION,
        gate_version: gate.gate_version.clone(),
        bead_id: gate.bead_id.clone(),
        scenario_id: scenario_id.to_owned(),
        valid: true,
        decision,
        invariant_map: writeback_invariant_map(),
        failure_modes: ALLOWED_REJECTION_REASONS
            .iter()
            .map(|reason| (*reason).to_owned())
            .collect(),
        required_artifact_fields: REQUIRED_ARTIFACT_FIELDS
            .iter()
            .map(|field| (*field).to_owned())
            .collect(),
        mount_options: gate.mount_options.clone(),
        artifact_paths: vec![
            gate.epoch_barrier_artifact.artifact_path.clone(),
            gate.crash_matrix_artifact.artifact_path.clone(),
            gate.fsync_evidence_artifact.artifact_path.clone(),
        ],
        reproduction_command: reproduction_command.to_owned(),
    })
}

pub fn fail_on_writeback_cache_audit_errors(report: &WritebackCacheAuditReport) -> Result<()> {
    if !report.valid {
        bail!("writeback-cache audit report is invalid");
    }
    if let WritebackCacheAuditDecision::Reject { reason, .. } = &report.decision {
        bail!("writeback-cache audit rejected mount option: {reason}");
    }
    Ok(())
}

#[must_use]
pub fn render_writeback_cache_audit_markdown(report: &WritebackCacheAuditReport) -> String {
    let decision = match &report.decision {
        WritebackCacheAuditDecision::Accept => "accept".to_owned(),
        WritebackCacheAuditDecision::Reject { reason, .. } => {
            format!("reject ({reason})")
        }
    };
    let mut text = String::new();
    text.push_str("# Writeback-Cache Audit Gate\n\n");
    let _ = writeln!(text, "- schema_version: {}", report.schema_version);
    let _ = writeln!(text, "- gate_version: {}", report.gate_version);
    let _ = writeln!(text, "- bead_id: {}", report.bead_id);
    let _ = writeln!(text, "- scenario_id: {}", report.scenario_id);
    let _ = writeln!(text, "- decision: {decision}");
    let _ = writeln!(
        text,
        "- reproduction_command: `{}`\n",
        report.reproduction_command
    );
    text.push_str("## Invariants\n\n");
    for invariant in &report.invariant_map {
        let _ = writeln!(
            text,
            "- {} {}: {}",
            invariant.id, invariant.name, invariant.gate_requirement
        );
    }
    text.push_str("\n## Failure Modes\n\n");
    for mode in &report.failure_modes {
        let _ = writeln!(text, "- {mode}");
    }
    text.push_str("\n## Artifact Fields\n\n");
    for field in &report.required_artifact_fields {
        let _ = writeln!(text, "- {field}");
    }
    text
}

#[must_use]
pub fn writeback_invariant_map() -> Vec<WritebackInvariant> {
    [
        (
            "I1",
            "Snapshot Visibility Boundary",
            "epoch_barrier_artifact must be present, fresh, and passing before rw opt-in",
        ),
        (
            "I2",
            "Alias Order Preservation",
            "operation_class must be in the audited mounted-write envelope",
        ),
        (
            "I3",
            "Metadata-After-Data Dependency",
            "rw repair-write serialization must be accepted and conflicting flags absent",
        ),
        (
            "I4",
            "Sync Boundary Completeness",
            "fsync evidence must be present, fresh, and passing",
        ),
        (
            "I5",
            "Flush Non-Durability",
            "mount mode must be rw with explicit opt-in; flush-only evidence is not sufficient",
        ),
        (
            "I6",
            "Cross-Epoch Order",
            "crash matrix evidence must be present, fresh, and passing",
        ),
    ]
    .into_iter()
    .map(|(id, name, gate_requirement)| WritebackInvariant {
        id: id.to_owned(),
        name: name.to_owned(),
        gate_requirement: gate_requirement.to_owned(),
    })
    .collect()
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
            "writeback_cache requires an rw mount; default, ro, and unsupported modes must keep it disabled",
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

fn check_fuse_capability(gate: &WritebackCacheAuditGate) -> Option<WritebackCacheAuditDecision> {
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

fn check_conflicting_flags(gate: &WritebackCacheAuditGate) -> Option<WritebackCacheAuditDecision> {
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
    if gate.gate_version.trim().is_empty() {
        bail!("writeback cache audit gate_version must not be empty");
    }
    if gate.mount_options.raw_options.is_empty() {
        bail!("writeback cache audit raw_options must include the declared mount option set");
    }
    if gate.mount_options.fs_name.trim().is_empty() {
        bail!("writeback cache audit fs_name must not be empty");
    }
    if gate.mount_options.mode.trim().is_empty() {
        bail!("writeback cache audit mount mode must not be empty");
    }
    if gate.fuse_capability.probe_status.trim().is_empty() {
        bail!("writeback cache audit fuse probe_status must not be empty");
    }
    for artifact in [
        &gate.epoch_barrier_artifact,
        &gate.crash_matrix_artifact,
        &gate.fsync_evidence_artifact,
    ] {
        if artifact.artifact_id.trim().is_empty() {
            bail!("writeback cache audit artifact_id must not be empty");
        }
        if artifact.artifact_path.trim().is_empty() {
            bail!(
                "writeback cache audit artifact_path must not be empty for {}",
                artifact.artifact_id
            );
        }
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
        assert_eq!(
            rejection_reason(&decision),
            Some("default_or_read_only_mount")
        );
    }

    #[test]
    fn read_only_mount_is_rejected() {
        let mut gate = happy_gate();
        gate.mount_options.mode = "ro".to_owned();
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("default_or_read_only_mount")
        );
    }

    #[test]
    fn missing_explicit_opt_in_is_rejected() {
        let mut gate = happy_gate();
        gate.explicit_opt_in = false;
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("default_or_read_only_mount")
        );
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
        assert_eq!(
            rejection_reason(&decision),
            Some("fuse_capability_unavailable")
        );
    }

    #[test]
    fn missing_helper_binary_is_rejected() {
        let mut gate = happy_gate();
        gate.fuse_capability.helper_binary_present = false;
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("fuse_capability_unavailable")
        );
    }

    #[test]
    fn kernel_writeback_capability_false_is_rejected() {
        let mut gate = happy_gate();
        gate.fuse_capability.kernel_supports_writeback_cache = false;
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("fuse_capability_unavailable")
        );
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
    fn stale_crash_matrix_is_rejected() {
        let mut gate = happy_gate();
        gate.crash_matrix_artifact.fresh = false;
        let decision = evaluate_writeback_cache_audit(&gate);
        assert_eq!(
            rejection_reason(&decision),
            Some("stale_crash_matrix_or_missing_fsync_evidence")
        );
    }

    #[test]
    fn missing_fsync_evidence_is_rejected() {
        let mut gate = happy_gate();
        gate.fsync_evidence_artifact.present = false;
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
        gate.conflicting_flags
            .push("ffs_writeback_force".to_owned());
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
        assert!(matches!(
            &decision,
            WritebackCacheAuditDecision::Reject {
                invariants_failing,
                ..
            } if invariants_failing.contains(&"I5".to_owned())
        ));
    }

    #[test]
    fn rejection_reason_is_stable_token() {
        let mut gate = happy_gate();
        gate.repair_serialization_state = "unknown".to_owned();
        let decision = evaluate_writeback_cache_audit(&gate);
        assert!(matches!(
            &decision,
            WritebackCacheAuditDecision::Reject { reason, .. }
                if ALLOWED_REJECTION_REASONS.contains(&reason.as_str())
        ));
    }

    #[test]
    fn validate_gate_top_level_rejects_bad_schema_version() {
        let mut gate = happy_gate();
        gate.schema_version = 99;
        let result = validate_writeback_cache_audit_gate(&gate);
        assert!(result.is_err());
    }

    #[test]
    fn unsupported_mode_builds_policy_rejection_report() {
        let mut gate = happy_gate();
        gate.mount_options.mode = "swap".to_owned();
        let report = build_writeback_cache_audit_report(
            &gate,
            "writeback_cache_audit_rejects_unsupported_mode",
            "ffs-harness validate-writeback-cache-audit --gate gate.json",
        )
        .expect("unsupported mode should still produce a policy report");

        assert!(matches!(
            report.decision,
            WritebackCacheAuditDecision::Reject { ref reason, .. }
                if reason == "default_or_read_only_mount"
        ));
    }

    #[test]
    fn validate_gate_top_level_rejects_empty_mode() {
        let mut gate = happy_gate();
        gate.mount_options.mode.clear();
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
    fn validate_gate_top_level_rejects_empty_artifact_path() {
        let mut gate = happy_gate();
        gate.fsync_evidence_artifact.artifact_path.clear();
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

    #[test]
    fn invariant_map_uses_design_invariant_names() {
        let map = writeback_invariant_map();
        let names: Vec<&str> = map
            .iter()
            .map(|invariant| invariant.name.as_str())
            .collect();
        assert!(names.contains(&"Snapshot Visibility Boundary"));
        assert!(names.contains(&"Alias Order Preservation"));
        assert!(names.contains(&"Metadata-After-Data Dependency"));
        assert!(names.contains(&"Sync Boundary Completeness"));
        assert!(names.contains(&"Flush Non-Durability"));
        assert!(names.contains(&"Cross-Epoch Order"));
    }

    #[test]
    fn report_includes_failure_modes_artifact_fields_and_repro() {
        let report = build_writeback_cache_audit_report(
            &happy_gate(),
            "writeback_cache_audit_accepts_complete_gate",
            "ffs-harness validate-writeback-cache-audit --gate gate.json",
        )
        .expect("happy gate should build report");

        assert_eq!(
            report.scenario_id,
            "writeback_cache_audit_accepts_complete_gate"
        );
        assert!(
            report
                .failure_modes
                .contains(&"default_or_read_only_mount".to_owned())
        );
        assert!(
            report
                .required_artifact_fields
                .contains(&"mount_options.raw_options".to_owned())
        );
        assert_eq!(report.artifact_paths.len(), 3);
        assert!(matches!(
            report.decision,
            WritebackCacheAuditDecision::Accept
        ));
    }

    #[test]
    fn require_accept_fails_closed_on_rejection() {
        let mut gate = happy_gate();
        gate.explicit_opt_in = false;
        let report = build_writeback_cache_audit_report(
            &gate,
            "writeback_cache_audit_rejects_default_mount",
            "ffs-harness validate-writeback-cache-audit --gate gate.json --require-accept",
        )
        .expect("schema-valid rejection should still build report");

        let result = fail_on_writeback_cache_audit_errors(&report);
        assert!(result.is_err());
    }
}
