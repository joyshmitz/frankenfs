#![forbid(unsafe_code)]

//! Authoritative-lane environment manifest with replayable host probes.
//!
//! Tracks bd-7mj5d: complements `authoritative_lane_manifest` with the full
//! host/worker fingerprint a release gate must consume before treating
//! mounted, xfstests, performance, or long-campaign evidence as
//! authoritative. A pass from an unknown worker, stale kernel/FUSE state,
//! changed helper binary, mismatched mount namespace, or non-authoritative
//! local run cannot upgrade public claims unless the observed environment
//! matches the recorded manifest.

use serde::{Deserialize, Serialize};

pub const AUTHORITATIVE_ENVIRONMENT_MANIFEST_SCHEMA_VERSION: u32 = 1;

const ALLOWED_PRIVILEGE_MODELS: [&str; 4] = [
    "unprivileged",
    "user_namespace",
    "sudo_capability",
    "rootful",
];

const AUTHORITATIVE_PRIVILEGE_MODELS: [&str; 3] = ["user_namespace", "sudo_capability", "rootful"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthoritativeEnvironmentManifest {
    pub schema_version: u32,
    pub manifest_id: String,
    pub bead_id: String,
    pub lane_id: String,
    pub authoritative: bool,
    pub host_id: String,
    pub worker_id: String,
    pub kernel: String,
    pub fuse_kernel_version: String,
    pub fuser_helper_version: String,
    pub mkfs_versions: Vec<MkfsVersion>,
    pub cargo_toolchain: String,
    pub rustc_version: String,
    pub mount_namespace: String,
    pub privilege_model: String,
    pub fs_tools: Vec<String>,
    pub resource_limits: ResourceLimits,
    pub git_sha: String,
    pub artifact_schema_version: u32,
    pub probe_at_unix: u64,
    pub freshness_ttl_seconds: u64,
    pub now_unix: u64,
    pub replay_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MkfsVersion {
    pub flavor: String,
    pub binary: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_open_files: u64,
    pub max_address_space_bytes: u64,
    pub max_processes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum AuthoritativeEnvironmentDecision {
    Authoritative { manifest_id: String },
    Skip { reason: String, remediation: String },
    RejectMismatch { reason: String, remediation: String },
}

#[must_use]
pub fn evaluate_authoritative_environment(
    manifest: &AuthoritativeEnvironmentManifest,
    observed: &AuthoritativeEnvironmentManifest,
) -> AuthoritativeEnvironmentDecision {
    if manifest.schema_version != AUTHORITATIVE_ENVIRONMENT_MANIFEST_SCHEMA_VERSION {
        return reject(
            "stale_environment_schema",
            "regenerate the environment manifest against the current schema",
        );
    }
    if let Some(decision) = check_required_fields(manifest) {
        return decision;
    }
    if !manifest.authoritative {
        return AuthoritativeEnvironmentDecision::Skip {
            reason: "non_authoritative_local_run".to_owned(),
            remediation: "rerun on an authoritative worker before promoting public claims"
                .to_owned(),
        };
    }
    if !AUTHORITATIVE_PRIVILEGE_MODELS.contains(&manifest.privilege_model.as_str()) {
        return reject(
            "non_authoritative_privilege_model",
            "authoritative lanes require user_namespace, sudo_capability, or rootful",
        );
    }
    if let Some(decision) = check_freshness(manifest) {
        return decision;
    }
    if let Some(decision) = check_observed_match(manifest, observed) {
        return decision;
    }
    AuthoritativeEnvironmentDecision::Authoritative {
        manifest_id: manifest.manifest_id.clone(),
    }
}

fn check_required_fields(
    manifest: &AuthoritativeEnvironmentManifest,
) -> Option<AuthoritativeEnvironmentDecision> {
    if let Some(decision) = check_required_identity_fields(manifest) {
        return Some(decision);
    }
    if let Some(decision) = check_required_runtime_fields(manifest) {
        return Some(decision);
    }
    check_required_artifact_fields(manifest)
}

fn check_required_identity_fields(
    manifest: &AuthoritativeEnvironmentManifest,
) -> Option<AuthoritativeEnvironmentDecision> {
    if manifest.lane_id.trim().is_empty() {
        return Some(reject("missing_lane_id", "set a non-empty lane_id"));
    }
    if manifest.manifest_id.trim().is_empty() {
        return Some(reject("missing_manifest_id", "set a non-empty manifest_id"));
    }
    if !manifest.bead_id.starts_with("bd-") {
        return Some(reject(
            "malformed_bead_id",
            "manifest bead_id must look like bd-...",
        ));
    }
    if manifest.host_id.trim().is_empty() {
        return Some(reject(
            "missing_host_id",
            "record host_id from the worker fingerprint",
        ));
    }
    if manifest.worker_id.trim().is_empty() {
        return Some(reject(
            "missing_worker_id",
            "record worker_id (rch worker name or runner identifier)",
        ));
    }
    None
}

fn check_required_runtime_fields(
    manifest: &AuthoritativeEnvironmentManifest,
) -> Option<AuthoritativeEnvironmentDecision> {
    if manifest.kernel.trim().is_empty() {
        return Some(reject("missing_kernel", "record uname -r"));
    }
    if manifest.fuse_kernel_version.trim().is_empty() {
        return Some(reject(
            "missing_fuse_kernel_version",
            "record the fuse kernel module version",
        ));
    }
    if manifest.fuser_helper_version.trim().is_empty() {
        return Some(reject(
            "missing_fuser_helper_version",
            "record the fuser helper binary version",
        ));
    }
    if manifest.cargo_toolchain.trim().is_empty() {
        return Some(reject(
            "missing_cargo_toolchain",
            "record the cargo channel and date",
        ));
    }
    if manifest.rustc_version.trim().is_empty() {
        return Some(reject(
            "missing_rustc_version",
            "record rustc --version output",
        ));
    }
    if !ALLOWED_PRIVILEGE_MODELS.contains(&manifest.privilege_model.as_str()) {
        return Some(reject(
            "unsupported_privilege_model",
            "privilege_model must be unprivileged / user_namespace / sudo_capability / rootful",
        ));
    }
    if manifest.mount_namespace.trim().is_empty() {
        return Some(reject(
            "missing_mount_namespace",
            "record the mount namespace identifier (e.g. readlink /proc/self/ns/mnt)",
        ));
    }
    None
}

fn check_required_artifact_fields(
    manifest: &AuthoritativeEnvironmentManifest,
) -> Option<AuthoritativeEnvironmentDecision> {
    if manifest.git_sha.trim().is_empty() || manifest.git_sha.len() < 7 {
        return Some(reject(
            "missing_git_sha",
            "record at least the short git SHA (>= 7 chars)",
        ));
    }
    if manifest.artifact_schema_version == 0 {
        return Some(reject(
            "zero_artifact_schema_version",
            "record the artifact schema version emitted by this lane",
        ));
    }
    if manifest.probe_at_unix == 0 {
        return Some(reject(
            "missing_probe_timestamp",
            "record probe_at_unix when the host probe ran",
        ));
    }
    if manifest.freshness_ttl_seconds == 0 {
        return Some(reject(
            "zero_freshness_ttl",
            "configure freshness_ttl_seconds; stale probes cannot upgrade authoritative claims",
        ));
    }
    if manifest.replay_command.trim().is_empty() {
        return Some(reject(
            "missing_replay_command",
            "record a replay_command operators can run to reproduce the manifest",
        ));
    }
    if manifest.mkfs_versions.is_empty() {
        return Some(reject(
            "missing_mkfs_versions",
            "record at least one mkfs.<flavor> binary + version",
        ));
    }
    for mkfs in &manifest.mkfs_versions {
        if mkfs.flavor.trim().is_empty()
            || mkfs.binary.trim().is_empty()
            || mkfs.version.trim().is_empty()
        {
            return Some(reject(
                "incomplete_mkfs_version",
                "every mkfs entry must record flavor, binary, and version",
            ));
        }
    }
    if manifest.fs_tools.is_empty() {
        return Some(reject(
            "missing_fs_tools",
            "record relevant filesystem tools (fsck, btrfs, e2fsck, ...)",
        ));
    }
    if manifest.resource_limits.max_open_files == 0
        || manifest.resource_limits.max_address_space_bytes == 0
        || manifest.resource_limits.max_processes == 0
    {
        return Some(reject(
            "missing_resource_limits",
            "record max_open_files, max_address_space_bytes, and max_processes",
        ));
    }
    None
}

fn check_freshness(
    manifest: &AuthoritativeEnvironmentManifest,
) -> Option<AuthoritativeEnvironmentDecision> {
    if manifest.probe_at_unix > manifest.now_unix {
        return Some(reject(
            "future_probe_timestamp",
            "rerun the host probe; future-dated manifests cannot upgrade authoritative claims",
        ));
    }
    let elapsed = manifest.now_unix.saturating_sub(manifest.probe_at_unix);
    if elapsed > manifest.freshness_ttl_seconds {
        return Some(reject(
            "stale_environment_manifest",
            "rerun the host probe; stale manifests cannot upgrade authoritative claims",
        ));
    }
    None
}

fn check_observed_match(
    manifest: &AuthoritativeEnvironmentManifest,
    observed: &AuthoritativeEnvironmentManifest,
) -> Option<AuthoritativeEnvironmentDecision> {
    if manifest.host_id != observed.host_id {
        return Some(reject(
            "host_mismatch",
            "observed host differs from recorded manifest; rebuild the manifest on the actual worker",
        ));
    }
    if manifest.worker_id != observed.worker_id {
        return Some(reject(
            "worker_mismatch",
            "observed worker differs; rebuild the manifest on the actual worker",
        ));
    }
    if manifest.kernel != observed.kernel {
        return Some(reject(
            "kernel_mismatch",
            "observed kernel differs from recorded manifest",
        ));
    }
    if manifest.fuse_kernel_version != observed.fuse_kernel_version {
        return Some(reject(
            "fuse_kernel_version_mismatch",
            "observed fuse module differs from recorded manifest",
        ));
    }
    if manifest.fuser_helper_version != observed.fuser_helper_version {
        return Some(reject(
            "fuser_helper_version_mismatch",
            "observed fuser helper differs from recorded manifest",
        ));
    }
    if manifest.cargo_toolchain != observed.cargo_toolchain {
        return Some(reject(
            "cargo_toolchain_mismatch",
            "observed cargo toolchain differs",
        ));
    }
    if manifest.rustc_version != observed.rustc_version {
        return Some(reject(
            "rustc_version_mismatch",
            "observed rustc version differs",
        ));
    }
    if manifest.mount_namespace != observed.mount_namespace {
        return Some(reject(
            "mount_namespace_mismatch",
            "observed mount namespace differs from the recorded manifest",
        ));
    }
    if observed.privilege_model == "unprivileged"
        || privilege_rank(&observed.privilege_model) < privilege_rank(&manifest.privilege_model)
    {
        return Some(reject(
            "privilege_model_downgrade",
            "observed privilege model is weaker than the recorded manifest",
        ));
    }
    if manifest.resource_limits != observed.resource_limits {
        return Some(reject(
            "resource_limits_mismatch",
            "observed resource limits diverge from the recorded manifest",
        ));
    }
    None
}

fn privilege_rank(value: &str) -> u8 {
    match value {
        "user_namespace" => 1,
        "sudo_capability" => 2,
        "rootful" => 3,
        _ => 0,
    }
}

fn reject(reason: &str, remediation: &str) -> AuthoritativeEnvironmentDecision {
    AuthoritativeEnvironmentDecision::RejectMismatch {
        reason: reason.to_owned(),
        remediation: remediation.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn happy_manifest() -> AuthoritativeEnvironmentManifest {
        AuthoritativeEnvironmentManifest {
            schema_version: AUTHORITATIVE_ENVIRONMENT_MANIFEST_SCHEMA_VERSION,
            manifest_id: "env_001".to_owned(),
            bead_id: "bd-7mj5d".to_owned(),
            lane_id: "rchk_authoritative_v1".to_owned(),
            authoritative: true,
            host_id: "worker-vmi1153651".to_owned(),
            worker_id: "rch-worker-vmi1153651".to_owned(),
            kernel: "linux-6.x.y".to_owned(),
            fuse_kernel_version: "fuse-3.16".to_owned(),
            fuser_helper_version: "fuser-0.16".to_owned(),
            mkfs_versions: vec![
                MkfsVersion {
                    flavor: "ext4".to_owned(),
                    binary: "mkfs.ext4".to_owned(),
                    version: "1.47.0".to_owned(),
                },
                MkfsVersion {
                    flavor: "btrfs".to_owned(),
                    binary: "mkfs.btrfs".to_owned(),
                    version: "6.5.1".to_owned(),
                },
            ],
            cargo_toolchain: "nightly-2024-edition-pinned".to_owned(),
            rustc_version: "rustc 1.85.0-nightly".to_owned(),
            mount_namespace: "mnt:[4026531840]".to_owned(),
            privilege_model: "sudo_capability".to_owned(),
            fs_tools: vec!["e2fsck".to_owned(), "btrfs".to_owned()],
            resource_limits: ResourceLimits {
                max_open_files: 65_536,
                max_address_space_bytes: 8 * 1024 * 1024 * 1024,
                max_processes: 4_096,
            },
            git_sha: "abcdef1234567890".to_owned(),
            artifact_schema_version: 1,
            probe_at_unix: 1_000,
            freshness_ttl_seconds: 3_600,
            now_unix: 1_500,
            replay_command:
                "rch exec -- cargo run -p ffs-harness -- record-environment-manifest --out artifacts/env-manifest.json"
                    .to_owned(),
        }
    }

    fn reason(decision: &AuthoritativeEnvironmentDecision) -> Option<&str> {
        match decision {
            AuthoritativeEnvironmentDecision::Authoritative { .. } => None,
            AuthoritativeEnvironmentDecision::Skip { reason, .. }
            | AuthoritativeEnvironmentDecision::RejectMismatch { reason, .. } => {
                Some(reason.as_str())
            }
        }
    }

    #[test]
    fn happy_authoritative_environment_passes() {
        let manifest = happy_manifest();
        let decision = evaluate_authoritative_environment(&manifest, &manifest.clone());
        assert!(matches!(
            decision,
            AuthoritativeEnvironmentDecision::Authoritative { .. }
        ));
    }

    #[test]
    fn non_authoritative_run_skips() {
        let mut manifest = happy_manifest();
        manifest.authoritative = false;
        let decision = evaluate_authoritative_environment(&manifest, &manifest.clone());
        assert_eq!(reason(&decision), Some("non_authoritative_local_run"));
    }

    #[test]
    fn missing_lane_id_is_rejected() {
        let mut manifest = happy_manifest();
        manifest.lane_id = String::new();
        let decision = evaluate_authoritative_environment(&manifest, &manifest.clone());
        assert_eq!(reason(&decision), Some("missing_lane_id"));
    }

    #[test]
    fn missing_host_id_is_rejected() {
        let mut manifest = happy_manifest();
        manifest.host_id = String::new();
        let decision = evaluate_authoritative_environment(&manifest, &manifest.clone());
        assert_eq!(reason(&decision), Some("missing_host_id"));
    }

    #[test]
    fn missing_worker_id_is_rejected() {
        let mut manifest = happy_manifest();
        manifest.worker_id = String::new();
        let decision = evaluate_authoritative_environment(&manifest, &manifest.clone());
        assert_eq!(reason(&decision), Some("missing_worker_id"));
    }

    #[test]
    fn missing_kernel_is_rejected() {
        let mut manifest = happy_manifest();
        manifest.kernel = String::new();
        let decision = evaluate_authoritative_environment(&manifest, &manifest.clone());
        assert_eq!(reason(&decision), Some("missing_kernel"));
    }

    #[test]
    fn missing_fuse_kernel_version_is_rejected() {
        let mut manifest = happy_manifest();
        manifest.fuse_kernel_version = String::new();
        let decision = evaluate_authoritative_environment(&manifest, &manifest.clone());
        assert_eq!(reason(&decision), Some("missing_fuse_kernel_version"));
    }

    #[test]
    fn missing_fuser_helper_version_is_rejected() {
        let mut manifest = happy_manifest();
        manifest.fuser_helper_version = String::new();
        let decision = evaluate_authoritative_environment(&manifest, &manifest.clone());
        assert_eq!(reason(&decision), Some("missing_fuser_helper_version"));
    }

    #[test]
    fn missing_cargo_toolchain_is_rejected() {
        let mut manifest = happy_manifest();
        manifest.cargo_toolchain = String::new();
        let decision = evaluate_authoritative_environment(&manifest, &manifest.clone());
        assert_eq!(reason(&decision), Some("missing_cargo_toolchain"));
    }

    #[test]
    fn missing_rustc_version_is_rejected() {
        let mut manifest = happy_manifest();
        manifest.rustc_version = String::new();
        let decision = evaluate_authoritative_environment(&manifest, &manifest.clone());
        assert_eq!(reason(&decision), Some("missing_rustc_version"));
    }

    #[test]
    fn unsupported_privilege_model_is_rejected() {
        let mut manifest = happy_manifest();
        manifest.privilege_model = "wizard_capability".to_owned();
        let decision = evaluate_authoritative_environment(&manifest, &manifest.clone());
        assert_eq!(reason(&decision), Some("unsupported_privilege_model"));
    }

    #[test]
    fn unprivileged_authoritative_is_rejected() {
        let mut manifest = happy_manifest();
        manifest.privilege_model = "unprivileged".to_owned();
        let decision = evaluate_authoritative_environment(&manifest, &manifest.clone());
        assert_eq!(reason(&decision), Some("non_authoritative_privilege_model"));
    }

    #[test]
    fn missing_mount_namespace_is_rejected() {
        let mut manifest = happy_manifest();
        manifest.mount_namespace = String::new();
        let decision = evaluate_authoritative_environment(&manifest, &manifest.clone());
        assert_eq!(reason(&decision), Some("missing_mount_namespace"));
    }

    #[test]
    fn missing_git_sha_is_rejected() {
        let mut manifest = happy_manifest();
        manifest.git_sha = "abc".to_owned();
        let decision = evaluate_authoritative_environment(&manifest, &manifest.clone());
        assert_eq!(reason(&decision), Some("missing_git_sha"));
    }

    #[test]
    fn zero_artifact_schema_version_is_rejected() {
        let mut manifest = happy_manifest();
        manifest.artifact_schema_version = 0;
        let decision = evaluate_authoritative_environment(&manifest, &manifest.clone());
        assert_eq!(reason(&decision), Some("zero_artifact_schema_version"));
    }

    #[test]
    fn missing_probe_timestamp_is_rejected() {
        let mut manifest = happy_manifest();
        manifest.probe_at_unix = 0;
        let decision = evaluate_authoritative_environment(&manifest, &manifest.clone());
        assert_eq!(reason(&decision), Some("missing_probe_timestamp"));
    }

    #[test]
    fn zero_freshness_ttl_is_rejected() {
        let mut manifest = happy_manifest();
        manifest.freshness_ttl_seconds = 0;
        let decision = evaluate_authoritative_environment(&manifest, &manifest.clone());
        assert_eq!(reason(&decision), Some("zero_freshness_ttl"));
    }

    #[test]
    fn missing_replay_command_is_rejected() {
        let mut manifest = happy_manifest();
        manifest.replay_command = String::new();
        let decision = evaluate_authoritative_environment(&manifest, &manifest.clone());
        assert_eq!(reason(&decision), Some("missing_replay_command"));
    }

    #[test]
    fn missing_mkfs_versions_is_rejected() {
        let mut manifest = happy_manifest();
        manifest.mkfs_versions.clear();
        let decision = evaluate_authoritative_environment(&manifest, &manifest.clone());
        assert_eq!(reason(&decision), Some("missing_mkfs_versions"));
    }

    #[test]
    fn incomplete_mkfs_version_is_rejected() {
        let mut manifest = happy_manifest();
        manifest.mkfs_versions[0].version = String::new();
        let decision = evaluate_authoritative_environment(&manifest, &manifest.clone());
        assert_eq!(reason(&decision), Some("incomplete_mkfs_version"));
    }

    #[test]
    fn missing_fs_tools_is_rejected() {
        let mut manifest = happy_manifest();
        manifest.fs_tools.clear();
        let decision = evaluate_authoritative_environment(&manifest, &manifest.clone());
        assert_eq!(reason(&decision), Some("missing_fs_tools"));
    }

    #[test]
    fn zero_resource_limit_is_rejected() {
        let mut manifest = happy_manifest();
        manifest.resource_limits.max_open_files = 0;
        let decision = evaluate_authoritative_environment(&manifest, &manifest.clone());
        assert_eq!(reason(&decision), Some("missing_resource_limits"));
    }

    #[test]
    fn stale_manifest_is_rejected() {
        let mut manifest = happy_manifest();
        manifest.now_unix = manifest.probe_at_unix + manifest.freshness_ttl_seconds + 1;
        let decision = evaluate_authoritative_environment(&manifest, &manifest.clone());
        assert_eq!(reason(&decision), Some("stale_environment_manifest"));
    }

    #[test]
    fn future_probe_timestamp_is_rejected() {
        let mut manifest = happy_manifest();
        manifest.probe_at_unix = manifest.now_unix + 1;
        let decision = evaluate_authoritative_environment(&manifest, &manifest.clone());
        assert_eq!(reason(&decision), Some("future_probe_timestamp"));
        assert!(matches!(
            decision,
            AuthoritativeEnvironmentDecision::RejectMismatch { .. }
        ));
    }

    #[test]
    fn host_mismatch_is_rejected() {
        let manifest = happy_manifest();
        let mut observed = manifest.clone();
        observed.host_id = "other-host".to_owned();
        let decision = evaluate_authoritative_environment(&manifest, &observed);
        assert_eq!(reason(&decision), Some("host_mismatch"));
    }

    #[test]
    fn worker_mismatch_is_rejected() {
        let manifest = happy_manifest();
        let mut observed = manifest.clone();
        observed.worker_id = "other-worker".to_owned();
        let decision = evaluate_authoritative_environment(&manifest, &observed);
        assert_eq!(reason(&decision), Some("worker_mismatch"));
    }

    #[test]
    fn kernel_mismatch_is_rejected() {
        let manifest = happy_manifest();
        let mut observed = manifest.clone();
        observed.kernel = "linux-7.0".to_owned();
        let decision = evaluate_authoritative_environment(&manifest, &observed);
        assert_eq!(reason(&decision), Some("kernel_mismatch"));
    }

    #[test]
    fn fuse_kernel_version_mismatch_is_rejected() {
        let manifest = happy_manifest();
        let mut observed = manifest.clone();
        observed.fuse_kernel_version = "fuse-2.9".to_owned();
        let decision = evaluate_authoritative_environment(&manifest, &observed);
        assert_eq!(reason(&decision), Some("fuse_kernel_version_mismatch"));
    }

    #[test]
    fn fuser_helper_version_mismatch_is_rejected() {
        let manifest = happy_manifest();
        let mut observed = manifest.clone();
        observed.fuser_helper_version = "fuser-0.10".to_owned();
        let decision = evaluate_authoritative_environment(&manifest, &observed);
        assert_eq!(reason(&decision), Some("fuser_helper_version_mismatch"));
    }

    #[test]
    fn toolchain_mismatch_is_rejected() {
        let manifest = happy_manifest();
        let mut observed = manifest.clone();
        observed.cargo_toolchain = "stable".to_owned();
        let decision = evaluate_authoritative_environment(&manifest, &observed);
        assert_eq!(reason(&decision), Some("cargo_toolchain_mismatch"));
    }

    #[test]
    fn mount_namespace_mismatch_is_rejected() {
        let manifest = happy_manifest();
        let mut observed = manifest.clone();
        observed.mount_namespace = "mnt:[1234567890]".to_owned();
        let decision = evaluate_authoritative_environment(&manifest, &observed);
        assert_eq!(reason(&decision), Some("mount_namespace_mismatch"));
    }

    #[test]
    fn privilege_model_downgrade_is_rejected() {
        let manifest = happy_manifest();
        let mut observed = manifest.clone();
        observed.privilege_model = "user_namespace".to_owned();
        let decision = evaluate_authoritative_environment(&manifest, &observed);
        assert_eq!(reason(&decision), Some("privilege_model_downgrade"));
    }

    #[test]
    fn unprivileged_observed_is_rejected() {
        let manifest = happy_manifest();
        let mut observed = manifest.clone();
        observed.privilege_model = "unprivileged".to_owned();
        let decision = evaluate_authoritative_environment(&manifest, &observed);
        assert_eq!(reason(&decision), Some("privilege_model_downgrade"));
    }

    #[test]
    fn resource_limit_mismatch_is_rejected() {
        let manifest = happy_manifest();
        let mut observed = manifest.clone();
        observed.resource_limits.max_open_files = 1024;
        let decision = evaluate_authoritative_environment(&manifest, &observed);
        assert_eq!(reason(&decision), Some("resource_limits_mismatch"));
    }

    #[test]
    fn malformed_bead_id_is_rejected() {
        let mut manifest = happy_manifest();
        manifest.bead_id = "PROJ-99".to_owned();
        let decision = evaluate_authoritative_environment(&manifest, &manifest.clone());
        assert_eq!(reason(&decision), Some("malformed_bead_id"));
    }

    #[test]
    fn stale_schema_version_is_rejected() {
        let mut manifest = happy_manifest();
        manifest.schema_version = 99;
        let decision = evaluate_authoritative_environment(&manifest, &manifest.clone());
        assert_eq!(reason(&decision), Some("stale_environment_schema"));
    }
}
