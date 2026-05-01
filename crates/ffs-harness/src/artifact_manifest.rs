#![forbid(unsafe_code)]

//! Verification artifact manifest schema, retention policy, and redaction rules.
//!
//! Defines a canonical, versioned manifest format for all FrankenFS verification
//! outputs (E2E results, benchmark baselines, proof artifacts, repro packs). The
//! schema enables:
//!
//! - **Reproducible audits**: every gate run produces a self-describing manifest.
//! - **Retention governance**: age/count-based pruning with configurable policies.
//! - **Redaction**: sensitive fields are scrubbed while preserving debug value.
//! - **Validation**: manifest conformance is checked by unit and E2E tests.
//!
//! # Contract version
//!
//! The current schema version is [`SCHEMA_VERSION`]. Any breaking change to
//! field semantics or required fields MUST bump this version.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tracing::{debug, info, warn};

/// Schema version for the artifact manifest. Bump on breaking changes.
pub const SCHEMA_VERSION: u32 = 1;

/// Maximum age in days for default retention policy.
pub const DEFAULT_MAX_AGE_DAYS: u32 = 90;

/// Maximum number of manifests to retain per gate (rolling window).
pub const DEFAULT_MAX_COUNT: u32 = 50;

/// Maximum total artifact size in bytes before pruning triggers (500 MB).
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 500 * 1024 * 1024;

// ── Manifest schema ──────────────────────────────────────────────────────

/// Top-level verification artifact manifest.
///
/// Every gate run (E2E, benchmark, fuzz) produces one manifest that indexes
/// all artifacts, captures environment context, and records scenario outcomes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactManifest {
    /// Schema version for forward compatibility.
    pub schema_version: u32,
    /// Unique run identifier (e.g., UUID or timestamp-based).
    pub run_id: String,
    /// ISO 8601 timestamp of manifest creation.
    pub created_at: String,
    /// Gate or suite identifier (e.g., "ffs_smoke", "ffs_benchmark_taxonomy").
    pub gate_id: String,
    /// Optional bead identifier for traceability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bead_id: Option<String>,
    /// Git context at the time of the run.
    pub git_context: GitContext,
    /// Host environment fingerprint.
    pub environment: EnvironmentFingerprint,
    /// Scenario outcomes indexed by scenario_id.
    pub scenarios: BTreeMap<String, ScenarioOutcome>,
    /// Run-level operational metadata required for readiness-grade artifacts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operational_context: Option<OperationalRunContext>,
    /// Per-scenario operational metadata keyed by scenario_id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub operational_scenarios: BTreeMap<String, OperationalScenarioRecord>,
    /// Artifact entries grouped by category.
    pub artifacts: Vec<ArtifactEntry>,
    /// Overall gate verdict.
    pub verdict: GateVerdict,
    /// Total wall-clock duration of the gate run in seconds.
    pub duration_secs: f64,
    /// Retention metadata (when this manifest was last pruning-evaluated).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<RetentionMetadata>,
}

/// Git context captured at manifest creation time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitContext {
    /// Current commit SHA (short or full).
    pub commit: String,
    /// Branch name.
    pub branch: String,
    /// Whether the working tree was clean at run time.
    pub clean: bool,
}

/// Host environment fingerprint for reproducibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentFingerprint {
    /// Hostname or machine identifier.
    pub hostname: String,
    /// CPU model string.
    pub cpu_model: String,
    /// Number of logical CPUs.
    pub cpu_count: u32,
    /// Total RAM in GiB.
    pub memory_gib: u32,
    /// Kernel version string.
    pub kernel: String,
    /// Rust compiler version.
    pub rustc_version: String,
    /// Cargo version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cargo_version: Option<String>,
}

/// Outcome of a single E2E scenario within a gate run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScenarioOutcome {
    /// Scenario identifier (must match `scenario_id_regex`).
    pub scenario_id: String,
    /// Pass/Fail outcome.
    pub outcome: ScenarioResult,
    /// Optional detail string (error message, note, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Duration of this scenario in seconds.
    #[serde(default)]
    pub duration_secs: f64,
}

/// Scenario result values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ScenarioResult {
    Pass,
    Fail,
    Skip,
}

/// Run-level metadata shared by operational E2E and long-running validation
/// artifacts.
///
/// This is stricter than the generic manifest envelope: every readiness-grade
/// run must record the command, worker identity, FUSE capability, and the
/// canonical stdout/stderr log paths needed to reproduce the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationalRunContext {
    /// Exact command line used to run the validation.
    pub command_line: Vec<String>,
    /// Host/worker identity for the run.
    pub worker: WorkerContext,
    /// FUSE capability observed before executing mount-sensitive scenarios.
    pub fuse_capability: FuseCapabilityResult,
    /// Primary stdout log path, relative to the repository root or artifact root.
    pub stdout_path: String,
    /// Primary stderr log path, relative to the repository root or artifact root.
    pub stderr_path: String,
}

/// Host/worker identity for operational validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerContext {
    /// Host identifier; redaction may replace this before external sharing.
    pub host: String,
    /// Optional worker or RCH target identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
}

/// FUSE capability result vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuseCapabilityResult {
    /// `/dev/fuse` and mount prerequisites are usable.
    Available,
    /// `/dev/fuse` or required mount tools are absent.
    Unavailable,
    /// FUSE exists but the current user cannot access or mount with it.
    PermissionDenied,
    /// User or CI configuration intentionally disabled FUSE lanes.
    DisabledByUser,
    /// FUSE is not relevant to this run.
    NotApplicable,
    /// Capability has not been probed; invalid for readiness-grade artifacts.
    NotChecked,
}

/// Filesystem flavor exercised by a scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemFlavor {
    Ext4,
    Btrfs,
    Native,
    Mixed,
    NotApplicable,
}

/// Operational pass/fail/skip/error classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationalOutcomeClass {
    Pass,
    Fail,
    Skip,
    Error,
}

/// Cleanup status for temporary images, mounts, and work directories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupStatus {
    Clean,
    PreservedArtifacts,
    Failed,
    NotRun,
}

/// Canonical skip reasons that preserve product-vs-host distinction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    FuseUnavailable,
    FusePermissionDenied,
    UserDisabled,
    WorkerDependencyMissing,
    UnsupportedV1Scope,
    RootOwnedBtrfsTestdirEacces,
    NotApplicable,
}

/// Canonical operational error classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationalErrorClass {
    ProductFailure,
    HarnessBug,
    WorkerDependencyMissing,
    FusePermissionSkip,
    RootOwnedBtrfsTestdirEacces,
    UnsupportedV1Scope,
    StaleTrackerToolingFailure,
    UnsafeCleanupFailure,
    ResourceLimit,
    HostEnvironmentFailure,
}

/// Per-scenario operational metadata required for user-readable readiness
/// artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationalScenarioRecord {
    /// Must match the manifest scenario map key.
    pub scenario_id: String,
    /// Filesystem flavor under test.
    pub filesystem: FilesystemFlavor,
    /// SHA-256 or other stable image digest when an image is involved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_hash: Option<String>,
    /// Mount options used by mounted scenarios.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mount_options: Vec<String>,
    /// Expected result before execution.
    pub expected_outcome: ScenarioResult,
    /// Observed result after execution.
    pub actual_outcome: ScenarioResult,
    /// Operational classification, including error for infrastructure or
    /// harness failures that are not product failures.
    pub classification: OperationalOutcomeClass,
    /// Exit status for the scenario command or probe.
    pub exit_status: i32,
    /// Scenario-specific stdout path.
    pub stdout_path: String,
    /// Scenario-specific stderr path.
    pub stderr_path: String,
    /// Evidence ledger paths produced or consumed by the scenario.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ledger_paths: Vec<String>,
    /// Artifact paths referenced by this scenario.
    pub artifact_refs: Vec<String>,
    /// Cleanup result for temporary resources.
    pub cleanup_status: CleanupStatus,
    /// Required when classification is fail/error; optional otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_class: Option<OperationalErrorClass>,
    /// Required for fail/error and for all skips that need user action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation_hint: Option<String>,
    /// Required when classification is skip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<SkipReason>,
}

/// A single artifact entry in the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactEntry {
    /// Relative path from the repository root.
    pub path: String,
    /// Artifact category for grouping and retention.
    pub category: ArtifactCategory,
    /// MIME type or format hint (e.g., "application/json", "text/plain").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// File size in bytes.
    pub size_bytes: u64,
    /// SHA-256 checksum hex string for integrity verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Whether this artifact contains redacted content.
    #[serde(default)]
    pub redacted: bool,
    /// Artifact-level metadata (e.g., scenario_id, operation_id).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

/// Artifact categories for grouping and retention policy application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactCategory {
    /// E2E test logs and SCENARIO_RESULT markers.
    E2eLog,
    /// Benchmark baseline JSON and hyperfine exports.
    BenchmarkBaseline,
    /// Benchmark comparison / regression reports.
    BenchmarkReport,
    /// Fuzz corpus seeds and crash artifacts.
    FuzzCorpus,
    /// Fuzz crash minimization artifacts.
    FuzzCrash,
    /// Proof-of-correctness or isomorphism evidence.
    ProofArtifact,
    /// Reproduction pack (environment + commands + inputs).
    ReproPack,
    /// Human-readable summary reports (Markdown, etc.).
    SummaryReport,
    /// Raw command output or logs.
    RawLog,
}

impl ArtifactCategory {
    /// Human-readable label for reports.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::E2eLog => "E2E test log",
            Self::BenchmarkBaseline => "Benchmark baseline",
            Self::BenchmarkReport => "Benchmark report",
            Self::FuzzCorpus => "Fuzz corpus",
            Self::FuzzCrash => "Fuzz crash artifact",
            Self::ProofArtifact => "Proof artifact",
            Self::ReproPack => "Reproduction pack",
            Self::SummaryReport => "Summary report",
            Self::RawLog => "Raw log",
        }
    }

    /// All category values for iteration.
    pub const ALL: &'static [Self] = &[
        Self::E2eLog,
        Self::BenchmarkBaseline,
        Self::BenchmarkReport,
        Self::FuzzCorpus,
        Self::FuzzCrash,
        Self::ProofArtifact,
        Self::ReproPack,
        Self::SummaryReport,
        Self::RawLog,
    ];
}

/// Overall gate verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum GateVerdict {
    /// All scenarios passed.
    Pass,
    /// At least one scenario failed.
    Fail,
    /// Gate was skipped (e.g., missing prerequisite).
    Skip,
}

// ── Retention policy ─────────────────────────────────────────────────────

/// Retention policy for artifact manifests and their referenced files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Maximum age in days before a manifest is eligible for pruning.
    pub max_age_days: u32,
    /// Maximum number of manifests to retain per gate (FIFO).
    pub max_count_per_gate: u32,
    /// Maximum total artifact storage in bytes before pruning triggers.
    pub max_total_bytes: u64,
    /// Per-category overrides (category → max_age_days).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub category_overrides: BTreeMap<ArtifactCategory, u32>,
    /// Whether to keep manifests with failing verdicts longer (2x max_age).
    pub preserve_failures: bool,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            max_age_days: DEFAULT_MAX_AGE_DAYS,
            max_count_per_gate: DEFAULT_MAX_COUNT,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            preserve_failures: true,
            category_overrides: BTreeMap::new(),
        }
    }
}

impl RetentionPolicy {
    /// Determine the effective max age for a given category and verdict.
    #[must_use]
    pub fn effective_max_age_days(&self, category: ArtifactCategory, verdict: GateVerdict) -> u32 {
        let base = self
            .category_overrides
            .get(&category)
            .copied()
            .unwrap_or(self.max_age_days);

        if self.preserve_failures && verdict == GateVerdict::Fail {
            base.saturating_mul(2)
        } else {
            base
        }
    }
}

/// Metadata about when retention was last evaluated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionMetadata {
    /// ISO 8601 timestamp of last retention evaluation.
    pub last_evaluated_at: String,
    /// Whether this manifest is marked for pruning.
    pub marked_for_pruning: bool,
    /// Reason for pruning eligibility (if marked).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pruning_reason: Option<String>,
}

/// Evaluate which manifests should be pruned based on the retention policy.
///
/// Takes a list of manifests sorted by creation time (oldest first) and
/// returns indices of those eligible for pruning.
#[must_use]
pub fn evaluate_retention(
    manifests: &[ArtifactManifest],
    policy: &RetentionPolicy,
    current_epoch_days: u32,
) -> Vec<usize> {
    let mut prune_indices = Vec::new();

    // Group by gate_id for per-gate count enforcement.
    let mut gate_counts: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (idx, manifest) in manifests.iter().enumerate() {
        gate_counts
            .entry(manifest.gate_id.as_str())
            .or_default()
            .push(idx);
    }

    // Age-based pruning.
    for (idx, manifest) in manifests.iter().enumerate() {
        let age_days = current_epoch_days
            .saturating_sub(manifest_epoch_days(manifest).unwrap_or(current_epoch_days));

        // Use the most permissive category age for the manifest.
        let max_age = manifest
            .artifacts
            .iter()
            .map(|a| policy.effective_max_age_days(a.category, manifest.verdict))
            .max()
            .unwrap_or(policy.max_age_days);

        if age_days > max_age {
            debug!(
                run_id = %manifest.run_id,
                age_days,
                max_age,
                "manifest eligible for age-based pruning"
            );
            prune_indices.push(idx);
        }
    }

    // Per-gate count pruning (keep only the newest max_count_per_gate).
    for (gate_id, indices) in &gate_counts {
        if indices.len() > policy.max_count_per_gate as usize {
            let excess = indices.len() - policy.max_count_per_gate as usize;
            for &idx in indices.iter().take(excess) {
                if !prune_indices.contains(&idx) {
                    debug!(
                        gate_id,
                        run_id = %manifests[idx].run_id,
                        "manifest eligible for count-based pruning"
                    );
                    prune_indices.push(idx);
                }
            }
        }
    }

    // Total size pruning (sum all artifact sizes, prune oldest first).
    let total_bytes: u64 = manifests
        .iter()
        .flat_map(|m| m.artifacts.iter())
        .map(|a| a.size_bytes)
        .sum();

    if total_bytes > policy.max_total_bytes {
        let already_selected_bytes: u64 = prune_indices
            .iter()
            .map(|&idx| {
                manifests[idx]
                    .artifacts
                    .iter()
                    .map(|a| a.size_bytes)
                    .sum::<u64>()
            })
            .sum();
        let mut running_total = total_bytes.saturating_sub(already_selected_bytes);
        for (idx, manifest) in manifests.iter().enumerate() {
            if running_total <= policy.max_total_bytes {
                break;
            }
            if !prune_indices.contains(&idx) {
                let manifest_bytes: u64 = manifest.artifacts.iter().map(|a| a.size_bytes).sum();
                running_total = running_total.saturating_sub(manifest_bytes);
                info!(
                    run_id = %manifest.run_id,
                    manifest_bytes,
                    total_bytes,
                    "manifest eligible for size-based pruning"
                );
                prune_indices.push(idx);
            }
        }
    }

    prune_indices.sort_unstable();
    prune_indices.dedup();
    prune_indices
}

/// Extract epoch day from a manifest's created_at timestamp.
///
/// Returns None if the timestamp cannot be parsed.
fn manifest_epoch_days(manifest: &ArtifactManifest) -> Option<u32> {
    parse_manifest_timestamp_epoch_days(&manifest.created_at)
}

fn parse_manifest_timestamp_epoch_days(timestamp: &str) -> Option<u32> {
    let bytes = timestamp.as_bytes();
    if bytes.len() < 20
        || bytes.get(4).copied()? != b'-'
        || bytes.get(7).copied()? != b'-'
        || bytes.get(10).copied()? != b'T'
        || bytes.get(13).copied()? != b':'
        || bytes.get(16).copied()? != b':'
    {
        return None;
    }

    let year = parse_fixed_digits(bytes, 0, 4)?;
    let month = parse_fixed_digits(bytes, 5, 2)?;
    let day = parse_fixed_digits(bytes, 8, 2)?;
    let hour = parse_fixed_digits(bytes, 11, 2)?;
    let minute = parse_fixed_digits(bytes, 14, 2)?;
    let second = parse_fixed_digits(bytes, 17, 2)?;

    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }

    let timezone_start = if bytes.get(19).copied()? == b'.' {
        let mut cursor = 20_usize;
        let first_fractional = bytes.get(cursor)?;
        if !first_fractional.is_ascii_digit() {
            return None;
        }
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor = cursor.checked_add(1)?;
        }
        cursor
    } else {
        19
    };

    let timezone_offset_seconds = parse_timezone_offset_seconds(bytes, timezone_start)?;
    let epoch_day = i64::from(epoch_days_from_date(year, month, day)?);
    let seconds_of_day = i64::from(hour * 3_600 + minute * 60 + second);
    let utc_seconds_of_day = seconds_of_day - i64::from(timezone_offset_seconds);
    let normalized_day = epoch_day.checked_add(utc_seconds_of_day.div_euclid(86_400))?;

    u32::try_from(normalized_day).ok()
}

fn parse_fixed_digits(bytes: &[u8], start: usize, count: usize) -> Option<u32> {
    let end = start.checked_add(count)?;
    let digits = bytes.get(start..end)?;
    let mut value = 0_u32;
    for &byte in digits {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
    }
    Some(value)
}

fn parse_timezone_offset_seconds(bytes: &[u8], start: usize) -> Option<i32> {
    match bytes.get(start).copied() {
        Some(b'Z') if start.checked_add(1) == Some(bytes.len()) => Some(0),
        Some(sign @ (b'+' | b'-')) => {
            if start.checked_add(6) != Some(bytes.len())
                || bytes.get(start + 3).copied() != Some(b':')
            {
                return None;
            }
            let hour = parse_fixed_digits(bytes, start + 1, 2)?;
            let minute = parse_fixed_digits(bytes, start + 4, 2)?;
            if hour > 23 || minute > 59 {
                return None;
            }
            let offset = i32::try_from(hour * 3_600 + minute * 60).ok()?;
            Some(if sign == b'+' { offset } else { -offset })
        }
        _ => None,
    }
}

fn epoch_days_from_date(year: u32, month: u32, day: u32) -> Option<u32> {
    if year == 0 || !(1..=12).contains(&month) {
        return None;
    }

    let days_in_month = days_in_month(year, month)?;
    if day == 0 || day > days_in_month {
        return None;
    }

    let years_before = year.checked_sub(1)?;
    let leap_days_before_year = years_before / 4 - years_before / 100 + years_before / 400;
    let common_days_before_year = years_before.checked_mul(365)?;
    let days_before_year = common_days_before_year.checked_add(leap_days_before_year)?;
    days_before_year.checked_add(day_of_year(year, month, day)? - 1)
}

fn day_of_year(year: u32, month: u32, day: u32) -> Option<u32> {
    const DAYS_BEFORE_MONTH_COMMON: [u32; 12] =
        [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let month_index = usize::try_from(month.checked_sub(1)?).ok()?;
    let mut ordinal = *DAYS_BEFORE_MONTH_COMMON.get(month_index)?;
    if month > 2 && is_leap_year(year) {
        ordinal = ordinal.checked_add(1)?;
    }
    ordinal.checked_add(day)
}

fn days_in_month(year: u32, month: u32) -> Option<u32> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 if is_leap_year(year) => Some(29),
        2 => Some(28),
        _ => None,
    }
}

fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

// ── Redaction policy ─────────────────────────────────────────────────────

/// Fields that should be redacted from artifact manifests before sharing.
pub const REDACTABLE_FIELDS: &[&str] = &[
    "hostname",
    "cpu_model",
    "kernel",
    "username",
    "home_dir",
    "ip_address",
    "mac_address",
    "ssh_key",
    "api_key",
    "token",
    "password",
    "secret",
];

/// Sentinel value used to replace redacted content.
pub const REDACTED_SENTINEL: &str = "[REDACTED]";

/// Redaction policy configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionPolicy {
    /// Fields to redact (matched case-insensitively against metadata keys).
    pub redact_fields: Vec<String>,
    /// Whether to redact hostnames from environment fingerprints.
    pub redact_hostname: bool,
    /// Whether to redact absolute paths (replace with relative).
    pub redact_absolute_paths: bool,
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self {
            redact_fields: REDACTABLE_FIELDS.iter().map(|s| (*s).to_owned()).collect(),
            redact_hostname: true,
            redact_absolute_paths: true,
        }
    }
}

/// Apply redaction to a manifest, returning a new redacted copy.
///
/// The original manifest is not modified. Redacted fields are replaced
/// with `[REDACTED]` and artifact entries are marked as `redacted: true`
/// if any of their metadata was scrubbed.
#[must_use]
pub fn redact_manifest(manifest: &ArtifactManifest, policy: &RedactionPolicy) -> ArtifactManifest {
    let mut redacted = manifest.clone();

    // Redact hostname.
    if policy.redact_hostname {
        REDACTED_SENTINEL.clone_into(&mut redacted.environment.hostname);
    }

    // Redact artifact metadata fields.
    for artifact in &mut redacted.artifacts {
        let mut was_redacted = false;
        for (key, value) in &mut artifact.metadata {
            if policy
                .redact_fields
                .iter()
                .any(|f| key.eq_ignore_ascii_case(f))
            {
                REDACTED_SENTINEL.clone_into(value);
                was_redacted = true;
            }
        }

        // Redact absolute paths.
        if policy.redact_absolute_paths && artifact.path.starts_with('/') {
            if let Some(relative) = artifact.path.strip_prefix('/') {
                artifact.path = relative.to_owned();
            }
            was_redacted = true;
        }

        if was_redacted {
            artifact.redacted = true;
        }
    }

    info!(
        run_id = %redacted.run_id,
        "manifest redacted"
    );

    redacted
}

// ── Manifest validation ──────────────────────────────────────────────────

/// Validation errors for artifact manifests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestValidationError {
    /// Schema version is unsupported.
    UnsupportedVersion(u32),
    /// Run ID is empty.
    EmptyRunId,
    /// Gate ID is empty.
    EmptyGateId,
    /// Created-at timestamp is empty or malformed.
    InvalidTimestamp(String),
    /// Git commit is empty.
    EmptyGitCommit,
    /// Scenario ID does not match the canonical regex.
    InvalidScenarioId(String),
    /// Artifact path is empty.
    EmptyArtifactPath,
    /// Artifact path is absolute or attempts to traverse upward.
    MalformedArtifactPath(String),
    /// Duplicate scenario IDs found.
    DuplicateScenarioId(String),
    /// Scenario map key and embedded scenario ID disagree.
    ScenarioIdMismatch { key: String, value: String },
    /// Verdict is inconsistent with scenario outcomes.
    InconsistentVerdict,
    /// Operational manifest is missing run-level context.
    MissingOperationalContext,
    /// Operational command line is empty.
    EmptyOperationalCommandLine,
    /// Operational host identity is empty.
    EmptyOperationalHost,
    /// Operational FUSE capability was not probed.
    FuseCapabilityNotChecked,
    /// Operational scenario metadata is missing for a scenario.
    MissingOperationalScenario(String),
    /// Operational scenario key and embedded scenario ID disagree.
    OperationalScenarioIdMismatch { key: String, value: String },
    /// Required operational log path is missing.
    MissingOperationalLogPath { scenario_id: String, field: String },
    /// Operational scenario has invalid pass/fail/skip/error semantics.
    InvalidOperationalClassification { scenario_id: String, reason: String },
    /// Operational artifact reference does not point at a manifest artifact.
    UnknownArtifactRef { scenario_id: String, path: String },
    /// Operational cleanup status was not recorded.
    MissingCleanupStatus(String),
}

impl std::fmt::Display for ManifestValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => {
                write!(
                    f,
                    "unsupported schema version: {v} (expected {SCHEMA_VERSION})"
                )
            }
            Self::EmptyRunId => write!(f, "run_id is empty"),
            Self::EmptyGateId => write!(f, "gate_id is empty"),
            Self::InvalidTimestamp(ts) => write!(f, "invalid timestamp: {ts}"),
            Self::EmptyGitCommit => write!(f, "git commit is empty"),
            Self::InvalidScenarioId(id) => write!(f, "invalid scenario_id: {id}"),
            Self::EmptyArtifactPath => write!(f, "artifact path is empty"),
            Self::MalformedArtifactPath(path) => {
                write!(f, "artifact path is malformed or unsafe: {path}")
            }
            Self::DuplicateScenarioId(id) => write!(f, "duplicate scenario_id: {id}"),
            Self::ScenarioIdMismatch { key, value } => {
                write!(
                    f,
                    "scenario map key {key} does not match embedded scenario_id {value}"
                )
            }
            Self::InconsistentVerdict => {
                write!(f, "verdict is PASS but scenarios contain failures")
            }
            Self::MissingOperationalContext => write!(f, "operational context is missing"),
            Self::EmptyOperationalCommandLine => write!(f, "operational command line is empty"),
            Self::EmptyOperationalHost => write!(f, "operational host identity is empty"),
            Self::FuseCapabilityNotChecked => {
                write!(f, "FUSE capability is not checked for operational manifest")
            }
            Self::MissingOperationalScenario(id) => {
                write!(f, "operational scenario metadata missing for {id}")
            }
            Self::OperationalScenarioIdMismatch { key, value } => {
                write!(
                    f,
                    "operational scenario map key {key} does not match embedded scenario_id {value}"
                )
            }
            Self::MissingOperationalLogPath { scenario_id, field } => {
                write!(f, "operational scenario {scenario_id} missing {field}")
            }
            Self::InvalidOperationalClassification {
                scenario_id,
                reason,
            } => {
                write!(
                    f,
                    "operational scenario {scenario_id} has invalid classification: {reason}"
                )
            }
            Self::UnknownArtifactRef { scenario_id, path } => {
                write!(
                    f,
                    "operational scenario {scenario_id} references unknown artifact {path}"
                )
            }
            Self::MissingCleanupStatus(id) => {
                write!(f, "operational scenario {id} missing cleanup status")
            }
        }
    }
}

/// Scenario ID regex pattern (at least 3 underscore-separated lowercase segments).
pub const SCENARIO_ID_PATTERN: &str = r"^[a-z][a-z0-9]*(_[a-z0-9]+){2,}$";

/// Validate an artifact manifest for schema conformance.
///
/// Returns a list of all validation errors found (empty = valid).
#[must_use]
pub fn validate_manifest(manifest: &ArtifactManifest) -> Vec<ManifestValidationError> {
    let mut errors = Vec::new();

    // Version check.
    if manifest.schema_version != SCHEMA_VERSION {
        errors.push(ManifestValidationError::UnsupportedVersion(
            manifest.schema_version,
        ));
    }

    // Required field checks.
    if manifest.run_id.is_empty() {
        errors.push(ManifestValidationError::EmptyRunId);
    }
    if manifest.gate_id.is_empty() {
        errors.push(ManifestValidationError::EmptyGateId);
    }
    if manifest_epoch_days(manifest).is_none() {
        errors.push(ManifestValidationError::InvalidTimestamp(
            manifest.created_at.clone(),
        ));
    }
    if manifest.git_context.commit.is_empty() {
        errors.push(ManifestValidationError::EmptyGitCommit);
    }

    // Scenario ID validation.
    let mut seen_ids = std::collections::HashSet::new();
    for (scenario_id, scenario) in &manifest.scenarios {
        if !is_valid_scenario_id(scenario_id) {
            errors.push(ManifestValidationError::InvalidScenarioId(
                scenario_id.clone(),
            ));
        }
        if !seen_ids.insert(scenario_id.as_str()) {
            errors.push(ManifestValidationError::DuplicateScenarioId(
                scenario_id.clone(),
            ));
        }
        if scenario.scenario_id != *scenario_id {
            if !is_valid_scenario_id(&scenario.scenario_id) {
                errors.push(ManifestValidationError::InvalidScenarioId(
                    scenario.scenario_id.clone(),
                ));
            }
            errors.push(ManifestValidationError::ScenarioIdMismatch {
                key: scenario_id.clone(),
                value: scenario.scenario_id.clone(),
            });
        }
    }

    // Artifact path validation.
    for artifact in &manifest.artifacts {
        if artifact.path.is_empty() {
            errors.push(ManifestValidationError::EmptyArtifactPath);
        } else if !is_safe_relative_artifact_path(&artifact.path) {
            errors.push(ManifestValidationError::MalformedArtifactPath(
                artifact.path.clone(),
            ));
        }
    }

    // Verdict consistency.
    let has_failures = manifest
        .scenarios
        .values()
        .any(|s| s.outcome == ScenarioResult::Fail);
    if manifest.verdict == GateVerdict::Pass && has_failures {
        errors.push(ManifestValidationError::InconsistentVerdict);
    }

    if errors.is_empty() {
        debug!(run_id = %manifest.run_id, "manifest validation passed");
    } else {
        warn!(
            run_id = %manifest.run_id,
            error_count = errors.len(),
            "manifest validation failed"
        );
    }

    errors
}

/// Validate the stricter operational schema required for E2E, xfstests, fuzz
/// smoke, performance, writeback-cache crash, and repair-readiness artifacts.
///
/// This deliberately builds on [`validate_manifest`] instead of replacing it:
/// generic historical manifests can stay lightweight, while readiness-grade
/// artifacts must carry enough context for a user to reproduce and understand a
/// pass, fail, skip, or error without reading agent transcripts.
#[must_use]
pub fn validate_operational_manifest(manifest: &ArtifactManifest) -> Vec<ManifestValidationError> {
    let mut errors = validate_manifest(manifest);

    let Some(context) = &manifest.operational_context else {
        errors.push(ManifestValidationError::MissingOperationalContext);
        return errors;
    };

    validate_operational_context(&mut errors, context);
    validate_operational_scenarios(&mut errors, manifest);

    errors
}

fn validate_operational_context(
    errors: &mut Vec<ManifestValidationError>,
    context: &OperationalRunContext,
) {
    if context.command_line.is_empty()
        || context
            .command_line
            .iter()
            .all(|part| part.trim().is_empty())
    {
        errors.push(ManifestValidationError::EmptyOperationalCommandLine);
    }
    if context.worker.host.trim().is_empty() {
        errors.push(ManifestValidationError::EmptyOperationalHost);
    }
    if context.fuse_capability == FuseCapabilityResult::NotChecked {
        errors.push(ManifestValidationError::FuseCapabilityNotChecked);
    }
    validate_required_run_log_path(errors, "run", "stdout_path", &context.stdout_path);
    validate_required_run_log_path(errors, "run", "stderr_path", &context.stderr_path);
    validate_safe_run_log_path(errors, &context.stdout_path);
    validate_safe_run_log_path(errors, &context.stderr_path);
}

fn validate_operational_scenarios(
    errors: &mut Vec<ManifestValidationError>,
    manifest: &ArtifactManifest,
) {
    let artifact_paths: std::collections::BTreeSet<&str> = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .collect();

    for (scenario_id, scenario) in &manifest.scenarios {
        let Some(operational) = manifest.operational_scenarios.get(scenario_id) else {
            errors.push(ManifestValidationError::MissingOperationalScenario(
                scenario_id.clone(),
            ));
            continue;
        };

        if operational.scenario_id != *scenario_id {
            errors.push(ManifestValidationError::OperationalScenarioIdMismatch {
                key: scenario_id.clone(),
                value: operational.scenario_id.clone(),
            });
        }

        if operational.actual_outcome != scenario.outcome {
            errors.push(ManifestValidationError::InvalidOperationalClassification {
                scenario_id: scenario_id.clone(),
                reason: format!(
                    "actual_outcome {:?} disagrees with scenario outcome {:?}",
                    operational.actual_outcome, scenario.outcome
                ),
            });
        }

        validate_required_scenario_log_path(
            errors,
            scenario_id,
            "stdout_path",
            &operational.stdout_path,
        );
        validate_required_scenario_log_path(
            errors,
            scenario_id,
            "stderr_path",
            &operational.stderr_path,
        );

        if operational.cleanup_status == CleanupStatus::NotRun {
            errors.push(ManifestValidationError::MissingCleanupStatus(
                scenario_id.clone(),
            ));
        }

        validate_operational_classification(errors, scenario_id, operational);

        if operational.artifact_refs.is_empty() {
            errors.push(ManifestValidationError::InvalidOperationalClassification {
                scenario_id: scenario_id.clone(),
                reason: "artifact_refs must contain at least one path".to_owned(),
            });
        }

        for path in operational
            .artifact_refs
            .iter()
            .chain(operational.ledger_paths.iter())
            .chain([&operational.stdout_path, &operational.stderr_path])
        {
            if !is_safe_relative_artifact_path(path) {
                errors.push(ManifestValidationError::MalformedArtifactPath(path.clone()));
            }
        }

        for artifact_ref in &operational.artifact_refs {
            if !artifact_paths.contains(artifact_ref.as_str()) {
                errors.push(ManifestValidationError::UnknownArtifactRef {
                    scenario_id: scenario_id.clone(),
                    path: artifact_ref.clone(),
                });
            }
        }
    }

    for scenario_id in manifest.operational_scenarios.keys() {
        if !manifest.scenarios.contains_key(scenario_id) {
            errors.push(ManifestValidationError::MissingOperationalScenario(
                scenario_id.clone(),
            ));
        }
    }
}

fn validate_required_run_log_path(
    errors: &mut Vec<ManifestValidationError>,
    scenario_id: &str,
    field: &str,
    value: &str,
) {
    if value.is_empty() {
        errors.push(ManifestValidationError::MissingOperationalLogPath {
            scenario_id: scenario_id.to_owned(),
            field: field.to_owned(),
        });
    }
}

fn validate_safe_run_log_path(errors: &mut Vec<ManifestValidationError>, value: &str) {
    if !value.is_empty() && !is_safe_relative_artifact_path(value) {
        errors.push(ManifestValidationError::MalformedArtifactPath(
            value.to_owned(),
        ));
    }
}

fn validate_required_scenario_log_path(
    errors: &mut Vec<ManifestValidationError>,
    scenario_id: &str,
    field: &str,
    value: &str,
) {
    if value.is_empty() {
        errors.push(ManifestValidationError::MissingOperationalLogPath {
            scenario_id: scenario_id.to_owned(),
            field: field.to_owned(),
        });
    }
}

fn validate_operational_classification(
    errors: &mut Vec<ManifestValidationError>,
    scenario_id: &str,
    operational: &OperationalScenarioRecord,
) {
    let expected_class = match operational.actual_outcome {
        ScenarioResult::Pass => OperationalOutcomeClass::Pass,
        ScenarioResult::Fail => OperationalOutcomeClass::Fail,
        ScenarioResult::Skip => OperationalOutcomeClass::Skip,
    };

    if operational.classification != OperationalOutcomeClass::Error
        && operational.classification != expected_class
    {
        errors.push(ManifestValidationError::InvalidOperationalClassification {
            scenario_id: scenario_id.to_owned(),
            reason: format!(
                "classification {:?} disagrees with actual outcome {:?}",
                operational.classification, operational.actual_outcome
            ),
        });
    }

    match operational.classification {
        OperationalOutcomeClass::Pass => {
            if operational.error_class.is_some() || operational.skip_reason.is_some() {
                errors.push(ManifestValidationError::InvalidOperationalClassification {
                    scenario_id: scenario_id.to_owned(),
                    reason: "passing scenarios cannot carry error_class or skip_reason".to_owned(),
                });
            }
        }
        OperationalOutcomeClass::Fail | OperationalOutcomeClass::Error => {
            if operational.classification == OperationalOutcomeClass::Error
                && operational.actual_outcome != ScenarioResult::Fail
            {
                errors.push(ManifestValidationError::InvalidOperationalClassification {
                    scenario_id: scenario_id.to_owned(),
                    reason: "error scenarios must use FAIL actual_outcome".to_owned(),
                });
            }
            if operational.error_class.is_none() {
                errors.push(ManifestValidationError::InvalidOperationalClassification {
                    scenario_id: scenario_id.to_owned(),
                    reason: "fail/error scenarios require error_class".to_owned(),
                });
            }
            if operational
                .remediation_hint
                .as_deref()
                .is_none_or(str::is_empty)
            {
                errors.push(ManifestValidationError::InvalidOperationalClassification {
                    scenario_id: scenario_id.to_owned(),
                    reason: "fail/error scenarios require remediation_hint".to_owned(),
                });
            }
        }
        OperationalOutcomeClass::Skip => {
            if operational.skip_reason.is_none() {
                errors.push(ManifestValidationError::InvalidOperationalClassification {
                    scenario_id: scenario_id.to_owned(),
                    reason: "skip scenarios require skip_reason".to_owned(),
                });
            }
            if operational
                .remediation_hint
                .as_deref()
                .is_none_or(str::is_empty)
                && !matches!(operational.skip_reason, Some(SkipReason::NotApplicable))
            {
                errors.push(ManifestValidationError::InvalidOperationalClassification {
                    scenario_id: scenario_id.to_owned(),
                    reason: "actionable skip scenarios require remediation_hint".to_owned(),
                });
            }
        }
    }
}

fn is_safe_relative_artifact_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path
            .split('/')
            .any(|component| matches!(component, "" | "." | ".."))
}

/// Check if a scenario ID matches the canonical pattern.
#[must_use]
pub fn is_valid_scenario_id(id: &str) -> bool {
    crate::log_contract::e2e_marker::is_valid_scenario_id(id)
}

// ── Builder convenience ──────────────────────────────────────────────────

/// Builder for constructing artifact manifests incrementally.
pub struct ManifestBuilder {
    manifest: ArtifactManifest,
}

impl ManifestBuilder {
    /// Create a new builder with required fields.
    #[must_use]
    pub fn new(run_id: &str, gate_id: &str, created_at: &str) -> Self {
        Self {
            manifest: ArtifactManifest {
                schema_version: SCHEMA_VERSION,
                run_id: run_id.to_owned(),
                created_at: created_at.to_owned(),
                gate_id: gate_id.to_owned(),
                bead_id: None,
                git_context: GitContext {
                    commit: String::new(),
                    branch: String::new(),
                    clean: true,
                },
                environment: EnvironmentFingerprint {
                    hostname: String::new(),
                    cpu_model: String::new(),
                    cpu_count: 0,
                    memory_gib: 0,
                    kernel: String::new(),
                    rustc_version: String::new(),
                    cargo_version: None,
                },
                scenarios: BTreeMap::new(),
                operational_context: None,
                operational_scenarios: BTreeMap::new(),
                artifacts: Vec::new(),
                verdict: GateVerdict::Pass,
                duration_secs: 0.0,
                retention: None,
            },
        }
    }

    /// Set the bead ID.
    #[must_use]
    pub fn bead_id(mut self, bead_id: &str) -> Self {
        self.manifest.bead_id = Some(bead_id.to_owned());
        self
    }

    /// Set the git context.
    #[must_use]
    pub fn git_context(mut self, commit: &str, branch: &str, clean: bool) -> Self {
        self.manifest.git_context = GitContext {
            commit: commit.to_owned(),
            branch: branch.to_owned(),
            clean,
        };
        self
    }

    /// Set the environment fingerprint.
    #[must_use]
    pub fn environment(mut self, env: EnvironmentFingerprint) -> Self {
        self.manifest.environment = env;
        self
    }

    /// Add a scenario outcome.
    #[must_use]
    pub fn scenario(
        mut self,
        scenario_id: &str,
        outcome: ScenarioResult,
        detail: Option<&str>,
        duration_secs: f64,
    ) -> Self {
        self.manifest.scenarios.insert(
            scenario_id.to_owned(),
            ScenarioOutcome {
                scenario_id: scenario_id.to_owned(),
                outcome,
                detail: detail.map(str::to_owned),
                duration_secs,
            },
        );
        self
    }

    /// Set run-level operational context.
    #[must_use]
    pub fn operational_context(mut self, context: OperationalRunContext) -> Self {
        self.manifest.operational_context = Some(context);
        self
    }

    /// Add per-scenario operational metadata.
    #[must_use]
    pub fn operational_scenario(mut self, record: OperationalScenarioRecord) -> Self {
        self.manifest
            .operational_scenarios
            .insert(record.scenario_id.clone(), record);
        self
    }

    /// Add an artifact entry.
    #[must_use]
    pub fn artifact(mut self, entry: ArtifactEntry) -> Self {
        self.manifest.artifacts.push(entry);
        self
    }

    /// Set the gate verdict.
    #[must_use]
    pub fn verdict(mut self, verdict: GateVerdict) -> Self {
        self.manifest.verdict = verdict;
        self
    }

    /// Set the total duration.
    #[must_use]
    pub fn duration_secs(mut self, secs: f64) -> Self {
        self.manifest.duration_secs = secs;
        self
    }

    /// Build the manifest, automatically computing verdict from scenarios
    /// if not explicitly set.
    #[must_use]
    pub fn build(mut self) -> ArtifactManifest {
        // Auto-compute verdict if any scenario failed.
        let has_failure = self
            .manifest
            .scenarios
            .values()
            .any(|s| s.outcome == ScenarioResult::Fail);
        if has_failure {
            self.manifest.verdict = GateVerdict::Fail;
        }
        self.manifest
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> ArtifactManifest {
        ManifestBuilder::new("run-001", "ffs_smoke", "2026-03-04T12:00:00Z")
            .git_context("abc123", "main", true)
            .environment(EnvironmentFingerprint {
                hostname: "build-host-01".to_owned(),
                cpu_model: "AMD Ryzen 9 5950X".to_owned(),
                cpu_count: 32,
                memory_gib: 64,
                kernel: "Linux 6.17.0".to_owned(),
                rustc_version: "1.85.0".to_owned(),
                cargo_version: Some("1.85.0".to_owned()),
            })
            .scenario(
                "cli_mount_runtime_help_contract",
                ScenarioResult::Pass,
                None,
                1.5,
            )
            .scenario(
                "cli_mount_runtime_invalid_standard_timeout",
                ScenarioResult::Pass,
                None,
                0.8,
            )
            .artifact(ArtifactEntry {
                path: "artifacts/e2e/20260304_ffs_smoke/run.log".to_owned(),
                category: ArtifactCategory::E2eLog,
                content_type: Some("text/plain".to_owned()),
                size_bytes: 4096,
                sha256: Some("abcdef1234567890".to_owned()),
                redacted: false,
                metadata: BTreeMap::new(),
            })
            .duration_secs(2.3)
            .build()
    }

    // ── Schema version ───────────────────────────────────────────────

    #[test]
    fn schema_version_is_set() {
        let manifest = sample_manifest();
        assert_eq!(manifest.schema_version, SCHEMA_VERSION);
    }

    // ── Validation tests ─────────────────────────────────────────────

    #[test]
    fn valid_manifest_passes_validation() {
        let manifest = sample_manifest();
        let errors = validate_manifest(&manifest);
        assert!(errors.is_empty(), "expected no errors, got: {errors:?}");
    }

    #[test]
    fn empty_run_id_fails_validation() {
        let mut manifest = sample_manifest();
        manifest.run_id = String::new();
        let errors = validate_manifest(&manifest);
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ManifestValidationError::EmptyRunId))
        );
    }

    #[test]
    fn empty_gate_id_fails_validation() {
        let mut manifest = sample_manifest();
        manifest.gate_id = String::new();
        let errors = validate_manifest(&manifest);
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ManifestValidationError::EmptyGateId))
        );
    }

    #[test]
    fn empty_git_commit_fails_validation() {
        let mut manifest = sample_manifest();
        manifest.git_context.commit = String::new();
        let errors = validate_manifest(&manifest);
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ManifestValidationError::EmptyGitCommit))
        );
    }

    #[test]
    fn invalid_timestamp_fails_validation() {
        for timestamp in [
            "bad",
            "2026-03-04",
            "2026-03-04 12:00:00Z",
            "2026-13-04T12:00:00Z",
            "2026-00-04T12:00:00Z",
            "2026-02-29T12:00:00Z",
            "2026-04-31T12:00:00Z",
            "2026-03-04T24:00:00Z",
            "2026-03-04T12:60:00Z",
            "2026-03-04T12:00:60Z",
            "2026-03-04T12:00:00",
            "2026-03-04T12:00:00+24:00",
            "2026-03-04T12:00:00+00:60",
            "2026-03-04T12:00:00.",
        ] {
            let mut manifest = sample_manifest();
            manifest.created_at = timestamp.to_owned();
            let errors = validate_manifest(&manifest);
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, ManifestValidationError::InvalidTimestamp(_))),
                "{timestamp} should fail timestamp validation"
            );
        }
    }

    #[test]
    fn valid_timestamp_forms_pass_validation() {
        for timestamp in [
            "2026-03-04T12:00:00Z",
            "2026-03-04T12:00:00.123Z",
            "2026-03-04T12:00:00+00:00",
            "2026-03-04T12:00:00.123+00:00",
            "2026-03-04T12:00:00-05:00",
            "2024-02-29T23:59:59Z",
        ] {
            let mut manifest = sample_manifest();
            manifest.created_at = timestamp.to_owned();
            let errors = validate_manifest(&manifest);
            assert!(
                !errors
                    .iter()
                    .any(|e| matches!(e, ManifestValidationError::InvalidTimestamp(_))),
                "{timestamp} should pass timestamp validation"
            );
        }
    }

    #[test]
    fn timestamp_offsets_normalize_retention_day() {
        assert_eq!(
            parse_manifest_timestamp_epoch_days("2026-03-04T00:30:00+02:00"),
            parse_manifest_timestamp_epoch_days("2026-03-03T22:30:00Z")
        );
        assert_eq!(
            parse_manifest_timestamp_epoch_days("2026-03-04T23:30:00-02:00"),
            parse_manifest_timestamp_epoch_days("2026-03-05T01:30:00Z")
        );
        assert_eq!(
            parse_manifest_timestamp_epoch_days("0001-01-01T00:00:00+00:01"),
            None
        );
    }

    #[test]
    fn unsupported_version_fails_validation() {
        let mut manifest = sample_manifest();
        manifest.schema_version = 999;
        let errors = validate_manifest(&manifest);
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ManifestValidationError::UnsupportedVersion(999)))
        );
    }

    #[test]
    fn invalid_scenario_id_detected() {
        let mut manifest = sample_manifest();
        manifest.scenarios.insert(
            "bad-id".to_owned(),
            ScenarioOutcome {
                scenario_id: "bad-id".to_owned(),
                outcome: ScenarioResult::Pass,
                detail: None,
                duration_secs: 0.0,
            },
        );
        let errors = validate_manifest(&manifest);
        assert!(errors.iter().any(
            |e| matches!(e, ManifestValidationError::InvalidScenarioId(id) if id == "bad-id")
        ));
    }

    #[test]
    fn embedded_invalid_scenario_id_detected() {
        let mut manifest = sample_manifest();
        manifest.scenarios.insert(
            "cli_mount_runtime_help_contract".to_owned(),
            ScenarioOutcome {
                scenario_id: "BAD".to_owned(),
                outcome: ScenarioResult::Pass,
                detail: None,
                duration_secs: 1.5,
            },
        );

        let errors = validate_manifest(&manifest);
        assert!(
            errors.iter().any(
                |e| matches!(e, ManifestValidationError::InvalidScenarioId(id) if id == "BAD")
            )
        );
        assert!(errors.iter().any(|e| matches!(
            e,
            ManifestValidationError::ScenarioIdMismatch { key, value }
                if key == "cli_mount_runtime_help_contract" && value == "BAD"
        )));
    }

    #[test]
    fn embedded_scenario_id_mismatch_detected() {
        let mut manifest = sample_manifest();
        manifest.scenarios.insert(
            "cli_mount_runtime_help_contract".to_owned(),
            ScenarioOutcome {
                scenario_id: "cli_mount_runtime_other_contract".to_owned(),
                outcome: ScenarioResult::Pass,
                detail: None,
                duration_secs: 1.5,
            },
        );

        let errors = validate_manifest(&manifest);
        assert!(errors.iter().any(|e| matches!(
            e,
            ManifestValidationError::ScenarioIdMismatch { key, value }
                if key == "cli_mount_runtime_help_contract"
                    && value == "cli_mount_runtime_other_contract"
        )));
    }

    #[test]
    fn inconsistent_verdict_detected() {
        let mut manifest = sample_manifest();
        manifest.scenarios.insert(
            "test_failure_scenario_detected".to_owned(),
            ScenarioOutcome {
                scenario_id: "test_failure_scenario_detected".to_owned(),
                outcome: ScenarioResult::Fail,
                detail: Some("test failure".to_owned()),
                duration_secs: 0.1,
            },
        );
        manifest.verdict = GateVerdict::Pass; // Inconsistent!
        let errors = validate_manifest(&manifest);
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ManifestValidationError::InconsistentVerdict))
        );
    }

    #[test]
    fn empty_artifact_path_detected() {
        let mut manifest = sample_manifest();
        manifest.artifacts.push(ArtifactEntry {
            path: String::new(),
            category: ArtifactCategory::RawLog,
            content_type: None,
            size_bytes: 0,
            sha256: None,
            redacted: false,
            metadata: BTreeMap::new(),
        });
        let errors = validate_manifest(&manifest);
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ManifestValidationError::EmptyArtifactPath))
        );
    }

    // ── Scenario ID validation ───────────────────────────────────────

    #[test]
    fn valid_scenario_ids() {
        assert!(is_valid_scenario_id("cli_mount_runtime_help_contract"));
        assert!(is_valid_scenario_id("taxonomy_builds_clean"));
        assert!(is_valid_scenario_id("btrfs_rw_crash_matrix_01_prealloc"));
        assert!(is_valid_scenario_id("a1_b2_c3"));
    }

    #[test]
    fn invalid_scenario_ids() {
        assert!(!is_valid_scenario_id("")); // empty
        assert!(!is_valid_scenario_id("two_segments")); // only 2 segments
        assert!(!is_valid_scenario_id("Upper_Case_Bad")); // uppercase
        assert!(!is_valid_scenario_id("has-hyphen_bad_id")); // hyphen
        assert!(!is_valid_scenario_id("_leading_underscore_bad")); // leading underscore
        assert!(!is_valid_scenario_id("1starts_with_digit_bad")); // starts with digit
    }

    // ── JSON round-trip ──────────────────────────────────────────────

    #[test]
    fn manifest_json_round_trip() {
        let manifest = sample_manifest();
        let json = serde_json::to_string_pretty(&manifest).expect("serialize");
        let parsed: ArtifactManifest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.run_id, manifest.run_id);
        assert_eq!(parsed.gate_id, manifest.gate_id);
        assert_eq!(parsed.scenarios.len(), manifest.scenarios.len());
        assert_eq!(parsed.artifacts.len(), manifest.artifacts.len());
        assert_eq!(parsed.verdict, manifest.verdict);
    }

    #[test]
    fn artifact_category_json_round_trip() {
        for &cat in ArtifactCategory::ALL {
            let json = serde_json::to_string(&cat).expect("serialize");
            let parsed: ArtifactCategory = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(parsed, cat);
        }
    }

    #[test]
    fn scenario_result_json_round_trip() {
        for result in [
            ScenarioResult::Pass,
            ScenarioResult::Fail,
            ScenarioResult::Skip,
        ] {
            let json = serde_json::to_string(&result).expect("serialize");
            let parsed: ScenarioResult = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(parsed, result);
        }
    }

    #[test]
    fn scenario_id_pattern_matches_shared_catalog_contract() {
        let catalog: serde_json::Value =
            serde_json::from_str(include_str!("../../../scripts/e2e/scenario_catalog.json"))
                .expect("scenario catalog json should parse");
        let catalog_pattern = catalog
            .get("scenario_id_regex")
            .and_then(serde_json::Value::as_str)
            .expect("scenario catalog should define scenario_id_regex");
        assert_eq!(SCENARIO_ID_PATTERN, catalog_pattern);
    }

    // ── Retention policy tests ───────────────────────────────────────

    #[test]
    fn default_retention_policy_values() {
        let policy = RetentionPolicy::default();
        assert_eq!(policy.max_age_days, DEFAULT_MAX_AGE_DAYS);
        assert_eq!(policy.max_count_per_gate, DEFAULT_MAX_COUNT);
        assert_eq!(policy.max_total_bytes, DEFAULT_MAX_TOTAL_BYTES);
        assert!(policy.preserve_failures);
    }

    #[test]
    fn retention_preserves_failures_longer() {
        let policy = RetentionPolicy {
            max_age_days: 30,
            preserve_failures: true,
            ..RetentionPolicy::default()
        };
        let pass_age = policy.effective_max_age_days(ArtifactCategory::E2eLog, GateVerdict::Pass);
        let fail_age = policy.effective_max_age_days(ArtifactCategory::E2eLog, GateVerdict::Fail);
        assert_eq!(pass_age, 30);
        assert_eq!(fail_age, 60);
    }

    #[test]
    fn retention_category_override() {
        let mut policy = RetentionPolicy::default();
        policy
            .category_overrides
            .insert(ArtifactCategory::FuzzCrash, 365);
        let age = policy.effective_max_age_days(ArtifactCategory::FuzzCrash, GateVerdict::Pass);
        assert_eq!(age, 365);
    }

    #[test]
    fn evaluate_retention_age_based() {
        let manifests = vec![
            make_manifest("run-old", "gate_a", "2025-01-01T00:00:00Z"),
            make_manifest("run-new", "gate_a", "2026-03-01T00:00:00Z"),
        ];
        let policy = RetentionPolicy {
            max_age_days: 30,
            ..RetentionPolicy::default()
        };
        let current_days = parse_manifest_timestamp_epoch_days("2026-03-04T00:00:00Z").unwrap_or(0);
        let prune = evaluate_retention(&manifests, &policy, current_days);
        assert!(prune.contains(&0), "old manifest should be pruned");
        assert!(!prune.contains(&1), "new manifest should be kept");
    }

    #[test]
    fn evaluate_retention_count_based() {
        let policy = RetentionPolicy {
            max_count_per_gate: 2,
            max_age_days: 9999, // disable age pruning
            ..RetentionPolicy::default()
        };
        let manifests = vec![
            make_manifest("run-1", "gate_a", "2026-03-01T00:00:00Z"),
            make_manifest("run-2", "gate_a", "2026-03-02T00:00:00Z"),
            make_manifest("run-3", "gate_a", "2026-03-03T00:00:00Z"),
        ];
        let current_days = parse_manifest_timestamp_epoch_days("2026-03-04T00:00:00Z").unwrap_or(0);
        let prune = evaluate_retention(&manifests, &policy, current_days);
        assert!(
            prune.contains(&0),
            "oldest manifest should be pruned for count"
        );
        assert_eq!(prune.len(), 1);
    }

    #[test]
    fn evaluate_retention_size_budget_counts_already_selected_manifests() {
        let mut old_large = make_manifest("run-old-large", "gate_a", "2025-01-01T00:00:00Z");
        old_large.artifacts[0].size_bytes = 900;
        let mut new_a = make_manifest("run-new-a", "gate_a", "2026-03-02T00:00:00Z");
        new_a.artifacts[0].size_bytes = 200;
        let mut new_b = make_manifest("run-new-b", "gate_a", "2026-03-03T00:00:00Z");
        new_b.artifacts[0].size_bytes = 200;

        let policy = RetentionPolicy {
            max_age_days: 30,
            max_total_bytes: 500,
            max_count_per_gate: 99,
            ..RetentionPolicy::default()
        };

        let current_days = parse_manifest_timestamp_epoch_days("2026-03-04T00:00:00Z").unwrap_or(0);
        let prune = evaluate_retention(&[old_large, new_a, new_b], &policy, current_days);

        assert_eq!(
            prune,
            vec![0],
            "old selected manifest already brings total bytes below the size budget",
        );
    }

    #[test]
    fn evaluate_retention_empty_list() {
        let policy = RetentionPolicy::default();
        let prune = evaluate_retention(&[], &policy, 0);
        assert!(prune.is_empty());
    }

    // ── Redaction tests ──────────────────────────────────────────────

    #[test]
    fn redaction_replaces_hostname() {
        let manifest = sample_manifest();
        let policy = RedactionPolicy::default();
        let redacted = redact_manifest(&manifest, &policy);
        assert_eq!(redacted.environment.hostname, REDACTED_SENTINEL);
    }

    #[test]
    fn redaction_strips_absolute_paths() {
        let mut manifest = sample_manifest();
        manifest.artifacts.push(ArtifactEntry {
            path: "/home/user/artifacts/test.log".to_owned(),
            category: ArtifactCategory::RawLog,
            content_type: None,
            size_bytes: 100,
            sha256: None,
            redacted: false,
            metadata: BTreeMap::new(),
        });
        let policy = RedactionPolicy::default();
        let redacted = redact_manifest(&manifest, &policy);
        let abs_artifact = &redacted.artifacts[1];
        assert!(!abs_artifact.path.starts_with('/'));
        assert!(abs_artifact.redacted);
    }

    #[test]
    fn redaction_scrubs_sensitive_metadata() {
        let mut manifest = sample_manifest();
        let mut meta = BTreeMap::new();
        meta.insert("hostname".to_owned(), "secret-host".to_owned());
        meta.insert("safe_field".to_owned(), "keep me".to_owned());
        manifest.artifacts[0].metadata = meta;

        let policy = RedactionPolicy::default();
        let redacted = redact_manifest(&manifest, &policy);
        assert_eq!(
            redacted.artifacts[0].metadata["hostname"],
            REDACTED_SENTINEL,
        );
        assert_eq!(redacted.artifacts[0].metadata["safe_field"], "keep me");
    }

    #[test]
    fn redaction_preserves_non_sensitive_data() {
        let manifest = sample_manifest();
        let policy = RedactionPolicy {
            redact_hostname: false,
            redact_absolute_paths: false,
            redact_fields: vec![],
        };
        let redacted = redact_manifest(&manifest, &policy);
        assert_eq!(redacted.environment.hostname, manifest.environment.hostname,);
    }

    // ── Builder tests ────────────────────────────────────────────────

    #[test]
    fn builder_auto_computes_fail_verdict() {
        let manifest = ManifestBuilder::new("run-x", "gate_x", "2026-03-04T00:00:00Z")
            .git_context("abc", "main", true)
            .scenario("test_pass_scenario_good", ScenarioResult::Pass, None, 1.0)
            .scenario(
                "test_fail_scenario_bad",
                ScenarioResult::Fail,
                Some("oops"),
                0.5,
            )
            .build();
        assert_eq!(manifest.verdict, GateVerdict::Fail);
    }

    #[test]
    fn builder_keeps_pass_when_all_pass() {
        let manifest = ManifestBuilder::new("run-x", "gate_x", "2026-03-04T00:00:00Z")
            .git_context("abc", "main", true)
            .scenario("test_pass_scenario_a", ScenarioResult::Pass, None, 1.0)
            .scenario("test_pass_scenario_b", ScenarioResult::Pass, None, 2.0)
            .build();
        assert_eq!(manifest.verdict, GateVerdict::Pass);
    }

    #[test]
    fn builder_sets_bead_id() {
        let manifest = ManifestBuilder::new("run-x", "gate_x", "2026-03-04T00:00:00Z")
            .bead_id("bd-h6nz.9.3")
            .git_context("abc", "main", true)
            .build();
        assert_eq!(manifest.bead_id, Some("bd-h6nz.9.3".to_owned()));
    }

    // ── Category tests ───────────────────────────────────────────────

    #[test]
    fn all_categories_have_labels() {
        for &cat in ArtifactCategory::ALL {
            assert!(!cat.label().is_empty(), "{cat:?} has empty label");
        }
    }

    #[test]
    fn artifact_category_all_is_exhaustive() {
        // Ensure ALL contains every variant.
        assert_eq!(ArtifactCategory::ALL.len(), 9);
    }

    #[test]
    fn all_artifact_categories_can_be_represented_in_one_manifest() {
        let manifest = ArtifactCategory::ALL
            .iter()
            .enumerate()
            .fold(
                ManifestBuilder::new("run-categories", "bd-h6nz.9", "2026-03-10T00:00:00Z")
                    .bead_id("bd-h6nz.9.3")
                    .git_context("abc123", "main", true)
                    .environment(EnvironmentFingerprint {
                        hostname: "build-host-01".to_owned(),
                        cpu_model: "AMD Ryzen 9 5950X".to_owned(),
                        cpu_count: 32,
                        memory_gib: 64,
                        kernel: "Linux 6.17.0".to_owned(),
                        rustc_version: "1.85.0".to_owned(),
                        cargo_version: Some("1.85.0".to_owned()),
                    })
                    .scenario(
                        "verification_artifact_manifest_schema",
                        ScenarioResult::Pass,
                        None,
                        0.5,
                    ),
                |builder, (idx, &category)| {
                    builder.artifact(ArtifactEntry {
                        path: format!("artifacts/e2e/run/artifact_{idx}.json"),
                        category,
                        content_type: Some("application/json".to_owned()),
                        size_bytes: 1024 + idx as u64,
                        sha256: Some(format!("artifact-checksum-{idx:02}")),
                        redacted: false,
                        metadata: BTreeMap::from([
                            ("category".to_owned(), category.label().to_owned()),
                            (
                                "scenario_id".to_owned(),
                                "verification_artifact_manifest_schema".to_owned(),
                            ),
                        ]),
                    })
                },
            )
            .duration_secs(1.0)
            .build();

        let errors = validate_manifest(&manifest);
        assert!(
            errors.is_empty(),
            "expected every artifact category to remain representable, got: {errors:?}"
        );
        assert_eq!(manifest.artifacts.len(), ArtifactCategory::ALL.len());
    }

    // ── Operational readiness schema tests ──────────────────────────

    #[test]
    fn operational_manifest_with_required_sample_surfaces_passes_validation() {
        let manifest = sample_operational_manifest();
        let errors = validate_operational_manifest(&manifest);
        assert!(
            errors.is_empty(),
            "expected operational manifest to validate, got: {errors:?}"
        );
    }

    #[test]
    fn operational_manifest_requires_context() {
        let manifest = sample_manifest();
        let errors = validate_operational_manifest(&manifest);
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ManifestValidationError::MissingOperationalContext))
        );
    }

    #[test]
    fn operational_manifest_rejects_missing_log_paths() {
        let mut manifest = sample_operational_manifest();
        manifest
            .operational_scenarios
            .get_mut("mounted_ext4_rw")
            .expect("scenario exists")
            .stdout_path = String::new();

        let errors = validate_operational_manifest(&manifest);
        assert!(errors.iter().any(|e| matches!(
            e,
            ManifestValidationError::MissingOperationalLogPath { scenario_id, field }
                if scenario_id == "mounted_ext4_rw" && field == "stdout_path"
        )));
    }

    #[test]
    fn operational_manifest_rejects_unsafe_run_log_paths() {
        let mut manifest = sample_operational_manifest();
        manifest
            .operational_context
            .as_mut()
            .expect("context exists")
            .stderr_path = "/tmp/frankenfs/stderr.log".to_owned();

        let errors = validate_operational_manifest(&manifest);
        assert!(errors.iter().any(|e| matches!(
            e,
            ManifestValidationError::MalformedArtifactPath(path)
                if path == "/tmp/frankenfs/stderr.log"
        )));
    }

    #[test]
    fn operational_manifest_rejects_whitespace_run_identity() {
        let mut manifest = sample_operational_manifest();
        let context = manifest
            .operational_context
            .as_mut()
            .expect("context exists");
        context.command_line = vec!["  ".to_owned(), "\t".to_owned()];
        context.worker.host = "  ".to_owned();

        let errors = validate_operational_manifest(&manifest);
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ManifestValidationError::EmptyOperationalCommandLine))
        );
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ManifestValidationError::EmptyOperationalHost))
        );
    }

    #[test]
    fn operational_manifest_rejects_actual_outcome_drift() {
        let mut manifest = sample_operational_manifest();
        manifest
            .operational_scenarios
            .get_mut("mounted_ext4_rw")
            .expect("scenario exists")
            .actual_outcome = ScenarioResult::Fail;

        let errors = validate_operational_manifest(&manifest);
        assert!(errors.iter().any(|e| matches!(
            e,
            ManifestValidationError::InvalidOperationalClassification { scenario_id, reason }
                if scenario_id == "mounted_ext4_rw"
                    && reason.contains("actual_outcome")
        )));
    }

    #[test]
    fn operational_manifest_rejects_ambiguous_skip_reason() {
        let mut manifest = sample_operational_manifest();
        let record = manifest
            .operational_scenarios
            .get_mut("fuse_capability_probe")
            .expect("scenario exists");
        record.skip_reason = None;

        let errors = validate_operational_manifest(&manifest);
        assert!(errors.iter().any(|e| matches!(
            e,
            ManifestValidationError::InvalidOperationalClassification { scenario_id, reason }
                if scenario_id == "fuse_capability_probe"
                    && reason.contains("skip_reason")
        )));
    }

    #[test]
    fn operational_manifest_rejects_fail_without_remediation() {
        let mut manifest = sample_operational_manifest();
        let record = manifest
            .operational_scenarios
            .get_mut("writeback_crash_matrix")
            .expect("scenario exists");
        record.remediation_hint = None;

        let errors = validate_operational_manifest(&manifest);
        assert!(errors.iter().any(|e| matches!(
            e,
            ManifestValidationError::InvalidOperationalClassification { scenario_id, reason }
                if scenario_id == "writeback_crash_matrix"
                    && reason.contains("remediation_hint")
        )));
    }

    #[test]
    fn operational_manifest_rejects_error_without_fail_outcome() {
        let mut manifest = sample_operational_manifest();
        let scenario = manifest
            .operational_scenarios
            .get_mut("fuzz_repair_smoke")
            .expect("scenario exists");
        scenario.classification = OperationalOutcomeClass::Error;
        scenario.actual_outcome = ScenarioResult::Skip;
        scenario.error_class = Some(OperationalErrorClass::HarnessBug);
        scenario.remediation_hint = Some("fix harness".to_owned());
        scenario.skip_reason = None;

        manifest
            .scenarios
            .get_mut("fuzz_repair_smoke")
            .expect("scenario exists")
            .outcome = ScenarioResult::Skip;

        let errors = validate_operational_manifest(&manifest);
        assert!(errors.iter().any(|e| matches!(
            e,
            ManifestValidationError::InvalidOperationalClassification { scenario_id, reason }
                if scenario_id == "fuzz_repair_smoke"
                    && reason.contains("FAIL actual_outcome")
        )));
    }

    #[test]
    fn operational_manifest_rejects_unknown_artifact_refs() {
        let mut manifest = sample_operational_manifest();
        manifest
            .operational_scenarios
            .get_mut("perf_baseline_run")
            .expect("scenario exists")
            .artifact_refs
            .push("artifacts/e2e/run/missing.json".to_owned());

        let errors = validate_operational_manifest(&manifest);
        assert!(errors.iter().any(|e| matches!(
            e,
            ManifestValidationError::UnknownArtifactRef { scenario_id, path }
                if scenario_id == "perf_baseline_run"
                    && path == "artifacts/e2e/run/missing.json"
        )));
    }

    #[test]
    fn operational_manifest_rejects_malformed_artifact_paths() {
        let mut manifest = sample_operational_manifest();
        manifest.artifacts.push(ArtifactEntry {
            path: "../outside.log".to_owned(),
            category: ArtifactCategory::RawLog,
            content_type: Some("text/plain".to_owned()),
            size_bytes: 1,
            sha256: None,
            redacted: false,
            metadata: BTreeMap::new(),
        });

        let errors = validate_operational_manifest(&manifest);
        assert!(errors.iter().any(|e| matches!(
            e,
            ManifestValidationError::MalformedArtifactPath(path) if path == "../outside.log"
        )));
    }

    #[test]
    fn operational_manifest_rejects_missing_cleanup_status() {
        let mut manifest = sample_operational_manifest();
        manifest
            .operational_scenarios
            .get_mut("xfstests_generic_subset")
            .expect("scenario exists")
            .cleanup_status = CleanupStatus::NotRun;

        let errors = validate_operational_manifest(&manifest);
        assert!(errors.iter().any(|e| matches!(
            e,
            ManifestValidationError::MissingCleanupStatus(id)
                if id == "xfstests_generic_subset"
        )));
    }

    #[test]
    fn operational_outcome_class_rejects_unknown_json_values() {
        let json = r#"{
            "scenario_id": "mounted_ext4_rw",
            "filesystem": "ext4",
            "image_hash": "sha256:abc",
            "mount_options": ["rw"],
            "expected_outcome": "PASS",
            "actual_outcome": "PASS",
            "classification": "maybe",
            "exit_status": 0,
            "stdout_path": "artifacts/e2e/run/stdout.log",
            "stderr_path": "artifacts/e2e/run/stderr.log",
            "ledger_paths": [],
            "artifact_refs": ["artifacts/e2e/run/stdout.log"],
            "cleanup_status": "clean"
        }"#;
        assert!(serde_json::from_str::<OperationalScenarioRecord>(json).is_err());
    }

    // ── Negative / invariant tests ───────────────────────────────────

    #[test]
    fn redactable_fields_are_lowercase() {
        for field in REDACTABLE_FIELDS {
            assert!(
                field.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "redactable field '{field}' must be lowercase",
            );
        }
    }

    #[test]
    fn validation_error_display_is_non_empty() {
        let errors = vec![
            ManifestValidationError::UnsupportedVersion(99),
            ManifestValidationError::EmptyRunId,
            ManifestValidationError::EmptyGateId,
            ManifestValidationError::InvalidTimestamp("bad".to_owned()),
            ManifestValidationError::EmptyGitCommit,
            ManifestValidationError::InvalidScenarioId("x".to_owned()),
            ManifestValidationError::EmptyArtifactPath,
            ManifestValidationError::MalformedArtifactPath("../bad.log".to_owned()),
            ManifestValidationError::DuplicateScenarioId("dup".to_owned()),
            ManifestValidationError::ScenarioIdMismatch {
                key: "test_key_scenario".to_owned(),
                value: "test_value_scenario".to_owned(),
            },
            ManifestValidationError::InconsistentVerdict,
            ManifestValidationError::MissingOperationalContext,
            ManifestValidationError::EmptyOperationalCommandLine,
            ManifestValidationError::EmptyOperationalHost,
            ManifestValidationError::FuseCapabilityNotChecked,
            ManifestValidationError::MissingOperationalScenario("test_scenario_id".to_owned()),
            ManifestValidationError::OperationalScenarioIdMismatch {
                key: "test_key_scenario".to_owned(),
                value: "test_value_scenario".to_owned(),
            },
            ManifestValidationError::MissingOperationalLogPath {
                scenario_id: "test_scenario_id".to_owned(),
                field: "stdout_path".to_owned(),
            },
            ManifestValidationError::InvalidOperationalClassification {
                scenario_id: "test_scenario_id".to_owned(),
                reason: "missing remediation".to_owned(),
            },
            ManifestValidationError::UnknownArtifactRef {
                scenario_id: "test_scenario_id".to_owned(),
                path: "artifacts/e2e/missing.log".to_owned(),
            },
            ManifestValidationError::MissingCleanupStatus("test_scenario_id".to_owned()),
        ];
        for err in &errors {
            assert!(!err.to_string().is_empty(), "{err:?} has empty display");
        }
    }

    // ── Helper ───────────────────────────────────────────────────────

    struct SampleOperationalCase {
        scenario_id: &'static str,
        result: ScenarioResult,
        classification: OperationalOutcomeClass,
        filesystem: FilesystemFlavor,
        primary_artifact: &'static str,
        skip_reason: Option<SkipReason>,
        error_class: Option<OperationalErrorClass>,
        remediation_hint: Option<&'static str>,
    }

    fn sample_operational_manifest() -> ArtifactManifest {
        let mut builder = ManifestBuilder::new(
            "run-operational",
            "operational_readiness",
            "2026-03-04T12:00:00Z",
        )
        .bead_id("bd-rchk0.4.1")
        .git_context("abc123", "main", true)
        .environment(sample_operational_environment())
        .operational_context(sample_operational_context());

        for case in sample_operational_cases() {
            builder = add_sample_operational_scenario(builder, &case);
        }

        builder.duration_secs(6.0).build()
    }

    fn sample_operational_context() -> OperationalRunContext {
        OperationalRunContext {
            command_line: vec![
                "scripts/e2e/run_gate.sh".to_owned(),
                "--gate".to_owned(),
                "operational_readiness".to_owned(),
            ],
            worker: WorkerContext {
                host: "build-host-01".to_owned(),
                worker_id: Some("rch-worker-a".to_owned()),
            },
            fuse_capability: FuseCapabilityResult::PermissionDenied,
            stdout_path: "artifacts/e2e/run/stdout.log".to_owned(),
            stderr_path: "artifacts/e2e/run/stderr.log".to_owned(),
        }
    }

    fn sample_operational_environment() -> EnvironmentFingerprint {
        EnvironmentFingerprint {
            hostname: "build-host-01".to_owned(),
            cpu_model: "AMD Ryzen 9 5950X".to_owned(),
            cpu_count: 32,
            memory_gib: 64,
            kernel: "Linux 6.17.0".to_owned(),
            rustc_version: "1.85.0".to_owned(),
            cargo_version: Some("1.85.0".to_owned()),
        }
    }

    fn sample_operational_cases() -> [SampleOperationalCase; 6] {
        [
            SampleOperationalCase {
                scenario_id: "xfstests_generic_subset",
                result: ScenarioResult::Pass,
                classification: OperationalOutcomeClass::Pass,
                filesystem: FilesystemFlavor::Ext4,
                primary_artifact: "artifacts/e2e/run/xfstests/results.json",
                skip_reason: None,
                error_class: None,
                remediation_hint: None,
            },
            SampleOperationalCase {
                scenario_id: "fuse_capability_probe",
                result: ScenarioResult::Skip,
                classification: OperationalOutcomeClass::Skip,
                filesystem: FilesystemFlavor::NotApplicable,
                primary_artifact: "artifacts/e2e/run/fuse/capability.json",
                skip_reason: Some(SkipReason::FusePermissionDenied),
                error_class: Some(OperationalErrorClass::FusePermissionSkip),
                remediation_hint: Some("rerun on a worker with /dev/fuse read/write access"),
            },
            SampleOperationalCase {
                scenario_id: "mounted_ext4_rw",
                result: ScenarioResult::Pass,
                classification: OperationalOutcomeClass::Pass,
                filesystem: FilesystemFlavor::Ext4,
                primary_artifact: "artifacts/e2e/run/mounted/ext4_rw.json",
                skip_reason: None,
                error_class: None,
                remediation_hint: None,
            },
            SampleOperationalCase {
                scenario_id: "fuzz_repair_smoke",
                result: ScenarioResult::Fail,
                classification: OperationalOutcomeClass::Error,
                filesystem: FilesystemFlavor::NotApplicable,
                primary_artifact: "artifacts/e2e/run/fuzz/repair_smoke.json",
                skip_reason: None,
                error_class: Some(OperationalErrorClass::WorkerDependencyMissing),
                remediation_hint: Some(
                    "install cargo-fuzz or run the fuzz smoke on the fuzz-capable lane",
                ),
            },
            SampleOperationalCase {
                scenario_id: "perf_baseline_run",
                result: ScenarioResult::Pass,
                classification: OperationalOutcomeClass::Pass,
                filesystem: FilesystemFlavor::Native,
                primary_artifact: "artifacts/e2e/run/perf/baseline.json",
                skip_reason: None,
                error_class: None,
                remediation_hint: None,
            },
            SampleOperationalCase {
                scenario_id: "writeback_crash_matrix",
                result: ScenarioResult::Fail,
                classification: OperationalOutcomeClass::Fail,
                filesystem: FilesystemFlavor::Ext4,
                primary_artifact: "artifacts/e2e/run/writeback/crash_matrix.json",
                skip_reason: None,
                error_class: Some(OperationalErrorClass::ProductFailure),
                remediation_hint: Some(
                    "open a narrow writeback crash-consistency bead with this artifact",
                ),
            },
        ]
    }

    fn add_sample_operational_scenario(
        builder: ManifestBuilder,
        case: &SampleOperationalCase,
    ) -> ManifestBuilder {
        let stdout_path = format!("artifacts/e2e/run/{}/stdout.log", case.scenario_id);
        let stderr_path = format!("artifacts/e2e/run/{}/stderr.log", case.scenario_id);
        let ledger_path = format!("artifacts/e2e/run/{}/ledger.jsonl", case.scenario_id);

        builder
            .scenario(case.scenario_id, case.result, case.remediation_hint, 1.0)
            .artifact(test_artifact(
                case.primary_artifact,
                ArtifactCategory::SummaryReport,
            ))
            .artifact(test_artifact(&stdout_path, ArtifactCategory::RawLog))
            .artifact(test_artifact(&stderr_path, ArtifactCategory::RawLog))
            .artifact(test_artifact(&ledger_path, ArtifactCategory::ProofArtifact))
            .operational_scenario(OperationalScenarioRecord {
                scenario_id: case.scenario_id.to_owned(),
                filesystem: case.filesystem,
                image_hash: Some(format!("sha256:{}", case.scenario_id)),
                mount_options: vec!["rw".to_owned(), "default_permissions".to_owned()],
                expected_outcome: case.result,
                actual_outcome: case.result,
                classification: case.classification,
                exit_status: i32::from(case.result != ScenarioResult::Pass),
                stdout_path,
                stderr_path,
                ledger_paths: vec![ledger_path],
                artifact_refs: vec![case.primary_artifact.to_owned()],
                cleanup_status: CleanupStatus::Clean,
                error_class: case.error_class,
                remediation_hint: case.remediation_hint.map(str::to_owned),
                skip_reason: case.skip_reason,
            })
    }

    fn test_artifact(path: &str, category: ArtifactCategory) -> ArtifactEntry {
        ArtifactEntry {
            path: path.to_owned(),
            category,
            content_type: Some("application/json".to_owned()),
            size_bytes: 256,
            sha256: Some(format!("checksum-for-{}", path.replace('/', "-"))),
            redacted: false,
            metadata: BTreeMap::new(),
        }
    }

    fn make_manifest(run_id: &str, gate_id: &str, created_at: &str) -> ArtifactManifest {
        ManifestBuilder::new(run_id, gate_id, created_at)
            .git_context("abc", "main", true)
            .environment(EnvironmentFingerprint {
                hostname: "test-host".to_owned(),
                cpu_model: "test-cpu".to_owned(),
                cpu_count: 4,
                memory_gib: 16,
                kernel: "Linux 6.17.0".to_owned(),
                rustc_version: "1.85.0".to_owned(),
                cargo_version: None,
            })
            .artifact(ArtifactEntry {
                path: "test.log".to_owned(),
                category: ArtifactCategory::E2eLog,
                content_type: None,
                size_bytes: 1024,
                sha256: None,
                redacted: false,
                metadata: BTreeMap::new(),
            })
            .build()
    }
}
