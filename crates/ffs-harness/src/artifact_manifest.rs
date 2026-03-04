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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GitContext {
    /// Current commit SHA (short or full).
    pub commit: String,
    /// Branch name.
    pub branch: String,
    /// Whether the working tree was clean at run time.
    pub clean: bool,
}

/// Host environment fingerprint for reproducibility.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// A single artifact entry in the manifest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    pub fn effective_max_age_days(
        &self,
        category: ArtifactCategory,
        verdict: GateVerdict,
    ) -> u32 {
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
        let age_days = current_epoch_days.saturating_sub(
            manifest_epoch_days(manifest).unwrap_or(current_epoch_days),
        );

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
        let mut running_total = total_bytes;
        for (idx, manifest) in manifests.iter().enumerate() {
            if running_total <= policy.max_total_bytes {
                break;
            }
            if !prune_indices.contains(&idx) {
                let manifest_bytes: u64 =
                    manifest.artifacts.iter().map(|a| a.size_bytes).sum();
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
    // Simple extraction: parse YYYY-MM-DD prefix and compute approximate days.
    let date_str = manifest.created_at.get(..10)?;
    let parts: Vec<&str> = date_str.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    let year: u32 = parts[0].parse().ok()?;
    let month: u32 = parts[1].parse().ok()?;
    let day: u32 = parts[2].parse().ok()?;
    // Approximate: 365.25 days/year, 30.44 days/month.
    Some(year * 365 + month * 30 + day)
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
            redact_fields: REDACTABLE_FIELDS
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
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
        redacted.environment.hostname = REDACTED_SENTINEL.to_owned();
    }

    // Redact artifact metadata fields.
    for artifact in &mut redacted.artifacts {
        let mut was_redacted = false;
        for key in artifact.metadata.keys().cloned().collect::<Vec<_>>() {
            if policy
                .redact_fields
                .iter()
                .any(|f| key.eq_ignore_ascii_case(f))
            {
                artifact
                    .metadata
                    .insert(key, REDACTED_SENTINEL.to_owned());
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
#[derive(Debug, Clone, PartialEq)]
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
    /// Duplicate scenario IDs found.
    DuplicateScenarioId(String),
    /// Verdict is inconsistent with scenario outcomes.
    InconsistentVerdict,
}

impl std::fmt::Display for ManifestValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => {
                write!(f, "unsupported schema version: {v} (expected {SCHEMA_VERSION})")
            }
            Self::EmptyRunId => write!(f, "run_id is empty"),
            Self::EmptyGateId => write!(f, "gate_id is empty"),
            Self::InvalidTimestamp(ts) => write!(f, "invalid timestamp: {ts}"),
            Self::EmptyGitCommit => write!(f, "git commit is empty"),
            Self::InvalidScenarioId(id) => write!(f, "invalid scenario_id: {id}"),
            Self::EmptyArtifactPath => write!(f, "artifact path is empty"),
            Self::DuplicateScenarioId(id) => write!(f, "duplicate scenario_id: {id}"),
            Self::InconsistentVerdict => {
                write!(f, "verdict is PASS but scenarios contain failures")
            }
        }
    }
}

/// Scenario ID regex pattern (at least 3 underscore-separated lowercase segments).
const SCENARIO_ID_PATTERN: &str = r"^[a-z][a-z0-9]*(_[a-z0-9]+){2,}$";

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
    if manifest.created_at.is_empty() || manifest.created_at.len() < 10 {
        errors.push(ManifestValidationError::InvalidTimestamp(
            manifest.created_at.clone(),
        ));
    }
    if manifest.git_context.commit.is_empty() {
        errors.push(ManifestValidationError::EmptyGitCommit);
    }

    // Scenario ID validation.
    let mut seen_ids = std::collections::HashSet::new();
    for (scenario_id, _outcome) in &manifest.scenarios {
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
    }

    // Artifact path validation.
    for artifact in &manifest.artifacts {
        if artifact.path.is_empty() {
            errors.push(ManifestValidationError::EmptyArtifactPath);
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

/// Check if a scenario ID matches the canonical pattern.
#[must_use]
pub fn is_valid_scenario_id(id: &str) -> bool {
    // Pattern: ^[a-z][a-z0-9]*(_[a-z0-9]+){2,}$
    // At least 3 underscore-separated segments, all lowercase alphanumeric.
    let segments: Vec<&str> = id.split('_').collect();
    if segments.len() < 3 {
        return false;
    }
    for (idx, segment) in segments.iter().enumerate() {
        if segment.is_empty() {
            return false;
        }
        if idx == 0 {
            // First segment must start with lowercase letter.
            if !segment.starts_with(|c: char| c.is_ascii_lowercase()) {
                return false;
            }
        }
        if !segment
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        {
            return false;
        }
    }
    true
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
        assert!(SCHEMA_VERSION >= 1);
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
        assert!(errors.iter().any(|e| matches!(e, ManifestValidationError::EmptyRunId)));
    }

    #[test]
    fn empty_gate_id_fails_validation() {
        let mut manifest = sample_manifest();
        manifest.gate_id = String::new();
        let errors = validate_manifest(&manifest);
        assert!(errors.iter().any(|e| matches!(e, ManifestValidationError::EmptyGateId)));
    }

    #[test]
    fn empty_git_commit_fails_validation() {
        let mut manifest = sample_manifest();
        manifest.git_context.commit = String::new();
        let errors = validate_manifest(&manifest);
        assert!(errors
            .iter()
            .any(|e| matches!(e, ManifestValidationError::EmptyGitCommit)));
    }

    #[test]
    fn invalid_timestamp_fails_validation() {
        let mut manifest = sample_manifest();
        manifest.created_at = "bad".to_owned();
        let errors = validate_manifest(&manifest);
        assert!(errors
            .iter()
            .any(|e| matches!(e, ManifestValidationError::InvalidTimestamp(_))));
    }

    #[test]
    fn unsupported_version_fails_validation() {
        let mut manifest = sample_manifest();
        manifest.schema_version = 999;
        let errors = validate_manifest(&manifest);
        assert!(errors
            .iter()
            .any(|e| matches!(e, ManifestValidationError::UnsupportedVersion(999))));
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
        assert!(errors
            .iter()
            .any(|e| matches!(e, ManifestValidationError::InvalidScenarioId(id) if id == "bad-id")));
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
        assert!(errors
            .iter()
            .any(|e| matches!(e, ManifestValidationError::InconsistentVerdict)));
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
        assert!(errors
            .iter()
            .any(|e| matches!(e, ManifestValidationError::EmptyArtifactPath)));
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
        for result in [ScenarioResult::Pass, ScenarioResult::Fail, ScenarioResult::Skip] {
            let json = serde_json::to_string(&result).expect("serialize");
            let parsed: ScenarioResult = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(parsed, result);
        }
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
        let age =
            policy.effective_max_age_days(ArtifactCategory::FuzzCrash, GateVerdict::Pass);
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
        // Current epoch: ~2026-03-04 → old manifest is >400 days old.
        let current_days = 2026 * 365 + 3 * 30 + 4;
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
        let current_days = 2026 * 365 + 3 * 30 + 4;
        let prune = evaluate_retention(&manifests, &policy, current_days);
        assert!(prune.contains(&0), "oldest manifest should be pruned for count");
        assert_eq!(prune.len(), 1);
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
        assert_eq!(
            redacted.environment.hostname,
            manifest.environment.hostname,
        );
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
            ManifestValidationError::DuplicateScenarioId("dup".to_owned()),
            ManifestValidationError::InconsistentVerdict,
        ];
        for err in &errors {
            assert!(!err.to_string().is_empty(), "{err:?} has empty display");
        }
    }

    // ── Helper ───────────────────────────────────────────────────────

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
