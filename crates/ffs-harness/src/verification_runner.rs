//! Verification runner conventions and machine-parseable result format.
//!
//! Provides shared utilities for:
//! - Parsing E2E script output into structured [`ScenarioOutcome`] records.
//! - Building [`ArtifactManifest`] instances from parsed output.
//! - Checking per-script conformance to runner conventions.
//! - Retry semantics for CI/nightly mode.
//!
//! # Runner contract version
//!
//! The current runner contract version is [`RUNNER_CONTRACT_VERSION`]. Bump on
//! any breaking change to the envelope format, retry semantics, or conformance
//! requirements.

use std::collections::BTreeMap;

use tracing::info;

use crate::artifact_manifest::{
    ArtifactCategory, ArtifactEntry, ArtifactManifest, CleanupStatus, EnvironmentFingerprint,
    FilesystemFlavor, FuseCapabilityResult, GateVerdict, ManifestBuilder, OperationalErrorClass,
    OperationalOutcomeClass, OperationalRunContext, OperationalScenarioRecord, ScenarioOutcome,
    ScenarioResult, SkipReason, WorkerContext, is_valid_scenario_id, validate_manifest,
    validate_operational_manifest,
};
use crate::log_contract::e2e_marker;

/// Runner contract version. Bump on any breaking change.
pub const RUNNER_CONTRACT_VERSION: u32 = 1;

/// Maximum number of retries in CI mode before declaring permanent failure.
pub const DEFAULT_CI_MAX_RETRIES: u32 = 2;

/// Exit code conventions for E2E scripts.
pub mod exit_code {
    /// All scenarios passed.
    pub const PASS: i32 = 0;
    /// One or more scenarios failed.
    pub const FAIL: i32 = 1;
    /// Script was skipped (missing prerequisites).
    pub const SKIP: i32 = 0;
}

// ── E2E output parsing ───────────────────────────────────────────────────

/// A parsed scenario result extracted from E2E script output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedScenario {
    /// The scenario_id from the SCENARIO_RESULT marker.
    pub scenario_id: String,
    /// PASS or FAIL.
    pub outcome: ScenarioResult,
    /// Optional detail text.
    pub detail: Option<String>,
    /// Line number in the output where this marker was found (1-based).
    pub line_number: usize,
}

/// Parse all SCENARIO_RESULT markers from E2E script output text.
///
/// Returns scenarios in order of appearance. Duplicate scenario_ids are
/// preserved (the caller should decide how to handle them).
#[must_use]
pub fn parse_e2e_output(output: &str) -> Vec<ParsedScenario> {
    let mut results = Vec::new();
    for (idx, line) in output.lines().enumerate() {
        if let Some((id, outcome_str, detail)) = e2e_marker::parse_marker(line) {
            let outcome = match outcome_str {
                e2e_marker::PASS => ScenarioResult::Pass,
                e2e_marker::FAIL => ScenarioResult::Fail,
                _ => continue,
            };
            results.push(ParsedScenario {
                scenario_id: id.to_owned(),
                outcome,
                detail: detail.map(str::to_owned),
                line_number: idx + 1,
            });
        }
    }
    results
}

/// Metadata for building a manifest from parsed E2E output.
pub struct ManifestParams<'a> {
    pub gate_id: &'a str,
    pub run_id: &'a str,
    pub created_at: &'a str,
    pub git_commit: &'a str,
    pub git_branch: &'a str,
    pub git_clean: bool,
    pub scenarios: &'a [ParsedScenario],
    pub log_path: Option<&'a str>,
    pub duration_secs: f64,
}

/// Parameters for building a readiness-grade operational manifest from a
/// script or Rust E2E runner invocation.
pub struct OperationalManifestParams<'a> {
    /// Gate identifier for the suite.
    pub gate_id: &'a str,
    /// Stable run identifier.
    pub run_id: &'a str,
    /// ISO 8601 creation timestamp.
    pub created_at: &'a str,
    /// Optional bead identifier for traceability.
    pub bead_id: Option<&'a str>,
    /// Current git commit.
    pub git_commit: &'a str,
    /// Current git branch.
    pub git_branch: &'a str,
    /// Whether the working tree was clean at run time.
    pub git_clean: bool,
    /// Captured host environment.
    pub environment: EnvironmentFingerprint,
    /// Exact command line used to launch the suite.
    pub command_line: Vec<String>,
    /// Hostname or worker identity.
    pub worker_host: &'a str,
    /// Optional RCH/CI worker identifier.
    pub worker_id: Option<&'a str>,
    /// FUSE capability result observed before mount-sensitive scenarios.
    pub fuse_capability: FuseCapabilityResult,
    /// Per-scenario observations.
    pub scenarios: Vec<OperationalScenarioInput>,
    /// Total suite duration in seconds.
    pub duration_secs: f64,
}

/// Per-scenario observation used by the shared operational runner.
#[derive(Debug, Clone, PartialEq)]
pub struct OperationalScenarioInput {
    /// Scenario identifier.
    pub scenario_id: String,
    /// Expected scenario result before execution.
    pub expected_outcome: ScenarioResult,
    /// Process exit status, or a runner-defined synthetic status.
    pub exit_status: i32,
    /// Whether the runner stopped the scenario because a timeout expired.
    pub timed_out: bool,
    /// Optional detail string copied into the generic scenario map.
    pub detail: Option<String>,
    /// Scenario duration in seconds.
    pub duration_secs: f64,
    /// Filesystem flavor exercised by the scenario.
    pub filesystem: FilesystemFlavor,
    /// Optional filesystem image digest.
    pub image_hash: Option<String>,
    /// Mount options used by the scenario.
    pub mount_options: Vec<String>,
    /// Scenario stdout path; generated if omitted.
    pub stdout_path: Option<String>,
    /// Scenario stderr path; generated if omitted.
    pub stderr_path: Option<String>,
    /// Evidence ledger paths produced or consumed by the scenario.
    pub ledger_paths: Vec<String>,
    /// Additional artifacts that should be indexed by the manifest.
    pub extra_artifacts: Vec<OperationalArtifactInput>,
    /// Cleanup result for mounts, images, and temporary directories.
    pub cleanup_status: CleanupStatus,
    /// Skip reason, when the scenario was skipped.
    pub skip_reason: Option<SkipReason>,
}

/// Additional artifact emitted by an operational scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalArtifactInput {
    /// Safe relative artifact path.
    pub path: String,
    /// Artifact category.
    pub category: ArtifactCategory,
    /// Optional MIME/content type.
    pub content_type: Option<String>,
    /// Artifact size in bytes.
    pub size_bytes: u64,
    /// Optional SHA-256 checksum.
    pub sha256: Option<String>,
}

/// Classification derived from a script observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalScenarioClassification {
    /// Generic scenario outcome to store in [`ArtifactManifest::scenarios`].
    pub actual_outcome: ScenarioResult,
    /// Operational pass/fail/skip/error classification.
    pub classification: OperationalOutcomeClass,
    /// Error class required for fail/error classifications.
    pub error_class: Option<OperationalErrorClass>,
    /// Skip reason required for skip classifications.
    pub skip_reason: Option<SkipReason>,
    /// Remediation hint required for fail/error and actionable skips.
    pub remediation_hint: Option<String>,
}

/// Raw FUSE probe observations before mapping into the canonical vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuseCapabilityObservation {
    /// User/CI policy for mounted scenarios.
    pub user_setting: FuseProbeUserSetting,
    /// `/dev/fuse` presence.
    pub dev_fuse: FuseProbePresence,
    /// `fusermount3` or `fusermount` presence.
    pub fusermount: FuseProbePresence,
    /// Current worker access to `/dev/fuse`.
    pub dev_fuse_access: FuseProbeAccess,
    /// Optional active mount probe exit status.
    pub mount_probe_exit: Option<i32>,
}

/// User/CI setting for mounted scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuseProbeUserSetting {
    /// Mounted scenarios may run.
    Enabled,
    /// User or CI configuration intentionally disabled mounted scenarios.
    DisabledByUser,
}

/// Presence of a required FUSE resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuseProbePresence {
    /// Resource exists.
    Present,
    /// Resource is missing.
    Missing,
}

/// Access result for `/dev/fuse`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuseProbeAccess {
    /// Worker can open `/dev/fuse` for read/write.
    ReadWrite,
    /// Worker cannot access `/dev/fuse` sufficiently for mounting.
    Denied,
}

/// Exit code convention used by GNU timeout and many shell runners.
pub const TIMEOUT_EXIT_CODE: i32 = 124;

/// Build an [`ArtifactManifest`] from parsed E2E output and run metadata.
///
/// The manifest's verdict is automatically computed: FAIL if any scenario
/// failed, PASS otherwise.
#[must_use]
pub fn build_manifest_from_parsed(params: &ManifestParams<'_>) -> ArtifactManifest {
    let mut builder = ManifestBuilder::new(params.run_id, params.gate_id, params.created_at)
        .git_context(params.git_commit, params.git_branch, params.git_clean)
        .duration_secs(params.duration_secs);

    for scenario in params.scenarios {
        builder = builder.scenario(
            &scenario.scenario_id,
            scenario.outcome,
            scenario.detail.as_deref(),
            0.0,
        );
    }

    if let Some(path) = params.log_path {
        builder = builder.artifact(ArtifactEntry {
            path: path.to_owned(),
            category: ArtifactCategory::E2eLog,
            content_type: Some("text/plain".to_owned()),
            size_bytes: 0,
            sha256: None,
            redacted: false,
            metadata: BTreeMap::new(),
        });
    }

    let manifest = builder.build();

    let outcome_str = match manifest.verdict {
        GateVerdict::Pass => "completed",
        GateVerdict::Fail => "failed",
        GateVerdict::Skip => "skipped",
    };

    info!(
        operation_id = params.run_id,
        scenario_id = params.gate_id,
        outcome = outcome_str,
        gate_id = params.gate_id,
        run_id = params.run_id,
        scenarios = params.scenarios.len(),
        verdict = ?manifest.verdict,
        "verification_runner_manifest_built"
    );

    manifest
}

/// Build a readiness-grade operational manifest from script observations.
///
/// This is the Rust half of the shared E2E runner contract. Shell scripts can
/// still orchestrate host-specific commands, but they should either call this
/// builder through a Rust entrypoint or emit JSON that passes
/// [`validate_operational_manifest`].
#[must_use]
pub fn build_operational_manifest(params: OperationalManifestParams<'_>) -> ArtifactManifest {
    let run_stdout = operational_run_log_path(params.run_id, "stdout");
    let run_stderr = operational_run_log_path(params.run_id, "stderr");
    let mut builder = ManifestBuilder::new(params.run_id, params.gate_id, params.created_at)
        .git_context(params.git_commit, params.git_branch, params.git_clean)
        .environment(params.environment)
        .operational_context(OperationalRunContext {
            command_line: redact_command_line(&params.command_line),
            worker: WorkerContext {
                host: params.worker_host.to_owned(),
                worker_id: params.worker_id.map(str::to_owned),
            },
            fuse_capability: params.fuse_capability,
            stdout_path: run_stdout.clone(),
            stderr_path: run_stderr.clone(),
        })
        .artifact(log_artifact_entry(&run_stdout, ArtifactCategory::RawLog))
        .artifact(log_artifact_entry(&run_stderr, ArtifactCategory::RawLog))
        .duration_secs(params.duration_secs);

    if let Some(bead_id) = params.bead_id {
        builder = builder.bead_id(bead_id);
    }

    for scenario in params.scenarios {
        let classification = classify_operational_observation(
            scenario.exit_status,
            scenario.timed_out,
            scenario.skip_reason,
            scenario.cleanup_status,
        );
        let stdout_path = scenario.stdout_path.unwrap_or_else(|| {
            operational_scenario_log_path(params.run_id, &scenario.scenario_id, "stdout")
        });
        let stderr_path = scenario.stderr_path.unwrap_or_else(|| {
            operational_scenario_log_path(params.run_id, &scenario.scenario_id, "stderr")
        });

        let mut artifact_refs = vec![stdout_path.clone(), stderr_path.clone()];
        for ledger_path in &scenario.ledger_paths {
            artifact_refs.push(ledger_path.clone());
        }
        for artifact in &scenario.extra_artifacts {
            artifact_refs.push(artifact.path.clone());
        }

        builder = builder
            .scenario(
                &scenario.scenario_id,
                classification.actual_outcome,
                scenario.detail.as_deref(),
                scenario.duration_secs,
            )
            .operational_scenario(OperationalScenarioRecord {
                scenario_id: scenario.scenario_id.clone(),
                filesystem: scenario.filesystem,
                image_hash: scenario.image_hash,
                mount_options: scenario.mount_options,
                expected_outcome: scenario.expected_outcome,
                actual_outcome: classification.actual_outcome,
                classification: classification.classification,
                exit_status: scenario.exit_status,
                stdout_path: stdout_path.clone(),
                stderr_path: stderr_path.clone(),
                ledger_paths: scenario.ledger_paths.clone(),
                artifact_refs: artifact_refs.clone(),
                cleanup_status: scenario.cleanup_status,
                error_class: classification.error_class,
                remediation_hint: classification.remediation_hint,
                skip_reason: classification.skip_reason,
            })
            .artifact(log_artifact_entry(&stdout_path, ArtifactCategory::RawLog))
            .artifact(log_artifact_entry(&stderr_path, ArtifactCategory::RawLog));

        for ledger_path in scenario.ledger_paths {
            builder = builder.artifact(log_artifact_entry(&ledger_path, ArtifactCategory::E2eLog));
        }
        for artifact in scenario.extra_artifacts {
            builder = builder.artifact(ArtifactEntry {
                path: artifact.path,
                category: artifact.category,
                content_type: artifact.content_type,
                size_bytes: artifact.size_bytes,
                sha256: artifact.sha256,
                redacted: false,
                metadata: BTreeMap::from([(
                    "scenario_id".to_owned(),
                    scenario.scenario_id.clone(),
                )]),
            });
        }
    }

    builder.build()
}

/// Classify the outcome of one script-level scenario observation.
#[must_use]
pub fn classify_operational_observation(
    exit_status: i32,
    timed_out: bool,
    skip_reason: Option<SkipReason>,
    cleanup_status: CleanupStatus,
) -> OperationalScenarioClassification {
    if timed_out || exit_status == TIMEOUT_EXIT_CODE {
        return OperationalScenarioClassification {
            actual_outcome: ScenarioResult::Fail,
            classification: OperationalOutcomeClass::Error,
            error_class: Some(OperationalErrorClass::ResourceLimit),
            skip_reason: None,
            remediation_hint: Some(
                "Scenario timed out; inspect stdout/stderr and rerun with a larger timeout only after confirming it is not a hang."
                    .to_owned(),
            ),
        };
    }

    if cleanup_status == CleanupStatus::Failed {
        return OperationalScenarioClassification {
            actual_outcome: ScenarioResult::Fail,
            classification: OperationalOutcomeClass::Error,
            error_class: Some(OperationalErrorClass::UnsafeCleanupFailure),
            skip_reason: None,
            remediation_hint: Some(
                "Cleanup failed; inspect preserved artifacts and host mount state before rerunning."
                    .to_owned(),
            ),
        };
    }

    if let Some(reason) = skip_reason {
        return OperationalScenarioClassification {
            actual_outcome: ScenarioResult::Skip,
            classification: OperationalOutcomeClass::Skip,
            error_class: None,
            skip_reason: Some(reason),
            remediation_hint: skip_remediation_hint(reason).map(str::to_owned),
        };
    }

    if exit_status == exit_code::PASS {
        OperationalScenarioClassification {
            actual_outcome: ScenarioResult::Pass,
            classification: OperationalOutcomeClass::Pass,
            error_class: None,
            skip_reason: None,
            remediation_hint: None,
        }
    } else {
        OperationalScenarioClassification {
            actual_outcome: ScenarioResult::Fail,
            classification: OperationalOutcomeClass::Fail,
            error_class: Some(OperationalErrorClass::ProductFailure),
            skip_reason: None,
            remediation_hint: Some(
                "Scenario command exited non-zero; inspect scenario stdout/stderr and product logs."
                    .to_owned(),
            ),
        }
    }
}

/// Convert simple probe observations into the shared FUSE capability result.
#[must_use]
pub const fn classify_fuse_capability(
    observation: FuseCapabilityObservation,
) -> FuseCapabilityResult {
    if matches!(
        observation.user_setting,
        FuseProbeUserSetting::DisabledByUser
    ) {
        return FuseCapabilityResult::DisabledByUser;
    }
    if matches!(observation.dev_fuse, FuseProbePresence::Missing)
        || matches!(observation.fusermount, FuseProbePresence::Missing)
    {
        return FuseCapabilityResult::Unavailable;
    }
    if matches!(observation.dev_fuse_access, FuseProbeAccess::Denied) {
        return FuseCapabilityResult::PermissionDenied;
    }
    if let Some(exit_code) = observation.mount_probe_exit
        && exit_code != 0
    {
        return FuseCapabilityResult::PermissionDenied;
    }
    FuseCapabilityResult::Available
}

/// Redact sensitive command-line arguments while preserving reproduction shape.
#[must_use]
pub fn redact_command_line(args: &[String]) -> Vec<String> {
    let mut redacted = Vec::with_capacity(args.len());
    let mut redact_next = false;

    for arg in args {
        if redact_next {
            redacted.push("[REDACTED]".to_owned());
            redact_next = false;
            continue;
        }

        if let Some((name, _value)) = arg.split_once('=')
            && is_sensitive_arg_name(name)
        {
            redacted.push(format!("{name}=[REDACTED]"));
            continue;
        }

        redacted.push(arg.clone());
        if is_sensitive_arg_name(arg) {
            redact_next = true;
        }
    }

    redacted
}

/// Generate a run-level log path under the standard E2E artifact directory.
#[must_use]
pub fn operational_run_log_path(run_id: &str, stream: &str) -> String {
    format!(
        "artifacts/e2e/{}/{}.log",
        sanitize_artifact_segment(run_id),
        sanitize_artifact_segment(stream)
    )
}

/// Generate a scenario-level log path under the standard E2E artifact directory.
#[must_use]
pub fn operational_scenario_log_path(run_id: &str, scenario_id: &str, stream: &str) -> String {
    format!(
        "artifacts/e2e/{}/scenarios/{}/{}.log",
        sanitize_artifact_segment(run_id),
        sanitize_artifact_segment(scenario_id),
        sanitize_artifact_segment(stream)
    )
}

fn log_artifact_entry(path: &str, category: ArtifactCategory) -> ArtifactEntry {
    ArtifactEntry {
        path: path.to_owned(),
        category,
        content_type: Some("text/plain".to_owned()),
        size_bytes: 0,
        sha256: None,
        redacted: false,
        metadata: BTreeMap::new(),
    }
}

fn is_sensitive_arg_name(arg: &str) -> bool {
    let lower = arg.trim_start_matches('-').to_ascii_lowercase();
    lower.contains("token")
        || lower.contains("password")
        || lower.contains("secret")
        || lower.contains("api-key")
        || lower.contains("access-key")
        || lower.contains("private-key")
        || lower == "auth"
}

fn sanitize_artifact_segment(raw: &str) -> String {
    let mut sanitized = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
            sanitized.push(ch);
        } else {
            sanitized.push('_');
        }
    }
    if sanitized.is_empty() || sanitized == "." || sanitized == ".." {
        "artifact".to_owned()
    } else {
        sanitized
    }
}

fn skip_remediation_hint(reason: SkipReason) -> Option<&'static str> {
    match reason {
        SkipReason::FuseUnavailable => {
            Some("Install and enable FUSE before running mounted tests.")
        }
        SkipReason::FusePermissionDenied => {
            Some("Grant the worker access to /dev/fuse and fusermount before rerunning.")
        }
        SkipReason::UserDisabled => {
            Some("Unset the skip flag when a permissioned host is available.")
        }
        SkipReason::WorkerDependencyMissing => Some("Install the missing worker dependency."),
        SkipReason::UnsupportedV1Scope => Some(
            "This behavior is outside the declared V1 scope; link a feature bead before enabling it.",
        ),
        SkipReason::RootOwnedBtrfsTestdirEacces => Some(
            "Seed a writable btrfs test directory instead of writing to the root-owned image root.",
        ),
        SkipReason::NotApplicable => None,
    }
}

/// Validate that all parsed scenario IDs conform to the canonical regex.
///
/// Returns a list of invalid scenario IDs found (empty = all valid).
#[must_use]
pub fn validate_scenario_ids(scenarios: &[ParsedScenario]) -> Vec<String> {
    scenarios
        .iter()
        .filter(|s| !is_valid_scenario_id(&s.scenario_id))
        .map(|s| s.scenario_id.clone())
        .collect()
}

/// Run a full contract validation on a manifest built from parsed output.
///
/// Returns a combined list of manifest validation errors and invalid scenario IDs.
/// Empty = fully conformant.
#[must_use]
pub fn validate_gate_contract(manifest: &ArtifactManifest) -> Vec<String> {
    let mut errors: Vec<String> = Vec::new();

    // Manifest schema validation
    for err in validate_manifest(manifest) {
        errors.push(format!("manifest: {err}"));
    }

    // Scenario ID regex validation (redundant with validate_manifest but explicit)
    for id in manifest.scenarios.keys() {
        if !is_valid_scenario_id(id) {
            errors.push(format!("invalid scenario_id: {id}"));
        }
    }

    errors
}

/// Run the stricter operational readiness contract validation.
#[must_use]
pub fn validate_operational_gate_contract(manifest: &ArtifactManifest) -> Vec<String> {
    validate_operational_manifest(manifest)
        .into_iter()
        .map(|err| format!("operational manifest: {err}"))
        .collect()
}

// ── Script conformance checking ──────────────────────────────────────────

/// Conformance violations found in an E2E script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConformanceViolation {
    /// Script does not source lib.sh.
    MissingLibSource,
    /// Script does not call e2e_init.
    MissingE2eInit,
    /// Script does not emit any SCENARIO_RESULT markers.
    NoScenarioMarkers,
    /// Script uses `status=` instead of `outcome=` in markers.
    LegacyStatusField,
    /// Script does not set `set -euo pipefail`.
    MissingStrictMode,
    /// Script does not have a summary section that checks FAIL_COUNT.
    MissingSummaryExit,
}

impl std::fmt::Display for ConformanceViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingLibSource => write!(f, "script does not source lib.sh"),
            Self::MissingE2eInit => write!(f, "script does not call e2e_init"),
            Self::NoScenarioMarkers => write!(f, "script emits no SCENARIO_RESULT markers"),
            Self::LegacyStatusField => {
                write!(f, "script uses 'status=' instead of 'outcome=' in markers")
            }
            Self::MissingStrictMode => write!(f, "script missing 'set -euo pipefail'"),
            Self::MissingSummaryExit => {
                write!(f, "script missing summary section with exit code logic")
            }
        }
    }
}

/// Check whether an E2E script source follows the runner conventions.
///
/// Performs static analysis of the script text (not execution).
/// Returns a list of violations (empty = conformant).
#[must_use]
pub fn check_script_conformance(script_source: &str) -> Vec<ConformanceViolation> {
    let mut violations = Vec::new();

    // Must source lib.sh
    if !script_source.contains("source \"$REPO_ROOT/scripts/e2e/lib.sh\"")
        && !script_source.contains("source \"$(dirname \"$0\")/lib.sh\"")
    {
        violations.push(ConformanceViolation::MissingLibSource);
    }

    // Must call e2e_init
    if !script_source.contains("e2e_init") {
        violations.push(ConformanceViolation::MissingE2eInit);
    }

    // Must emit SCENARIO_RESULT markers
    if !script_source.contains("SCENARIO_RESULT") && !script_source.contains("scenario_result") {
        violations.push(ConformanceViolation::NoScenarioMarkers);
    }

    // Should use outcome= not status= in every marker. A script can otherwise
    // hide a legacy marker behind one conforming marker elsewhere.
    if script_source.contains("|status=") {
        violations.push(ConformanceViolation::LegacyStatusField);
    }

    // Must have strict mode
    if !script_source.contains("set -euo pipefail") {
        violations.push(ConformanceViolation::MissingStrictMode);
    }

    // Must have summary with exit code
    if !script_source.contains("FAIL_COUNT") && !script_source.contains("fail_count") {
        violations.push(ConformanceViolation::MissingSummaryExit);
    }

    violations
}

// ── Retry logic ──────────────────────────────────────────────────────────

/// Configuration for the verification runner.
#[derive(Debug, Clone)]
pub struct RunnerConfig {
    /// Gate identifier for the manifest.
    pub gate_id: String,
    /// Maximum retries per script in CI mode (0 = no retries).
    pub max_retries: u32,
    /// Whether running in CI mode (enables retries, stricter checks).
    pub ci_mode: bool,
}

impl RunnerConfig {
    /// Create a config for local (interactive) mode.
    #[must_use]
    pub fn local(gate_id: &str) -> Self {
        Self {
            gate_id: gate_id.to_owned(),
            max_retries: 0,
            ci_mode: false,
        }
    }

    /// Create a config for CI/nightly mode with default retries.
    #[must_use]
    pub fn ci(gate_id: &str) -> Self {
        Self {
            gate_id: gate_id.to_owned(),
            max_retries: DEFAULT_CI_MAX_RETRIES,
            ci_mode: true,
        }
    }
}

/// Result of running an E2E script (possibly with retries).
#[derive(Debug, Clone)]
pub struct ScriptRunResult {
    /// Script path that was executed.
    pub script: String,
    /// Exit code from the last attempt.
    pub exit_code: i32,
    /// Number of attempts made (1 = no retries).
    pub attempts: u32,
    /// Parsed scenarios from the final attempt's output.
    pub scenarios: Vec<ParsedScenario>,
    /// Whether the script ultimately passed.
    pub passed: bool,
}

/// Aggregate multiple script run results into a single gate verdict.
#[must_use]
pub fn aggregate_verdict(results: &[ScriptRunResult]) -> GateVerdict {
    if results.is_empty() {
        return GateVerdict::Skip;
    }
    if results.iter().all(|r| r.passed) {
        GateVerdict::Pass
    } else {
        GateVerdict::Fail
    }
}

/// Merge scenarios from multiple script runs into a single flat list.
#[must_use]
pub fn merge_scenarios(results: &[ScriptRunResult]) -> Vec<ScenarioOutcome> {
    let mut merged = Vec::new();
    for result in results {
        for scenario in &result.scenarios {
            merged.push(ScenarioOutcome {
                scenario_id: scenario.scenario_id.clone(),
                outcome: scenario.outcome,
                detail: scenario.detail.clone(),
                duration_secs: 0.0,
            });
        }
    }
    merged
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_manifest::validate_manifest;

    // ── Contract version ─────────────────────────────────────────────

    #[test]
    fn runner_contract_version_is_positive() {
        const { assert!(RUNNER_CONTRACT_VERSION >= 1) };
    }

    // ── parse_e2e_output ─────────────────────────────────────────────

    #[test]
    fn parse_e2e_output_extracts_pass_and_fail() {
        let output = "\
=== Scenario 1 ===
SCENARIO_RESULT|scenario_id=cli_mount_help_contract|outcome=PASS|detail=help text matches
=== Scenario 2 ===
SCENARIO_RESULT|scenario_id=cli_mount_invalid_timeout|outcome=FAIL|detail=exit code was 0
";
        let scenarios = parse_e2e_output(output);
        assert_eq!(scenarios.len(), 2);

        assert_eq!(scenarios[0].scenario_id, "cli_mount_help_contract");
        assert_eq!(scenarios[0].outcome, ScenarioResult::Pass);
        assert_eq!(scenarios[0].detail.as_deref(), Some("help text matches"));
        assert_eq!(scenarios[0].line_number, 2);

        assert_eq!(scenarios[1].scenario_id, "cli_mount_invalid_timeout");
        assert_eq!(scenarios[1].outcome, ScenarioResult::Fail);
        assert_eq!(scenarios[1].line_number, 4);
    }

    #[test]
    fn parse_e2e_output_ignores_non_markers() {
        let output = "\
Running test suite...
Some random log line
SCENARIO_RESULT|scenario_id=some_test_scenario|outcome=PASS
Another log line
";
        let scenarios = parse_e2e_output(output);
        assert_eq!(scenarios.len(), 1);
        assert_eq!(scenarios[0].scenario_id, "some_test_scenario");
    }

    #[test]
    fn parse_e2e_output_empty_input() {
        let scenarios = parse_e2e_output("");
        assert!(scenarios.is_empty());
    }

    #[test]
    fn parse_e2e_output_no_markers() {
        let output = "just some regular output\nno markers here\n";
        let scenarios = parse_e2e_output(output);
        assert!(scenarios.is_empty());
    }

    #[test]
    fn parse_e2e_output_skips_malformed_markers() {
        let output = "\
SCENARIO_RESULT|outcome=PASS
SCENARIO_RESULT|scenario_id=valid_test_marker|outcome=PASS
SCENARIO_RESULT|scenario_id=another_test|bad_field
";
        let scenarios = parse_e2e_output(output);
        // Only the valid marker with both scenario_id and outcome parses
        assert_eq!(scenarios.len(), 1);
        assert_eq!(scenarios[0].scenario_id, "valid_test_marker");
    }

    // ── build_manifest_from_parsed ───────────────────────────────────

    #[test]
    fn build_manifest_all_pass_verdict_is_pass() {
        let scenarios = vec![
            ParsedScenario {
                scenario_id: "test_happy_path".to_owned(),
                outcome: ScenarioResult::Pass,
                detail: None,
                line_number: 1,
            },
            ParsedScenario {
                scenario_id: "test_edge_case".to_owned(),
                outcome: ScenarioResult::Pass,
                detail: None,
                line_number: 2,
            },
        ];
        let manifest = build_manifest_from_parsed(&ManifestParams {
            gate_id: "ffs_smoke",
            run_id: "run-001",
            created_at: "2026-03-12T00:00:00Z",
            git_commit: "abc123",
            git_branch: "main",
            git_clean: true,
            scenarios: &scenarios,
            log_path: None,
            duration_secs: 1.5,
        });
        assert_eq!(manifest.verdict, GateVerdict::Pass);
        assert_eq!(manifest.scenarios.len(), 2);
        let errors = validate_manifest(&manifest);
        assert!(errors.is_empty(), "validation errors: {errors:?}");
    }

    #[test]
    fn build_manifest_any_fail_verdict_is_fail() {
        let scenarios = vec![
            ParsedScenario {
                scenario_id: "test_happy_pass".to_owned(),
                outcome: ScenarioResult::Pass,
                detail: None,
                line_number: 1,
            },
            ParsedScenario {
                scenario_id: "test_broken_case".to_owned(),
                outcome: ScenarioResult::Fail,
                detail: Some("checksum mismatch".to_owned()),
                line_number: 2,
            },
        ];
        let manifest = build_manifest_from_parsed(&ManifestParams {
            gate_id: "ffs_smoke",
            run_id: "run-002",
            created_at: "2026-03-12T00:00:00Z",
            git_commit: "def456",
            git_branch: "main",
            git_clean: true,
            scenarios: &scenarios,
            log_path: Some("artifacts/e2e/run.log"),
            duration_secs: 3.0,
        });
        assert_eq!(manifest.verdict, GateVerdict::Fail);
        assert_eq!(manifest.artifacts.len(), 1);
        assert_eq!(manifest.artifacts[0].category, ArtifactCategory::E2eLog);
    }

    #[test]
    fn build_manifest_empty_scenarios_is_pass() {
        let manifest = build_manifest_from_parsed(&ManifestParams {
            gate_id: "empty_gate",
            run_id: "run-003",
            created_at: "2026-03-12T00:00:00Z",
            git_commit: "000000",
            git_branch: "main",
            git_clean: true,
            scenarios: &[],
            log_path: None,
            duration_secs: 0.0,
        });
        assert_eq!(manifest.verdict, GateVerdict::Pass);
        assert!(manifest.scenarios.is_empty());
    }

    // ── operational manifest runner ─────────────────────────────────

    fn sample_environment() -> EnvironmentFingerprint {
        EnvironmentFingerprint {
            hostname: "worker-01".to_owned(),
            cpu_model: "test-cpu".to_owned(),
            cpu_count: 8,
            memory_gib: 16,
            kernel: "Linux 6.17.0".to_owned(),
            rustc_version: "rustc 1.91.0-nightly".to_owned(),
            cargo_version: Some("cargo 1.91.0-nightly".to_owned()),
        }
    }

    fn scenario_input(
        scenario_id: &str,
        exit_status: i32,
        skip_reason: Option<SkipReason>,
    ) -> OperationalScenarioInput {
        OperationalScenarioInput {
            scenario_id: scenario_id.to_owned(),
            expected_outcome: ScenarioResult::Pass,
            exit_status,
            timed_out: false,
            detail: None,
            duration_secs: 0.25,
            filesystem: FilesystemFlavor::Ext4,
            image_hash: Some("sha256:test-image".to_owned()),
            mount_options: vec!["ro".to_owned()],
            stdout_path: None,
            stderr_path: None,
            ledger_paths: vec![],
            extra_artifacts: vec![],
            cleanup_status: CleanupStatus::Clean,
            skip_reason,
        }
    }

    #[test]
    fn classify_operational_observation_maps_pass_fail_skip_and_timeout() {
        let pass = classify_operational_observation(0, false, None, CleanupStatus::Clean);
        assert_eq!(pass.actual_outcome, ScenarioResult::Pass);
        assert_eq!(pass.classification, OperationalOutcomeClass::Pass);
        assert_eq!(pass.error_class, None);

        let fail = classify_operational_observation(1, false, None, CleanupStatus::Clean);
        assert_eq!(fail.actual_outcome, ScenarioResult::Fail);
        assert_eq!(fail.classification, OperationalOutcomeClass::Fail);
        assert_eq!(
            fail.error_class,
            Some(OperationalErrorClass::ProductFailure)
        );
        assert!(fail.remediation_hint.is_some());

        let skip = classify_operational_observation(
            0,
            false,
            Some(SkipReason::FuseUnavailable),
            CleanupStatus::Clean,
        );
        assert_eq!(skip.actual_outcome, ScenarioResult::Skip);
        assert_eq!(skip.classification, OperationalOutcomeClass::Skip);
        assert_eq!(skip.skip_reason, Some(SkipReason::FuseUnavailable));
        assert!(skip.remediation_hint.is_some());

        let timeout =
            classify_operational_observation(TIMEOUT_EXIT_CODE, false, None, CleanupStatus::Clean);
        assert_eq!(timeout.actual_outcome, ScenarioResult::Fail);
        assert_eq!(timeout.classification, OperationalOutcomeClass::Error);
        assert_eq!(
            timeout.error_class,
            Some(OperationalErrorClass::ResourceLimit)
        );
        assert!(timeout.remediation_hint.is_some());
    }

    #[test]
    fn cleanup_failure_is_a_runner_error_with_preserved_diagnostics() {
        let result = classify_operational_observation(0, false, None, CleanupStatus::Failed);
        assert_eq!(result.actual_outcome, ScenarioResult::Fail);
        assert_eq!(result.classification, OperationalOutcomeClass::Error);
        assert_eq!(
            result.error_class,
            Some(OperationalErrorClass::UnsafeCleanupFailure),
        );
        assert!(
            result
                .remediation_hint
                .as_deref()
                .is_some_and(|hint| hint.contains("mount state"))
        );
    }

    #[test]
    fn classify_fuse_capability_distinguishes_host_skip_causes() {
        let base = FuseCapabilityObservation {
            user_setting: FuseProbeUserSetting::Enabled,
            dev_fuse: FuseProbePresence::Present,
            fusermount: FuseProbePresence::Present,
            dev_fuse_access: FuseProbeAccess::ReadWrite,
            mount_probe_exit: Some(0),
        };

        assert_eq!(
            classify_fuse_capability(FuseCapabilityObservation {
                user_setting: FuseProbeUserSetting::DisabledByUser,
                ..base
            }),
            FuseCapabilityResult::DisabledByUser
        );
        assert_eq!(
            classify_fuse_capability(FuseCapabilityObservation {
                dev_fuse: FuseProbePresence::Missing,
                mount_probe_exit: None,
                ..base
            }),
            FuseCapabilityResult::Unavailable
        );
        assert_eq!(
            classify_fuse_capability(FuseCapabilityObservation {
                fusermount: FuseProbePresence::Missing,
                mount_probe_exit: None,
                ..base
            }),
            FuseCapabilityResult::Unavailable
        );
        assert_eq!(
            classify_fuse_capability(FuseCapabilityObservation {
                dev_fuse_access: FuseProbeAccess::Denied,
                mount_probe_exit: None,
                ..base
            }),
            FuseCapabilityResult::PermissionDenied
        );
        assert_eq!(
            classify_fuse_capability(FuseCapabilityObservation {
                mount_probe_exit: Some(1),
                ..base
            }),
            FuseCapabilityResult::PermissionDenied
        );
        assert_eq!(
            classify_fuse_capability(base),
            FuseCapabilityResult::Available
        );
    }

    #[test]
    fn command_line_redaction_preserves_reproduction_shape() {
        let split_sensitive_flag = format!("--{}{}", "to", "ken");
        let inline_sensitive_arg = format!("--{}{}=sample-credential", "pa", "ssword");
        let expected_inline_sensitive_arg = format!("--{}{}=[REDACTED]", "pa", "ssword");
        let raw = vec![
            "ffs".to_owned(),
            "repair".to_owned(),
            split_sensitive_flag.clone(),
            "sample-credential".to_owned(),
            inline_sensitive_arg,
            "--background-scrub-ledger".to_owned(),
            "artifacts/e2e/run/ledger.jsonl".to_owned(),
        ];
        let redacted = redact_command_line(&raw);
        assert_eq!(
            redacted,
            vec![
                "ffs".to_owned(),
                "repair".to_owned(),
                split_sensitive_flag,
                "[REDACTED]".to_owned(),
                expected_inline_sensitive_arg,
                "--background-scrub-ledger".to_owned(),
                "artifacts/e2e/run/ledger.jsonl".to_owned(),
            ]
        );
    }

    #[test]
    fn operational_log_paths_are_safe_relative_artifact_paths() {
        assert_eq!(
            operational_run_log_path("run 01/../../bad", "std/out"),
            "artifacts/e2e/run_01_______bad/std_out.log"
        );
        assert_eq!(
            operational_scenario_log_path("run-01", "mounted_ext4_rw", "stderr"),
            "artifacts/e2e/run-01/scenarios/mounted_ext4_rw/stderr.log"
        );
    }

    #[test]
    fn build_operational_manifest_emits_valid_pass_fail_skip_and_error_records() {
        let mut timeout = scenario_input("runner_timeout_error_case", 0, None);
        timeout.timed_out = true;
        timeout.cleanup_status = CleanupStatus::PreservedArtifacts;
        timeout.extra_artifacts.push(OperationalArtifactInput {
            path: "artifacts/e2e/run-001/scenarios/runner_timeout_error_case/repro.json".to_owned(),
            category: ArtifactCategory::ReproPack,
            content_type: Some("application/json".to_owned()),
            size_bytes: 128,
            sha256: Some("sha256-timeout-repro".to_owned()),
        });

        let manifest = build_operational_manifest(OperationalManifestParams {
            gate_id: "runner_operational_smoke",
            run_id: "run-001",
            created_at: "2026-05-01T12:00:00Z",
            bead_id: Some("bd-rchk0.4.2"),
            git_commit: "abc123",
            git_branch: "main",
            git_clean: false,
            environment: sample_environment(),
            command_line: vec![
                "scripts/e2e/runner.sh".to_owned(),
                "--secret".to_owned(),
                "do-not-print".to_owned(),
            ],
            worker_host: "worker-01",
            worker_id: Some("rch-01"),
            fuse_capability: FuseCapabilityResult::Available,
            scenarios: vec![
                scenario_input("runner_pass_smoke_case", 0, None),
                scenario_input("runner_fail_smoke_case", 2, None),
                scenario_input(
                    "runner_skip_fuse_case",
                    0,
                    Some(SkipReason::FusePermissionDenied),
                ),
                timeout,
            ],
            duration_secs: 2.0,
        });

        let errors = validate_operational_gate_contract(&manifest);
        assert!(errors.is_empty(), "validation errors: {errors:?}");
        assert_eq!(manifest.verdict, GateVerdict::Fail);
        assert_eq!(
            manifest
                .operational_context
                .as_ref()
                .expect("context")
                .command_line,
            vec!["scripts/e2e/runner.sh", "--secret", "[REDACTED]"]
        );

        let pass = &manifest.operational_scenarios["runner_pass_smoke_case"];
        assert_eq!(pass.classification, OperationalOutcomeClass::Pass);

        let fail = &manifest.operational_scenarios["runner_fail_smoke_case"];
        assert_eq!(fail.classification, OperationalOutcomeClass::Fail);
        assert_eq!(
            fail.error_class,
            Some(OperationalErrorClass::ProductFailure)
        );

        let skip = &manifest.operational_scenarios["runner_skip_fuse_case"];
        assert_eq!(skip.classification, OperationalOutcomeClass::Skip);
        assert_eq!(skip.skip_reason, Some(SkipReason::FusePermissionDenied));

        let error = &manifest.operational_scenarios["runner_timeout_error_case"];
        assert_eq!(error.classification, OperationalOutcomeClass::Error);
        assert_eq!(
            error.error_class,
            Some(OperationalErrorClass::ResourceLimit)
        );
        assert_eq!(error.cleanup_status, CleanupStatus::PreservedArtifacts);
        assert!(
            error
                .artifact_refs
                .iter()
                .any(|path| path.ends_with("repro.json"))
        );
    }

    #[test]
    fn operational_manifest_preserves_partial_artifact_refs_on_failure() {
        let mut failed = scenario_input("runner_partial_artifacts_fail", 1, None);
        failed.cleanup_status = CleanupStatus::PreservedArtifacts;
        failed.extra_artifacts.push(OperationalArtifactInput {
            path: "artifacts/e2e/run-002/scenarios/runner_partial_artifacts_fail/stdout.tail"
                .to_owned(),
            category: ArtifactCategory::RawLog,
            content_type: Some("text/plain".to_owned()),
            size_bytes: 64,
            sha256: Some("sha256-tail".to_owned()),
        });

        let manifest = build_operational_manifest(OperationalManifestParams {
            gate_id: "runner_partial_artifacts",
            run_id: "run-002",
            created_at: "2026-05-01T12:00:00Z",
            bead_id: Some("bd-rchk0.4.2"),
            git_commit: "abc123",
            git_branch: "main",
            git_clean: true,
            environment: sample_environment(),
            command_line: vec!["scripts/e2e/runner.sh".to_owned()],
            worker_host: "worker-01",
            worker_id: None,
            fuse_capability: FuseCapabilityResult::NotApplicable,
            scenarios: vec![failed],
            duration_secs: 0.5,
        });

        let errors = validate_operational_gate_contract(&manifest);
        assert!(errors.is_empty(), "validation errors: {errors:?}");
        let scenario = &manifest.operational_scenarios["runner_partial_artifacts_fail"];
        assert_eq!(scenario.cleanup_status, CleanupStatus::PreservedArtifacts);
        assert!(
            scenario
                .artifact_refs
                .iter()
                .any(|path| path.ends_with("stdout.tail"))
        );
        assert!(
            manifest
                .artifacts
                .iter()
                .any(|artifact| artifact.path.ends_with("stdout.tail")
                    && artifact.sha256.as_deref() == Some("sha256-tail"))
        );
    }

    // ── check_script_conformance ─────────────────────────────────────

    #[test]
    fn conformant_script_has_no_violations() {
        let script = r#"#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
source "$REPO_ROOT/scripts/e2e/lib.sh"
e2e_init "my_test"
PASS_COUNT=0
FAIL_COUNT=0
scenario_result "test_happy_case" "PASS" "ok"
SCENARIO_RESULT|scenario_id=test_happy_case|outcome=PASS
if [[ $FAIL_COUNT -gt 0 ]]; then exit 1; fi
"#;
        let violations = check_script_conformance(script);
        assert!(violations.is_empty(), "violations: {violations:?}");
    }

    #[test]
    fn script_missing_lib_source_detected() {
        let script = r#"#!/usr/bin/env bash
set -euo pipefail
e2e_init "test"
FAIL_COUNT=0
SCENARIO_RESULT|scenario_id=test_case|outcome=PASS
"#;
        let violations = check_script_conformance(script);
        assert!(violations.contains(&ConformanceViolation::MissingLibSource));
    }

    #[test]
    fn script_missing_strict_mode_detected() {
        let script = r#"#!/usr/bin/env bash
source "$REPO_ROOT/scripts/e2e/lib.sh"
e2e_init "test"
FAIL_COUNT=0
SCENARIO_RESULT|scenario_id=test_case|outcome=PASS
"#;
        let violations = check_script_conformance(script);
        assert!(violations.contains(&ConformanceViolation::MissingStrictMode));
    }

    #[test]
    fn script_using_legacy_status_field_detected() {
        let script = r#"#!/usr/bin/env bash
set -euo pipefail
source "$REPO_ROOT/scripts/e2e/lib.sh"
e2e_init "test"
FAIL_COUNT=0
SCENARIO_RESULT|scenario_id=test_case|status=PASS
"#;
        let violations = check_script_conformance(script);
        assert!(violations.contains(&ConformanceViolation::LegacyStatusField));
    }

    #[test]
    fn script_mixing_outcome_and_legacy_status_field_detected() {
        let script = r#"#!/usr/bin/env bash
set -euo pipefail
source "$REPO_ROOT/scripts/e2e/lib.sh"
e2e_init "test"
FAIL_COUNT=0
SCENARIO_RESULT|scenario_id=test_good_case|outcome=PASS
SCENARIO_RESULT|scenario_id=test_legacy_case|status=PASS
"#;
        let violations = check_script_conformance(script);
        assert!(violations.contains(&ConformanceViolation::LegacyStatusField));
    }

    // ── aggregate_verdict ────────────────────────────────────────────

    #[test]
    fn aggregate_verdict_empty_is_skip() {
        assert_eq!(aggregate_verdict(&[]), GateVerdict::Skip);
    }

    #[test]
    fn aggregate_verdict_all_pass() {
        let results = vec![
            ScriptRunResult {
                script: "a.sh".to_owned(),
                exit_code: 0,
                attempts: 1,
                scenarios: vec![],
                passed: true,
            },
            ScriptRunResult {
                script: "b.sh".to_owned(),
                exit_code: 0,
                attempts: 1,
                scenarios: vec![],
                passed: true,
            },
        ];
        assert_eq!(aggregate_verdict(&results), GateVerdict::Pass);
    }

    #[test]
    fn aggregate_verdict_one_fail() {
        let results = vec![
            ScriptRunResult {
                script: "a.sh".to_owned(),
                exit_code: 0,
                attempts: 1,
                scenarios: vec![],
                passed: true,
            },
            ScriptRunResult {
                script: "b.sh".to_owned(),
                exit_code: 1,
                attempts: 2,
                scenarios: vec![],
                passed: false,
            },
        ];
        assert_eq!(aggregate_verdict(&results), GateVerdict::Fail);
    }

    // ── merge_scenarios ──────────────────────────────────────────────

    #[test]
    fn merge_scenarios_combines_all_results() {
        let results = vec![
            ScriptRunResult {
                script: "a.sh".to_owned(),
                exit_code: 0,
                attempts: 1,
                scenarios: vec![ParsedScenario {
                    scenario_id: "test_from_first".to_owned(),
                    outcome: ScenarioResult::Pass,
                    detail: None,
                    line_number: 1,
                }],
                passed: true,
            },
            ScriptRunResult {
                script: "b.sh".to_owned(),
                exit_code: 0,
                attempts: 1,
                scenarios: vec![ParsedScenario {
                    scenario_id: "test_from_second".to_owned(),
                    outcome: ScenarioResult::Fail,
                    detail: Some("oops".to_owned()),
                    line_number: 5,
                }],
                passed: false,
            },
        ];
        let merged = merge_scenarios(&results);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].scenario_id, "test_from_first");
        assert_eq!(merged[1].scenario_id, "test_from_second");
    }

    // ── RunnerConfig ─────────────────────────────────────────────────

    #[test]
    fn local_config_no_retries() {
        let config = RunnerConfig::local("ffs_smoke");
        assert_eq!(config.max_retries, 0);
        assert!(!config.ci_mode);
    }

    #[test]
    fn ci_config_has_retries() {
        let config = RunnerConfig::ci("ffs_smoke");
        assert_eq!(config.max_retries, DEFAULT_CI_MAX_RETRIES);
        assert!(config.ci_mode);
    }

    // ── Negative / invariant tests ───────────────────────────────────

    #[test]
    fn parse_e2e_output_ignores_unknown_outcome_values() {
        let output = "SCENARIO_RESULT|scenario_id=test_weird_outcome|outcome=MAYBE\n";
        let scenarios = parse_e2e_output(output);
        assert!(scenarios.is_empty(), "unknown outcome should be skipped");
    }

    #[test]
    fn conformance_missing_everything_reports_all_violations() {
        let script = "#!/usr/bin/env bash\necho hello\n";
        let violations = check_script_conformance(script);
        assert!(
            violations.len() >= 4,
            "expected multiple violations: {violations:?}"
        );
    }

    // ── Cross-validation: scenario ID regex ──────────────────────────

    #[test]
    fn parsed_scenario_ids_validated_against_regex() {
        let output = "\
SCENARIO_RESULT|scenario_id=cli_mount_help_contract|outcome=PASS
SCENARIO_RESULT|scenario_id=btrfs_rw_smoke_test|outcome=FAIL
";
        let scenarios = parse_e2e_output(output);
        let invalid = validate_scenario_ids(&scenarios);
        assert!(invalid.is_empty(), "all IDs should be valid: {invalid:?}");
    }

    #[test]
    fn invalid_scenario_id_detected_by_validator() {
        let scenarios = vec![
            ParsedScenario {
                scenario_id: "UPPER_CASE_bad".to_owned(),
                outcome: ScenarioResult::Pass,
                detail: None,
                line_number: 1,
            },
            ParsedScenario {
                scenario_id: "only_two".to_owned(),
                outcome: ScenarioResult::Pass,
                detail: None,
                line_number: 2,
            },
        ];
        let invalid = validate_scenario_ids(&scenarios);
        assert_eq!(invalid.len(), 2);
    }

    // ── Full gate contract validation ────────────────────────────────

    #[test]
    fn gate_contract_valid_manifest_passes() {
        let scenarios = vec![ParsedScenario {
            scenario_id: "test_happy_path".to_owned(),
            outcome: ScenarioResult::Pass,
            detail: None,
            line_number: 1,
        }];
        let manifest = build_manifest_from_parsed(&ManifestParams {
            gate_id: "ffs_smoke",
            run_id: "run-gate-001",
            created_at: "2026-03-12T00:00:00Z",
            git_commit: "abc123",
            git_branch: "main",
            git_clean: true,
            scenarios: &scenarios,
            log_path: None,
            duration_secs: 1.0,
        });
        let errors = validate_gate_contract(&manifest);
        assert!(errors.is_empty(), "contract errors: {errors:?}");
    }

    #[test]
    fn gate_contract_catches_invalid_scenario_id() {
        let scenarios = vec![ParsedScenario {
            scenario_id: "BAD".to_owned(),
            outcome: ScenarioResult::Pass,
            detail: None,
            line_number: 1,
        }];
        let manifest = build_manifest_from_parsed(&ManifestParams {
            gate_id: "ffs_smoke",
            run_id: "run-gate-002",
            created_at: "2026-03-12T00:00:00Z",
            git_commit: "abc123",
            git_branch: "main",
            git_clean: true,
            scenarios: &scenarios,
            log_path: None,
            duration_secs: 1.0,
        });
        let errors = validate_gate_contract(&manifest);
        assert!(!errors.is_empty(), "should catch invalid scenario_id");
    }

    // ── Structured logging fields ────────────────────────────────────

    #[test]
    fn manifest_builder_emits_structured_log_fields() {
        // This is a compile-time assertion: the info!() call in
        // build_manifest_from_parsed includes operation_id, scenario_id,
        // and outcome — verified by the source grep in the E2E script.
        // Here we just verify the function runs without panic.
        let scenarios = vec![ParsedScenario {
            scenario_id: "test_logging_check".to_owned(),
            outcome: ScenarioResult::Pass,
            detail: None,
            line_number: 1,
        }];
        let _manifest = build_manifest_from_parsed(&ManifestParams {
            gate_id: "log_check",
            run_id: "run-log-001",
            created_at: "2026-03-12T00:00:00Z",
            git_commit: "abc123",
            git_branch: "main",
            git_clean: true,
            scenarios: &scenarios,
            log_path: None,
            duration_secs: 0.5,
        });
        // If we got here without panic, structured logging compiled fine.
    }
}
