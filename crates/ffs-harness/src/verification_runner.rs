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
    ArtifactCategory, ArtifactEntry, ArtifactManifest, GateVerdict, ManifestBuilder,
    ScenarioOutcome, ScenarioResult, is_valid_scenario_id, validate_manifest,
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
