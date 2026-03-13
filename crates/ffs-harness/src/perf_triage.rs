#![forbid(unsafe_code)]

//! Performance regression triage decision helpers.
//!
//! Provides a structured classification pipeline that maps a
//! [`ComparisonResult`] into a triage action with human-readable rationale
//! and structured log fields for post-mortem correlation.
//!
//! The triage decision tree is documented in
//! `docs/runbooks/perf-regression-triage.md`.

use crate::benchmark_taxonomy::BenchmarkFamily;
use crate::perf_comparison::{ComparisonResult, ComparisonVerdict, HystereticVerdict};
use serde::{Deserialize, Serialize};
use tracing::info;

/// Triage contract version. Bump on any breaking change to classification logic.
pub const TRIAGE_VERSION: u32 = 1;

/// Root-cause category for a performance regression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriageCause {
    /// Regression is within noise — no action needed.
    Noise,
    /// Not enough data to make a statistical determination.
    InsufficientData,
    /// Statistically insignificant change — likely environmental jitter.
    NotSignificant,
    /// Significant but negligible effect size — no practical impact.
    NegligibleEffect,
    /// Likely a real code regression in a CPU-bound path.
    CodeRegression,
    /// Likely an environment/hardware/scheduler change.
    EnvironmentChange,
    /// Thresholds may be too tight for this operation's variance profile.
    ThresholdCalibration,
}

/// Recommended operator action based on triage classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriageAction {
    /// No action required — pass.
    NoAction,
    /// Collect more samples before deciding.
    CollectMoreSamples,
    /// Re-run on stable hardware to confirm.
    RerunOnReference,
    /// Investigate recent commits in the owning crate.
    BisectCommits,
    /// Check environment factors (CPU governor, load, kernel).
    CheckEnvironment,
    /// Recalibrate thresholds using fresh CV% measurement.
    RecalibrateThresholds,
}

/// Complete triage classification for a single operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageDecision {
    /// Operation that triggered the guard.
    pub operation_id: String,
    /// Benchmark family (determines variance expectations).
    pub family: BenchmarkFamily,
    /// Root-cause classification.
    pub cause: TriageCause,
    /// Recommended next action.
    pub action: TriageAction,
    /// Human-readable explanation.
    pub rationale: String,
    /// Whether the operator should block the pipeline.
    pub should_block: bool,
    /// Reference to the runbook section.
    pub runbook_ref: String,
    /// Exact CLI command to confirm/reproduce the regression.
    ///
    /// Guard failures include a deterministic repro command so the operator
    /// can immediately rerun without reading the runbook.
    pub followup_command: String,
}

/// Build a deterministic follow-up command for a given operation and action.
fn followup_for(operation_id: &str, action: TriageAction) -> String {
    match action {
        TriageAction::NoAction => String::new(),
        TriageAction::CollectMoreSamples => {
            format!(
                "rch exec -- cargo bench -p ffs-harness -- {operation_id} && \
                 scripts/benchmark_record.sh --op {operation_id} --runs 10"
            )
        }
        TriageAction::RerunOnReference | TriageAction::CheckEnvironment => {
            format!(
                "rch exec -- scripts/benchmark_record.sh --op {operation_id} \
                 --runs 10 --compare-baseline"
            )
        }
        TriageAction::BisectCommits => {
            format!(
                "git log --oneline -10 -- crates/ && \
                 rch exec -- scripts/benchmark_record.sh --op {operation_id} --runs 10"
            )
        }
        TriageAction::RecalibrateThresholds => {
            format!(
                "rch exec -- scripts/benchmark_record.sh --op {operation_id} \
                 --runs 30 --out-json artifacts/baselines/recalibration_{operation_id}.json"
            )
        }
    }
}

/// Classify a comparison result into a triage decision.
///
/// This implements the decision tree from `docs/runbooks/perf-regression-triage.md`.
#[must_use]
pub fn classify_triage(
    result: &ComparisonResult,
    family: BenchmarkFamily,
    hysteresis: Option<HystereticVerdict>,
) -> TriageDecision {
    // Try early-exit branches (noise, inconclusive, not significant, negligible)
    if let Some(decision) = try_early_exit(result, family) {
        emit_triage_log(&decision, result);
        return decision;
    }

    // Branch 5: Warn or Fail — classify by family characteristics
    let (cause, action) = classify_by_family(family, result);
    let should_block = resolve_hysteresis_block(hysteresis, result.final_verdict);
    let hysteresis_note = hysteresis_label(hysteresis);
    let op = &result.operation_id;

    let decision = TriageDecision {
        operation_id: op.clone(),
        family,
        cause,
        action,
        rationale: format!(
            "{op}: {:?} — delta {:.1}%, effect {:.2} ({}), p={}{hysteresis_note}",
            result.final_verdict,
            result.delta_percent,
            result.effect_size,
            result.effect_label,
            format_p_value(result),
        ),
        should_block,
        runbook_ref: "docs/runbooks/perf-regression-triage.md#step-5".to_owned(),
        followup_command: followup_for(op, action),
    };
    emit_triage_log(&decision, result);
    decision
}

/// Try early-exit branches that short-circuit before family classification.
fn try_early_exit(result: &ComparisonResult, family: BenchmarkFamily) -> Option<TriageDecision> {
    let op = &result.operation_id;

    // Branch 1: noise floor
    if result.final_verdict == ComparisonVerdict::Pass
        && result.delta_percent.abs() <= noise_floor_for(family)
    {
        return Some(TriageDecision {
            operation_id: op.clone(),
            family,
            cause: TriageCause::Noise,
            action: TriageAction::NoAction,
            rationale: format!(
                "{op}: delta {:.1}% within noise floor ({:.0}%) — no action",
                result.delta_percent,
                noise_floor_for(family),
            ),
            should_block: false,
            runbook_ref: "docs/runbooks/perf-regression-triage.md#step-3".to_owned(),
            followup_command: followup_for(op, TriageAction::NoAction),
        });
    }

    // Branch 2: insufficient data
    if result.final_verdict == ComparisonVerdict::Inconclusive {
        return Some(TriageDecision {
            operation_id: op.clone(),
            family,
            cause: TriageCause::InsufficientData,
            action: TriageAction::CollectMoreSamples,
            rationale: format!(
                "{op}: insufficient samples (baseline={}, current={}) — collect more runs",
                result.baseline.n, result.current.n,
            ),
            should_block: false,
            runbook_ref: "docs/runbooks/perf-regression-triage.md#step-2".to_owned(),
            followup_command: followup_for(op, TriageAction::CollectMoreSamples),
        });
    }

    // Branch 3: not significant (Pass verdict from significance downgrade)
    if result.final_verdict == ComparisonVerdict::Pass && !result.significant {
        return Some(TriageDecision {
            operation_id: op.clone(),
            family,
            cause: TriageCause::NotSignificant,
            action: TriageAction::RerunOnReference,
            rationale: format!(
                "{op}: delta {:.1}% not statistically significant (p={}) — re-run to confirm",
                result.delta_percent,
                format_p_value(result),
            ),
            should_block: false,
            runbook_ref: "docs/runbooks/perf-regression-triage.md#step-3".to_owned(),
            followup_command: followup_for(op, TriageAction::RerunOnReference),
        });
    }

    // Branch 4: negligible effect size
    if result.final_verdict == ComparisonVerdict::Pass && result.effect_size.abs() < 0.2 {
        return Some(TriageDecision {
            operation_id: op.clone(),
            family,
            cause: TriageCause::NegligibleEffect,
            action: TriageAction::NoAction,
            rationale: format!(
                "{op}: effect size {:.2} ({}) — negligible practical impact",
                result.effect_size, result.effect_label,
            ),
            should_block: false,
            runbook_ref: "docs/runbooks/perf-regression-triage.md#step-3".to_owned(),
            followup_command: followup_for(op, TriageAction::NoAction),
        });
    }

    None
}

/// Format p-value from a comparison result.
fn format_p_value(result: &ComparisonResult) -> String {
    result
        .t_test
        .map_or_else(|| "N/A".to_owned(), |t| format!("{:.3}", t.p_value))
}

/// Determine whether hysteresis state warrants blocking the pipeline.
fn resolve_hysteresis_block(
    hysteresis: Option<HystereticVerdict>,
    verdict: ComparisonVerdict,
) -> bool {
    match hysteresis {
        Some(HystereticVerdict::ConfirmedFail) => true,
        Some(HystereticVerdict::ConfirmedWarn) => verdict == ComparisonVerdict::Fail,
        _ => false,
    }
}

/// Human-readable hysteresis state label for rationale strings.
fn hysteresis_label(hysteresis: Option<HystereticVerdict>) -> &'static str {
    match hysteresis {
        Some(HystereticVerdict::ConfirmedFail) => " [hysteresis: CONFIRMED]",
        Some(HystereticVerdict::ConfirmedWarn) => " [hysteresis: warn-confirmed]",
        Some(HystereticVerdict::EarlyWarning) => " [hysteresis: early-warning, monitor next run]",
        Some(HystereticVerdict::NoSignal) | None => "",
    }
}

/// Classify root cause and action based on benchmark family characteristics.
fn classify_by_family(
    family: BenchmarkFamily,
    result: &ComparisonResult,
) -> (TriageCause, TriageAction) {
    match family {
        // CPU-bound families with low expected variance → likely code regression
        BenchmarkFamily::Parser | BenchmarkFamily::Repair => {
            (TriageCause::CodeRegression, TriageAction::BisectCommits)
        }
        // High-variance families sensitive to environment
        BenchmarkFamily::Mount | BenchmarkFamily::Concurrency => {
            if result.current.cv_percent > 15.0 {
                (
                    TriageCause::ThresholdCalibration,
                    TriageAction::RecalibrateThresholds,
                )
            } else {
                (
                    TriageCause::EnvironmentChange,
                    TriageAction::CheckEnvironment,
                )
            }
        }
        // Intentionally stressed — widest thresholds, check pressure config
        BenchmarkFamily::DegradedMode => {
            if result.current.cv_percent > 20.0 {
                (
                    TriageCause::ThresholdCalibration,
                    TriageAction::RecalibrateThresholds,
                )
            } else {
                (
                    TriageCause::EnvironmentChange,
                    TriageAction::CheckEnvironment,
                )
            }
        }
        // Moderate variance families — context-dependent
        BenchmarkFamily::MetadataOps | BenchmarkFamily::BlockCache | BenchmarkFamily::WritePath => {
            if result.effect_size.abs() >= 0.8 {
                // Large effect → likely real code change
                (TriageCause::CodeRegression, TriageAction::BisectCommits)
            } else {
                // Moderate effect → could be environment or code
                (
                    TriageCause::EnvironmentChange,
                    TriageAction::RerunOnReference,
                )
            }
        }
    }
}

/// Default noise floor percentage for a given family.
fn noise_floor_for(family: BenchmarkFamily) -> f64 {
    family.default_envelope().noise_floor_percent
}

/// Emit a structured log event for the triage decision.
fn emit_triage_log(decision: &TriageDecision, result: &ComparisonResult) {
    info!(
        operation_id = %decision.operation_id,
        scenario_id = "perf_regression_triage",
        outcome = if decision.should_block { "rejected" } else { "completed" },
        family = %decision.family.label(),
        cause = ?decision.cause,
        action = ?decision.action,
        delta_percent = result.delta_percent,
        effect_size = result.effect_size,
        should_block = decision.should_block,
        runbook_ref = %decision.runbook_ref,
        followup_command = %decision.followup_command,
        "triage_decision"
    );
}

/// Validate that the triage runbook file exists at the expected path.
///
/// This is used by E2E tests to verify the runbook is deployed.
#[must_use]
pub fn runbook_path() -> &'static str {
    "docs/runbooks/perf-regression-triage.md"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::benchmark_taxonomy::EnvelopeVerdict;
    use crate::perf_comparison::{ComparisonVerdict, SampleStats, TTestResult};

    fn make_stats(n: usize, mean: f64, std_dev: f64) -> SampleStats {
        SampleStats {
            n,
            mean,
            std_dev,
            cv_percent: if mean.abs() > f64::EPSILON {
                (std_dev / mean.abs()) * 100.0
            } else {
                0.0
            },
            min: mean - std_dev,
            max: mean + std_dev,
            median: mean,
        }
    }

    fn noise_result(op: &str) -> ComparisonResult {
        ComparisonResult {
            operation_id: op.to_owned(),
            baseline: make_stats(10, 100.0, 2.0),
            current: make_stats(10, 101.0, 2.0),
            delta_percent: 1.0,
            effect_size: 0.05,
            effect_label: "negligible",
            t_test: Some(TTestResult {
                t_stat: 0.5,
                df: 18.0,
                p_value: 0.62,
            }),
            significant: false,
            envelope_verdict: EnvelopeVerdict::Noise,
            final_verdict: ComparisonVerdict::Pass,
            explanation: "within noise".to_owned(),
        }
    }

    fn inconclusive_result(op: &str) -> ComparisonResult {
        ComparisonResult {
            operation_id: op.to_owned(),
            baseline: make_stats(2, 100.0, 5.0),
            current: make_stats(2, 120.0, 5.0),
            delta_percent: 20.0,
            effect_size: 0.9,
            effect_label: "large",
            t_test: None,
            significant: false,
            envelope_verdict: EnvelopeVerdict::Warn,
            final_verdict: ComparisonVerdict::Inconclusive,
            explanation: "insufficient data".to_owned(),
        }
    }

    fn fail_result(op: &str) -> ComparisonResult {
        ComparisonResult {
            operation_id: op.to_owned(),
            baseline: make_stats(10, 100.0, 3.0),
            current: make_stats(10, 130.0, 3.0),
            delta_percent: 30.0,
            effect_size: 1.2,
            effect_label: "large",
            t_test: Some(TTestResult {
                t_stat: 4.5,
                df: 18.0,
                p_value: 0.0003,
            }),
            significant: true,
            envelope_verdict: EnvelopeVerdict::Fail,
            final_verdict: ComparisonVerdict::Fail,
            explanation: "confirmed regression".to_owned(),
        }
    }

    fn warn_result(op: &str) -> ComparisonResult {
        ComparisonResult {
            operation_id: op.to_owned(),
            baseline: make_stats(10, 100.0, 4.0),
            current: make_stats(10, 112.0, 4.0),
            delta_percent: 12.0,
            effect_size: 0.55,
            effect_label: "medium",
            t_test: Some(TTestResult {
                t_stat: 2.8,
                df: 18.0,
                p_value: 0.012,
            }),
            significant: true,
            envelope_verdict: EnvelopeVerdict::Warn,
            final_verdict: ComparisonVerdict::Warn,
            explanation: "possible regression".to_owned(),
        }
    }

    fn not_significant_pass_result(op: &str) -> ComparisonResult {
        ComparisonResult {
            operation_id: op.to_owned(),
            baseline: make_stats(10, 100.0, 8.0),
            current: make_stats(10, 108.0, 8.0),
            delta_percent: 8.0,
            effect_size: 0.35,
            effect_label: "small",
            t_test: Some(TTestResult {
                t_stat: 1.2,
                df: 18.0,
                p_value: 0.24,
            }),
            significant: false,
            envelope_verdict: EnvelopeVerdict::Ok,
            final_verdict: ComparisonVerdict::Pass,
            explanation: "not significant — downgraded".to_owned(),
        }
    }

    // ── Happy path tests ──────────────────────────────────────────────────

    #[test]
    fn triage_noise_returns_no_action() {
        let result = noise_result("metadata_parity_cli");
        let decision = classify_triage(&result, BenchmarkFamily::MetadataOps, None);
        assert_eq!(decision.cause, TriageCause::Noise);
        assert_eq!(decision.action, TriageAction::NoAction);
        assert!(!decision.should_block);
    }

    #[test]
    fn triage_inconclusive_requests_more_samples() {
        let result = inconclusive_result("mount_cold");
        let decision = classify_triage(&result, BenchmarkFamily::Mount, None);
        assert_eq!(decision.cause, TriageCause::InsufficientData);
        assert_eq!(decision.action, TriageAction::CollectMoreSamples);
        assert!(!decision.should_block);
    }

    #[test]
    fn triage_fail_parser_recommends_bisect() {
        let result = fail_result("ext4_superblock_parse");
        let decision = classify_triage(
            &result,
            BenchmarkFamily::Parser,
            Some(HystereticVerdict::ConfirmedFail),
        );
        assert_eq!(decision.cause, TriageCause::CodeRegression);
        assert_eq!(decision.action, TriageAction::BisectCommits);
        assert!(decision.should_block);
    }

    #[test]
    fn triage_fail_mount_checks_environment() {
        let result = fail_result("mount_cold");
        let decision = classify_triage(
            &result,
            BenchmarkFamily::Mount,
            Some(HystereticVerdict::ConfirmedFail),
        );
        assert_eq!(decision.cause, TriageCause::EnvironmentChange);
        assert_eq!(decision.action, TriageAction::CheckEnvironment);
        assert!(decision.should_block);
    }

    #[test]
    fn triage_warn_without_hysteresis_does_not_block() {
        let result = warn_result("block_cache_arc_scan");
        let decision = classify_triage(
            &result,
            BenchmarkFamily::BlockCache,
            Some(HystereticVerdict::EarlyWarning),
        );
        assert!(!decision.should_block);
        assert!(decision.rationale.contains("early-warning"));
    }

    #[test]
    fn triage_not_significant_pass_suggests_rerun() {
        let result = not_significant_pass_result("write_seq_4k");
        let decision = classify_triage(&result, BenchmarkFamily::WritePath, None);
        assert_eq!(decision.cause, TriageCause::NotSignificant);
        assert_eq!(decision.action, TriageAction::RerunOnReference);
        assert!(!decision.should_block);
    }

    // ── Edge case tests ───────────────────────────────────────────────────

    #[test]
    fn triage_high_cv_mount_suggests_recalibration() {
        let mut result = fail_result("mount_recovery");
        result.current = make_stats(10, 130.0, 25.0); // CV ~19%
        let decision = classify_triage(
            &result,
            BenchmarkFamily::Mount,
            Some(HystereticVerdict::ConfirmedFail),
        );
        assert_eq!(decision.cause, TriageCause::ThresholdCalibration);
        assert_eq!(decision.action, TriageAction::RecalibrateThresholds);
    }

    #[test]
    fn triage_large_effect_metadata_recommends_bisect() {
        let result = fail_result("metadata_parity_cli");
        // effect_size is 1.2 (large) → code regression path
        let decision = classify_triage(
            &result,
            BenchmarkFamily::MetadataOps,
            Some(HystereticVerdict::ConfirmedFail),
        );
        assert_eq!(decision.cause, TriageCause::CodeRegression);
        assert_eq!(decision.action, TriageAction::BisectCommits);
    }

    // ── Negative/invariant tests ──────────────────────────────────────────

    #[test]
    fn triage_version_is_positive() {
        const { assert!(TRIAGE_VERSION >= 1) };
    }

    #[test]
    fn triage_all_families_produce_valid_decisions() {
        let families = [
            BenchmarkFamily::Parser,
            BenchmarkFamily::Mount,
            BenchmarkFamily::MetadataOps,
            BenchmarkFamily::BlockCache,
            BenchmarkFamily::WritePath,
            BenchmarkFamily::Concurrency,
            BenchmarkFamily::Repair,
            BenchmarkFamily::DegradedMode,
        ];
        let result = fail_result("test_op");
        for family in families {
            let decision = classify_triage(&result, family, None);
            // Every decision must have a non-empty rationale and valid runbook ref
            assert!(
                !decision.rationale.is_empty(),
                "empty rationale for {family:?}"
            );
            assert!(
                decision.runbook_ref.starts_with("docs/runbooks/"),
                "bad runbook ref for {family:?}",
            );
        }
    }

    #[test]
    fn triage_runbook_path_is_stable() {
        assert_eq!(runbook_path(), "docs/runbooks/perf-regression-triage.md");
    }

    #[test]
    fn triage_decision_round_trips_through_json() {
        let result = fail_result("test_op");
        let decision = classify_triage(&result, BenchmarkFamily::Parser, None);
        let json = serde_json::to_string(&decision).expect("serialize");
        let parsed: TriageDecision = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.operation_id, decision.operation_id);
        assert_eq!(parsed.cause, decision.cause);
        assert_eq!(parsed.action, decision.action);
    }

    #[test]
    fn triage_confirmed_fail_blocks_confirmed_warn_does_not_for_warn_verdict() {
        let result = warn_result("test_op");
        // ConfirmedWarn + Warn verdict → should_block is false (only blocks on Fail verdict)
        let decision_confirmed_warn = classify_triage(
            &result,
            BenchmarkFamily::MetadataOps,
            Some(HystereticVerdict::ConfirmedWarn),
        );
        assert!(!decision_confirmed_warn.should_block);

        // ConfirmedFail always blocks regardless of verdict
        let decision_confirmed_fail = classify_triage(
            &result,
            BenchmarkFamily::MetadataOps,
            Some(HystereticVerdict::ConfirmedFail),
        );
        assert!(decision_confirmed_fail.should_block);
    }

    #[test]
    fn triage_followup_command_nonempty_for_actionable_decisions() {
        // Fail → bisect → non-empty followup
        let result = fail_result("scrub_clean");
        let decision = classify_triage(&result, BenchmarkFamily::Parser, None);
        assert!(
            !decision.followup_command.is_empty(),
            "BisectCommits should have a followup command"
        );
        assert!(
            decision.followup_command.contains("scrub_clean"),
            "followup must reference the failing operation"
        );
    }

    #[test]
    fn triage_followup_command_empty_for_noise() {
        let result = noise_result("metadata_parity_cli");
        let decision = classify_triage(&result, BenchmarkFamily::Parser, None);
        assert!(
            decision.followup_command.is_empty(),
            "NoAction should have empty followup command"
        );
    }

    #[test]
    fn triage_followup_command_contains_benchmark_record_for_collect_more() {
        let result = inconclusive_result("wal_commit");
        let decision = classify_triage(&result, BenchmarkFamily::Concurrency, None);
        assert_eq!(decision.action, TriageAction::CollectMoreSamples);
        assert!(
            decision.followup_command.contains("benchmark_record"),
            "CollectMoreSamples followup should reference benchmark_record.sh"
        );
    }

    #[test]
    fn triage_followup_includes_runs_count() {
        let result = fail_result("block_cache_arc_scan");
        let decision = classify_triage(&result, BenchmarkFamily::MetadataOps, None);
        assert!(
            decision.followup_command.contains("--runs"),
            "followup command should specify --runs for reproducibility"
        );
    }

    #[test]
    fn triage_decision_json_includes_followup_command() {
        let result = fail_result("test_op");
        let decision = classify_triage(&result, BenchmarkFamily::Parser, None);
        let json = serde_json::to_string(&decision).expect("serialize");
        assert!(
            json.contains("followup_command"),
            "JSON must include followup_command field"
        );
    }
}
