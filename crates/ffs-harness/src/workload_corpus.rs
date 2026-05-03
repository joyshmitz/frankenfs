#![allow(clippy::too_many_lines)]

//! Versioned P1 workload corpus validation for `bd-rchk0.5.7.1`.
//!
//! The corpus is the shared proof substrate for user-risk scenarios consumed by
//! invariant, mounted differential, repair, crash/replay, proof-bundle, and
//! release-gate workflows.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub const WORKLOAD_CORPUS_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_WORKLOAD_CORPUS_PATH: &str = "tests/workload-corpus/p1_workload_corpus.json";

const REQUIRED_SCENARIO_STATUSES: [WorkloadScenarioStatus; 4] = [
    WorkloadScenarioStatus::Positive,
    WorkloadScenarioStatus::Negative,
    WorkloadScenarioStatus::Unsupported,
    WorkloadScenarioStatus::HostSkip,
];

struct CorpusVocabularies<'a> {
    user_risks: BTreeSet<&'a str>,
    operations: BTreeSet<&'a str>,
    filesystems: BTreeSet<&'a str>,
    capabilities: BTreeSet<&'a str>,
    proof_consumers: BTreeSet<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadCorpus {
    pub schema_version: u32,
    pub corpus_id: String,
    pub corpus_version: String,
    pub bead_id: String,
    pub scenario_id_regex: String,
    pub user_risks: Vec<String>,
    pub operation_classes: Vec<String>,
    pub filesystem_flavors: Vec<String>,
    pub capability_vocabulary: Vec<String>,
    pub proof_consumers: Vec<String>,
    pub scenarios: Vec<WorkloadScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadScenario {
    pub scenario_id: String,
    pub title: String,
    pub status: WorkloadScenarioStatus,
    pub user_risk: String,
    pub operation_class: String,
    pub supported_filesystems: Vec<String>,
    pub required_capabilities: Vec<String>,
    pub expected_artifacts: Vec<ExpectedWorkloadArtifact>,
    pub expected_logs: Vec<ExpectedWorkloadLog>,
    pub linked_proof_consumers: Vec<String>,
    pub linked_e2e_suites: Vec<String>,
    pub reproduction_command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsupported_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_skip_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follow_up_bead: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub non_goal_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedWorkloadArtifact {
    pub path: String,
    pub kind: String,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedWorkloadLog {
    pub marker: String,
    pub required_fields: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadScenarioStatus {
    Positive,
    Negative,
    Unsupported,
    HostSkip,
}

impl WorkloadScenarioStatus {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Positive => "positive",
            Self::Negative => "negative",
            Self::Unsupported => "unsupported",
            Self::HostSkip => "host_skip",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadCorpusValidationReport {
    pub schema_version: u32,
    pub corpus_id: String,
    pub corpus_version: String,
    pub bead_id: String,
    pub valid: bool,
    pub scenario_count: usize,
    pub status_counts: BTreeMap<String, usize>,
    pub by_user_risk: BTreeMap<String, usize>,
    pub by_filesystem_flavor: BTreeMap<String, usize>,
    pub by_proof_consumer: BTreeMap<String, usize>,
    pub proof_bundle_coverage: WorkloadProofBundleCoverage,
    pub duplicate_scenario_ids: Vec<String>,
    pub missing_required_statuses: Vec<String>,
    pub host_skip_scenarios: Vec<String>,
    pub btrfs_default_permissions_scenarios: Vec<String>,
    pub scenario_logs: Vec<WorkloadScenarioLog>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadProofBundleCoverage {
    pub scenario_ids: Vec<String>,
    pub by_user_risk: BTreeMap<String, usize>,
    pub by_filesystem_flavor: BTreeMap<String, usize>,
    pub ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadScenarioLog {
    pub scenario_id: String,
    pub status: WorkloadScenarioStatus,
    pub user_risk: String,
    pub filesystem_flavors: Vec<String>,
    pub proof_consumers: Vec<String>,
    pub reproduction_command: String,
    pub log_line: String,
}

pub fn load_workload_corpus(path: &Path) -> Result<WorkloadCorpus> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read workload corpus {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("invalid workload corpus JSON {}", path.display()))
}

#[must_use]
pub fn validate_workload_corpus(corpus: &WorkloadCorpus) -> WorkloadCorpusValidationReport {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut duplicate_scenario_ids = Vec::new();
    let mut scenario_ids = BTreeMap::<&str, usize>::new();
    let mut status_counts = BTreeMap::<String, usize>::new();
    let mut by_user_risk = BTreeMap::<String, usize>::new();
    let mut by_filesystem_flavor = BTreeMap::<String, usize>::new();
    let mut by_proof_consumer = BTreeMap::<String, usize>::new();
    let mut host_skip_scenarios = Vec::new();
    let mut btrfs_default_permissions_scenarios = Vec::new();
    let mut scenario_logs = Vec::new();

    validate_header(corpus, &mut errors);

    let vocabularies = CorpusVocabularies {
        user_risks: corpus.user_risks.iter().map(String::as_str).collect(),
        operations: corpus
            .operation_classes
            .iter()
            .map(String::as_str)
            .collect(),
        filesystems: corpus
            .filesystem_flavors
            .iter()
            .map(String::as_str)
            .collect(),
        capabilities: corpus
            .capability_vocabulary
            .iter()
            .map(String::as_str)
            .collect(),
        proof_consumers: corpus.proof_consumers.iter().map(String::as_str).collect(),
    };

    for scenario in &corpus.scenarios {
        *scenario_ids
            .entry(scenario.scenario_id.as_str())
            .or_default() += 1;
        *status_counts
            .entry(scenario.status.label().to_owned())
            .or_default() += 1;
        *by_user_risk.entry(scenario.user_risk.clone()).or_default() += 1;
        for filesystem in &scenario.supported_filesystems {
            *by_filesystem_flavor.entry(filesystem.clone()).or_default() += 1;
        }
        for consumer in &scenario.linked_proof_consumers {
            *by_proof_consumer.entry(consumer.clone()).or_default() += 1;
        }
        if scenario.status == WorkloadScenarioStatus::HostSkip {
            host_skip_scenarios.push(scenario.scenario_id.clone());
        }
        if scenario.scenario_id.contains("btrfs_default_permissions")
            || scenario
                .title
                .to_ascii_lowercase()
                .contains("defaultpermissions")
        {
            btrfs_default_permissions_scenarios.push(scenario.scenario_id.clone());
        }
        validate_scenario(scenario, &vocabularies, &mut errors, &mut warnings);
        scenario_logs.push(build_scenario_log(scenario));
    }

    for (scenario_id, count) in scenario_ids {
        if count > 1 {
            duplicate_scenario_ids.push(scenario_id.to_owned());
        }
    }
    for duplicate in &duplicate_scenario_ids {
        errors.push(format!("duplicate scenario_id {duplicate}"));
    }

    let missing_required_statuses = REQUIRED_SCENARIO_STATUSES
        .iter()
        .filter_map(|status| {
            let label = status.label();
            (!status_counts.contains_key(label)).then(|| label.to_owned())
        })
        .collect::<Vec<_>>();
    for status in &missing_required_statuses {
        errors.push(format!("missing required scenario status {status}"));
    }

    if host_skip_scenarios.is_empty() {
        errors.push("corpus must include at least one host capability skip scenario".to_owned());
    }
    if btrfs_default_permissions_scenarios.is_empty() {
        errors.push(
            "corpus must include a btrfs DefaultPermissions image-ownership diagnostic scenario"
                .to_owned(),
        );
    }

    let proof_bundle_coverage = summarize_proof_bundle_coverage(corpus);
    if !proof_bundle_coverage.ready {
        errors.push(
            "proof_bundle consumer must cover at least one user risk and filesystem flavor"
                .to_owned(),
        );
    }

    WorkloadCorpusValidationReport {
        schema_version: corpus.schema_version,
        corpus_id: corpus.corpus_id.clone(),
        corpus_version: corpus.corpus_version.clone(),
        bead_id: corpus.bead_id.clone(),
        valid: errors.is_empty(),
        scenario_count: corpus.scenarios.len(),
        status_counts,
        by_user_risk,
        by_filesystem_flavor,
        by_proof_consumer,
        proof_bundle_coverage,
        duplicate_scenario_ids,
        missing_required_statuses,
        host_skip_scenarios,
        btrfs_default_permissions_scenarios,
        scenario_logs,
        errors,
        warnings,
    }
}

pub fn fail_on_workload_corpus_errors(report: &WorkloadCorpusValidationReport) -> Result<()> {
    if report.valid {
        return Ok(());
    }
    bail!(
        "workload corpus validation failed: {}",
        report.errors.join("; ")
    )
}

#[must_use]
pub fn render_workload_corpus_markdown(report: &WorkloadCorpusValidationReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Workload Corpus Validation");
    let _ = writeln!(out);
    let _ = writeln!(out, "- corpus: `{}`", report.corpus_id);
    let _ = writeln!(out, "- version: `{}`", report.corpus_version);
    let _ = writeln!(out, "- bead: `{}`", report.bead_id);
    let _ = writeln!(out, "- valid: `{}`", report.valid);
    let _ = writeln!(out, "- scenarios: `{}`", report.scenario_count);
    let _ = writeln!(out);
    render_counts(&mut out, "Status Coverage", &report.status_counts);
    render_counts(&mut out, "User Risk Coverage", &report.by_user_risk);
    render_counts(
        &mut out,
        "Filesystem Coverage",
        &report.by_filesystem_flavor,
    );
    render_counts(
        &mut out,
        "Proof Consumer Coverage",
        &report.by_proof_consumer,
    );
    let _ = writeln!(out, "## Scenario Logs");
    for log in &report.scenario_logs {
        let _ = writeln!(out, "- `{}`", log.log_line);
    }
    out
}

fn render_counts(out: &mut String, title: &str, counts: &BTreeMap<String, usize>) {
    let _ = writeln!(out, "## {title}");
    for (key, count) in counts {
        let _ = writeln!(out, "- `{key}`: `{count}`");
    }
    let _ = writeln!(out);
}

fn validate_header(corpus: &WorkloadCorpus, errors: &mut Vec<String>) {
    if corpus.schema_version != WORKLOAD_CORPUS_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version must be {WORKLOAD_CORPUS_SCHEMA_VERSION}, got {}",
            corpus.schema_version
        ));
    }
    validate_nonempty("corpus_id", &corpus.corpus_id, errors);
    validate_nonempty("corpus_version", &corpus.corpus_version, errors);
    validate_nonempty("bead_id", &corpus.bead_id, errors);
    validate_nonempty("scenario_id_regex", &corpus.scenario_id_regex, errors);
    validate_nonempty_vec("user_risks", &corpus.user_risks, errors);
    validate_nonempty_vec("operation_classes", &corpus.operation_classes, errors);
    validate_nonempty_vec("filesystem_flavors", &corpus.filesystem_flavors, errors);
    validate_nonempty_vec(
        "capability_vocabulary",
        &corpus.capability_vocabulary,
        errors,
    );
    validate_nonempty_vec("proof_consumers", &corpus.proof_consumers, errors);
    if corpus.scenarios.is_empty() {
        errors.push("scenarios must not be empty".to_owned());
    }
}

fn validate_scenario(
    scenario: &WorkloadScenario,
    vocabularies: &CorpusVocabularies<'_>,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    validate_stable_scenario_id(&scenario.scenario_id, errors);
    validate_nonempty("scenario.title", &scenario.title, errors);
    validate_member(
        "user_risk",
        &scenario.user_risk,
        &vocabularies.user_risks,
        &scenario.scenario_id,
        errors,
    );
    validate_member(
        "operation_class",
        &scenario.operation_class,
        &vocabularies.operations,
        &scenario.scenario_id,
        errors,
    );
    validate_members(
        "supported_filesystems",
        &scenario.supported_filesystems,
        &vocabularies.filesystems,
        &scenario.scenario_id,
        errors,
    );
    validate_members(
        "required_capabilities",
        &scenario.required_capabilities,
        &vocabularies.capabilities,
        &scenario.scenario_id,
        errors,
    );
    validate_members(
        "linked_proof_consumers",
        &scenario.linked_proof_consumers,
        &vocabularies.proof_consumers,
        &scenario.scenario_id,
        errors,
    );
    if scenario.linked_proof_consumers.len() < 2 {
        errors.push(format!(
            "scenario {} must be reusable by at least two proof consumers",
            scenario.scenario_id
        ));
    }
    validate_artifacts(scenario, errors);
    validate_logs(scenario, errors);
    validate_nonempty(
        "reproduction_command",
        &scenario.reproduction_command,
        errors,
    );
    if scenario.linked_e2e_suites.is_empty() {
        errors.push(format!(
            "scenario {} must link at least one E2E suite",
            scenario.scenario_id
        ));
    }
    validate_status_specific_fields(scenario, errors, warnings);
}

fn validate_stable_scenario_id(scenario_id: &str, errors: &mut Vec<String>) {
    if scenario_id.is_empty() {
        errors.push("scenario_id must not be empty".to_owned());
        return;
    }
    let segments = scenario_id.split('_').collect::<Vec<_>>();
    let valid = segments.len() >= 3
        && scenario_id
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_lowercase())
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && segment
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
        });
    if !valid {
        errors.push(format!(
            "scenario_id {scenario_id} must be lowercase snake-case with at least three segments"
        ));
    }
}

fn validate_artifacts(scenario: &WorkloadScenario, errors: &mut Vec<String>) {
    if scenario.expected_artifacts.is_empty() {
        errors.push(format!(
            "scenario {} must declare expected_artifacts",
            scenario.scenario_id
        ));
    }
    for artifact in &scenario.expected_artifacts {
        validate_nonempty("artifact.path", &artifact.path, errors);
        validate_nonempty("artifact.kind", &artifact.kind, errors);
    }
    if !scenario
        .expected_artifacts
        .iter()
        .any(|artifact| artifact.required)
    {
        errors.push(format!(
            "scenario {} must have at least one required artifact",
            scenario.scenario_id
        ));
    }
}

fn validate_logs(scenario: &WorkloadScenario, errors: &mut Vec<String>) {
    if scenario.expected_logs.is_empty() {
        errors.push(format!(
            "scenario {} must declare expected_logs",
            scenario.scenario_id
        ));
    }
    for log in &scenario.expected_logs {
        validate_nonempty("log.marker", &log.marker, errors);
        validate_nonempty_vec("log.required_fields", &log.required_fields, errors);
        for required in ["scenario_id", "reproduction_command"] {
            if !log.required_fields.iter().any(|field| field == required) {
                errors.push(format!(
                    "scenario {} log {} missing required field {required}",
                    scenario.scenario_id, log.marker
                ));
            }
        }
    }
}

fn validate_status_specific_fields(
    scenario: &WorkloadScenario,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    match scenario.status {
        WorkloadScenarioStatus::Positive => {
            if scenario.follow_up_bead.is_some() {
                warnings.push(format!(
                    "positive scenario {} carries follow_up_bead",
                    scenario.scenario_id
                ));
            }
        }
        WorkloadScenarioStatus::Negative => {
            require_follow_up_or_non_goal(scenario, errors);
        }
        WorkloadScenarioStatus::Unsupported => {
            validate_optional_nonempty(
                "unsupported_reason",
                scenario.unsupported_reason.as_deref(),
                &scenario.scenario_id,
                errors,
            );
            require_follow_up_or_non_goal(scenario, errors);
        }
        WorkloadScenarioStatus::HostSkip => {
            validate_optional_nonempty(
                "host_skip_reason",
                scenario.host_skip_reason.as_deref(),
                &scenario.scenario_id,
                errors,
            );
            if !scenario
                .required_capabilities
                .iter()
                .any(|capability| capability.contains("fuse") || capability.contains("host"))
            {
                errors.push(format!(
                    "host-skip scenario {} must require a host or FUSE capability",
                    scenario.scenario_id
                ));
            }
        }
    }
}

fn require_follow_up_or_non_goal(scenario: &WorkloadScenario, errors: &mut Vec<String>) {
    let has_follow_up = scenario
        .follow_up_bead
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    let has_non_goal = scenario
        .non_goal_reason
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    if !has_follow_up && !has_non_goal {
        errors.push(format!(
            "scenario {} must declare follow_up_bead or non_goal_reason",
            scenario.scenario_id
        ));
    }
}

fn summarize_proof_bundle_coverage(corpus: &WorkloadCorpus) -> WorkloadProofBundleCoverage {
    let mut scenario_ids = Vec::new();
    let mut by_user_risk = BTreeMap::<String, usize>::new();
    let mut by_filesystem_flavor = BTreeMap::<String, usize>::new();

    for scenario in &corpus.scenarios {
        if !scenario
            .linked_proof_consumers
            .iter()
            .any(|consumer| consumer == "proof_bundle")
        {
            continue;
        }
        scenario_ids.push(scenario.scenario_id.clone());
        *by_user_risk.entry(scenario.user_risk.clone()).or_default() += 1;
        for filesystem in &scenario.supported_filesystems {
            *by_filesystem_flavor.entry(filesystem.clone()).or_default() += 1;
        }
    }

    WorkloadProofBundleCoverage {
        ready: !scenario_ids.is_empty()
            && !by_user_risk.is_empty()
            && by_filesystem_flavor.len() >= 2,
        scenario_ids,
        by_user_risk,
        by_filesystem_flavor,
    }
}

fn build_scenario_log(scenario: &WorkloadScenario) -> WorkloadScenarioLog {
    let proof_consumers = scenario.linked_proof_consumers.join(",");
    let filesystem_flavors = scenario.supported_filesystems.join(",");
    let log_line = format!(
        "WORKLOAD_CORPUS_SCENARIO|scenario_id={}|status={}|user_risk={}|filesystems={}|proof_consumers={}|reproduction_command={}",
        scenario.scenario_id,
        scenario.status.label(),
        scenario.user_risk,
        filesystem_flavors,
        proof_consumers,
        scenario.reproduction_command
    );
    WorkloadScenarioLog {
        scenario_id: scenario.scenario_id.clone(),
        status: scenario.status,
        user_risk: scenario.user_risk.clone(),
        filesystem_flavors: scenario.supported_filesystems.clone(),
        proof_consumers: scenario.linked_proof_consumers.clone(),
        reproduction_command: scenario.reproduction_command.clone(),
        log_line,
    }
}

fn validate_nonempty(field: &str, value: &str, errors: &mut Vec<String>) {
    if value.trim().is_empty() {
        errors.push(format!("{field} must not be empty"));
    }
}

fn validate_nonempty_vec(field: &str, values: &[String], errors: &mut Vec<String>) {
    if values.is_empty() {
        errors.push(format!("{field} must not be empty"));
    }
    for value in values {
        if value.trim().is_empty() {
            errors.push(format!("{field} must not contain empty values"));
        }
    }
}

fn validate_optional_nonempty(
    field: &str,
    value: Option<&str>,
    scenario_id: &str,
    errors: &mut Vec<String>,
) {
    if value.is_none_or(|raw| raw.trim().is_empty()) {
        errors.push(format!("scenario {scenario_id} must declare {field}"));
    }
}

fn validate_member(
    field: &str,
    value: &str,
    vocabulary: &BTreeSet<&str>,
    scenario_id: &str,
    errors: &mut Vec<String>,
) {
    if !vocabulary.contains(value) {
        errors.push(format!(
            "scenario {scenario_id} {field} references unknown value {value}"
        ));
    }
}

fn validate_members(
    field: &str,
    values: &[String],
    vocabulary: &BTreeSet<&str>,
    scenario_id: &str,
    errors: &mut Vec<String>,
) {
    if values.is_empty() {
        errors.push(format!("scenario {scenario_id} {field} must not be empty"));
    }
    for value in values {
        validate_member(field, value, vocabulary, scenario_id, errors);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_corpus() -> WorkloadCorpus {
        serde_json::from_str(include_str!(
            "../../../tests/workload-corpus/p1_workload_corpus.json"
        ))
        .expect("checked-in corpus is valid JSON")
    }

    #[test]
    fn checked_in_corpus_validates_required_contract() {
        let corpus = fixture_corpus();
        let report = validate_workload_corpus(&corpus);
        assert!(report.valid, "{:?}", report.errors);
        assert!(report.scenario_count >= 11);
        for status in ["positive", "negative", "unsupported", "host_skip"] {
            assert!(report.status_counts.contains_key(status));
        }
        assert!(!report.host_skip_scenarios.is_empty());
        assert!(!report.btrfs_default_permissions_scenarios.is_empty());
        assert!(report.proof_bundle_coverage.ready);
    }

    #[test]
    fn rejects_duplicate_scenario_ids() {
        let mut corpus = fixture_corpus();
        corpus.scenarios[1].scenario_id = corpus.scenarios[0].scenario_id.clone();
        let report = validate_workload_corpus(&corpus);
        assert!(!report.valid);
        assert_eq!(report.duplicate_scenario_ids.len(), 1);
    }

    #[test]
    fn rejects_unknown_capability_tags() {
        let mut corpus = fixture_corpus();
        corpus.scenarios[0]
            .required_capabilities
            .push("unknown_capability".to_owned());
        let report = validate_workload_corpus(&corpus);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("unknown_capability"))
        );
    }

    #[test]
    fn rejects_missing_user_risk_field() {
        let mut corpus = fixture_corpus();
        corpus.scenarios[0].user_risk.clear();
        let report = validate_workload_corpus(&corpus);
        assert!(!report.valid);
        assert!(report.errors.iter().any(|error| {
            error.contains("user_risk") && error.contains("references unknown value")
        }));
    }

    #[test]
    fn rejects_missing_required_artifact_declarations() {
        let mut corpus = fixture_corpus();
        corpus.scenarios[0].expected_artifacts.clear();
        let report = validate_workload_corpus(&corpus);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("expected_artifacts"))
        );
    }

    #[test]
    fn rejects_unsupported_without_classification() {
        let mut corpus = fixture_corpus();
        let scenario = corpus
            .scenarios
            .iter_mut()
            .find(|scenario| scenario.status == WorkloadScenarioStatus::Unsupported)
            .expect("fixture has unsupported scenario");
        scenario.unsupported_reason = None;
        scenario.follow_up_bead = None;
        scenario.non_goal_reason = None;
        let report = validate_workload_corpus(&corpus);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("unsupported_reason"))
        );
    }

    #[test]
    fn rejects_host_skip_without_host_capability() {
        let mut corpus = fixture_corpus();
        let scenario = corpus
            .scenarios
            .iter_mut()
            .find(|scenario| scenario.status == WorkloadScenarioStatus::HostSkip)
            .expect("fixture has host skip scenario");
        scenario.required_capabilities = vec!["metadata_ops".to_owned()];
        let report = validate_workload_corpus(&corpus);
        assert!(!report.valid);
        assert!(report.errors.iter().any(|error| {
            error.contains("host-skip") && error.contains("host or FUSE capability")
        }));
    }
}
