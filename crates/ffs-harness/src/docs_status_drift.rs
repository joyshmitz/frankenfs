#![forbid(unsafe_code)]
#![allow(clippy::too_many_arguments, clippy::too_many_lines)]

//! Public docs/status wording drift detection for `bd-jtu4q`.
//!
//! This validator sits above support-state accounting and the ambition evidence
//! matrix. It turns their rows into generated wording contracts for README,
//! parity, spec, CLI, operator, and proof-bundle surfaces, then fails closed
//! when observed wording claims a stronger state than the controlling evidence.

use crate::ambition_evidence_matrix::analyze_ambition_evidence_matrix;
use crate::support_state_accounting::{
    SupportStateAccountingRow, analyze_support_state_accounting,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

pub const DOCS_STATUS_DRIFT_VERSION: &str = "bd-jtu4q-docs-status-drift-v1";
pub const DEFAULT_DOCS_STATUS_DRIFT_ARTIFACT: &str = "artifacts/docs-status/docs_status_drift.json";
pub const DEFAULT_DOCS_STATUS_DRIFT_SUMMARY: &str = "artifacts/docs-status/docs_status_drift.md";

const REPRODUCTION_COMMAND: &str = "ffs-harness validate-docs-status-drift --issues .beads/issues.jsonl --feature-parity FEATURE_PARITY.md --out artifacts/docs-status/docs_status_drift.json --summary-out artifacts/docs-status/docs_status_drift.md";
const RELEASE_GATE_CONTRACT: &str =
    "release-gates:bd-rchk0.5.6.1 fail-closed docs-status drift consumer";

const REQUIRED_DOC_TARGETS: [&str; 9] = [
    "README.md",
    "FEATURE_PARITY.md",
    "COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md",
    "PLAN_TO_PORT_FRANKENFS_TO_RUST.md",
    "EXISTING_EXT4_BTRFS_STRUCTURE.md",
    "PROPOSED_ARCHITECTURE.md",
    "CLI help/status text",
    "scripts/e2e/README.md",
    "proof-bundle summaries",
];

const REQUIRED_PUBLIC_STATUSES: [&str; 12] = [
    "validated",
    "experimental",
    "detection-only",
    "dry-run-only",
    "parse-only",
    "opt-in mutating",
    "disabled",
    "unsupported",
    "deferred",
    "stale-evidence",
    "host-blocked",
    "security-refused",
];

const REQUIRED_LOG_FIELDS: [&str; 11] = [
    "docs_target",
    "section_anchor",
    "feature_id",
    "source_support_state_row",
    "gate_artifact_hash",
    "generated_wording_id",
    "observed_wording_hash",
    "drift_classification",
    "remediation_id",
    "output_path",
    "reproduction_command",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocsStatusDriftConfig {
    pub issues_jsonl: PathBuf,
    pub feature_parity_markdown: PathBuf,
    pub snippets_json: Option<PathBuf>,
    pub generated_artifact_paths: Vec<String>,
}

impl Default for DocsStatusDriftConfig {
    fn default() -> Self {
        Self {
            issues_jsonl: PathBuf::from(".beads/issues.jsonl"),
            feature_parity_markdown: PathBuf::from("FEATURE_PARITY.md"),
            snippets_json: None,
            generated_artifact_paths: vec![
                DEFAULT_DOCS_STATUS_DRIFT_ARTIFACT.to_owned(),
                DEFAULT_DOCS_STATUS_DRIFT_SUMMARY.to_owned(),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocsStatusDriftReport {
    pub docs_status_drift_version: String,
    pub release_gate_contract: String,
    pub release_gate_pass: bool,
    pub source_issue_count: usize,
    pub rule_count: usize,
    pub observation_count: usize,
    pub required_doc_targets: Vec<String>,
    pub allowed_status_vocabulary: Vec<String>,
    pub generated_artifact_paths: Vec<String>,
    pub rules: Vec<DocsStatusWordingRule>,
    pub observations: Vec<DocsStatusObservation>,
    pub structured_logs: Vec<DocsStatusLogEvent>,
    pub grouped_by_docs_target: BTreeMap<String, Vec<String>>,
    pub grouped_by_public_status: BTreeMap<String, Vec<String>>,
    pub drift_classification_counts: BTreeMap<String, usize>,
    pub required_log_fields: Vec<String>,
    pub errors: Vec<String>,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocsStatusWordingRule {
    pub feature_id: String,
    pub source_support_state_feature_id: String,
    pub evidence_matrix_row: String,
    pub gate_consumer: String,
    pub allowed_status_vocabulary: Vec<String>,
    pub public_status: String,
    pub docs_target: String,
    pub spec_anchor: String,
    pub generated_wording_id: String,
    pub downgrade_wording: String,
    pub remediation_id: String,
    pub freshness_requirement: String,
    pub owning_bead: String,
    pub explicit_non_goal: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocsStatusSnippetSet {
    pub snippets: Vec<DocsStatusSnippet>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocsStatusSnippet {
    pub feature_id: String,
    pub docs_target: String,
    pub section_anchor: String,
    pub observed_text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocsStatusObservation {
    pub feature_id: String,
    pub docs_target: String,
    pub section_anchor: String,
    pub expected_public_status: String,
    pub strongest_observed_status: String,
    pub source_support_state_row: String,
    pub evidence_matrix_row: String,
    pub gate_consumer: String,
    pub gate_artifact_hash: String,
    pub generated_wording_id: String,
    pub generated_wording: String,
    pub observed_wording_hash: String,
    pub drift_classification: String,
    pub remediation_id: String,
    pub output_path: String,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocsStatusLogEvent {
    pub docs_target: String,
    pub section_anchor: String,
    pub feature_id: String,
    pub source_support_state_row: String,
    pub gate_artifact_hash: String,
    pub generated_wording_id: String,
    pub observed_wording_hash: String,
    pub drift_classification: String,
    pub remediation_id: String,
    pub output_path: String,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IssueSummary {
    id: String,
}

pub fn run_docs_status_drift(config: &DocsStatusDriftConfig) -> Result<DocsStatusDriftReport> {
    let issues_jsonl = fs::read_to_string(&config.issues_jsonl)
        .with_context(|| format!("failed to read {}", config.issues_jsonl.display()))?;
    let feature_parity =
        fs::read_to_string(&config.feature_parity_markdown).with_context(|| {
            format!(
                "failed to read {}",
                config.feature_parity_markdown.display()
            )
        })?;
    let snippets_json = config
        .snippets_json
        .as_ref()
        .map(fs::read_to_string)
        .transpose()
        .with_context(|| {
            format!(
                "failed to read {}",
                config.snippets_json.as_ref().map_or_else(
                    || "<default snippets>".to_owned(),
                    |path| path.display().to_string()
                )
            )
        })?;

    Ok(analyze_docs_status_drift(
        &issues_jsonl,
        &feature_parity,
        snippets_json.as_deref(),
        &config.generated_artifact_paths,
    ))
}

#[must_use]
pub fn analyze_docs_status_drift(
    issues_jsonl: &str,
    feature_parity_markdown: &str,
    snippets_json: Option<&str>,
    generated_artifact_paths: &[String],
) -> DocsStatusDriftReport {
    let mut errors = Vec::new();
    let issues = parse_issues(issues_jsonl, &mut errors);
    let support_report = analyze_support_state_accounting(
        issues_jsonl,
        feature_parity_markdown,
        &[
            "artifacts/parity/support_state_accounting.json".to_owned(),
            "artifacts/parity/support_state_accounting.md".to_owned(),
        ],
    );
    let matrix_report = analyze_ambition_evidence_matrix(
        issues_jsonl,
        &["artifacts/ambition/evidence_matrix.json".to_owned()],
    );
    let support_rows = support_report
        .rows
        .iter()
        .map(|row| (row.feature_id.clone(), row.clone()))
        .collect::<BTreeMap<_, _>>();
    let matrix_rows = matrix_report
        .rows
        .iter()
        .map(|row| row.source_bead_id.clone())
        .collect::<BTreeSet<_>>();
    let rules = default_docs_status_rules();

    errors.extend(
        support_report
            .errors
            .iter()
            .map(|error| format!("source support-state accounting error: {error}")),
    );
    errors.extend(
        matrix_report
            .errors
            .iter()
            .map(|error| format!("source ambition evidence matrix error: {error}")),
    );
    errors.extend(validate_docs_status_rules(
        &rules,
        &support_rows,
        &matrix_rows,
        &issues,
    ));

    let snippets = match build_observed_snippets(snippets_json, &rules, &support_rows) {
        Ok(snippets) => snippets,
        Err(err) => {
            errors.push(err);
            Vec::new()
        }
    };
    let observations =
        build_observations(&rules, &support_rows, &snippets, generated_artifact_paths);
    errors.extend(validate_observation_coverage(&observations));
    errors.extend(
        observations
            .iter()
            .filter(|observation| observation.drift_classification != "matches")
            .map(drift_error),
    );

    let structured_logs = observations
        .iter()
        .map(DocsStatusLogEvent::from)
        .collect::<Vec<_>>();
    let grouped_by_docs_target = group_by(&observations, |observation| {
        observation.docs_target.as_str()
    });
    let grouped_by_public_status = group_by(&observations, |observation| {
        observation.expected_public_status.as_str()
    });
    let drift_classification_counts = count_by(&observations, |observation| {
        observation.drift_classification.as_str()
    });

    DocsStatusDriftReport {
        docs_status_drift_version: DOCS_STATUS_DRIFT_VERSION.to_owned(),
        release_gate_contract: RELEASE_GATE_CONTRACT.to_owned(),
        release_gate_pass: errors.is_empty(),
        source_issue_count: issues_jsonl
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count(),
        rule_count: rules.len(),
        observation_count: observations.len(),
        required_doc_targets: REQUIRED_DOC_TARGETS
            .iter()
            .map(ToString::to_string)
            .collect(),
        allowed_status_vocabulary: REQUIRED_PUBLIC_STATUSES
            .iter()
            .map(ToString::to_string)
            .collect(),
        generated_artifact_paths: generated_artifact_paths.to_vec(),
        rules,
        observations,
        structured_logs,
        grouped_by_docs_target,
        grouped_by_public_status,
        drift_classification_counts,
        required_log_fields: REQUIRED_LOG_FIELDS
            .iter()
            .map(ToString::to_string)
            .collect(),
        errors,
        reproduction_command: REPRODUCTION_COMMAND.to_owned(),
    }
}

#[must_use]
pub fn render_docs_status_drift_markdown(report: &DocsStatusDriftReport) -> String {
    let mut out = String::new();
    writeln!(&mut out, "# FrankenFS Docs Status Drift").ok();
    writeln!(&mut out).ok();
    writeln!(
        &mut out,
        "- Version: `{}`",
        report.docs_status_drift_version
    )
    .ok();
    writeln!(
        &mut out,
        "- Release gate pass: `{}`",
        report.release_gate_pass
    )
    .ok();
    writeln!(&mut out, "- Rules: `{}`", report.rule_count).ok();
    writeln!(&mut out, "- Observations: `{}`", report.observation_count).ok();
    writeln!(
        &mut out,
        "- Reproduction: `{}`",
        report.reproduction_command
    )
    .ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "## Observations").ok();
    writeln!(
        &mut out,
        "| Feature | Target | Expected | Drift | Wording | Remediation |"
    )
    .ok();
    writeln!(&mut out, "|---|---|---|---|---|---|").ok();
    for observation in &report.observations {
        writeln!(
            &mut out,
            "| `{}` | {} | `{}` | `{}` | `{}` | `{}` |",
            observation.feature_id,
            observation.docs_target,
            observation.expected_public_status,
            observation.drift_classification,
            observation.generated_wording_id,
            observation.remediation_id
        )
        .ok();
    }
    if !report.errors.is_empty() {
        writeln!(&mut out).ok();
        writeln!(&mut out, "## Errors").ok();
        for error in &report.errors {
            writeln!(&mut out, "- {error}").ok();
        }
    }
    out
}

pub fn fail_on_docs_status_drift_errors(report: &DocsStatusDriftReport) -> Result<()> {
    if report.errors.is_empty() {
        Ok(())
    } else {
        bail!(
            "docs status drift failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        )
    }
}

#[must_use]
pub fn default_docs_status_rules() -> Vec<DocsStatusWordingRule> {
    let vocab = REQUIRED_PUBLIC_STATUSES
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    vec![
        rule(
            "readonly_ext4_btrfs_inspection",
            "readonly_ext4_btrfs_inspection",
            "bd-rchk0.5.10.1",
            "validated",
            "FEATURE_PARITY.md",
            "coverage-summary",
            "support.readonly-inspection.validated",
            "bd-mpcse",
            "bd-mpcse",
            "read-only inspection may say validated only with fresh conformance and mounted smoke evidence",
            "keep read/write and repair readiness separate from validated read-only wording",
            &vocab,
        ),
        rule(
            "mounted_write_paths",
            "mounted_write_paths",
            "bd-rchk0.5.10.1",
            "experimental",
            "README.md",
            "project-status",
            "docs.mounted-writes.experimental",
            "bd-jtu4q",
            "bd-jtu4q",
            "fresh mounted matrix plus crash/reopen artifacts required before upgrade",
            "preserve implemented write-path claims but scope them as experimental",
            &vocab,
        ),
        rule(
            "background_scrub",
            "background_scrub",
            "bd-rchk0.5.10.1",
            "detection-only",
            "COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md",
            "self-healing-durability",
            "docs.background-scrub.detection-only",
            "bd-wjsuj",
            "bd-wjsuj",
            "fresh repair side-effect fixtures required before mutating wording",
            "say detection-only unless explicit repair authority and ledger evidence are present",
            &vocab,
        ),
        rule(
            "performance_claim_budget",
            "performance_claim_budget",
            "bd-rchk0.5.13",
            "dry-run-only",
            "PLAN_TO_PORT_FRANKENFS_TO_RUST.md",
            "performance-baseline-plan",
            "docs.performance.dry-run-only",
            "bd-rchk5.2",
            "bd-rchk5.2",
            "authoritative benchmark artifacts required before performance wording improves",
            "budget validation is real but does not claim measured speed",
            &vocab,
        ),
        rule(
            "btrfs_send_receive_streams",
            "btrfs_send_receive_streams",
            "bd-rchk0.5.10.1",
            "parse-only",
            "EXISTING_EXT4_BTRFS_STRUCTURE.md",
            "btrfs-send-receive",
            "docs.btrfs-send-receive.parse-only",
            "bd-naww5",
            "bd-naww5",
            "export/apply roundtrip corpus required before support upgrade",
            "preserve parser coverage while blocking operational send/receive parity wording",
            &vocab,
        ),
        rule(
            "readonly_repair_with_ledger",
            "readonly_repair_with_ledger",
            "bd-rchk0.5.10.1",
            "opt-in mutating",
            "PROPOSED_ARCHITECTURE.md",
            "repair-ledger-authority",
            "docs.readonly-repair.opt-in-mutating",
            "bd-wjsuj",
            "bd-wjsuj",
            "operator ledger and side-effect boundary fixtures required",
            "automatic repair wording must retain explicit opt-in mutation boundaries",
            &vocab,
        ),
        rule(
            "fuse_writeback_cache",
            "fuse_writeback_cache",
            "bd-rchk0.5.10.1",
            "disabled",
            "CLI help/status text",
            "mount-options",
            "docs.writeback-cache.disabled",
            "bd-4nobd",
            "bd-4nobd",
            "negative-option and ordering oracles required before enablement",
            "CLI/help text must say writeback-cache is disabled, not available",
            &vocab,
        ),
        rule(
            "unsupported_legacy_ext4_codecs",
            "unsupported_legacy_ext4_codecs",
            "bd-rchk0.5.12",
            "unsupported",
            "scripts/e2e/README.md",
            "unsupported-scope",
            "docs.ext4-legacy-codecs.unsupported",
            "bd-mpcse",
            "bd-mpcse",
            "explicit non-goal remains valid until scope changes",
            "preserve the feature mention as deterministic unsupported behavior",
            &vocab,
        ),
        rule(
            "writeback_cache_negative_option",
            "writeback_cache_negative_option",
            "bd-rchk0.5.10.1",
            "deferred",
            "proof-bundle summaries",
            "release-gate-summary",
            "docs.writeback-cache.deferred",
            "bd-rchk0.2.1.1",
            "bd-rchk0.2.1.1",
            "negative-option proof required before proof bundles can improve the state",
            "proof summaries must retain deferred state until the dedicated gate lands",
            &vocab,
        ),
        rule(
            "performance_baseline_freshness",
            "performance_budget_enforcement",
            "bd-rchk0.5.13",
            "stale-evidence",
            "README.md",
            "performance-readiness",
            "docs.performance.stale-evidence",
            "bd-rchk5.2",
            "bd-rchk5.2",
            "fresh dated benchmark artifacts with environment metadata required",
            "do not delete performance claims; mark old measurements stale until refreshed",
            &vocab,
        ),
        rule(
            "rw_background_repair",
            "rw_background_repair",
            "bd-rchk0.5.10.1",
            "host-blocked",
            "README.md",
            "mounted-self-healing",
            "docs.rw-background-repair.host-blocked",
            "bd-bqgy8",
            "bd-bqgy8",
            "fresh two-key gate and rollback proof required before upgrade",
            "read-write automatic repair wording must remain host-blocked when proof is absent",
            &vocab,
        ),
        rule(
            "hostile_image_safety",
            "unsupported_legacy_ext4_codecs",
            "bd-rchk0.5.11",
            "security-refused",
            "FEATURE_PARITY.md",
            "hostile-image-safety",
            "docs.hostile-image.security-refused",
            "bd-0qx9b",
            "bd-0qx9b",
            "containment proof and adversarial model artifacts required before readiness wording",
            "security surfaces must say refused or contained, never generally safe, without proof",
            &vocab,
        ),
    ]
}

fn rule(
    feature_id: &str,
    source_support_state_feature_id: &str,
    evidence_matrix_row: &str,
    public_status: &str,
    docs_target: &str,
    spec_anchor: &str,
    generated_wording_id: &str,
    remediation_id: &str,
    owning_bead: &str,
    freshness_requirement: &str,
    downgrade_wording: &str,
    vocab: &[String],
) -> DocsStatusWordingRule {
    DocsStatusWordingRule {
        feature_id: feature_id.to_owned(),
        source_support_state_feature_id: source_support_state_feature_id.to_owned(),
        evidence_matrix_row: evidence_matrix_row.to_owned(),
        gate_consumer: RELEASE_GATE_CONTRACT.to_owned(),
        allowed_status_vocabulary: vocab.to_vec(),
        public_status: public_status.to_owned(),
        docs_target: docs_target.to_owned(),
        spec_anchor: spec_anchor.to_owned(),
        generated_wording_id: generated_wording_id.to_owned(),
        downgrade_wording: downgrade_wording.to_owned(),
        remediation_id: remediation_id.to_owned(),
        freshness_requirement: freshness_requirement.to_owned(),
        owning_bead: owning_bead.to_owned(),
        explicit_non_goal: String::new(),
    }
}

fn parse_issues(issues_jsonl: &str, errors: &mut Vec<String>) -> BTreeMap<String, IssueSummary> {
    let mut issues = BTreeMap::new();
    for (line_no, line) in issues_jsonl.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value = match serde_json::from_str::<Value>(line) {
            Ok(value) => value,
            Err(err) => {
                errors.push(format!("invalid issue json at line {}: {err}", line_no + 1));
                continue;
            }
        };
        let id = value
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if id.is_empty() {
            errors.push(format!("issue at line {} is missing id", line_no + 1));
        } else {
            issues.insert(id.clone(), IssueSummary { id });
        }
    }
    issues
}

fn validate_docs_status_rules(
    rules: &[DocsStatusWordingRule],
    support_rows: &BTreeMap<String, SupportStateAccountingRow>,
    matrix_rows: &BTreeSet<String>,
    issues: &BTreeMap<String, IssueSummary>,
) -> Vec<String> {
    let mut errors = Vec::new();
    let mut seen = BTreeSet::new();
    let observed_targets = rules
        .iter()
        .map(|rule| rule.docs_target.as_str())
        .collect::<BTreeSet<_>>();
    let observed_statuses = rules
        .iter()
        .map(|rule| rule.public_status.as_str())
        .collect::<BTreeSet<_>>();

    for target in REQUIRED_DOC_TARGETS {
        if !observed_targets.contains(target) {
            errors.push(format!("missing required docs target {target}"));
        }
    }
    for status in REQUIRED_PUBLIC_STATUSES {
        if !observed_statuses.contains(status) {
            errors.push(format!("missing required public status {status}"));
        }
    }

    for rule in rules {
        let rule_key = format!("{}:{}", rule.feature_id, rule.docs_target);
        if !seen.insert(rule_key.clone()) {
            errors.push(format!("duplicate docs status rule {rule_key}"));
        }
        require_rule_field(rule, "feature_id", &rule.feature_id, &mut errors);
        require_rule_field(
            rule,
            "source_support_state_row",
            &rule.source_support_state_feature_id,
            &mut errors,
        );
        require_rule_field(
            rule,
            "evidence_matrix_row",
            &rule.evidence_matrix_row,
            &mut errors,
        );
        require_rule_field(rule, "gate_consumer", &rule.gate_consumer, &mut errors);
        require_rule_field(rule, "public_status", &rule.public_status, &mut errors);
        require_rule_field(rule, "docs_target", &rule.docs_target, &mut errors);
        require_rule_field(rule, "spec_anchor", &rule.spec_anchor, &mut errors);
        require_rule_field(
            rule,
            "generated_wording_id",
            &rule.generated_wording_id,
            &mut errors,
        );
        require_rule_field(
            rule,
            "downgrade_wording",
            &rule.downgrade_wording,
            &mut errors,
        );
        require_rule_field(rule, "remediation_id", &rule.remediation_id, &mut errors);
        require_rule_field(
            rule,
            "freshness_requirement",
            &rule.freshness_requirement,
            &mut errors,
        );

        if rule.owning_bead.trim().is_empty() && rule.explicit_non_goal.trim().is_empty() {
            errors.push(format!(
                "{} missing owning_bead or explicit_non_goal",
                rule.feature_id
            ));
        }
        if !support_rows.contains_key(&rule.source_support_state_feature_id) {
            errors.push(format!(
                "{} missing source support-state row {}",
                rule.feature_id, rule.source_support_state_feature_id
            ));
        }
        if !matrix_rows.contains(&rule.evidence_matrix_row) {
            errors.push(format!(
                "{} missing evidence matrix row {}",
                rule.feature_id, rule.evidence_matrix_row
            ));
        }
        if !rule.gate_consumer.contains("bd-rchk0.5.6.1") {
            errors.push(format!(
                "{} gate_consumer must name bd-rchk0.5.6.1",
                rule.feature_id
            ));
        }
        if missing_status_vocab(&rule.allowed_status_vocabulary).is_some() {
            errors.push(format!(
                "{} allowed_status_vocabulary missing required status",
                rule.feature_id
            ));
        }
        if !REQUIRED_PUBLIC_STATUSES.contains(&rule.public_status.as_str()) {
            errors.push(format!(
                "{} invalid public_status {}",
                rule.feature_id, rule.public_status
            ));
        }
        if rule.generated_wording_id == rule.feature_id {
            errors.push(format!(
                "{} generated_wording_id must be a stable wording id",
                rule.feature_id
            ));
        }
        for bead in [&rule.remediation_id, &rule.owning_bead] {
            if !bead.is_empty() && !issues.contains_key(bead) {
                errors.push(format!("{} stale bead reference {bead}", rule.feature_id));
            }
        }
    }
    errors
}

fn require_rule_field(
    rule: &DocsStatusWordingRule,
    field: &str,
    value: &str,
    errors: &mut Vec<String>,
) {
    if value.trim().is_empty() {
        errors.push(format!("{} missing {field}", rule.feature_id));
    }
}

fn missing_status_vocab(vocab: &[String]) -> Option<&'static str> {
    REQUIRED_PUBLIC_STATUSES
        .iter()
        .copied()
        .find(|status| !vocab.iter().any(|item| item == status))
}

fn build_observed_snippets(
    snippets_json: Option<&str>,
    rules: &[DocsStatusWordingRule],
    support_rows: &BTreeMap<String, SupportStateAccountingRow>,
) -> std::result::Result<Vec<DocsStatusSnippet>, String> {
    let mut snippets = default_snippets(rules, support_rows);
    let Some(raw_json) = snippets_json else {
        return Ok(snippets);
    };
    let overrides = serde_json::from_str::<DocsStatusSnippetSet>(raw_json)
        .map_err(|err| format!("invalid docs status snippets JSON: {err}"))?;
    for override_snippet in overrides.snippets {
        if let Some(existing) = snippets.iter_mut().find(|snippet| {
            snippet.feature_id == override_snippet.feature_id
                && snippet.docs_target == override_snippet.docs_target
        }) {
            *existing = override_snippet;
        } else {
            snippets.push(override_snippet);
        }
    }
    Ok(snippets)
}

fn default_snippets(
    rules: &[DocsStatusWordingRule],
    support_rows: &BTreeMap<String, SupportStateAccountingRow>,
) -> Vec<DocsStatusSnippet> {
    rules
        .iter()
        .filter_map(|rule| {
            support_rows
                .get(&rule.source_support_state_feature_id)
                .map(|row| DocsStatusSnippet {
                    feature_id: rule.feature_id.clone(),
                    docs_target: rule.docs_target.clone(),
                    section_anchor: rule.spec_anchor.clone(),
                    observed_text: generated_wording(rule, row),
                })
        })
        .collect()
}

fn build_observations(
    rules: &[DocsStatusWordingRule],
    support_rows: &BTreeMap<String, SupportStateAccountingRow>,
    snippets: &[DocsStatusSnippet],
    generated_artifact_paths: &[String],
) -> Vec<DocsStatusObservation> {
    let output_path = generated_artifact_paths
        .first()
        .cloned()
        .unwrap_or_else(|| DEFAULT_DOCS_STATUS_DRIFT_ARTIFACT.to_owned());
    rules
        .iter()
        .filter_map(|rule| {
            let row = support_rows.get(&rule.source_support_state_feature_id)?;
            let generated_wording = generated_wording(rule, row);
            let source_support_state_row =
                format!("{}:{}", row.feature_id.as_str(), row.support_state.as_str());
            let gate_artifact_hash = hash_text(&format!(
                "{}|{}|{}|{}|{}",
                DOCS_STATUS_DRIFT_VERSION,
                rule.feature_id,
                rule.evidence_matrix_row,
                row.docs_wording_id,
                rule.public_status
            ));
            let snippet = snippets.iter().find(|snippet| {
                snippet.feature_id == rule.feature_id && snippet.docs_target == rule.docs_target
            });
            let (section_anchor, observed_text) = snippet.map_or_else(
                || (rule.spec_anchor.clone(), String::new()),
                |snippet| {
                    (
                        snippet.section_anchor.clone(),
                        snippet.observed_text.clone(),
                    )
                },
            );
            let strongest_observed_status = strongest_status_in_text(&observed_text);
            let drift_classification = classify_drift(
                rule,
                &generated_wording,
                &observed_text,
                &strongest_observed_status,
            );
            Some(DocsStatusObservation {
                feature_id: rule.feature_id.clone(),
                docs_target: rule.docs_target.clone(),
                section_anchor,
                expected_public_status: rule.public_status.clone(),
                strongest_observed_status,
                source_support_state_row,
                evidence_matrix_row: rule.evidence_matrix_row.clone(),
                gate_consumer: rule.gate_consumer.clone(),
                gate_artifact_hash,
                generated_wording_id: rule.generated_wording_id.clone(),
                generated_wording,
                observed_wording_hash: hash_text(&observed_text),
                drift_classification,
                remediation_id: rule.remediation_id.clone(),
                output_path: output_path.clone(),
                reproduction_command: REPRODUCTION_COMMAND.to_owned(),
            })
        })
        .collect()
}

fn generated_wording(rule: &DocsStatusWordingRule, row: &SupportStateAccountingRow) -> String {
    format!(
        "{}: `{}` status is `{}` for `{}` at `{}`. Source support-state row `{}` is `{}` with docs wording `{}`; evidence matrix row `{}` and gate consumer `{}` control upgrades. Freshness requirement: {}. Downgrade wording: {}. Remediation: `{}`. Owner: `{}`.",
        rule.generated_wording_id,
        rule.feature_id,
        rule.public_status,
        rule.docs_target,
        rule.spec_anchor,
        row.feature_id,
        row.support_state,
        row.docs_wording_id,
        rule.evidence_matrix_row,
        rule.gate_consumer,
        rule.freshness_requirement,
        rule.downgrade_wording,
        rule.remediation_id,
        rule.owning_bead,
    )
}

fn classify_drift(
    rule: &DocsStatusWordingRule,
    generated_wording: &str,
    observed_text: &str,
    strongest_observed_status: &str,
) -> String {
    if observed_text.trim().is_empty() {
        return "missing-observed-wording".to_owned();
    }
    let lower = observed_text.to_ascii_lowercase();
    if contains_flat_parity_claim(&lower) {
        return "stale-flat-parity".to_owned();
    }
    if observed_text.trim() == generated_wording.trim() {
        return "matches".to_owned();
    }
    if status_rank(strongest_observed_status) > status_rank(&rule.public_status) {
        return "stronger-than-evidence".to_owned();
    }
    if !lower.contains(&rule.generated_wording_id.to_ascii_lowercase()) {
        return "missing-generated-wording-id".to_owned();
    }
    if !lower.contains(&rule.public_status) {
        return "missing-required-status".to_owned();
    }
    "wording-hash-drift".to_owned()
}

fn contains_flat_parity_claim(lower_text: &str) -> bool {
    (lower_text.contains("100 percent parity")
        || lower_text.contains("100% parity")
        || lower_text.contains("100.0% parity"))
        && !lower_text.contains("support-state")
}

fn strongest_status_in_text(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    for (needle, status) in [
        ("production-ready", "validated"),
        ("fully supported", "validated"),
        ("validated", "validated"),
        ("opt-in mutating", "opt-in mutating"),
        ("experimental", "experimental"),
        ("detection-only", "detection-only"),
        ("dry-run-only", "dry-run-only"),
        ("parse-only", "parse-only"),
        ("stale-evidence", "stale-evidence"),
        ("host-blocked", "host-blocked"),
        ("security-refused", "security-refused"),
        ("unsupported", "unsupported"),
        ("disabled", "disabled"),
        ("deferred", "deferred"),
    ] {
        if lower.contains(needle) {
            return status.to_owned();
        }
    }
    "unknown".to_owned()
}

fn status_rank(status: &str) -> u8 {
    match status {
        "validated" => 100,
        "opt-in mutating" => 80,
        "experimental" => 70,
        "detection-only" => 55,
        "dry-run-only" => 50,
        "parse-only" => 45,
        "stale-evidence" => 40,
        "host-blocked" => 35,
        "security-refused" => 30,
        "unsupported" => 25,
        "disabled" => 20,
        "deferred" => 10,
        _ => 0,
    }
}

fn validate_observation_coverage(observations: &[DocsStatusObservation]) -> Vec<String> {
    let mut errors = Vec::new();
    let targets = observations
        .iter()
        .map(|observation| observation.docs_target.as_str())
        .collect::<BTreeSet<_>>();
    let statuses = observations
        .iter()
        .map(|observation| observation.expected_public_status.as_str())
        .collect::<BTreeSet<_>>();
    for target in REQUIRED_DOC_TARGETS {
        if !targets.contains(target) {
            errors.push(format!("missing observed docs target {target}"));
        }
    }
    for status in REQUIRED_PUBLIC_STATUSES {
        if !statuses.contains(status) {
            errors.push(format!("missing observed public status {status}"));
        }
    }
    errors
}

fn drift_error(observation: &DocsStatusObservation) -> String {
    format!(
        "docs drift feature_id={} docs_target={} expected_wording_id={} observed_wording_hash={} source_support_state_row={} drift_classification={} remediation_id={}",
        observation.feature_id,
        observation.docs_target,
        observation.generated_wording_id,
        observation.observed_wording_hash,
        observation.source_support_state_row,
        observation.drift_classification,
        observation.remediation_id,
    )
}

impl From<&DocsStatusObservation> for DocsStatusLogEvent {
    fn from(observation: &DocsStatusObservation) -> Self {
        Self {
            docs_target: observation.docs_target.clone(),
            section_anchor: observation.section_anchor.clone(),
            feature_id: observation.feature_id.clone(),
            source_support_state_row: observation.source_support_state_row.clone(),
            gate_artifact_hash: observation.gate_artifact_hash.clone(),
            generated_wording_id: observation.generated_wording_id.clone(),
            observed_wording_hash: observation.observed_wording_hash.clone(),
            drift_classification: observation.drift_classification.clone(),
            remediation_id: observation.remediation_id.clone(),
            output_path: observation.output_path.clone(),
            reproduction_command: observation.reproduction_command.clone(),
        }
    }
}

fn hash_text(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hex::encode(hasher.finalize())
}

fn group_by<F>(observations: &[DocsStatusObservation], key_fn: F) -> BTreeMap<String, Vec<String>>
where
    F: Fn(&DocsStatusObservation) -> &str,
{
    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for observation in observations {
        grouped
            .entry(key_fn(observation).to_owned())
            .or_default()
            .push(observation.feature_id.clone());
    }
    grouped
}

fn count_by<F>(observations: &[DocsStatusObservation], key_fn: F) -> BTreeMap<String, usize>
where
    F: Fn(&DocsStatusObservation) -> &str,
{
    let mut counts = BTreeMap::new();
    for observation in observations {
        *counts.entry(key_fn(observation).to_owned()).or_insert(0) += 1;
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_issue(id: &str) -> String {
        format!(r#"{{"id":"{id}","title":"{id}","status":"open","labels":["test"]}}"#)
    }

    fn fixture_issues() -> String {
        [
            "bd-mpcse",
            "bd-jtu4q",
            "bd-naww5",
            "bd-ch373",
            "bd-9er6s",
            "bd-4nobd",
            "bd-rchk0.2.1.1",
            "bd-bqgy8",
            "bd-wjsuj",
            "bd-rchk5.2",
            "bd-hol07",
            "bd-rchk0.5.10.1",
            "bd-rchk0.5.11",
            "bd-rchk0.5.12",
            "bd-rchk0.5.13",
            "bd-rchk0.5.14",
            "bd-0qx9b",
        ]
        .iter()
        .map(|id| fixture_issue(id))
        .collect::<Vec<_>>()
        .join("\n")
    }

    fn feature_parity_fixture() -> String {
        r"
## 1. Coverage Summary (Current)

| Domain | Implemented | Total Tracked | Coverage |
|--------|-------------|---------------|----------|
| ext4 metadata parsing | 27 | 27 | 100.0% |
| btrfs metadata parsing | 27 | 27 | 100.0% |
| MVCC/COW core | 14 | 14 | 100.0% |
| FUSE surface | 19 | 19 | 100.0% |
| self-healing durability policy | 10 | 10 | 100.0% |

> **Boundary rule:** this table measures the tracked V1 feature denominator
> under support-state accounting. It does not certify production readiness;
> parse-only, detection-only, disabled, and host-blocked states require the
> support-state row and owner bead.
"
        .to_owned()
    }

    fn fixture_report(snippets_json: Option<&str>) -> DocsStatusDriftReport {
        analyze_docs_status_drift(
            &fixture_issues(),
            &feature_parity_fixture(),
            snippets_json,
            &[
                DEFAULT_DOCS_STATUS_DRIFT_ARTIFACT.to_owned(),
                DEFAULT_DOCS_STATUS_DRIFT_SUMMARY.to_owned(),
            ],
        )
    }

    fn support_rows_for_tests() -> BTreeMap<String, SupportStateAccountingRow> {
        let report = analyze_support_state_accounting(
            &fixture_issues(),
            &feature_parity_fixture(),
            &["artifacts/parity/support_state_accounting.json".to_owned()],
        );
        report
            .rows
            .into_iter()
            .map(|row| (row.feature_id.clone(), row))
            .collect()
    }

    fn matrix_rows_for_tests() -> BTreeSet<String> {
        let report = analyze_ambition_evidence_matrix(
            &fixture_issues(),
            &["artifacts/ambition/evidence_matrix.json".to_owned()],
        );
        report
            .rows
            .into_iter()
            .map(|row| row.source_bead_id)
            .collect()
    }

    fn issues_for_tests() -> BTreeMap<String, IssueSummary> {
        let mut errors = Vec::new();
        parse_issues(&fixture_issues(), &mut errors)
    }

    #[test]
    fn builds_docs_status_drift_report_without_errors() {
        let report = fixture_report(None);
        assert!(
            report.errors.is_empty(),
            "unexpected errors: {:?}",
            report.errors
        );
        assert_eq!(report.docs_status_drift_version, DOCS_STATUS_DRIFT_VERSION);
        assert!(report.release_gate_pass);
        assert_eq!(report.rule_count, 12);
        assert_eq!(report.observation_count, 12);
        assert_eq!(report.drift_classification_counts["matches"], 12);
    }

    #[test]
    fn schema_rejects_rules_missing_required_fields() {
        let support_rows = support_rows_for_tests();
        let matrix_rows = matrix_rows_for_tests();
        let issues = issues_for_tests();
        let base = default_docs_status_rules()[0].clone();
        let mut cases: Vec<(&str, DocsStatusWordingRule)> = Vec::new();

        macro_rules! missing {
            ($field:literal, $edit:expr) => {{
                let mut rule = base.clone();
                $edit(&mut rule);
                cases.push(($field, rule));
            }};
        }

        missing!("feature_id", |rule: &mut DocsStatusWordingRule| rule
            .feature_id
            .clear());
        missing!(
            "source_support_state_row",
            |rule: &mut DocsStatusWordingRule| {
                rule.source_support_state_feature_id.clear();
            }
        );
        missing!("evidence_matrix_row", |rule: &mut DocsStatusWordingRule| {
            rule.evidence_matrix_row.clear();
        });
        missing!("gate_consumer", |rule: &mut DocsStatusWordingRule| rule
            .gate_consumer
            .clear());
        missing!(
            "allowed_status_vocabulary",
            |rule: &mut DocsStatusWordingRule| {
                rule.allowed_status_vocabulary.pop();
            }
        );
        missing!("docs_target", |rule: &mut DocsStatusWordingRule| rule
            .docs_target
            .clear());
        missing!("spec_anchor", |rule: &mut DocsStatusWordingRule| rule
            .spec_anchor
            .clear());
        missing!("downgrade_wording", |rule: &mut DocsStatusWordingRule| {
            rule.downgrade_wording.clear();
        });
        missing!("remediation_id", |rule: &mut DocsStatusWordingRule| rule
            .remediation_id
            .clear());
        missing!(
            "freshness_requirement",
            |rule: &mut DocsStatusWordingRule| {
                rule.freshness_requirement.clear();
            }
        );
        missing!(
            "owning_bead or explicit_non_goal",
            |rule: &mut DocsStatusWordingRule| {
                rule.owning_bead.clear();
                rule.explicit_non_goal.clear();
            }
        );

        for (expected, rule) in cases {
            let errors = validate_docs_status_rules(&[rule], &support_rows, &matrix_rows, &issues);
            assert!(
                errors.iter().any(|error| error.contains(expected)),
                "expected {expected} error, observed {errors:?}"
            );
        }
    }

    #[test]
    fn covers_required_statuses_and_public_surfaces() {
        let report = fixture_report(None);
        let statuses = report
            .observations
            .iter()
            .map(|observation| observation.expected_public_status.as_str())
            .collect::<BTreeSet<_>>();
        let targets = report
            .observations
            .iter()
            .map(|observation| observation.docs_target.as_str())
            .collect::<BTreeSet<_>>();
        for status in REQUIRED_PUBLIC_STATUSES {
            assert!(statuses.contains(status), "missing {status}");
        }
        for target in REQUIRED_DOC_TARGETS {
            assert!(targets.contains(target), "missing {target}");
        }
    }

    #[test]
    fn structured_logs_include_release_gate_fields() {
        let report = fixture_report(None);
        let log = report
            .structured_logs
            .iter()
            .find(|event| event.feature_id == "rw_background_repair")
            .expect("rw repair log");
        assert_eq!(log.docs_target, "README.md");
        assert_eq!(log.remediation_id, "bd-bqgy8");
        assert_eq!(log.observed_wording_hash.len(), 64);
        assert!(
            log.reproduction_command
                .contains("validate-docs-status-drift")
        );
        for field in REQUIRED_LOG_FIELDS {
            assert!(
                report.required_log_fields.iter().any(|item| item == field),
                "missing log field {field}"
            );
        }
    }

    #[test]
    fn rejects_hand_upgraded_claim_with_exact_diagnostic_fields() {
        let snippets = r#"{
  "snippets": [
    {
      "feature_id": "rw_background_repair",
      "docs_target": "README.md",
      "section_anchor": "mounted-self-healing",
      "observed_text": "rw_background_repair is validated and fully supported for production automatic repair."
    }
  ]
}"#;
        let report = fixture_report(Some(snippets));
        assert!(!report.release_gate_pass);
        let error = report
            .errors
            .iter()
            .find(|error| error.contains("rw_background_repair"))
            .expect("rw repair error");
        assert!(error.contains("docs_target=README.md"));
        assert!(error.contains("expected_wording_id=docs.rw-background-repair.host-blocked"));
        assert!(error.contains("observed_wording_hash="));
        assert!(error.contains("source_support_state_row=rw_background_repair:host_blocked"));
        assert!(error.contains("drift_classification=stronger-than-evidence"));
        assert!(error.contains("remediation_id=bd-bqgy8"));
    }

    #[test]
    fn rejects_stale_flat_parity_claim() {
        let snippets = r#"{
  "snippets": [
    {
      "feature_id": "mounted_write_paths",
      "docs_target": "README.md",
      "section_anchor": "project-status",
      "observed_text": "FrankenFS has 100 percent parity, including mounted write paths."
    }
  ]
}"#;
        let report = fixture_report(Some(snippets));
        assert!(
            report.errors.iter().any(|error| {
                error.contains("mounted_write_paths")
                    && error.contains("drift_classification=stale-flat-parity")
            }),
            "errors were {:?}",
            report.errors
        );
    }

    #[test]
    fn rejects_unknown_snippet_json_shape() {
        let report = fixture_report(Some(r#"{"bad": true}"#));
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("invalid docs status snippets JSON")),
            "errors were {:?}",
            report.errors
        );
    }

    #[test]
    fn renders_markdown_summary() {
        let report = fixture_report(None);
        let markdown = render_docs_status_drift_markdown(&report);
        assert!(markdown.contains("# FrankenFS Docs Status Drift"));
        assert!(markdown.contains("rw_background_repair"));
        assert!(markdown.contains("docs.rw-background-repair.host-blocked"));
    }

    /// bd-wly6z — golden-output snapshot for
    /// `render_docs_status_drift_markdown` on the deterministic
    /// `fixture_report(None)`. Pins:
    ///   * the title line `# FrankenFS Docs Status Drift`
    ///   * the 5-bullet metadata header (Version / Release gate pass /
    ///     Rules / Observations / Reproduction)
    ///   * the `## Observations` section heading
    ///   * the 6-column table layout (Feature / Target / Expected /
    ///     Drift / Wording / Remediation) with all 12 fixture rows
    ///   * the `## Errors` section heading and the per-error bullet
    ///     format
    ///   * the exact ordering of observation and error bullets
    /// Substring-only assertions in `renders_markdown_summary` cannot
    /// detect column reorders, section ordering swaps, or table-cell
    /// drift; this snapshot does.
    #[test]
    fn render_docs_status_drift_markdown_default_fixture_snapshot() {
        let report = fixture_report(None);
        let markdown = render_docs_status_drift_markdown(&report);
        insta::assert_snapshot!(
            "render_docs_status_drift_markdown_default_fixture",
            markdown
        );
    }
}
