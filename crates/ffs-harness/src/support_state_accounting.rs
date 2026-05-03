#![forbid(unsafe_code)]

//! Tiered support-state accounting for `bd-mpcse`.
//!
//! This report is the machine-checkable layer between implementation-count
//! parity and user-facing readiness. It preserves the flat coverage counts as
//! inventory while forcing docs, proof bundles, and release gates to consume a
//! feature state with evidence, freshness, wording, and ownership metadata.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

pub const SUPPORT_STATE_VERSION: &str = "bd-mpcse-support-state-accounting-v1";

const DEFAULT_ARTIFACT_PATH: &str = "artifacts/parity/support_state_accounting.json";
const DEFAULT_MARKDOWN_PATH: &str = "artifacts/parity/support_state_accounting.md";
const REPRODUCTION_COMMAND: &str = "ffs-harness validate-support-state-accounting --issues .beads/issues.jsonl --feature-parity FEATURE_PARITY.md --out artifacts/parity/support_state_accounting.json --summary-out artifacts/parity/support_state_accounting.md";
const RELEASE_GATE_CONTRACT: &str =
    "bd-rchk0.5.6.1 fail-closed release evaluator consumes support-state rows";

const REQUIRED_OWNER_BEADS: [&str; 11] = [
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
];

const REQUIRED_SUPPORT_STATES: [&str; 12] = [
    "validated",
    "experimental",
    "detection_only",
    "dry_run_only",
    "parse_only",
    "single_device_only",
    "basic_coverage",
    "disabled",
    "opt_in_mutating",
    "unsupported",
    "deferred",
    "host_blocked",
];

const REQUIRED_LOG_FIELDS: [&str; 8] = [
    "feature_id",
    "old_count_claim",
    "support_state",
    "controlling_bead_or_artifact",
    "downgrade_or_upgrade_reason",
    "docs_target",
    "release_gate_effect",
    "reproduction_command",
];

const REQUIRED_DOC_WORDING_TOKENS: [&str; 7] = [
    "support-state accounting",
    "Boundary rule",
    "does not certify production readiness",
    "parse-only",
    "detection-only",
    "disabled",
    "host-blocked",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportStateAccountingConfig {
    pub issues_jsonl: PathBuf,
    pub feature_parity_markdown: PathBuf,
    pub generated_artifact_paths: Vec<String>,
}

impl Default for SupportStateAccountingConfig {
    fn default() -> Self {
        Self {
            issues_jsonl: PathBuf::from(".beads/issues.jsonl"),
            feature_parity_markdown: PathBuf::from("FEATURE_PARITY.md"),
            generated_artifact_paths: vec![
                DEFAULT_ARTIFACT_PATH.to_owned(),
                DEFAULT_MARKDOWN_PATH.to_owned(),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportStateAccountingReport {
    pub support_state_version: String,
    pub source_issue_count: usize,
    pub coverage_domain_count: usize,
    pub row_count: usize,
    pub flat_parity_rejected: bool,
    pub release_gate_contract: String,
    pub generated_artifact_paths: Vec<String>,
    pub coverage_domains: Vec<SupportStateCoverageDomain>,
    pub rows: Vec<SupportStateAccountingRow>,
    pub grouped_by_support_state: BTreeMap<String, Vec<String>>,
    pub grouped_by_gate_consumer: BTreeMap<String, Vec<String>>,
    pub grouped_by_docs_target: BTreeMap<String, Vec<String>>,
    pub migration_cases: Vec<SupportStateMigrationCase>,
    pub reference_checks: Vec<SupportStateReferenceCheck>,
    pub required_log_fields: Vec<String>,
    pub errors: Vec<String>,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportStateCoverageDomain {
    pub domain: String,
    pub implemented: u32,
    pub total_tracked: u32,
    pub coverage: String,
    pub count_claim_scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportStateAccountingRow {
    pub feature_id: String,
    pub domain: String,
    pub legacy_count_bucket: String,
    pub support_state: String,
    pub evidence_lane: String,
    pub artifact_freshness: String,
    pub gate_consumer: String,
    pub docs_wording_id: String,
    pub unsupported_or_deferred_rationale: String,
    pub owner_bead: String,
    pub docs_target: String,
    pub release_gate_effect: String,
    pub old_count_claim: String,
    pub downgrade_or_upgrade_reason: String,
    pub required_logs: String,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportStateMigrationCase {
    pub historical_claim: String,
    pub feature_id: String,
    pub old_bucket: String,
    pub classified_support_state: String,
    pub docs_safe_claim: String,
    pub owner_bead: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportStateReferenceCheck {
    pub feature_id: String,
    pub referenced_bead_id: String,
    pub field: String,
    pub exists: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HistoricalParityClaim {
    pub historical_claim: String,
    pub feature_id: String,
    pub evidence_profile: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IssueSummary {
    id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SupportRowTemplate {
    feature_id: &'static str,
    domain: &'static str,
    legacy_count_bucket: &'static str,
    support_state: &'static str,
    evidence_lane: &'static str,
    artifact_freshness: &'static str,
    gate_consumer: &'static str,
    docs_wording_id: &'static str,
    rationale: &'static str,
    owner_bead: &'static str,
    docs_target: &'static str,
    release_gate_effect: &'static str,
    old_count_claim: &'static str,
    reason: &'static str,
}

pub fn run_support_state_accounting(
    config: &SupportStateAccountingConfig,
) -> Result<SupportStateAccountingReport> {
    let issues_jsonl = fs::read_to_string(&config.issues_jsonl)
        .with_context(|| format!("failed to read {}", config.issues_jsonl.display()))?;
    let feature_parity =
        fs::read_to_string(&config.feature_parity_markdown).with_context(|| {
            format!(
                "failed to read {}",
                config.feature_parity_markdown.display()
            )
        })?;
    Ok(analyze_support_state_accounting(
        &issues_jsonl,
        &feature_parity,
        &config.generated_artifact_paths,
    ))
}

#[must_use]
pub fn analyze_support_state_accounting(
    issues_jsonl: &str,
    feature_parity_markdown: &str,
    generated_artifact_paths: &[String],
) -> SupportStateAccountingReport {
    let mut errors = Vec::new();
    let issues = parse_issues(issues_jsonl, &mut errors);
    let coverage_domains = parse_coverage_domains(feature_parity_markdown, &mut errors);
    let rows = support_state_rows();
    let migration_cases = classify_historical_claims(default_historical_claims_json(), &mut errors);
    let reference_checks = collect_reference_checks(&rows, &issues);

    errors.extend(validate_support_state_rows(&rows));
    errors.extend(validate_migration_cases(&migration_cases));
    errors.extend(validate_feature_parity_wording(feature_parity_markdown));
    errors.extend(
        reference_checks
            .iter()
            .filter(|check| !check.exists)
            .map(|check| {
                format!(
                    "{} stale reference {} in {}",
                    check.feature_id, check.referenced_bead_id, check.field
                )
            }),
    );

    SupportStateAccountingReport {
        support_state_version: SUPPORT_STATE_VERSION.to_owned(),
        source_issue_count: issues_jsonl
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count(),
        coverage_domain_count: coverage_domains.len(),
        row_count: rows.len(),
        flat_parity_rejected: true,
        release_gate_contract: RELEASE_GATE_CONTRACT.to_owned(),
        generated_artifact_paths: generated_artifact_paths.to_vec(),
        coverage_domains,
        rows: rows.clone(),
        grouped_by_support_state: group_by(&rows, |row| row.support_state.as_str()),
        grouped_by_gate_consumer: group_by(&rows, |row| row.gate_consumer.as_str()),
        grouped_by_docs_target: group_by(&rows, |row| row.docs_target.as_str()),
        migration_cases,
        reference_checks,
        required_log_fields: REQUIRED_LOG_FIELDS
            .iter()
            .map(ToString::to_string)
            .collect(),
        errors,
        reproduction_command: REPRODUCTION_COMMAND.to_owned(),
    }
}

#[must_use]
pub fn render_support_state_markdown(report: &SupportStateAccountingReport) -> String {
    let mut out = String::new();
    writeln!(&mut out, "# FrankenFS Support-State Accounting").ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "- Version: `{}`", report.support_state_version).ok();
    writeln!(&mut out, "- Rows: `{}`", report.row_count).ok();
    writeln!(
        &mut out,
        "- Flat parity rejected: `{}`",
        report.flat_parity_rejected
    )
    .ok();
    writeln!(
        &mut out,
        "- Release gate contract: {}",
        report.release_gate_contract
    )
    .ok();
    writeln!(
        &mut out,
        "- Reproduction: `{}`",
        report.reproduction_command
    )
    .ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "## Support Rows").ok();
    writeln!(
        &mut out,
        "| Feature | Domain | Old Claim | Support State | Owner | Gate Effect |"
    )
    .ok();
    writeln!(&mut out, "|---|---|---|---|---|---|").ok();
    for row in &report.rows {
        writeln!(
            &mut out,
            "| `{}` | {} | {} | `{}` | `{}` | {} |",
            row.feature_id,
            row.domain,
            row.old_count_claim,
            row.support_state,
            row.owner_bead,
            row.release_gate_effect
        )
        .ok();
    }
    writeln!(&mut out).ok();
    writeln!(&mut out, "## Migration Cases").ok();
    writeln!(
        &mut out,
        "| Historical Claim | Feature | Classified State | Safe Claim |"
    )
    .ok();
    writeln!(&mut out, "|---|---|---|---|").ok();
    for case in &report.migration_cases {
        writeln!(
            &mut out,
            "| {} | `{}` | `{}` | {} |",
            case.historical_claim,
            case.feature_id,
            case.classified_support_state,
            case.docs_safe_claim
        )
        .ok();
    }
    writeln!(&mut out).ok();
    writeln!(&mut out, "## Required Log Fields").ok();
    for field in &report.required_log_fields {
        writeln!(&mut out, "- `{field}`").ok();
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

fn parse_coverage_domains(
    feature_parity_markdown: &str,
    errors: &mut Vec<String>,
) -> Vec<SupportStateCoverageDomain> {
    let mut rows = Vec::new();
    let mut in_coverage_summary = false;

    for line in feature_parity_markdown.lines() {
        let trimmed = line.trim();
        if !in_coverage_summary {
            if trimmed.starts_with("## ") && trimmed.contains("Coverage Summary") {
                in_coverage_summary = true;
            }
            continue;
        }

        if trimmed.starts_with("## ") {
            break;
        }

        let cols: Vec<&str> = trimmed.split('|').map(str::trim).collect();
        if cols.len() < 5 {
            continue;
        }
        let domain = strip_markdown(cols[1]);
        if domain.is_empty()
            || domain.eq_ignore_ascii_case("domain")
            || domain.eq_ignore_ascii_case("overall")
            || domain.chars().all(|ch| ch == '-')
        {
            continue;
        }
        let implemented = strip_markdown(cols[2]).parse::<u32>();
        let total = strip_markdown(cols[3]).parse::<u32>();
        match (implemented, total) {
            (Ok(implemented), Ok(total)) => rows.push(SupportStateCoverageDomain {
                domain: domain.to_owned(),
                implemented,
                total_tracked: total,
                coverage: strip_markdown(cols[4]).to_owned(),
                count_claim_scope:
                    "implementation inventory only; readiness comes from support_state rows"
                        .to_owned(),
            }),
            _ => errors.push(format!("unparseable coverage row: {trimmed}")),
        }
    }

    if rows.is_empty() {
        errors.push("FEATURE_PARITY.md has no parseable coverage summary rows".to_owned());
    }
    rows
}

fn strip_markdown(raw: &str) -> &str {
    raw.trim().trim_matches('*')
}

fn support_state_rows() -> Vec<SupportStateAccountingRow> {
    support_row_templates()
        .iter()
        .map(row_from_template)
        .collect()
}

const SUPPORT_ROW_TEMPLATES: [SupportRowTemplate; 13] = [
    SupportRowTemplate {
        feature_id: "readonly_ext4_btrfs_inspection",
        domain: "ext4/btrfs mounted inspection",
        legacy_count_bucket: "100_percent_v1_bucket",
        support_state: "validated",
        evidence_lane: "conformance fixtures plus mounted read-only smoke",
        artifact_freshness: "fresh authoritative gate required before stronger docs wording",
        gate_consumer: "release-gates:bd-rchk0.5.6.1",
        docs_wording_id: "support.readonly-inspection.validated",
        rationale: "validated read-only inspection may be claimed without mutating-readiness wording",
        owner_bead: "bd-mpcse",
        docs_target: "FEATURE_PARITY.md",
        release_gate_effect: "allows validated read-only wording only",
        old_count_claim: "100 percent V1 feature coverage",
        reason: "keeps inventory count separate from write and repair readiness",
    },
    SupportRowTemplate {
        feature_id: "btrfs_send_receive_streams",
        domain: "btrfs metadata parsing",
        legacy_count_bucket: "86/86,90/90,100_percent_buckets",
        support_state: "parse_only",
        evidence_lane: "send stream parser and dump comparison; no export/apply roundtrip",
        artifact_freshness: "roundtrip corpus required before support upgrade",
        gate_consumer: "release-gates:bd-rchk0.5.6.1",
        docs_wording_id: "support.btrfs-send-receive.parse-only",
        rationale: "full export/receive apply remains owned by bd-naww5",
        owner_bead: "bd-naww5",
        docs_target: "FEATURE_PARITY.md",
        release_gate_effect: "blocks full send/receive parity wording",
        old_count_claim: "100 percent btrfs metadata parsing",
        reason: "parser coverage is real but not operational send/receive readiness",
    },
    SupportRowTemplate {
        feature_id: "btrfs_multi_device_raid",
        domain: "btrfs metadata parsing",
        legacy_count_bucket: "90/90,100_percent_buckets",
        support_state: "single_device_only",
        evidence_lane: "single-device and stripe mapping fixtures; multi-image corpus pending",
        artifact_freshness: "multi-image degraded corpus required before support upgrade",
        gate_consumer: "release-gates:bd-rchk0.5.6.1",
        docs_wording_id: "support.btrfs-multidevice.single-device-only",
        rationale: "multi-device proof surface is owned by bd-ch373",
        owner_bead: "bd-ch373",
        docs_target: "FEATURE_PARITY.md",
        release_gate_effect: "downgrades multidevice readiness claims",
        old_count_claim: "100 percent btrfs metadata parsing",
        reason: "single-device evidence must not imply degraded multidevice readiness",
    },
    SupportRowTemplate {
        feature_id: "ext4_casefold",
        domain: "ext4 metadata parsing",
        legacy_count_bucket: "90/90,100_percent_buckets",
        support_state: "basic_coverage",
        evidence_lane: "basic lookup/readdir fixture coverage",
        artifact_freshness: "unicode collision corpus required before support upgrade",
        gate_consumer: "release-gates:bd-rchk0.5.6.1",
        docs_wording_id: "support.ext4-casefold.basic-coverage",
        rationale: "Unicode collision conformance is owned by bd-9er6s",
        owner_bead: "bd-9er6s",
        docs_target: "FEATURE_PARITY.md",
        release_gate_effect: "blocks robust casefold parity wording",
        old_count_claim: "100 percent ext4 metadata parsing",
        reason: "basic feature coverage is narrower than collision-safe mounted conformance",
    },
    SupportRowTemplate {
        feature_id: "mounted_write_paths",
        domain: "FUSE surface",
        legacy_count_bucket: "100_percent_v1_bucket",
        support_state: "experimental",
        evidence_lane: "mounted write matrix and crash/replay proof lanes",
        artifact_freshness: "fresh mounted matrix plus crash evidence required before support upgrade",
        gate_consumer: "release-gates:bd-rchk0.5.6.1",
        docs_wording_id: "support.mounted-writes.experimental",
        rationale: "write-path claims remain operator-caution until all gate lanes agree",
        owner_bead: "bd-jtu4q",
        docs_target: "README.md",
        release_gate_effect: "keeps mounted write wording experimental",
        old_count_claim: "100 percent FUSE surface",
        reason: "write success coverage is not the same as data-integrity readiness",
    },
    SupportRowTemplate {
        feature_id: "background_scrub",
        domain: "self-healing durability policy",
        legacy_count_bucket: "100_percent_v1_bucket",
        support_state: "detection_only",
        evidence_lane: "scrub detection evidence without automatic writeback promotion",
        artifact_freshness: "fresh repair side-effect fixtures required before support upgrade",
        gate_consumer: "release-gates:bd-rchk0.5.6.1",
        docs_wording_id: "support.background-scrub.detection-only",
        rationale: "mounted repair side effects are owned by bd-wjsuj",
        owner_bead: "bd-wjsuj",
        docs_target: "README.md",
        release_gate_effect: "allows detection-only scrub wording",
        old_count_claim: "100 percent self-healing durability policy",
        reason: "detection-only scrub must not imply automatic mutation readiness",
    },
    SupportRowTemplate {
        feature_id: "fuse_writeback_cache",
        domain: "FUSE surface",
        legacy_count_bucket: "100_percent_v1_bucket",
        support_state: "disabled",
        evidence_lane: "negative-option audit and runtime kill-switch gate",
        artifact_freshness: "fresh negative and positive ordering oracle required before support upgrade",
        gate_consumer: "release-gates:bd-rchk0.5.6.1",
        docs_wording_id: "support.writeback-cache.disabled",
        rationale: "writeback-cache opt-in is owned by bd-rchk0.2.1.1 and bd-4nobd",
        owner_bead: "bd-4nobd",
        docs_target: "README.md",
        release_gate_effect: "fails closed to disabled",
        old_count_claim: "100 percent FUSE surface",
        reason: "kernel writeback cache is unsafe unless ordering proof is fresh",
    },
    SupportRowTemplate {
        feature_id: "writeback_cache_negative_option",
        domain: "FUSE surface",
        legacy_count_bucket: "100_percent_v1_bucket",
        support_state: "deferred",
        evidence_lane: "negative-option audit proof pending",
        artifact_freshness: "fresh negative-option proof required",
        gate_consumer: "release-gates:bd-rchk0.5.6.1",
        docs_wording_id: "support.writeback-cache.negative-option-deferred",
        rationale: "negative-option audit remains open in bd-rchk0.2.1.1",
        owner_bead: "bd-rchk0.2.1.1",
        docs_target: "README.md",
        release_gate_effect: "blocks writeback-cache upgrade",
        old_count_claim: "100 percent FUSE surface",
        reason: "explicit deferred state prevents docs from hand-upgrading the option",
    },
    SupportRowTemplate {
        feature_id: "readonly_repair_with_ledger",
        domain: "self-healing durability policy",
        legacy_count_bucket: "100_percent_v1_bucket",
        support_state: "opt_in_mutating",
        evidence_lane: "operator opt-in repair ledger and side-effect boundary fixtures",
        artifact_freshness: "fresh mounted repair conformance required",
        gate_consumer: "release-gates:bd-rchk0.5.6.1",
        docs_wording_id: "support.readonly-repair.opt-in-mutating",
        rationale: "repair mutation must remain explicit operator opt-in",
        owner_bead: "bd-wjsuj",
        docs_target: "README.md",
        release_gate_effect: "allows opt-in-only repair wording",
        old_count_claim: "100 percent self-healing durability policy",
        reason: "repair mutation has a narrower supported envelope than durability inventory",
    },
    SupportRowTemplate {
        feature_id: "rw_background_repair",
        domain: "self-healing durability policy",
        legacy_count_bucket: "100_percent_v1_bucket",
        support_state: "host_blocked",
        evidence_lane: "read-write serialization gate absent or stale",
        artifact_freshness: "fresh two-key gate and rollback proof required",
        gate_consumer: "release-gates:bd-rchk0.5.6.1",
        docs_wording_id: "support.rw-background-repair.host-blocked",
        rationale: "rw automatic repair enablement is owned by bd-bqgy8",
        owner_bead: "bd-bqgy8",
        docs_target: "README.md",
        release_gate_effect: "blocks read-write automatic repair claims",
        old_count_claim: "100 percent self-healing durability policy",
        reason: "rw repair risks user data unless serialization and rollback proof is fresh",
    },
    SupportRowTemplate {
        feature_id: "performance_claim_budget",
        domain: "performance evidence",
        legacy_count_bucket: "not_counted_by_feature_parity",
        support_state: "dry_run_only",
        evidence_lane: "dry-run manifest validation and claim-tier budget checks",
        artifact_freshness: "authoritative benchmark artifacts required before support upgrade",
        gate_consumer: "release-gates:bd-rchk0.5.6.1",
        docs_wording_id: "support.performance.dry-run-only",
        rationale: "measured core benchmark execution remains owned by bd-rchk5.2",
        owner_bead: "bd-rchk5.2",
        docs_target: "README.md",
        release_gate_effect: "blocks performance claims stronger than experimental",
        old_count_claim: "historical performance wording outside feature counts",
        reason: "dry-run manifests control claims but do not replace benchmark data",
    },
    SupportRowTemplate {
        feature_id: "unsupported_legacy_ext4_codecs",
        domain: "ext4 metadata parsing",
        legacy_count_bucket: "100_percent_v1_bucket",
        support_state: "unsupported",
        evidence_lane: "deterministic EOPNOTSUPP rejection for excluded codecs",
        artifact_freshness: "explicit non-goal accepted until scope changes",
        gate_consumer: "release-gates:bd-rchk0.5.6.1",
        docs_wording_id: "support.ext4-legacy-codecs.unsupported",
        rationale: "rare e2compr methods lzv1, bzip2, and lzrw3a are explicit V1 non-goals",
        owner_bead: "bd-mpcse",
        docs_target: "FEATURE_PARITY.md",
        release_gate_effect: "permits unsupported wording only",
        old_count_claim: "100 percent ext4 metadata parsing",
        reason: "deterministic rejection counts as inventory coverage, not support",
    },
    SupportRowTemplate {
        feature_id: "performance_budget_enforcement",
        domain: "performance evidence",
        legacy_count_bucket: "not_counted_by_feature_parity",
        support_state: "validated",
        evidence_lane: "performance manifest claim-tier and budget validator",
        artifact_freshness: "manifest validation fresh as of bd-hol07 closure",
        gate_consumer: "release-gates:bd-rchk0.5.6.1",
        docs_wording_id: "support.performance-budget.validated",
        rationale: "claim-budget enforcement is implemented; benchmark execution remains separate",
        owner_bead: "bd-hol07",
        docs_target: "benchmarks/performance_baseline_manifest.json",
        release_gate_effect: "allows only budget-enforced performance wording",
        old_count_claim: "historical performance wording outside feature counts",
        reason: "budget enforcement is validated but does not prove workload speed",
    },
];

fn support_row_templates() -> &'static [SupportRowTemplate] {
    &SUPPORT_ROW_TEMPLATES
}

fn row_from_template(template: &SupportRowTemplate) -> SupportStateAccountingRow {
    SupportStateAccountingRow {
        feature_id: template.feature_id.to_owned(),
        domain: template.domain.to_owned(),
        legacy_count_bucket: template.legacy_count_bucket.to_owned(),
        support_state: template.support_state.to_owned(),
        evidence_lane: template.evidence_lane.to_owned(),
        artifact_freshness: template.artifact_freshness.to_owned(),
        gate_consumer: template.gate_consumer.to_owned(),
        docs_wording_id: template.docs_wording_id.to_owned(),
        unsupported_or_deferred_rationale: template.rationale.to_owned(),
        owner_bead: template.owner_bead.to_owned(),
        docs_target: template.docs_target.to_owned(),
        release_gate_effect: template.release_gate_effect.to_owned(),
        old_count_claim: template.old_count_claim.to_owned(),
        downgrade_or_upgrade_reason: template.reason.to_owned(),
        required_logs: REQUIRED_LOG_FIELDS.join(","),
        reproduction_command: REPRODUCTION_COMMAND.to_owned(),
    }
}

fn validate_support_state_rows(rows: &[SupportStateAccountingRow]) -> Vec<String> {
    let mut errors = Vec::new();
    let mut seen = BTreeSet::new();
    let states: BTreeSet<&str> = rows.iter().map(|row| row.support_state.as_str()).collect();

    for required_state in REQUIRED_SUPPORT_STATES {
        if !states.contains(required_state) {
            errors.push(format!("missing required support state {required_state}"));
        }
    }

    for row in rows {
        if !seen.insert(row.feature_id.clone()) {
            errors.push(format!("duplicate support-state row {}", row.feature_id));
        }
        require_row_field(row, "domain", &row.domain, &mut errors);
        require_row_field(
            row,
            "legacy_count_bucket",
            &row.legacy_count_bucket,
            &mut errors,
        );
        require_row_field(row, "support_state", &row.support_state, &mut errors);
        require_row_field(row, "evidence_lane", &row.evidence_lane, &mut errors);
        require_row_field(
            row,
            "artifact_freshness",
            &row.artifact_freshness,
            &mut errors,
        );
        require_row_field(row, "gate_consumer", &row.gate_consumer, &mut errors);
        require_row_field(row, "docs_wording_id", &row.docs_wording_id, &mut errors);
        require_row_field(row, "owner_bead", &row.owner_bead, &mut errors);
        require_row_field(row, "docs_target", &row.docs_target, &mut errors);
        require_row_field(
            row,
            "release_gate_effect",
            &row.release_gate_effect,
            &mut errors,
        );
        require_row_field(row, "old_count_claim", &row.old_count_claim, &mut errors);
        require_row_field(
            row,
            "downgrade_or_upgrade_reason",
            &row.downgrade_or_upgrade_reason,
            &mut errors,
        );

        if !REQUIRED_SUPPORT_STATES.contains(&row.support_state.as_str()) {
            errors.push(format!(
                "{} invalid support state {}",
                row.feature_id, row.support_state
            ));
        }
        if !row.gate_consumer.contains("bd-rchk0.5.6.1") {
            errors.push(format!(
                "{} does not compose with bd-rchk0.5.6.1",
                row.feature_id
            ));
        }
        if row.docs_wording_id == row.feature_id {
            errors.push(format!(
                "{} docs_wording_id must be a stable wording id",
                row.feature_id
            ));
        }
        if !row.owner_bead.starts_with("bd-") {
            errors.push(format!("{} owner_bead is not a bead id", row.feature_id));
        }
        if row.support_state != "validated" && row.unsupported_or_deferred_rationale.is_empty() {
            errors.push(format!(
                "{} non-validated state lacks rationale",
                row.feature_id
            ));
        }
        for field in REQUIRED_LOG_FIELDS {
            if !row.required_logs.contains(field) {
                errors.push(format!("{} required_logs missing {field}", row.feature_id));
            }
        }
        if !row
            .reproduction_command
            .contains("validate-support-state-accounting")
        {
            errors.push(format!(
                "{} missing validate-support-state-accounting reproduction command",
                row.feature_id
            ));
        }
    }
    errors
}

fn require_row_field(
    row: &SupportStateAccountingRow,
    field: &str,
    value: &str,
    errors: &mut Vec<String>,
) {
    if value.trim().is_empty() {
        errors.push(format!("{} missing {field}", row.feature_id));
    }
}

fn collect_reference_checks(
    rows: &[SupportStateAccountingRow],
    issues: &BTreeMap<String, IssueSummary>,
) -> Vec<SupportStateReferenceCheck> {
    let mut checks = Vec::new();
    for required in REQUIRED_OWNER_BEADS {
        checks.push(reference_check(
            "support-state-accounting",
            required,
            "required_owner_beads",
            issues,
        ));
    }
    for row in rows {
        checks.push(reference_check(
            &row.feature_id,
            &row.owner_bead,
            "owner_bead",
            issues,
        ));
    }
    checks
}

fn reference_check(
    feature_id: &str,
    referenced_bead_id: &str,
    field: &str,
    issues: &BTreeMap<String, IssueSummary>,
) -> SupportStateReferenceCheck {
    SupportStateReferenceCheck {
        feature_id: feature_id.to_owned(),
        referenced_bead_id: referenced_bead_id.to_owned(),
        field: field.to_owned(),
        exists: issues
            .get(referenced_bead_id)
            .is_some_and(|issue| issue.id == referenced_bead_id),
    }
}

fn default_historical_claims_json() -> &'static str {
    r#"[
  {"historical_claim":"FEATURE_PARITY 86/86","feature_id":"btrfs_send_receive_streams","evidence_profile":"parse-only stream parser"},
  {"historical_claim":"FEATURE_PARITY 86/86","feature_id":"btrfs_multi_device_raid","evidence_profile":"single-device-only multidevice fixture"},
  {"historical_claim":"FEATURE_PARITY 90/90","feature_id":"ext4_casefold","evidence_profile":"basic casefold lookup"},
  {"historical_claim":"FEATURE_PARITY 90/90","feature_id":"mounted_write_paths","evidence_profile":"experimental mount/write"},
  {"historical_claim":"FEATURE_PARITY 100 percent","feature_id":"background_scrub","evidence_profile":"detection-only scrub"},
  {"historical_claim":"FEATURE_PARITY 100 percent","feature_id":"fuse_writeback_cache","evidence_profile":"disabled writeback-cache"},
  {"historical_claim":"FEATURE_PARITY 100 percent","feature_id":"rw_background_repair","evidence_profile":"rw repair blocked"},
  {"historical_claim":"FEATURE_PARITY 100 percent","feature_id":"readonly_ext4_btrfs_inspection","evidence_profile":"validated read-only inspection"}
]"#
}

pub fn classify_historical_claims(
    claims_json: &str,
    errors: &mut Vec<String>,
) -> Vec<SupportStateMigrationCase> {
    let claims = match serde_json::from_str::<Vec<HistoricalParityClaim>>(claims_json) {
        Ok(claims) => claims,
        Err(err) => {
            errors.push(format!("invalid historical parity claim fixture: {err}"));
            return Vec::new();
        }
    };

    claims
        .into_iter()
        .map(|claim| migration_case_from_claim(&claim))
        .collect()
}

fn migration_case_from_claim(claim: &HistoricalParityClaim) -> SupportStateMigrationCase {
    let rows = support_state_rows();
    if let Some(row) = rows.iter().find(|row| row.feature_id == claim.feature_id) {
        return SupportStateMigrationCase {
            historical_claim: claim.historical_claim.clone(),
            feature_id: claim.feature_id.clone(),
            old_bucket: row.legacy_count_bucket.clone(),
            classified_support_state: row.support_state.clone(),
            docs_safe_claim: format!(
                "{} may claim `{}` only with wording id `{}`",
                claim.feature_id, row.support_state, row.docs_wording_id
            ),
            owner_bead: row.owner_bead.clone(),
        };
    }

    SupportStateMigrationCase {
        historical_claim: claim.historical_claim.clone(),
        feature_id: claim.feature_id.clone(),
        old_bucket: "unknown".to_owned(),
        classified_support_state: "deferred".to_owned(),
        docs_safe_claim: "unknown historical feature must remain deferred until classified"
            .to_owned(),
        owner_bead: "bd-mpcse".to_owned(),
    }
}

fn validate_migration_cases(cases: &[SupportStateMigrationCase]) -> Vec<String> {
    let mut errors = Vec::new();
    let expected = [
        ("btrfs_send_receive_streams", "parse_only"),
        ("btrfs_multi_device_raid", "single_device_only"),
        ("ext4_casefold", "basic_coverage"),
        ("mounted_write_paths", "experimental"),
        ("background_scrub", "detection_only"),
        ("fuse_writeback_cache", "disabled"),
        ("rw_background_repair", "host_blocked"),
        ("readonly_ext4_btrfs_inspection", "validated"),
    ];

    for (feature_id, expected_state) in expected {
        let Some(case) = cases.iter().find(|case| case.feature_id == feature_id) else {
            errors.push(format!("missing migration case {feature_id}"));
            continue;
        };
        if case.classified_support_state != expected_state {
            errors.push(format!(
                "{} classified as {}, expected {expected_state}",
                feature_id, case.classified_support_state
            ));
        }
    }

    for old_claim in [
        "FEATURE_PARITY 86/86",
        "FEATURE_PARITY 90/90",
        "FEATURE_PARITY 100 percent",
    ] {
        if !cases.iter().any(|case| case.historical_claim == old_claim) {
            errors.push(format!("missing historical claim fixture {old_claim}"));
        }
    }
    errors
}

fn validate_feature_parity_wording(markdown: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let lower = markdown.to_ascii_lowercase();
    let has_flat_claim =
        lower.contains("100.0%") || lower.contains("100%") || lower.contains("100 percent");
    if !has_flat_claim {
        return errors;
    }

    for token in REQUIRED_DOC_WORDING_TOKENS {
        if !markdown.contains(token) {
            errors.push(format!(
                "FEATURE_PARITY.md contains flat 100 percent parity wording without `{token}`"
            ));
        }
    }
    errors
}

fn group_by<F>(rows: &[SupportStateAccountingRow], key_fn: F) -> BTreeMap<String, Vec<String>>
where
    F: Fn(&SupportStateAccountingRow) -> &str,
{
    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for row in rows {
        grouped
            .entry(key_fn(row).to_owned())
            .or_default()
            .push(row.feature_id.clone());
    }
    grouped
}

pub fn fail_on_support_state_accounting_errors(
    report: &SupportStateAccountingReport,
) -> Result<()> {
    if report.errors.is_empty() {
        Ok(())
    } else {
        bail!(
            "support-state accounting failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_issue(id: &str) -> String {
        format!(r#"{{"id":"{id}","title":"{id}","status":"open","labels":["test"]}}"#)
    }

    fn fixture_issues() -> String {
        REQUIRED_OWNER_BEADS
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

    #[test]
    fn builds_support_state_report_without_errors() {
        let report = analyze_support_state_accounting(
            &fixture_issues(),
            &feature_parity_fixture(),
            &[
                DEFAULT_ARTIFACT_PATH.to_owned(),
                DEFAULT_MARKDOWN_PATH.to_owned(),
            ],
        );
        assert!(
            report.errors.is_empty(),
            "unexpected errors: {:?}",
            report.errors
        );
        assert_eq!(report.support_state_version, SUPPORT_STATE_VERSION);
        assert!(report.flat_parity_rejected);
        assert!(report.release_gate_contract.contains("bd-rchk0.5.6.1"));
        assert_eq!(report.coverage_domain_count, 5);
    }

    #[test]
    fn rows_cover_required_schema_fields_and_states() {
        let rows = support_state_rows();
        let errors = validate_support_state_rows(&rows);
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
        let states: BTreeSet<&str> = rows.iter().map(|row| row.support_state.as_str()).collect();
        for state in REQUIRED_SUPPORT_STATES {
            assert!(states.contains(state), "missing state {state}");
        }
        let sample = rows
            .iter()
            .find(|row| row.feature_id == "btrfs_send_receive_streams")
            .expect("send/receive row");
        assert_eq!(sample.support_state, "parse_only");
        assert_eq!(sample.owner_bead, "bd-naww5");
        assert!(sample.required_logs.contains("feature_id"));
        assert!(sample.docs_wording_id.starts_with("support."));
    }

    #[test]
    fn migration_fixture_classifies_historical_flat_claims() {
        let mut errors = Vec::new();
        let cases = classify_historical_claims(default_historical_claims_json(), &mut errors);
        errors.extend(validate_migration_cases(&cases));
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
        let states: BTreeMap<&str, &str> = cases
            .iter()
            .map(|case| {
                (
                    case.feature_id.as_str(),
                    case.classified_support_state.as_str(),
                )
            })
            .collect();
        assert_eq!(states["btrfs_send_receive_streams"], "parse_only");
        assert_eq!(states["btrfs_multi_device_raid"], "single_device_only");
        assert_eq!(states["ext4_casefold"], "basic_coverage");
        assert_eq!(states["mounted_write_paths"], "experimental");
        assert_eq!(states["background_scrub"], "detection_only");
        assert_eq!(states["fuse_writeback_cache"], "disabled");
        assert_eq!(states["rw_background_repair"], "host_blocked");
        assert_eq!(states["readonly_ext4_btrfs_inspection"], "validated");
    }

    #[test]
    fn rejects_unscoped_flat_parity_wording() {
        let errors = validate_feature_parity_wording(
            "Overall 97/97 100.0%. FrankenFS has 100 percent parity.",
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("support-state accounting")),
            "errors were {errors:?}"
        );
    }

    #[test]
    fn accepts_scoped_flat_count_inventory_wording() {
        let errors = validate_feature_parity_wording(&feature_parity_fixture());
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn reports_missing_owner_bead_references() {
        let report = analyze_support_state_accounting(
            &fixture_issue("bd-mpcse"),
            &feature_parity_fixture(),
            &[DEFAULT_ARTIFACT_PATH.to_owned()],
        );
        assert!(
            report.errors.iter().any(|error| error.contains("bd-naww5")),
            "errors were {:?}",
            report.errors
        );
    }

    #[test]
    fn renders_markdown_human_report() {
        let report = analyze_support_state_accounting(
            &fixture_issues(),
            &feature_parity_fixture(),
            &[DEFAULT_ARTIFACT_PATH.to_owned()],
        );
        let markdown = render_support_state_markdown(&report);
        assert!(markdown.contains("# FrankenFS Support-State Accounting"));
        assert!(markdown.contains("btrfs_send_receive_streams"));
        assert!(markdown.contains("Required Log Fields"));
    }
}
