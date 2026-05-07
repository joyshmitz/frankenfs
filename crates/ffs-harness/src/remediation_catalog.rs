#![forbid(unsafe_code)]

//! User remediation catalog for proof failures and readiness blockers.
//!
//! Tracks bd-rchk0.5.12: every readiness outcome (product failure, host
//! capability skip, security refusal, repair confidence state, stale artifact,
//! unsupported feature) maps to a user-facing remediation entry that names a
//! data-safety severity, an immediate operator action, an owning bead, and a
//! docs target. Release gates and proof bundles consume this catalog so they
//! can fail closed when an outcome lacks a concrete next action.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

pub const REMEDIATION_CATALOG_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_REMEDIATION_CATALOG_PATH: &str =
    "tests/remediation-catalog/remediation_catalog.json";
const DEFAULT_REMEDIATION_CATALOG_JSON: &str =
    include_str!("../../../tests/remediation-catalog/remediation_catalog.json");
const REPO_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

const ALLOWED_PROOF_LANES: [&str; 9] = [
    "core_unit",
    "core_property",
    "mounted_smoke",
    "mounted_xfstests",
    "repair_lab",
    "crash_replay",
    "fuzz",
    "performance",
    "long_campaign",
];

const ALLOWED_FEATURE_STATES: [&str; 8] = [
    "validated",
    "experimental",
    "detection_only",
    "dry_run_only",
    "opt_in_mutating",
    "disabled",
    "unsupported",
    "deferred",
];

const ALLOWED_OUTCOME_CLASSES: [&str; 7] = [
    "product_failure",
    "host_capability_skip",
    "unsupported_operation",
    "stale_artifact",
    "security_refusal",
    "unsafe_repair_refusal",
    "passing_with_caveat",
];

const ALLOWED_DATA_SAFETY_SEVERITIES: [&str; 5] = [
    "no_user_data_at_risk",
    "potential_data_loss",
    "data_loss_blocked_by_refusal",
    "data_loss_recoverable",
    "data_loss_unrecoverable",
];

const REQUIRED_OUTCOME_COVERAGE: [&str; 7] = [
    "product_failure",
    "host_capability_skip",
    "unsupported_operation",
    "stale_artifact",
    "security_refusal",
    "unsafe_repair_refusal",
    "passing_with_caveat",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationCatalog {
    pub schema_version: u32,
    pub catalog_id: String,
    pub bead_id: String,
    pub entries: Vec<RemediationEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationEntry {
    pub id: String,
    pub proof_lane: String,
    pub feature_state: String,
    pub outcome_class: String,
    pub data_safety_severity: String,
    pub mutation_status: String,
    pub user_summary: String,
    pub technical_cause: String,
    pub immediate_action: String,
    pub safe_retry_policy: String,
    pub reproduction_command: String,
    pub artifact_links: Vec<String>,
    pub owning_bead: String,
    pub escalation_path: String,
    pub docs_target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationCatalogReport {
    pub schema_version: u32,
    pub catalog_id: String,
    pub bead_id: String,
    pub entry_count: usize,
    pub outcome_classes: Vec<String>,
    pub feature_states: Vec<String>,
    pub valid: bool,
    pub errors: Vec<String>,
}

pub fn parse_remediation_catalog(text: &str) -> Result<RemediationCatalog> {
    serde_json::from_str(text)
        .map_err(|err| anyhow::anyhow!("failed to parse remediation catalog JSON: {err}"))
}

pub fn validate_default_remediation_catalog() -> Result<RemediationCatalogReport> {
    let catalog = parse_remediation_catalog(DEFAULT_REMEDIATION_CATALOG_JSON)?;
    let report = validate_remediation_catalog(&catalog);
    if !report.valid {
        bail!(
            "remediation catalog failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        );
    }
    Ok(report)
}

#[must_use]
pub fn validate_remediation_catalog(catalog: &RemediationCatalog) -> RemediationCatalogReport {
    let mut errors = Vec::new();
    let mut ids = BTreeSet::new();
    let mut outcome_classes = BTreeSet::new();
    let mut feature_states = BTreeSet::new();

    validate_remediation_top_level(catalog, &mut errors);

    for entry in &catalog.entries {
        validate_remediation_entry(
            entry,
            &mut ids,
            &mut outcome_classes,
            &mut feature_states,
            &mut errors,
        );
    }

    validate_outcome_class_coverage(&outcome_classes, &mut errors);

    RemediationCatalogReport {
        schema_version: catalog.schema_version,
        catalog_id: catalog.catalog_id.clone(),
        bead_id: catalog.bead_id.clone(),
        entry_count: catalog.entries.len(),
        outcome_classes: outcome_classes.into_iter().collect(),
        feature_states: feature_states.into_iter().collect(),
        valid: errors.is_empty(),
        errors,
    }
}

fn validate_remediation_top_level(catalog: &RemediationCatalog, errors: &mut Vec<String>) {
    if catalog.schema_version != REMEDIATION_CATALOG_SCHEMA_VERSION {
        errors.push(format!(
            "remediation catalog schema_version must be {REMEDIATION_CATALOG_SCHEMA_VERSION}, got {}",
            catalog.schema_version
        ));
    }
    if catalog.catalog_id.trim().is_empty() {
        errors.push("remediation catalog missing catalog_id".to_owned());
    }
    if !catalog.bead_id.starts_with("bd-") {
        errors.push(format!(
            "remediation catalog bead_id must look like bd-..., got `{}`",
            catalog.bead_id
        ));
    }
    if catalog.entries.is_empty() {
        errors.push("remediation catalog must declare at least one entry".to_owned());
    }
}

fn validate_remediation_entry(
    entry: &RemediationEntry,
    ids: &mut BTreeSet<String>,
    outcome_classes: &mut BTreeSet<String>,
    feature_states: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    if !ids.insert(entry.id.clone()) {
        errors.push(format!("duplicate remediation id `{}`", entry.id));
    }
    if entry.id.trim().is_empty() {
        errors.push("remediation entry has empty id".to_owned());
    }
    validate_remediation_vocabulary(entry, outcome_classes, feature_states, errors);
    validate_remediation_required_text(entry, errors);
    validate_reproduction_script_paths(
        &format!("remediation `{}`", entry.id),
        &entry.reproduction_command,
        errors,
    );
    validate_remediation_links(entry, errors);
    validate_remediation_safety_invariants(entry, errors);
}

fn validate_remediation_vocabulary(
    entry: &RemediationEntry,
    outcome_classes: &mut BTreeSet<String>,
    feature_states: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    if !ALLOWED_PROOF_LANES.contains(&entry.proof_lane.as_str()) {
        errors.push(format!(
            "remediation `{}` has unsupported proof_lane `{}`",
            entry.id, entry.proof_lane
        ));
    }
    if ALLOWED_FEATURE_STATES.contains(&entry.feature_state.as_str()) {
        feature_states.insert(entry.feature_state.clone());
    } else {
        errors.push(format!(
            "remediation `{}` has unsupported feature_state `{}`",
            entry.id, entry.feature_state
        ));
    }
    if ALLOWED_OUTCOME_CLASSES.contains(&entry.outcome_class.as_str()) {
        outcome_classes.insert(entry.outcome_class.clone());
    } else {
        errors.push(format!(
            "remediation `{}` has unsupported outcome_class `{}`",
            entry.id, entry.outcome_class
        ));
    }
    if !ALLOWED_DATA_SAFETY_SEVERITIES.contains(&entry.data_safety_severity.as_str()) {
        errors.push(format!(
            "remediation `{}` has unsupported data_safety_severity `{}`",
            entry.id, entry.data_safety_severity
        ));
    }
    if !["none", "dry_run", "applied", "rolled_back", "refused"]
        .contains(&entry.mutation_status.as_str())
    {
        errors.push(format!(
            "remediation `{}` has unsupported mutation_status `{}`",
            entry.id, entry.mutation_status
        ));
    }
}

fn validate_remediation_required_text(entry: &RemediationEntry, errors: &mut Vec<String>) {
    let required_fields = [
        ("user_summary", &entry.user_summary),
        ("technical_cause", &entry.technical_cause),
        ("immediate_action", &entry.immediate_action),
        ("safe_retry_policy", &entry.safe_retry_policy),
        ("reproduction_command", &entry.reproduction_command),
        ("escalation_path", &entry.escalation_path),
        ("docs_target", &entry.docs_target),
    ];
    for (field, value) in required_fields {
        if value.trim().is_empty() {
            errors.push(format!("remediation `{}` missing {field}", entry.id));
        }
    }
}

fn validate_remediation_links(entry: &RemediationEntry, errors: &mut Vec<String>) {
    if !entry.owning_bead.starts_with("bd-") {
        errors.push(format!(
            "remediation `{}` owning_bead must look like bd-..., got `{}`",
            entry.id, entry.owning_bead
        ));
    }
    if entry.artifact_links.is_empty() {
        errors.push(format!(
            "remediation `{}` must declare at least one artifact_link",
            entry.id
        ));
    }
    for link in &entry.artifact_links {
        if link.trim().is_empty() {
            errors.push(format!(
                "remediation `{}` has empty artifact_link",
                entry.id
            ));
        }
    }
    if !entry.docs_target.contains('/')
        && !entry.docs_target.starts_with("README")
        && !entry.docs_target.starts_with("FEATURE_PARITY")
    {
        errors.push(format!(
            "remediation `{}` docs_target must name a path or canonical doc",
            entry.id
        ));
    }
}

fn validate_remediation_safety_invariants(entry: &RemediationEntry, errors: &mut Vec<String>) {
    let is_refusal =
        entry.outcome_class == "security_refusal" || entry.outcome_class == "unsafe_repair_refusal";
    let claims_no_data_loss = entry.data_safety_severity == "data_loss_blocked_by_refusal"
        || entry.data_safety_severity == "no_user_data_at_risk";
    if is_refusal && !claims_no_data_loss {
        errors.push(format!(
            "remediation `{}` refusal outcome must classify data_safety_severity as `data_loss_blocked_by_refusal` or `no_user_data_at_risk`",
            entry.id
        ));
    }
    if entry.mutation_status == "applied"
        && entry.data_safety_severity == "data_loss_unrecoverable"
        && entry.outcome_class != "product_failure"
    {
        errors.push(format!(
            "remediation `{}` applied mutation with unrecoverable data loss must classify as product_failure",
            entry.id
        ));
    }
    if entry.outcome_class == "passing_with_caveat" && entry.feature_state == "validated" {
        errors.push(format!(
            "remediation `{}` passing_with_caveat must not claim feature_state=validated",
            entry.id
        ));
    }
}

fn validate_outcome_class_coverage(seen: &BTreeSet<String>, errors: &mut Vec<String>) {
    for required in REQUIRED_OUTCOME_COVERAGE {
        if !seen.contains(required) {
            errors.push(format!(
                "remediation catalog missing required outcome_class `{required}`"
            ));
        }
    }
}

fn validate_reproduction_script_paths(owner: &str, command: &str, errors: &mut Vec<String>) {
    for script_path in e2e_script_paths(command) {
        if !Path::new(REPO_ROOT).join(script_path).is_file() {
            errors.push(format!(
                "{owner} reproduction_command references missing script `{script_path}`"
            ));
        }
    }
}

fn e2e_script_paths(command: &str) -> impl Iterator<Item = &str> {
    command.split_whitespace().filter_map(|raw| {
        let token =
            raw.trim_matches(|ch: char| matches!(ch, '\'' | '"' | '`' | ';' | ',' | '(' | ')'));
        let token = token.strip_prefix("./").unwrap_or(token);
        (token.starts_with("scripts/e2e/")
            && Path::new(token)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("sh")))
        .then_some(token)
    })
}

#[must_use]
pub fn render_remediation_markdown(catalog: &RemediationCatalog) -> String {
    let mut output = String::new();
    let _ = writeln!(
        &mut output,
        "# Remediation Catalog `{}` (bead {})",
        catalog.catalog_id, catalog.bead_id
    );
    let _ = writeln!(&mut output);
    let _ = writeln!(
        &mut output,
        "| ID | Outcome | Feature State | Data-Safety | Mutation | Owner | Action |"
    );
    let _ = writeln!(
        &mut output,
        "|----|---------|---------------|-------------|----------|-------|--------|"
    );
    for entry in &catalog.entries {
        let _ = writeln!(
            &mut output,
            "| {} | {} | {} | {} | {} | {} | {} |",
            entry.id,
            entry.outcome_class,
            entry.feature_state,
            entry.data_safety_severity,
            entry.mutation_status,
            entry.owning_bead,
            entry.immediate_action.replace('|', "\\|"),
        );
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_catalog() -> RemediationCatalog {
        parse_remediation_catalog(DEFAULT_REMEDIATION_CATALOG_JSON)
            .expect("default remediation catalog parses")
    }

    #[test]
    fn default_catalog_validates_required_outcomes() {
        let report =
            validate_default_remediation_catalog().expect("default remediation catalog validates");
        assert_eq!(report.bead_id, "bd-rchk0.5.12");
        assert_eq!(report.schema_version, REMEDIATION_CATALOG_SCHEMA_VERSION);
        assert!(report.entry_count >= REQUIRED_OUTCOME_COVERAGE.len());
        for outcome in REQUIRED_OUTCOME_COVERAGE {
            assert!(
                report.outcome_classes.iter().any(|o| o == outcome),
                "missing outcome class {outcome}"
            );
        }
    }

    #[test]
    fn default_catalog_covers_mvcc_merge_proof_refusals() {
        let catalog = fixture_catalog();
        let entry = catalog
            .entries
            .iter()
            .find(|entry| entry.id == "rem_mvcc_merge_proof_validation_failed")
            .expect("catalog should include MVCC merge-proof remediation");

        assert_eq!(entry.proof_lane, "core_property");
        assert_eq!(entry.feature_state, "experimental");
        assert_eq!(entry.outcome_class, "product_failure");
        assert_eq!(entry.data_safety_severity, "data_loss_blocked_by_refusal");
        assert_eq!(entry.mutation_status, "refused");
        assert_eq!(entry.safe_retry_policy, "no_retry_until_root_cause");
        assert_eq!(entry.owning_bead, "bd-rchk0.53.11");
        assert!(
            entry.technical_cause.contains("merge_proof_checked=false")
                && entry.technical_cause.contains("merge_rejected"),
            "technical cause should point operators back to the evidence events"
        );
        assert!(
            entry
                .artifact_links
                .iter()
                .any(|link| link.ends_with(".evidence.jsonl")),
            "merge-proof remediation should preserve the evidence ledger"
        );
    }

    #[test]
    fn missing_outcome_class_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog
            .entries
            .retain(|entry| entry.outcome_class != "host_capability_skip");
        let report = validate_remediation_catalog(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required outcome_class `host_capability_skip`"))
        );
    }

    #[test]
    fn missing_security_refusal_outcome_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog
            .entries
            .retain(|entry| entry.outcome_class != "security_refusal");
        let report = validate_remediation_catalog(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required outcome_class `security_refusal`"))
        );
    }

    #[test]
    fn missing_unsafe_repair_outcome_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog
            .entries
            .retain(|entry| entry.outcome_class != "unsafe_repair_refusal");
        let report = validate_remediation_catalog(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required outcome_class `unsafe_repair_refusal`"))
        );
    }

    #[test]
    fn duplicate_id_is_rejected() {
        let mut catalog = fixture_catalog();
        let dup = catalog.entries[0].id.clone();
        catalog.entries[1].id = dup;
        let report = validate_remediation_catalog(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("duplicate remediation id"))
        );
    }

    #[test]
    fn unsupported_proof_lane_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog.entries[0].proof_lane = "vibes_lane".to_owned();
        let report = validate_remediation_catalog(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported proof_lane"))
        );
    }

    #[test]
    fn unsupported_feature_state_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog.entries[0].feature_state = "telepathy".to_owned();
        let report = validate_remediation_catalog(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported feature_state"))
        );
    }

    #[test]
    fn unsupported_data_safety_severity_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog.entries[0].data_safety_severity = "kinda_safe".to_owned();
        let report = validate_remediation_catalog(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported data_safety_severity"))
        );
    }

    #[test]
    fn unsupported_mutation_status_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog.entries[0].mutation_status = "yolo".to_owned();
        let report = validate_remediation_catalog(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported mutation_status"))
        );
    }

    #[test]
    fn missing_user_summary_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog.entries[0].user_summary = String::new();
        let report = validate_remediation_catalog(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing user_summary"))
        );
    }

    #[test]
    fn missing_immediate_action_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog.entries[0].immediate_action = String::new();
        let report = validate_remediation_catalog(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing immediate_action"))
        );
    }

    #[test]
    fn missing_reproduction_command_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog.entries[0].reproduction_command = String::new();
        let report = validate_remediation_catalog(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing reproduction_command"))
        );
    }

    #[test]
    fn missing_reproduction_script_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog.entries[0].reproduction_command =
            "scripts/e2e/ffs_missing_remediation_runner.sh".to_owned();
        let report = validate_remediation_catalog(&catalog);
        assert!(report.errors.iter().any(|err| {
            err.contains("references missing script")
                && err.contains("ffs_missing_remediation_runner.sh")
        }));
    }

    #[test]
    fn missing_artifact_links_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog.entries[0].artifact_links.clear();
        let report = validate_remediation_catalog(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("at least one artifact_link"))
        );
    }

    #[test]
    fn malformed_owning_bead_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog.entries[0].owning_bead = "PROJ-42".to_owned();
        let report = validate_remediation_catalog(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("owning_bead must look like bd-"))
        );
    }

    #[test]
    fn refusal_with_loss_classification_is_rejected() {
        let mut catalog = fixture_catalog();
        let refusal = catalog
            .entries
            .iter_mut()
            .find(|entry| entry.outcome_class == "security_refusal")
            .expect("fixture has security_refusal entry");
        refusal.data_safety_severity = "data_loss_unrecoverable".to_owned();
        let report = validate_remediation_catalog(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("refusal outcome must classify"))
        );
    }

    #[test]
    fn passing_with_caveat_cannot_claim_validated() {
        let mut catalog = fixture_catalog();
        let caveat = catalog
            .entries
            .iter_mut()
            .find(|entry| entry.outcome_class == "passing_with_caveat")
            .expect("fixture has passing_with_caveat entry");
        caveat.feature_state = "validated".to_owned();
        let report = validate_remediation_catalog(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err
                    .contains("passing_with_caveat must not claim feature_state=validated"))
        );
    }

    #[test]
    fn empty_entries_list_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog.entries.clear();
        let report = validate_remediation_catalog(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("at least one entry"))
        );
    }

    #[test]
    fn render_markdown_includes_all_entries() {
        let catalog = fixture_catalog();
        let markdown = render_remediation_markdown(&catalog);
        for entry in &catalog.entries {
            assert!(
                markdown.contains(&entry.id),
                "rendered markdown missing id {}",
                entry.id
            );
            assert!(
                markdown.contains(&entry.outcome_class),
                "rendered markdown missing outcome {}",
                entry.outcome_class
            );
        }
    }

    /// bd-aofgb — golden-output snapshot for
    /// `render_remediation_markdown` on the default catalog. Pins the
    /// title format, blank line, table header, alignment row, the
    /// per-row cell field order
    /// (id|outcome|feature_state|data_safety|mutation|owner|action),
    /// and the `\|` escape rule for the `immediate_action` column.
    /// Substring-only assertions in `render_markdown_includes_all_entries`
    /// cannot detect column reorders or alignment-row drift; this
    /// snapshot does.
    #[test]
    fn render_remediation_markdown_default_catalog_snapshot() {
        let catalog = fixture_catalog();
        let markdown = render_remediation_markdown(&catalog);
        insta::assert_snapshot!("render_remediation_markdown_default_catalog", markdown);
    }
}
