#![forbid(unsafe_code)]

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const INVENTORY_MARKDOWN: &str =
    include_str!("../../../docs/reports/FUZZ_AND_CONFORMANCE_INVENTORY.md");
const INVENTORY_HEADING: &str = "## Open-Ended Inventory Registry";

const REQUIRED_HEADERS: [&str; 12] = [
    "ID",
    "Source location",
    "Risk surface",
    "Current evidence",
    "Required proof type",
    "Expected unit coverage",
    "Expected E2E/fuzz-smoke coverage",
    "Log/artifact expectations",
    "Decision",
    "Linked bead or artifact",
    "Owner/status",
    "Non-applicability rationale",
];

const PROOF_TYPES: [&str; 8] = [
    "parser-unit",
    "mounted-e2e",
    "corpus-seed",
    "golden-fixture",
    "long-campaign",
    "property-test",
    "security-audit",
    "docs-non-goal",
];

const DECISIONS: [&str; 4] = [
    "active-bead",
    "artifact-covered",
    "explicit-non-goal",
    "needs-follow-up",
];

const COVERAGE_STATES: [&str; 4] = ["required", "existing", "not-applicable", "deferred"];
const REQUIRED_LOG_TOKENS: [&str; 4] =
    ["source_path", "row_id", "decision", "reproduction_command"];
const REQUIRED_ARTIFACT_TOKENS: [&str; 2] = ["artifact_path", "owner_status"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenEndedInventoryReport {
    pub row_count: usize,
    pub proof_types: Vec<String>,
    pub decisions: Vec<String>,
    pub rows: Vec<OpenEndedInventoryRow>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenEndedInventoryRow {
    pub id: String,
    pub source_location: String,
    pub risk_surface: String,
    pub current_evidence: String,
    pub required_proof_type: String,
    pub expected_unit_coverage: String,
    pub expected_e2e_fuzz_smoke_coverage: String,
    pub log_artifact_expectations: String,
    pub decision: String,
    pub linked_bead_or_artifact: String,
    pub owner_status: String,
    pub non_applicability_rationale: String,
}

#[must_use]
pub fn analyze_inventory(markdown: &str) -> OpenEndedInventoryReport {
    let mut errors = Vec::new();
    let rows = parse_inventory_rows(markdown, &mut errors);
    let seen_ids = rows.iter().map(|row| row.id.as_str()).collect::<Vec<_>>();
    validate_unique_ids(&seen_ids, &mut errors);
    for row in &rows {
        validate_row(row, &mut errors);
    }

    OpenEndedInventoryReport {
        row_count: rows.len(),
        proof_types: PROOF_TYPES
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        decisions: DECISIONS.iter().map(|value| (*value).to_owned()).collect(),
        rows,
        errors,
    }
}

pub fn validate_current_inventory() -> Result<OpenEndedInventoryReport> {
    let report = analyze_inventory(INVENTORY_MARKDOWN);
    if !report.errors.is_empty() {
        bail!(
            "open-ended inventory validation failed: {}",
            report.errors.join("; ")
        );
    }
    Ok(report)
}

fn parse_inventory_rows(markdown: &str, errors: &mut Vec<String>) -> Vec<OpenEndedInventoryRow> {
    let Some(table_lines) = inventory_table_lines(markdown) else {
        errors.push(format!("missing inventory heading `{INVENTORY_HEADING}`"));
        return Vec::new();
    };

    if table_lines.len() < 3 {
        errors.push("inventory table must include header, separator, and rows".to_owned());
        return Vec::new();
    }

    let header = split_table_row(table_lines[0]);
    if header != REQUIRED_HEADERS {
        errors.push(format!(
            "inventory table header mismatch: expected {REQUIRED_HEADERS:?}, got {header:?}"
        ));
        return Vec::new();
    }

    table_lines
        .iter()
        .skip(2)
        .filter_map(|line| {
            let cells = split_table_row(line);
            if cells.len() != REQUIRED_HEADERS.len() {
                errors.push(format!(
                    "inventory row has {} cells, expected {}: {line}",
                    cells.len(),
                    REQUIRED_HEADERS.len()
                ));
                return None;
            }
            Some(OpenEndedInventoryRow {
                id: cells[0].clone(),
                source_location: cells[1].clone(),
                risk_surface: cells[2].clone(),
                current_evidence: cells[3].clone(),
                required_proof_type: cells[4].clone(),
                expected_unit_coverage: cells[5].clone(),
                expected_e2e_fuzz_smoke_coverage: cells[6].clone(),
                log_artifact_expectations: cells[7].clone(),
                decision: cells[8].clone(),
                linked_bead_or_artifact: cells[9].clone(),
                owner_status: cells[10].clone(),
                non_applicability_rationale: cells[11].clone(),
            })
        })
        .collect()
}

fn inventory_table_lines(markdown: &str) -> Option<Vec<&str>> {
    let mut in_section = false;
    let mut lines = Vec::new();

    for line in markdown.lines() {
        if line.trim() == INVENTORY_HEADING {
            in_section = true;
            continue;
        }
        if in_section && line.starts_with("## ") {
            break;
        }
        if in_section && line.trim_start().starts_with('|') {
            lines.push(line);
        }
    }

    (!lines.is_empty()).then_some(lines)
}

fn split_table_row(line: &str) -> Vec<String> {
    line.trim()
        .trim_matches('|')
        .split('|')
        .map(|cell| normalize_cell(cell.trim()))
        .collect()
}

fn normalize_cell(cell: &str) -> String {
    cell.replace("<br>", "; ")
        .replace("&nbsp;", " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn validate_unique_ids(ids: &[&str], errors: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    for id in ids {
        if !seen.insert(*id) {
            errors.push(format!("duplicate inventory row id `{id}`"));
        }
    }
}

fn validate_row(row: &OpenEndedInventoryRow, errors: &mut Vec<String>) {
    validate_row_id(&row.id, errors);
    validate_non_empty_fields(row, errors);
    validate_vocabulary(row, errors);
    validate_log_and_artifact_fields(row, errors);
    validate_linkage(row, errors);
}

fn validate_row_id(id: &str, errors: &mut Vec<String>) {
    let mut chars = id.chars();
    let Some(prefix) = chars.next() else {
        errors.push("inventory row id is empty".to_owned());
        return;
    };
    if !prefix.is_ascii_uppercase() || !chars.all(|ch| ch.is_ascii_digit()) {
        errors.push(format!("inventory row id `{id}` must look like A1"));
    }
}

fn validate_non_empty_fields(row: &OpenEndedInventoryRow, errors: &mut Vec<String>) {
    let fields = [
        ("source_location", &row.source_location),
        ("risk_surface", &row.risk_surface),
        ("current_evidence", &row.current_evidence),
        ("required_proof_type", &row.required_proof_type),
        ("expected_unit_coverage", &row.expected_unit_coverage),
        (
            "expected_e2e_fuzz_smoke_coverage",
            &row.expected_e2e_fuzz_smoke_coverage,
        ),
        ("log_artifact_expectations", &row.log_artifact_expectations),
        ("decision", &row.decision),
        ("linked_bead_or_artifact", &row.linked_bead_or_artifact),
        ("owner_status", &row.owner_status),
        (
            "non_applicability_rationale",
            &row.non_applicability_rationale,
        ),
    ];

    for (field, value) in fields {
        if value.trim().is_empty() || value == "-" {
            errors.push(format!("row {} has empty {field}", row.id));
        }
    }
    if !row.source_location.contains(':') && !row.source_location.contains('/') {
        errors.push(format!(
            "row {} source_location must name a file/anchor",
            row.id
        ));
    }
}

fn validate_vocabulary(row: &OpenEndedInventoryRow, errors: &mut Vec<String>) {
    validate_allowed(
        row,
        "required_proof_type",
        &row.required_proof_type,
        &PROOF_TYPES,
        errors,
    );
    validate_allowed(row, "decision", &row.decision, &DECISIONS, errors);
    validate_allowed(
        row,
        "expected_unit_coverage",
        &row.expected_unit_coverage,
        &COVERAGE_STATES,
        errors,
    );
    validate_allowed(
        row,
        "expected_e2e_fuzz_smoke_coverage",
        &row.expected_e2e_fuzz_smoke_coverage,
        &COVERAGE_STATES,
        errors,
    );
}

fn validate_allowed(
    row: &OpenEndedInventoryRow,
    field: &str,
    value: &str,
    allowed: &[&str],
    errors: &mut Vec<String>,
) {
    if !allowed.contains(&value) {
        errors.push(format!(
            "row {} {field} `{value}` is not in {:?}",
            row.id, allowed
        ));
    }
}

fn validate_log_and_artifact_fields(row: &OpenEndedInventoryRow, errors: &mut Vec<String>) {
    for token in REQUIRED_LOG_TOKENS {
        if !row.log_artifact_expectations.contains(token) {
            errors.push(format!(
                "row {} log_artifact_expectations missing `{token}`",
                row.id
            ));
        }
    }
    for token in REQUIRED_ARTIFACT_TOKENS {
        if !row.log_artifact_expectations.contains(token) {
            errors.push(format!(
                "row {} log_artifact_expectations missing `{token}`",
                row.id
            ));
        }
    }
}

fn validate_linkage(row: &OpenEndedInventoryRow, errors: &mut Vec<String>) {
    let has_bead = row.linked_bead_or_artifact.contains("bd-");
    let has_artifact = row.linked_bead_or_artifact.contains('/');
    if !has_bead && !has_artifact {
        errors.push(format!(
            "row {} linked_bead_or_artifact must include a bead id or artifact path",
            row.id
        ));
    }

    if row.decision == "explicit-non-goal" && row.non_applicability_rationale == "n/a" {
        errors.push(format!(
            "row {} explicit non-goal needs a concrete rationale",
            row.id
        ));
    }
    if row.decision != "explicit-non-goal" && row.non_applicability_rationale != "n/a" {
        errors.push(format!(
            "row {} non_applicability_rationale must be n/a unless decision is explicit-non-goal",
            row.id
        ));
    }
}

pub const SOURCE_SCOPE_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_SOURCE_SCOPE_MANIFEST_PATH: &str =
    "tests/source-scope-manifest/source_scope_manifest.json";
const DEFAULT_SOURCE_SCOPE_MANIFEST_JSON: &str =
    include_str!("../../../tests/source-scope-manifest/source_scope_manifest.json");

const REQUIRED_SOURCE_FAMILIES: [&str; 10] = [
    "readme_status_docs",
    "feature_parity_doc",
    "conformance_docs",
    "fixture_manifests",
    "tests",
    "fuzz_corpus_notes",
    "harness_scripts",
    "mounted_lane_docs",
    "repair_docs",
    "performance_xfstests_notes",
];

const ALLOWED_RISK_CATEGORIES: [&str; 9] = [
    "data_safety",
    "parser",
    "mounted_path",
    "repair",
    "fuzz",
    "conformance",
    "performance",
    "observability",
    "docs_only",
];

const ALLOWED_SOURCE_STATUSES: [&str; 4] = ["active", "deferred", "sunset", "non_applicable"];

const ALLOWED_FRESHNESS_STATES: [&str; 3] = ["fresh", "stale", "exempt"];
const NOTE_MATCH_TOKENS: [&str; 5] = ["TODO", "FIXME", "NOTE", "non-goal", "bd-"];
pub const OPEN_ENDED_NOTE_SCANNER_VERSION: &str = "bd-l7ov7-open-ended-note-scanner-v1";

const OPEN_ENDED_NOTE_PATTERNS: [&str; 7] = [
    "add more cases",
    "expand corpus",
    "TODO fuzz",
    "future edge cases",
    "adversarial inputs",
    "more goldens",
    "known gaps",
];

const REQUIRED_NOTE_LOG_FIELDS: [&str; 8] = [
    "scanner_version",
    "search_patterns",
    "source_path",
    "row_id",
    "matched_text_snippet_hash",
    "decision",
    "linked_bead_or_artifact",
    "reproduction_command",
];

const REQUIRED_NOTE_ARTIFACT_FIELDS: [&str; 3] =
    ["report_json", "run_log", "scanner_fixture_path"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenEndedNoteSource {
    pub source_path: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenEndedNoteScanReport {
    pub schema_version: u32,
    pub scanner_version: String,
    pub source_count: usize,
    pub search_patterns: Vec<String>,
    pub match_count: usize,
    pub real_open_note_count: usize,
    pub false_positive_count: usize,
    pub unresolved_note_count: usize,
    pub rows: Vec<OpenEndedNoteMatch>,
    pub output_path: String,
    pub reproduction_command: String,
    pub valid: bool,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenEndedNoteMatch {
    pub source_path: String,
    pub line_number: usize,
    pub section_id: String,
    pub matched_phrase: String,
    pub matched_text_snippet_hash: String,
    pub decision: String,
    pub false_positive_reason: String,
    pub linked_bead_or_artifact: String,
    pub risk_surface: String,
    pub required_log_fields: Vec<String>,
    pub required_artifacts: Vec<String>,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceScopeManifest {
    pub schema_version: u32,
    pub manifest_id: String,
    pub bead_id: String,
    pub sources: Vec<SourceScopeEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceScopeEntry {
    pub id: String,
    pub source_family: String,
    pub included_globs: Vec<String>,
    pub excluded_globs: Vec<String>,
    pub risk_category: String,
    pub owner: String,
    pub status: String,
    pub expected_proof_types: Vec<String>,
    pub freshness_ttl_days: u32,
    pub freshness_state: String,
    #[serde(default)]
    pub source_hash: String,
    #[serde(default)]
    pub non_applicability_rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceScopeManifestReport {
    pub schema_version: u32,
    pub manifest_id: String,
    pub bead_id: String,
    pub source_count: usize,
    pub source_families: Vec<String>,
    pub non_applicable_families: Vec<String>,
    pub stale_sources: Vec<String>,
    pub valid: bool,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceScopeScanReport {
    pub schema_version: u32,
    pub manifest_id: String,
    pub bead_id: String,
    pub workspace_root: String,
    pub source_count: usize,
    pub source_manifest_version: u32,
    pub scanned_sources: Vec<SourceScopeScanEntry>,
    pub stale_sources: Vec<String>,
    pub output_path: String,
    pub reproduction_command: String,
    pub valid: bool,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceScopeScanEntry {
    pub id: String,
    pub source_family: String,
    pub included_globs: Vec<String>,
    pub excluded_globs: Vec<String>,
    pub inclusion_decision: String,
    pub exclusion_reason: String,
    pub file_or_directory_hash: String,
    pub matched_note_count: usize,
    pub linked_bead_or_artifact_count: usize,
    pub stale_allowance: String,
    pub output_path: String,
    pub reproduction_command: String,
    pub matched_paths: Vec<SourceScopePathDecision>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceScopePathDecision {
    pub source_path: String,
    pub source_glob: String,
    pub inclusion_decision: String,
    pub exclusion_reason: String,
    pub file_hash: String,
    pub matched_note_count: usize,
    pub linked_bead_or_artifact_count: usize,
}

pub fn parse_source_scope_manifest(text: &str) -> Result<SourceScopeManifest> {
    serde_json::from_str(text)
        .map_err(|err| anyhow::anyhow!("failed to parse source scope manifest JSON: {err}"))
}

pub fn load_source_scope_manifest(path: impl AsRef<Path>) -> Result<SourceScopeManifest> {
    let path = path.as_ref();
    let text = fs::read_to_string(path).map_err(|err| {
        anyhow::anyhow!(
            "failed to read source scope manifest {}: {err}",
            path.display()
        )
    })?;
    parse_source_scope_manifest(&text)
}

pub fn validate_default_source_scope_manifest() -> Result<SourceScopeManifestReport> {
    let manifest = parse_source_scope_manifest(DEFAULT_SOURCE_SCOPE_MANIFEST_JSON)?;
    let report = validate_source_scope_manifest(&manifest);
    if !report.valid {
        bail!(
            "source scope manifest failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        );
    }
    Ok(report)
}

#[must_use]
pub fn scan_source_scope_manifest(
    manifest: &SourceScopeManifest,
    workspace_root: &Path,
    output_path: Option<&Path>,
    reproduction_command: &str,
) -> SourceScopeScanReport {
    let manifest_report = validate_source_scope_manifest(manifest);
    let mut errors = manifest_report.errors.clone();
    let workspace_files = match collect_workspace_files(workspace_root) {
        Ok(files) => files,
        Err(err) => {
            errors.push(err.to_string());
            Vec::new()
        }
    };
    let output_path =
        output_path.map_or_else(|| "<stdout>".to_owned(), |path| path.display().to_string());

    let scanned_sources = manifest
        .sources
        .iter()
        .map(|entry| {
            scan_source_scope_entry(
                entry,
                workspace_root,
                &workspace_files,
                &output_path,
                reproduction_command,
                &mut errors,
            )
        })
        .collect::<Vec<_>>();

    SourceScopeScanReport {
        schema_version: SOURCE_SCOPE_MANIFEST_SCHEMA_VERSION,
        manifest_id: manifest.manifest_id.clone(),
        bead_id: manifest.bead_id.clone(),
        workspace_root: workspace_root.display().to_string(),
        source_count: manifest.sources.len(),
        source_manifest_version: manifest.schema_version,
        scanned_sources,
        stale_sources: manifest_report.stale_sources,
        output_path,
        reproduction_command: reproduction_command.to_owned(),
        valid: errors.is_empty(),
        errors,
    }
}

#[must_use]
pub fn validate_source_scope_manifest(manifest: &SourceScopeManifest) -> SourceScopeManifestReport {
    let mut errors = Vec::new();
    let mut ids = BTreeSet::new();
    let mut families_seen = BTreeSet::new();
    let mut non_applicable_families = BTreeSet::new();
    let mut stale_sources = Vec::new();

    validate_source_manifest_top_level(manifest, &mut errors);

    for entry in &manifest.sources {
        validate_source_scope_entry(
            entry,
            &mut ids,
            &mut families_seen,
            &mut non_applicable_families,
            &mut stale_sources,
            &mut errors,
        );
    }

    validate_source_family_coverage(&families_seen, &non_applicable_families, &mut errors);

    SourceScopeManifestReport {
        schema_version: manifest.schema_version,
        manifest_id: manifest.manifest_id.clone(),
        bead_id: manifest.bead_id.clone(),
        source_count: manifest.sources.len(),
        source_families: families_seen.into_iter().collect(),
        non_applicable_families: non_applicable_families.into_iter().collect(),
        stale_sources,
        valid: errors.is_empty(),
        errors,
    }
}

fn validate_source_manifest_top_level(manifest: &SourceScopeManifest, errors: &mut Vec<String>) {
    if manifest.schema_version != SOURCE_SCOPE_MANIFEST_SCHEMA_VERSION {
        errors.push(format!(
            "source scope manifest schema_version must be {SOURCE_SCOPE_MANIFEST_SCHEMA_VERSION}, got {}",
            manifest.schema_version
        ));
    }
    if manifest.manifest_id.trim().is_empty() {
        errors.push("source scope manifest missing manifest_id".to_owned());
    }
    if !manifest.bead_id.starts_with("bd-") {
        errors.push(format!(
            "source scope manifest bead_id must look like bd-..., got `{}`",
            manifest.bead_id
        ));
    }
    if manifest.sources.is_empty() {
        errors.push("source scope manifest must declare at least one source".to_owned());
    }
}

fn validate_source_scope_entry(
    entry: &SourceScopeEntry,
    ids: &mut BTreeSet<String>,
    families_seen: &mut BTreeSet<String>,
    non_applicable_families: &mut BTreeSet<String>,
    stale_sources: &mut Vec<String>,
    errors: &mut Vec<String>,
) {
    if !ids.insert(entry.id.clone()) {
        errors.push(format!("duplicate source scope entry id `{}`", entry.id));
    }
    if entry.id.trim().is_empty() {
        errors.push("source scope entry has empty id".to_owned());
    }

    if REQUIRED_SOURCE_FAMILIES.contains(&entry.source_family.as_str()) {
        families_seen.insert(entry.source_family.clone());
    } else {
        errors.push(format!(
            "source `{}` has unsupported source_family `{}`",
            entry.id, entry.source_family
        ));
    }

    let has_rationale = !entry.non_applicability_rationale.trim().is_empty();
    if has_rationale {
        non_applicable_families.insert(entry.source_family.clone());
    }

    if entry.included_globs.is_empty() && !has_rationale {
        errors.push(format!(
            "source `{}` must declare included_globs unless non_applicability_rationale is set",
            entry.id
        ));
    }
    for glob in &entry.included_globs {
        if glob.trim().is_empty() {
            errors.push(format!("source `{}` has empty included glob", entry.id));
        }
    }
    for glob in &entry.excluded_globs {
        if glob.trim().is_empty() {
            errors.push(format!("source `{}` has empty excluded glob", entry.id));
        }
    }

    if !ALLOWED_RISK_CATEGORIES.contains(&entry.risk_category.as_str()) {
        errors.push(format!(
            "source `{}` has unsupported risk_category `{}`",
            entry.id, entry.risk_category
        ));
    }

    if entry.owner.trim().is_empty() {
        errors.push(format!("source `{}` missing owner", entry.id));
    }
    if !ALLOWED_SOURCE_STATUSES.contains(&entry.status.as_str()) {
        errors.push(format!(
            "source `{}` has unsupported status `{}`",
            entry.id, entry.status
        ));
    }
    if entry.status == "non_applicable" && !has_rationale {
        errors.push(format!(
            "source `{}` status non_applicable requires non_applicability_rationale",
            entry.id
        ));
    }

    if entry.expected_proof_types.is_empty() && !has_rationale {
        errors.push(format!(
            "source `{}` must declare at least one expected_proof_type",
            entry.id
        ));
    }
    for proof in &entry.expected_proof_types {
        if !PROOF_TYPES.contains(&proof.as_str()) {
            errors.push(format!(
                "source `{}` references unsupported proof type `{}`",
                entry.id, proof
            ));
        }
    }

    if entry.freshness_ttl_days == 0 && entry.freshness_state != "exempt" {
        errors.push(format!(
            "source `{}` freshness_ttl_days must be positive unless freshness_state is exempt",
            entry.id
        ));
    }
    if !ALLOWED_FRESHNESS_STATES.contains(&entry.freshness_state.as_str()) {
        errors.push(format!(
            "source `{}` has unsupported freshness_state `{}`",
            entry.id, entry.freshness_state
        ));
    }
    if entry.freshness_state == "stale" {
        stale_sources.push(entry.id.clone());
    }

    if !entry.source_hash.is_empty() && !is_valid_source_hash(&entry.source_hash) {
        errors.push(format!(
            "source `{}` has malformed source_hash `{}` (expected sha256:<64-hex>)",
            entry.id, entry.source_hash
        ));
    }
    if entry.freshness_state == "stale" && entry.source_hash.is_empty() {
        errors.push(format!(
            "source `{}` freshness_state stale requires source_hash",
            entry.id
        ));
    }

    validate_source_exclusion_policy(entry, errors);
}

fn validate_source_family_coverage(
    families_seen: &BTreeSet<String>,
    non_applicable_families: &BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    for required in REQUIRED_SOURCE_FAMILIES {
        if !families_seen.contains(required) {
            errors.push(format!(
                "source scope manifest missing required family `{required}`; declare it with non_applicability_rationale if intentionally excluded"
            ));
        }
    }
    for family in non_applicable_families {
        if !REQUIRED_SOURCE_FAMILIES.contains(&family.as_str()) {
            errors.push(format!(
                "non_applicability rationale provided for non-required family `{family}`"
            ));
        }
    }
}

fn is_valid_source_hash(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("sha256:") else {
        return false;
    };
    suffix.len() == 64 && suffix.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn validate_source_exclusion_policy(entry: &SourceScopeEntry, errors: &mut Vec<String>) {
    let excluded = entry.excluded_globs.join("\n");
    let missing_target_paths = !excluded.contains("target") && !excluded.contains(".rch-target");
    match entry.source_family.as_str() {
        "readme_status_docs"
            if !excluded.contains("_generated") || !excluded.contains("_drafts") =>
        {
            errors.push(format!(
                "source `{}` must exclude generated status docs and drafts",
                entry.id
            ));
        }
        "tests" => validate_tests_exclusions(entry, &excluded, missing_target_paths, errors),
        "conformance_docs" if missing_target_paths => {
            errors.push(format!(
                "source `{}` must exclude build target paths from conformance source scope",
                entry.id
            ));
        }
        "harness_scripts" if !excluded.contains("_artifacts") => {
            errors.push(format!(
                "source `{}` must exclude generated e2e artifact directories",
                entry.id
            ));
        }
        _ => {}
    }
}

fn validate_tests_exclusions(
    entry: &SourceScopeEntry,
    excluded: &str,
    missing_target_paths: bool,
    errors: &mut Vec<String>,
) {
    if !excluded.contains("vendor") {
        errors.push(format!(
            "source `{}` must exclude vendor paths from test source scope",
            entry.id
        ));
    }
    if missing_target_paths {
        errors.push(format!(
            "source `{}` must exclude build target paths from test source scope",
            entry.id
        ));
    }
}

fn scan_source_scope_entry(
    entry: &SourceScopeEntry,
    workspace_root: &Path,
    workspace_files: &[PathBuf],
    output_path: &str,
    reproduction_command: &str,
    errors: &mut Vec<String>,
) -> SourceScopeScanEntry {
    let stale_allowance = format_stale_allowance(entry);
    if !entry.non_applicability_rationale.trim().is_empty() {
        return non_applicable_scan_entry(
            entry,
            output_path,
            reproduction_command,
            stale_allowance,
        );
    }

    let matched_paths = collect_matched_paths(entry, workspace_root, workspace_files, errors);
    let included_paths: Vec<&SourceScopePathDecision> = matched_paths
        .iter()
        .filter(|path| path.inclusion_decision == "included")
        .collect();
    if included_paths.is_empty() {
        errors.push(format!(
            "source `{}` matched no files for included_globs {:?}",
            entry.id, entry.included_globs
        ));
    }

    let matched_note_count = included_paths
        .iter()
        .map(|path| path.matched_note_count)
        .sum();
    let linked_bead_or_artifact_count = included_paths
        .iter()
        .map(|path| path.linked_bead_or_artifact_count)
        .sum();
    let file_or_directory_hash = directory_hash(&included_paths);
    let inclusion_decision = if included_paths.is_empty() {
        "missing"
    } else {
        "included"
    };

    SourceScopeScanEntry {
        id: entry.id.clone(),
        source_family: entry.source_family.clone(),
        included_globs: entry.included_globs.clone(),
        excluded_globs: entry.excluded_globs.clone(),
        inclusion_decision: inclusion_decision.to_owned(),
        exclusion_reason: String::new(),
        file_or_directory_hash,
        matched_note_count,
        linked_bead_or_artifact_count,
        stale_allowance,
        output_path: output_path.to_owned(),
        reproduction_command: reproduction_command.to_owned(),
        matched_paths,
    }
}

fn format_stale_allowance(entry: &SourceScopeEntry) -> String {
    format!(
        "freshness_state={} ttl_days={} source_hash={}",
        entry.freshness_state,
        entry.freshness_ttl_days,
        if entry.source_hash.is_empty() {
            "<none>"
        } else {
            entry.source_hash.as_str()
        }
    )
}

fn non_applicable_scan_entry(
    entry: &SourceScopeEntry,
    output_path: &str,
    reproduction_command: &str,
    stale_allowance: String,
) -> SourceScopeScanEntry {
    SourceScopeScanEntry {
        id: entry.id.clone(),
        source_family: entry.source_family.clone(),
        included_globs: entry.included_globs.clone(),
        excluded_globs: entry.excluded_globs.clone(),
        inclusion_decision: "non_applicable".to_owned(),
        exclusion_reason: entry.non_applicability_rationale.clone(),
        file_or_directory_hash: String::new(),
        matched_note_count: 0,
        linked_bead_or_artifact_count: 0,
        stale_allowance,
        output_path: output_path.to_owned(),
        reproduction_command: reproduction_command.to_owned(),
        matched_paths: Vec::new(),
    }
}

fn collect_matched_paths(
    entry: &SourceScopeEntry,
    workspace_root: &Path,
    workspace_files: &[PathBuf],
    errors: &mut Vec<String>,
) -> Vec<SourceScopePathDecision> {
    let mut matched_paths = Vec::new();
    for relative_path in workspace_files {
        let relative = normalize_path(relative_path);
        let Some(included_glob) = entry
            .included_globs
            .iter()
            .find(|glob| glob_matches(glob, &relative))
        else {
            continue;
        };
        let excluded_glob = entry
            .excluded_globs
            .iter()
            .find(|glob| glob_matches(glob, &relative));
        let full_path = workspace_root.join(relative_path);
        let file_hash = hash_file(&full_path).unwrap_or_else(|err| {
            errors.push(format!("failed to hash source path `{relative}`: {err}"));
            String::new()
        });
        let text = fs::read_to_string(&full_path).unwrap_or_default();
        let matched_note_count = count_note_matches(&text);
        let linked_bead_or_artifact_count = count_linked_beads_or_artifacts(&text);

        let (inclusion_decision, exclusion_reason) = excluded_glob.map_or_else(
            || ("included".to_owned(), String::new()),
            |glob| {
                (
                    "excluded".to_owned(),
                    format!("matched excluded_glob `{glob}`"),
                )
            },
        );
        matched_paths.push(SourceScopePathDecision {
            source_path: relative,
            source_glob: included_glob.clone(),
            inclusion_decision,
            exclusion_reason,
            file_hash,
            matched_note_count,
            linked_bead_or_artifact_count,
        });
    }
    matched_paths
}

fn collect_workspace_files(workspace_root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_workspace_files_from(workspace_root, workspace_root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_workspace_files_from(
    root: &Path,
    current: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<()> {
    for entry in fs::read_dir(current).map_err(|err| {
        anyhow::anyhow!("failed to read workspace path {}: {err}", current.display())
    })? {
        let entry = entry.map_err(|err| {
            anyhow::anyhow!(
                "failed to read workspace entry under {}: {err}",
                current.display()
            )
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|err| {
            anyhow::anyhow!(
                "failed to inspect workspace entry {}: {err}",
                path.display()
            )
        })?;
        if file_type.is_dir() {
            if should_skip_walk_dir(root, &path) {
                continue;
            }
            collect_workspace_files_from(root, &path, files)?;
        } else if file_type.is_file() {
            let relative = path.strip_prefix(root).map_err(|err| {
                anyhow::anyhow!(
                    "failed to relativize workspace entry {}: {err}",
                    path.display()
                )
            })?;
            files.push(relative.to_path_buf());
        }
    }
    Ok(())
}

fn should_skip_walk_dir(root: &Path, path: &Path) -> bool {
    let relative = path.strip_prefix(root).unwrap_or(path);
    matches!(
        normalize_path(relative).as_str(),
        ".git" | "target" | ".rch-target" | "data/tmp"
    ) || normalize_path(relative).starts_with("data/tmp/")
}

fn normalize_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn glob_matches(pattern: &str, path: &str) -> bool {
    let pattern_segments = pattern.split('/').collect::<Vec<_>>();
    let path_segments = path.split('/').collect::<Vec<_>>();
    glob_segments_match(&pattern_segments, &path_segments)
}

fn glob_segments_match(pattern: &[&str], path: &[&str]) -> bool {
    if pattern.is_empty() {
        return path.is_empty();
    }
    if pattern[0] == "**" {
        return glob_segments_match(&pattern[1..], path)
            || (!path.is_empty() && glob_segments_match(pattern, &path[1..]));
    }
    !path.is_empty()
        && glob_segment_match(pattern[0], path[0])
        && glob_segments_match(&pattern[1..], &path[1..])
}

fn glob_segment_match(pattern: &str, segment: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let parts = pattern.split('*').collect::<Vec<_>>();
    if parts.len() == 1 {
        return pattern == segment;
    }

    let mut remainder = segment;
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if index == 0 {
            let Some(stripped) = remainder.strip_prefix(part) else {
                return false;
            };
            remainder = stripped;
        } else if let Some(position) = remainder.find(part) {
            remainder = &remainder[position + part.len()..];
        } else {
            return false;
        }
    }
    pattern.ends_with('*') || remainder.is_empty()
}

fn hash_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path)
        .map_err(|err| anyhow::anyhow!("failed to read {} for hashing: {err}", path.display()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

fn directory_hash(paths: &[&SourceScopePathDecision]) -> String {
    if paths.is_empty() {
        return String::new();
    }
    let mut hasher = Sha256::new();
    for path in paths {
        hasher.update(path.source_path.as_bytes());
        hasher.update(b"\0");
        hasher.update(path.file_hash.as_bytes());
        hasher.update(b"\0");
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn count_note_matches(text: &str) -> usize {
    NOTE_MATCH_TOKENS
        .iter()
        .map(|token| text.matches(token).count())
        .sum()
}

fn count_linked_beads_or_artifacts(text: &str) -> usize {
    text.matches("bd-").count() + text.matches("artifact").count()
}

#[must_use]
pub fn scan_open_ended_notes(
    sources: &[OpenEndedNoteSource],
    output_path: &str,
    reproduction_command: &str,
) -> OpenEndedNoteScanReport {
    let mut errors = Vec::new();
    if output_path.trim().is_empty() {
        errors.push("open-ended note scan output_path must be nonempty".to_owned());
    }
    if !reproduction_command.contains("open_ended_note_scanner") {
        errors.push(
            "open-ended note scan reproduction_command must name open_ended_note_scanner"
                .to_owned(),
        );
    }

    let rows = sources
        .iter()
        .flat_map(|source| {
            scan_open_ended_note_source(source, reproduction_command, &mut errors)
        })
        .collect::<Vec<_>>();

    let real_open_note_count = rows
        .iter()
        .filter(|row| row.decision == "requires_inventory_row")
        .count();
    let false_positive_count = rows
        .iter()
        .filter(|row| row.decision == "false_positive")
        .count();
    let unresolved_note_count = rows
        .iter()
        .filter(|row| {
            row.decision == "requires_inventory_row" && row.linked_bead_or_artifact == "missing"
        })
        .count();

    for row in &rows {
        validate_open_ended_note_match(row, &mut errors);
        if row.decision == "requires_inventory_row" && row.linked_bead_or_artifact == "missing" {
            errors.push(format!(
                "{}:{} matched `{}` but lacks linked bead/artifact or inventory row",
                row.source_path, row.line_number, row.matched_phrase
            ));
        }
    }

    OpenEndedNoteScanReport {
        schema_version: SOURCE_SCOPE_MANIFEST_SCHEMA_VERSION,
        scanner_version: OPEN_ENDED_NOTE_SCANNER_VERSION.to_owned(),
        source_count: sources.len(),
        search_patterns: OPEN_ENDED_NOTE_PATTERNS
            .iter()
            .map(|pattern| (*pattern).to_owned())
            .collect(),
        match_count: rows.len(),
        real_open_note_count,
        false_positive_count,
        unresolved_note_count,
        rows,
        output_path: output_path.to_owned(),
        reproduction_command: reproduction_command.to_owned(),
        valid: errors.is_empty(),
        errors,
    }
}

fn scan_open_ended_note_source(
    source: &OpenEndedNoteSource,
    reproduction_command: &str,
    errors: &mut Vec<String>,
) -> Vec<OpenEndedNoteMatch> {
    if source.source_path.trim().is_empty() {
        errors.push("open-ended note scan source_path must be nonempty".to_owned());
    }
    let mut rows = Vec::new();
    let mut section_id = "root".to_owned();
    let mut in_fenced_code = false;

    for (index, line) in source.text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") {
            in_fenced_code = !in_fenced_code;
        }
        if !in_fenced_code && trimmed.starts_with('#') {
            section_id = slugify_heading(trimmed);
        }
        for pattern in matched_open_ended_patterns(line) {
            rows.push(build_note_match(
                source,
                index + 1,
                &section_id,
                line,
                pattern,
                in_fenced_code,
                reproduction_command,
            ));
        }
    }

    rows
}

fn matched_open_ended_patterns(line: &str) -> Vec<&'static str> {
    let lower = line.to_ascii_lowercase();
    OPEN_ENDED_NOTE_PATTERNS
        .iter()
        .copied()
        .filter(|pattern| lower.contains(&pattern.to_ascii_lowercase()))
        .collect()
}

fn build_note_match(
    source: &OpenEndedNoteSource,
    line_number: usize,
    section_id: &str,
    line: &str,
    matched_phrase: &str,
    in_fenced_code: bool,
    reproduction_command: &str,
) -> OpenEndedNoteMatch {
    let (decision, false_positive_reason, linked_bead_or_artifact) =
        classify_open_ended_note(line, in_fenced_code);

    OpenEndedNoteMatch {
        source_path: source.source_path.clone(),
        line_number,
        section_id: section_id.to_owned(),
        matched_phrase: matched_phrase.to_owned(),
        matched_text_snippet_hash: snippet_hash(line),
        decision: decision.to_owned(),
        false_positive_reason: false_positive_reason.to_owned(),
        linked_bead_or_artifact,
        risk_surface: infer_note_risk_surface(line, matched_phrase).to_owned(),
        required_log_fields: REQUIRED_NOTE_LOG_FIELDS
            .iter()
            .map(|field| (*field).to_owned())
            .collect(),
        required_artifacts: REQUIRED_NOTE_ARTIFACT_FIELDS
            .iter()
            .map(|field| (*field).to_owned())
            .collect(),
        reproduction_command: reproduction_command.to_owned(),
    }
}

fn classify_open_ended_note(line: &str, in_fenced_code: bool) -> (&'static str, &'static str, String) {
    let trimmed = line.trim_start();
    if in_fenced_code || trimmed.starts_with('>') {
        return (
            "false_positive",
            "quoted_or_example",
            "not_applicable".to_owned(),
        );
    }
    let lower = line.to_ascii_lowercase();
    if lower.contains("historical")
        || lower.contains("closed bead")
        || lower.contains("status: closed")
        || lower.contains("already closed")
    {
        return (
            "false_positive",
            "historical_closed_context",
            first_linked_bead_or_artifact(line)
                .unwrap_or_else(|| "historical-context".to_owned()),
        );
    }
    if let Some(link) = first_linked_bead_or_artifact(line) {
        return ("already_linked", "n/a", link);
    }
    ("requires_inventory_row", "n/a", "missing".to_owned())
}

fn first_linked_bead_or_artifact(line: &str) -> Option<String> {
    line.split_whitespace().find_map(|raw| {
        let token = raw.trim_matches(|ch: char| {
            matches!(
                ch,
                '`' | '\'' | '"' | ',' | ';' | ':' | ')' | '(' | '[' | ']' | '.'
            )
        });
        if token.starts_with("bd-") {
            return Some(token.to_owned());
        }
        if token.contains('/') && (token.ends_with(".md") || token.ends_with(".json")) {
            return Some(token.to_owned());
        }
        if token.contains("artifact") {
            return Some(token.to_owned());
        }
        None
    })
}

fn infer_note_risk_surface(line: &str, matched_phrase: &str) -> &'static str {
    let lower = format!(
        "{} {}",
        line.to_ascii_lowercase(),
        matched_phrase.to_ascii_lowercase()
    );
    if lower.contains("fuzz") || lower.contains("adversarial") {
        "fuzz"
    } else if lower.contains("golden") {
        "golden-fixture"
    } else if lower.contains("corpus") {
        "corpus"
    } else if lower.contains("parser") {
        "parser"
    } else {
        "conformance"
    }
}

fn slugify_heading(line: &str) -> String {
    let slug = line
        .trim_start_matches('#')
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if slug.is_empty() {
        "root".to_owned()
    } else {
        slug
    }
}

fn snippet_hash(line: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(line.as_bytes())))
}

fn validate_open_ended_note_match(row: &OpenEndedNoteMatch, errors: &mut Vec<String>) {
    if row.source_path.trim().is_empty() {
        errors.push("open-ended note row missing source_path".to_owned());
    }
    if row.line_number == 0 {
        errors.push(format!(
            "open-ended note row {} missing line_number",
            row.source_path
        ));
    }
    if row.section_id.trim().is_empty() {
        errors.push(format!(
            "open-ended note row {}:{} missing section_id",
            row.source_path, row.line_number
        ));
    }
    if !row.matched_text_snippet_hash.starts_with("sha256:") {
        errors.push(format!(
            "open-ended note row {}:{} missing snippet hash",
            row.source_path, row.line_number
        ));
    }
    if !matches!(
        row.decision.as_str(),
        "requires_inventory_row" | "already_linked" | "false_positive"
    ) {
        errors.push(format!(
            "open-ended note row {}:{} has invalid decision {}",
            row.source_path, row.line_number, row.decision
        ));
    }
    if row.decision == "false_positive" && row.false_positive_reason == "n/a" {
        errors.push(format!(
            "open-ended note row {}:{} false_positive needs reason",
            row.source_path, row.line_number
        ));
    }
    if row.decision != "requires_inventory_row" && row.linked_bead_or_artifact == "missing" {
        errors.push(format!(
            "open-ended note row {}:{} non-open note missing linkage marker",
            row.source_path, row.line_number
        ));
    }
    for field in REQUIRED_NOTE_LOG_FIELDS {
        if !row.required_log_fields.iter().any(|value| value == field) {
            errors.push(format!(
                "open-ended note row {}:{} missing log field {field}",
                row.source_path, row.line_number
            ));
        }
    }
    for field in REQUIRED_NOTE_ARTIFACT_FIELDS {
        if !row.required_artifacts.iter().any(|value| value == field) {
            errors.push(format!(
                "open-ended note row {}:{} missing artifact field {field}",
                row.source_path, row.line_number
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DECISIONS, INVENTORY_MARKDOWN, OPEN_ENDED_NOTE_PATTERNS, OpenEndedNoteSource,
        PROOF_TYPES, analyze_inventory, scan_open_ended_notes, validate_current_inventory,
    };
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    const POSITIVE_SCANNER_FIXTURE: &str =
        include_str!("../../../tests/open-ended-inventory/scanner_fixture_positive.md");
    const NEGATIVE_SCANNER_FIXTURE: &str =
        include_str!("../../../tests/open-ended-inventory/scanner_fixture_negative.md");

    fn note_source(path: &str, text: &str) -> OpenEndedNoteSource {
        OpenEndedNoteSource {
            source_path: path.to_owned(),
            text: text.to_owned(),
        }
    }

    #[test]
    fn current_inventory_has_valid_rows_and_vocabularies() {
        let report = validate_current_inventory().expect("inventory should validate");
        assert!(report.row_count >= 10, "expected substantive inventory");
        assert_eq!(
            report.proof_types,
            PROOF_TYPES
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            report.decisions,
            DECISIONS
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn current_inventory_links_every_row_to_beads_or_artifacts() {
        let report = validate_current_inventory().expect("inventory should validate");
        for row in report.rows {
            assert!(
                row.linked_bead_or_artifact.contains("bd-")
                    || row.linked_bead_or_artifact.contains('/'),
                "row {} has weak linkage",
                row.id
            );
        }
    }

    #[test]
    fn current_inventory_requires_log_and_artifact_tokens() {
        let report = validate_current_inventory().expect("inventory should validate");
        for row in report.rows {
            for token in [
                "source_path",
                "row_id",
                "decision",
                "reproduction_command",
                "artifact_path",
                "owner_status",
            ] {
                assert!(
                    row.log_artifact_expectations.contains(token),
                    "row {} missing {token}",
                    row.id
                );
            }
        }
    }

    #[test]
    fn malformed_inventory_reports_schema_errors() {
        let bad = r"
## Open-Ended Inventory Registry

| ID | Source location | Risk surface | Current evidence | Required proof type | Expected unit coverage | Expected E2E/fuzz-smoke coverage | Log/artifact expectations | Decision | Linked bead or artifact | Owner/status | Non-applicability rationale |
|----|-----------------|--------------|------------------|---------------------|------------------------|----------------------------------|---------------------------|----------|-------------------------|--------------|-----------------------------|
| aa | nowhere | risk | evidence | vibes | maybe | maybe | source_path,row_id | maybe | none | open | not n/a |
";
        let report = analyze_inventory(bad);
        assert!(report.errors.iter().any(|err| err.contains("must look")));
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("required_proof_type"))
        );
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("artifact_path"))
        );
        assert!(report.errors.iter().any(|err| err.contains("linked_bead")));
    }

    #[test]
    fn inventory_document_names_the_acceptance_bead() {
        assert!(INVENTORY_MARKDOWN.contains("bd-rchk7.1"));
    }

    #[test]
    fn open_ended_note_scanner_fixture_docs_emit_expected_rows() {
        let reproduction_command =
            "cargo test -p ffs-harness open_ended_note_scanner -- --nocapture";
        let positive = scan_open_ended_notes(
            &[note_source(
                "tests/open-ended-inventory/scanner_fixture_positive.md",
                POSITIVE_SCANNER_FIXTURE,
            )],
            "artifacts/open-ended-inventory/positive_report.json",
            reproduction_command,
        );
        println!(
            "OPEN_ENDED_NOTE_SCAN|fixture=positive|valid={}|matches={}|false_positives={}|unresolved={}|scanner_version={}",
            positive.valid,
            positive.match_count,
            positive.false_positive_count,
            positive.unresolved_note_count,
            positive.scanner_version
        );
        assert!(positive.valid, "{:?}", positive.errors);
        assert!(positive.match_count >= 4, "positive fixture should scan real rows");
        assert!(
            positive.false_positive_count >= 2,
            "positive fixture should include false-positive controls"
        );
        assert_eq!(positive.unresolved_note_count, 0);

        let negative = scan_open_ended_notes(
            &[note_source(
                "tests/open-ended-inventory/scanner_fixture_negative.md",
                NEGATIVE_SCANNER_FIXTURE,
            )],
            "artifacts/open-ended-inventory/negative_report.json",
            reproduction_command,
        );
        println!(
            "OPEN_ENDED_NOTE_SCAN|fixture=negative|valid={}|matches={}|false_positives={}|unresolved={}|scanner_version={}",
            negative.valid,
            negative.match_count,
            negative.false_positive_count,
            negative.unresolved_note_count,
            negative.scanner_version
        );
        assert!(!negative.valid);
        assert_eq!(negative.unresolved_note_count, 1);
        assert!(
            negative
                .errors
                .iter()
                .any(|error| error.contains("lacks linked bead/artifact"))
        );
    }

    #[test]
    fn open_ended_note_scanner_covers_pattern_vocabulary() {
        let text = OPEN_ENDED_NOTE_PATTERNS
            .iter()
            .enumerate()
            .map(|(index, pattern)| {
                format!(
                    "- {pattern} is tracked by bd-l7ov7 with artifact tests/open-ended-inventory/pattern-{index}.json"
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let report = scan_open_ended_notes(
            &[note_source("docs/patterns.md", &text)],
            "artifacts/open-ended-inventory/patterns.json",
            "cargo test -p ffs-harness open_ended_note_scanner -- --nocapture",
        );
        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.match_count, OPEN_ENDED_NOTE_PATTERNS.len());
        for pattern in OPEN_ENDED_NOTE_PATTERNS {
            assert!(
                report.rows.iter().any(|row| row.matched_phrase == pattern),
                "missing pattern {pattern}"
            );
        }
    }

    #[test]
    fn open_ended_note_scanner_separates_false_positive_classes() {
        let text = r#"
## Scanner Examples

Historical context: closed bead bd-rchk7.1 asked to expand corpus before the inventory existed.

> Add more cases for the parser is shown here as a quoted example only.

```
TODO fuzz: future edge cases in a code block are examples, not source notes.
```

The known gaps are already linked to bd-l7ov7 and artifact reports/open-ended.json.
"#;
        let report = scan_open_ended_notes(
            &[note_source("docs/scanner-examples.md", text)],
            "artifacts/open-ended-inventory/examples.json",
            "cargo test -p ffs-harness open_ended_note_scanner -- --nocapture",
        );
        assert!(report.valid, "{:?}", report.errors);
        assert!(report.rows.iter().any(|row| {
            row.decision == "false_positive"
                && row.false_positive_reason == "historical_closed_context"
        }));
        assert!(report.rows.iter().any(|row| {
            row.decision == "false_positive"
                && row.false_positive_reason == "quoted_or_example"
        }));
        assert!(report.rows.iter().any(|row| {
            row.decision == "already_linked" && row.linked_bead_or_artifact == "bd-l7ov7"
        }));
    }

    #[test]
    fn open_ended_note_scanner_real_inventory_sample_has_no_unresolved_notes() {
        let report = scan_open_ended_notes(
            &[note_source(
                "docs/reports/FUZZ_AND_CONFORMANCE_INVENTORY.md",
                INVENTORY_MARKDOWN,
            )],
            "artifacts/open-ended-inventory/current_inventory_scan.json",
            "cargo test -p ffs-harness open_ended_note_scanner -- --nocapture",
        );
        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.unresolved_note_count, 0);
        for row in report.rows {
            assert!(!row.source_path.is_empty());
            assert!(row.line_number > 0);
            assert!(!row.section_id.is_empty());
            assert!(row.matched_text_snippet_hash.starts_with("sha256:"));
            assert!(row.required_log_fields.iter().any(|field| field == "row_id"));
            assert!(
                row.required_artifacts
                    .iter()
                    .any(|field| field == "report_json")
            );
        }
    }

    use super::{
        DEFAULT_SOURCE_SCOPE_MANIFEST_JSON, REQUIRED_SOURCE_FAMILIES,
        SOURCE_SCOPE_MANIFEST_SCHEMA_VERSION, SourceScopeManifest, parse_source_scope_manifest,
        scan_source_scope_manifest, validate_default_source_scope_manifest,
        validate_source_scope_manifest,
    };

    fn fixture_manifest() -> SourceScopeManifest {
        parse_source_scope_manifest(DEFAULT_SOURCE_SCOPE_MANIFEST_JSON)
            .expect("default source scope manifest parses")
    }

    fn write_sample_file(root: &Path, path: &str, text: &str) -> anyhow::Result<()> {
        let path = root.join(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, text)?;
        Ok(())
    }

    fn populate_source_scope_workspace(root: &Path) -> anyhow::Result<()> {
        for (path, text) in [
            ("README.md", "NOTE bd-rchk7.1 artifact coverage\n"),
            ("FEATURE_PARITY.md", "bd-rchk7.1 artifact coverage\n"),
            (
                "docs/reports/CONFORMANCE_SAMPLE.md",
                "NOTE conformance bd-rchk7.1 artifact\n",
            ),
            (
                "tests/fixtures/sample.json",
                "{\"note\":\"bd-rchk7.1 artifact\"}\n",
            ),
            (
                "crates/ffs-harness/src/sample.rs",
                "// NOTE bd-rchk7.1 artifact\n",
            ),
            (
                "tests/fuzz_corpus/README.md",
                "TODO fuzz bd-rchk7.1 artifact\n",
            ),
            (
                "scripts/e2e/sample.sh",
                "# NOTE mounted-e2e bd-rchk7.1 artifact\n",
            ),
            (
                "docs/mounted/README.md",
                "NOTE mounted path bd-rchk7.1 artifact\n",
            ),
            ("docs/repair/README.md", "NOTE repair bd-rchk7.1 artifact\n"),
            (
                "docs/performance/README.md",
                "NOTE xfstests perf bd-rchk7.1 artifact\n",
            ),
        ] {
            write_sample_file(root, path, text)?;
        }
        Ok(())
    }

    #[test]
    fn default_source_scope_manifest_validates_required_families() {
        let report = validate_default_source_scope_manifest().expect("default manifest validates");
        assert_eq!(report.schema_version, SOURCE_SCOPE_MANIFEST_SCHEMA_VERSION);
        assert_eq!(report.bead_id, "bd-lm0g9");
        assert_eq!(report.source_count, REQUIRED_SOURCE_FAMILIES.len());
        for family in REQUIRED_SOURCE_FAMILIES {
            assert!(
                report.source_families.iter().any(|f| f == family),
                "missing required family {family}"
            );
        }
        assert!(report.stale_sources.is_empty());
    }

    #[test]
    fn missing_required_family_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest
            .sources
            .retain(|entry| entry.source_family != "tests");
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required family `tests`"))
        );
    }

    #[test]
    fn missing_repair_family_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest
            .sources
            .retain(|entry| entry.source_family != "repair_docs");
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required family `repair_docs`"))
        );
    }

    #[test]
    fn missing_fuzz_corpus_family_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest
            .sources
            .retain(|entry| entry.source_family != "fuzz_corpus_notes");
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required family `fuzz_corpus_notes`"))
        );
    }

    #[test]
    fn duplicate_source_id_is_rejected() {
        let mut manifest = fixture_manifest();
        let duplicate_id = manifest.sources[0].id.clone();
        manifest.sources[1].id = duplicate_id;
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("duplicate source scope entry id"))
        );
    }

    #[test]
    fn invalid_risk_category_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].risk_category = "vibes".to_owned();
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported risk_category"))
        );
    }

    #[test]
    fn unsupported_proof_type_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].expected_proof_types = vec!["telepathy".to_owned()];
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported proof type"))
        );
    }

    #[test]
    fn empty_included_globs_without_rationale_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].included_globs.clear();
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must declare included_globs"))
        );
    }

    #[test]
    fn non_applicability_rationale_allows_empty_globs() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].included_globs.clear();
        manifest.sources[0].expected_proof_types.clear();
        manifest.sources[0].non_applicability_rationale =
            "intentionally absent: status sourced from beads".to_owned();
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report.valid,
            "non-applicability path should pass: {:?}",
            report.errors
        );
    }

    #[test]
    fn missing_owner_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].owner = String::new();
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing owner"))
        );
    }

    #[test]
    fn invalid_status_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].status = "spelunking".to_owned();
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported status"))
        );
    }

    #[test]
    fn non_applicable_status_requires_rationale() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].status = "non_applicable".to_owned();
        manifest.sources[0].non_applicability_rationale = String::new();
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("non_applicable requires non_applicability_rationale"))
        );
    }

    #[test]
    fn stale_freshness_state_is_surfaced() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].freshness_state = "stale".to_owned();
        manifest.sources[0].source_hash =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned();
        let report = validate_source_scope_manifest(&manifest);
        assert!(report.valid, "stale state alone should not fail validation");
        assert!(
            report
                .stale_sources
                .iter()
                .any(|id| id == &manifest.sources[0].id)
        );
    }

    #[test]
    fn invalid_freshness_state_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].freshness_state = "ancient".to_owned();
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported freshness_state"))
        );
    }

    #[test]
    fn zero_ttl_without_exempt_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].freshness_ttl_days = 0;
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("freshness_ttl_days must be positive"))
        );
    }

    #[test]
    fn malformed_source_hash_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].source_hash = "sha1:not-the-right-format".to_owned();
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("malformed source_hash"))
        );
    }

    #[test]
    fn stale_freshness_state_requires_source_hash() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].freshness_state = "stale".to_owned();
        manifest.sources[0].source_hash = String::new();
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("stale requires source_hash"))
        );
    }

    #[test]
    fn well_formed_sha256_hash_is_accepted() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].source_hash =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned();
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report.valid,
            "well-formed sha256 should pass: {:?}",
            report.errors
        );
    }

    #[test]
    fn empty_sources_list_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.sources.clear();
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("at least one source"))
        );
    }

    #[test]
    fn unsupported_source_family_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.sources[0].source_family = "blog_drafts".to_owned();
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported source_family"))
        );
    }

    #[test]
    fn required_generated_and_vendor_exclusions_are_validated() {
        let mut manifest = fixture_manifest();
        let tests = manifest
            .sources
            .iter_mut()
            .find(|entry| entry.source_family == "tests")
            .expect("tests source exists");
        tests.excluded_globs.retain(|glob| !glob.contains("vendor"));
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must exclude vendor paths"))
        );

        let mut manifest = fixture_manifest();
        let readme = manifest
            .sources
            .iter_mut()
            .find(|entry| entry.source_family == "readme_status_docs")
            .expect("readme status source exists");
        readme
            .excluded_globs
            .retain(|glob| !glob.contains("_generated"));
        let report = validate_source_scope_manifest(&manifest);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("generated status docs"))
        );
    }

    #[test]
    fn source_scope_scan_logs_workspace_hashes_and_counts() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        populate_source_scope_workspace(temp.path())?;
        let report = scan_source_scope_manifest(
            &fixture_manifest(),
            temp.path(),
            Some(Path::new("artifacts/source_scope_scan.json")),
            "cargo run -p ffs-harness -- validate-source-scope-manifest",
        );
        assert!(report.valid, "scan should validate: {:?}", report.errors);
        assert_eq!(report.source_count, REQUIRED_SOURCE_FAMILIES.len());
        assert_eq!(
            report.source_manifest_version,
            SOURCE_SCOPE_MANIFEST_SCHEMA_VERSION
        );
        assert_eq!(report.output_path, "artifacts/source_scope_scan.json");
        for source in &report.scanned_sources {
            assert_eq!(source.inclusion_decision, "included");
            assert!(
                source.file_or_directory_hash.starts_with("sha256:"),
                "source {} missing aggregate hash",
                source.id
            );
            assert!(
                source.matched_note_count > 0,
                "source {} should count open-ended note tokens",
                source.id
            );
            assert!(
                source.linked_bead_or_artifact_count > 0,
                "source {} should count linked beads/artifacts",
                source.id
            );
            assert!(source.output_path.ends_with("source_scope_scan.json"));
            assert!(
                source
                    .reproduction_command
                    .contains("validate-source-scope")
            );
        }
        Ok(())
    }

    #[test]
    fn source_scope_scan_logs_excluded_generated_paths() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        populate_source_scope_workspace(temp.path())?;
        write_sample_file(
            temp.path(),
            "docs/status/_generated/ignored.md",
            "NOTE generated bd-rchk7.1 artifact\n",
        )?;
        let report = scan_source_scope_manifest(
            &fixture_manifest(),
            temp.path(),
            None,
            "cargo run -p ffs-harness -- validate-source-scope-manifest",
        );
        let readme = report
            .scanned_sources
            .iter()
            .find(|source| source.source_family == "readme_status_docs")
            .expect("readme status source scanned");
        assert!(
            readme.matched_paths.iter().any(|path| {
                path.source_path == "docs/status/_generated/ignored.md"
                    && path.inclusion_decision == "excluded"
                    && path.exclusion_reason.contains("excluded_glob")
                    && path.file_hash.starts_with("sha256:")
            }),
            "generated status path should be logged as excluded"
        );
        Ok(())
    }

    #[test]
    fn source_scope_scan_reports_precise_removed_family() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        populate_source_scope_workspace(temp.path())?;
        let mut manifest = fixture_manifest();
        manifest
            .sources
            .retain(|entry| entry.source_family != "feature_parity_doc");
        let report = scan_source_scope_manifest(
            &manifest,
            temp.path(),
            None,
            "cargo run -p ffs-harness -- validate-source-scope-manifest",
        );
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required family `feature_parity_doc`"))
        );
        Ok(())
    }

    #[test]
    fn source_scope_scan_rejects_unmatched_required_source() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let report = scan_source_scope_manifest(
            &fixture_manifest(),
            temp.path(),
            None,
            "cargo run -p ffs-harness -- validate-source-scope-manifest",
        );
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("source `readme_status_docs` matched no files"))
        );
        Ok(())
    }
}
