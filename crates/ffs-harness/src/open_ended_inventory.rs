#![forbid(unsafe_code)]

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

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

#[cfg(test)]
mod tests {
    use super::{
        DECISIONS, INVENTORY_MARKDOWN, PROOF_TYPES, analyze_inventory, validate_current_inventory,
    };

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
}
