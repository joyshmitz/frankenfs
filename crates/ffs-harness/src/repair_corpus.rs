#![forbid(unsafe_code)]

//! Repair and ledger corruption corpus with chain-of-custody validation.
//!
//! Tracks bd-0xa7h: every repair fixture row must bind its symbol generation,
//! ledger id, repair-symbol budget, and expected verdict to the image under
//! repair. Wrong-image and stale-ledger rows must be present and refused so
//! release gates and remediation entries cannot reuse convincing-but-unsafe
//! evidence from a different image.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const REPAIR_CORPUS_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_REPAIR_CORPUS_PATH: &str = "tests/repair-corpus/repair_corpus.json";
const DEFAULT_REPAIR_CORPUS_JSON: &str =
    include_str!("../../../tests/repair-corpus/repair_corpus.json");

const ALLOWED_OUTCOME_CLASSES: [&str; 4] = [
    "recovered",
    "refused_wrong_image",
    "refused_stale_ledger",
    "refused_other",
];

const ALLOWED_REFUSAL_REASONS: [&str; 7] = [
    "wrong_image_ledger",
    "stale_ledger",
    "truncated_ledger",
    "tampered_ledger_row",
    "duplicate_ledger_row",
    "insufficient_symbols",
    "post_repair_refresh_mismatch",
];

const REQUIRED_NEGATIVE_CASES: [&str; 4] = [
    "wrong_image_ledger",
    "stale_ledger",
    "truncated_ledger",
    "post_repair_refresh_mismatch",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairCorpus {
    pub schema_version: u32,
    pub corpus_id: String,
    pub bead_id: String,
    pub cases: Vec<RepairCorpusCase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairCorpusCase {
    pub case_id: String,
    pub seed: u64,
    pub original_image_hash: String,
    pub corrupted_image_hash: String,
    pub corruption_manifest_hash: String,
    pub ledger: LedgerRef,
    pub repair_symbol_budget: u32,
    pub symbols_required_for_recovery: u32,
    pub symbols_supplied: u32,
    pub expected_outcome: String,
    #[serde(default)]
    pub expected_refusal_reason: String,
    pub verification: VerificationExpectation,
    pub chain_of_custody: ChainOfCustody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerRef {
    pub ledger_id: String,
    pub symbol_generation: u32,
    pub bound_image_hash: String,
    pub bound_corrupted_image_hash: String,
    pub bound_corruption_manifest_hash: String,
    pub row_count: u32,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub tampered_row_id: String,
    #[serde(default)]
    pub duplicate_row_id: String,
    #[serde(default)]
    pub stale_against_generation: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationExpectation {
    pub post_repair_image_hash: String,
    pub post_repair_symbol_generation: u32,
    pub scrub_clean: bool,
    pub reopen_clean: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainOfCustody {
    pub artifact_path: String,
    pub artifact_sha256: String,
    pub recorded_by: String,
    pub recorded_at_unix: u64,
    pub linked_bead: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairCorpusReport {
    pub schema_version: u32,
    pub corpus_id: String,
    pub bead_id: String,
    pub case_count: usize,
    pub outcome_classes: Vec<String>,
    pub refusal_reasons: Vec<String>,
    pub valid: bool,
    pub errors: Vec<String>,
}

pub fn parse_repair_corpus(text: &str) -> Result<RepairCorpus> {
    serde_json::from_str(text)
        .map_err(|err| anyhow::anyhow!("failed to parse repair corpus JSON: {err}"))
}

pub fn validate_default_repair_corpus() -> Result<RepairCorpusReport> {
    let corpus = parse_repair_corpus(DEFAULT_REPAIR_CORPUS_JSON)?;
    let report = validate_repair_corpus(&corpus);
    if !report.valid {
        bail!(
            "repair corpus failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        );
    }
    Ok(report)
}

#[must_use]
pub fn validate_repair_corpus(corpus: &RepairCorpus) -> RepairCorpusReport {
    let mut errors = Vec::new();
    let mut ids = BTreeSet::new();
    let mut outcome_classes = BTreeSet::new();
    let mut refusal_reasons = BTreeSet::new();

    validate_corpus_top_level(corpus, &mut errors);
    for case in &corpus.cases {
        validate_repair_case(
            case,
            &mut ids,
            &mut outcome_classes,
            &mut refusal_reasons,
            &mut errors,
        );
    }
    validate_negative_case_coverage(&refusal_reasons, &mut errors);

    RepairCorpusReport {
        schema_version: corpus.schema_version,
        corpus_id: corpus.corpus_id.clone(),
        bead_id: corpus.bead_id.clone(),
        case_count: corpus.cases.len(),
        outcome_classes: outcome_classes.into_iter().collect(),
        refusal_reasons: refusal_reasons.into_iter().collect(),
        valid: errors.is_empty(),
        errors,
    }
}

fn validate_corpus_top_level(corpus: &RepairCorpus, errors: &mut Vec<String>) {
    if corpus.schema_version != REPAIR_CORPUS_SCHEMA_VERSION {
        errors.push(format!(
            "repair corpus schema_version must be {REPAIR_CORPUS_SCHEMA_VERSION}, got {}",
            corpus.schema_version
        ));
    }
    if corpus.corpus_id.trim().is_empty() {
        errors.push("repair corpus missing corpus_id".to_owned());
    }
    if !corpus.bead_id.starts_with("bd-") {
        errors.push(format!(
            "repair corpus bead_id must look like bd-..., got `{}`",
            corpus.bead_id
        ));
    }
    if corpus.cases.is_empty() {
        errors.push("repair corpus must declare at least one case".to_owned());
    }
}

fn validate_repair_case(
    case: &RepairCorpusCase,
    ids: &mut BTreeSet<String>,
    outcome_classes: &mut BTreeSet<String>,
    refusal_reasons: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    if !ids.insert(case.case_id.clone()) {
        errors.push(format!(
            "duplicate repair corpus case_id `{}`",
            case.case_id
        ));
    }
    if case.case_id.trim().is_empty() {
        errors.push("repair corpus case has empty case_id".to_owned());
    }

    validate_image_and_manifest_hashes(case, errors);
    validate_ledger_binding(case, errors);
    validate_symbol_budget(case, errors);
    validate_outcome_and_refusal(case, outcome_classes, refusal_reasons, errors);
    validate_verification(case, errors);
    validate_chain_of_custody(case, errors);
}

fn validate_image_and_manifest_hashes(case: &RepairCorpusCase, errors: &mut Vec<String>) {
    for (field, value) in [
        ("original_image_hash", &case.original_image_hash),
        ("corrupted_image_hash", &case.corrupted_image_hash),
        ("corruption_manifest_hash", &case.corruption_manifest_hash),
    ] {
        if !is_valid_sha256(value) {
            errors.push(format!(
                "repair case `{}` has malformed {field} `{value}` (expected sha256:<64-hex>)",
                case.case_id
            ));
        }
    }
    if case.original_image_hash == case.corrupted_image_hash {
        errors.push(format!(
            "repair case `{}` corrupted_image_hash must differ from original_image_hash",
            case.case_id
        ));
    }
}

fn validate_ledger_binding(case: &RepairCorpusCase, errors: &mut Vec<String>) {
    if case.ledger.ledger_id.trim().is_empty() {
        errors.push(format!(
            "repair case `{}` ledger missing ledger_id",
            case.case_id
        ));
    }
    if case.ledger.symbol_generation == 0 {
        errors.push(format!(
            "repair case `{}` ledger symbol_generation must be positive",
            case.case_id
        ));
    }
    for (field, value) in [
        ("bound_image_hash", &case.ledger.bound_image_hash),
        (
            "bound_corrupted_image_hash",
            &case.ledger.bound_corrupted_image_hash,
        ),
        (
            "bound_corruption_manifest_hash",
            &case.ledger.bound_corruption_manifest_hash,
        ),
    ] {
        if !is_valid_sha256(value) {
            errors.push(format!(
                "repair case `{}` ledger has malformed {field} `{value}`",
                case.case_id
            ));
        }
    }
}

fn validate_symbol_budget(case: &RepairCorpusCase, errors: &mut Vec<String>) {
    if case.repair_symbol_budget == 0 {
        errors.push(format!(
            "repair case `{}` repair_symbol_budget must be positive",
            case.case_id
        ));
    }
    if case.symbols_required_for_recovery == 0 {
        errors.push(format!(
            "repair case `{}` symbols_required_for_recovery must be positive",
            case.case_id
        ));
    }
    if case.symbols_supplied > case.repair_symbol_budget {
        errors.push(format!(
            "repair case `{}` symbols_supplied exceeds repair_symbol_budget",
            case.case_id
        ));
    }
}

fn validate_outcome_and_refusal(
    case: &RepairCorpusCase,
    outcome_classes: &mut BTreeSet<String>,
    refusal_reasons: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    if !ALLOWED_OUTCOME_CLASSES.contains(&case.expected_outcome.as_str()) {
        errors.push(format!(
            "repair case `{}` has unsupported expected_outcome `{}`",
            case.case_id, case.expected_outcome
        ));
    }
    outcome_classes.insert(case.expected_outcome.clone());

    let is_refusal = case.expected_outcome.starts_with("refused_");
    if is_refusal {
        if case.expected_refusal_reason.trim().is_empty() {
            errors.push(format!(
                "repair case `{}` refusal outcome must declare expected_refusal_reason",
                case.case_id
            ));
        } else if ALLOWED_REFUSAL_REASONS.contains(&case.expected_refusal_reason.as_str()) {
            refusal_reasons.insert(case.expected_refusal_reason.clone());
        } else {
            errors.push(format!(
                "repair case `{}` has unsupported expected_refusal_reason `{}`",
                case.case_id, case.expected_refusal_reason
            ));
        }
        validate_refusal_evidence(case, errors);
    } else if !case.expected_refusal_reason.trim().is_empty() {
        errors.push(format!(
            "repair case `{}` non-refusal outcome must leave expected_refusal_reason empty",
            case.case_id
        ));
    }

    if case.expected_outcome == "recovered"
        && case.symbols_supplied < case.symbols_required_for_recovery
    {
        errors.push(format!(
            "repair case `{}` recovered outcome cannot supply fewer symbols than required",
            case.case_id
        ));
    }
}

fn validate_refusal_evidence(case: &RepairCorpusCase, errors: &mut Vec<String>) {
    match case.expected_refusal_reason.as_str() {
        "wrong_image_ledger" if case.ledger.bound_image_hash == case.original_image_hash => {
            errors.push(format!(
                "repair case `{}` wrong_image_ledger requires bound_image_hash differs from original_image_hash",
                case.case_id
            ));
        }
        "stale_ledger"
            if case.ledger.stale_against_generation == 0
                || case.ledger.stale_against_generation <= case.ledger.symbol_generation =>
        {
            errors.push(format!(
                "repair case `{}` stale_ledger requires stale_against_generation > symbol_generation",
                case.case_id
            ));
        }
        "truncated_ledger" if !case.ledger.truncated => {
            errors.push(format!(
                "repair case `{}` truncated_ledger must set ledger.truncated = true",
                case.case_id
            ));
        }
        "tampered_ledger_row" if case.ledger.tampered_row_id.trim().is_empty() => {
            errors.push(format!(
                "repair case `{}` tampered_ledger_row must name the tampered_row_id",
                case.case_id
            ));
        }
        "duplicate_ledger_row" if case.ledger.duplicate_row_id.trim().is_empty() => {
            errors.push(format!(
                "repair case `{}` duplicate_ledger_row must name the duplicate_row_id",
                case.case_id
            ));
        }
        "insufficient_symbols" if case.symbols_supplied >= case.symbols_required_for_recovery => {
            errors.push(format!(
                "repair case `{}` insufficient_symbols requires symbols_supplied < symbols_required_for_recovery",
                case.case_id
            ));
        }
        "post_repair_refresh_mismatch"
            if case.verification.post_repair_symbol_generation <= case.ledger.symbol_generation =>
        {
            errors.push(format!(
                "repair case `{}` post_repair_refresh_mismatch requires post_repair_symbol_generation > ledger.symbol_generation",
                case.case_id
            ));
        }
        _ => {}
    }
}

fn validate_verification(case: &RepairCorpusCase, errors: &mut Vec<String>) {
    if case.expected_outcome == "recovered" {
        if !is_valid_sha256(&case.verification.post_repair_image_hash) {
            errors.push(format!(
                "repair case `{}` recovered outcome must declare a valid post_repair_image_hash",
                case.case_id
            ));
        }
        if !case.verification.scrub_clean || !case.verification.reopen_clean {
            errors.push(format!(
                "repair case `{}` recovered outcome must report scrub_clean and reopen_clean",
                case.case_id
            ));
        }
        if case.verification.post_repair_symbol_generation <= case.ledger.symbol_generation {
            errors.push(format!(
                "repair case `{}` recovered outcome must refresh post_repair_symbol_generation",
                case.case_id
            ));
        }
    }
}

fn validate_chain_of_custody(case: &RepairCorpusCase, errors: &mut Vec<String>) {
    if case.chain_of_custody.artifact_path.trim().is_empty() {
        errors.push(format!(
            "repair case `{}` chain_of_custody missing artifact_path",
            case.case_id
        ));
    }
    if !is_valid_sha256(&case.chain_of_custody.artifact_sha256) {
        errors.push(format!(
            "repair case `{}` chain_of_custody artifact_sha256 must be sha256:<64-hex>",
            case.case_id
        ));
    }
    if case.chain_of_custody.recorded_by.trim().is_empty() {
        errors.push(format!(
            "repair case `{}` chain_of_custody missing recorded_by",
            case.case_id
        ));
    }
    if case.chain_of_custody.recorded_at_unix == 0 {
        errors.push(format!(
            "repair case `{}` chain_of_custody recorded_at_unix must be positive",
            case.case_id
        ));
    }
    if !case.chain_of_custody.linked_bead.starts_with("bd-") {
        errors.push(format!(
            "repair case `{}` chain_of_custody linked_bead must look like bd-...",
            case.case_id
        ));
    }
}

fn validate_negative_case_coverage(seen: &BTreeSet<String>, errors: &mut Vec<String>) {
    for required in REQUIRED_NEGATIVE_CASES {
        if !seen.contains(required) {
            errors.push(format!(
                "repair corpus missing required negative case `{required}`"
            ));
        }
    }
}

fn is_valid_sha256(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("sha256:") else {
        return false;
    };
    suffix.len() == 64 && suffix.chars().all(|ch| ch.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_corpus() -> RepairCorpus {
        parse_repair_corpus(DEFAULT_REPAIR_CORPUS_JSON).expect("default repair corpus parses")
    }

    #[test]
    fn default_corpus_validates_required_negative_cases() {
        let report = validate_default_repair_corpus().expect("default corpus validates");
        assert_eq!(report.schema_version, REPAIR_CORPUS_SCHEMA_VERSION);
        assert_eq!(report.bead_id, "bd-0xa7h");
        for required in REQUIRED_NEGATIVE_CASES {
            assert!(
                report.refusal_reasons.iter().any(|r| r == required),
                "missing refusal reason {required}"
            );
        }
        assert!(report.outcome_classes.iter().any(|o| o == "recovered"));
    }

    #[test]
    fn missing_wrong_image_case_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus
            .cases
            .retain(|case| case.expected_refusal_reason != "wrong_image_ledger");
        let report = validate_repair_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required negative case `wrong_image_ledger`"))
        );
    }

    #[test]
    fn missing_stale_ledger_case_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus
            .cases
            .retain(|case| case.expected_refusal_reason != "stale_ledger");
        let report = validate_repair_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required negative case `stale_ledger`"))
        );
    }

    #[test]
    fn duplicate_case_id_is_rejected() {
        let mut corpus = fixture_corpus();
        let dup = corpus.cases[0].case_id.clone();
        corpus.cases[1].case_id = dup;
        let report = validate_repair_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("duplicate repair corpus case_id"))
        );
    }

    #[test]
    fn malformed_image_hash_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases[0].original_image_hash = "md5:not-supported".to_owned();
        let report = validate_repair_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("malformed original_image_hash"))
        );
    }

    #[test]
    fn corrupted_hash_must_differ_from_original() {
        let mut corpus = fixture_corpus();
        corpus.cases[0].corrupted_image_hash = corpus.cases[0].original_image_hash.clone();
        let report = validate_repair_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must differ from original_image_hash"))
        );
    }

    #[test]
    fn wrong_image_ledger_requires_distinct_bound_hash() {
        let mut corpus = fixture_corpus();
        let case = corpus
            .cases
            .iter_mut()
            .find(|c| c.expected_refusal_reason == "wrong_image_ledger")
            .expect("wrong_image_ledger fixture exists");
        case.ledger.bound_image_hash = case.original_image_hash.clone();
        let report = validate_repair_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("wrong_image_ledger requires bound_image_hash differs"))
        );
    }

    #[test]
    fn stale_ledger_requires_higher_against_generation() {
        let mut corpus = fixture_corpus();
        let case = corpus
            .cases
            .iter_mut()
            .find(|c| c.expected_refusal_reason == "stale_ledger")
            .expect("stale_ledger fixture exists");
        case.ledger.stale_against_generation = case.ledger.symbol_generation;
        let report = validate_repair_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("stale_ledger requires stale_against_generation"))
        );
    }

    #[test]
    fn truncated_ledger_requires_truncated_flag() {
        let mut corpus = fixture_corpus();
        let case = corpus
            .cases
            .iter_mut()
            .find(|c| c.expected_refusal_reason == "truncated_ledger")
            .expect("truncated_ledger fixture exists");
        case.ledger.truncated = false;
        let report = validate_repair_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("truncated_ledger must set ledger.truncated = true"))
        );
    }

    #[test]
    fn insufficient_symbols_requires_lower_supply() {
        let mut corpus = fixture_corpus();
        let index = corpus
            .cases
            .iter()
            .position(|c| c.expected_refusal_reason == "insufficient_symbols")
            .unwrap_or(0);
        let case = &mut corpus.cases[index];
        case.expected_outcome = "refused_other".to_owned();
        case.expected_refusal_reason = "insufficient_symbols".to_owned();
        case.symbols_supplied = case.symbols_required_for_recovery;
        let report = validate_repair_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err.contains(
            "insufficient_symbols requires symbols_supplied < symbols_required_for_recovery"
        )));
    }

    #[test]
    fn recovered_outcome_requires_symbol_refresh() {
        let mut corpus = fixture_corpus();
        let case = corpus
            .cases
            .iter_mut()
            .find(|c| c.expected_outcome == "recovered")
            .expect("recovered fixture exists");
        case.verification.post_repair_symbol_generation = case.ledger.symbol_generation;
        let report = validate_repair_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must refresh post_repair_symbol_generation"))
        );
    }

    #[test]
    fn recovered_outcome_requires_clean_scrub_and_reopen() {
        let mut corpus = fixture_corpus();
        let case = corpus
            .cases
            .iter_mut()
            .find(|c| c.expected_outcome == "recovered")
            .expect("recovered fixture exists");
        case.verification.scrub_clean = false;
        let report = validate_repair_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must report scrub_clean and reopen_clean"))
        );
    }

    #[test]
    fn recovered_outcome_cannot_undersupply_symbols() {
        let mut corpus = fixture_corpus();
        let case = corpus
            .cases
            .iter_mut()
            .find(|c| c.expected_outcome == "recovered")
            .expect("recovered fixture exists");
        case.symbols_supplied = case.symbols_required_for_recovery - 1;
        let report = validate_repair_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("recovered outcome cannot supply fewer symbols"))
        );
    }

    #[test]
    fn refusal_outcome_requires_refusal_reason() {
        let mut corpus = fixture_corpus();
        let case = corpus
            .cases
            .iter_mut()
            .find(|c| c.expected_outcome.starts_with("refused_"))
            .expect("refusal fixture exists");
        case.expected_refusal_reason = String::new();
        let report = validate_repair_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must declare expected_refusal_reason"))
        );
    }

    #[test]
    fn missing_chain_of_custody_artifact_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases[0].chain_of_custody.artifact_path = String::new();
        let report = validate_repair_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("chain_of_custody missing artifact_path"))
        );
    }

    #[test]
    fn malformed_chain_of_custody_artifact_hash_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases[0].chain_of_custody.artifact_sha256 = "deadbeef".to_owned();
        let report = validate_repair_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("artifact_sha256 must be sha256:<64-hex>"))
        );
    }

    #[test]
    fn malformed_linked_bead_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases[0].chain_of_custody.linked_bead = "PROJ-42".to_owned();
        let report = validate_repair_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("linked_bead must look like bd-"))
        );
    }

    #[test]
    fn empty_cases_list_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases.clear();
        let report = validate_repair_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("at least one case"))
        );
    }
}
