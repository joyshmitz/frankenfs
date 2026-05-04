#![forbid(unsafe_code)]

//! Deterministic fault-injection corpus for repair confidence evidence.
//!
//! Tracks bd-rchk0.5.3: complements the prior repair_confidence_lab schema
//! with a corpus of deterministic fault models — bit flips, block erasures,
//! reordered/stale blocks, truncated repair metadata, mismatched symbol
//! sets, and adversarial seeds. Each row binds a deterministic seed,
//! reproducible affected offsets, the logical structure under attack, the
//! expected repair class (clean / partial / detection_only / false_positive
//! / unsafe_to_repair), and the lower-bound confidence the system must
//! achieve before claiming the class. Adversarial cases must keep the
//! system in detection-only or unsafe-to-repair until calibration evidence
//! upgrades them.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const FAULT_INJECTION_CORPUS_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_FAULT_INJECTION_CORPUS_PATH: &str =
    "tests/fault-injection-corpus/fault_injection_corpus.json";
const DEFAULT_FAULT_INJECTION_CORPUS_JSON: &str =
    include_str!("../../../tests/fault-injection-corpus/fault_injection_corpus.json");

const ALLOWED_FAULT_KINDS: [&str; 6] = [
    "bit_flip",
    "block_erasure",
    "reordered_blocks",
    "truncated_repair_metadata",
    "mismatched_symbol_set",
    "adversarial_seed",
];

const ALLOWED_LOGICAL_STRUCTURES: [&str; 7] = [
    "superblock",
    "group_descriptor",
    "inode_block",
    "directory_entry",
    "extent_tree",
    "repair_ledger",
    "raptor_symbol_block",
];

const ALLOWED_REPAIR_CLASSES: [&str; 5] = [
    "clean_repair",
    "partial_repair",
    "detection_only",
    "false_positive",
    "unsafe_to_repair",
];

const REQUIRED_FAULT_COVERAGE: [&str; 6] = [
    "bit_flip",
    "block_erasure",
    "reordered_blocks",
    "truncated_repair_metadata",
    "mismatched_symbol_set",
    "adversarial_seed",
];

const REQUIRED_REPAIR_CLASS_COVERAGE: [&str; 4] = [
    "clean_repair",
    "detection_only",
    "false_positive",
    "unsafe_to_repair",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FaultInjectionCorpus {
    pub schema_version: u32,
    pub corpus_id: String,
    pub bead_id: String,
    pub min_confidence_lower_bound_for_clean_repair: f64,
    pub cases: Vec<FaultInjectionCase>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FaultInjectionCase {
    pub case_id: String,
    pub seed: u64,
    pub fault_kind: String,
    pub affected_offsets: Vec<u64>,
    pub affected_logical_structure: String,
    pub repair_symbol_budget: u32,
    pub symbols_required_for_recovery: u32,
    pub symbols_supplied: u32,
    pub expected_repair_class: String,
    pub expected_confidence_lower_bound: f64,
    pub corruption_manifest_hash: String,
    pub original_image_hash: String,
    pub corrupted_image_hash: String,
    pub replay_command: String,
    #[serde(default)]
    pub follow_up_bead: String,
    #[serde(default)]
    pub adversarial: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FaultInjectionCorpusReport {
    pub schema_version: u32,
    pub corpus_id: String,
    pub bead_id: String,
    pub case_count: usize,
    pub fault_kinds_seen: Vec<String>,
    pub repair_classes_seen: Vec<String>,
    pub adversarial_count: usize,
    pub valid: bool,
    pub errors: Vec<String>,
}

pub fn parse_fault_injection_corpus(text: &str) -> Result<FaultInjectionCorpus> {
    serde_json::from_str(text)
        .map_err(|err| anyhow::anyhow!("failed to parse fault injection corpus JSON: {err}"))
}

pub fn validate_default_fault_injection_corpus() -> Result<FaultInjectionCorpusReport> {
    let corpus = parse_fault_injection_corpus(DEFAULT_FAULT_INJECTION_CORPUS_JSON)?;
    let report = validate_fault_injection_corpus(&corpus);
    if !report.valid {
        bail!(
            "fault injection corpus failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        );
    }
    Ok(report)
}

#[must_use]
pub fn validate_fault_injection_corpus(
    corpus: &FaultInjectionCorpus,
) -> FaultInjectionCorpusReport {
    let mut errors = Vec::new();
    let mut ids = BTreeSet::new();
    let mut seeds = BTreeSet::new();
    let mut fault_kinds = BTreeSet::new();
    let mut classes = BTreeSet::new();
    let mut adversarial = 0_usize;

    validate_top_level(corpus, &mut errors);
    for case in &corpus.cases {
        validate_case(
            case,
            corpus.min_confidence_lower_bound_for_clean_repair,
            &mut ids,
            &mut seeds,
            &mut fault_kinds,
            &mut classes,
            &mut adversarial,
            &mut errors,
        );
    }
    validate_required_coverage(&fault_kinds, &classes, &mut errors);

    FaultInjectionCorpusReport {
        schema_version: corpus.schema_version,
        corpus_id: corpus.corpus_id.clone(),
        bead_id: corpus.bead_id.clone(),
        case_count: corpus.cases.len(),
        fault_kinds_seen: fault_kinds.into_iter().collect(),
        repair_classes_seen: classes.into_iter().collect(),
        adversarial_count: adversarial,
        valid: errors.is_empty(),
        errors,
    }
}

fn validate_top_level(corpus: &FaultInjectionCorpus, errors: &mut Vec<String>) {
    if corpus.schema_version != FAULT_INJECTION_CORPUS_SCHEMA_VERSION {
        errors.push(format!(
            "fault injection corpus schema_version must be {FAULT_INJECTION_CORPUS_SCHEMA_VERSION}, got {}",
            corpus.schema_version
        ));
    }
    if corpus.corpus_id.trim().is_empty() {
        errors.push("fault injection corpus missing corpus_id".to_owned());
    }
    if !corpus.bead_id.starts_with("bd-") {
        errors.push(format!(
            "fault injection corpus bead_id must look like bd-..., got `{}`",
            corpus.bead_id
        ));
    }
    if !(0.0..=1.0).contains(&corpus.min_confidence_lower_bound_for_clean_repair) {
        errors.push(format!(
            "min_confidence_lower_bound_for_clean_repair must be in [0.0, 1.0], got {}",
            corpus.min_confidence_lower_bound_for_clean_repair
        ));
    }
    if corpus.min_confidence_lower_bound_for_clean_repair < 0.5 {
        errors.push(format!(
            "min_confidence_lower_bound_for_clean_repair {} is too lax; clean_repair must require >= 0.5 confidence",
            corpus.min_confidence_lower_bound_for_clean_repair
        ));
    }
    if corpus.cases.is_empty() {
        errors.push("fault injection corpus must declare at least one case".to_owned());
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_case(
    case: &FaultInjectionCase,
    min_clean_confidence: f64,
    ids: &mut BTreeSet<String>,
    seeds: &mut BTreeSet<u64>,
    fault_kinds: &mut BTreeSet<String>,
    repair_classes: &mut BTreeSet<String>,
    adversarial: &mut usize,
    errors: &mut Vec<String>,
) {
    if !ids.insert(case.case_id.clone()) {
        errors.push(format!("duplicate fault injection case_id `{}`", case.case_id));
    }
    if !case.case_id.starts_with("fic_") {
        errors.push(format!(
            "case_id `{}` must start with fic_",
            case.case_id
        ));
    }
    if case.seed == 0 {
        errors.push(format!(
            "case `{}` seed must be positive",
            case.case_id
        ));
    }
    if !seeds.insert(case.seed) {
        errors.push(format!(
            "case `{}` seed `{}` is not unique across the corpus",
            case.case_id, case.seed
        ));
    }
    if ALLOWED_FAULT_KINDS.contains(&case.fault_kind.as_str()) {
        fault_kinds.insert(case.fault_kind.clone());
    } else {
        errors.push(format!(
            "case `{}` has unsupported fault_kind `{}`",
            case.case_id, case.fault_kind
        ));
    }
    if !ALLOWED_LOGICAL_STRUCTURES.contains(&case.affected_logical_structure.as_str()) {
        errors.push(format!(
            "case `{}` has unsupported affected_logical_structure `{}`",
            case.case_id, case.affected_logical_structure
        ));
    }
    if ALLOWED_REPAIR_CLASSES.contains(&case.expected_repair_class.as_str()) {
        repair_classes.insert(case.expected_repair_class.clone());
    } else {
        errors.push(format!(
            "case `{}` has unsupported expected_repair_class `{}`",
            case.case_id, case.expected_repair_class
        ));
    }
    if case.adversarial {
        *adversarial += 1;
    }

    validate_case_offsets(case, errors);
    validate_case_symbol_budget(case, errors);
    validate_case_confidence(case, min_clean_confidence, errors);
    validate_case_required_text(case, errors);
    validate_case_class_invariants(case, errors);
}

fn validate_case_offsets(case: &FaultInjectionCase, errors: &mut Vec<String>) {
    if case.affected_offsets.is_empty() {
        errors.push(format!(
            "case `{}` must declare at least one affected_offset",
            case.case_id
        ));
    }
    let mut last = u64::MAX;
    for offset in &case.affected_offsets {
        if last != u64::MAX && *offset <= last {
            errors.push(format!(
                "case `{}` affected_offsets must be strictly increasing for deterministic replay",
                case.case_id
            ));
            break;
        }
        last = *offset;
    }
}

fn validate_case_symbol_budget(case: &FaultInjectionCase, errors: &mut Vec<String>) {
    if case.repair_symbol_budget == 0 {
        errors.push(format!(
            "case `{}` repair_symbol_budget must be positive",
            case.case_id
        ));
    }
    if case.symbols_required_for_recovery == 0 {
        errors.push(format!(
            "case `{}` symbols_required_for_recovery must be positive",
            case.case_id
        ));
    }
    if case.symbols_supplied > case.repair_symbol_budget {
        errors.push(format!(
            "case `{}` symbols_supplied exceeds repair_symbol_budget",
            case.case_id
        ));
    }
}

fn validate_case_confidence(
    case: &FaultInjectionCase,
    min_clean_confidence: f64,
    errors: &mut Vec<String>,
) {
    if !(0.0..=1.0).contains(&case.expected_confidence_lower_bound) {
        errors.push(format!(
            "case `{}` expected_confidence_lower_bound must be in [0.0, 1.0]",
            case.case_id
        ));
    }
    match case.expected_repair_class.as_str() {
        "clean_repair" => {
            if case.expected_confidence_lower_bound < min_clean_confidence {
                errors.push(format!(
                    "case `{}` clean_repair must declare expected_confidence_lower_bound >= {}",
                    case.case_id, min_clean_confidence
                ));
            }
            if case.symbols_supplied < case.symbols_required_for_recovery {
                errors.push(format!(
                    "case `{}` clean_repair must supply at least the required symbols",
                    case.case_id
                ));
            }
        }
        "partial_repair" => {
            if case.expected_confidence_lower_bound < 0.25 {
                errors.push(format!(
                    "case `{}` partial_repair must declare expected_confidence_lower_bound >= 0.25",
                    case.case_id
                ));
            }
        }
        "detection_only" => {
            if case.expected_confidence_lower_bound != 0.0 {
                errors.push(format!(
                    "case `{}` detection_only must declare expected_confidence_lower_bound = 0.0",
                    case.case_id
                ));
            }
        }
        "false_positive" => {
            if case.expected_confidence_lower_bound > 0.05 {
                errors.push(format!(
                    "case `{}` false_positive must declare expected_confidence_lower_bound <= 0.05",
                    case.case_id
                ));
            }
        }
        "unsafe_to_repair" => {
            if case.expected_confidence_lower_bound != 0.0 {
                errors.push(format!(
                    "case `{}` unsafe_to_repair must declare expected_confidence_lower_bound = 0.0",
                    case.case_id
                ));
            }
        }
        _ => {}
    }
}

fn validate_case_required_text(case: &FaultInjectionCase, errors: &mut Vec<String>) {
    if !is_valid_sha256(&case.original_image_hash) {
        errors.push(format!(
            "case `{}` original_image_hash must be sha256:<64-hex>",
            case.case_id
        ));
    }
    if !is_valid_sha256(&case.corrupted_image_hash) {
        errors.push(format!(
            "case `{}` corrupted_image_hash must be sha256:<64-hex>",
            case.case_id
        ));
    }
    if case.original_image_hash == case.corrupted_image_hash {
        errors.push(format!(
            "case `{}` corrupted_image_hash must differ from original_image_hash",
            case.case_id
        ));
    }
    if !is_valid_sha256(&case.corruption_manifest_hash) {
        errors.push(format!(
            "case `{}` corruption_manifest_hash must be sha256:<64-hex>",
            case.case_id
        ));
    }
    if case.replay_command.trim().is_empty() {
        errors.push(format!(
            "case `{}` missing replay_command",
            case.case_id
        ));
    }
    if !case.follow_up_bead.is_empty() && !case.follow_up_bead.starts_with("bd-") {
        errors.push(format!(
            "case `{}` follow_up_bead must look like bd-..., got `{}`",
            case.case_id, case.follow_up_bead
        ));
    }
}

fn validate_case_class_invariants(
    case: &FaultInjectionCase,
    errors: &mut Vec<String>,
) {
    if case.fault_kind == "adversarial_seed" && !case.adversarial {
        errors.push(format!(
            "case `{}` fault_kind=adversarial_seed must set adversarial=true",
            case.case_id
        ));
    }
    if case.adversarial
        && !matches!(
            case.expected_repair_class.as_str(),
            "detection_only" | "unsafe_to_repair"
        )
    {
        errors.push(format!(
            "case `{}` adversarial cases must classify as detection_only or unsafe_to_repair until calibrated",
            case.case_id
        ));
    }
    if case.expected_repair_class == "unsafe_to_repair"
        && !case.follow_up_bead.starts_with("bd-")
    {
        errors.push(format!(
            "case `{}` unsafe_to_repair must link a follow_up_bead so calibration is tracked",
            case.case_id
        ));
    }
}

fn validate_required_coverage(
    fault_kinds: &BTreeSet<String>,
    classes: &BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    for required in REQUIRED_FAULT_COVERAGE {
        if !fault_kinds.contains(required) {
            errors.push(format!(
                "fault injection corpus missing required fault_kind `{required}`"
            ));
        }
    }
    for required in REQUIRED_REPAIR_CLASS_COVERAGE {
        if !classes.contains(required) {
            errors.push(format!(
                "fault injection corpus missing required expected_repair_class `{required}`"
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

    fn fixture_corpus() -> FaultInjectionCorpus {
        parse_fault_injection_corpus(DEFAULT_FAULT_INJECTION_CORPUS_JSON)
            .expect("default fault injection corpus parses")
    }

    #[test]
    fn default_corpus_validates_required_coverage() {
        let report = validate_default_fault_injection_corpus()
            .expect("default fault injection corpus validates");
        assert_eq!(report.bead_id, "bd-rchk0.5.3");
        for kind in REQUIRED_FAULT_COVERAGE {
            assert!(
                report.fault_kinds_seen.iter().any(|k| k == kind),
                "missing fault_kind {kind}"
            );
        }
        for class in REQUIRED_REPAIR_CLASS_COVERAGE {
            assert!(
                report.repair_classes_seen.iter().any(|c| c == class),
                "missing repair_class {class}"
            );
        }
        assert!(report.adversarial_count >= 1);
    }

    #[test]
    fn missing_bit_flip_kind_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases.retain(|c| c.fault_kind != "bit_flip");
        let report = validate_fault_injection_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err.contains("missing required fault_kind `bit_flip`")));
    }

    #[test]
    fn missing_unsafe_class_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus
            .cases
            .retain(|c| c.expected_repair_class != "unsafe_to_repair");
        let report = validate_fault_injection_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err
            .contains("missing required expected_repair_class `unsafe_to_repair`")));
    }

    #[test]
    fn duplicate_case_id_is_rejected() {
        let mut corpus = fixture_corpus();
        let dup = corpus.cases[0].case_id.clone();
        corpus.cases[1].case_id = dup;
        let report = validate_fault_injection_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err.contains("duplicate fault injection case_id")));
    }

    #[test]
    fn case_id_prefix_is_enforced() {
        let mut corpus = fixture_corpus();
        corpus.cases[0].case_id = "case_001".to_owned();
        let report = validate_fault_injection_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err.contains("must start with fic_")));
    }

    #[test]
    fn zero_seed_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases[0].seed = 0;
        let report = validate_fault_injection_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err.contains("seed must be positive")));
    }

    #[test]
    fn duplicate_seed_is_rejected() {
        let mut corpus = fixture_corpus();
        let seed = corpus.cases[0].seed;
        corpus.cases[1].seed = seed;
        let report = validate_fault_injection_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err.contains("is not unique across the corpus")));
    }

    #[test]
    fn unsupported_fault_kind_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases[0].fault_kind = "alien_radiation".to_owned();
        let report = validate_fault_injection_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err.contains("unsupported fault_kind")));
    }

    #[test]
    fn unsupported_logical_structure_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases[0].affected_logical_structure = "vibes_block".to_owned();
        let report = validate_fault_injection_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err.contains("unsupported affected_logical_structure")));
    }

    #[test]
    fn empty_offsets_list_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases[0].affected_offsets.clear();
        let report = validate_fault_injection_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err.contains("at least one affected_offset")));
    }

    #[test]
    fn non_increasing_offsets_are_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases[0].affected_offsets = vec![100, 50];
        let report = validate_fault_injection_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err
            .contains("affected_offsets must be strictly increasing for deterministic replay")));
    }

    #[test]
    fn zero_repair_symbol_budget_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases[0].repair_symbol_budget = 0;
        let report = validate_fault_injection_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err.contains("repair_symbol_budget must be positive")));
    }

    #[test]
    fn symbols_supplied_exceeds_budget_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases[0].symbols_supplied = corpus.cases[0].repair_symbol_budget + 5;
        let report = validate_fault_injection_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err.contains("symbols_supplied exceeds repair_symbol_budget")));
    }

    #[test]
    fn clean_repair_must_supply_required_symbols() {
        let mut corpus = fixture_corpus();
        let case = corpus
            .cases
            .iter_mut()
            .find(|c| c.expected_repair_class == "clean_repair")
            .expect("clean repair fixture exists");
        case.symbols_supplied = case.symbols_required_for_recovery - 1;
        let report = validate_fault_injection_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err
            .contains("clean_repair must supply at least the required symbols")));
    }

    #[test]
    fn clean_repair_must_meet_min_confidence() {
        let mut corpus = fixture_corpus();
        let case = corpus
            .cases
            .iter_mut()
            .find(|c| c.expected_repair_class == "clean_repair")
            .expect("clean repair fixture exists");
        case.expected_confidence_lower_bound = 0.5;
        let report = validate_fault_injection_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err
            .contains("clean_repair must declare expected_confidence_lower_bound >=")));
    }

    #[test]
    fn detection_only_must_declare_zero_confidence() {
        let mut corpus = fixture_corpus();
        let case = corpus
            .cases
            .iter_mut()
            .find(|c| c.expected_repair_class == "detection_only")
            .expect("detection only fixture exists");
        case.expected_confidence_lower_bound = 0.5;
        let report = validate_fault_injection_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err
            .contains("detection_only must declare expected_confidence_lower_bound = 0.0")));
    }

    #[test]
    fn false_positive_confidence_must_be_below_5_percent() {
        let mut corpus = fixture_corpus();
        let case = corpus
            .cases
            .iter_mut()
            .find(|c| c.expected_repair_class == "false_positive")
            .expect("false positive fixture exists");
        case.expected_confidence_lower_bound = 0.5;
        let report = validate_fault_injection_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err
            .contains("false_positive must declare expected_confidence_lower_bound <= 0.05")));
    }

    #[test]
    fn adversarial_must_classify_as_detection_or_unsafe() {
        let mut corpus = fixture_corpus();
        let case = corpus
            .cases
            .iter_mut()
            .find(|c| c.adversarial)
            .expect("adversarial fixture exists");
        case.expected_repair_class = "clean_repair".to_owned();
        case.expected_confidence_lower_bound = 0.99;
        case.symbols_supplied = case.symbols_required_for_recovery;
        let report = validate_fault_injection_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err
            .contains("adversarial cases must classify as detection_only or unsafe_to_repair")));
    }

    #[test]
    fn adversarial_seed_kind_must_set_adversarial_flag() {
        let mut corpus = fixture_corpus();
        let case = corpus
            .cases
            .iter_mut()
            .find(|c| c.fault_kind == "adversarial_seed")
            .expect("adversarial seed fixture exists");
        case.adversarial = false;
        let report = validate_fault_injection_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err
            .contains("fault_kind=adversarial_seed must set adversarial=true")));
    }

    #[test]
    fn unsafe_to_repair_must_link_follow_up_bead() {
        let mut corpus = fixture_corpus();
        let case = corpus
            .cases
            .iter_mut()
            .find(|c| c.expected_repair_class == "unsafe_to_repair")
            .expect("unsafe fixture exists");
        case.follow_up_bead = String::new();
        let report = validate_fault_injection_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err
            .contains("unsafe_to_repair must link a follow_up_bead")));
    }

    #[test]
    fn malformed_image_hash_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases[0].original_image_hash = "md5:not-supported".to_owned();
        let report = validate_fault_injection_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err.contains("original_image_hash must be sha256")));
    }

    #[test]
    fn corrupted_hash_must_differ_from_original() {
        let mut corpus = fixture_corpus();
        corpus.cases[0].corrupted_image_hash = corpus.cases[0].original_image_hash.clone();
        let report = validate_fault_injection_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err.contains("must differ from original_image_hash")));
    }

    #[test]
    fn missing_replay_command_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases[0].replay_command = String::new();
        let report = validate_fault_injection_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err.contains("missing replay_command")));
    }

    #[test]
    fn lax_min_confidence_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.min_confidence_lower_bound_for_clean_repair = 0.1;
        let report = validate_fault_injection_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err.contains("too lax")));
    }

    #[test]
    fn out_of_range_min_confidence_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.min_confidence_lower_bound_for_clean_repair = 1.5;
        let report = validate_fault_injection_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err.contains("must be in [0.0, 1.0]")));
    }

    #[test]
    fn empty_cases_list_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases.clear();
        let report = validate_fault_injection_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err.contains("at least one case")));
    }
}
