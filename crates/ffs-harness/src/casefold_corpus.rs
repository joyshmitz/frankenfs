#![forbid(unsafe_code)]

//! Ext4 casefold conformance corpus.
//!
//! Tracks bd-9er6s: every fixture row binds Unicode input bytes to a
//! normalized/casefold key and an expected lookup/create/rename outcome,
//! including invalid-encoding refusal, overly-long normalized names, htree
//! interaction, and mount-time feature-bit validation. The corpus
//! distinguishes basic-lookup support from collision-safe mounted casefold
//! conformance so README and proof bundles cannot imply robust parity from
//! happy-path coverage alone.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const CASEFOLD_CORPUS_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_CASEFOLD_CORPUS_PATH: &str = "tests/casefold-corpus/casefold_corpus.json";
const DEFAULT_CASEFOLD_CORPUS_JSON: &str =
    include_str!("../../../tests/casefold-corpus/casefold_corpus.json");

const ALLOWED_OPERATION_KINDS: [&str; 5] = [
    "lookup",
    "create",
    "rename",
    "cross_directory_rename",
    "mount_feature_check",
];

const ALLOWED_OUTCOMES: [&str; 8] = [
    "lookup_hit",
    "lookup_miss",
    "create_success",
    "create_collision_refused",
    "rename_success",
    "rename_collision_refused",
    "invalid_encoding_refused",
    "mount_feature_accepted",
];

const ALLOWED_NORMALIZED_CLASSES: [&str; 5] = [
    "ascii_lower",
    "nfc_canonical",
    "casefold_only",
    "invalid_utf8",
    "overlong_normalized_name",
];

const ALLOWED_KERNEL_COMPARISON: [&str; 4] = [
    "kernel_exact_match",
    "kernel_skipped_no_capability",
    "kernel_diverges_documented",
    "kernel_unsupported_submode",
];

const REQUIRED_FEATURE_FLAGS: [&str; 2] =
    ["EXT4_FEATURE_INCOMPAT_CASEFOLD", "ext4_encoding_utf8_12_1"];

const ALLOWED_CLEANUP_POLICIES: [&str; 3] = [
    "teardown_image",
    "preserve_artifacts_on_failure",
    "preserve_artifacts_always",
];

const REQUIRED_OPERATION_COVERAGE: [&str; 5] = [
    "lookup",
    "create",
    "rename",
    "cross_directory_rename",
    "mount_feature_check",
];

const REQUIRED_OUTCOME_COVERAGE: [&str; 4] = [
    "create_collision_refused",
    "rename_collision_refused",
    "invalid_encoding_refused",
    "mount_feature_accepted",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CasefoldCorpus {
    pub schema_version: u32,
    pub corpus_id: String,
    pub bead_id: String,
    pub cases: Vec<CasefoldCase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CasefoldCase {
    pub case_id: String,
    pub source_name_bytes_hex: String,
    pub normalized_form_bytes_hex: String,
    pub normalized_class: String,
    pub operation_kind: String,
    pub feature_flags: Vec<String>,
    pub expected_outcome: String,
    pub kernel_comparison_status: String,
    #[serde(default)]
    pub unsupported_rationale: String,
    pub cleanup_policy: String,
    pub artifact_requirements: Vec<String>,
    #[serde(default)]
    pub htree_interaction: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CasefoldCorpusReport {
    pub schema_version: u32,
    pub corpus_id: String,
    pub bead_id: String,
    pub case_count: usize,
    pub operations_seen: Vec<String>,
    pub outcomes_seen: Vec<String>,
    pub kernel_compared_count: usize,
    pub valid: bool,
    pub errors: Vec<String>,
}

pub fn parse_casefold_corpus(text: &str) -> Result<CasefoldCorpus> {
    serde_json::from_str(text)
        .map_err(|err| anyhow::anyhow!("failed to parse casefold corpus JSON: {err}"))
}

pub fn validate_default_casefold_corpus() -> Result<CasefoldCorpusReport> {
    let corpus = parse_casefold_corpus(DEFAULT_CASEFOLD_CORPUS_JSON)?;
    let report = validate_casefold_corpus(&corpus);
    if !report.valid {
        bail!(
            "casefold corpus failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        );
    }
    Ok(report)
}

#[must_use]
pub fn validate_casefold_corpus(corpus: &CasefoldCorpus) -> CasefoldCorpusReport {
    let mut errors = Vec::new();
    let mut ids = BTreeSet::new();
    let mut operations = BTreeSet::new();
    let mut outcomes = BTreeSet::new();
    let mut kernel_compared_count = 0_usize;

    validate_top_level(corpus, &mut errors);
    for case in &corpus.cases {
        validate_case(
            case,
            &mut ids,
            &mut operations,
            &mut outcomes,
            &mut kernel_compared_count,
            &mut errors,
        );
    }
    validate_operation_coverage(&operations, &mut errors);
    validate_outcome_coverage(&outcomes, &mut errors);

    CasefoldCorpusReport {
        schema_version: corpus.schema_version,
        corpus_id: corpus.corpus_id.clone(),
        bead_id: corpus.bead_id.clone(),
        case_count: corpus.cases.len(),
        operations_seen: operations.into_iter().collect(),
        outcomes_seen: outcomes.into_iter().collect(),
        kernel_compared_count,
        valid: errors.is_empty(),
        errors,
    }
}

fn validate_top_level(corpus: &CasefoldCorpus, errors: &mut Vec<String>) {
    if corpus.schema_version != CASEFOLD_CORPUS_SCHEMA_VERSION {
        errors.push(format!(
            "casefold corpus schema_version must be {CASEFOLD_CORPUS_SCHEMA_VERSION}, got {}",
            corpus.schema_version
        ));
    }
    if corpus.corpus_id.trim().is_empty() {
        errors.push("casefold corpus missing corpus_id".to_owned());
    }
    if !corpus.bead_id.starts_with("bd-") {
        errors.push(format!(
            "casefold corpus bead_id must look like bd-..., got `{}`",
            corpus.bead_id
        ));
    }
    if corpus.cases.is_empty() {
        errors.push("casefold corpus must declare at least one case".to_owned());
    }
}

fn validate_case(
    case: &CasefoldCase,
    ids: &mut BTreeSet<String>,
    operations: &mut BTreeSet<String>,
    outcomes: &mut BTreeSet<String>,
    kernel_compared_count: &mut usize,
    errors: &mut Vec<String>,
) {
    if !ids.insert(case.case_id.clone()) {
        errors.push(format!("duplicate casefold case_id `{}`", case.case_id));
    }
    if !case.case_id.starts_with("casefold_") {
        errors.push(format!(
            "case_id `{}` must start with casefold_",
            case.case_id
        ));
    }

    validate_case_inputs(case, errors);
    validate_case_classification(case, operations, outcomes, errors);
    validate_case_kernel(case, kernel_compared_count, errors);
    validate_case_feature_flags(case, errors);
    validate_case_envelope(case, errors);
    validate_case_invariants(case, errors);
}

fn validate_case_inputs(case: &CasefoldCase, errors: &mut Vec<String>) {
    if !is_lower_hex(&case.source_name_bytes_hex) {
        errors.push(format!(
            "case `{}` source_name_bytes_hex must be lowercase hex",
            case.case_id
        ));
    }
    if case.source_name_bytes_hex.is_empty() {
        errors.push(format!(
            "case `{}` source_name_bytes_hex must not be empty",
            case.case_id
        ));
    }
    let normalized_required = case.expected_outcome != "invalid_encoding_refused"
        && case.expected_outcome != "mount_feature_accepted";
    if normalized_required && !is_lower_hex(&case.normalized_form_bytes_hex) {
        errors.push(format!(
            "case `{}` normalized_form_bytes_hex must be lowercase hex",
            case.case_id
        ));
    }
    if !ALLOWED_NORMALIZED_CLASSES.contains(&case.normalized_class.as_str()) {
        errors.push(format!(
            "case `{}` has unsupported normalized_class `{}`",
            case.case_id, case.normalized_class
        ));
    }
    if case.normalized_class == "invalid_utf8"
        && case.expected_outcome != "invalid_encoding_refused"
    {
        errors.push(format!(
            "case `{}` invalid_utf8 normalized_class must expect invalid_encoding_refused",
            case.case_id
        ));
    }
    if case.normalized_class == "overlong_normalized_name"
        && case.normalized_form_bytes_hex.len() < 510
    {
        errors.push(format!(
            "case `{}` overlong_normalized_name must declare a normalized form longer than 255 bytes (510+ hex chars)",
            case.case_id
        ));
    }
}

fn validate_case_classification(
    case: &CasefoldCase,
    operations: &mut BTreeSet<String>,
    outcomes: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    if ALLOWED_OPERATION_KINDS.contains(&case.operation_kind.as_str()) {
        operations.insert(case.operation_kind.clone());
    } else {
        errors.push(format!(
            "case `{}` has unsupported operation_kind `{}`",
            case.case_id, case.operation_kind
        ));
    }
    if ALLOWED_OUTCOMES.contains(&case.expected_outcome.as_str()) {
        outcomes.insert(case.expected_outcome.clone());
    } else {
        errors.push(format!(
            "case `{}` has unsupported expected_outcome `{}`",
            case.case_id, case.expected_outcome
        ));
    }
    let must_match_op = match case.expected_outcome.as_str() {
        "lookup_hit" | "lookup_miss" => Some("lookup"),
        "create_success" | "create_collision_refused" => Some("create"),
        "rename_success" => Some("rename"),
        "mount_feature_accepted" => Some("mount_feature_check"),
        _ => None,
    };
    if let Some(expected_op) = must_match_op
        && case.operation_kind != expected_op
        && !(case.expected_outcome == "rename_success"
            && case.operation_kind == "cross_directory_rename")
    {
        errors.push(format!(
            "case `{}` outcome `{}` requires operation_kind `{}`",
            case.case_id, case.expected_outcome, expected_op
        ));
    }
    if case.expected_outcome == "rename_collision_refused"
        && case.operation_kind != "rename"
        && case.operation_kind != "cross_directory_rename"
    {
        errors.push(format!(
            "case `{}` rename_collision_refused requires rename or cross_directory_rename",
            case.case_id
        ));
    }
}

fn validate_case_kernel(
    case: &CasefoldCase,
    kernel_compared_count: &mut usize,
    errors: &mut Vec<String>,
) {
    if !ALLOWED_KERNEL_COMPARISON.contains(&case.kernel_comparison_status.as_str()) {
        errors.push(format!(
            "case `{}` has unsupported kernel_comparison_status `{}`",
            case.case_id, case.kernel_comparison_status
        ));
        return;
    }
    if case.kernel_comparison_status == "kernel_exact_match" {
        *kernel_compared_count += 1;
    }
    if case.kernel_comparison_status == "kernel_unsupported_submode"
        && case.unsupported_rationale.trim().is_empty()
    {
        errors.push(format!(
            "case `{}` kernel_unsupported_submode requires unsupported_rationale",
            case.case_id
        ));
    }
    if case.kernel_comparison_status != "kernel_unsupported_submode"
        && !case.unsupported_rationale.trim().is_empty()
    {
        errors.push(format!(
            "case `{}` non-unsupported kernel status must leave unsupported_rationale empty",
            case.case_id
        ));
    }
}

fn validate_case_feature_flags(case: &CasefoldCase, errors: &mut Vec<String>) {
    if case.feature_flags.is_empty() {
        errors.push(format!(
            "case `{}` must declare feature_flags",
            case.case_id
        ));
    }
    for required in REQUIRED_FEATURE_FLAGS {
        if !case.feature_flags.iter().any(|flag| flag == required) {
            errors.push(format!(
                "case `{}` feature_flags missing `{required}`",
                case.case_id
            ));
        }
    }
}

fn validate_case_envelope(case: &CasefoldCase, errors: &mut Vec<String>) {
    if !ALLOWED_CLEANUP_POLICIES.contains(&case.cleanup_policy.as_str()) {
        errors.push(format!(
            "case `{}` has unsupported cleanup_policy `{}`",
            case.case_id, case.cleanup_policy
        ));
    }
    for required in [
        "case_id",
        "source_name_bytes_hex",
        "normalized_form_bytes_hex",
        "expected_outcome",
        "kernel_comparison_status",
    ] {
        if !case
            .artifact_requirements
            .iter()
            .any(|requirement| requirement == required)
        {
            errors.push(format!(
                "case `{}` artifact_requirements missing `{required}`",
                case.case_id
            ));
        }
    }
}

fn validate_case_invariants(case: &CasefoldCase, errors: &mut Vec<String>) {
    if case.htree_interaction
        && !matches!(
            case.expected_outcome.as_str(),
            "lookup_hit" | "create_success" | "rename_success" | "create_collision_refused"
        )
    {
        errors.push(format!(
            "case `{}` htree_interaction can only annotate lookup/create/rename outcomes",
            case.case_id
        ));
    }
    if case.expected_outcome == "invalid_encoding_refused"
        && case.normalized_class != "invalid_utf8"
        && case.normalized_class != "overlong_normalized_name"
    {
        errors.push(format!(
            "case `{}` invalid_encoding_refused requires invalid_utf8 or overlong_normalized_name class",
            case.case_id
        ));
    }
    if case.expected_outcome == "mount_feature_accepted"
        && case.operation_kind != "mount_feature_check"
    {
        errors.push(format!(
            "case `{}` mount_feature_accepted requires mount_feature_check operation",
            case.case_id
        ));
    }
}

fn validate_operation_coverage(seen: &BTreeSet<String>, errors: &mut Vec<String>) {
    for required in REQUIRED_OPERATION_COVERAGE {
        if !seen.contains(required) {
            errors.push(format!(
                "casefold corpus missing required operation `{required}`"
            ));
        }
    }
}

fn validate_outcome_coverage(seen: &BTreeSet<String>, errors: &mut Vec<String>) {
    for required in REQUIRED_OUTCOME_COVERAGE {
        if !seen.contains(required) {
            errors.push(format!(
                "casefold corpus missing required outcome `{required}`"
            ));
        }
    }
}

fn is_lower_hex(value: &str) -> bool {
    !value.is_empty()
        && value.len() % 2 == 0
        && value
            .chars()
            .all(|ch| ch.is_ascii_digit() || ('a'..='f').contains(&ch))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_corpus() -> CasefoldCorpus {
        parse_casefold_corpus(DEFAULT_CASEFOLD_CORPUS_JSON).expect("default casefold corpus parses")
    }

    #[test]
    fn default_corpus_validates_required_coverage() {
        let report = validate_default_casefold_corpus().expect("default casefold corpus validates");
        assert_eq!(report.bead_id, "bd-9er6s");
        for op in REQUIRED_OPERATION_COVERAGE {
            assert!(
                report.operations_seen.iter().any(|o| o == op),
                "missing operation {op}"
            );
        }
        for outcome in REQUIRED_OUTCOME_COVERAGE {
            assert!(
                report.outcomes_seen.iter().any(|o| o == outcome),
                "missing outcome {outcome}"
            );
        }
    }

    #[test]
    fn missing_required_operation_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus
            .cases
            .retain(|c| c.operation_kind != "cross_directory_rename");
        let report = validate_casefold_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required operation `cross_directory_rename`"))
        );
    }

    #[test]
    fn missing_required_outcome_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus
            .cases
            .retain(|c| c.expected_outcome != "invalid_encoding_refused");
        let report = validate_casefold_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required outcome `invalid_encoding_refused`"))
        );
    }

    #[test]
    fn missing_collision_outcome_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus
            .cases
            .retain(|c| c.expected_outcome != "create_collision_refused");
        let report = validate_casefold_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required outcome `create_collision_refused`"))
        );
    }

    #[test]
    fn duplicate_case_id_is_rejected() {
        let mut corpus = fixture_corpus();
        let dup = corpus.cases[0].case_id.clone();
        corpus.cases[1].case_id = dup;
        let report = validate_casefold_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("duplicate casefold case_id"))
        );
    }

    #[test]
    fn case_id_prefix_is_enforced() {
        let mut corpus = fixture_corpus();
        corpus.cases[0].case_id = "fold_001".to_owned();
        let report = validate_casefold_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must start with casefold_"))
        );
    }

    #[test]
    fn malformed_source_hex_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases[0].source_name_bytes_hex = "not-hex".to_owned();
        let report = validate_casefold_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("source_name_bytes_hex must be lowercase hex"))
        );
    }

    #[test]
    fn empty_source_hex_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases[0].source_name_bytes_hex = String::new();
        let report = validate_casefold_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("source_name_bytes_hex must not be empty"))
        );
    }

    #[test]
    fn invalid_utf8_class_must_expect_refusal() {
        let mut corpus = fixture_corpus();
        let case = corpus
            .cases
            .iter_mut()
            .find(|c| c.normalized_class == "invalid_utf8")
            .expect("invalid_utf8 fixture exists");
        case.expected_outcome = "lookup_miss".to_owned();
        case.operation_kind = "lookup".to_owned();
        let report = validate_casefold_corpus(&corpus);
        assert!(report.errors.iter().any(|err| {
            err.contains("invalid_utf8 normalized_class must expect invalid_encoding_refused")
        }));
    }

    #[test]
    fn overlong_class_requires_long_normalized_form() {
        let mut corpus = fixture_corpus();
        let case = corpus
            .cases
            .iter_mut()
            .find(|c| c.normalized_class == "overlong_normalized_name")
            .expect("overlong fixture exists");
        case.normalized_form_bytes_hex = "1234".to_owned();
        let report = validate_casefold_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err.contains(
            "overlong_normalized_name must declare a normalized form longer than 255 bytes"
        )));
    }

    #[test]
    fn outcome_must_match_operation() {
        let mut corpus = fixture_corpus();
        let case = corpus
            .cases
            .iter_mut()
            .find(|c| c.expected_outcome == "lookup_hit")
            .expect("lookup_hit fixture exists");
        case.operation_kind = "create".to_owned();
        let report = validate_casefold_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("outcome `lookup_hit` requires operation_kind `lookup`"))
        );
    }

    #[test]
    fn unsupported_kernel_status_requires_rationale() {
        let mut corpus = fixture_corpus();
        let case = corpus
            .cases
            .iter_mut()
            .find(|c| c.kernel_comparison_status == "kernel_unsupported_submode")
            .expect("unsupported submode fixture exists");
        case.unsupported_rationale = String::new();
        let report = validate_casefold_corpus(&corpus);
        assert!(
            report.errors.iter().any(
                |err| err.contains("kernel_unsupported_submode requires unsupported_rationale")
            )
        );
    }

    #[test]
    fn non_unsupported_kernel_status_must_leave_rationale_empty() {
        let mut corpus = fixture_corpus();
        corpus.cases[0].unsupported_rationale = "non-empty".to_owned();
        let report = validate_casefold_corpus(&corpus);
        assert!(report.errors.iter().any(|err| {
            err.contains("non-unsupported kernel status must leave unsupported_rationale empty")
        }));
    }

    #[test]
    fn missing_required_feature_flag_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases[0]
            .feature_flags
            .retain(|flag| flag != "EXT4_FEATURE_INCOMPAT_CASEFOLD");
        let report = validate_casefold_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("feature_flags missing `EXT4_FEATURE_INCOMPAT_CASEFOLD`"))
        );
    }

    #[test]
    fn missing_artifact_requirement_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases[0]
            .artifact_requirements
            .retain(|r| r != "expected_outcome");
        let report = validate_casefold_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("artifact_requirements missing `expected_outcome`"))
        );
    }

    #[test]
    fn htree_interaction_only_on_supported_outcomes() {
        let mut corpus = fixture_corpus();
        let case = corpus
            .cases
            .iter_mut()
            .find(|c| c.expected_outcome == "invalid_encoding_refused")
            .expect("invalid_encoding fixture exists");
        case.htree_interaction = true;
        let report = validate_casefold_corpus(&corpus);
        assert!(report.errors.iter().any(|err| {
            err.contains("htree_interaction can only annotate lookup/create/rename outcomes")
        }));
    }

    #[test]
    fn invalid_encoding_outcome_requires_invalid_utf8_class() {
        let mut corpus = fixture_corpus();
        let case = corpus
            .cases
            .iter_mut()
            .find(|c| c.expected_outcome == "invalid_encoding_refused")
            .expect("invalid_encoding fixture exists");
        case.normalized_class = "ascii_lower".to_owned();
        let report = validate_casefold_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err.contains(
            "invalid_encoding_refused requires invalid_utf8 or overlong_normalized_name class"
        )));
    }

    #[test]
    fn mount_feature_outcome_requires_mount_check_operation() {
        let mut corpus = fixture_corpus();
        let case = corpus
            .cases
            .iter_mut()
            .find(|c| c.expected_outcome == "mount_feature_accepted")
            .expect("mount feature fixture exists");
        case.operation_kind = "lookup".to_owned();
        let report = validate_casefold_corpus(&corpus);
        assert!(report.errors.iter().any(|err| {
            err.contains("mount_feature_accepted requires mount_feature_check operation")
        }));
    }

    #[test]
    fn empty_cases_list_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases.clear();
        let report = validate_casefold_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("at least one case"))
        );
    }
}
