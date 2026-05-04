#![forbid(unsafe_code)]

//! Btrfs send/receive parity corpus and roundtrip oracle.
//!
//! Tracks bd-naww5: the historical lane closed parse-only with the export and
//! apply paths deferred. This corpus restores the missing planning so README,
//! FEATURE_PARITY, release gates, and proof bundles cannot imply full
//! send/receive parity from parse-only evidence. Each row binds source and
//! parent snapshot identities, expected stream hash, receive-target hash,
//! supported subset (parse_only / export_only / receive_only /
//! roundtrip_supported / unsupported), unsupported-record refusal class,
//! capability requirements, and chain-of-custody.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const BTRFS_SEND_RECEIVE_CORPUS_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_BTRFS_SEND_RECEIVE_CORPUS_PATH: &str =
    "tests/btrfs-send-receive-corpus/btrfs_send_receive_corpus.json";
const DEFAULT_BTRFS_SEND_RECEIVE_CORPUS_JSON: &str = include_str!(
    "../../../tests/btrfs-send-receive-corpus/btrfs_send_receive_corpus.json"
);

const ALLOWED_SUPPORTED_SUBSETS: [&str; 5] = [
    "parse_only",
    "export_only",
    "receive_only",
    "roundtrip_supported",
    "unsupported",
];

const ALLOWED_OUTCOMES: [&str; 7] = [
    "parse_success",
    "export_success",
    "receive_success",
    "roundtrip_success",
    "refused_unsupported_record",
    "refused_incremental_parent_mismatch",
    "refused_stream_hash_mismatch",
];

const ALLOWED_UNSUPPORTED_RECORDS: [&str; 6] = [
    "encoded_write",
    "fallocate_extent_v3",
    "raid_stripe_metadata",
    "compression_zstd_v2",
    "subvolume_uuid_collision",
    "post_v1_record_kind",
];

const ALLOWED_CAPABILITIES: [&str; 5] = [
    "deterministic_only",
    "permissioned_loop",
    "permissioned_btrfs_progs",
    "host_skip",
    "long_campaign",
];

const ALLOWED_CLEANUP_POLICIES: [&str; 3] = [
    "teardown_image_set",
    "preserve_artifacts_on_failure",
    "preserve_artifacts_always",
];

const REQUIRED_SUBSETS: [&str; 4] = [
    "parse_only",
    "export_only",
    "receive_only",
    "roundtrip_supported",
];

const REQUIRED_REFUSAL_KINDS: [&str; 2] = [
    "refused_unsupported_record",
    "refused_incremental_parent_mismatch",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsSendReceiveCorpus {
    pub schema_version: u32,
    pub corpus_id: String,
    pub bead_id: String,
    pub cases: Vec<BtrfsSendReceiveCase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsSendReceiveCase {
    pub case_id: String,
    pub supported_subset: String,
    pub source_snapshot: SnapshotRef,
    #[serde(default)]
    pub parent_snapshot: Option<SnapshotRef>,
    pub expected_stream_hash: String,
    pub expected_receive_target_hash: String,
    pub record_count: u32,
    pub expected_outcome: String,
    #[serde(default)]
    pub unsupported_record: String,
    pub capability_required: String,
    pub cleanup_policy: String,
    pub artifact_requirements: Vec<String>,
    pub chain_of_custody: SendCustody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRef {
    pub snapshot_id: String,
    pub uuid: String,
    pub parent_uuid: String,
    pub generation: u64,
    pub image_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendCustody {
    pub artifact_path: String,
    pub artifact_sha256: String,
    pub recorded_by: String,
    pub recorded_at_unix: u64,
    pub linked_bead: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsSendReceiveCorpusReport {
    pub schema_version: u32,
    pub corpus_id: String,
    pub bead_id: String,
    pub case_count: usize,
    pub supported_subsets: Vec<String>,
    pub refusal_kinds: Vec<String>,
    pub valid: bool,
    pub errors: Vec<String>,
}

pub fn parse_btrfs_send_receive_corpus(text: &str) -> Result<BtrfsSendReceiveCorpus> {
    serde_json::from_str(text).map_err(|err| {
        anyhow::anyhow!("failed to parse btrfs send/receive corpus JSON: {err}")
    })
}

pub fn validate_default_btrfs_send_receive_corpus() -> Result<BtrfsSendReceiveCorpusReport> {
    let corpus = parse_btrfs_send_receive_corpus(DEFAULT_BTRFS_SEND_RECEIVE_CORPUS_JSON)?;
    let report = validate_btrfs_send_receive_corpus(&corpus);
    if !report.valid {
        bail!(
            "btrfs send/receive corpus failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        );
    }
    Ok(report)
}

#[must_use]
pub fn validate_btrfs_send_receive_corpus(
    corpus: &BtrfsSendReceiveCorpus,
) -> BtrfsSendReceiveCorpusReport {
    let mut errors = Vec::new();
    let mut ids = BTreeSet::new();
    let mut subsets = BTreeSet::new();
    let mut refusal_kinds = BTreeSet::new();

    validate_corpus_top_level(corpus, &mut errors);
    for case in &corpus.cases {
        validate_case(case, &mut ids, &mut subsets, &mut refusal_kinds, &mut errors);
    }
    validate_required_subsets(&subsets, &mut errors);
    validate_required_refusals(&refusal_kinds, &mut errors);

    BtrfsSendReceiveCorpusReport {
        schema_version: corpus.schema_version,
        corpus_id: corpus.corpus_id.clone(),
        bead_id: corpus.bead_id.clone(),
        case_count: corpus.cases.len(),
        supported_subsets: subsets.into_iter().collect(),
        refusal_kinds: refusal_kinds.into_iter().collect(),
        valid: errors.is_empty(),
        errors,
    }
}

fn validate_corpus_top_level(
    corpus: &BtrfsSendReceiveCorpus,
    errors: &mut Vec<String>,
) {
    if corpus.schema_version != BTRFS_SEND_RECEIVE_CORPUS_SCHEMA_VERSION {
        errors.push(format!(
            "btrfs send/receive corpus schema_version must be {BTRFS_SEND_RECEIVE_CORPUS_SCHEMA_VERSION}, got {}",
            corpus.schema_version
        ));
    }
    if corpus.corpus_id.trim().is_empty() {
        errors.push("btrfs send/receive corpus missing corpus_id".to_owned());
    }
    if !corpus.bead_id.starts_with("bd-") {
        errors.push(format!(
            "btrfs send/receive corpus bead_id must look like bd-..., got `{}`",
            corpus.bead_id
        ));
    }
    if corpus.cases.is_empty() {
        errors.push("btrfs send/receive corpus must declare at least one case".to_owned());
    }
}

fn validate_case(
    case: &BtrfsSendReceiveCase,
    ids: &mut BTreeSet<String>,
    subsets: &mut BTreeSet<String>,
    refusal_kinds: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    if !ids.insert(case.case_id.clone()) {
        errors.push(format!(
            "duplicate btrfs send/receive case_id `{}`",
            case.case_id
        ));
    }
    if !case.case_id.starts_with("btrfs_send_recv_") {
        errors.push(format!(
            "case_id `{}` must start with btrfs_send_recv_",
            case.case_id
        ));
    }

    if ALLOWED_SUPPORTED_SUBSETS.contains(&case.supported_subset.as_str()) {
        subsets.insert(case.supported_subset.clone());
    } else {
        errors.push(format!(
            "case `{}` has unsupported supported_subset `{}`",
            case.case_id, case.supported_subset
        ));
    }

    validate_snapshots(case, errors);
    validate_stream_and_target_hashes(case, errors);
    validate_outcome(case, refusal_kinds, errors);
    validate_capability(case, errors);
    validate_envelope(case, errors);
    validate_chain_of_custody(case, errors);
}

fn validate_snapshots(case: &BtrfsSendReceiveCase, errors: &mut Vec<String>) {
    if case.source_snapshot.snapshot_id.trim().is_empty() {
        errors.push(format!(
            "case `{}` source_snapshot missing snapshot_id",
            case.case_id
        ));
    }
    if !is_uuid(&case.source_snapshot.uuid) {
        errors.push(format!(
            "case `{}` source_snapshot uuid must be a 36-char dashed UUID",
            case.case_id
        ));
    }
    if !is_valid_sha256(&case.source_snapshot.image_hash) {
        errors.push(format!(
            "case `{}` source_snapshot image_hash must be sha256:<64-hex>",
            case.case_id
        ));
    }
    if case.source_snapshot.generation == 0 {
        errors.push(format!(
            "case `{}` source_snapshot generation must be positive",
            case.case_id
        ));
    }

    if let Some(parent) = &case.parent_snapshot {
        if !is_uuid(&parent.uuid) {
            errors.push(format!(
                "case `{}` parent_snapshot uuid must be a 36-char dashed UUID",
                case.case_id
            ));
        }
        if !is_valid_sha256(&parent.image_hash) {
            errors.push(format!(
                "case `{}` parent_snapshot image_hash must be sha256:<64-hex>",
                case.case_id
            ));
        }
        if parent.generation >= case.source_snapshot.generation {
            errors.push(format!(
                "case `{}` parent_snapshot generation must be less than source generation",
                case.case_id
            ));
        }
        if parent.uuid == case.source_snapshot.uuid {
            errors.push(format!(
                "case `{}` parent and source uuids must differ",
                case.case_id
            ));
        }
    } else if case.expected_outcome == "refused_incremental_parent_mismatch" {
        errors.push(format!(
            "case `{}` incremental parent mismatch outcome requires a parent_snapshot",
            case.case_id
        ));
    }
}

fn validate_stream_and_target_hashes(
    case: &BtrfsSendReceiveCase,
    errors: &mut Vec<String>,
) {
    let stream_required = matches!(
        case.expected_outcome.as_str(),
        "parse_success" | "export_success" | "receive_success" | "roundtrip_success"
    );
    if stream_required && !is_valid_sha256(&case.expected_stream_hash) {
        errors.push(format!(
            "case `{}` expected_stream_hash must be sha256:<64-hex>",
            case.case_id
        ));
    }
    let target_required = matches!(
        case.expected_outcome.as_str(),
        "receive_success" | "roundtrip_success"
    );
    if target_required && !is_valid_sha256(&case.expected_receive_target_hash) {
        errors.push(format!(
            "case `{}` expected_receive_target_hash must be sha256:<64-hex>",
            case.case_id
        ));
    }
    if case.record_count == 0 && case.expected_outcome != "refused_unsupported_record" {
        errors.push(format!(
            "case `{}` record_count must be positive for non-refusal outcomes",
            case.case_id
        ));
    }
}

fn validate_outcome(
    case: &BtrfsSendReceiveCase,
    refusal_kinds: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    if !ALLOWED_OUTCOMES.contains(&case.expected_outcome.as_str()) {
        errors.push(format!(
            "case `{}` has unsupported expected_outcome `{}`",
            case.case_id, case.expected_outcome
        ));
    }
    if case.expected_outcome.starts_with("refused_") {
        refusal_kinds.insert(case.expected_outcome.clone());
    }
    let must_match_subset = match case.expected_outcome.as_str() {
        "parse_success" => Some("parse_only"),
        "export_success" => Some("export_only"),
        "receive_success" => Some("receive_only"),
        "roundtrip_success" => Some("roundtrip_supported"),
        _ => None,
    };
    if let Some(expected_subset) = must_match_subset
        && case.supported_subset != expected_subset
    {
        errors.push(format!(
            "case `{}` outcome `{}` requires supported_subset=`{}`",
            case.case_id, case.expected_outcome, expected_subset
        ));
    }
    if case.expected_outcome == "refused_unsupported_record" {
        if case.unsupported_record.trim().is_empty() {
            errors.push(format!(
                "case `{}` refused_unsupported_record must declare unsupported_record",
                case.case_id
            ));
        } else if !ALLOWED_UNSUPPORTED_RECORDS.contains(&case.unsupported_record.as_str()) {
            errors.push(format!(
                "case `{}` has unsupported unsupported_record `{}`",
                case.case_id, case.unsupported_record
            ));
        }
    } else if !case.unsupported_record.trim().is_empty() {
        errors.push(format!(
            "case `{}` non-unsupported-record outcome must leave unsupported_record empty",
            case.case_id
        ));
    }
}

fn validate_capability(case: &BtrfsSendReceiveCase, errors: &mut Vec<String>) {
    if !ALLOWED_CAPABILITIES.contains(&case.capability_required.as_str()) {
        errors.push(format!(
            "case `{}` has unsupported capability_required `{}`",
            case.case_id, case.capability_required
        ));
    }
}

fn validate_envelope(case: &BtrfsSendReceiveCase, errors: &mut Vec<String>) {
    if !ALLOWED_CLEANUP_POLICIES.contains(&case.cleanup_policy.as_str()) {
        errors.push(format!(
            "case `{}` has unsupported cleanup_policy `{}`",
            case.case_id, case.cleanup_policy
        ));
    }
    for required in [
        "case_id",
        "expected_stream_hash",
        "expected_receive_target_hash",
        "expected_outcome",
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

fn validate_chain_of_custody(case: &BtrfsSendReceiveCase, errors: &mut Vec<String>) {
    if case.chain_of_custody.artifact_path.trim().is_empty() {
        errors.push(format!(
            "case `{}` chain_of_custody missing artifact_path",
            case.case_id
        ));
    }
    if !is_valid_sha256(&case.chain_of_custody.artifact_sha256) {
        errors.push(format!(
            "case `{}` chain_of_custody artifact_sha256 must be sha256:<64-hex>",
            case.case_id
        ));
    }
    if case.chain_of_custody.recorded_by.trim().is_empty() {
        errors.push(format!(
            "case `{}` chain_of_custody missing recorded_by",
            case.case_id
        ));
    }
    if case.chain_of_custody.recorded_at_unix == 0 {
        errors.push(format!(
            "case `{}` chain_of_custody recorded_at_unix must be positive",
            case.case_id
        ));
    }
    if !case.chain_of_custody.linked_bead.starts_with("bd-") {
        errors.push(format!(
            "case `{}` chain_of_custody linked_bead must look like bd-...",
            case.case_id
        ));
    }
}

fn validate_required_subsets(seen: &BTreeSet<String>, errors: &mut Vec<String>) {
    for required in REQUIRED_SUBSETS {
        if !seen.contains(required) {
            errors.push(format!(
                "btrfs send/receive corpus missing required supported_subset `{required}`"
            ));
        }
    }
}

fn validate_required_refusals(seen: &BTreeSet<String>, errors: &mut Vec<String>) {
    for required in REQUIRED_REFUSAL_KINDS {
        if !seen.contains(required) {
            errors.push(format!(
                "btrfs send/receive corpus missing required refusal `{required}`"
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

fn is_uuid(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    let bytes = value.as_bytes();
    [8, 13, 18, 23]
        .iter()
        .all(|i| bytes[*i] == b'-')
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    *b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_corpus() -> BtrfsSendReceiveCorpus {
        parse_btrfs_send_receive_corpus(DEFAULT_BTRFS_SEND_RECEIVE_CORPUS_JSON)
            .expect("default btrfs send/receive corpus parses")
    }

    #[test]
    fn default_corpus_validates_required_subsets_and_refusals() {
        let report = validate_default_btrfs_send_receive_corpus()
            .expect("default btrfs send/receive corpus validates");
        assert_eq!(report.bead_id, "bd-naww5");
        for subset in REQUIRED_SUBSETS {
            assert!(
                report.supported_subsets.iter().any(|s| s == subset),
                "missing required subset {subset}"
            );
        }
        for refusal in REQUIRED_REFUSAL_KINDS {
            assert!(
                report.refusal_kinds.iter().any(|r| r == refusal),
                "missing required refusal {refusal}"
            );
        }
    }

    #[test]
    fn missing_required_subset_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus
            .cases
            .retain(|case| case.supported_subset != "roundtrip_supported");
        let report = validate_btrfs_send_receive_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required supported_subset `roundtrip_supported`"))
        );
    }

    #[test]
    fn missing_unsupported_record_refusal_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus
            .cases
            .retain(|case| case.expected_outcome != "refused_unsupported_record");
        let report = validate_btrfs_send_receive_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required refusal `refused_unsupported_record`"))
        );
    }

    #[test]
    fn missing_incremental_parent_refusal_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus
            .cases
            .retain(|case| case.expected_outcome != "refused_incremental_parent_mismatch");
        let report = validate_btrfs_send_receive_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err
            .contains("missing required refusal `refused_incremental_parent_mismatch`")));
    }

    #[test]
    fn duplicate_case_id_is_rejected() {
        let mut corpus = fixture_corpus();
        let dup = corpus.cases[0].case_id.clone();
        corpus.cases[1].case_id = dup;
        let report = validate_btrfs_send_receive_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("duplicate btrfs send/receive case_id"))
        );
    }

    #[test]
    fn case_id_prefix_is_enforced() {
        let mut corpus = fixture_corpus();
        corpus.cases[0].case_id = "stream_001".to_owned();
        let report = validate_btrfs_send_receive_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must start with btrfs_send_recv_"))
        );
    }

    #[test]
    fn outcome_must_match_subset() {
        let mut corpus = fixture_corpus();
        let case = corpus
            .cases
            .iter_mut()
            .find(|c| c.expected_outcome == "roundtrip_success")
            .expect("roundtrip fixture exists");
        case.supported_subset = "parse_only".to_owned();
        let report = validate_btrfs_send_receive_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err
            .contains("outcome `roundtrip_success` requires supported_subset=`roundtrip_supported`")));
    }

    #[test]
    fn malformed_uuid_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases[0].source_snapshot.uuid = "not-a-uuid".to_owned();
        let report = validate_btrfs_send_receive_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("source_snapshot uuid must be"))
        );
    }

    #[test]
    fn malformed_image_hash_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases[0].source_snapshot.image_hash = "md5:not-supported".to_owned();
        let report = validate_btrfs_send_receive_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("source_snapshot image_hash must be sha256"))
        );
    }

    #[test]
    fn parent_generation_must_be_lower_than_source() {
        let mut corpus = fixture_corpus();
        let case = corpus
            .cases
            .iter_mut()
            .find(|c| c.parent_snapshot.is_some())
            .expect("a fixture with parent exists");
        let source_gen = case.source_snapshot.generation;
        if let Some(parent) = case.parent_snapshot.as_mut() {
            parent.generation = source_gen + 1;
        }
        let report = validate_btrfs_send_receive_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err
            .contains("parent_snapshot generation must be less than source generation")));
    }

    #[test]
    fn parent_uuid_must_differ_from_source() {
        let mut corpus = fixture_corpus();
        let case = corpus
            .cases
            .iter_mut()
            .find(|c| c.parent_snapshot.is_some())
            .expect("parent fixture exists");
        let source_uuid = case.source_snapshot.uuid.clone();
        if let Some(parent) = case.parent_snapshot.as_mut() {
            parent.uuid = source_uuid;
        }
        let report = validate_btrfs_send_receive_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("parent and source uuids must differ"))
        );
    }

    #[test]
    fn unsupported_record_outcome_requires_record_kind() {
        let mut corpus = fixture_corpus();
        let case = corpus
            .cases
            .iter_mut()
            .find(|c| c.expected_outcome == "refused_unsupported_record")
            .expect("refused_unsupported_record fixture exists");
        case.unsupported_record = String::new();
        let report = validate_btrfs_send_receive_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err
            .contains("refused_unsupported_record must declare unsupported_record")));
    }

    #[test]
    fn unsupported_record_outcome_rejects_unknown_kind() {
        let mut corpus = fixture_corpus();
        let case = corpus
            .cases
            .iter_mut()
            .find(|c| c.expected_outcome == "refused_unsupported_record")
            .expect("refused_unsupported_record fixture exists");
        case.unsupported_record = "telepathy_record".to_owned();
        let report = validate_btrfs_send_receive_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported unsupported_record"))
        );
    }

    #[test]
    fn non_unsupported_record_outcome_must_leave_record_empty() {
        let mut corpus = fixture_corpus();
        corpus.cases[0].unsupported_record = "encoded_write".to_owned();
        let report = validate_btrfs_send_receive_corpus(&corpus);
        assert!(report.errors.iter().any(|err| err
            .contains("non-unsupported-record outcome must leave unsupported_record empty")));
    }

    #[test]
    fn unsupported_capability_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases[0].capability_required = "telepathy".to_owned();
        let report = validate_btrfs_send_receive_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported capability_required"))
        );
    }

    #[test]
    fn missing_artifact_requirement_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases[0]
            .artifact_requirements
            .retain(|r| r != "expected_stream_hash");
        let report = validate_btrfs_send_receive_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("artifact_requirements missing `expected_stream_hash`"))
        );
    }

    #[test]
    fn malformed_chain_of_custody_hash_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases[0].chain_of_custody.artifact_sha256 = "deadbeef".to_owned();
        let report = validate_btrfs_send_receive_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("artifact_sha256 must be sha256"))
        );
    }

    #[test]
    fn empty_cases_list_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.cases.clear();
        let report = validate_btrfs_send_receive_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("at least one case"))
        );
    }
}
