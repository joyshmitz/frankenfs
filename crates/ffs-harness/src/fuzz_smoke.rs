#![forbid(unsafe_code)]

//! Deterministic fuzz-smoke manifest validation for high-risk parser surfaces.

use crate::repair_corpus::{parse_repair_corpus, validate_repair_corpus};
use anyhow::{bail, Context, Result};
use ffs_ondisk::{
    parse_dir_block, parse_extent_tree, parse_leaf_items, parse_sys_chunk_array, BtrfsSuperblock,
    Ext4GroupDesc, Ext4Inode, Ext4Superblock,
};
use ffs_types::ParseError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::time::{Duration, Instant};

pub const FUZZ_SMOKE_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_FUZZ_SMOKE_MANIFEST_PATH: &str = "tests/fuzz-smoke/fuzz_smoke_manifest.json";
const DEFAULT_FUZZ_SMOKE_MANIFEST_JSON: &str =
    include_str!("../../../tests/fuzz-smoke/fuzz_smoke_manifest.json");

const REQUIRED_ARTIFACT_FIELDS: [&str; 8] = [
    "command_line",
    "seed_ids",
    "corpus_checksum",
    "duration_ms",
    "stdout_path",
    "stderr_path",
    "cleanup_status",
    "report_json",
];

const SHA256_PREFIX: &str = "sha256:";

const ALLOWED_TARGETS: [&str; 9] = [
    "ext4_superblock",
    "ext4_group_desc_32",
    "ext4_inode",
    "ext4_extent_tree",
    "ext4_dir_block",
    "btrfs_superblock",
    "btrfs_sys_chunk_array",
    "btrfs_leaf_items",
    "repair_corpus_manifest",
];

const ALLOWED_EXPECTED_CLASSES: [&str; 10] = [
    "accepted",
    "InsufficientData",
    "InvalidMagic",
    "InvalidField",
    "IntegerConversion",
    "RepairCorpusInvalid",
    "Utf8Error",
    "panic",
    "timeout",
    "resource_cap",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzSmokeManifest {
    pub schema_version: u32,
    pub corpus_id: String,
    pub bead_id: String,
    pub corpus_version: String,
    pub default_timeout_ms: u64,
    pub artifact_contract: Vec<String>,
    pub seeds: Vec<FuzzSmokeSeed>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzSmokeSeed {
    pub seed_id: String,
    pub path: String,
    pub source: String,
    pub provenance: String,
    pub target: String,
    pub expected_class: String,
    #[serde(default)]
    pub expected_error_contains: Option<String>,
    pub corpus_checksum: String,
    pub timeout_ms: u64,
    pub resource_budget: FuzzSmokeResourceBudget,
    pub minimization: FuzzSmokeMinimization,
    pub quarantine: FuzzSmokeQuarantine,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzSmokeResourceBudget {
    pub max_input_bytes: usize,
    pub max_duration_ms: u64,
    pub max_artifact_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzSmokeMinimization {
    pub status: String,
    pub replay_command: String,
    #[serde(default)]
    pub follow_up_bead: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzSmokeQuarantine {
    pub status: String,
    #[serde(default)]
    pub quarantine_id: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub owning_bead: Option<String>,
    #[serde(default)]
    pub rationale: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzSmokeReport {
    pub schema_version: u32,
    pub corpus_id: String,
    pub bead_id: String,
    pub corpus_version: String,
    pub command_line: String,
    pub seed_count: usize,
    pub seed_ids: Vec<String>,
    pub corpus_checksum: String,
    pub duration_ms: u64,
    pub target_summary: BTreeMap<String, usize>,
    pub outcome_summary: BTreeMap<String, usize>,
    pub minimization_summary: BTreeMap<String, usize>,
    pub quarantine_summary: BTreeMap<String, usize>,
    pub artifact_contract: Vec<String>,
    pub seed_results: Vec<FuzzSmokeSeedResult>,
    pub valid: bool,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the QA JSON schema exposes independent verdict bits for downstream artifact validators"
)]
pub struct FuzzSmokeSeedResult {
    pub seed_id: String,
    pub path: String,
    pub source: String,
    pub provenance: String,
    pub target: String,
    pub expected_class: String,
    pub actual_class: String,
    pub expected_error_contains: Option<String>,
    pub error_detail: String,
    pub class_matched: bool,
    pub error_detail_matched: bool,
    pub corpus_checksum: String,
    pub observed_checksum: String,
    pub corpus_checksum_matched: bool,
    pub timed_out: bool,
    pub duration_ms: u64,
    pub byte_len: usize,
    pub sha256: String,
    pub resource_budget: FuzzSmokeResourceBudget,
    pub minimization_status: String,
    pub replay_command: String,
    pub follow_up_bead: Option<String>,
    pub quarantine_status: String,
    pub quarantine_id: Option<String>,
    pub quarantine_owner: Option<String>,
    pub quarantine_expires_at: Option<String>,
    pub quarantine_owning_bead: Option<String>,
    pub artifact_paths: Vec<String>,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TargetExecution {
    actual_class: String,
    error_detail: String,
}

#[derive(Debug)]
enum TargetFailure {
    Parse(ParseError),
    RepairCorpusInvalid(String),
    Utf8(std::str::Utf8Error),
}

pub fn parse_fuzz_smoke_manifest(text: &str) -> Result<FuzzSmokeManifest> {
    serde_json::from_str(text)
        .map_err(|err| anyhow::anyhow!("failed to parse fuzz-smoke manifest JSON: {err}"))
}

pub fn load_fuzz_smoke_manifest(path: &Path) -> Result<FuzzSmokeManifest> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read fuzz-smoke manifest {}", path.display()))?;
    parse_fuzz_smoke_manifest(&text)
}

pub fn load_default_fuzz_smoke_manifest() -> Result<FuzzSmokeManifest> {
    parse_fuzz_smoke_manifest(DEFAULT_FUZZ_SMOKE_MANIFEST_JSON)
}

#[must_use]
pub fn validate_fuzz_smoke_manifest(manifest: &FuzzSmokeManifest) -> Vec<String> {
    let mut errors = Vec::new();

    if manifest.schema_version != FUZZ_SMOKE_SCHEMA_VERSION {
        errors.push(format!(
            "fuzz-smoke schema_version must be {FUZZ_SMOKE_SCHEMA_VERSION}, got {}",
            manifest.schema_version
        ));
    }
    if manifest.corpus_id.trim().is_empty() {
        errors.push("fuzz-smoke manifest missing corpus_id".to_owned());
    }
    if !manifest.bead_id.starts_with("bd-") {
        errors.push(format!(
            "fuzz-smoke bead_id must look like bd-..., got `{}`",
            manifest.bead_id
        ));
    }
    if manifest.corpus_version.trim().is_empty() {
        errors.push("fuzz-smoke manifest missing corpus_version".to_owned());
    }
    if manifest.default_timeout_ms == 0 {
        errors.push("fuzz-smoke default_timeout_ms must be positive".to_owned());
    }
    validate_artifact_contract(&manifest.artifact_contract, &mut errors);
    validate_seeds(&manifest.seeds, &mut errors);

    errors
}

#[must_use]
pub fn run_fuzz_smoke_manifest(
    manifest: &FuzzSmokeManifest,
    workspace_root: &Path,
) -> FuzzSmokeReport {
    let started = Instant::now();
    let mut errors = validate_fuzz_smoke_manifest(manifest);
    let mut seed_results = Vec::new();
    let mut hasher = Sha256::new();

    hasher.update(manifest.corpus_id.as_bytes());
    hasher.update([0]);
    hasher.update(manifest.corpus_version.as_bytes());
    hasher.update([0]);

    if errors.is_empty() {
        for seed in &manifest.seeds {
            let result = run_seed(seed, manifest.default_timeout_ms, workspace_root);
            update_corpus_checksum(&mut hasher, &result);
            if !result.class_matched {
                errors.push(format!(
                    "seed `{}` expected class `{}` but got `{}`",
                    result.seed_id, result.expected_class, result.actual_class
                ));
            }
            if !result.error_detail_matched {
                let expected = result
                    .expected_error_contains
                    .as_deref()
                    .unwrap_or_default();
                errors.push(format!(
                    "seed `{}` expected error detail containing `{expected}` but got `{}`",
                    result.seed_id, result.error_detail
                ));
            }
            if !result.corpus_checksum_matched {
                errors.push(format!(
                    "seed `{}` corpus_checksum drifted: manifest `{}` observed `{}`",
                    result.seed_id, result.corpus_checksum, result.observed_checksum
                ));
            }
            if result.requires_failure_owner()
                && result.follow_up_bead.is_none()
                && result.quarantine_owning_bead.is_none()
                && result.replay_command.trim().is_empty()
            {
                errors.push(format!(
                    "seed `{}` failure needs replay_command, follow_up_bead, or quarantine owning_bead",
                    result.seed_id
                ));
            }
            seed_results.push(result);
        }
    }

    let seed_ids = manifest
        .seeds
        .iter()
        .map(|seed| seed.seed_id.clone())
        .collect::<Vec<_>>();
    let target_summary = summarize_targets(&manifest.seeds);
    let outcome_summary = summarize_outcomes(&seed_results);
    let minimization_summary = summarize_minimization(&manifest.seeds);
    let quarantine_summary = summarize_quarantine(&manifest.seeds);
    let corpus_checksum = format!("sha256:{}", hex::encode(hasher.finalize()));

    FuzzSmokeReport {
        schema_version: manifest.schema_version,
        corpus_id: manifest.corpus_id.clone(),
        bead_id: manifest.bead_id.clone(),
        corpus_version: manifest.corpus_version.clone(),
        command_line: std::env::args().collect::<Vec<_>>().join(" "),
        seed_count: manifest.seeds.len(),
        seed_ids,
        corpus_checksum,
        duration_ms: duration_ms(started.elapsed()),
        target_summary,
        outcome_summary,
        minimization_summary,
        quarantine_summary,
        artifact_contract: manifest.artifact_contract.clone(),
        seed_results,
        valid: errors.is_empty(),
        errors,
    }
}

pub fn fail_on_fuzz_smoke_errors(report: &FuzzSmokeReport) -> Result<()> {
    if !report.valid {
        bail!(
            "fuzz-smoke validation failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        );
    }
    Ok(())
}

fn validate_artifact_contract(artifact_contract: &[String], errors: &mut Vec<String>) {
    let declared = artifact_contract
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for required in REQUIRED_ARTIFACT_FIELDS {
        if !declared.contains(required) {
            errors.push(format!(
                "fuzz-smoke artifact_contract missing required field `{required}`"
            ));
        }
    }
}

fn validate_seeds(seeds: &[FuzzSmokeSeed], errors: &mut Vec<String>) {
    if seeds.is_empty() {
        errors.push("fuzz-smoke manifest must declare at least one seed".to_owned());
        return;
    }

    let mut ids = BTreeSet::new();
    for seed in seeds {
        if seed.seed_id.trim().is_empty() {
            errors.push("fuzz-smoke seed has empty seed_id".to_owned());
        } else if !ids.insert(seed.seed_id.as_str()) {
            errors.push(format!("duplicate fuzz-smoke seed_id `{}`", seed.seed_id));
        }
        if seed.path.trim().is_empty() {
            errors.push(format!("fuzz-smoke seed `{}` missing path", seed.seed_id));
        }
        if Path::new(&seed.path).is_absolute() {
            errors.push(format!(
                "fuzz-smoke seed `{}` path must be workspace-relative",
                seed.seed_id
            ));
        }
        if seed.source.trim().is_empty() {
            errors.push(format!("fuzz-smoke seed `{}` missing source", seed.seed_id));
        }
        if seed.provenance.trim().is_empty() {
            errors.push(format!(
                "fuzz-smoke seed `{}` missing provenance",
                seed.seed_id
            ));
        }
        if !ALLOWED_TARGETS.contains(&seed.target.as_str()) {
            errors.push(format!(
                "fuzz-smoke seed `{}` uses unsupported target `{}`",
                seed.seed_id, seed.target
            ));
        }
        if !ALLOWED_EXPECTED_CLASSES.contains(&seed.expected_class.as_str()) {
            errors.push(format!(
                "fuzz-smoke seed `{}` uses unsupported expected_class `{}`",
                seed.seed_id, seed.expected_class
            ));
        }
        if seed.expected_class == "accepted" && seed.expected_error_contains.is_some() {
            errors.push(format!(
                "fuzz-smoke seed `{}` cannot require error text for accepted output",
                seed.seed_id
            ));
        }
        if !is_sha256_digest(&seed.corpus_checksum) {
            errors.push(format!(
                "fuzz-smoke seed `{}` corpus_checksum must be sha256:<64 hex chars>",
                seed.seed_id
            ));
        }
        if seed.timeout_ms == 0 {
            errors.push(format!(
                "fuzz-smoke seed `{}` timeout_ms must be positive",
                seed.seed_id
            ));
        }
        validate_resource_budget(seed, errors);
        validate_minimization(seed, errors);
        validate_quarantine(seed, errors);
    }
}

fn validate_resource_budget(seed: &FuzzSmokeSeed, errors: &mut Vec<String>) {
    if seed.resource_budget.max_input_bytes == 0 {
        errors.push(format!(
            "fuzz-smoke seed `{}` resource_budget.max_input_bytes must be positive",
            seed.seed_id
        ));
    }
    if seed.resource_budget.max_duration_ms == 0 {
        errors.push(format!(
            "fuzz-smoke seed `{}` resource_budget.max_duration_ms must be positive",
            seed.seed_id
        ));
    }
    if seed.resource_budget.max_artifact_bytes == 0 {
        errors.push(format!(
            "fuzz-smoke seed `{}` resource_budget.max_artifact_bytes must be positive",
            seed.seed_id
        ));
    }
    if seed.timeout_ms > seed.resource_budget.max_duration_ms {
        errors.push(format!(
            "fuzz-smoke seed `{}` timeout_ms must not exceed resource_budget.max_duration_ms",
            seed.seed_id
        ));
    }
}

fn validate_minimization(seed: &FuzzSmokeSeed, errors: &mut Vec<String>) {
    match seed.minimization.status.as_str() {
        "minimized" => {
            if seed.minimization.replay_command.trim().is_empty() {
                errors.push(format!(
                    "fuzz-smoke seed `{}` minimized seeds require replay_command",
                    seed.seed_id
                ));
            }
        }
        "not_minimized" => {
            if seed
                .minimization
                .follow_up_bead
                .as_deref()
                .is_none_or(|bead| !bead.starts_with("bd-"))
            {
                errors.push(format!(
                    "fuzz-smoke seed `{}` non-minimized seeds require follow_up_bead",
                    seed.seed_id
                ));
            }
        }
        "not_applicable" => {}
        other => errors.push(format!(
            "fuzz-smoke seed `{}` uses unsupported minimization status `{other}`",
            seed.seed_id
        )),
    }
}

fn validate_quarantine(seed: &FuzzSmokeSeed, errors: &mut Vec<String>) {
    match seed.quarantine.status.as_str() {
        "none" => {}
        "active" => {
            for (field, value) in [
                ("quarantine_id", seed.quarantine.quarantine_id.as_deref()),
                ("owner", seed.quarantine.owner.as_deref()),
                ("expires_at", seed.quarantine.expires_at.as_deref()),
                ("owning_bead", seed.quarantine.owning_bead.as_deref()),
                ("rationale", seed.quarantine.rationale.as_deref()),
            ] {
                if value.is_none_or(str::is_empty) {
                    errors.push(format!(
                        "fuzz-smoke seed `{}` active quarantine missing {field}",
                        seed.seed_id
                    ));
                }
            }
            if seed
                .quarantine
                .owning_bead
                .as_deref()
                .is_some_and(|bead| !bead.starts_with("bd-"))
            {
                errors.push(format!(
                    "fuzz-smoke seed `{}` quarantine owning_bead must look like bd-...",
                    seed.seed_id
                ));
            }
        }
        "expired" => errors.push(format!(
            "fuzz-smoke seed `{}` quarantine has expired and cannot count as healthy",
            seed.seed_id
        )),
        other => errors.push(format!(
            "fuzz-smoke seed `{}` uses unsupported quarantine status `{other}`",
            seed.seed_id
        )),
    }
}

fn run_seed(
    seed: &FuzzSmokeSeed,
    default_timeout_ms: u64,
    workspace_root: &Path,
) -> FuzzSmokeSeedResult {
    let started = Instant::now();
    let seed_path = workspace_root.join(&seed.path);
    let (bytes, read_error) = match fs::read(&seed_path) {
        Ok(bytes) => (bytes, None),
        Err(err) => (
            Vec::new(),
            Some(format!("failed to read {}: {err}", seed_path.display())),
        ),
    };

    let mut execution = read_error.map_or_else(
        || {
            if bytes.len() > seed.resource_budget.max_input_bytes {
                TargetExecution {
                    actual_class: "resource_cap".to_owned(),
                    error_detail: format!(
                        "seed input {} bytes exceeded max_input_bytes {}",
                        bytes.len(),
                        seed.resource_budget.max_input_bytes
                    ),
                }
            } else {
                execute_target(&seed.target, &bytes)
            }
        },
        |error| TargetExecution {
            actual_class: "SeedReadError".to_owned(),
            error_detail: error,
        },
    );

    let duration = started.elapsed();
    let timeout_ms = if seed.timeout_ms == 0 {
        default_timeout_ms
    } else {
        seed.timeout_ms
    };
    let timed_out = timed_out(duration, timeout_ms);
    if timed_out {
        "timeout".clone_into(&mut execution.actual_class);
        execution.error_detail = format!(
            "seed runtime {}ms exceeded timeout {timeout_ms}ms",
            duration_ms(duration)
        );
    }

    let error_detail_matched = seed
        .expected_error_contains
        .as_deref()
        .is_none_or(|needle| execution.error_detail.contains(needle));
    let observed_checksum = sha256_hex(&bytes);
    let corpus_checksum_matched = seed.corpus_checksum == observed_checksum;

    FuzzSmokeSeedResult {
        seed_id: seed.seed_id.clone(),
        path: seed.path.clone(),
        source: seed.source.clone(),
        provenance: seed.provenance.clone(),
        target: seed.target.clone(),
        expected_class: seed.expected_class.clone(),
        actual_class: execution.actual_class.clone(),
        expected_error_contains: seed.expected_error_contains.clone(),
        error_detail: execution.error_detail,
        class_matched: seed.expected_class == execution.actual_class,
        error_detail_matched,
        corpus_checksum: seed.corpus_checksum.clone(),
        observed_checksum: observed_checksum.clone(),
        corpus_checksum_matched,
        timed_out,
        duration_ms: duration_ms(duration),
        byte_len: bytes.len(),
        sha256: observed_checksum,
        resource_budget: seed.resource_budget.clone(),
        minimization_status: seed.minimization.status.clone(),
        replay_command: seed.minimization.replay_command.clone(),
        follow_up_bead: seed.minimization.follow_up_bead.clone(),
        quarantine_status: seed.quarantine.status.clone(),
        quarantine_id: seed.quarantine.quarantine_id.clone(),
        quarantine_owner: seed.quarantine.owner.clone(),
        quarantine_expires_at: seed.quarantine.expires_at.clone(),
        quarantine_owning_bead: seed.quarantine.owning_bead.clone(),
        artifact_paths: vec![seed.path.clone()],
        reproduction_command: seed.minimization.replay_command.clone(),
    }
}

fn execute_target(target: &str, bytes: &[u8]) -> TargetExecution {
    classify_execution(|| match target {
        "ext4_superblock" => Ext4Superblock::parse_superblock_region(bytes)
            .map(|_| ())
            .map_err(TargetFailure::Parse),
        "ext4_group_desc_32" => Ext4GroupDesc::parse_from_bytes(bytes, 32)
            .map(|_| ())
            .map_err(TargetFailure::Parse),
        "ext4_inode" => Ext4Inode::parse_from_bytes(bytes)
            .map(|_| ())
            .map_err(TargetFailure::Parse),
        "ext4_extent_tree" => parse_extent_tree(bytes)
            .map(|_| ())
            .map_err(TargetFailure::Parse),
        "ext4_dir_block" => parse_dir_block(bytes, 4096)
            .map(|_| ())
            .map_err(TargetFailure::Parse),
        "btrfs_superblock" => BtrfsSuperblock::parse_superblock_region(bytes)
            .map(|_| ())
            .map_err(TargetFailure::Parse),
        "btrfs_sys_chunk_array" => parse_sys_chunk_array(bytes)
            .map(|_| ())
            .map_err(TargetFailure::Parse),
        "btrfs_leaf_items" => parse_leaf_items(bytes)
            .map(|_| ())
            .map_err(TargetFailure::Parse),
        "repair_corpus_manifest" => validate_repair_manifest_bytes(bytes),
        _ => Ok(()),
    })
}

fn classify_execution<F>(operation: F) -> TargetExecution
where
    F: FnOnce() -> Result<(), TargetFailure>,
{
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(())) => TargetExecution {
            actual_class: "accepted".to_owned(),
            error_detail: String::new(),
        },
        Ok(Err(failure)) => TargetExecution {
            actual_class: failure.class().to_owned(),
            error_detail: failure.detail(),
        },
        Err(payload) => TargetExecution {
            actual_class: "panic".to_owned(),
            error_detail: panic_payload_message(payload.as_ref()),
        },
    }
}

fn validate_repair_manifest_bytes(bytes: &[u8]) -> Result<(), TargetFailure> {
    let text = std::str::from_utf8(bytes).map_err(TargetFailure::Utf8)?;
    let corpus = parse_repair_corpus(text).map_err(|err| {
        TargetFailure::RepairCorpusInvalid(format!("repair corpus JSON decode failed: {err}"))
    })?;
    let report = validate_repair_corpus(&corpus);
    if report.valid {
        Ok(())
    } else {
        Err(TargetFailure::RepairCorpusInvalid(report.errors.join("; ")))
    }
}

impl TargetFailure {
    fn class(&self) -> &'static str {
        match self {
            Self::Parse(err) => parse_error_class(err),
            Self::RepairCorpusInvalid(_) => "RepairCorpusInvalid",
            Self::Utf8(_) => "Utf8Error",
        }
    }

    fn detail(&self) -> String {
        match self {
            Self::Parse(err) => err.to_string(),
            Self::RepairCorpusInvalid(detail) => detail.clone(),
            Self::Utf8(err) => err.to_string(),
        }
    }
}

fn parse_error_class(err: &ParseError) -> &'static str {
    match err {
        ParseError::InsufficientData { .. } => "InsufficientData",
        ParseError::InvalidMagic { .. } => "InvalidMagic",
        ParseError::InvalidField { .. } => "InvalidField",
        ParseError::IntegerConversion { .. } => "IntegerConversion",
    }
}

fn update_corpus_checksum(hasher: &mut Sha256, result: &FuzzSmokeSeedResult) {
    for part in [
        result.seed_id.as_str(),
        result.path.as_str(),
        result.target.as_str(),
        result.sha256.as_str(),
    ] {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
}

fn summarize_targets(seeds: &[FuzzSmokeSeed]) -> BTreeMap<String, usize> {
    let mut summary = BTreeMap::new();
    for seed in seeds {
        *summary.entry(seed.target.clone()).or_insert(0) += 1;
    }
    summary
}

fn summarize_outcomes(results: &[FuzzSmokeSeedResult]) -> BTreeMap<String, usize> {
    let mut summary = BTreeMap::new();
    for result in results {
        *summary.entry(result.actual_class.clone()).or_insert(0) += 1;
    }
    summary
}

fn summarize_minimization(seeds: &[FuzzSmokeSeed]) -> BTreeMap<String, usize> {
    let mut summary = BTreeMap::new();
    for seed in seeds {
        *summary.entry(seed.minimization.status.clone()).or_insert(0) += 1;
    }
    summary
}

fn summarize_quarantine(seeds: &[FuzzSmokeSeed]) -> BTreeMap<String, usize> {
    let mut summary = BTreeMap::new();
    for seed in seeds {
        *summary.entry(seed.quarantine.status.clone()).or_insert(0) += 1;
    }
    summary
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn is_sha256_digest(value: &str) -> bool {
    value
        .strip_prefix(SHA256_PREFIX)
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn timed_out(duration: Duration, timeout_ms: u64) -> bool {
    duration_ms(duration) > timeout_ms
}

fn panic_payload_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload.downcast_ref::<&'static str>().map_or_else(
        || {
            payload.downcast_ref::<String>().map_or_else(
                || "non-string panic payload".to_owned(),
                std::clone::Clone::clone,
            )
        },
        |message| (*message).to_owned(),
    )
}

impl FuzzSmokeSeedResult {
    fn requires_failure_owner(&self) -> bool {
        !self.class_matched
            || !self.error_detail_matched
            || !self.corpus_checksum_matched
            || self.timed_out
            || matches!(self.actual_class.as_str(), "resource_cap" | "panic")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn default_manifest_validates_and_runs() {
        let manifest = load_default_fuzz_smoke_manifest().expect("default manifest parses");
        let manifest_errors = validate_fuzz_smoke_manifest(&manifest);
        assert!(manifest_errors.is_empty(), "{manifest_errors:?}");

        let report = run_fuzz_smoke_manifest(&manifest, &workspace_root());
        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.seed_count, manifest.seeds.len());
        assert_eq!(report.seed_ids.len(), manifest.seeds.len());
        assert!(report.corpus_checksum.starts_with("sha256:"));
        assert_eq!(
            report.minimization_summary.get("minimized"),
            Some(&manifest.seeds.len())
        );
        assert_eq!(
            report.quarantine_summary.get("none"),
            Some(&manifest.seeds.len())
        );
        assert!(report.seed_results.iter().all(|result| {
            !result.provenance.is_empty()
                && result.corpus_checksum_matched
                && result.minimization_status == "minimized"
                && result.quarantine_status == "none"
                && !result.reproduction_command.is_empty()
        }));
    }

    #[test]
    fn duplicate_seed_ids_are_rejected() {
        let mut manifest = load_default_fuzz_smoke_manifest().expect("default manifest parses");
        let duplicate_id = manifest.seeds[0].seed_id.clone();
        manifest.seeds[1].seed_id = duplicate_id;

        let errors = validate_fuzz_smoke_manifest(&manifest);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("duplicate fuzz-smoke seed_id")),
            "{errors:?}"
        );
    }

    #[test]
    fn unsupported_targets_are_rejected() {
        let mut manifest = load_default_fuzz_smoke_manifest().expect("default manifest parses");
        manifest.seeds[0].target = "unknown_parser".to_owned();

        let errors = validate_fuzz_smoke_manifest(&manifest);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("unsupported target")),
            "{errors:?}"
        );
    }

    #[test]
    fn missing_artifact_contract_fields_are_rejected() {
        let mut manifest = load_default_fuzz_smoke_manifest().expect("default manifest parses");
        manifest
            .artifact_contract
            .retain(|field| field != "stdout_path");

        let errors = validate_fuzz_smoke_manifest(&manifest);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("artifact_contract missing required field")),
            "{errors:?}"
        );
    }

    #[test]
    fn missing_required_seed_schema_fields_are_rejected() {
        let mut value: serde_json::Value =
            serde_json::from_str(DEFAULT_FUZZ_SMOKE_MANIFEST_JSON).expect("manifest JSON parses");
        value["seeds"][0]
            .as_object_mut()
            .expect("seed is object")
            .remove("source");

        let text = serde_json::to_string(&value).expect("manifest serializes");
        let error = parse_fuzz_smoke_manifest(&text).expect_err("source is required");
        assert!(error.to_string().contains("missing field `source`"));
    }

    #[test]
    fn missing_provenance_is_rejected() {
        let mut manifest = load_default_fuzz_smoke_manifest().expect("default manifest parses");
        manifest.seeds[0].provenance.clear();

        let errors = validate_fuzz_smoke_manifest(&manifest);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("missing provenance")),
            "{errors:?}"
        );
    }

    #[test]
    fn stale_corpus_checksum_invalidates_report() {
        let mut manifest = load_default_fuzz_smoke_manifest().expect("default manifest parses");
        manifest.seeds[0].corpus_checksum =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned();

        let report = run_fuzz_smoke_manifest(&manifest, &workspace_root());
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("corpus_checksum drifted")),
            "{:?}",
            report.errors
        );
    }

    #[test]
    fn resource_cap_classification_is_fail_closed() {
        let mut manifest = load_default_fuzz_smoke_manifest().expect("default manifest parses");
        manifest.seeds[0].expected_class = "resource_cap".to_owned();
        manifest.seeds[0].expected_error_contains = Some("exceeded max_input_bytes".to_owned());
        manifest.seeds[0].resource_budget.max_input_bytes = 1;

        let report = run_fuzz_smoke_manifest(&manifest, &workspace_root());
        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.seed_results[0].actual_class, "resource_cap");
    }

    #[test]
    fn timeout_and_resource_budgets_are_required() {
        let mut manifest = load_default_fuzz_smoke_manifest().expect("default manifest parses");
        manifest.seeds[0].timeout_ms = 0;
        manifest.seeds[0].resource_budget.max_input_bytes = 0;

        let errors = validate_fuzz_smoke_manifest(&manifest);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("timeout_ms must be positive")),
            "{errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("max_input_bytes must be positive")),
            "{errors:?}"
        );
    }

    #[test]
    fn non_minimized_seed_requires_follow_up_bead() {
        let mut manifest = load_default_fuzz_smoke_manifest().expect("default manifest parses");
        manifest.seeds[0].minimization.status = "not_minimized".to_owned();
        manifest.seeds[0].minimization.follow_up_bead = None;

        let errors = validate_fuzz_smoke_manifest(&manifest);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("non-minimized seeds require follow_up_bead")),
            "{errors:?}"
        );
    }

    #[test]
    fn minimized_seed_requires_replay_command() {
        let mut manifest = load_default_fuzz_smoke_manifest().expect("default manifest parses");
        manifest.seeds[0].minimization.replay_command.clear();

        let errors = validate_fuzz_smoke_manifest(&manifest);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("minimized seeds require replay_command")),
            "{errors:?}"
        );
    }

    #[test]
    fn active_quarantine_requires_owner_expiry_and_owning_bead() {
        let mut manifest = load_default_fuzz_smoke_manifest().expect("default manifest parses");
        manifest.seeds[0].quarantine.status = "active".to_owned();
        manifest.seeds[0].quarantine.quarantine_id = Some("q-fs-ext4-superblock".to_owned());
        manifest.seeds[0].quarantine.expires_at = Some("2026-06-01T00:00:00Z".to_owned());
        manifest.seeds[0].quarantine.rationale = Some("bounded parser follow-up".to_owned());
        manifest.seeds[0].quarantine.owning_bead = Some("not-a-bead".to_owned());

        let errors = validate_fuzz_smoke_manifest(&manifest);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("active quarantine missing owner")),
            "{errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("quarantine owning_bead must look like bd-")),
            "{errors:?}"
        );
    }

    #[test]
    fn expired_quarantine_is_rejected() {
        let mut manifest = load_default_fuzz_smoke_manifest().expect("default manifest parses");
        manifest.seeds[0].quarantine.status = "expired".to_owned();

        let errors = validate_fuzz_smoke_manifest(&manifest);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("quarantine has expired")),
            "{errors:?}"
        );
    }

    #[test]
    fn expected_class_mismatch_invalidates_report() {
        let mut manifest = load_default_fuzz_smoke_manifest().expect("default manifest parses");
        manifest.seeds[0].expected_class = "InvalidMagic".to_owned();

        let report = run_fuzz_smoke_manifest(&manifest, &workspace_root());
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("expected class")),
            "{:?}",
            report.errors
        );
    }

    #[test]
    fn expected_error_fragment_mismatch_invalidates_report() {
        let mut manifest = load_default_fuzz_smoke_manifest().expect("default manifest parses");
        manifest.seeds[0].expected_error_contains = Some("not-present-in-parser-error".to_owned());

        let report = run_fuzz_smoke_manifest(&manifest, &workspace_root());
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("expected error detail")),
            "{:?}",
            report.errors
        );
    }

    #[test]
    fn panic_classification_is_fail_closed() {
        let execution =
            classify_execution(|| std::panic::panic_any("fuzz smoke probe panic".to_owned()));
        assert_eq!(execution.actual_class, "panic");
        assert!(execution.error_detail.contains("fuzz smoke probe panic"));
    }

    #[test]
    fn timeout_classification_uses_millisecond_budget() {
        assert!(timed_out(Duration::from_millis(2), 1));
        assert!(!timed_out(Duration::from_millis(1), 1));
    }
}
