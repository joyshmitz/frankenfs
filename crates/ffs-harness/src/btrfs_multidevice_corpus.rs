#![forbid(unsafe_code)]

//! Btrfs multi-device RAID corpus and degraded-mode proof surface.
//!
//! Tracks bd-ch373: makes the btrfs multi-device support envelope measurable.
//! The corpus enumerates supported profile assembly, device-order
//! permutations, missing-device handling, unsupported-profile refusal, stale
//! superblock detection, and the repair/scrub boundary so README, FEATURE
//! _PARITY, release gates, and proof bundles cannot claim multi-device parity
//! from single-device tests alone.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const BTRFS_MULTIDEV_CORPUS_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_BTRFS_MULTIDEV_CORPUS_PATH: &str =
    "tests/btrfs-multidevice-corpus/btrfs_multidevice_corpus.json";
const DEFAULT_BTRFS_MULTIDEV_CORPUS_JSON: &str =
    include_str!("../../../tests/btrfs-multidevice-corpus/btrfs_multidevice_corpus.json");

const ALLOWED_PROFILES: [&str; 7] =
    ["single", "dup", "raid0", "raid1", "raid10", "raid5", "raid6"];

const ALLOWED_DEGRADED_STATES: [&str; 4] =
    ["healthy", "missing_device", "stale_device", "duplicate_device_id"];

const ALLOWED_OUTCOMES: [&str; 6] = [
    "assembly_success",
    "degraded_read_only",
    "refused_unsupported_profile",
    "refused_missing_required_device",
    "refused_stale_superblock",
    "refused_duplicate_device_id",
];

const ALLOWED_CLEANUP_POLICIES: [&str; 3] = [
    "teardown_image_set",
    "preserve_artifacts_on_failure",
    "preserve_artifacts_always",
];

const REQUIRED_SCENARIO_KINDS: [&str; 6] = [
    "healthy_assembly",
    "device_order_permutation",
    "missing_device",
    "duplicate_device_id",
    "stale_superblock",
    "unsupported_profile",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsMultidevCorpus {
    pub schema_version: u32,
    pub corpus_id: String,
    pub bead_id: String,
    pub scenarios: Vec<BtrfsMultidevScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsMultidevScenario {
    pub scenario_id: String,
    pub kind: String,
    pub profile: String,
    pub device_count: u32,
    pub devices: Vec<BtrfsDevice>,
    pub chunk_layout: ChunkLayout,
    pub degraded_state: String,
    pub expected_outcome: String,
    #[serde(default)]
    pub expected_refusal_remediation: String,
    pub mount_mode: String,
    pub repair_scrub_boundary: RepairScrubBoundary,
    pub artifact_requirements: Vec<String>,
    pub cleanup_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsDevice {
    pub device_id: u32,
    pub fsid_hash: String,
    pub image_path: String,
    pub image_hash: String,
    pub byte_size: u64,
    pub stripe_index: Option<u32>,
    #[serde(default)]
    pub stale: bool,
    #[serde(default)]
    pub present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkLayout {
    pub chunk_size: u64,
    pub stripe_size: u64,
    pub stripes_per_chunk: u32,
    pub mirror_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairScrubBoundary {
    pub scrub_supported: bool,
    pub repair_supported: bool,
    pub follow_up_bead: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsMultidevCorpusReport {
    pub schema_version: u32,
    pub corpus_id: String,
    pub bead_id: String,
    pub scenario_count: usize,
    pub scenario_kinds: Vec<String>,
    pub profiles: Vec<String>,
    pub valid: bool,
    pub errors: Vec<String>,
}

pub fn parse_btrfs_multidev_corpus(text: &str) -> Result<BtrfsMultidevCorpus> {
    serde_json::from_str(text).map_err(|err| {
        anyhow::anyhow!("failed to parse btrfs multi-device corpus JSON: {err}")
    })
}

pub fn validate_default_btrfs_multidev_corpus() -> Result<BtrfsMultidevCorpusReport> {
    let corpus = parse_btrfs_multidev_corpus(DEFAULT_BTRFS_MULTIDEV_CORPUS_JSON)?;
    let report = validate_btrfs_multidev_corpus(&corpus);
    if !report.valid {
        bail!(
            "btrfs multi-device corpus failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        );
    }
    Ok(report)
}

#[must_use]
pub fn validate_btrfs_multidev_corpus(
    corpus: &BtrfsMultidevCorpus,
) -> BtrfsMultidevCorpusReport {
    let mut errors = Vec::new();
    let mut ids = BTreeSet::new();
    let mut kinds_seen = BTreeSet::new();
    let mut profiles_seen = BTreeSet::new();

    validate_corpus_top_level(corpus, &mut errors);

    for scenario in &corpus.scenarios {
        validate_scenario(scenario, &mut ids, &mut kinds_seen, &mut profiles_seen, &mut errors);
    }
    validate_required_kinds(&kinds_seen, &mut errors);

    BtrfsMultidevCorpusReport {
        schema_version: corpus.schema_version,
        corpus_id: corpus.corpus_id.clone(),
        bead_id: corpus.bead_id.clone(),
        scenario_count: corpus.scenarios.len(),
        scenario_kinds: kinds_seen.into_iter().collect(),
        profiles: profiles_seen.into_iter().collect(),
        valid: errors.is_empty(),
        errors,
    }
}

fn validate_corpus_top_level(
    corpus: &BtrfsMultidevCorpus,
    errors: &mut Vec<String>,
) {
    if corpus.schema_version != BTRFS_MULTIDEV_CORPUS_SCHEMA_VERSION {
        errors.push(format!(
            "btrfs multi-device corpus schema_version must be {BTRFS_MULTIDEV_CORPUS_SCHEMA_VERSION}, got {}",
            corpus.schema_version
        ));
    }
    if corpus.corpus_id.trim().is_empty() {
        errors.push("btrfs multi-device corpus missing corpus_id".to_owned());
    }
    if !corpus.bead_id.starts_with("bd-") {
        errors.push(format!(
            "btrfs multi-device corpus bead_id must look like bd-..., got `{}`",
            corpus.bead_id
        ));
    }
    if corpus.scenarios.is_empty() {
        errors.push("btrfs multi-device corpus must declare at least one scenario".to_owned());
    }
}

fn validate_scenario(
    scenario: &BtrfsMultidevScenario,
    ids: &mut BTreeSet<String>,
    kinds: &mut BTreeSet<String>,
    profiles: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    if !ids.insert(scenario.scenario_id.clone()) {
        errors.push(format!(
            "duplicate btrfs multi-device scenario_id `{}`",
            scenario.scenario_id
        ));
    }
    if !scenario
        .scenario_id
        .starts_with("btrfs_multidev_")
    {
        errors.push(format!(
            "scenario_id `{}` must start with btrfs_multidev_",
            scenario.scenario_id
        ));
    }
    if REQUIRED_SCENARIO_KINDS.contains(&scenario.kind.as_str()) {
        kinds.insert(scenario.kind.clone());
    } else {
        errors.push(format!(
            "scenario `{}` has unsupported kind `{}`",
            scenario.scenario_id, scenario.kind
        ));
    }
    if !ALLOWED_PROFILES.contains(&scenario.profile.as_str()) {
        errors.push(format!(
            "scenario `{}` has unsupported profile `{}`",
            scenario.scenario_id, scenario.profile
        ));
    } else {
        profiles.insert(scenario.profile.clone());
    }

    validate_devices(scenario, errors);
    validate_chunk_layout(scenario, errors);
    validate_degraded_and_outcome(scenario, errors);
    validate_repair_scrub_boundary(scenario, errors);
    validate_scenario_envelope(scenario, errors);
}

fn validate_devices(scenario: &BtrfsMultidevScenario, errors: &mut Vec<String>) {
    if scenario.device_count == 0 {
        errors.push(format!(
            "scenario `{}` device_count must be positive",
            scenario.scenario_id
        ));
    }
    if scenario.devices.len() != scenario.device_count as usize {
        errors.push(format!(
            "scenario `{}` device_count {} mismatches devices array length {}",
            scenario.scenario_id,
            scenario.device_count,
            scenario.devices.len()
        ));
    }
    let mut seen_ids = BTreeSet::new();
    let mut duplicate_seen = false;
    for device in &scenario.devices {
        if device.image_hash.trim().is_empty() {
            errors.push(format!(
                "scenario `{}` device `{}` missing image_hash",
                scenario.scenario_id, device.device_id
            ));
        }
        if !is_valid_sha256(&device.image_hash) {
            errors.push(format!(
                "scenario `{}` device `{}` image_hash must be sha256:<64-hex>",
                scenario.scenario_id, device.device_id
            ));
        }
        if device.fsid_hash.trim().is_empty() {
            errors.push(format!(
                "scenario `{}` device `{}` missing fsid_hash",
                scenario.scenario_id, device.device_id
            ));
        }
        if !seen_ids.insert(device.device_id) {
            duplicate_seen = true;
        }
    }
    if duplicate_seen
        && scenario.kind != "duplicate_device_id"
        && scenario.degraded_state != "duplicate_device_id"
    {
        errors.push(format!(
            "scenario `{}` has duplicate device_id but is not classified as duplicate_device_id",
            scenario.scenario_id
        ));
    }
    if scenario.profile == "single" && scenario.device_count != 1 {
        errors.push(format!(
            "scenario `{}` profile=single requires device_count=1",
            scenario.scenario_id
        ));
    }
    if scenario.profile == "raid1" && scenario.device_count < 2 {
        errors.push(format!(
            "scenario `{}` profile=raid1 requires at least two devices",
            scenario.scenario_id
        ));
    }
    if scenario.profile == "raid10" && scenario.device_count < 4 {
        errors.push(format!(
            "scenario `{}` profile=raid10 requires at least four devices",
            scenario.scenario_id
        ));
    }
}

fn validate_chunk_layout(scenario: &BtrfsMultidevScenario, errors: &mut Vec<String>) {
    if scenario.chunk_layout.chunk_size == 0 {
        errors.push(format!(
            "scenario `{}` chunk_size must be positive",
            scenario.scenario_id
        ));
    }
    if scenario.chunk_layout.stripe_size == 0 {
        errors.push(format!(
            "scenario `{}` stripe_size must be positive",
            scenario.scenario_id
        ));
    }
    if scenario.chunk_layout.stripes_per_chunk == 0 {
        errors.push(format!(
            "scenario `{}` stripes_per_chunk must be positive",
            scenario.scenario_id
        ));
    }
    if scenario.chunk_layout.mirror_count == 0 {
        errors.push(format!(
            "scenario `{}` mirror_count must be positive",
            scenario.scenario_id
        ));
    }
    if scenario.profile == "raid1" && scenario.chunk_layout.mirror_count < 2 {
        errors.push(format!(
            "scenario `{}` raid1 must have mirror_count >= 2",
            scenario.scenario_id
        ));
    }
}

fn validate_degraded_and_outcome(
    scenario: &BtrfsMultidevScenario,
    errors: &mut Vec<String>,
) {
    if !ALLOWED_DEGRADED_STATES.contains(&scenario.degraded_state.as_str()) {
        errors.push(format!(
            "scenario `{}` has unsupported degraded_state `{}`",
            scenario.scenario_id, scenario.degraded_state
        ));
    }
    if !ALLOWED_OUTCOMES.contains(&scenario.expected_outcome.as_str()) {
        errors.push(format!(
            "scenario `{}` has unsupported expected_outcome `{}`",
            scenario.scenario_id, scenario.expected_outcome
        ));
    }
    let is_refusal = scenario.expected_outcome.starts_with("refused_");
    if is_refusal && scenario.expected_refusal_remediation.trim().is_empty() {
        errors.push(format!(
            "scenario `{}` refusal outcome must declare expected_refusal_remediation",
            scenario.scenario_id
        ));
    }
    if !is_refusal && !scenario.expected_refusal_remediation.trim().is_empty() {
        errors.push(format!(
            "scenario `{}` non-refusal outcome must leave expected_refusal_remediation empty",
            scenario.scenario_id
        ));
    }
    if scenario.degraded_state == "missing_device"
        && scenario.expected_outcome == "assembly_success"
    {
        errors.push(format!(
            "scenario `{}` missing_device cannot expect assembly_success without degraded_read_only",
            scenario.scenario_id
        ));
    }
    if !["read_only", "rw_unsupported", "rw_safe", "parser_only"]
        .contains(&scenario.mount_mode.as_str())
    {
        errors.push(format!(
            "scenario `{}` has unsupported mount_mode `{}`",
            scenario.scenario_id, scenario.mount_mode
        ));
    }
}

fn validate_repair_scrub_boundary(
    scenario: &BtrfsMultidevScenario,
    errors: &mut Vec<String>,
) {
    if scenario.repair_scrub_boundary.repair_supported
        && !scenario.repair_scrub_boundary.scrub_supported
    {
        errors.push(format!(
            "scenario `{}` repair_supported requires scrub_supported",
            scenario.scenario_id
        ));
    }
    if !scenario.repair_scrub_boundary.scrub_supported
        && !scenario.repair_scrub_boundary.follow_up_bead.starts_with("bd-")
    {
        errors.push(format!(
            "scenario `{}` unsupported scrub must point to a follow_up_bead (bd-...)",
            scenario.scenario_id
        ));
    }
}

fn validate_scenario_envelope(
    scenario: &BtrfsMultidevScenario,
    errors: &mut Vec<String>,
) {
    if scenario.artifact_requirements.is_empty() {
        errors.push(format!(
            "scenario `{}` must declare artifact_requirements",
            scenario.scenario_id
        ));
    }
    for required in ["scenario_id", "device_image_hashes", "expected_outcome"] {
        if !scenario
            .artifact_requirements
            .iter()
            .any(|requirement| requirement == required)
        {
            errors.push(format!(
                "scenario `{}` artifact_requirements missing `{required}`",
                scenario.scenario_id
            ));
        }
    }
    if !ALLOWED_CLEANUP_POLICIES.contains(&scenario.cleanup_policy.as_str()) {
        errors.push(format!(
            "scenario `{}` has unsupported cleanup_policy `{}`",
            scenario.scenario_id, scenario.cleanup_policy
        ));
    }
}

fn validate_required_kinds(seen: &BTreeSet<String>, errors: &mut Vec<String>) {
    for required in REQUIRED_SCENARIO_KINDS {
        if !seen.contains(required) {
            errors.push(format!(
                "btrfs multi-device corpus missing required kind `{required}`"
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

    fn fixture_corpus() -> BtrfsMultidevCorpus {
        parse_btrfs_multidev_corpus(DEFAULT_BTRFS_MULTIDEV_CORPUS_JSON)
            .expect("default btrfs multi-device corpus parses")
    }

    #[test]
    fn default_corpus_validates_required_kinds() {
        let report = validate_default_btrfs_multidev_corpus()
            .expect("default btrfs multi-device corpus validates");
        assert_eq!(report.bead_id, "bd-ch373");
        assert_eq!(report.schema_version, BTRFS_MULTIDEV_CORPUS_SCHEMA_VERSION);
        for kind in REQUIRED_SCENARIO_KINDS {
            assert!(
                report.scenario_kinds.iter().any(|k| k == kind),
                "missing required kind {kind}"
            );
        }
    }

    #[test]
    fn missing_required_kind_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus
            .scenarios
            .retain(|scenario| scenario.kind != "missing_device");
        let report = validate_btrfs_multidev_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required kind `missing_device`"))
        );
    }

    #[test]
    fn missing_unsupported_profile_kind_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus
            .scenarios
            .retain(|scenario| scenario.kind != "unsupported_profile");
        let report = validate_btrfs_multidev_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required kind `unsupported_profile`"))
        );
    }

    #[test]
    fn duplicate_scenario_id_is_rejected() {
        let mut corpus = fixture_corpus();
        let dup = corpus.scenarios[0].scenario_id.clone();
        corpus.scenarios[1].scenario_id = dup;
        let report = validate_btrfs_multidev_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("duplicate btrfs multi-device scenario_id"))
        );
    }

    #[test]
    fn scenario_id_prefix_is_enforced() {
        let mut corpus = fixture_corpus();
        corpus.scenarios[0].scenario_id = "totally_unrelated_id".to_owned();
        let report = validate_btrfs_multidev_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must start with btrfs_multidev_"))
        );
    }

    #[test]
    fn unsupported_profile_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.scenarios[0].profile = "raid42".to_owned();
        let report = validate_btrfs_multidev_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported profile"))
        );
    }

    #[test]
    fn raid1_requires_two_devices() {
        let mut corpus = fixture_corpus();
        let scenario = corpus
            .scenarios
            .iter_mut()
            .find(|s| s.profile == "raid1")
            .expect("raid1 scenario exists");
        scenario.device_count = 1;
        scenario.devices.truncate(1);
        scenario.chunk_layout.mirror_count = 1;
        let report = validate_btrfs_multidev_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("raid1 requires at least two devices"))
        );
    }

    #[test]
    fn raid10_requires_four_devices() {
        let mut corpus = fixture_corpus();
        let index = corpus
            .scenarios
            .iter()
            .position(|s| s.profile == "raid10")
            .unwrap_or(0);
        let scenario = &mut corpus.scenarios[index];
        scenario.profile = "raid10".to_owned();
        scenario.device_count = 2;
        scenario.devices.truncate(2);
        let report = validate_btrfs_multidev_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("raid10 requires at least four devices"))
        );
    }

    #[test]
    fn device_count_array_length_must_match() {
        let mut corpus = fixture_corpus();
        corpus.scenarios[0].device_count = 99;
        let report = validate_btrfs_multidev_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("mismatches devices array length"))
        );
    }

    #[test]
    fn malformed_device_image_hash_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.scenarios[0].devices[0].image_hash = "md5:not-supported".to_owned();
        let report = validate_btrfs_multidev_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("image_hash must be sha256"))
        );
    }

    #[test]
    fn duplicate_device_id_outside_classified_kind_is_rejected() {
        let mut corpus = fixture_corpus();
        let scenario = corpus
            .scenarios
            .iter_mut()
            .find(|s| s.kind == "healthy_assembly" && s.devices.len() >= 2)
            .expect("healthy assembly fixture exists");
        scenario.devices[1].device_id = scenario.devices[0].device_id;
        let report = validate_btrfs_multidev_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("duplicate device_id but is not classified"))
        );
    }

    #[test]
    fn unsupported_degraded_state_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.scenarios[0].degraded_state = "kinda_broken".to_owned();
        let report = validate_btrfs_multidev_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported degraded_state"))
        );
    }

    #[test]
    fn missing_device_cannot_claim_assembly_success() {
        let mut corpus = fixture_corpus();
        let scenario = corpus
            .scenarios
            .iter_mut()
            .find(|s| s.kind == "missing_device")
            .expect("missing_device fixture exists");
        scenario.expected_outcome = "assembly_success".to_owned();
        scenario.expected_refusal_remediation = String::new();
        let report = validate_btrfs_multidev_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing_device cannot expect assembly_success"))
        );
    }

    #[test]
    fn refusal_outcome_requires_remediation_text() {
        let mut corpus = fixture_corpus();
        let scenario = corpus
            .scenarios
            .iter_mut()
            .find(|s| s.expected_outcome.starts_with("refused_"))
            .expect("refusal fixture exists");
        scenario.expected_refusal_remediation = String::new();
        let report = validate_btrfs_multidev_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must declare expected_refusal_remediation"))
        );
    }

    #[test]
    fn unsupported_mount_mode_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.scenarios[0].mount_mode = "rwx_eyes_only".to_owned();
        let report = validate_btrfs_multidev_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported mount_mode"))
        );
    }

    #[test]
    fn repair_supported_requires_scrub_supported() {
        let mut corpus = fixture_corpus();
        corpus.scenarios[0].repair_scrub_boundary.repair_supported = true;
        corpus.scenarios[0].repair_scrub_boundary.scrub_supported = false;
        let report = validate_btrfs_multidev_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("repair_supported requires scrub_supported"))
        );
    }

    #[test]
    fn unsupported_scrub_must_link_follow_up_bead() {
        let mut corpus = fixture_corpus();
        let index = corpus
            .scenarios
            .iter()
            .position(|s| !s.repair_scrub_boundary.scrub_supported)
            .unwrap_or(0);
        let scenario = &mut corpus.scenarios[index];
        scenario.repair_scrub_boundary.scrub_supported = false;
        scenario.repair_scrub_boundary.repair_supported = false;
        scenario.repair_scrub_boundary.follow_up_bead = String::new();
        let report = validate_btrfs_multidev_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported scrub must point to a follow_up_bead"))
        );
    }

    #[test]
    fn missing_artifact_requirement_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.scenarios[0]
            .artifact_requirements
            .retain(|requirement| requirement != "device_image_hashes");
        let report = validate_btrfs_multidev_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("artifact_requirements missing `device_image_hashes`"))
        );
    }

    #[test]
    fn unsupported_cleanup_policy_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.scenarios[0].cleanup_policy = "leave_disks_dirty".to_owned();
        let report = validate_btrfs_multidev_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported cleanup_policy"))
        );
    }

    #[test]
    fn empty_scenarios_list_is_rejected() {
        let mut corpus = fixture_corpus();
        corpus.scenarios.clear();
        let report = validate_btrfs_multidev_corpus(&corpus);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("at least one scenario"))
        );
    }
}
