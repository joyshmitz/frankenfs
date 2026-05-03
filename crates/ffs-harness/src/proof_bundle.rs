#![allow(clippy::too_many_lines)]

//! Versioned proof-bundle validation for `bd-rchk0.5.4.1`.
//!
//! Proof bundles are offline release-readiness packs: they preserve the raw
//! logs, summaries, gate inputs, artifact hashes, runtime fingerprint, and
//! redaction policy needed to inspect a readiness claim without a live build
//! tree.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const PROOF_BUNDLE_SCHEMA_VERSION: u32 = 1;
pub const REQUIRED_PROOF_BUNDLE_LANES: [&str; 11] = [
    "conformance",
    "xfstests",
    "fuse",
    "differential_oracle",
    "repair_lab",
    "crash_replay",
    "performance",
    "writeback_cache",
    "scrub_repair_status",
    "known_deferrals",
    "release_gates",
];

const PRESERVED_REDACTION_FIELDS: [&str; 5] = [
    "reproduction_command",
    "git_sha",
    "bundle_id",
    "artifact_paths",
    "scenario_ids",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofBundleValidationConfig {
    pub manifest_path: PathBuf,
    pub current_git_sha: Option<String>,
    pub max_age_days: Option<u64>,
}

impl ProofBundleValidationConfig {
    #[must_use]
    pub fn new(manifest_path: impl Into<PathBuf>) -> Self {
        Self {
            manifest_path: manifest_path.into(),
            current_git_sha: None,
            max_age_days: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleManifest {
    pub schema_version: u32,
    pub bundle_id: String,
    pub generated_at: String,
    pub git_sha: String,
    pub toolchain: String,
    pub kernel: String,
    pub mount_capability: String,
    pub required_lanes: Vec<String>,
    pub lanes: Vec<ProofBundleLane>,
    pub redaction: ProofBundleRedactionPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity: Option<ProofBundleIntegrityPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleLane {
    pub lane_id: String,
    pub status: ProofBundleOutcome,
    pub raw_log_path: String,
    pub summary_path: String,
    pub scenario_ids: Vec<String>,
    pub gate_inputs: Vec<String>,
    pub artifacts: Vec<ProofBundleArtifact>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofBundleOutcome {
    Pass,
    Fail,
    Skip,
    Error,
}

impl ProofBundleOutcome {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Skip => "skip",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleArtifact {
    pub path: String,
    pub sha256: String,
    pub redacted: bool,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleRedactionPolicy {
    pub redacted_fields: Vec<String>,
    pub preserved_fields: Vec<String>,
    pub reproduction_command: String,
    #[serde(default = "default_redaction_policy_version")]
    pub policy_version: String,
    #[serde(default = "default_redacted_value_placeholder")]
    pub redacted_value_placeholder: String,
    #[serde(default)]
    pub forbidden_unredacted_markers: Vec<String>,
    #[serde(default)]
    pub require_placeholder_in_redacted_artifacts: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleIntegrityPolicy {
    pub artifact_hash_chain_sha256: String,
    pub artifact_count: usize,
    pub redaction_policy_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleValidationReport {
    pub schema_version: u32,
    pub bundle_id: String,
    pub manifest_path: String,
    pub valid: bool,
    pub totals: ProofBundleTotals,
    pub missing_required_lanes: Vec<String>,
    pub duplicate_lane_ids: Vec<String>,
    pub duplicate_scenario_ids: Vec<String>,
    pub stale_git_sha: Option<StaleProofBundleGitSha>,
    pub stale_timestamp: Option<StaleProofBundleTimestamp>,
    pub broken_links: Vec<ProofBundleBrokenLink>,
    pub artifact_hash_mismatches: Vec<ProofBundleHashMismatch>,
    pub artifact_hash_chain: Option<ProofBundleHashChainReport>,
    pub artifact_reports: Vec<ProofBundleArtifactReport>,
    pub redaction_errors: Vec<String>,
    pub redaction_leaks: Vec<ProofBundleRedactionLeak>,
    pub integrity_errors: Vec<String>,
    pub lanes: Vec<ProofBundleLaneReport>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleTotals {
    pub pass: usize,
    pub fail: usize,
    pub skip: usize,
    pub error: usize,
    pub lanes: usize,
    pub scenarios: usize,
    pub artifacts: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaleProofBundleGitSha {
    pub observed: String,
    pub expected: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaleProofBundleTimestamp {
    pub generated_at: String,
    pub max_age_days: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleBrokenLink {
    pub lane_id: String,
    pub field: String,
    pub path: String,
    pub diagnostic: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleHashMismatch {
    pub lane_id: String,
    pub path: String,
    pub expected_sha256: String,
    pub actual_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleHashChainReport {
    pub expected_sha256: String,
    pub observed_sha256: String,
    pub artifact_count: usize,
    pub redaction_policy_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleArtifactReport {
    pub lane_id: String,
    pub path: String,
    pub sha256: String,
    pub redacted: bool,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleRedactionLeak {
    pub lane_id: String,
    pub field: String,
    pub path: String,
    pub marker: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleLaneReport {
    pub lane_id: String,
    pub status: ProofBundleOutcome,
    pub raw_log_path: String,
    pub summary_path: String,
    pub scenario_count: usize,
    pub artifact_count: usize,
}

#[must_use]
pub fn proof_bundle_required_lanes() -> Vec<String> {
    REQUIRED_PROOF_BUNDLE_LANES
        .iter()
        .map(|lane| (*lane).to_owned())
        .collect()
}

fn default_redaction_policy_version() -> String {
    "v1".to_owned()
}

fn default_redacted_value_placeholder() -> String {
    "[REDACTED]".to_owned()
}

pub fn load_proof_bundle_manifest(path: &Path) -> Result<ProofBundleManifest> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read proof bundle {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("invalid proof bundle JSON {}", path.display()))
}

pub fn validate_proof_bundle(
    config: &ProofBundleValidationConfig,
) -> Result<ProofBundleValidationReport> {
    let manifest = load_proof_bundle_manifest(&config.manifest_path)?;
    let bundle_root = config
        .manifest_path
        .parent()
        .unwrap_or_else(|| Path::new("."));
    Ok(validate_proof_bundle_manifest(
        &manifest,
        bundle_root,
        &config.manifest_path,
        config.current_git_sha.as_deref(),
        config.max_age_days,
    ))
}

#[must_use]
pub fn validate_proof_bundle_manifest(
    manifest: &ProofBundleManifest,
    bundle_root: &Path,
    manifest_path: &Path,
    current_git_sha: Option<&str>,
    max_age_days: Option<u64>,
) -> ProofBundleValidationReport {
    let mut builder = ProofBundleReportBuilder::new(manifest_path);

    builder.validate_top_level(manifest, current_git_sha, max_age_days);
    builder.validate_lanes(manifest, bundle_root);
    builder.validate_integrity_policy(manifest);
    builder.validate_redaction_policy(&manifest.redaction);
    builder.validate_redaction_contents(manifest, bundle_root);

    builder.finish(manifest)
}

#[must_use]
pub fn render_proof_bundle_markdown(report: &ProofBundleValidationReport) -> String {
    let mut out = String::new();
    writeln!(&mut out, "# FrankenFS Proof Bundle").ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "- Bundle: `{}`", report.bundle_id).ok();
    writeln!(&mut out, "- Manifest: `{}`", report.manifest_path).ok();
    writeln!(&mut out, "- Valid: `{}`", report.valid).ok();
    writeln!(
        &mut out,
        "- Totals: pass={} fail={} skip={} error={} lanes={} scenarios={} artifacts={}",
        report.totals.pass,
        report.totals.fail,
        report.totals.skip,
        report.totals.error,
        report.totals.lanes,
        report.totals.scenarios,
        report.totals.artifacts
    )
    .ok();
    writeln!(
        &mut out,
        "- Diagnostics: missing_lanes={} duplicate_lanes={} duplicate_scenarios={} broken_links={} hash_mismatches={} redaction_errors={} redaction_leaks={} integrity_errors={} errors={} warnings={}",
        report.missing_required_lanes.len(),
        report.duplicate_lane_ids.len(),
        report.duplicate_scenario_ids.len(),
        report.broken_links.len(),
        report.artifact_hash_mismatches.len(),
        report.redaction_errors.len(),
        report.redaction_leaks.len(),
        report.integrity_errors.len(),
        report.errors.len(),
        report.warnings.len()
    )
    .ok();
    if let Some(chain) = &report.artifact_hash_chain {
        writeln!(
            &mut out,
            "- Artifact hash chain: observed=`{}` expected=`{}` artifacts={} redaction_policy_version=`{}`",
            chain.observed_sha256,
            chain.expected_sha256,
            chain.artifact_count,
            chain.redaction_policy_version
        )
        .ok();
    }
    writeln!(
        &mut out,
        "- Reproduction: `{}`",
        escape_markdown_table_cell(&report.reproduction_command)
    )
    .ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "## Lanes").ok();
    writeln!(
        &mut out,
        "| Lane | Outcome | Scenarios | Artifacts | Raw log | Summary |"
    )
    .ok();
    writeln!(&mut out, "|---|---:|---:|---:|---|---|").ok();
    for lane in &report.lanes {
        writeln!(
            &mut out,
            "| `{}` | `{}` | {} | {} | [{}]({}) | [{}]({}) |",
            lane.lane_id,
            lane.status.label(),
            lane.scenario_count,
            lane.artifact_count,
            lane.raw_log_path,
            lane.raw_log_path,
            lane.summary_path,
            lane.summary_path
        )
        .ok();
    }
    if !report.errors.is_empty() {
        writeln!(&mut out).ok();
        writeln!(&mut out, "## Errors").ok();
        for error in &report.errors {
            writeln!(&mut out, "- {}", escape_markdown_table_cell(error)).ok();
        }
    }
    out
}

pub fn fail_on_proof_bundle_errors(report: &ProofBundleValidationReport) -> Result<()> {
    if report.valid {
        Ok(())
    } else {
        bail!(
            "proof bundle validation failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        )
    }
}

pub fn sha256_file_hex(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("failed to open artifact {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read artifact {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

struct ProofBundleReportBuilder {
    manifest_path: String,
    totals: ProofBundleTotals,
    missing_required_lanes: Vec<String>,
    duplicate_lane_ids: Vec<String>,
    duplicate_scenario_ids: Vec<String>,
    stale_git_sha: Option<StaleProofBundleGitSha>,
    stale_timestamp: Option<StaleProofBundleTimestamp>,
    broken_links: Vec<ProofBundleBrokenLink>,
    artifact_hash_mismatches: Vec<ProofBundleHashMismatch>,
    artifact_hash_chain: Option<ProofBundleHashChainReport>,
    artifact_reports: Vec<ProofBundleArtifactReport>,
    redaction_errors: Vec<String>,
    redaction_leaks: Vec<ProofBundleRedactionLeak>,
    integrity_errors: Vec<String>,
    lanes: Vec<ProofBundleLaneReport>,
    errors: Vec<String>,
    warnings: Vec<String>,
}

impl ProofBundleReportBuilder {
    fn new(manifest_path: &Path) -> Self {
        Self {
            manifest_path: manifest_path.display().to_string(),
            totals: ProofBundleTotals::default(),
            missing_required_lanes: Vec::new(),
            duplicate_lane_ids: Vec::new(),
            duplicate_scenario_ids: Vec::new(),
            stale_git_sha: None,
            stale_timestamp: None,
            broken_links: Vec::new(),
            artifact_hash_mismatches: Vec::new(),
            artifact_hash_chain: None,
            artifact_reports: Vec::new(),
            redaction_errors: Vec::new(),
            redaction_leaks: Vec::new(),
            integrity_errors: Vec::new(),
            lanes: Vec::new(),
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn validate_top_level(
        &mut self,
        manifest: &ProofBundleManifest,
        current_git_sha: Option<&str>,
        max_age_days: Option<u64>,
    ) {
        if manifest.schema_version != PROOF_BUNDLE_SCHEMA_VERSION {
            self.errors.push(format!(
                "stale schema_version {} expected {}",
                manifest.schema_version, PROOF_BUNDLE_SCHEMA_VERSION
            ));
        }
        validate_nonempty("bundle_id", &manifest.bundle_id, &mut self.errors);
        validate_nonempty("generated_at", &manifest.generated_at, &mut self.errors);
        validate_nonempty("git_sha", &manifest.git_sha, &mut self.errors);
        validate_nonempty("toolchain", &manifest.toolchain, &mut self.errors);
        validate_nonempty("kernel", &manifest.kernel, &mut self.errors);
        validate_nonempty(
            "mount_capability",
            &manifest.mount_capability,
            &mut self.errors,
        );

        let declared_required: BTreeSet<&str> =
            manifest.required_lanes.iter().map(String::as_str).collect();
        for required in REQUIRED_PROOF_BUNDLE_LANES {
            if !declared_required.contains(required) {
                self.errors
                    .push(format!("required_lanes missing lane {required}"));
            }
        }

        if let Some(expected) = current_git_sha
            && expected != manifest.git_sha
        {
            self.stale_git_sha = Some(StaleProofBundleGitSha {
                observed: manifest.git_sha.clone(),
                expected: expected.to_owned(),
            });
            self.errors.push(format!(
                "stale git_sha {} expected {expected}",
                manifest.git_sha
            ));
        }

        match parse_utc_timestamp_seconds(&manifest.generated_at) {
            Ok(generated_seconds) => {
                if let Some(days) = max_age_days
                    && timestamp_is_stale(generated_seconds, days)
                {
                    self.stale_timestamp = Some(StaleProofBundleTimestamp {
                        generated_at: manifest.generated_at.clone(),
                        max_age_days: days,
                    });
                    self.errors.push(format!(
                        "stale generated_at {} older than {days} day(s)",
                        manifest.generated_at
                    ));
                }
            }
            Err(error) => self
                .errors
                .push(format!("generated_at must be UTC RFC3339 seconds: {error}")),
        }
    }

    fn validate_lanes(&mut self, manifest: &ProofBundleManifest, bundle_root: &Path) {
        let mut lane_ids = BTreeMap::<String, usize>::new();
        let mut scenario_ids = BTreeMap::<String, usize>::new();

        for lane in &manifest.lanes {
            *lane_ids.entry(lane.lane_id.clone()).or_default() += 1;
            self.validate_lane(lane, bundle_root, &mut scenario_ids);
        }

        self.duplicate_lane_ids = lane_ids
            .into_iter()
            .filter_map(|(lane_id, count)| (count > 1).then_some(lane_id))
            .collect();
        for lane_id in &self.duplicate_lane_ids {
            self.errors.push(format!("duplicate lane_id {lane_id}"));
        }

        self.duplicate_scenario_ids = scenario_ids
            .into_iter()
            .filter_map(|(scenario_id, count)| (count > 1).then_some(scenario_id))
            .collect();
        for scenario_id in &self.duplicate_scenario_ids {
            self.errors
                .push(format!("duplicate scenario_id {scenario_id}"));
        }

        let lane_id_set: BTreeSet<&str> = manifest
            .lanes
            .iter()
            .map(|lane| lane.lane_id.as_str())
            .collect();
        for required in REQUIRED_PROOF_BUNDLE_LANES {
            if !lane_id_set.contains(required) {
                self.missing_required_lanes.push(required.to_owned());
                self.errors
                    .push(format!("lanes missing required lane {required}"));
            }
        }
    }

    fn validate_lane(
        &mut self,
        lane: &ProofBundleLane,
        bundle_root: &Path,
        scenario_ids: &mut BTreeMap<String, usize>,
    ) {
        validate_nonempty("lane_id", &lane.lane_id, &mut self.errors);
        self.totals.lanes += 1;
        self.count_outcome(lane.status);
        self.totals.scenarios += lane.scenario_ids.len();
        self.totals.artifacts += lane.artifacts.len();

        if lane.scenario_ids.is_empty() {
            self.errors
                .push(format!("lane {} has no scenario_ids", lane.lane_id));
        }
        for scenario_id in &lane.scenario_ids {
            validate_nonempty(
                &format!("lane {} scenario_id", lane.lane_id),
                scenario_id,
                &mut self.errors,
            );
            *scenario_ids.entry(scenario_id.clone()).or_default() += 1;
        }

        self.validate_existing_file(
            bundle_root,
            &lane.lane_id,
            "raw_log_path",
            &lane.raw_log_path,
        );
        self.validate_existing_file(
            bundle_root,
            &lane.lane_id,
            "summary_path",
            &lane.summary_path,
        );

        if lane.gate_inputs.is_empty() {
            self.errors
                .push(format!("lane {} has no gate_inputs", lane.lane_id));
        }
        for gate_input in &lane.gate_inputs {
            self.validate_existing_file(bundle_root, &lane.lane_id, "gate_input", gate_input);
        }

        if lane.artifacts.is_empty() {
            self.errors
                .push(format!("lane {} has no artifacts", lane.lane_id));
        }
        for artifact in &lane.artifacts {
            self.validate_artifact(bundle_root, &lane.lane_id, artifact);
        }

        self.lanes.push(ProofBundleLaneReport {
            lane_id: lane.lane_id.clone(),
            status: lane.status,
            raw_log_path: lane.raw_log_path.clone(),
            summary_path: lane.summary_path.clone(),
            scenario_count: lane.scenario_ids.len(),
            artifact_count: lane.artifacts.len(),
        });
    }

    fn count_outcome(&mut self, outcome: ProofBundleOutcome) {
        match outcome {
            ProofBundleOutcome::Pass => self.totals.pass += 1,
            ProofBundleOutcome::Fail => self.totals.fail += 1,
            ProofBundleOutcome::Skip => self.totals.skip += 1,
            ProofBundleOutcome::Error => self.totals.error += 1,
        }
    }

    fn validate_artifact(
        &mut self,
        bundle_root: &Path,
        lane_id: &str,
        artifact: &ProofBundleArtifact,
    ) {
        self.artifact_reports.push(ProofBundleArtifactReport {
            lane_id: lane_id.to_owned(),
            path: artifact.path.clone(),
            sha256: artifact.sha256.clone(),
            redacted: artifact.redacted,
            role: artifact.role.clone(),
        });
        validate_nonempty(
            &format!("lane {lane_id} artifact role"),
            &artifact.role,
            &mut self.errors,
        );
        if !is_valid_sha256_hex(&artifact.sha256) {
            self.errors.push(format!(
                "lane {lane_id} artifact {} has invalid sha256",
                artifact.path
            ));
            return;
        }

        let Some(path) =
            self.validate_existing_file(bundle_root, lane_id, "artifact", &artifact.path)
        else {
            return;
        };

        match sha256_file_hex(&path) {
            Ok(actual) if actual == artifact.sha256 => {}
            Ok(actual) => {
                self.artifact_hash_mismatches.push(ProofBundleHashMismatch {
                    lane_id: lane_id.to_owned(),
                    path: artifact.path.clone(),
                    expected_sha256: artifact.sha256.clone(),
                    actual_sha256: actual.clone(),
                });
                self.errors.push(format!(
                    "artifact hash mismatch lane={lane_id} path={} expected={} actual={actual}",
                    artifact.path, artifact.sha256
                ));
            }
            Err(error) => self.errors.push(format!(
                "failed to hash lane {lane_id} artifact {}: {error:#}",
                artifact.path
            )),
        }
    }

    fn validate_existing_file(
        &mut self,
        bundle_root: &Path,
        lane_id: &str,
        field: &str,
        raw_path: &str,
    ) -> Option<PathBuf> {
        let relative = match validate_relative_path(raw_path) {
            Ok(()) => PathBuf::from(raw_path),
            Err(error) => {
                self.broken_links.push(ProofBundleBrokenLink {
                    lane_id: lane_id.to_owned(),
                    field: field.to_owned(),
                    path: raw_path.to_owned(),
                    diagnostic: error.to_string(),
                });
                self.errors.push(format!(
                    "lane {lane_id} {field} path {raw_path:?} invalid: {error}"
                ));
                return None;
            }
        };
        let absolute = bundle_root.join(&relative);
        if !absolute.is_file() {
            self.broken_links.push(ProofBundleBrokenLink {
                lane_id: lane_id.to_owned(),
                field: field.to_owned(),
                path: raw_path.to_owned(),
                diagnostic: "file does not exist".to_owned(),
            });
            self.errors.push(format!(
                "broken link lane={lane_id} field={field} path={raw_path}"
            ));
            return None;
        }
        Some(absolute)
    }

    fn validate_integrity_policy(&mut self, manifest: &ProofBundleManifest) {
        let Some(integrity) = &manifest.integrity else {
            self.warnings
                .push("proof bundle has no artifact hash-chain integrity policy".to_owned());
            return;
        };

        validate_nonempty(
            "integrity.redaction_policy_version",
            &integrity.redaction_policy_version,
            &mut self.errors,
        );
        let observed_sha256 = artifact_hash_chain_sha256(manifest);
        self.artifact_hash_chain = Some(ProofBundleHashChainReport {
            expected_sha256: integrity.artifact_hash_chain_sha256.clone(),
            observed_sha256: observed_sha256.clone(),
            artifact_count: manifest_artifact_count(manifest),
            redaction_policy_version: integrity.redaction_policy_version.clone(),
        });

        if !is_valid_sha256_hex(&integrity.artifact_hash_chain_sha256) {
            self.integrity_errors
                .push("integrity artifact_hash_chain_sha256 must be SHA-256 hex".to_owned());
        } else if integrity.artifact_hash_chain_sha256 != observed_sha256 {
            self.integrity_errors.push(format!(
                "artifact hash-chain mismatch expected={} observed={observed_sha256}",
                integrity.artifact_hash_chain_sha256
            ));
        }

        let observed_artifact_count = manifest_artifact_count(manifest);
        if integrity.artifact_count != observed_artifact_count {
            self.integrity_errors.push(format!(
                "integrity artifact_count {} observed {observed_artifact_count}",
                integrity.artifact_count
            ));
        }
        if integrity.redaction_policy_version != manifest.redaction.policy_version {
            self.integrity_errors.push(format!(
                "integrity redaction_policy_version {} observed {}",
                integrity.redaction_policy_version, manifest.redaction.policy_version
            ));
        }

        for error in &self.integrity_errors {
            self.errors.push(error.clone());
        }
    }

    fn validate_redaction_policy(&mut self, policy: &ProofBundleRedactionPolicy) {
        validate_nonempty(
            "redaction.reproduction_command",
            &policy.reproduction_command,
            &mut self.errors,
        );
        validate_nonempty(
            "redaction.policy_version",
            &policy.policy_version,
            &mut self.errors,
        );
        validate_nonempty(
            "redaction.redacted_value_placeholder",
            &policy.redacted_value_placeholder,
            &mut self.errors,
        );
        if !policy
            .reproduction_command
            .contains("validate-proof-bundle")
        {
            self.redaction_errors.push(
                "redaction reproduction_command must preserve validate-proof-bundle invocation"
                    .to_owned(),
            );
        }

        let preserved: BTreeSet<&str> =
            policy.preserved_fields.iter().map(String::as_str).collect();
        let redacted: BTreeSet<&str> = policy.redacted_fields.iter().map(String::as_str).collect();

        for field in PRESERVED_REDACTION_FIELDS {
            if !preserved.contains(field) {
                self.redaction_errors.push(format!(
                    "redaction preserved_fields missing required field {field}"
                ));
            }
            if redacted.contains(field) {
                self.redaction_errors
                    .push(format!("redaction may not remove required field {field}"));
            }
        }

        for error in &self.redaction_errors {
            self.errors.push(error.clone());
        }
    }

    fn validate_redaction_contents(&mut self, manifest: &ProofBundleManifest, bundle_root: &Path) {
        if manifest.redaction.forbidden_unredacted_markers.is_empty()
            && !manifest.redaction.require_placeholder_in_redacted_artifacts
        {
            return;
        }

        for lane in &manifest.lanes {
            self.scan_redaction_file(
                bundle_root,
                &lane.lane_id,
                "raw_log_path",
                &lane.raw_log_path,
                &manifest.redaction,
                false,
            );
            self.scan_redaction_file(
                bundle_root,
                &lane.lane_id,
                "summary_path",
                &lane.summary_path,
                &manifest.redaction,
                false,
            );
            for gate_input in &lane.gate_inputs {
                self.scan_redaction_file(
                    bundle_root,
                    &lane.lane_id,
                    "gate_input",
                    gate_input,
                    &manifest.redaction,
                    false,
                );
            }
            for artifact in &lane.artifacts {
                self.scan_redaction_file(
                    bundle_root,
                    &lane.lane_id,
                    "artifact",
                    &artifact.path,
                    &manifest.redaction,
                    artifact.redacted,
                );
            }
        }

        for leak in &self.redaction_leaks {
            self.redaction_errors.push(format!(
                "redaction leak lane={} field={} path={} marker={}",
                leak.lane_id, leak.field, leak.path, leak.marker
            ));
        }
        for error in &self.redaction_errors {
            if !self.errors.contains(error) {
                self.errors.push(error.clone());
            }
        }
    }

    fn scan_redaction_file(
        &mut self,
        bundle_root: &Path,
        lane_id: &str,
        field: &str,
        raw_path: &str,
        policy: &ProofBundleRedactionPolicy,
        artifact_is_redacted: bool,
    ) {
        let Ok(()) = validate_relative_path(raw_path) else {
            return;
        };
        let path = bundle_root.join(raw_path);
        let Ok(bytes) = fs::read(&path) else {
            return;
        };

        for marker in &policy.forbidden_unredacted_markers {
            if marker.is_empty() {
                continue;
            }
            if bytes_contains(&bytes, marker.as_bytes()) {
                self.redaction_leaks.push(ProofBundleRedactionLeak {
                    lane_id: lane_id.to_owned(),
                    field: field.to_owned(),
                    path: raw_path.to_owned(),
                    marker: marker.clone(),
                });
            }
        }

        if policy.require_placeholder_in_redacted_artifacts
            && artifact_is_redacted
            && !bytes_contains(&bytes, policy.redacted_value_placeholder.as_bytes())
        {
            self.redaction_errors.push(format!(
                "redacted artifact lane={lane_id} path={raw_path} lacks placeholder {}",
                policy.redacted_value_placeholder
            ));
        }
    }

    fn finish(self, manifest: &ProofBundleManifest) -> ProofBundleValidationReport {
        let valid = self.errors.is_empty();
        ProofBundleValidationReport {
            schema_version: PROOF_BUNDLE_SCHEMA_VERSION,
            bundle_id: manifest.bundle_id.clone(),
            manifest_path: self.manifest_path,
            valid,
            totals: self.totals,
            missing_required_lanes: self.missing_required_lanes,
            duplicate_lane_ids: self.duplicate_lane_ids,
            duplicate_scenario_ids: self.duplicate_scenario_ids,
            stale_git_sha: self.stale_git_sha,
            stale_timestamp: self.stale_timestamp,
            broken_links: self.broken_links,
            artifact_hash_mismatches: self.artifact_hash_mismatches,
            artifact_hash_chain: self.artifact_hash_chain,
            artifact_reports: self.artifact_reports,
            redaction_errors: self.redaction_errors,
            redaction_leaks: self.redaction_leaks,
            integrity_errors: self.integrity_errors,
            lanes: self.lanes,
            errors: self.errors,
            warnings: self.warnings,
            reproduction_command: manifest.redaction.reproduction_command.clone(),
        }
    }
}

fn validate_nonempty(field: &str, value: &str, errors: &mut Vec<String>) {
    if value.trim().is_empty() {
        errors.push(format!("{field} must not be empty"));
    }
}

fn validate_relative_path(raw: &str) -> Result<()> {
    if raw.trim().is_empty() {
        bail!("path is empty");
    }
    let path = Path::new(raw);
    if path.is_absolute() {
        bail!("path must be relative");
    }
    for component in path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => bail!("path must not contain parent traversal"),
            Component::RootDir | Component::Prefix(_) => bail!("path must be relative"),
        }
    }
    Ok(())
}

fn is_valid_sha256_hex(raw: &str) -> bool {
    raw.len() == 64 && raw.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn manifest_artifact_count(manifest: &ProofBundleManifest) -> usize {
    manifest.lanes.iter().map(|lane| lane.artifacts.len()).sum()
}

fn artifact_hash_chain_sha256(manifest: &ProofBundleManifest) -> String {
    let mut hasher = Sha256::new();
    for lane in &manifest.lanes {
        hash_chain_part(&mut hasher, "lane");
        hash_chain_part(&mut hasher, &lane.lane_id);
        for artifact in &lane.artifacts {
            hash_chain_part(&mut hasher, "artifact");
            hash_chain_part(&mut hasher, &artifact.path);
            hash_chain_part(&mut hasher, &artifact.sha256);
            hash_chain_part(
                &mut hasher,
                if artifact.redacted {
                    "redacted"
                } else {
                    "clear"
                },
            );
            hash_chain_part(&mut hasher, &artifact.role);
        }
    }
    hex::encode(hasher.finalize())
}

fn hash_chain_part(hasher: &mut Sha256, value: &str) {
    hasher.update(value.len().to_string().as_bytes());
    hasher.update(b":");
    hasher.update(value.as_bytes());
    hasher.update(b";");
}

fn bytes_contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn parse_utc_timestamp_seconds(raw: &str) -> Result<i64> {
    let trimmed = raw.trim();
    let without_z = trimmed
        .strip_suffix('Z')
        .context("timestamp must end with Z")?;
    let (date, time) = without_z
        .split_once('T')
        .context("timestamp must contain T separator")?;
    let mut date_parts = date.split('-');
    let year = parse_i64_part(date_parts.next(), "year")?;
    let month = parse_i64_part(date_parts.next(), "month")?;
    let day = parse_i64_part(date_parts.next(), "day")?;
    if date_parts.next().is_some() {
        bail!("date has too many components");
    }

    let time_no_fraction = time.split_once('.').map_or(time, |(seconds, _)| seconds);
    let mut time_parts = time_no_fraction.split(':');
    let hour = parse_i64_part(time_parts.next(), "hour")?;
    let minute = parse_i64_part(time_parts.next(), "minute")?;
    let second = parse_i64_part(time_parts.next(), "second")?;
    if time_parts.next().is_some() {
        bail!("time has too many components");
    }
    validate_timestamp_ranges(month, day, hour, minute, second)?;
    Ok(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn parse_i64_part(part: Option<&str>, field: &str) -> Result<i64> {
    part.context(format!("{field} missing"))?
        .parse()
        .with_context(|| format!("{field} is not an integer"))
}

fn validate_timestamp_ranges(
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
) -> Result<()> {
    if !(1..=12).contains(&month) {
        bail!("month out of range");
    }
    if !(1..=31).contains(&day) {
        bail!("day out of range");
    }
    if !(0..=23).contains(&hour) {
        bail!("hour out of range");
    }
    if !(0..=59).contains(&minute) {
        bail!("minute out of range");
    }
    if !(0..=60).contains(&second) {
        bail!("second out of range");
    }
    Ok(())
}

fn timestamp_is_stale(generated_seconds: i64, max_age_days: u64) -> bool {
    let now_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let Ok(generated_seconds) = u64::try_from(generated_seconds) else {
        return true;
    };
    now_seconds.saturating_sub(generated_seconds) > max_age_days.saturating_mul(86_400)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let adjusted_year = if month <= 2 { year - 1 } else { year };
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let year_of_era = adjusted_year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn escape_markdown_table_cell(raw: &str) -> String {
    raw.replace('|', "\\|")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    struct SampleBundle {
        root: TempDir,
        manifest: ProofBundleManifest,
    }

    fn sample_bundle() -> SampleBundle {
        let root = tempfile::tempdir().expect("tempdir");
        let mut lanes = Vec::new();
        for (index, lane_id) in REQUIRED_PROOF_BUNDLE_LANES.iter().enumerate() {
            let raw_log_path = format!("logs/{lane_id}.log");
            let summary_path = format!("summaries/{lane_id}.md");
            let input_path = format!("inputs/{lane_id}.json");
            let artifact_path = format!("artifacts/{lane_id}.json");

            write_file(root.path(), &raw_log_path, &format!("{lane_id} raw log\n"));
            write_file(root.path(), &summary_path, &format!("# {lane_id}\n"));
            write_file(
                root.path(),
                &input_path,
                &format!("{{\"lane\":\"{lane_id}\"}}\n"),
            );
            write_file(
                root.path(),
                &artifact_path,
                &format!("{{\"artifact\":\"{lane_id}\"}}\n"),
            );

            let artifact_hash =
                sha256_file_hex(&root.path().join(&artifact_path)).expect("artifact hash");
            let status = match index % 4 {
                0 => ProofBundleOutcome::Pass,
                1 => ProofBundleOutcome::Fail,
                2 => ProofBundleOutcome::Skip,
                _ => ProofBundleOutcome::Error,
            };
            lanes.push(ProofBundleLane {
                lane_id: (*lane_id).to_owned(),
                status,
                raw_log_path,
                summary_path,
                scenario_ids: vec![format!("{lane_id}_scenario_primary")],
                gate_inputs: vec![input_path],
                artifacts: vec![ProofBundleArtifact {
                    path: artifact_path,
                    sha256: artifact_hash,
                    redacted: index % 2 == 0,
                    role: "primary_evidence".to_owned(),
                }],
            });
        }

        let mut manifest = ProofBundleManifest {
            schema_version: PROOF_BUNDLE_SCHEMA_VERSION,
            bundle_id: "proof-bundle-sample".to_owned(),
            generated_at: "2030-01-01T00:00:00Z".to_owned(),
            git_sha: "abcdef1".to_owned(),
            toolchain: "rustc 1.85.0-nightly".to_owned(),
            kernel: "Linux 6.10.0".to_owned(),
            mount_capability: "available".to_owned(),
            required_lanes: proof_bundle_required_lanes(),
            lanes,
            redaction: ProofBundleRedactionPolicy {
                redacted_fields: vec!["hostname".to_owned(), "api_key".to_owned()],
                preserved_fields: PRESERVED_REDACTION_FIELDS
                    .iter()
                    .map(|field| (*field).to_owned())
                    .collect(),
                reproduction_command:
                    "cargo run -p ffs-harness -- validate-proof-bundle --bundle manifest.json"
                        .to_owned(),
                policy_version: "redaction-v1".to_owned(),
                redacted_value_placeholder: "[REDACTED]".to_owned(),
                forbidden_unredacted_markers: vec!["SECRET_TOKEN".to_owned()],
                require_placeholder_in_redacted_artifacts: false,
            },
            integrity: None,
        };
        manifest.integrity = Some(integrity_for(&manifest));
        SampleBundle { root, manifest }
    }

    fn integrity_for(manifest: &ProofBundleManifest) -> ProofBundleIntegrityPolicy {
        ProofBundleIntegrityPolicy {
            artifact_hash_chain_sha256: artifact_hash_chain_sha256(manifest),
            artifact_count: manifest_artifact_count(manifest),
            redaction_policy_version: manifest.redaction.policy_version.clone(),
        }
    }

    fn write_file(root: &Path, relative: &str, text: &str) {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent dir");
        }
        fs::write(path, text).expect("write fixture");
    }

    fn validate_sample(sample: &SampleBundle) -> ProofBundleValidationReport {
        validate_proof_bundle_manifest(
            &sample.manifest,
            sample.root.path(),
            &sample.root.path().join("manifest.json"),
            Some("abcdef1"),
            Some(10_000),
        )
    }

    #[test]
    fn valid_sample_bundle_passes() {
        let sample = sample_bundle();
        let report = validate_sample(&sample);
        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.totals.lanes, REQUIRED_PROOF_BUNDLE_LANES.len());
        assert_eq!(report.totals.pass, 3);
        assert_eq!(report.totals.fail, 3);
        assert_eq!(report.totals.skip, 3);
        assert_eq!(report.totals.error, 2);
    }

    #[test]
    fn required_lanes_cover_operator_readiness_sections() {
        let lanes = proof_bundle_required_lanes();
        for required in [
            "conformance",
            "xfstests",
            "fuse",
            "differential_oracle",
            "repair_lab",
            "crash_replay",
            "performance",
            "writeback_cache",
            "scrub_repair_status",
            "known_deferrals",
            "release_gates",
        ] {
            assert!(
                lanes.iter().any(|lane| lane == required),
                "missing required proof-bundle lane {required}"
            );
        }
    }

    #[test]
    fn missing_required_lane_is_rejected() {
        let mut sample = sample_bundle();
        sample
            .manifest
            .lanes
            .retain(|lane| lane.lane_id != "known_deferrals");
        let report = validate_sample(&sample);
        assert!(!report.valid);
        assert!(
            report
                .missing_required_lanes
                .contains(&"known_deferrals".to_owned())
        );
    }

    #[test]
    fn stale_sha_and_schema_are_rejected() {
        let mut sample = sample_bundle();
        sample.manifest.schema_version = 0;
        let report = validate_proof_bundle_manifest(
            &sample.manifest,
            sample.root.path(),
            &sample.root.path().join("manifest.json"),
            Some("1234567"),
            Some(10_000),
        );
        assert!(!report.valid);
        assert!(report.stale_git_sha.is_some());
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("stale schema_version"))
        );
    }

    #[test]
    fn stale_timestamp_is_rejected() {
        let mut sample = sample_bundle();
        sample.manifest.generated_at = "2000-01-01T00:00:00Z".to_owned();
        let report = validate_proof_bundle_manifest(
            &sample.manifest,
            sample.root.path(),
            &sample.root.path().join("manifest.json"),
            Some("abcdef1"),
            Some(1),
        );
        assert!(!report.valid);
        assert!(report.stale_timestamp.is_some());
    }

    #[test]
    fn artifact_hash_mismatch_is_rejected() {
        let mut sample = sample_bundle();
        sample.manifest.lanes[0].artifacts[0].sha256 =
            "0000000000000000000000000000000000000000000000000000000000000000".to_owned();
        let report = validate_sample(&sample);
        assert!(!report.valid);
        assert_eq!(report.artifact_hash_mismatches.len(), 1);
    }

    #[test]
    fn broken_links_are_rejected() {
        let mut sample = sample_bundle();
        sample.manifest.lanes[0].raw_log_path = "logs/missing.log".to_owned();
        let report = validate_sample(&sample);
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("broken link"))
        );
    }

    #[test]
    fn duplicate_scenario_ids_are_rejected() {
        let mut sample = sample_bundle();
        let duplicate = sample.manifest.lanes[0].scenario_ids[0].clone();
        sample.manifest.lanes[1].scenario_ids[0] = duplicate;
        let report = validate_sample(&sample);
        assert!(!report.valid);
        assert_eq!(report.duplicate_scenario_ids.len(), 1);
    }

    #[test]
    fn redaction_cannot_remove_reproduction_command() {
        let mut sample = sample_bundle();
        sample.manifest.redaction.redacted_fields = vec!["reproduction_command".to_owned()];
        sample
            .manifest
            .redaction
            .preserved_fields
            .retain(|field| field != "reproduction_command");
        let report = validate_sample(&sample);
        assert!(!report.valid);
        assert!(
            report
                .redaction_errors
                .iter()
                .any(|error| error.contains("reproduction_command"))
        );
    }

    #[test]
    fn artifact_hash_chain_mismatch_is_rejected() {
        let mut sample = sample_bundle();
        sample
            .manifest
            .integrity
            .as_mut()
            .expect("integrity")
            .artifact_hash_chain_sha256 =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned();
        let report = validate_sample(&sample);
        assert!(!report.valid);
        assert!(
            report
                .integrity_errors
                .iter()
                .any(|error| error.contains("artifact hash-chain mismatch"))
        );
        assert!(report.artifact_hash_chain.is_some());
    }

    #[test]
    fn artifact_count_and_redaction_version_are_integrity_checked() {
        let mut sample = sample_bundle();
        let integrity = sample.manifest.integrity.as_mut().expect("integrity");
        integrity.artifact_count += 1;
        integrity.redaction_policy_version = "wrong-redaction-version".to_owned();
        let report = validate_sample(&sample);
        assert!(!report.valid);
        assert!(
            report
                .integrity_errors
                .iter()
                .any(|error| error.contains("artifact_count"))
        );
        assert!(
            report
                .integrity_errors
                .iter()
                .any(|error| error.contains("redaction_policy_version"))
        );
    }

    #[test]
    fn artifact_reports_preserve_lane_path_hash_and_role() {
        let sample = sample_bundle();
        let report = validate_sample(&sample);
        assert_eq!(
            report.artifact_reports.len(),
            REQUIRED_PROOF_BUNDLE_LANES.len()
        );
        let conformance = report
            .artifact_reports
            .iter()
            .find(|artifact| artifact.lane_id == "conformance")
            .expect("conformance artifact");
        assert_eq!(conformance.path, "artifacts/conformance.json");
        assert_eq!(conformance.sha256.len(), 64);
        assert_eq!(conformance.role, "primary_evidence");
    }

    #[test]
    fn redaction_leaks_are_rejected_from_artifacts_and_summaries() {
        let sample = sample_bundle();
        write_file(
            sample.root.path(),
            "summaries/conformance.md",
            "# conformance\nSECRET_TOKEN\n",
        );
        write_file(
            sample.root.path(),
            "artifacts/conformance.json",
            "{\"token\":\"SECRET_TOKEN\"}\n",
        );
        let report = validate_sample(&sample);
        assert!(!report.valid);
        assert_eq!(report.redaction_leaks.len(), 2);
        assert!(
            report
                .redaction_errors
                .iter()
                .any(|error| error.contains("redaction leak"))
        );
    }

    #[test]
    fn redacted_artifact_placeholder_can_be_required() {
        let mut sample = sample_bundle();
        sample
            .manifest
            .redaction
            .require_placeholder_in_redacted_artifacts = true;
        let report = validate_sample(&sample);
        assert!(!report.valid);
        assert!(
            report
                .redaction_errors
                .iter()
                .any(|error| error.contains("lacks placeholder"))
        );

        for lane in &mut sample.manifest.lanes {
            for artifact in &mut lane.artifacts {
                if artifact.redacted {
                    write_file(
                        sample.root.path(),
                        &artifact.path,
                        "{\"redacted\":\"[REDACTED]\"}\n",
                    );
                    artifact.sha256 =
                        sha256_file_hex(&sample.root.path().join(&artifact.path)).expect("hash");
                }
            }
        }
        sample.manifest.integrity = Some(integrity_for(&sample.manifest));
        let report = validate_sample(&sample);
        assert!(report.valid, "{:?}", report.errors);
    }

    #[test]
    fn summary_contains_totals_lanes_logs_and_artifacts() {
        let sample = sample_bundle();
        let report = validate_sample(&sample);
        let summary = render_proof_bundle_markdown(&report);
        assert!(summary.contains("Totals: pass=3 fail=3 skip=3 error=2"));
        assert!(summary.contains("[logs/conformance.log](logs/conformance.log)"));
        assert!(summary.contains("scrub_repair_status"));
        assert!(summary.contains("known_deferrals"));
        assert!(summary.contains("writeback_cache"));
        assert!(summary.contains("Artifact hash chain"));
    }
}
