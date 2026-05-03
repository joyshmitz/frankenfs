#![allow(clippy::module_name_repetitions, clippy::too_many_lines)]
#![forbid(unsafe_code)]

//! Adversarial-image and hostile-artifact threat model for `bd-rchk0.5.11`.
//!
//! This module validates the security/safety contract that downstream fuzzing,
//! E2E, proof-bundle, release-gate, and operator-doc work must consume. It does
//! not run heavyweight hostile-image campaigns; it makes the fail-closed contract
//! executable and smoke-testable.

use crate::artifact_manifest::{
    ArtifactCategory, ArtifactEntry, ArtifactManifest, EnvironmentFingerprint, GateVerdict,
    ManifestBuilder, ScenarioResult, validate_manifest,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};

pub const ADVERSARIAL_THREAT_MODEL_SCHEMA_VERSION: u32 = 1;

const REQUIRED_LOG_FIELDS: [&str; 20] = [
    "threat_scenario_id",
    "input_hash",
    "parser_capability",
    "mount_capability",
    "repair_capability",
    "resource_controls",
    "expected_safe_behavior",
    "expected_classification",
    "observed_classification",
    "resource_limits",
    "observed_input_bytes",
    "observed_cpu_ms",
    "observed_wall_ms",
    "observed_memory_mib",
    "observed_disk_bytes",
    "enforcement_point",
    "cleanup_status",
    "artifact_paths",
    "remediation_id",
    "reproduction_command",
];

const REQUIRED_THREAT_CLASSES: [ThreatClass; 7] = [
    ThreatClass::MalformedImage,
    ThreatClass::HostileArtifactPath,
    ThreatClass::MissingHostCapability,
    ThreatClass::ResourceExhaustion,
    ThreatClass::RepairLedgerTamper,
    ThreatClass::UnsupportedMountOption,
    ThreatClass::UnsafeOperatorCommand,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdversarialThreatModel {
    pub schema_version: u32,
    pub model_id: String,
    pub shared_qa_schema_version: u32,
    pub release_gate_contract: ThreatReleaseGateContract,
    pub required_log_fields: Vec<String>,
    pub required_threat_classes: Vec<ThreatClass>,
    pub scenarios: Vec<ThreatScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatReleaseGateContract {
    pub hostile_image_readiness_feature_id: String,
    pub docs_claims_require_valid_artifact: bool,
    pub unreviewed_critical_behavior: ReleaseGateEffect,
    pub minimum_public_state_without_valid_artifact: PublicSecurityState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatScenario {
    pub scenario_id: String,
    pub threat_class: ThreatClass,
    pub severity: ThreatSeverity,
    pub review_status: ThreatReviewStatus,
    pub input_kind: ThreatInputKind,
    pub input_hash: String,
    pub parser_capability: ThreatCapability,
    pub mount_capability: ThreatCapability,
    pub repair_capability: ThreatCapability,
    pub hostile_path: String,
    pub hostile_path_kind: HostileArtifactPathKind,
    pub expected_path_decision: ArtifactPathDecision,
    pub expected_safe_behavior: ExpectedSafeBehavior,
    pub expected_classification: ObservedThreatClassification,
    pub observed_classification: ObservedThreatClassification,
    pub resource_controls: Vec<ThreatResourceControl>,
    pub resource_limits: ThreatResourceLimits,
    pub observed_resource_counters: ThreatObservedResourceCounters,
    pub cleanup_status: ThreatCleanupStatus,
    pub artifact_paths: Vec<String>,
    pub release_gate_effect: ReleaseGateEffect,
    pub remediation_id: String,
    pub reproduction_command: String,
    pub public_status_context: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatClass {
    MalformedImage,
    HostileArtifactPath,
    MissingHostCapability,
    ResourceExhaustion,
    RepairLedgerTamper,
    UnsupportedMountOption,
    UnsafeOperatorCommand,
}

impl ThreatClass {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MalformedImage => "malformed_image",
            Self::HostileArtifactPath => "hostile_artifact_path",
            Self::MissingHostCapability => "missing_host_capability",
            Self::ResourceExhaustion => "resource_exhaustion",
            Self::RepairLedgerTamper => "repair_ledger_tamper",
            Self::UnsupportedMountOption => "unsupported_mount_option",
            Self::UnsafeOperatorCommand => "unsafe_operator_command",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatSeverity {
    Critical,
    High,
    Medium,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatReviewStatus {
    Reviewed,
    Unreviewed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatInputKind {
    Ext4Image,
    BtrfsImage,
    ProofBundle,
    RepairLedger,
    FuseMountRequest,
    OperatorCommand,
    CorpusSeed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatCapability {
    Available,
    Missing,
    NotApplicable,
}

impl ThreatCapability {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Missing => "missing",
            Self::NotApplicable => "not_applicable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostileArtifactPathKind {
    Normal,
    Symlink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactPathDecision {
    AcceptConfined,
    RefuseTraversal,
    RefuseAbsolute,
    RefuseSymlink,
    RefuseEmpty,
}

impl ArtifactPathDecision {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AcceptConfined => "accept_confined",
            Self::RefuseTraversal => "refuse_traversal",
            Self::RefuseAbsolute => "refuse_absolute",
            Self::RefuseSymlink => "refuse_symlink",
            Self::RefuseEmpty => "refuse_empty",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedSafeBehavior {
    RejectBeforeMount,
    ClassifyUnsupported,
    DegradeToReadOnly,
    CapResources,
    Quarantine,
    RefuseMutation,
    RefuseHostPath,
    PreserveEvidence,
}

impl ExpectedSafeBehavior {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::RejectBeforeMount => "reject_before_mount",
            Self::ClassifyUnsupported => "classify_unsupported",
            Self::DegradeToReadOnly => "degrade_to_read_only",
            Self::CapResources => "cap_resources",
            Self::Quarantine => "quarantine",
            Self::RefuseMutation => "refuse_mutation",
            Self::RefuseHostPath => "refuse_host_path",
            Self::PreserveEvidence => "preserve_evidence",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedThreatClassification {
    Rejected,
    Unsupported,
    DetectionOnly,
    Capped,
    Quarantined,
    MutationRefused,
    HostPathRefused,
    EvidencePreserved,
}

impl ObservedThreatClassification {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Rejected => "rejected",
            Self::Unsupported => "unsupported",
            Self::DetectionOnly => "detection_only",
            Self::Capped => "capped",
            Self::Quarantined => "quarantined",
            Self::MutationRefused => "mutation_refused",
            Self::HostPathRefused => "host_path_refused",
            Self::EvidencePreserved => "evidence_preserved",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatResourceLimits {
    pub max_input_bytes: u64,
    pub max_wall_ms: u64,
    pub max_memory_mib: u32,
    pub max_artifact_bytes: u64,
    pub max_log_bytes: u64,
    pub max_file_descriptors: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatResourceControl {
    pub resource_class: ThreatResourceClass,
    pub limit_value: u64,
    pub limit_unit: ThreatResourceLimitUnit,
    pub enforcement_point: ThreatEnforcementPoint,
    pub cleanup_policy: ThreatCleanupPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatResourceClass {
    InputBytes,
    CpuTime,
    WallTime,
    Memory,
    DiskSpace,
    ArtifactSpace,
    ArtifactCount,
    LogOutput,
    FileDescriptors,
}

impl ThreatResourceClass {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::InputBytes => "input_bytes",
            Self::CpuTime => "cpu_time",
            Self::WallTime => "wall_time",
            Self::Memory => "memory",
            Self::DiskSpace => "disk_space",
            Self::ArtifactSpace => "artifact_space",
            Self::ArtifactCount => "artifact_count",
            Self::LogOutput => "log_output",
            Self::FileDescriptors => "file_descriptors",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatResourceLimitUnit {
    Bytes,
    Milliseconds,
    Mib,
    Count,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatEnforcementPoint {
    Ext4Parser,
    BtrfsParser,
    MountPreflight,
    RepairLedgerIngestion,
    ProofBundleValidation,
    OperatorCommandPreflight,
    FuzzCorpusSmoke,
}

impl ThreatEnforcementPoint {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ext4Parser => "ext4_parser",
            Self::BtrfsParser => "btrfs_parser",
            Self::MountPreflight => "mount_preflight",
            Self::RepairLedgerIngestion => "repair_ledger_ingestion",
            Self::ProofBundleValidation => "proof_bundle_validation",
            Self::OperatorCommandPreflight => "operator_command_preflight",
            Self::FuzzCorpusSmoke => "fuzz_corpus_smoke",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatCleanupPolicy {
    CleanWorkspace,
    QuarantineArtifacts,
    PreserveEvidence,
    RefuseBeforeMutation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatObservedResourceCounters {
    pub input_bytes: u64,
    pub wall_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mib: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_descriptors: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatCleanupStatus {
    Clean,
    PreservedArtifacts,
    Quarantined,
    Failed,
    NotRun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseGateEffect {
    FailClosed,
    DowngradeToDetectionOnly,
    BlockMutatingClaim,
    FollowUpOnly,
}

impl ReleaseGateEffect {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::DowngradeToDetectionOnly => "downgrade_to_detection_only",
            Self::BlockMutatingClaim => "block_mutating_claim",
            Self::FollowUpOnly => "follow_up_only",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicSecurityState {
    Hidden,
    Blocked,
    DetectionOnly,
    Experimental,
    Validated,
}

impl PublicSecurityState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Hidden => "hidden",
            Self::Blocked => "blocked",
            Self::DetectionOnly => "detection_only",
            Self::Experimental => "experimental",
            Self::Validated => "validated",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatScenarioEvaluation {
    pub scenario_id: String,
    pub threat_class: String,
    pub input_hash: String,
    pub parser_capability: String,
    pub mount_capability: String,
    pub repair_capability: String,
    pub expected_safe_behavior: String,
    pub expected_classification: String,
    pub observed_classification: String,
    pub path_decision: String,
    pub resource_controls: Vec<ThreatResourceControl>,
    pub release_gate_effect: String,
    pub cleanup_status: ThreatCleanupStatus,
    pub resource_limits: ThreatResourceLimits,
    pub observed_resource_counters: ThreatObservedResourceCounters,
    pub primary_enforcement_point: String,
    pub artifact_paths: Vec<String>,
    pub remediation_id: String,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityStatusWording {
    pub feature_id: String,
    pub state: String,
    pub docs_wording_id: String,
    pub wording: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdversarialThreatModelReport {
    pub schema_version: u32,
    pub model_id: String,
    pub valid: bool,
    pub scenario_count: usize,
    pub required_log_fields: Vec<String>,
    pub required_threat_classes: Vec<String>,
    pub evaluated_scenarios: Vec<ThreatScenarioEvaluation>,
    pub sample_artifact_manifest_errors: Vec<String>,
    pub generated_security_wording: Vec<SecurityStatusWording>,
    pub errors: Vec<String>,
}

pub fn load_adversarial_threat_model(path: &Path) -> Result<AdversarialThreatModel> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read adversarial threat model {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("invalid adversarial threat model JSON {}", path.display()))
}

#[must_use]
pub fn validate_adversarial_threat_model(
    model: &AdversarialThreatModel,
    artifact_root: &str,
) -> AdversarialThreatModelReport {
    let mut errors = Vec::new();
    validate_model_shape(model, &mut errors);
    let evaluated_scenarios = evaluate_scenarios(model, &mut errors);
    let sample_artifact_manifest = build_adversarial_threat_model_sample_artifact_manifest(
        model,
        artifact_root,
        &evaluated_scenarios,
    );
    let sample_artifact_manifest_errors = validate_manifest(&sample_artifact_manifest)
        .into_iter()
        .map(|error| format!("{error:?}"))
        .collect::<Vec<_>>();
    errors.extend(
        sample_artifact_manifest_errors
            .iter()
            .map(|error| format!("sample artifact manifest invalid: {error}")),
    );
    let valid = errors.is_empty();

    AdversarialThreatModelReport {
        schema_version: ADVERSARIAL_THREAT_MODEL_SCHEMA_VERSION,
        model_id: model.model_id.clone(),
        valid,
        scenario_count: model.scenarios.len(),
        required_log_fields: model.required_log_fields.clone(),
        required_threat_classes: model
            .required_threat_classes
            .iter()
            .map(|threat_class| threat_class.label().to_owned())
            .collect(),
        evaluated_scenarios,
        sample_artifact_manifest_errors,
        generated_security_wording: generate_security_status_wording(model, valid),
        errors,
    }
}

pub fn fail_on_adversarial_threat_model_errors(
    report: &AdversarialThreatModelReport,
) -> Result<()> {
    if report.valid {
        Ok(())
    } else {
        bail!(
            "adversarial threat model validation failed with {} error(s)",
            report.errors.len()
        )
    }
}

#[must_use]
pub fn classify_hostile_artifact_path(
    raw_path: &str,
    path_kind: HostileArtifactPathKind,
) -> ArtifactPathDecision {
    if raw_path.trim().is_empty() {
        return ArtifactPathDecision::RefuseEmpty;
    }
    if path_kind == HostileArtifactPathKind::Symlink {
        return ArtifactPathDecision::RefuseSymlink;
    }

    let path = Path::new(raw_path);
    if path.is_absolute() {
        return ArtifactPathDecision::RefuseAbsolute;
    }
    for component in path.components() {
        match component {
            Component::ParentDir => return ArtifactPathDecision::RefuseTraversal,
            Component::Prefix(_) | Component::RootDir => {
                return ArtifactPathDecision::RefuseAbsolute;
            }
            Component::CurDir | Component::Normal(_) => {}
        }
    }
    ArtifactPathDecision::AcceptConfined
}

#[must_use]
pub fn redact_host_path(text: &str) -> String {
    text.split_whitespace()
        .map(|token| {
            if token.starts_with('/') {
                "<redacted-host-path>"
            } else {
                token
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[must_use]
pub fn build_adversarial_threat_model_sample_artifact_manifest(
    model: &AdversarialThreatModel,
    artifact_root: &str,
    evaluations: &[ThreatScenarioEvaluation],
) -> ArtifactManifest {
    let mut builder = ManifestBuilder::new(
        "adversarial_threat_model_dry_run",
        "adversarial_threat_model",
        "2026-05-03T00:00:00Z",
    )
    .bead_id("bd-0qx9b")
    .git_context("dry-run", "main", true)
    .environment(EnvironmentFingerprint {
        hostname: "dry-run-host".to_owned(),
        cpu_model: "dry-run-cpu".to_owned(),
        cpu_count: 64,
        memory_gib: 256,
        kernel: "dry-run-kernel".to_owned(),
        rustc_version: "dry-run-rustc".to_owned(),
        cargo_version: Some("dry-run-cargo".to_owned()),
    })
    .scenario(
        "adversarial_threat_model_validate",
        ScenarioResult::Pass,
        Some("adversarial threat model dry-run validation"),
        0.0,
    )
    .artifact(ArtifactEntry {
        path: format!("{artifact_root}/threat_model_report.json"),
        category: ArtifactCategory::SummaryReport,
        content_type: Some("application/json".to_owned()),
        size_bytes: 0,
        sha256: None,
        redacted: false,
        metadata: BTreeMap::from([
            ("model_id".to_owned(), model.model_id.clone()),
            ("bead_id".to_owned(), "bd-0qx9b".to_owned()),
        ]),
    });

    for evaluation in evaluations {
        builder = builder.artifact(ArtifactEntry {
            path: format!(
                "{artifact_root}/logs/{}.json",
                evaluation.scenario_id.replace('/', "_")
            ),
            category: ArtifactCategory::RawLog,
            content_type: Some("application/json".to_owned()),
            size_bytes: 0,
            sha256: None,
            redacted: true,
            metadata: BTreeMap::from([
                ("scenario_id".to_owned(), evaluation.scenario_id.clone()),
                ("threat_class".to_owned(), evaluation.threat_class.clone()),
                (
                    "expected_safe_behavior".to_owned(),
                    evaluation.expected_safe_behavior.clone(),
                ),
                (
                    "release_gate_effect".to_owned(),
                    evaluation.release_gate_effect.clone(),
                ),
                (
                    "primary_enforcement_point".to_owned(),
                    evaluation.primary_enforcement_point.clone(),
                ),
                (
                    "artifact_path_count".to_owned(),
                    evaluation.artifact_paths.len().to_string(),
                ),
            ]),
        });
    }

    builder
        .artifact(ArtifactEntry {
            path: format!("{artifact_root}/repro/adversarial_threat_model_repro.json"),
            category: ArtifactCategory::ReproPack,
            content_type: Some("application/json".to_owned()),
            size_bytes: 0,
            sha256: None,
            redacted: true,
            metadata: BTreeMap::from([(
                "reproduction_command".to_owned(),
                "ffs-harness validate-adversarial-threat-model --model security/adversarial_image_threat_model.json".to_owned(),
            )]),
        })
        .verdict(GateVerdict::Pass)
        .build()
}

fn validate_model_shape(model: &AdversarialThreatModel, errors: &mut Vec<String>) {
    if model.schema_version != ADVERSARIAL_THREAT_MODEL_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version {} expected {}",
            model.schema_version, ADVERSARIAL_THREAT_MODEL_SCHEMA_VERSION
        ));
    }
    validate_nonempty("model_id", &model.model_id, errors);
    validate_release_gate_contract(&model.release_gate_contract, errors);
    validate_required_log_fields(&model.required_log_fields, errors);
    validate_required_threat_classes(&model.required_threat_classes, errors);
    if model.scenarios.is_empty() {
        errors.push("scenarios must not be empty".to_owned());
    }
}

fn validate_release_gate_contract(contract: &ThreatReleaseGateContract, errors: &mut Vec<String>) {
    validate_nonempty(
        "release_gate_contract.hostile_image_readiness_feature_id",
        &contract.hostile_image_readiness_feature_id,
        errors,
    );
    if !contract.docs_claims_require_valid_artifact {
        errors.push(
            "release_gate_contract.docs_claims_require_valid_artifact must be true".to_owned(),
        );
    }
    if contract.unreviewed_critical_behavior != ReleaseGateEffect::FailClosed {
        errors.push(
            "release_gate_contract.unreviewed_critical_behavior must be fail_closed".to_owned(),
        );
    }
    if contract.minimum_public_state_without_valid_artifact > PublicSecurityState::DetectionOnly {
        errors.push(
            "release_gate_contract.minimum_public_state_without_valid_artifact must not exceed detection_only".to_owned(),
        );
    }
}

fn validate_required_log_fields(observed: &[String], errors: &mut Vec<String>) {
    let observed = observed.iter().map(String::as_str).collect::<BTreeSet<_>>();
    for required in REQUIRED_LOG_FIELDS {
        if !observed.contains(required) {
            errors.push(format!("required_log_fields missing {required}"));
        }
    }
}

fn validate_required_threat_classes(observed: &[ThreatClass], errors: &mut Vec<String>) {
    let observed = observed.iter().copied().collect::<BTreeSet<_>>();
    for required in REQUIRED_THREAT_CLASSES {
        if !observed.contains(&required) {
            errors.push(format!(
                "required_threat_classes missing {}",
                required.label()
            ));
        }
    }
}

fn evaluate_scenarios(
    model: &AdversarialThreatModel,
    errors: &mut Vec<String>,
) -> Vec<ThreatScenarioEvaluation> {
    let declared_threat_classes = model
        .required_threat_classes
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut scenario_ids = BTreeMap::<&str, usize>::new();
    let mut covered = BTreeSet::new();
    let mut evaluations = Vec::new();

    for scenario in &model.scenarios {
        validate_scenario(scenario, &declared_threat_classes, &mut covered, errors);
        *scenario_ids
            .entry(scenario.scenario_id.as_str())
            .or_default() += 1;
        evaluations.push(evaluate_scenario(scenario));
    }

    for (scenario_id, count) in scenario_ids {
        if count > 1 {
            errors.push(format!("duplicate threat scenario id {scenario_id}"));
        }
    }
    for required in REQUIRED_THREAT_CLASSES {
        if !covered.contains(&required) {
            errors.push(format!("no scenario covers {}", required.label()));
        }
    }

    evaluations
}

fn validate_scenario(
    scenario: &ThreatScenario,
    declared_threat_classes: &BTreeSet<ThreatClass>,
    covered: &mut BTreeSet<ThreatClass>,
    errors: &mut Vec<String>,
) {
    validate_nonempty("scenario_id", &scenario.scenario_id, errors);
    validate_nonempty("input_hash", &scenario.input_hash, errors);
    validate_nonempty("hostile_path", &scenario.hostile_path, errors);
    validate_nonempty("remediation_id", &scenario.remediation_id, errors);
    validate_nonempty(
        "reproduction_command",
        &scenario.reproduction_command,
        errors,
    );
    validate_nonempty(
        "public_status_context",
        &scenario.public_status_context,
        errors,
    );

    if !declared_threat_classes.contains(&scenario.threat_class) {
        errors.push(format!(
            "scenario {} references undeclared threat class {}",
            scenario.scenario_id,
            scenario.threat_class.label()
        ));
    }
    covered.insert(scenario.threat_class);

    if !looks_like_sha256(&scenario.input_hash) {
        errors.push(format!(
            "scenario {} input_hash must be 64 lowercase hex chars",
            scenario.scenario_id
        ));
    }

    let observed_decision =
        classify_hostile_artifact_path(&scenario.hostile_path, scenario.hostile_path_kind);
    if observed_decision != scenario.expected_path_decision {
        errors.push(format!(
            "scenario {} expected path decision {} but classifier returned {}",
            scenario.scenario_id,
            scenario.expected_path_decision.label(),
            observed_decision.label()
        ));
    }

    if scenario.expected_classification != scenario.observed_classification {
        errors.push(format!(
            "scenario {} expected classification {} but observed {}",
            scenario.scenario_id,
            scenario.expected_classification.label(),
            scenario.observed_classification.label()
        ));
    }

    validate_artifact_paths(scenario, errors);
    validate_cleanup_contract(scenario, errors);
    validate_resource_limits(scenario, errors);
    validate_resource_controls(scenario, errors);
    validate_observed_resource_counters(scenario, errors);
    validate_fail_closed_contract(scenario, errors);
    validate_safe_behavior_matches_threat_class(scenario, errors);
}

fn validate_artifact_paths(scenario: &ThreatScenario, errors: &mut Vec<String>) {
    if scenario.artifact_paths.is_empty() {
        errors.push(format!(
            "scenario {} artifact_paths must not be empty",
            scenario.scenario_id
        ));
    }
    for artifact_path in &scenario.artifact_paths {
        let decision =
            classify_hostile_artifact_path(artifact_path, HostileArtifactPathKind::Normal);
        if decision != ArtifactPathDecision::AcceptConfined {
            errors.push(format!(
                "scenario {} artifact path {} is not confined: {}",
                scenario.scenario_id,
                artifact_path,
                decision.label()
            ));
        }
    }
}

fn validate_cleanup_contract(scenario: &ThreatScenario, errors: &mut Vec<String>) {
    match scenario.cleanup_status {
        ThreatCleanupStatus::Clean
        | ThreatCleanupStatus::PreservedArtifacts
        | ThreatCleanupStatus::Quarantined => {}
        ThreatCleanupStatus::Failed | ThreatCleanupStatus::NotRun => errors.push(format!(
            "scenario {} cleanup_status must be clean, preserved_artifacts, or quarantined",
            scenario.scenario_id
        )),
    }
    if scenario.observed_classification == ObservedThreatClassification::Quarantined
        && scenario.cleanup_status != ThreatCleanupStatus::Quarantined
    {
        errors.push(format!(
            "scenario {} quarantined classification requires quarantined cleanup status",
            scenario.scenario_id
        ));
    }
}

fn validate_resource_limits(scenario: &ThreatScenario, errors: &mut Vec<String>) {
    let limits = scenario.resource_limits;
    if limits.max_input_bytes == 0
        || limits.max_wall_ms == 0
        || limits.max_memory_mib == 0
        || limits.max_artifact_bytes == 0
        || limits.max_log_bytes == 0
        || limits.max_file_descriptors == 0
    {
        errors.push(format!(
            "scenario {} resource limits must be positive",
            scenario.scenario_id
        ));
    }
    if scenario.threat_class == ThreatClass::ResourceExhaustion
        && !matches!(
            scenario.expected_safe_behavior,
            ExpectedSafeBehavior::CapResources | ExpectedSafeBehavior::Quarantine
        )
    {
        errors.push(format!(
            "scenario {} resource exhaustion must cap or quarantine resources",
            scenario.scenario_id
        ));
    }
}

fn validate_resource_controls(scenario: &ThreatScenario, errors: &mut Vec<String>) {
    if scenario.resource_controls.is_empty() {
        errors.push(format!(
            "scenario {} resource_controls must not be empty",
            scenario.scenario_id
        ));
        return;
    }

    let mut classes = BTreeSet::new();
    let mut has_wall_time = false;
    let mut has_artifact_space = false;

    for control in &scenario.resource_controls {
        if control.limit_value == 0 {
            errors.push(format!(
                "scenario {} resource control {} limit_value must be positive",
                scenario.scenario_id,
                control.resource_class.label()
            ));
        }
        if !classes.insert(control.resource_class) {
            errors.push(format!(
                "scenario {} duplicates resource control {}",
                scenario.scenario_id,
                control.resource_class.label()
            ));
        }
        if !resource_unit_matches_class(control.resource_class, control.limit_unit) {
            errors.push(format!(
                "scenario {} resource control {} uses incompatible unit {:?}",
                scenario.scenario_id,
                control.resource_class.label(),
                control.limit_unit
            ));
        }
        validate_resource_control_with_limits(scenario, control, errors);
        has_wall_time |= control.resource_class == ThreatResourceClass::WallTime;
        has_artifact_space |= control.resource_class == ThreatResourceClass::ArtifactSpace;
    }

    if !has_wall_time {
        errors.push(format!(
            "scenario {} resource_controls missing wall_time",
            scenario.scenario_id
        ));
    }
    if !has_artifact_space {
        errors.push(format!(
            "scenario {} resource_controls missing artifact_space",
            scenario.scenario_id
        ));
    }
    if scenario.threat_class == ThreatClass::ResourceExhaustion {
        for required in [
            ThreatResourceClass::InputBytes,
            ThreatResourceClass::WallTime,
            ThreatResourceClass::Memory,
            ThreatResourceClass::ArtifactSpace,
            ThreatResourceClass::LogOutput,
            ThreatResourceClass::FileDescriptors,
        ] {
            if !classes.contains(&required) {
                errors.push(format!(
                    "scenario {} resource exhaustion missing {} control",
                    scenario.scenario_id,
                    required.label()
                ));
            }
        }
    }
}

fn resource_unit_matches_class(
    resource_class: ThreatResourceClass,
    unit: ThreatResourceLimitUnit,
) -> bool {
    matches!(
        (resource_class, unit),
        (
            ThreatResourceClass::InputBytes
                | ThreatResourceClass::DiskSpace
                | ThreatResourceClass::ArtifactSpace
                | ThreatResourceClass::LogOutput,
            ThreatResourceLimitUnit::Bytes
        ) | (
            ThreatResourceClass::CpuTime | ThreatResourceClass::WallTime,
            ThreatResourceLimitUnit::Milliseconds
        ) | (ThreatResourceClass::Memory, ThreatResourceLimitUnit::Mib)
            | (
                ThreatResourceClass::ArtifactCount | ThreatResourceClass::FileDescriptors,
                ThreatResourceLimitUnit::Count
            )
    )
}

fn validate_resource_control_with_limits(
    scenario: &ThreatScenario,
    control: &ThreatResourceControl,
    errors: &mut Vec<String>,
) {
    let limit = match control.resource_class {
        ThreatResourceClass::InputBytes => Some(scenario.resource_limits.max_input_bytes),
        ThreatResourceClass::WallTime => Some(scenario.resource_limits.max_wall_ms),
        ThreatResourceClass::Memory => Some(u64::from(scenario.resource_limits.max_memory_mib)),
        ThreatResourceClass::ArtifactSpace => Some(scenario.resource_limits.max_artifact_bytes),
        ThreatResourceClass::LogOutput => Some(scenario.resource_limits.max_log_bytes),
        ThreatResourceClass::FileDescriptors => {
            Some(u64::from(scenario.resource_limits.max_file_descriptors))
        }
        ThreatResourceClass::CpuTime
        | ThreatResourceClass::DiskSpace
        | ThreatResourceClass::ArtifactCount => None,
    };
    if let Some(limit) = limit
        && control.limit_value > limit
    {
        errors.push(format!(
            "scenario {} resource control {} limit {} exceeds coarse limit {}",
            scenario.scenario_id,
            control.resource_class.label(),
            control.limit_value,
            limit
        ));
    }
}

fn validate_observed_resource_counters(scenario: &ThreatScenario, errors: &mut Vec<String>) {
    let counters = &scenario.observed_resource_counters;
    if counters.input_bytes > scenario.resource_limits.max_input_bytes {
        errors.push(format!(
            "scenario {} observed input bytes {} exceed max_input_bytes {}",
            scenario.scenario_id, counters.input_bytes, scenario.resource_limits.max_input_bytes
        ));
    }
    if counters.wall_ms > scenario.resource_limits.max_wall_ms {
        errors.push(format!(
            "scenario {} observed wall_ms {} exceed max_wall_ms {}",
            scenario.scenario_id, counters.wall_ms, scenario.resource_limits.max_wall_ms
        ));
    }

    for control in &scenario.resource_controls {
        validate_observed_counter_for_control(scenario, control, errors);
    }
}

fn validate_observed_counter_for_control(
    scenario: &ThreatScenario,
    control: &ThreatResourceControl,
    errors: &mut Vec<String>,
) {
    let counters = &scenario.observed_resource_counters;
    match control.resource_class {
        ThreatResourceClass::InputBytes => {
            validate_u64_observed_counter(
                scenario,
                control,
                "input_bytes",
                Some(counters.input_bytes),
                errors,
            );
        }
        ThreatResourceClass::CpuTime => {
            validate_u64_observed_counter(scenario, control, "cpu_ms", counters.cpu_ms, errors);
        }
        ThreatResourceClass::WallTime => {
            validate_u64_observed_counter(
                scenario,
                control,
                "wall_ms",
                Some(counters.wall_ms),
                errors,
            );
        }
        ThreatResourceClass::Memory => {
            validate_u64_observed_counter(
                scenario,
                control,
                "memory_mib",
                counters.memory_mib.map(u64::from),
                errors,
            );
        }
        ThreatResourceClass::DiskSpace => {
            validate_u64_observed_counter(
                scenario,
                control,
                "disk_bytes",
                counters.disk_bytes,
                errors,
            );
        }
        ThreatResourceClass::ArtifactSpace => {
            validate_u64_observed_counter(
                scenario,
                control,
                "artifact_bytes",
                counters.artifact_bytes,
                errors,
            );
        }
        ThreatResourceClass::ArtifactCount => {
            validate_u64_observed_counter(
                scenario,
                control,
                "artifact_count",
                counters.artifact_count.map(u64::from),
                errors,
            );
        }
        ThreatResourceClass::LogOutput => {
            validate_u64_observed_counter(
                scenario,
                control,
                "log_bytes",
                counters.log_bytes,
                errors,
            );
        }
        ThreatResourceClass::FileDescriptors => {
            validate_u64_observed_counter(
                scenario,
                control,
                "file_descriptors",
                counters.file_descriptors.map(u64::from),
                errors,
            );
        }
    }
}

fn validate_u64_observed_counter(
    scenario: &ThreatScenario,
    control: &ThreatResourceControl,
    counter_name: &str,
    observed: Option<u64>,
    errors: &mut Vec<String>,
) {
    let Some(observed) = observed else {
        errors.push(format!(
            "scenario {} missing observed counter {} for {}",
            scenario.scenario_id,
            counter_name,
            control.resource_class.label()
        ));
        return;
    };
    if observed > control.limit_value {
        errors.push(format!(
            "scenario {} observed counter {}={} exceeds {} limit {}",
            scenario.scenario_id,
            counter_name,
            observed,
            control.resource_class.label(),
            control.limit_value
        ));
    }
}

fn validate_fail_closed_contract(scenario: &ThreatScenario, errors: &mut Vec<String>) {
    if scenario.severity == ThreatSeverity::Critical
        && scenario.review_status != ThreatReviewStatus::Reviewed
    {
        errors.push(format!(
            "critical threat scenario {} must be reviewed or release gates fail closed",
            scenario.scenario_id
        ));
    }
    if scenario.severity == ThreatSeverity::Critical
        && scenario.release_gate_effect != ReleaseGateEffect::FailClosed
    {
        errors.push(format!(
            "critical threat scenario {} must use fail_closed release gate effect",
            scenario.scenario_id
        ));
    }
    if scenario.severity == ThreatSeverity::Critical
        && matches!(
            scenario.observed_classification,
            ObservedThreatClassification::DetectionOnly
                | ObservedThreatClassification::EvidencePreserved
        )
    {
        errors.push(format!(
            "critical threat scenario {} must reject, cap, quarantine, refuse, or classify unsupported",
            scenario.scenario_id
        ));
    }
}

fn validate_safe_behavior_matches_threat_class(
    scenario: &ThreatScenario,
    errors: &mut Vec<String>,
) {
    match scenario.threat_class {
        ThreatClass::MalformedImage => {
            if scenario.expected_safe_behavior != ExpectedSafeBehavior::RejectBeforeMount {
                errors.push(format!(
                    "scenario {} malformed images must reject before mount",
                    scenario.scenario_id
                ));
            }
        }
        ThreatClass::HostileArtifactPath => {
            if scenario.expected_safe_behavior != ExpectedSafeBehavior::RefuseHostPath {
                errors.push(format!(
                    "scenario {} hostile artifact paths must refuse host paths",
                    scenario.scenario_id
                ));
            }
            if scenario.expected_path_decision == ArtifactPathDecision::AcceptConfined {
                errors.push(format!(
                    "scenario {} hostile artifact path must not be accepted as confined",
                    scenario.scenario_id
                ));
            }
        }
        ThreatClass::MissingHostCapability | ThreatClass::UnsupportedMountOption => {
            if scenario.expected_safe_behavior != ExpectedSafeBehavior::ClassifyUnsupported {
                errors.push(format!(
                    "scenario {} host capability or unsupported option must classify unsupported",
                    scenario.scenario_id
                ));
            }
        }
        ThreatClass::ResourceExhaustion => {
            if !matches!(
                scenario.expected_safe_behavior,
                ExpectedSafeBehavior::CapResources | ExpectedSafeBehavior::Quarantine
            ) {
                errors.push(format!(
                    "scenario {} resource exhaustion must cap or quarantine resources",
                    scenario.scenario_id
                ));
            }
        }
        ThreatClass::RepairLedgerTamper | ThreatClass::UnsafeOperatorCommand => {
            if scenario.expected_safe_behavior != ExpectedSafeBehavior::RefuseMutation {
                errors.push(format!(
                    "scenario {} repair ledger or operator command threat must refuse mutation",
                    scenario.scenario_id
                ));
            }
        }
    }
}

fn evaluate_scenario(scenario: &ThreatScenario) -> ThreatScenarioEvaluation {
    ThreatScenarioEvaluation {
        scenario_id: scenario.scenario_id.clone(),
        threat_class: scenario.threat_class.label().to_owned(),
        input_hash: scenario.input_hash.clone(),
        parser_capability: scenario.parser_capability.label().to_owned(),
        mount_capability: scenario.mount_capability.label().to_owned(),
        repair_capability: scenario.repair_capability.label().to_owned(),
        expected_safe_behavior: scenario.expected_safe_behavior.label().to_owned(),
        expected_classification: scenario.expected_classification.label().to_owned(),
        observed_classification: scenario.observed_classification.label().to_owned(),
        path_decision: scenario.expected_path_decision.label().to_owned(),
        resource_controls: scenario.resource_controls.clone(),
        release_gate_effect: scenario.release_gate_effect.label().to_owned(),
        cleanup_status: scenario.cleanup_status,
        resource_limits: scenario.resource_limits,
        observed_resource_counters: scenario.observed_resource_counters.clone(),
        primary_enforcement_point: scenario.resource_controls.first().map_or_else(
            || "missing".to_owned(),
            |control| control.enforcement_point.label().to_owned(),
        ),
        artifact_paths: scenario.artifact_paths.clone(),
        remediation_id: scenario.remediation_id.clone(),
        reproduction_command: redact_host_path(&scenario.reproduction_command),
    }
}

fn generate_security_status_wording(
    model: &AdversarialThreatModel,
    valid: bool,
) -> Vec<SecurityStatusWording> {
    let state = if valid {
        model
            .release_gate_contract
            .minimum_public_state_without_valid_artifact
    } else {
        PublicSecurityState::Blocked
    };
    let wording = format!(
        "Hostile-image safety is {} and evidence-gated: ordinary corruption repair, unsupported formats, detection-only behavior, and mutating repair readiness are separate claims; docs alone cannot promote {} without a fresh adversarial threat-model artifact.",
        state.label(),
        model
            .release_gate_contract
            .hostile_image_readiness_feature_id
    );

    vec![SecurityStatusWording {
        feature_id: model
            .release_gate_contract
            .hostile_image_readiness_feature_id
            .clone(),
        state: state.label().to_owned(),
        docs_wording_id: "hostile_image_safety_status_v1".to_owned(),
        wording,
    }]
}

fn validate_nonempty(field: &str, value: &str, errors: &mut Vec<String>) {
    if value.trim().is_empty() {
        errors.push(format!("{field} must not be empty"));
    }
}

fn looks_like_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_model() -> AdversarialThreatModel {
        serde_json::from_str(include_str!(
            "../../../security/adversarial_image_threat_model.json"
        ))
        .expect("checked-in adversarial threat model parses")
    }

    #[test]
    fn checked_in_model_validates_and_generates_wording() {
        let model = sample_model();
        let report = validate_adversarial_threat_model(&model, "artifacts/security/dry-run");
        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.scenario_count, 17);
        assert_eq!(report.sample_artifact_manifest_errors, Vec::<String>::new());
        assert!(
            report
                .evaluated_scenarios
                .iter()
                .any(|scenario| scenario.path_decision == "refuse_traversal")
        );
        assert!(
            report.generated_security_wording[0]
                .wording
                .contains("docs alone cannot promote")
        );
    }

    #[test]
    fn path_classifier_refuses_traversal_absolute_symlink_and_empty() {
        assert_eq!(
            classify_hostile_artifact_path(
                "proof/../../etc/passwd",
                HostileArtifactPathKind::Normal
            ),
            ArtifactPathDecision::RefuseTraversal
        );
        assert_eq!(
            classify_hostile_artifact_path("/etc/passwd", HostileArtifactPathKind::Normal),
            ArtifactPathDecision::RefuseAbsolute
        );
        assert_eq!(
            classify_hostile_artifact_path("proof/current.json", HostileArtifactPathKind::Symlink),
            ArtifactPathDecision::RefuseSymlink
        );
        assert_eq!(
            classify_hostile_artifact_path(" ", HostileArtifactPathKind::Normal),
            ArtifactPathDecision::RefuseEmpty
        );
        assert_eq!(
            classify_hostile_artifact_path("proof/current.json", HostileArtifactPathKind::Normal),
            ArtifactPathDecision::AcceptConfined
        );
    }

    #[test]
    fn rejects_missing_required_threat_class() {
        let mut model = sample_model();
        model
            .required_threat_classes
            .retain(|class| *class != ThreatClass::ResourceExhaustion);
        let report = validate_adversarial_threat_model(&model, "artifacts/security");
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("required_threat_classes missing resource_exhaustion"))
        );
    }

    #[test]
    fn rejects_path_traversal_mismatch() {
        let mut model = sample_model();
        model.scenarios[0].hostile_path = "proof/../../etc/passwd".to_owned();
        model.scenarios[0].expected_path_decision = ArtifactPathDecision::AcceptConfined;
        let report = validate_adversarial_threat_model(&model, "artifacts/security");
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("classifier returned refuse_traversal"))
        );
    }

    #[test]
    fn rejects_symlink_path_when_expected_as_confined() {
        let mut model = sample_model();
        let scenario = model
            .scenarios
            .iter_mut()
            .find(|scenario| scenario.scenario_id == "hostile_proof_bundle_symlink_refused")
            .expect("symlink scenario exists");
        scenario.expected_path_decision = ArtifactPathDecision::AcceptConfined;
        let report = validate_adversarial_threat_model(&model, "artifacts/security");
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("classifier returned refuse_symlink"))
        );
    }

    #[test]
    fn rejects_unreviewed_critical_threats() {
        let mut model = sample_model();
        model.scenarios[0].review_status = ThreatReviewStatus::Unreviewed;
        let report = validate_adversarial_threat_model(&model, "artifacts/security");
        assert!(!report.valid);
        assert!(report.errors.iter().any(|error| {
            error.contains("critical threat scenario malformed_ext4_superblock_reject_before_mount")
        }));
    }

    #[test]
    fn rejects_zero_resource_caps() {
        let mut model = sample_model();
        model.scenarios[0].resource_limits.max_wall_ms = 0;
        let report = validate_adversarial_threat_model(&model, "artifacts/security");
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("resource limits must be positive"))
        );
    }

    #[test]
    fn rejects_unsafe_operator_command_promotion() {
        let mut model = sample_model();
        let scenario = model
            .scenarios
            .iter_mut()
            .find(|scenario| scenario.scenario_id == "unsafe_repair_operator_command_refused")
            .expect("operator scenario exists");
        scenario.release_gate_effect = ReleaseGateEffect::FollowUpOnly;
        let report = validate_adversarial_threat_model(&model, "artifacts/security");
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("must use fail_closed release gate effect"))
        );
    }

    #[test]
    fn invalid_units_and_enums_fail_during_parse() {
        let mut value = json!(sample_model());
        value["scenarios"][0]["expected_safe_behavior"] = json!("run_anyway");
        let parsed = serde_json::from_value::<AdversarialThreatModel>(value);
        assert!(parsed.is_err());
    }

    #[test]
    fn redacts_absolute_host_paths_from_wording() {
        let redacted = redact_host_path("open /home/user/private.img with /tmp/ledger.jsonl");
        assert_eq!(
            redacted,
            "open <redacted-host-path> with <redacted-host-path>"
        );
    }

    #[test]
    fn sample_artifact_manifest_maps_to_shared_qa_schema() {
        let model = sample_model();
        let report = validate_adversarial_threat_model(&model, "artifacts/security/dry-run");
        let artifact_manifest = build_adversarial_threat_model_sample_artifact_manifest(
            &model,
            "artifacts/security/dry-run",
            &report.evaluated_scenarios,
        );
        let errors = validate_manifest(&artifact_manifest);
        assert_eq!(errors, Vec::new());
        assert_eq!(artifact_manifest.gate_id, "adversarial_threat_model");
        assert_eq!(artifact_manifest.bead_id.as_deref(), Some("bd-0qx9b"));
        assert!(
            artifact_manifest
                .artifacts
                .iter()
                .any(|artifact| artifact.category == ArtifactCategory::ReproPack)
        );
    }

    #[test]
    fn checked_in_model_covers_bounded_hostile_fixture_matrix() {
        let model = sample_model();
        let report = validate_adversarial_threat_model(&model, "artifacts/security/dry-run");
        assert!(report.valid, "{:?}", report.errors);
        let scenario_ids = report
            .evaluated_scenarios
            .iter()
            .map(|scenario| scenario.scenario_id.as_str())
            .collect::<BTreeSet<_>>();
        for required in [
            "oversized_metadata_seed_capped",
            "cyclic_metadata_reference_quarantined",
            "deeply_nested_directory_capped",
            "huge_xattr_payload_capped",
            "truncated_repair_ledger_quarantined",
            "corrupt_repair_ledger_quarantined",
            "hostile_proof_bundle_traversal_refused",
            "hostile_proof_bundle_symlink_refused",
            "excessive_log_output_capped",
            "excessive_artifact_count_capped",
            "timeout_capped",
            "file_descriptor_exhaustion_capped",
        ] {
            assert!(scenario_ids.contains(required), "missing {required}");
        }
    }

    #[test]
    fn rejects_missing_resource_controls() {
        let mut model = sample_model();
        model.scenarios[0].resource_controls.clear();
        let report = validate_adversarial_threat_model(&model, "artifacts/security");
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("resource_controls must not be empty"))
        );
    }

    #[test]
    fn rejects_resource_control_unit_mismatch() {
        let mut model = sample_model();
        model.scenarios[0].resource_controls[0].limit_unit = ThreatResourceLimitUnit::Count;
        let report = validate_adversarial_threat_model(&model, "artifacts/security");
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("uses incompatible unit"))
        );
    }

    #[test]
    fn rejects_expected_classification_mismatch() {
        let mut model = sample_model();
        model.scenarios[0].expected_classification = ObservedThreatClassification::Capped;
        let report = validate_adversarial_threat_model(&model, "artifacts/security");
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("expected classification capped but observed rejected"))
        );
    }

    #[test]
    fn rejects_observed_counter_over_limit() {
        let mut model = sample_model();
        model.scenarios[0].observed_resource_counters.wall_ms =
            model.scenarios[0].resource_limits.max_wall_ms + 1;
        let report = validate_adversarial_threat_model(&model, "artifacts/security");
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("observed wall_ms"))
        );
    }

    #[test]
    fn rejects_artifact_path_traversal() {
        let mut model = sample_model();
        model.scenarios[0]
            .artifact_paths
            .push("artifacts/security/../../host_escape.json".to_owned());
        let report = validate_adversarial_threat_model(&model, "artifacts/security");
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("is not confined"))
        );
    }

    #[test]
    fn rejects_cleanup_failure() {
        let mut model = sample_model();
        model.scenarios[0].cleanup_status = ThreatCleanupStatus::Failed;
        let report = validate_adversarial_threat_model(&model, "artifacts/security");
        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("cleanup_status must be clean"))
        );
    }
}
