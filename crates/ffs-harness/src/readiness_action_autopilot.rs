#![allow(clippy::module_name_repetitions, clippy::too_many_lines)]
#![forbid(unsafe_code)]

//! Schema and deterministic fixtures for readiness-action planning.
//!
//! This module does not choose or execute actions. It defines the evidence
//! envelope consumed by the planner beads that follow `bd-rchk0.98.1`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION: u32 = 1;
pub const READINESS_ACTION_FIXTURE_VALIDATOR_VERSION: u32 = 1;

const REQUIRED_FIXTURE_CLASSIFICATIONS: [ReadinessFixtureClassification; 4] = [
    ReadinessFixtureClassification::LocalSafe,
    ReadinessFixtureClassification::PermissionedBlocked,
    ReadinessFixtureClassification::StaleEvidence,
    ReadinessFixtureClassification::ContradictoryEvidence,
];

const REQUIRED_INPUT_KINDS: [ReadinessActionInputKind; 5] = [
    ReadinessActionInputKind::BeadsJsonl,
    ReadinessActionInputKind::ReleaseGatePolicy,
    ReadinessActionInputKind::ProofBundleReport,
    ReadinessActionInputKind::OperationalReadinessReport,
    ReadinessActionInputKind::HostCapabilityArtifact,
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessActionAutopilotFixtureSet {
    pub schema_version: u32,
    pub fixture_set_id: String,
    pub fixtures: Vec<ReadinessActionAutopilotFixture>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessActionAutopilotFixture {
    pub fixture_id: String,
    pub expected_classification: ReadinessFixtureClassification,
    pub report: ReadinessActionAutopilotReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessFixtureClassification {
    LocalSafe,
    PermissionedBlocked,
    StaleEvidence,
    ContradictoryEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessActionAutopilotReport {
    pub schema_version: u32,
    pub report_id: String,
    pub generated_at: String,
    pub source_inputs: Vec<ReadinessActionInput>,
    pub recommendations: Vec<ReadinessActionRecommendation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessActionInput {
    pub input_id: String,
    pub kind: ReadinessActionInputKind,
    pub path: String,
    pub required: bool,
    pub state: ReadinessActionInputState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessActionInputKind {
    BeadsJsonl,
    ReleaseGatePolicy,
    ProofBundleReport,
    OperationalReadinessReport,
    HostCapabilityArtifact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessActionInputState {
    Present,
    Missing,
    Stale,
    Contradictory,
    PermissionRequired,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessActionRecommendation {
    pub action_id: String,
    pub title: String,
    pub safety_class: ReadinessActionSafetyClass,
    pub controlling_bead: String,
    pub evidence_tier: ReadinessEvidenceTier,
    pub ack_required: bool,
    pub reproduction_command: String,
    pub rationale: String,
    pub public_claim_effect: PublicClaimEffect,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<ReadinessActionDiagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessActionSafetyClass {
    LocalSafe,
    Permissioned,
    Destructive,
    Impossible,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessEvidenceTier {
    TrackerOnly,
    Smoke,
    ProofBundle,
    OperationalReadiness,
    Authoritative,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicClaimEffect {
    NoChange,
    BlockUpgrade,
    DowngradeRequired,
    UpgradeEligible,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessActionDiagnostic {
    pub diagnostic_id: String,
    pub severity: ReadinessActionDiagnosticSeverity,
    pub source_kind: ReadinessActionInputKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    pub message: String,
    pub remediation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_age_days: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freshness_ttl_days: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessActionDiagnosticSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessActionFixtureValidationReport {
    pub schema_version: u32,
    pub validator_version: u32,
    pub fixture_set_id: String,
    pub fixture_count: usize,
    pub valid: bool,
    pub classifications_seen: Vec<ReadinessFixtureClassification>,
    pub input_kinds_seen: Vec<ReadinessActionInputKind>,
    pub safety_classes_seen: Vec<ReadinessActionSafetyClass>,
    pub evidence_tiers_seen: Vec<ReadinessEvidenceTier>,
    pub errors: Vec<String>,
}

#[must_use]
pub fn default_readiness_action_autopilot_fixture_set() -> ReadinessActionAutopilotFixtureSet {
    ReadinessActionAutopilotFixtureSet {
        schema_version: READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION,
        fixture_set_id: "frankenfs_readiness_action_autopilot_fixtures_v1".to_owned(),
        fixtures: vec![
            ReadinessActionAutopilotFixture {
                fixture_id: "local_safe_schema_slice".to_owned(),
                expected_classification: ReadinessFixtureClassification::LocalSafe,
                report: ReadinessActionAutopilotReport {
                    schema_version: READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION,
                    report_id: "readiness_action_local_safe_schema_slice".to_owned(),
                    generated_at: "2026-05-07T00:00:00Z".to_owned(),
                    source_inputs: vec![
                        input(
                            "beads-open-queue",
                            ReadinessActionInputKind::BeadsJsonl,
                            ".beads/issues.jsonl",
                            ReadinessActionInputState::Present,
                        ),
                        input(
                            "release-gate-policy",
                            ReadinessActionInputKind::ReleaseGatePolicy,
                            "crates/ffs-harness/fixtures/release_gate_policy_v1.json",
                            ReadinessActionInputState::Present,
                        ),
                    ],
                    recommendations: vec![ReadinessActionRecommendation {
                        action_id: "define-readiness-action-schema".to_owned(),
                        title: "Define readiness action autopilot schema and fixtures".to_owned(),
                        safety_class: ReadinessActionSafetyClass::LocalSafe,
                        controlling_bead: "bd-rchk0.98.1".to_owned(),
                        evidence_tier: ReadinessEvidenceTier::TrackerOnly,
                        ack_required: false,
                        reproduction_command:
                            "cargo test -p ffs-harness readiness_action_autopilot"
                                .to_owned(),
                        rationale: "The only required changes are local schema and fixture tests."
                            .to_owned(),
                        public_claim_effect: PublicClaimEffect::NoChange,
                        diagnostics: Vec::new(),
                    }],
                },
            },
            ReadinessActionAutopilotFixture {
                fixture_id: "permissioned_xfstests_blocked".to_owned(),
                expected_classification: ReadinessFixtureClassification::PermissionedBlocked,
                report: ReadinessActionAutopilotReport {
                    schema_version: READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION,
                    report_id: "readiness_action_permissioned_xfstests_blocked".to_owned(),
                    generated_at: "2026-05-07T00:00:00Z".to_owned(),
                    source_inputs: vec![
                        input(
                            "beads-open-queue",
                            ReadinessActionInputKind::BeadsJsonl,
                            ".beads/issues.jsonl",
                            ReadinessActionInputState::Present,
                        ),
                        input(
                            "operational-readiness-report",
                            ReadinessActionInputKind::OperationalReadinessReport,
                            "artifacts/readiness/operational_readiness_report.json",
                            ReadinessActionInputState::Missing,
                        ),
                    ],
                    recommendations: vec![ReadinessActionRecommendation {
                        action_id: "run-permissioned-xfstests-baseline".to_owned(),
                        title: "Run permissioned xfstests baseline".to_owned(),
                        safety_class: ReadinessActionSafetyClass::Permissioned,
                        controlling_bead: "bd-rchk3.3".to_owned(),
                        evidence_tier: ReadinessEvidenceTier::OperationalReadiness,
                        ack_required: true,
                        reproduction_command: "XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices scripts/e2e/run_xfstests_baseline.sh".to_owned(),
                        rationale: "The current queue contains xfstests work that cannot run without explicit mutation authorization.".to_owned(),
                        public_claim_effect: PublicClaimEffect::BlockUpgrade,
                        diagnostics: vec![diagnostic(
                            "xfstests-real-run-ack-missing",
                            ReadinessActionDiagnosticSeverity::Error,
                            ReadinessActionInputKind::OperationalReadinessReport,
                            Some("artifacts/readiness/operational_readiness_report.json"),
                            "No real xfstests pass/fail artifact is present.",
                            "Obtain explicit operator authorization before running the mutating baseline.",
                        )],
                    }],
                },
            },
            ReadinessActionAutopilotFixture {
                fixture_id: "stale_large_host_swarm_evidence".to_owned(),
                expected_classification: ReadinessFixtureClassification::StaleEvidence,
                report: ReadinessActionAutopilotReport {
                    schema_version: READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION,
                    report_id: "readiness_action_stale_large_host_swarm_evidence".to_owned(),
                    generated_at: "2026-05-07T00:00:00Z".to_owned(),
                    source_inputs: vec![
                        input(
                            "proof-bundle-report",
                            ReadinessActionInputKind::ProofBundleReport,
                            "artifacts/proof_bundles/swarm_tail_latency.json",
                            ReadinessActionInputState::Stale,
                        ),
                        input(
                            "host-capability-manifest",
                            ReadinessActionInputKind::HostCapabilityArtifact,
                            "artifacts/hosts/large_host_capability.json",
                            ReadinessActionInputState::PermissionRequired,
                        ),
                    ],
                    recommendations: vec![ReadinessActionRecommendation {
                        action_id: "refresh-large-host-swarm-campaign".to_owned(),
                        title: "Refresh large-host swarm responsiveness evidence".to_owned(),
                        safety_class: ReadinessActionSafetyClass::Permissioned,
                        controlling_bead: "bd-rchk0.53.8".to_owned(),
                        evidence_tier: ReadinessEvidenceTier::Authoritative,
                        ack_required: true,
                        reproduction_command: "FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD=1 FFS_SWARM_WORKLOAD_REAL_RUN_ACK=swarm-workload-may-use-permissioned-large-host scripts/e2e/run_swarm_workload_campaign.sh".to_owned(),
                        rationale: "Large-host responsiveness claims require fresh authoritative host evidence.".to_owned(),
                        public_claim_effect: PublicClaimEffect::DowngradeRequired,
                        diagnostics: vec![ReadinessActionDiagnostic {
                            diagnostic_id: "swarm-evidence-stale".to_owned(),
                            severity: ReadinessActionDiagnosticSeverity::Warning,
                            source_kind: ReadinessActionInputKind::ProofBundleReport,
                            source_path: Some(
                                "artifacts/proof_bundles/swarm_tail_latency.json".to_owned(),
                            ),
                            message: "The swarm tail-latency proof bundle is beyond its freshness window.".to_owned(),
                            remediation: "Rerun on a permissioned large host before upgrading readiness wording.".to_owned(),
                            stale_age_days: Some(31),
                            freshness_ttl_days: Some(14),
                        }],
                    }],
                },
            },
            ReadinessActionAutopilotFixture {
                fixture_id: "contradictory_release_gate_claim".to_owned(),
                expected_classification: ReadinessFixtureClassification::ContradictoryEvidence,
                report: ReadinessActionAutopilotReport {
                    schema_version: READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION,
                    report_id: "readiness_action_contradictory_release_gate_claim".to_owned(),
                    generated_at: "2026-05-07T00:00:00Z".to_owned(),
                    source_inputs: vec![
                        input(
                            "release-gate-policy",
                            ReadinessActionInputKind::ReleaseGatePolicy,
                            "crates/ffs-harness/fixtures/release_gate_policy_v1.json",
                            ReadinessActionInputState::Present,
                        ),
                        input(
                            "proof-bundle-report",
                            ReadinessActionInputKind::ProofBundleReport,
                            "artifacts/proof_bundles/release_gate.json",
                            ReadinessActionInputState::Contradictory,
                        ),
                    ],
                    recommendations: vec![ReadinessActionRecommendation {
                        action_id: "refuse-contradictory-readiness-upgrade".to_owned(),
                        title: "Refuse contradictory readiness upgrade".to_owned(),
                        safety_class: ReadinessActionSafetyClass::Impossible,
                        controlling_bead: "bd-rchk0".to_owned(),
                        evidence_tier: ReadinessEvidenceTier::ProofBundle,
                        ack_required: false,
                        reproduction_command: "cargo test -p ffs-harness release_gate -- --nocapture".to_owned(),
                        rationale: "A public readiness upgrade is impossible while proof-bundle and release-gate evidence disagree.".to_owned(),
                        public_claim_effect: PublicClaimEffect::BlockUpgrade,
                        diagnostics: vec![diagnostic(
                            "release-gate-proof-contradiction",
                            ReadinessActionDiagnosticSeverity::Error,
                            ReadinessActionInputKind::ProofBundleReport,
                            Some("artifacts/proof_bundles/release_gate.json"),
                            "The proof bundle contradicts the release-gate policy state.",
                            "Resolve the artifact conflict before changing README or FEATURE_PARITY readiness claims.",
                        )],
                    }],
                },
            },
        ],
    }
}

#[must_use]
pub fn validate_readiness_action_fixture_set(
    fixture_set: &ReadinessActionAutopilotFixtureSet,
) -> ReadinessActionFixtureValidationReport {
    let mut errors = Vec::new();
    let mut classifications_seen = BTreeSet::new();
    let mut input_kinds_seen = BTreeSet::new();
    let mut safety_classes_seen = BTreeSet::new();
    let mut evidence_tiers_seen = BTreeSet::new();

    if fixture_set.schema_version != READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION {
        errors.push(format!(
            "fixture_set schema_version {} must equal {READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION}",
            fixture_set.schema_version
        ));
    }
    if fixture_set.fixture_set_id.trim().is_empty() {
        errors.push("fixture_set_id must be non-empty".to_owned());
    }
    if fixture_set.fixtures.is_empty() {
        errors.push("fixture set must include at least one fixture".to_owned());
    }

    let mut fixture_ids = BTreeSet::new();
    for fixture in &fixture_set.fixtures {
        validate_fixture(
            fixture,
            &mut fixture_ids,
            &mut classifications_seen,
            &mut input_kinds_seen,
            &mut safety_classes_seen,
            &mut evidence_tiers_seen,
            &mut errors,
        );
    }

    for required in REQUIRED_FIXTURE_CLASSIFICATIONS {
        if !classifications_seen.contains(&required) {
            errors.push(format!(
                "missing required fixture classification {required:?}"
            ));
        }
    }
    for required in REQUIRED_INPUT_KINDS {
        if !input_kinds_seen.contains(&required) {
            errors.push(format!("missing required input kind {required:?}"));
        }
    }

    ReadinessActionFixtureValidationReport {
        schema_version: READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION,
        validator_version: READINESS_ACTION_FIXTURE_VALIDATOR_VERSION,
        fixture_set_id: fixture_set.fixture_set_id.clone(),
        fixture_count: fixture_set.fixtures.len(),
        valid: errors.is_empty(),
        classifications_seen: classifications_seen.into_iter().collect(),
        input_kinds_seen: input_kinds_seen.into_iter().collect(),
        safety_classes_seen: safety_classes_seen.into_iter().collect(),
        evidence_tiers_seen: evidence_tiers_seen.into_iter().collect(),
        errors,
    }
}

fn validate_fixture(
    fixture: &ReadinessActionAutopilotFixture,
    fixture_ids: &mut BTreeSet<String>,
    classifications_seen: &mut BTreeSet<ReadinessFixtureClassification>,
    input_kinds_seen: &mut BTreeSet<ReadinessActionInputKind>,
    safety_classes_seen: &mut BTreeSet<ReadinessActionSafetyClass>,
    evidence_tiers_seen: &mut BTreeSet<ReadinessEvidenceTier>,
    errors: &mut Vec<String>,
) {
    let fixture_label = if fixture.fixture_id.trim().is_empty() {
        "<missing-fixture-id>"
    } else {
        fixture.fixture_id.as_str()
    };

    if fixture.fixture_id.trim().is_empty() {
        errors.push("fixture_id must be non-empty".to_owned());
    }
    if !fixture_ids.insert(fixture.fixture_id.clone()) {
        errors.push(format!("duplicate fixture_id {}", fixture.fixture_id));
    }
    classifications_seen.insert(fixture.expected_classification);

    validate_report(
        fixture_label,
        &fixture.report,
        input_kinds_seen,
        safety_classes_seen,
        evidence_tiers_seen,
        errors,
    );
}

fn validate_report(
    fixture_label: &str,
    report: &ReadinessActionAutopilotReport,
    input_kinds_seen: &mut BTreeSet<ReadinessActionInputKind>,
    safety_classes_seen: &mut BTreeSet<ReadinessActionSafetyClass>,
    evidence_tiers_seen: &mut BTreeSet<ReadinessEvidenceTier>,
    errors: &mut Vec<String>,
) {
    if report.schema_version != READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION {
        errors.push(format!(
            "{fixture_label}: report schema_version {} must equal {READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION}",
            report.schema_version
        ));
    }
    if report.report_id.trim().is_empty() {
        errors.push(format!("{fixture_label}: report_id must be non-empty"));
    }
    if report.generated_at.trim().is_empty() {
        errors.push(format!("{fixture_label}: generated_at must be non-empty"));
    }
    if report.source_inputs.is_empty() {
        errors.push(format!(
            "{fixture_label}: source_inputs must include at least one input"
        ));
    }
    if report.recommendations.is_empty() {
        errors.push(format!(
            "{fixture_label}: recommendations must include at least one action"
        ));
    }

    validate_inputs(
        fixture_label,
        &report.source_inputs,
        input_kinds_seen,
        errors,
    );
    validate_recommendations(
        fixture_label,
        &report.recommendations,
        safety_classes_seen,
        evidence_tiers_seen,
        errors,
    );
}

fn validate_inputs(
    fixture_label: &str,
    inputs: &[ReadinessActionInput],
    input_kinds_seen: &mut BTreeSet<ReadinessActionInputKind>,
    errors: &mut Vec<String>,
) {
    let mut input_ids = BTreeSet::new();
    for input in inputs {
        if input.input_id.trim().is_empty() {
            errors.push(format!("{fixture_label}: input_id must be non-empty"));
        }
        if !input_ids.insert(input.input_id.clone()) {
            errors.push(format!(
                "{fixture_label}: duplicate input_id {}",
                input.input_id
            ));
        }
        if input.path.trim().is_empty() {
            errors.push(format!(
                "{fixture_label}: input {} path must be non-empty",
                input.input_id
            ));
        }
        if input.required && input.state == ReadinessActionInputState::NotApplicable {
            errors.push(format!(
                "{fixture_label}: required input {} cannot be not_applicable",
                input.input_id
            ));
        }
        input_kinds_seen.insert(input.kind);
    }
}

fn validate_recommendations(
    fixture_label: &str,
    recommendations: &[ReadinessActionRecommendation],
    safety_classes_seen: &mut BTreeSet<ReadinessActionSafetyClass>,
    evidence_tiers_seen: &mut BTreeSet<ReadinessEvidenceTier>,
    errors: &mut Vec<String>,
) {
    let mut action_ids = BTreeSet::new();
    for recommendation in recommendations {
        validate_recommendation(
            fixture_label,
            recommendation,
            &mut action_ids,
            safety_classes_seen,
            evidence_tiers_seen,
            errors,
        );
    }
}

fn validate_recommendation(
    fixture_label: &str,
    recommendation: &ReadinessActionRecommendation,
    action_ids: &mut BTreeSet<String>,
    safety_classes_seen: &mut BTreeSet<ReadinessActionSafetyClass>,
    evidence_tiers_seen: &mut BTreeSet<ReadinessEvidenceTier>,
    errors: &mut Vec<String>,
) {
    if recommendation.action_id.trim().is_empty() {
        errors.push(format!("{fixture_label}: action_id must be non-empty"));
    }
    if !action_ids.insert(recommendation.action_id.clone()) {
        errors.push(format!(
            "{fixture_label}: duplicate action_id {}",
            recommendation.action_id
        ));
    }
    if recommendation.title.trim().is_empty() {
        errors.push(format!(
            "{fixture_label}: action {} title must be non-empty",
            recommendation.action_id
        ));
    }
    if !recommendation.controlling_bead.starts_with("bd-") {
        errors.push(format!(
            "{fixture_label}: action {} controlling_bead must start with bd-",
            recommendation.action_id
        ));
    }
    if recommendation.reproduction_command.trim().is_empty() {
        errors.push(format!(
            "{fixture_label}: action {} missing reproduction_command",
            recommendation.action_id
        ));
    }
    if recommendation.rationale.trim().is_empty() {
        errors.push(format!(
            "{fixture_label}: action {} rationale must be non-empty",
            recommendation.action_id
        ));
    }
    if requires_ack(recommendation.safety_class) && !recommendation.ack_required {
        errors.push(format!(
            "{fixture_label}: action {} requires ack for {:?}",
            recommendation.action_id, recommendation.safety_class
        ));
    }
    if recommendation.evidence_tier == ReadinessEvidenceTier::Smoke
        && recommendation.public_claim_effect == PublicClaimEffect::UpgradeEligible
    {
        errors.push(format!(
            "{fixture_label}: action {} cannot upgrade public claims from smoke evidence",
            recommendation.action_id
        ));
    }
    if requires_diagnostics(recommendation.safety_class) && recommendation.diagnostics.is_empty() {
        errors.push(format!(
            "{fixture_label}: action {} must include diagnostics for {:?}",
            recommendation.action_id, recommendation.safety_class
        ));
    }

    validate_diagnostics(fixture_label, recommendation, errors);
    safety_classes_seen.insert(recommendation.safety_class);
    evidence_tiers_seen.insert(recommendation.evidence_tier);
}

fn validate_diagnostics(
    fixture_label: &str,
    recommendation: &ReadinessActionRecommendation,
    errors: &mut Vec<String>,
) {
    let mut diagnostic_ids = BTreeSet::new();
    for diagnostic in &recommendation.diagnostics {
        if diagnostic.diagnostic_id.trim().is_empty() {
            errors.push(format!(
                "{fixture_label}: action {} diagnostic_id must be non-empty",
                recommendation.action_id
            ));
        }
        if !diagnostic_ids.insert(diagnostic.diagnostic_id.clone()) {
            errors.push(format!(
                "{fixture_label}: action {} duplicate diagnostic_id {}",
                recommendation.action_id, diagnostic.diagnostic_id
            ));
        }
        if diagnostic.message.trim().is_empty() {
            errors.push(format!(
                "{fixture_label}: diagnostic {} message must be non-empty",
                diagnostic.diagnostic_id
            ));
        }
        if diagnostic.remediation.trim().is_empty() {
            errors.push(format!(
                "{fixture_label}: diagnostic {} remediation must be non-empty",
                diagnostic.diagnostic_id
            ));
        }
        if diagnostic.stale_age_days.is_some() != diagnostic.freshness_ttl_days.is_some() {
            errors.push(format!(
                "{fixture_label}: diagnostic {} stale age and ttl must be provided together",
                diagnostic.diagnostic_id
            ));
        }
    }
}

const fn requires_ack(safety_class: ReadinessActionSafetyClass) -> bool {
    matches!(
        safety_class,
        ReadinessActionSafetyClass::Permissioned | ReadinessActionSafetyClass::Destructive
    )
}

const fn requires_diagnostics(safety_class: ReadinessActionSafetyClass) -> bool {
    matches!(
        safety_class,
        ReadinessActionSafetyClass::Permissioned | ReadinessActionSafetyClass::Impossible
    )
}

fn input(
    input_id: &str,
    kind: ReadinessActionInputKind,
    path: &str,
    state: ReadinessActionInputState,
) -> ReadinessActionInput {
    ReadinessActionInput {
        input_id: input_id.to_owned(),
        kind,
        path: path.to_owned(),
        required: true,
        state,
        schema_version: Some(READINESS_ACTION_AUTOPILOT_SCHEMA_VERSION),
        digest: None,
    }
}

fn diagnostic(
    diagnostic_id: &str,
    severity: ReadinessActionDiagnosticSeverity,
    source_kind: ReadinessActionInputKind,
    source_path: Option<&str>,
    message: &str,
    remediation: &str,
) -> ReadinessActionDiagnostic {
    ReadinessActionDiagnostic {
        diagnostic_id: diagnostic_id.to_owned(),
        severity,
        source_kind,
        source_path: source_path.map(str::to_owned),
        message: message.to_owned(),
        remediation: remediation.to_owned(),
        stale_age_days: None,
        freshness_ttl_days: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_fixture_set_covers_required_schema_surface() {
        let fixture_set = default_readiness_action_autopilot_fixture_set();
        let report = validate_readiness_action_fixture_set(&fixture_set);

        assert!(report.valid, "{:?}", report.errors);
        assert_eq!(report.fixture_count, 4);
        assert_eq!(
            report.classifications_seen,
            REQUIRED_FIXTURE_CLASSIFICATIONS
        );
        assert_eq!(report.input_kinds_seen, REQUIRED_INPUT_KINDS);
        assert_eq!(
            report.safety_classes_seen,
            vec![
                ReadinessActionSafetyClass::LocalSafe,
                ReadinessActionSafetyClass::Permissioned,
                ReadinessActionSafetyClass::Impossible,
            ]
        );
    }

    #[test]
    fn fixtures_round_trip_with_stable_json() {
        let fixture_set = default_readiness_action_autopilot_fixture_set();
        let first = serde_json::to_string_pretty(&fixture_set).expect("serialize fixtures");
        let reparsed: ReadinessActionAutopilotFixtureSet =
            serde_json::from_str(&first).expect("parse fixtures");
        let second = serde_json::to_string_pretty(&reparsed).expect("serialize reparsed fixtures");

        assert_eq!(fixture_set, reparsed);
        assert_eq!(first, second);
        assert!(
            first.contains(
                "\"fixture_set_id\": \"frankenfs_readiness_action_autopilot_fixtures_v1\""
            )
        );
    }

    #[test]
    fn validation_rejects_missing_required_fields() {
        let mut fixture_set = default_readiness_action_autopilot_fixture_set();
        fixture_set.fixtures[0].report.source_inputs.clear();
        fixture_set.fixtures[0].report.recommendations[0]
            .reproduction_command
            .clear();

        let report = validate_readiness_action_fixture_set(&fixture_set);

        assert!(!report.valid);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("source_inputs must include at least one input"))
        );
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("missing reproduction_command"))
        );
    }

    #[test]
    fn validation_rejects_smoke_upgrade_claims() {
        let mut fixture_set = default_readiness_action_autopilot_fixture_set();
        let recommendation = &mut fixture_set.fixtures[0].report.recommendations[0];
        recommendation.evidence_tier = ReadinessEvidenceTier::Smoke;
        recommendation.public_claim_effect = PublicClaimEffect::UpgradeEligible;

        let report = validate_readiness_action_fixture_set(&fixture_set);

        assert!(!report.valid);
        assert!(
            report.errors.iter().any(|error| {
                error.contains("cannot upgrade public claims from smoke evidence")
            })
        );
    }
}
