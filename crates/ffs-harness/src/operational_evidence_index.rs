#![forbid(unsafe_code)]

//! Latest-truth index over operational evidence artifacts.
//!
//! The index consumes the existing operational readiness aggregation and adds
//! a stable selection layer for Agent Mail updates and proof bundles. It keeps
//! every observed record, but marks only fresh, log-backed, non-downgraded rows
//! as authoritative candidates for the latest truth of a lane/scenario/bead.

use crate::operational_readiness_report::{
    ArtifactRecencyState, OperationalReadinessReport, OperationalReadinessReportConfig,
    ReadinessOutcome, ReadinessScenarioRow, ReadinessTaxonomyClass,
    build_operational_readiness_report,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;

pub const OPERATIONAL_EVIDENCE_INDEX_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalEvidenceIndexConfig {
    pub artifacts_dir: PathBuf,
    pub current_git_sha: Option<String>,
    pub max_artifact_age_days: Option<u32>,
    pub recency_reference_epoch_days: Option<u32>,
}

impl OperationalEvidenceIndexConfig {
    #[must_use]
    pub fn new(artifacts_dir: impl Into<PathBuf>) -> Self {
        Self {
            artifacts_dir: artifacts_dir.into(),
            current_git_sha: None,
            max_artifact_age_days: None,
            recency_reference_epoch_days: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationalEvidenceIndex {
    pub schema_version: u32,
    pub index_id: String,
    pub source_root: String,
    pub readiness_report_id: String,
    pub source_record_count: usize,
    pub selected_record_count: usize,
    pub authoritative_record_count: usize,
    pub stale_record_count: usize,
    pub missing_raw_log_record_count: usize,
    pub conflict_count: usize,
    pub duplicate_run_id_count: usize,
    pub host_downgrade_count: usize,
    pub records: Vec<OperationalEvidenceRecord>,
    pub selections: Vec<OperationalEvidenceSelection>,
    pub conflicts: Vec<OperationalEvidenceConflict>,
    pub duplicate_run_ids: Vec<OperationalEvidenceDuplicateRunId>,
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "flat evidence JSON keeps independent audit booleans queryable"
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationalEvidenceRecord {
    pub record_id: String,
    pub lane_id: String,
    pub scenario_id: String,
    pub bead_id: Option<String>,
    pub git_sha: String,
    pub run_id: String,
    pub gate_id: String,
    pub source_path: String,
    pub source_kind: String,
    pub host_class: OperationalEvidenceHostClass,
    pub freshness: OperationalEvidenceFreshness,
    pub outcome: OperationalEvidenceOutcome,
    pub taxonomy_class: String,
    pub release_claim_effect: OperationalEvidenceReleaseClaimEffect,
    pub raw_log_paths: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub missing_raw_logs: bool,
    pub authoritative: bool,
    pub selected: bool,
    pub stale_git_sha: bool,
    pub stale_artifact: bool,
    pub reproduction_command: Option<String>,
    pub cleanup_status: Option<String>,
    pub remediation_hint: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationalEvidenceSelection {
    pub lane_id: String,
    pub scenario_id: String,
    pub bead_id: Option<String>,
    pub selected_record_id: String,
    pub selected_run_id: String,
    pub selected_source_path: String,
    pub selected_outcome: OperationalEvidenceOutcome,
    pub selected_release_claim_effect: OperationalEvidenceReleaseClaimEffect,
    pub superseded_record_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationalEvidenceConflict {
    pub lane_id: String,
    pub scenario_id: String,
    pub bead_id: Option<String>,
    pub outcomes: Vec<OperationalEvidenceOutcome>,
    pub record_ids: Vec<String>,
    pub source_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationalEvidenceDuplicateRunId {
    pub run_id: String,
    pub record_ids: Vec<String>,
    pub source_paths: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationalEvidenceOutcome {
    Pass,
    Fail,
    Skip,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationalEvidenceFreshness {
    NotChecked,
    Fresh,
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationalEvidenceHostClass {
    PermissionedLargeHost,
    DeveloperSmoke,
    SmallHostSmoke,
    CapabilityDowngraded,
    Unknown,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationalEvidenceReleaseClaimEffect {
    Strengthens,
    Blocks,
    Downgrades,
    FollowUpOnly,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EvidenceKey {
    lane: String,
    scenario: String,
    bead: Option<String>,
}

#[must_use]
pub fn build_operational_evidence_index_from_report(
    report: &OperationalReadinessReport,
) -> OperationalEvidenceIndex {
    let mut records = report
        .scenarios
        .iter()
        .enumerate()
        .map(|(index, row)| build_record(report, row, index))
        .collect::<Vec<_>>();
    let groups = group_records(&records);
    let conflicts = collect_conflicts(&records, &groups);
    let duplicate_run_ids = collect_duplicate_run_ids(&records);
    let selections = select_latest_authoritative_records(&mut records, &groups);

    let selected_record_count = records.iter().filter(|record| record.selected).count();
    let authoritative_record_count = records.iter().filter(|record| record.authoritative).count();
    let stale_record_count = records
        .iter()
        .filter(|record| record.stale_git_sha || record.stale_artifact)
        .count();
    let missing_raw_log_record_count = records
        .iter()
        .filter(|record| record.missing_raw_logs)
        .count();
    let host_downgrade_count = records
        .iter()
        .filter(|record| {
            matches!(
                record.host_class,
                OperationalEvidenceHostClass::CapabilityDowngraded
            )
        })
        .count();

    OperationalEvidenceIndex {
        schema_version: OPERATIONAL_EVIDENCE_INDEX_SCHEMA_VERSION,
        index_id: format!("operational-evidence-index:{}", report.report_id),
        source_root: report.source_root.clone(),
        readiness_report_id: report.report_id.clone(),
        source_record_count: records.len(),
        selected_record_count,
        authoritative_record_count,
        stale_record_count,
        missing_raw_log_record_count,
        conflict_count: conflicts.len(),
        duplicate_run_id_count: duplicate_run_ids.len(),
        host_downgrade_count,
        records,
        selections,
        conflicts,
        duplicate_run_ids,
    }
}

pub fn build_operational_evidence_index(
    config: &OperationalEvidenceIndexConfig,
) -> Result<OperationalEvidenceIndex> {
    let readiness_config = OperationalReadinessReportConfig {
        artifacts_dir: config.artifacts_dir.clone(),
        current_git_sha: config.current_git_sha.clone(),
        max_artifact_age_days: config.max_artifact_age_days,
        recency_reference_epoch_days: config.recency_reference_epoch_days,
    };
    let report = build_operational_readiness_report(&readiness_config)?;
    Ok(build_operational_evidence_index_from_report(&report))
}

#[must_use]
pub fn render_operational_evidence_index_markdown(index: &OperationalEvidenceIndex) -> String {
    let mut out = String::new();
    writeln!(&mut out, "# FrankenFS Operational Evidence Index").ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "- Source root: `{}`", index.source_root).ok();
    writeln!(
        &mut out,
        "- Records: source={} authoritative={} selected={}",
        index.source_record_count, index.authoritative_record_count, index.selected_record_count
    )
    .ok();
    writeln!(
        &mut out,
        "- Diagnostics: stale={} missing_raw_logs={} conflicts={} duplicate_run_ids={} host_downgrades={}",
        index.stale_record_count,
        index.missing_raw_log_record_count,
        index.conflict_count,
        index.duplicate_run_id_count,
        index.host_downgrade_count
    )
    .ok();
    writeln!(&mut out).ok();
    writeln!(&mut out, "## Latest Truth").ok();
    writeln!(
        &mut out,
        "| Lane | Scenario | Bead | Outcome | Effect | Host | Run | Source | Logs |"
    )
    .ok();
    writeln!(&mut out, "|---|---|---|---:|---|---|---|---|---|").ok();
    for selection in &index.selections {
        if let Some(record) = index.records.iter().find(|record| {
            matches!(
                record.record_id.cmp(&selection.selected_record_id),
                Ordering::Equal
            )
        }) {
            writeln!(
                &mut out,
                "| `{}` | `{}` | `{}` | `{:?}` | `{:?}` | `{:?}` | `{}` | `{}` | {} |",
                selection.lane_id,
                selection.scenario_id,
                selection.bead_id.as_deref().unwrap_or(""),
                selection.selected_outcome,
                selection.selected_release_claim_effect,
                record.host_class,
                selection.selected_run_id,
                selection.selected_source_path,
                render_logs(record)
            )
            .ok();
        }
    }
    writeln!(&mut out).ok();
    if !index.conflicts.is_empty() {
        writeln!(&mut out, "## Conflicts").ok();
        for conflict in &index.conflicts {
            writeln!(
                &mut out,
                "- `{}` `{}` bead=`{}` outcomes={} records={}",
                conflict.lane_id,
                conflict.scenario_id,
                conflict.bead_id.as_deref().unwrap_or(""),
                conflict
                    .outcomes
                    .iter()
                    .map(|outcome| format!("{outcome:?}"))
                    .collect::<Vec<_>>()
                    .join(","),
                conflict.record_ids.join(",")
            )
            .ok();
        }
        writeln!(&mut out).ok();
    }
    if !index.duplicate_run_ids.is_empty() {
        writeln!(&mut out, "## Duplicate Run IDs").ok();
        for duplicate in &index.duplicate_run_ids {
            writeln!(
                &mut out,
                "- `{}` records={} sources={}",
                duplicate.run_id,
                duplicate.record_ids.join(","),
                duplicate.source_paths.join(",")
            )
            .ok();
        }
        writeln!(&mut out).ok();
    }
    out
}

fn build_record(
    report: &OperationalReadinessReport,
    row: &ReadinessScenarioRow,
    index: usize,
) -> OperationalEvidenceRecord {
    let raw_log_paths = raw_log_paths(row);
    let missing_raw_logs = row_missing_raw_logs(report, row);
    let stale_artifact = matches!(row.artifact_recency, ArtifactRecencyState::Stale);
    let freshness = freshness(row.artifact_recency);
    let host_class = classify_host_class(row);
    let outcome = evidence_outcome(row.outcome);
    let release_claim_effect =
        release_claim_effect(row, host_class, missing_raw_logs, stale_artifact);
    let authoritative =
        is_authoritative(row, release_claim_effect, missing_raw_logs, stale_artifact);

    OperationalEvidenceRecord {
        record_id: format!(
            "{}:{}:{}:{}:{index}",
            row.workstream,
            row.scenario_id,
            row.owner_bead.as_deref().unwrap_or("none"),
            row.run_id
        ),
        lane_id: row.workstream.clone(),
        scenario_id: row.scenario_id.clone(),
        bead_id: row.owner_bead.clone(),
        git_sha: row.git_commit.clone(),
        run_id: row.run_id.clone(),
        gate_id: row.gate_id.clone(),
        source_path: row.source_path.clone(),
        source_kind: serialized_enum_name(row.source_kind),
        host_class,
        freshness,
        outcome,
        taxonomy_class: serialized_enum_name(row.taxonomy_class),
        release_claim_effect,
        raw_log_paths,
        artifact_refs: row.artifact_refs.clone(),
        missing_raw_logs,
        authoritative,
        selected: false,
        stale_git_sha: row.stale_git_sha,
        stale_artifact,
        reproduction_command: row.reproduction_command.clone(),
        cleanup_status: row.cleanup_status.clone(),
        remediation_hint: row.remediation_hint.clone(),
        detail: row.detail.clone(),
    }
}

fn group_records(records: &[OperationalEvidenceRecord]) -> BTreeMap<EvidenceKey, Vec<usize>> {
    let mut groups: BTreeMap<EvidenceKey, Vec<usize>> = BTreeMap::new();
    for (index, record) in records.iter().enumerate() {
        groups
            .entry(EvidenceKey {
                lane: record.lane_id.clone(),
                scenario: record.scenario_id.clone(),
                bead: record.bead_id.clone(),
            })
            .or_default()
            .push(index);
    }
    groups
}

fn collect_conflicts(
    records: &[OperationalEvidenceRecord],
    groups: &BTreeMap<EvidenceKey, Vec<usize>>,
) -> Vec<OperationalEvidenceConflict> {
    let mut conflicts = Vec::new();
    for (key, indices) in groups {
        let outcomes = indices
            .iter()
            .map(|index| records[*index].outcome)
            .collect::<BTreeSet<_>>();
        if outcomes.len() < 2 {
            continue;
        }
        let record_ids = indices
            .iter()
            .map(|index| records[*index].record_id.clone())
            .collect::<Vec<_>>();
        let source_paths = indices
            .iter()
            .map(|index| records[*index].source_path.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        conflicts.push(OperationalEvidenceConflict {
            lane_id: key.lane.clone(),
            scenario_id: key.scenario.clone(),
            bead_id: key.bead.clone(),
            outcomes: outcomes.into_iter().collect(),
            record_ids,
            source_paths,
        });
    }
    conflicts
}

fn collect_duplicate_run_ids(
    records: &[OperationalEvidenceRecord],
) -> Vec<OperationalEvidenceDuplicateRunId> {
    let mut by_run_id: BTreeMap<&str, Vec<&OperationalEvidenceRecord>> = BTreeMap::new();
    for record in records {
        by_run_id.entry(&record.run_id).or_default().push(record);
    }
    by_run_id
        .into_iter()
        .filter_map(|(run_id, records)| {
            if records.len() < 2 {
                return None;
            }
            Some(OperationalEvidenceDuplicateRunId {
                run_id: run_id.to_owned(),
                record_ids: records
                    .iter()
                    .map(|record| record.record_id.clone())
                    .collect(),
                source_paths: records
                    .iter()
                    .map(|record| record.source_path.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            })
        })
        .collect()
}

fn select_latest_authoritative_records(
    records: &mut [OperationalEvidenceRecord],
    groups: &BTreeMap<EvidenceKey, Vec<usize>>,
) -> Vec<OperationalEvidenceSelection> {
    let mut selected = Vec::new();
    let mut selected_indices = Vec::new();

    for (key, indices) in groups {
        let mut candidates = indices
            .iter()
            .copied()
            .filter(|index| records[*index].authoritative)
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| compare_latest(&records[*left], &records[*right]));
        let Some(selected_index) = candidates.last().copied() else {
            continue;
        };
        let selected_record = &records[selected_index];
        selected_indices.push(selected_index);
        selected.push(OperationalEvidenceSelection {
            lane_id: key.lane.clone(),
            scenario_id: key.scenario.clone(),
            bead_id: key.bead.clone(),
            selected_record_id: selected_record.record_id.clone(),
            selected_run_id: selected_record.run_id.clone(),
            selected_source_path: selected_record.source_path.clone(),
            selected_outcome: selected_record.outcome,
            selected_release_claim_effect: selected_record.release_claim_effect,
            superseded_record_ids: indices
                .iter()
                .filter_map(|index| {
                    if matches!(index.cmp(&selected_index), Ordering::Equal) {
                        None
                    } else {
                        Some(records[*index].record_id.clone())
                    }
                })
                .collect(),
        });
    }

    for index in selected_indices {
        records[index].selected = true;
    }
    selected
}

fn compare_latest(left: &OperationalEvidenceRecord, right: &OperationalEvidenceRecord) -> Ordering {
    left.run_id
        .cmp(&right.run_id)
        .then_with(|| left.source_path.cmp(&right.source_path))
        .then_with(|| left.record_id.cmp(&right.record_id))
}

fn raw_log_paths(row: &ReadinessScenarioRow) -> Vec<String> {
    let mut paths = BTreeSet::new();
    if let Some(path) = &row.stdout_path {
        paths.insert(path.clone());
    }
    if let Some(path) = &row.stderr_path {
        paths.insert(path.clone());
    }
    for artifact in &row.artifact_refs {
        if artifact.to_ascii_lowercase().contains("log") {
            paths.insert(artifact.clone());
        }
    }
    paths.into_iter().collect()
}

fn row_missing_raw_logs(report: &OperationalReadinessReport, row: &ReadinessScenarioRow) -> bool {
    report.missing_log_paths.iter().any(|missing| {
        matches!(missing.source_path.cmp(&row.source_path), Ordering::Equal)
            && (missing.scenario_id.is_none()
                || missing.scenario_id.as_deref().is_some_and(|scenario_id| {
                    matches!(scenario_id.cmp(row.scenario_id.as_str()), Ordering::Equal)
                }))
    })
}

fn freshness(state: ArtifactRecencyState) -> OperationalEvidenceFreshness {
    match state {
        ArtifactRecencyState::NotChecked => OperationalEvidenceFreshness::NotChecked,
        ArtifactRecencyState::Fresh => OperationalEvidenceFreshness::Fresh,
        ArtifactRecencyState::Stale => OperationalEvidenceFreshness::Stale,
    }
}

fn evidence_outcome(outcome: ReadinessOutcome) -> OperationalEvidenceOutcome {
    match outcome {
        ReadinessOutcome::Pass => OperationalEvidenceOutcome::Pass,
        ReadinessOutcome::Fail => OperationalEvidenceOutcome::Fail,
        ReadinessOutcome::Skip => OperationalEvidenceOutcome::Skip,
        ReadinessOutcome::Error => OperationalEvidenceOutcome::Error,
    }
}

fn classify_host_class(row: &ReadinessScenarioRow) -> OperationalEvidenceHostClass {
    if matches!(
        row.taxonomy_class,
        ReadinessTaxonomyClass::HostCapabilitySkip
            | ReadinessTaxonomyClass::AuthoritativeLaneUnavailable
    ) {
        return OperationalEvidenceHostClass::CapabilityDowngraded;
    }

    let Some(host) = row.host_fingerprint.as_deref() else {
        return OperationalEvidenceHostClass::NotApplicable;
    };
    let host = host.to_ascii_lowercase();
    if host.contains("permissioned") || host_is_large(&host) {
        return OperationalEvidenceHostClass::PermissionedLargeHost;
    }
    if host.contains("developer") || host.contains("dev-") {
        return OperationalEvidenceHostClass::DeveloperSmoke;
    }
    if host.contains("small") || host.contains("smoke") || host.contains("local") {
        return OperationalEvidenceHostClass::SmallHostSmoke;
    }
    OperationalEvidenceHostClass::Unknown
}

fn host_is_large(host: &str) -> bool {
    let cpu_large = parse_number_before_token(host, "cpu").is_some_and(|cpu| cpu >= 32);
    let memory_large = parse_number_before_token(host, "gib").is_some_and(|memory| memory >= 128);
    cpu_large || memory_large
}

fn parse_number_before_token(text: &str, token: &str) -> Option<u32> {
    let index = text.rfind(token)?;
    let prefix = &text[..index];
    let digits = prefix
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    if digits.is_empty() {
        return None;
    }
    digits.chars().rev().collect::<String>().parse().ok()
}

fn release_claim_effect(
    row: &ReadinessScenarioRow,
    host_class: OperationalEvidenceHostClass,
    missing_raw_logs: bool,
    stale_artifact: bool,
) -> OperationalEvidenceReleaseClaimEffect {
    if row.stale_git_sha || stale_artifact || missing_raw_logs {
        return OperationalEvidenceReleaseClaimEffect::Downgrades;
    }
    if matches!(
        host_class,
        OperationalEvidenceHostClass::CapabilityDowngraded
    ) {
        return OperationalEvidenceReleaseClaimEffect::Downgrades;
    }
    match row.taxonomy_class {
        ReadinessTaxonomyClass::Pass | ReadinessTaxonomyClass::PassWithExperimentalCaveat => {
            OperationalEvidenceReleaseClaimEffect::Strengthens
        }
        ReadinessTaxonomyClass::ProductFailure
        | ReadinessTaxonomyClass::SecurityRefusal
        | ReadinessTaxonomyClass::UnsafeRepairRefusal => {
            OperationalEvidenceReleaseClaimEffect::Blocks
        }
        ReadinessTaxonomyClass::HostCapabilitySkip
        | ReadinessTaxonomyClass::AuthoritativeLaneUnavailable
        | ReadinessTaxonomyClass::StaleArtifact
        | ReadinessTaxonomyClass::NoisyMeasurement => {
            OperationalEvidenceReleaseClaimEffect::Downgrades
        }
        ReadinessTaxonomyClass::HarnessFailure | ReadinessTaxonomyClass::MissingArtifact => {
            OperationalEvidenceReleaseClaimEffect::FollowUpOnly
        }
        ReadinessTaxonomyClass::UnsupportedByScope => OperationalEvidenceReleaseClaimEffect::None,
    }
}

fn is_authoritative(
    row: &ReadinessScenarioRow,
    release_claim_effect: OperationalEvidenceReleaseClaimEffect,
    missing_raw_logs: bool,
    stale_artifact: bool,
) -> bool {
    !row.stale_git_sha
        && !stale_artifact
        && !missing_raw_logs
        && matches!(
            release_claim_effect,
            OperationalEvidenceReleaseClaimEffect::Strengthens
                | OperationalEvidenceReleaseClaimEffect::Blocks
        )
}

fn render_logs(record: &OperationalEvidenceRecord) -> String {
    if record.raw_log_paths.is_empty() {
        return String::new();
    }
    record
        .raw_log_paths
        .iter()
        .map(|path| format!("`{path}`"))
        .collect::<Vec<_>>()
        .join("<br>")
}

fn serialized_enum_name<T>(value: T) -> String
where
    T: Serialize + std::fmt::Debug,
{
    serde_json::to_value(&value)
        .ok()
        .and_then(|json| json.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{value:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_manifest::{
        ArtifactCategory, ArtifactEntry, ArtifactManifest, CleanupStatus, EnvironmentFingerprint,
        FilesystemFlavor, FuseCapabilityResult, GateVerdict, GitContext, OperationalOutcomeClass,
        OperationalRunContext, OperationalScenarioRecord, READINESS_EVENT_ENVELOPE_VERSION,
        ReadinessEventEnvelope, ReadinessEventSeverity, SCHEMA_VERSION, ScenarioOutcome,
        ScenarioResult, SkipReason, WorkerContext,
    };
    use std::fs;
    use tempfile::TempDir;

    struct EvidenceFixture {
        dir: TempDir,
    }

    impl EvidenceFixture {
        fn new() -> Self {
            Self {
                dir: TempDir::new().expect("tempdir"),
            }
        }

        fn index(&self, current_git_sha: Option<&str>) -> OperationalEvidenceIndex {
            let config = OperationalEvidenceIndexConfig {
                artifacts_dir: self.dir.path().to_path_buf(),
                current_git_sha: current_git_sha.map(str::to_owned),
                max_artifact_age_days: None,
                recency_reference_epoch_days: None,
            };
            build_operational_evidence_index(&config).expect("index builds")
        }

        fn index_with_recency(
            &self,
            current_git_sha: Option<&str>,
            max_artifact_age_days: u32,
            reference_epoch_days: u32,
        ) -> OperationalEvidenceIndex {
            let config = OperationalEvidenceIndexConfig {
                artifacts_dir: self.dir.path().to_path_buf(),
                current_git_sha: current_git_sha.map(str::to_owned),
                max_artifact_age_days: Some(max_artifact_age_days),
                recency_reference_epoch_days: Some(reference_epoch_days),
            };
            build_operational_evidence_index(&config).expect("index builds")
        }

        fn write_manifest(&self, name: &str, manifest: &ArtifactManifest) {
            fs::write(
                self.dir.path().join(name),
                serde_json::to_string_pretty(manifest).expect("manifest serializes"),
            )
            .expect("write manifest");
        }

        fn touch(&self, path: &str) {
            let path = self.dir.path().join(path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create parent");
            }
            fs::write(path, "log\n").expect("write fixture file");
        }
    }

    #[test]
    fn selects_newest_authoritative_artifact_and_preserves_conflict() {
        let fixture = EvidenceFixture::new();
        let old = sample_manifest(SampleManifestInput {
            run_id: "run_20260501",
            scenario_id: "mounted_ext4_rw",
            commit: "abc123",
            classification: OperationalOutcomeClass::Fail,
            result: ScenarioResult::Fail,
            error_class: Some(crate::artifact_manifest::OperationalErrorClass::ProductFailure),
            skip_reason: None,
            created_at: "2026-05-01T00:00:00Z",
            include_log_artifacts: true,
            cpu_count: 64,
            memory_gib: 256,
        });
        let new = sample_manifest(SampleManifestInput {
            run_id: "run_20260509",
            scenario_id: "mounted_ext4_rw",
            commit: "abc123",
            classification: OperationalOutcomeClass::Pass,
            result: ScenarioResult::Pass,
            error_class: None,
            skip_reason: None,
            created_at: "2026-05-09T00:00:00Z",
            include_log_artifacts: true,
            cpu_count: 64,
            memory_gib: 256,
        });
        touch_manifest_logs(&fixture, &old);
        touch_manifest_logs(&fixture, &new);
        fixture.write_manifest("old.json", &old);
        fixture.write_manifest("new.json", &new);

        let index = fixture.index(Some("abc123"));

        assert_eq!(index.conflict_count, 1);
        assert_eq!(index.selected_record_count, 1);
        let selection = index.selections.first().expect("selection");
        assert_eq!(selection.selected_run_id, "run_20260509");
        assert_eq!(selection.selected_outcome, OperationalEvidenceOutcome::Pass);
        assert_eq!(selection.superseded_record_ids.len(), 1);
    }

    #[test]
    fn duplicate_run_ids_are_reported_without_hiding_records() {
        let fixture = EvidenceFixture::new();
        for scenario_id in ["xfstests_generic_001", "xfstests_generic_002"] {
            let manifest = sample_manifest(SampleManifestInput {
                run_id: "run_duplicate",
                scenario_id,
                commit: "abc123",
                classification: OperationalOutcomeClass::Pass,
                result: ScenarioResult::Pass,
                error_class: None,
                skip_reason: None,
                created_at: "2026-05-09T00:00:00Z",
                include_log_artifacts: true,
                cpu_count: 64,
                memory_gib: 256,
            });
            touch_manifest_logs(&fixture, &manifest);
            fixture.write_manifest(&format!("{scenario_id}.json"), &manifest);
        }

        let index = fixture.index(Some("abc123"));

        assert_eq!(index.source_record_count, 2);
        assert_eq!(index.duplicate_run_id_count, 1);
        assert_eq!(index.duplicate_run_ids[0].run_id, "run_duplicate");
        assert_eq!(index.duplicate_run_ids[0].record_ids.len(), 2);
    }

    #[test]
    fn stale_git_shas_and_missing_raw_logs_are_non_authoritative() {
        let fixture = EvidenceFixture::new();
        let stale = sample_manifest(SampleManifestInput {
            run_id: "run_stale_sha",
            scenario_id: "proof_bundle_stale",
            commit: "oldsha",
            classification: OperationalOutcomeClass::Pass,
            result: ScenarioResult::Pass,
            error_class: None,
            skip_reason: None,
            created_at: "2026-05-05T00:00:00Z",
            include_log_artifacts: true,
            cpu_count: 64,
            memory_gib: 256,
        });
        let missing_logs = sample_manifest(SampleManifestInput {
            run_id: "run_missing_logs",
            scenario_id: "proof_bundle_missing_logs",
            commit: "abc123",
            classification: OperationalOutcomeClass::Pass,
            result: ScenarioResult::Pass,
            error_class: None,
            skip_reason: None,
            created_at: "2026-05-09T00:00:00Z",
            include_log_artifacts: false,
            cpu_count: 64,
            memory_gib: 256,
        });
        touch_manifest_logs(&fixture, &stale);
        fixture.write_manifest("stale.json", &stale);
        fixture.write_manifest("missing.json", &missing_logs);

        let index = fixture.index(Some("abc123"));

        assert_eq!(index.stale_record_count, 1);
        assert_eq!(index.missing_raw_log_record_count, 1);
        assert_eq!(index.authoritative_record_count, 0);
        assert!(index.records.iter().any(|record| {
            matches!(record.run_id.as_str().cmp("run_stale_sha"), Ordering::Equal)
                && record.stale_git_sha
                && matches!(
                    record.release_claim_effect,
                    OperationalEvidenceReleaseClaimEffect::Downgrades
                )
        }));
        assert!(index.records.iter().any(|record| {
            matches!(
                record.run_id.as_str().cmp("run_missing_logs"),
                Ordering::Equal
            ) && record.missing_raw_logs
                && matches!(
                    record.release_claim_effect,
                    OperationalEvidenceReleaseClaimEffect::Downgrades
                )
        }));
    }

    #[test]
    fn host_capability_skips_are_downgraded_for_release_claims() {
        let fixture = EvidenceFixture::new();
        let manifest = sample_manifest(SampleManifestInput {
            run_id: "run_host_skip",
            scenario_id: "fuse_permission_probe",
            commit: "abc123",
            classification: OperationalOutcomeClass::Skip,
            result: ScenarioResult::Skip,
            error_class: Some(crate::artifact_manifest::OperationalErrorClass::FusePermissionSkip),
            skip_reason: Some(SkipReason::FusePermissionDenied),
            created_at: "2026-05-09T00:00:00Z",
            include_log_artifacts: true,
            cpu_count: 2,
            memory_gib: 4,
        });
        touch_manifest_logs(&fixture, &manifest);
        fixture.write_manifest("skip.json", &manifest);

        let index = fixture.index(Some("abc123"));
        let record = index.records.first().expect("record");

        assert_eq!(
            record.host_class,
            OperationalEvidenceHostClass::CapabilityDowngraded
        );
        assert_eq!(
            record.release_claim_effect,
            OperationalEvidenceReleaseClaimEffect::Downgrades
        );
        assert!(!record.authoritative);
        assert_eq!(index.host_downgrade_count, 1);
    }

    #[test]
    fn max_age_marks_old_artifacts_stale() {
        let fixture = EvidenceFixture::new();
        let manifest = sample_manifest(SampleManifestInput {
            run_id: "run_old",
            scenario_id: "release_gate_old",
            commit: "abc123",
            classification: OperationalOutcomeClass::Pass,
            result: ScenarioResult::Pass,
            error_class: None,
            skip_reason: None,
            created_at: "2026-05-01T00:00:00Z",
            include_log_artifacts: true,
            cpu_count: 64,
            memory_gib: 256,
        });
        touch_manifest_logs(&fixture, &manifest);
        fixture.write_manifest("old.json", &manifest);

        let reference_epoch_days =
            crate::artifact_manifest::parse_manifest_timestamp_epoch_days("2026-05-09T00:00:00Z")
                .expect("reference timestamp parses");
        let index = fixture.index_with_recency(Some("abc123"), 3, reference_epoch_days);
        let record = index.records.first().expect("record");

        assert_eq!(record.freshness, OperationalEvidenceFreshness::Stale);
        assert!(record.stale_artifact);
        assert!(!record.authoritative);
    }

    #[test]
    fn markdown_renders_latest_truth_and_diagnostics() {
        let fixture = EvidenceFixture::new();
        let manifest = sample_manifest(SampleManifestInput {
            run_id: "run_20260509",
            scenario_id: "release_gate_green",
            commit: "abc123",
            classification: OperationalOutcomeClass::Pass,
            result: ScenarioResult::Pass,
            error_class: None,
            skip_reason: None,
            created_at: "2026-05-09T00:00:00Z",
            include_log_artifacts: true,
            cpu_count: 64,
            memory_gib: 256,
        });
        touch_manifest_logs(&fixture, &manifest);
        fixture.write_manifest("green.json", &manifest);

        let index = fixture.index(Some("abc123"));
        let markdown = render_operational_evidence_index_markdown(&index);

        assert!(markdown.contains("# FrankenFS Operational Evidence Index"));
        assert!(markdown.contains("## Latest Truth"));
        assert!(markdown.contains("release_gate_green"));
        assert!(markdown.contains("Strengthens"));
    }

    #[derive(Clone, Copy)]
    struct SampleManifestInput<'a> {
        run_id: &'a str,
        scenario_id: &'a str,
        commit: &'a str,
        classification: OperationalOutcomeClass,
        result: ScenarioResult,
        error_class: Option<crate::artifact_manifest::OperationalErrorClass>,
        skip_reason: Option<SkipReason>,
        created_at: &'a str,
        include_log_artifacts: bool,
        cpu_count: u32,
        memory_gib: u32,
    }

    fn sample_manifest(input: SampleManifestInput<'_>) -> ArtifactManifest {
        let stdout_path = format!("{}/{}/stdout.log", input.run_id, input.scenario_id);
        let stderr_path = format!("{}/{}/stderr.log", input.run_id, input.scenario_id);
        let run_stdout_path = format!("{}/run_stdout.log", input.run_id);
        let run_stderr_path = format!("{}/run_stderr.log", input.run_id);
        let artifact_ref = format!("{}/{}/evidence.json", input.run_id, input.scenario_id);
        let mut scenarios = BTreeMap::new();
        scenarios.insert(
            input.scenario_id.to_owned(),
            ScenarioOutcome {
                scenario_id: input.scenario_id.to_owned(),
                outcome: input.result,
                detail: Some("fixture detail".to_owned()),
                duration_secs: 1.0,
            },
        );
        let mut operational_scenarios = BTreeMap::new();
        operational_scenarios.insert(
            input.scenario_id.to_owned(),
            OperationalScenarioRecord {
                scenario_id: input.scenario_id.to_owned(),
                filesystem: FilesystemFlavor::NotApplicable,
                image_hash: None,
                mount_options: Vec::new(),
                expected_outcome: input.result,
                actual_outcome: input.result,
                classification: input.classification,
                exit_status: i32::from(!matches!(
                    input.classification,
                    OperationalOutcomeClass::Pass
                )),
                stdout_path: stdout_path.clone(),
                stderr_path: stderr_path.clone(),
                ledger_paths: Vec::new(),
                artifact_refs: vec![artifact_ref.clone()],
                cleanup_status: CleanupStatus::Clean,
                error_class: input.error_class,
                remediation_hint: input.error_class.map(|_| "inspect fixture".to_owned()),
                skip_reason: input.skip_reason,
            },
        );
        let mut artifacts = vec![artifact(&artifact_ref, ArtifactCategory::ProofArtifact)];
        if input.include_log_artifacts {
            artifacts.extend([
                artifact(&stdout_path, ArtifactCategory::RawLog),
                artifact(&stderr_path, ArtifactCategory::RawLog),
                artifact(&run_stdout_path, ArtifactCategory::RawLog),
                artifact(&run_stderr_path, ArtifactCategory::RawLog),
            ]);
        }
        ArtifactManifest {
            schema_version: SCHEMA_VERSION,
            run_id: input.run_id.to_owned(),
            created_at: input.created_at.to_owned(),
            gate_id: "xfstests".to_owned(),
            bead_id: Some("bd-4v16z.6".to_owned()),
            git_context: GitContext {
                commit: input.commit.to_owned(),
                branch: "main".to_owned(),
                clean: true,
            },
            environment: EnvironmentFingerprint {
                hostname: "permissioned-host".to_owned(),
                cpu_model: "cpu".to_owned(),
                cpu_count: input.cpu_count,
                memory_gib: input.memory_gib,
                kernel: "Linux 6.17.0".to_owned(),
                rustc_version: "rustc 1.85.0".to_owned(),
                cargo_version: Some("cargo 1.85.0".to_owned()),
            },
            scenarios,
            operational_context: Some(OperationalRunContext {
                command_line: vec!["scripts/e2e/fixture.sh".to_owned()],
                worker: WorkerContext {
                    host: "permissioned-host".to_owned(),
                    worker_id: Some("worker-a".to_owned()),
                },
                fuse_capability: FuseCapabilityResult::NotApplicable,
                stdout_path: run_stdout_path,
                stderr_path: run_stderr_path,
            }),
            operational_scenarios,
            readiness_events: vec![readiness_event(
                &input,
                &artifact_ref,
                &stdout_path,
                &stderr_path,
            )],
            artifacts,
            verdict: if matches!(input.classification, OperationalOutcomeClass::Pass) {
                GateVerdict::Pass
            } else {
                GateVerdict::Fail
            },
            duration_secs: 1.0,
            retention: None,
        }
    }

    fn readiness_event(
        input: &SampleManifestInput<'_>,
        artifact_ref: &str,
        stdout_path: &str,
        stderr_path: &str,
    ) -> ReadinessEventEnvelope {
        ReadinessEventEnvelope {
            envelope_version: READINESS_EVENT_ENVELOPE_VERSION,
            event_id: format!("event_{}_{}", input.run_id, input.scenario_id),
            report_id: format!("report_{}", input.run_id),
            run_id: input.run_id.to_owned(),
            lane_id: "xfstests".to_owned(),
            scenario_id: Some(input.scenario_id.to_owned()),
            aggregate_marker: None,
            artifact_id: artifact_ref.to_owned(),
            parent_correlation_id: None,
            classification: input.classification,
            severity: if matches!(input.classification, OperationalOutcomeClass::Pass) {
                ReadinessEventSeverity::Info
            } else {
                ReadinessEventSeverity::Error
            },
            created_at: input.created_at.to_owned(),
            git_commit: input.commit.to_owned(),
            host_fingerprint: "permissioned-host|64cpu|256GiB".to_owned(),
            capability_fingerprint: "fuse:not_applicable".to_owned(),
            raw_log_refs: vec![stdout_path.to_owned(), stderr_path.to_owned()],
            controlling_evidence: vec![artifact_ref.to_owned()],
            remediation_id: "bd-4v16z.6:test-fixture".to_owned(),
            reproduction_command: "scripts/e2e/fixture.sh".to_owned(),
        }
    }

    fn artifact(path: &str, category: ArtifactCategory) -> ArtifactEntry {
        ArtifactEntry {
            path: path.to_owned(),
            category,
            content_type: Some("text/plain".to_owned()),
            size_bytes: 4,
            sha256: None,
            redacted: false,
            metadata: BTreeMap::new(),
        }
    }

    fn touch_manifest_logs(fixture: &EvidenceFixture, manifest: &ArtifactManifest) {
        if let Some(context) = &manifest.operational_context {
            fixture.touch(&context.stdout_path);
            fixture.touch(&context.stderr_path);
        }
        for record in manifest.operational_scenarios.values() {
            fixture.touch(&record.stdout_path);
            fixture.touch(&record.stderr_path);
        }
    }
}
