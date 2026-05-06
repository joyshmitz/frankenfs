#![forbid(unsafe_code)]

//! Mounted write error class catalog.
//!
//! Tracks bd-rchk0.3.4: maps mounted write failure scenarios to actionable
//! error classes so operators can distinguish product bugs from unsupported
//! scope, host setup limitations, and intentional refusals. Each row binds an
//! operation/scenario id, expected error class, raw kernel/FUSE errno or
//! status, broad-fallback justification (when EIO/EINVAL is the only honest
//! answer), remediation hint, redaction policy, and a linked follow-up bead
//! for every unresolved broad fallback.

use crate::mounted_write_matrix::MountedWriteMatrix;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

pub const MOUNTED_WRITE_ERROR_CLASSES_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_MOUNTED_WRITE_ERROR_CLASSES_PATH: &str =
    "tests/mounted-write-error-classes/mounted_write_error_classes.json";
const DEFAULT_MOUNTED_WRITE_ERROR_CLASSES_JSON: &str =
    include_str!("../../../tests/mounted-write-error-classes/mounted_write_error_classes.json");

const ALLOWED_ERROR_CLASSES: [&str; 9] = [
    "ok",
    "host_capability_skip",
    "default_permissions_eacces",
    "unsupported_operation",
    "repair_serialization_blocked",
    "cancelled_by_caller",
    "stale_snapshot_refused",
    "product_failure",
    "broad_fallback",
];

const ALLOWED_RAW_ERRNO: [&str; 14] = [
    "0",
    "EIO",
    "EINVAL",
    "EACCES",
    "EPERM",
    "ENOSYS",
    "ENOTSUP",
    "EOPNOTSUPP",
    "EROFS",
    "EBUSY",
    "ECANCELED",
    "ENOTCONN",
    "ESTALE",
    "ENAMETOOLONG",
];

const ALLOWED_REDACTION_POLICIES: [&str; 4] = [
    "none",
    "redact_paths",
    "redact_paths_and_xattr_values",
    "redact_image_bytes",
];

const REQUIRED_ERROR_CLASS_COVERAGE: [&str; 6] = [
    "host_capability_skip",
    "default_permissions_eacces",
    "unsupported_operation",
    "repair_serialization_blocked",
    "cancelled_by_caller",
    "stale_snapshot_refused",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedWriteErrorClasses {
    pub schema_version: u32,
    pub catalog_id: String,
    pub bead_id: String,
    #[serde(default)]
    pub catalog_owner_beads: Vec<String>,
    pub entries: Vec<MountedWriteErrorEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedWriteErrorEntry {
    pub entry_id: String,
    pub scenario_id: String,
    pub operation_id: String,
    pub error_class: String,
    pub raw_errno: String,
    pub remediation_hint: String,
    pub redaction_policy: String,
    pub artifact_paths: Vec<String>,
    #[serde(default)]
    pub broad_fallback_justification: String,
    #[serde(default)]
    pub follow_up_bead: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedWriteErrorReport {
    pub schema_version: u32,
    pub catalog_id: String,
    pub bead_id: String,
    pub entry_count: usize,
    pub error_classes_seen: Vec<String>,
    pub broad_fallback_count: usize,
    pub valid: bool,
    pub errors: Vec<String>,
}

pub fn parse_mounted_write_error_classes(text: &str) -> Result<MountedWriteErrorClasses> {
    serde_json::from_str(text)
        .map_err(|err| anyhow::anyhow!("failed to parse mounted write error classes JSON: {err}"))
}

pub fn validate_default_mounted_write_error_classes() -> Result<MountedWriteErrorReport> {
    let catalog = parse_mounted_write_error_classes(DEFAULT_MOUNTED_WRITE_ERROR_CLASSES_JSON)?;
    let matrix = crate::mounted_write_matrix::parse_mounted_write_matrix(include_str!(
        "../../../tests/workload-matrix/mounted_write_workload_matrix.json"
    ))?;
    let report = validate_mounted_write_error_classes_with_matrix(&catalog, &matrix);
    fail_on_mounted_write_error_classes_errors(&report)?;
    Ok(report)
}

pub fn fail_on_mounted_write_error_classes_errors(report: &MountedWriteErrorReport) -> Result<()> {
    if !report.valid {
        bail!(
            "mounted write error classes failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        );
    }
    Ok(())
}

#[must_use]
pub fn validate_mounted_write_error_classes(
    catalog: &MountedWriteErrorClasses,
) -> MountedWriteErrorReport {
    let mut errors = Vec::new();
    let mut ids = BTreeSet::new();
    let mut classes_seen = BTreeSet::new();
    let mut broad_fallback_count = 0_usize;

    validate_top_level(catalog, &mut errors);
    validate_catalog_owner_beads(catalog, &mut errors);
    for entry in &catalog.entries {
        validate_entry(
            entry,
            &catalog.catalog_owner_beads,
            &mut ids,
            &mut classes_seen,
            &mut broad_fallback_count,
            &mut errors,
        );
    }
    validate_class_coverage(&classes_seen, &mut errors);

    MountedWriteErrorReport {
        schema_version: catalog.schema_version,
        catalog_id: catalog.catalog_id.clone(),
        bead_id: catalog.bead_id.clone(),
        entry_count: catalog.entries.len(),
        error_classes_seen: classes_seen.into_iter().collect(),
        broad_fallback_count,
        valid: errors.is_empty(),
        errors,
    }
}

#[must_use]
pub fn validate_mounted_write_error_classes_with_matrix(
    catalog: &MountedWriteErrorClasses,
    matrix: &MountedWriteMatrix,
) -> MountedWriteErrorReport {
    let mut report = validate_mounted_write_error_classes(catalog);
    validate_matrix_references(catalog, matrix, &mut report.errors);
    report.valid = report.errors.is_empty();
    report
}

#[must_use]
pub fn render_mounted_write_error_classes_markdown(report: &MountedWriteErrorReport) -> String {
    let classes = if report.error_classes_seen.is_empty() {
        "none".to_owned()
    } else {
        report
            .error_classes_seen
            .iter()
            .map(|class| format!("`{}`", escape_markdown_table_cell(class)))
            .collect::<Vec<_>>()
            .join(", ")
    };

    let mut output = String::new();
    writeln!(
        &mut output,
        "# Mounted Write Error Classes `{}`",
        report.catalog_id
    )
    .ok();
    writeln!(&mut output).ok();
    writeln!(&mut output, "- Bead: `{}`", report.bead_id).ok();
    writeln!(&mut output, "- Entries: `{}`", report.entry_count).ok();
    writeln!(
        &mut output,
        "- Broad fallbacks: `{}`",
        report.broad_fallback_count
    )
    .ok();
    writeln!(&mut output, "- Valid: `{}`", report.valid).ok();
    writeln!(&mut output, "- Classes seen: {classes}").ok();
    writeln!(&mut output).ok();
    writeln!(&mut output, "## Errors").ok();
    if report.errors.is_empty() {
        writeln!(&mut output, "- none").ok();
    } else {
        for error in &report.errors {
            writeln!(&mut output, "- {}", escape_markdown_table_cell(error)).ok();
        }
    }
    output
}

fn validate_top_level(catalog: &MountedWriteErrorClasses, errors: &mut Vec<String>) {
    if catalog.schema_version != MOUNTED_WRITE_ERROR_CLASSES_SCHEMA_VERSION {
        errors.push(format!(
            "mounted write error classes schema_version must be {MOUNTED_WRITE_ERROR_CLASSES_SCHEMA_VERSION}, got {}",
            catalog.schema_version
        ));
    }
    if catalog.catalog_id.trim().is_empty() {
        errors.push("mounted write error classes missing catalog_id".to_owned());
    }
    if !catalog.bead_id.starts_with("bd-") {
        errors.push(format!(
            "mounted write error classes bead_id must look like bd-..., got `{}`",
            catalog.bead_id
        ));
    }
    if catalog.entries.is_empty() {
        errors.push("mounted write error classes must declare at least one entry".to_owned());
    }
}

fn validate_catalog_owner_beads(catalog: &MountedWriteErrorClasses, errors: &mut Vec<String>) {
    if catalog.catalog_owner_beads.is_empty() {
        errors.push("mounted write error classes must declare catalog_owner_beads".to_owned());
    }
    if !catalog
        .catalog_owner_beads
        .iter()
        .any(|bead| bead == &catalog.bead_id)
    {
        errors.push(format!(
            "mounted write error classes catalog_owner_beads must include bead_id `{}`",
            catalog.bead_id
        ));
    }
    for bead in &catalog.catalog_owner_beads {
        if !bead.starts_with("bd-") {
            errors.push(format!(
                "mounted write error classes catalog_owner_beads entry must look like bd-..., got `{bead}`"
            ));
        }
    }
}

fn validate_entry(
    entry: &MountedWriteErrorEntry,
    catalog_owner_beads: &[String],
    ids: &mut BTreeSet<String>,
    classes_seen: &mut BTreeSet<String>,
    broad_fallback_count: &mut usize,
    errors: &mut Vec<String>,
) {
    if !ids.insert(entry.entry_id.clone()) {
        errors.push(format!(
            "duplicate mounted write error entry_id `{}`",
            entry.entry_id
        ));
    }
    if !entry.entry_id.starts_with("mwerr_") {
        errors.push(format!(
            "entry_id `{}` must start with mwerr_",
            entry.entry_id
        ));
    }
    if entry.scenario_id.trim().is_empty() {
        errors.push(format!("entry `{}` missing scenario_id", entry.entry_id));
    }
    if entry.operation_id.trim().is_empty() {
        errors.push(format!("entry `{}` missing operation_id", entry.entry_id));
    }
    if ALLOWED_ERROR_CLASSES.contains(&entry.error_class.as_str()) {
        classes_seen.insert(entry.error_class.clone());
    } else {
        errors.push(format!(
            "entry `{}` has unsupported error_class `{}`",
            entry.entry_id, entry.error_class
        ));
    }
    if !ALLOWED_RAW_ERRNO.contains(&entry.raw_errno.as_str()) {
        errors.push(format!(
            "entry `{}` has unsupported raw_errno `{}`",
            entry.entry_id, entry.raw_errno
        ));
    }
    if !ALLOWED_REDACTION_POLICIES.contains(&entry.redaction_policy.as_str()) {
        errors.push(format!(
            "entry `{}` has unsupported redaction_policy `{}`",
            entry.entry_id, entry.redaction_policy
        ));
    }
    if entry.remediation_hint.trim().is_empty() && entry.error_class != "ok" {
        errors.push(format!(
            "entry `{}` non-ok error class must declare a remediation_hint",
            entry.entry_id
        ));
    }
    if entry.artifact_paths.is_empty() {
        errors.push(format!(
            "entry `{}` must declare at least one artifact path",
            entry.entry_id
        ));
    }

    validate_errno_class_consistency(entry, errors);
    validate_redaction_policy_consistency(entry, errors);
    validate_broad_fallback(entry, catalog_owner_beads, broad_fallback_count, errors);
    validate_ok_invariants(entry, errors);
}

fn validate_errno_class_consistency(entry: &MountedWriteErrorEntry, errors: &mut Vec<String>) {
    let expected_errnos: &[&str] = match entry.error_class.as_str() {
        "ok" => &["0"],
        "default_permissions_eacces" => &["EACCES", "EPERM"],
        "host_capability_skip" => &["ENOTCONN", "ENOSYS"],
        "unsupported_operation" => &["ENOSYS", "ENOTSUP", "EOPNOTSUPP", "ENAMETOOLONG"],
        "repair_serialization_blocked" => &["EBUSY", "EROFS"],
        "cancelled_by_caller" => &["ECANCELED"],
        "stale_snapshot_refused" => &["ESTALE", "EROFS"],
        "broad_fallback" => &["EIO", "EINVAL"],
        _ => &[],
    };
    if !expected_errnos.is_empty()
        && !expected_errnos
            .iter()
            .any(|expected| *expected == entry.raw_errno)
    {
        errors.push(format!(
            "entry `{}` raw_errno `{}` does not match error_class `{}` expectations",
            entry.entry_id, entry.raw_errno, entry.error_class
        ));
    }
}

fn validate_redaction_policy_consistency(entry: &MountedWriteErrorEntry, errors: &mut Vec<String>) {
    if entry.error_class == "ok" && entry.redaction_policy != "none" {
        errors.push(format!(
            "entry `{}` ok class must use redaction_policy=none",
            entry.entry_id
        ));
    }
    let writes_xattr = entry.operation_id.contains("xattr");
    if writes_xattr && entry.redaction_policy == "none" && entry.error_class != "ok" {
        errors.push(format!(
            "entry `{}` xattr operation must redact_paths_and_xattr_values when surfacing errors",
            entry.entry_id
        ));
    }
}

fn validate_broad_fallback(
    entry: &MountedWriteErrorEntry,
    catalog_owner_beads: &[String],
    broad_fallback_count: &mut usize,
    errors: &mut Vec<String>,
) {
    let is_broad = entry.error_class == "broad_fallback";
    if is_broad {
        *broad_fallback_count += 1;
        if entry.broad_fallback_justification.trim().is_empty() {
            errors.push(format!(
                "entry `{}` broad_fallback class must declare broad_fallback_justification",
                entry.entry_id
            ));
        }
        if !entry.follow_up_bead.starts_with("bd-") {
            errors.push(format!(
                "entry `{}` broad_fallback class must link a follow_up_bead (bd-...)",
                entry.entry_id
            ));
        }
        if catalog_owner_beads
            .iter()
            .any(|bead| bead == &entry.follow_up_bead)
        {
            errors.push(format!(
                "entry `{}` broad_fallback follow_up_bead `{}` must name a distinct investigation bead, not a catalog owner bead",
                entry.entry_id, entry.follow_up_bead
            ));
        }
    } else {
        if !entry.broad_fallback_justification.trim().is_empty() {
            errors.push(format!(
                "entry `{}` non-broad_fallback class must leave broad_fallback_justification empty",
                entry.entry_id
            ));
        }
        if !entry.follow_up_bead.is_empty() && !entry.follow_up_bead.starts_with("bd-") {
            errors.push(format!(
                "entry `{}` follow_up_bead must look like bd-..., got `{}`",
                entry.entry_id, entry.follow_up_bead
            ));
        }
    }
}

fn validate_ok_invariants(entry: &MountedWriteErrorEntry, errors: &mut Vec<String>) {
    if entry.error_class == "ok" {
        if entry.raw_errno != "0" {
            errors.push(format!(
                "entry `{}` ok class must record raw_errno=0",
                entry.entry_id
            ));
        }
        if !entry.follow_up_bead.is_empty() {
            errors.push(format!(
                "entry `{}` ok class must leave follow_up_bead empty",
                entry.entry_id
            ));
        }
    }
}

fn validate_class_coverage(seen: &BTreeSet<String>, errors: &mut Vec<String>) {
    for required in REQUIRED_ERROR_CLASS_COVERAGE {
        if !seen.contains(required) {
            errors.push(format!(
                "mounted write error classes missing required error_class `{required}`"
            ));
        }
    }
}

fn validate_matrix_references(
    catalog: &MountedWriteErrorClasses,
    matrix: &MountedWriteMatrix,
    errors: &mut Vec<String>,
) {
    let operations_by_scenario = matrix_operation_index(matrix);
    for entry in &catalog.entries {
        if is_synthetic_matrix_reference_escape(entry) {
            continue;
        }
        let Some(operations) = operations_by_scenario.get(&entry.scenario_id) else {
            errors.push(format!(
                "entry `{}` references unknown mounted write matrix scenario_id `{}`",
                entry.entry_id, entry.scenario_id
            ));
            continue;
        };
        if !operations.contains(&entry.operation_id) {
            errors.push(format!(
                "entry `{}` operation_id `{}` is not declared by mounted write matrix scenario `{}`; known operations: {}",
                entry.entry_id,
                entry.operation_id,
                entry.scenario_id,
                operations.iter().cloned().collect::<Vec<_>>().join(", ")
            ));
        }
    }
}

fn matrix_operation_index(matrix: &MountedWriteMatrix) -> BTreeMap<String, BTreeSet<String>> {
    let mut operations_by_scenario = BTreeMap::new();
    for scenario in &matrix.scenarios {
        let mut operations = BTreeSet::new();
        operations.extend(scenario.workload.operation_sequence.iter().cloned());
        operations.extend(scenario.workload.unsupported_operations.iter().cloned());
        operations_by_scenario.insert(scenario.scenario_id.clone(), operations);
    }
    for scenario in &matrix.namespace_scenarios {
        let mut operations = BTreeSet::new();
        operations.insert(scenario.namespace_operation_kind.clone());
        operations_by_scenario.insert(scenario.scenario_id.clone(), operations);
    }
    for scenario in &matrix.multi_handle_scenarios {
        let mut operations = BTreeSet::new();
        operations.insert(scenario.kind.clone());
        operations.extend(scenario.operation_trace.iter().map(|op| op.op.clone()));
        operations_by_scenario.insert(scenario.scenario_id.clone(), operations);
    }
    operations_by_scenario
}

fn is_synthetic_matrix_reference_escape(entry: &MountedWriteErrorEntry) -> bool {
    entry.entry_id.starts_with("mwerr_synthetic_")
        && entry.scenario_id.starts_with("synthetic_")
        && entry.operation_id.starts_with("synthetic_")
}

fn escape_markdown_table_cell(raw: &str) -> String {
    raw.replace('|', "\\|")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mounted_write_matrix::{MountedWriteMatrix, parse_mounted_write_matrix};

    fn fixture_catalog() -> MountedWriteErrorClasses {
        parse_mounted_write_error_classes(DEFAULT_MOUNTED_WRITE_ERROR_CLASSES_JSON)
            .expect("default mounted write error classes parses")
    }

    fn fixture_matrix() -> MountedWriteMatrix {
        parse_mounted_write_matrix(include_str!(
            "../../../tests/workload-matrix/mounted_write_workload_matrix.json"
        ))
        .expect("default mounted write matrix parses")
    }

    fn synthetic_broad_fallback_entry(
        catalog: &mut MountedWriteErrorClasses,
    ) -> &mut MountedWriteErrorEntry {
        let entry = catalog
            .entries
            .iter_mut()
            .find(|e| e.entry_id == "mwerr_product_failure_btrfs_write_readback_eio")
            .expect("btrfs write/readback product failure fixture exists");
        entry.error_class = "broad_fallback".to_owned();
        entry.broad_fallback_justification =
            "synthetic opaque EIO branch for validator coverage".to_owned();
        entry.follow_up_bead = "bd-0s5a3".to_owned();
        entry
    }

    #[test]
    fn default_catalog_validates_required_classes() {
        let report = validate_default_mounted_write_error_classes()
            .expect("default mounted write error classes validates");
        assert_eq!(report.bead_id, "bd-rchk0.3.4");
        for class in REQUIRED_ERROR_CLASS_COVERAGE {
            assert!(
                report.error_classes_seen.iter().any(|c| c == class),
                "missing class {class}"
            );
        }
    }

    #[test]
    fn default_catalog_references_workload_matrix_rows() {
        let catalog = fixture_catalog();
        let matrix = fixture_matrix();
        let report = validate_mounted_write_error_classes_with_matrix(&catalog, &matrix);
        assert!(
            report.valid,
            "default catalog must reference mounted write matrix rows: {:?}",
            report.errors
        );
    }

    #[test]
    fn matrix_cross_check_rejects_orphan_scenario_ids() {
        let mut catalog = fixture_catalog();
        catalog.entries[0].scenario_id = "mounted_write_missing_scenario".to_owned();
        let matrix = fixture_matrix();
        let report = validate_mounted_write_error_classes_with_matrix(&catalog, &matrix);
        assert!(report.errors.iter().any(|err| {
            err.contains("unknown mounted write matrix scenario_id")
                && err.contains("mounted_write_missing_scenario")
        }));
    }

    #[test]
    fn matrix_cross_check_rejects_orphan_operation_ids() {
        let mut catalog = fixture_catalog();
        catalog.entries[0].operation_id = "missing_matrix_operation".to_owned();
        let matrix = fixture_matrix();
        let report = validate_mounted_write_error_classes_with_matrix(&catalog, &matrix);
        assert!(report.errors.iter().any(|err| {
            err.contains("operation_id `missing_matrix_operation`")
                && err.contains("is not declared by mounted write matrix scenario")
        }));
    }

    #[test]
    fn matrix_cross_check_rejects_accidental_stale_catalog_rows() {
        let mut catalog = fixture_catalog();
        let entry = catalog
            .entries
            .iter_mut()
            .find(|entry| entry.entry_id == "mwerr_unsupported_overlong_xattr_name")
            .expect("overlong xattr fixture exists");
        entry.scenario_id = "mounted_write_ext4_xattr_modes".to_owned();
        let matrix = fixture_matrix();
        let report = validate_mounted_write_error_classes_with_matrix(&catalog, &matrix);
        assert!(report.errors.iter().any(|err| {
            err.contains("mwerr_unsupported_overlong_xattr_name")
                && err.contains("operation_id `xattr_set_overlong`")
        }));
    }

    #[test]
    fn documented_synthetic_validator_rows_can_escape_matrix_cross_check() {
        let mut catalog = fixture_catalog();
        catalog.entries.push(MountedWriteErrorEntry {
            entry_id: "mwerr_synthetic_validator_only".to_owned(),
            scenario_id: "synthetic_matrix_gap".to_owned(),
            operation_id: "synthetic_operation_gap".to_owned(),
            error_class: "broad_fallback".to_owned(),
            raw_errno: "EIO".to_owned(),
            remediation_hint: "synthetic validator-only row".to_owned(),
            redaction_policy: "redact_paths".to_owned(),
            artifact_paths: vec!["artifacts/mounted-write/synthetic.json".to_owned()],
            broad_fallback_justification: "synthetic validator branch".to_owned(),
            follow_up_bead: "bd-synthetic".to_owned(),
        });
        let matrix = fixture_matrix();
        let report = validate_mounted_write_error_classes_with_matrix(&catalog, &matrix);
        assert!(
            !report.errors.iter().any(|err| {
                err.contains("mwerr_synthetic_validator_only")
                    && err.contains("mounted write matrix")
            }),
            "synthetic validator-only rows should bypass matrix references: {:?}",
            report.errors
        );
    }

    #[test]
    fn markdown_report_includes_catalog_summary_and_errors() {
        let mut report = validate_default_mounted_write_error_classes()
            .expect("default mounted write error classes validates");
        report.valid = false;
        report.errors.push("example | escaped error".to_owned());
        let markdown = render_mounted_write_error_classes_markdown(&report);
        assert!(markdown.contains("# Mounted Write Error Classes"));
        assert!(markdown.contains("frankenfs_mounted_write_error_classes_v1"));
        assert!(markdown.contains("- Bead: `bd-rchk0.3.4`"));
        assert!(markdown.contains("- Entries: `9`"));
        assert!(markdown.contains("- Broad fallbacks: `0`"));
        assert!(markdown.contains("- Valid: `false`"));
        assert!(markdown.contains("`host_capability_skip`"));
        assert!(markdown.contains("example \\| escaped error"));
    }

    /// bd-rchk0.73 — exact golden snapshot for the default mounted write
    /// error-class report renderer. Pins the title, summary bullets,
    /// class ordering, error section, and the no-error sentinel so operator
    /// report consumers notice accidental markdown drift.
    #[test]
    fn render_mounted_write_error_classes_markdown_default_report() {
        let report = validate_default_mounted_write_error_classes()
            .expect("default mounted write error classes validates");
        let markdown = render_mounted_write_error_classes_markdown(&report);
        insta::assert_snapshot!(
            "render_mounted_write_error_classes_markdown_default_report",
            markdown
        );
    }

    #[test]
    fn missing_default_permissions_class_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog
            .entries
            .retain(|e| e.error_class != "default_permissions_eacces");
        let report = validate_mounted_write_error_classes(&catalog);
        assert!(
            report.errors.iter().any(
                |err| err.contains("missing required error_class `default_permissions_eacces`")
            )
        );
    }

    #[test]
    fn missing_repair_serialization_blocked_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog
            .entries
            .retain(|e| e.error_class != "repair_serialization_blocked");
        let report = validate_mounted_write_error_classes(&catalog);
        assert!(report.errors.iter().any(|err| {
            err.contains("missing required error_class `repair_serialization_blocked`")
        }));
    }

    #[test]
    fn duplicate_entry_id_is_rejected() {
        let mut catalog = fixture_catalog();
        let dup = catalog.entries[0].entry_id.clone();
        catalog.entries[1].entry_id = dup;
        let report = validate_mounted_write_error_classes(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("duplicate mounted write error entry_id"))
        );
    }

    #[test]
    fn entry_id_prefix_is_enforced() {
        let mut catalog = fixture_catalog();
        catalog.entries[0].entry_id = "err_001".to_owned();
        let report = validate_mounted_write_error_classes(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must start with mwerr_"))
        );
    }

    #[test]
    fn errno_must_match_error_class() {
        let mut catalog = fixture_catalog();
        let entry = catalog
            .entries
            .iter_mut()
            .find(|e| e.error_class == "default_permissions_eacces")
            .expect("default permissions fixture exists");
        entry.raw_errno = "EIO".to_owned();
        let report = validate_mounted_write_error_classes(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("does not match error_class `default_permissions_eacces`"))
        );
    }

    #[test]
    fn broad_fallback_requires_justification() {
        let mut catalog = fixture_catalog();
        let entry = synthetic_broad_fallback_entry(&mut catalog);
        entry.broad_fallback_justification = String::new();
        let report = validate_mounted_write_error_classes(&catalog);
        assert!(report.errors.iter().any(|err| {
            err.contains("broad_fallback class must declare broad_fallback_justification")
        }));
    }

    #[test]
    fn broad_fallback_requires_follow_up_bead() {
        let mut catalog = fixture_catalog();
        let entry = synthetic_broad_fallback_entry(&mut catalog);
        entry.follow_up_bead = String::new();
        let report = validate_mounted_write_error_classes(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must link a follow_up_bead"))
        );
    }

    #[test]
    fn broad_fallback_requires_distinct_investigation_bead() {
        let mut catalog = fixture_catalog();
        let owner_bead = catalog
            .catalog_owner_beads
            .iter()
            .find(|bead| bead.as_str() != catalog.bead_id)
            .expect("fixture declares supplemental catalog owner bead")
            .clone();
        let entry = synthetic_broad_fallback_entry(&mut catalog);
        entry.follow_up_bead = owner_bead;
        let report = validate_mounted_write_error_classes(&catalog);
        assert!(report.errors.iter().any(|err| {
            err.contains("must name a distinct investigation bead")
                && err.contains("catalog owner bead")
        }));
    }

    #[test]
    fn non_broad_fallback_must_leave_justification_empty() {
        let mut catalog = fixture_catalog();
        let entry = catalog
            .entries
            .iter_mut()
            .find(|e| e.error_class == "default_permissions_eacces")
            .expect("default permissions fixture exists");
        entry.broad_fallback_justification = "leftover prose".to_owned();
        let report = validate_mounted_write_error_classes(&catalog);
        assert!(report.errors.iter().any(|err| {
            err.contains("non-broad_fallback class must leave broad_fallback_justification empty")
        }));
    }

    #[test]
    fn ok_class_requires_zero_errno() {
        let mut catalog = fixture_catalog();
        let entry = catalog
            .entries
            .iter_mut()
            .find(|e| e.error_class == "ok")
            .expect("ok fixture exists");
        entry.raw_errno = "EINVAL".to_owned();
        let report = validate_mounted_write_error_classes(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("ok class must record raw_errno=0"))
        );
    }

    #[test]
    fn ok_class_must_use_redaction_none() {
        let mut catalog = fixture_catalog();
        let entry = catalog
            .entries
            .iter_mut()
            .find(|e| e.error_class == "ok")
            .expect("ok fixture exists");
        entry.redaction_policy = "redact_paths".to_owned();
        let report = validate_mounted_write_error_classes(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("ok class must use redaction_policy=none"))
        );
    }

    #[test]
    fn xattr_operations_require_xattr_redaction() {
        let mut catalog = fixture_catalog();
        let entry = catalog
            .entries
            .iter_mut()
            .find(|e| e.operation_id.contains("xattr") && e.error_class != "ok")
            .expect("xattr non-ok fixture exists");
        entry.redaction_policy = "none".to_owned();
        let report = validate_mounted_write_error_classes(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("xattr operation must redact_paths_and_xattr_values"))
        );
    }

    #[test]
    fn missing_remediation_for_failure_is_rejected() {
        let mut catalog = fixture_catalog();
        let entry = catalog
            .entries
            .iter_mut()
            .find(|e| e.error_class != "ok")
            .expect("non-ok fixture exists");
        entry.remediation_hint = String::new();
        let report = validate_mounted_write_error_classes(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("non-ok error class must declare a remediation_hint"))
        );
    }

    #[test]
    fn missing_artifact_paths_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog.entries[0].artifact_paths.clear();
        let report = validate_mounted_write_error_classes(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("at least one artifact path"))
        );
    }

    #[test]
    fn unsupported_redaction_policy_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog.entries[0].redaction_policy = "publish_everything".to_owned();
        let report = validate_mounted_write_error_classes(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported redaction_policy"))
        );
    }

    #[test]
    fn malformed_follow_up_bead_is_rejected() {
        let mut catalog = fixture_catalog();
        let entry = catalog
            .entries
            .iter_mut()
            .find(|e| e.error_class != "broad_fallback" && e.error_class != "ok")
            .expect("non-broad-fallback fixture exists");
        entry.follow_up_bead = "PROJ-99".to_owned();
        let report = validate_mounted_write_error_classes(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("follow_up_bead must look like bd-"))
        );
    }

    #[test]
    fn empty_entries_list_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog.entries.clear();
        let report = validate_mounted_write_error_classes(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("at least one entry"))
        );
    }

    #[test]
    fn default_catalog_has_no_broad_fallbacks_after_classification() {
        let report = validate_default_mounted_write_error_classes().expect("default validates");
        assert_eq!(report.broad_fallback_count, 0);
        assert!(
            report
                .error_classes_seen
                .iter()
                .any(|class| class == "product_failure")
        );
    }
}
