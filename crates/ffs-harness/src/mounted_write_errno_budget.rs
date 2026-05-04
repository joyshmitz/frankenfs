#![forbid(unsafe_code)]

//! Mounted write errno parity table with broad-fallback budgets.
//!
//! Tracks bd-6t32i: extends the mounted-write error catalog with explicit
//! kernel-errno parity per (filesystem, operation) cell and a per-cell
//! broad-fallback budget. A generic EIO/EINVAL fallback may sometimes be
//! correct, but it needs an explicit budget and follow-up path so operators
//! are not left with opaque failures. The validator fails closed when a
//! broad-fallback cell exceeds its budget without naming a follow-up bead.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MOUNTED_WRITE_ERRNO_BUDGET_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_MOUNTED_WRITE_ERRNO_BUDGET_PATH: &str =
    "tests/mounted-write-errno-budget/mounted_write_errno_budget.json";
const DEFAULT_MOUNTED_WRITE_ERRNO_BUDGET_JSON: &str = include_str!(
    "../../../tests/mounted-write-errno-budget/mounted_write_errno_budget.json"
);

const ALLOWED_FILESYSTEMS: [&str; 2] = ["ext4", "btrfs"];

const ALLOWED_OPERATION_CLASSES: [&str; 11] = [
    "permission_denied",
    "unsupported_operation",
    "stale_snapshot",
    "stale_repair_lease",
    "writeback_cache_gate_refusal",
    "missing_ledger",
    "unsafe_repair_refusal",
    "host_fuse_skip",
    "btrfs_default_permissions_ownership",
    "harness_failure",
    "cleanup_failure",
];

const ALLOWED_USER_FACING_CLASSES: [&str; 8] = [
    "default_permissions_eacces",
    "unsupported_operation",
    "stale_snapshot_refused",
    "repair_serialization_blocked",
    "host_capability_skip",
    "product_failure",
    "harness_bug",
    "broad_fallback",
];

const ALLOWED_NORMALIZED_ERRNOS: [&str; 13] = [
    "EACCES",
    "EPERM",
    "ENOSYS",
    "ENOTSUP",
    "EOPNOTSUPP",
    "EBUSY",
    "EROFS",
    "ESTALE",
    "ECANCELED",
    "ENOTCONN",
    "ENAMETOOLONG",
    "EIO",
    "EINVAL",
];

const ALLOWED_REDACTION_POLICIES: [&str; 4] = [
    "none",
    "redact_paths",
    "redact_paths_and_xattr_values",
    "redact_image_bytes",
];

const REQUIRED_OPERATION_COVERAGE: [&str; 8] = [
    "permission_denied",
    "unsupported_operation",
    "stale_snapshot",
    "stale_repair_lease",
    "writeback_cache_gate_refusal",
    "missing_ledger",
    "unsafe_repair_refusal",
    "host_fuse_skip",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedWriteErrnoBudget {
    pub schema_version: u32,
    pub catalog_id: String,
    pub bead_id: String,
    pub max_broad_fallback_budget_per_cell: u32,
    pub cells: Vec<MountedWriteErrnoCell>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedWriteErrnoCell {
    pub cell_id: String,
    pub filesystem: String,
    pub operation_class: String,
    pub normalized_errno: String,
    pub user_facing_class: String,
    pub remediation_id: String,
    pub artifact_fields: Vec<String>,
    pub redaction_policy: String,
    pub broad_fallback_count: u32,
    #[serde(default)]
    pub broad_fallback_justification: String,
    #[serde(default)]
    pub follow_up_bead: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountedWriteErrnoBudgetReport {
    pub schema_version: u32,
    pub catalog_id: String,
    pub bead_id: String,
    pub cell_count: usize,
    pub operations_covered: Vec<String>,
    pub broad_fallback_total: u32,
    pub budget_exceeded_cell_count: usize,
    pub valid: bool,
    pub errors: Vec<String>,
}

pub fn parse_mounted_write_errno_budget(text: &str) -> Result<MountedWriteErrnoBudget> {
    serde_json::from_str(text).map_err(|err| {
        anyhow::anyhow!("failed to parse mounted write errno budget JSON: {err}")
    })
}

pub fn validate_default_mounted_write_errno_budget() -> Result<MountedWriteErrnoBudgetReport> {
    let catalog = parse_mounted_write_errno_budget(DEFAULT_MOUNTED_WRITE_ERRNO_BUDGET_JSON)?;
    let report = validate_mounted_write_errno_budget(&catalog);
    if !report.valid {
        bail!(
            "mounted write errno budget failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        );
    }
    Ok(report)
}

#[must_use]
pub fn validate_mounted_write_errno_budget(
    catalog: &MountedWriteErrnoBudget,
) -> MountedWriteErrnoBudgetReport {
    let mut errors = Vec::new();
    let mut ids = BTreeSet::new();
    let mut cell_keys = BTreeSet::new();
    let mut operations_covered = BTreeSet::new();
    let mut broad_fallback_total = 0_u32;
    let mut budget_exceeded_cells = 0_usize;

    validate_top_level(catalog, &mut errors);
    for cell in &catalog.cells {
        validate_cell(
            cell,
            catalog.max_broad_fallback_budget_per_cell,
            &mut ids,
            &mut cell_keys,
            &mut operations_covered,
            &mut broad_fallback_total,
            &mut budget_exceeded_cells,
            &mut errors,
        );
    }
    validate_operation_coverage(&operations_covered, &mut errors);
    validate_filesystem_pair_coverage(catalog, &mut errors);

    MountedWriteErrnoBudgetReport {
        schema_version: catalog.schema_version,
        catalog_id: catalog.catalog_id.clone(),
        bead_id: catalog.bead_id.clone(),
        cell_count: catalog.cells.len(),
        operations_covered: operations_covered.into_iter().collect(),
        broad_fallback_total,
        budget_exceeded_cell_count: budget_exceeded_cells,
        valid: errors.is_empty(),
        errors,
    }
}

fn validate_top_level(catalog: &MountedWriteErrnoBudget, errors: &mut Vec<String>) {
    if catalog.schema_version != MOUNTED_WRITE_ERRNO_BUDGET_SCHEMA_VERSION {
        errors.push(format!(
            "mounted write errno budget schema_version must be {MOUNTED_WRITE_ERRNO_BUDGET_SCHEMA_VERSION}, got {}",
            catalog.schema_version
        ));
    }
    if catalog.catalog_id.trim().is_empty() {
        errors.push("mounted write errno budget missing catalog_id".to_owned());
    }
    if !catalog.bead_id.starts_with("bd-") {
        errors.push(format!(
            "mounted write errno budget bead_id must look like bd-..., got `{}`",
            catalog.bead_id
        ));
    }
    if catalog.max_broad_fallback_budget_per_cell == 0 {
        errors.push(
            "max_broad_fallback_budget_per_cell must be positive; otherwise broad fallbacks cannot be tracked"
                .to_owned(),
        );
    }
    if catalog.cells.is_empty() {
        errors.push("mounted write errno budget must declare at least one cell".to_owned());
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_cell(
    cell: &MountedWriteErrnoCell,
    max_budget: u32,
    ids: &mut BTreeSet<String>,
    cell_keys: &mut BTreeSet<(String, String)>,
    operations_covered: &mut BTreeSet<String>,
    broad_fallback_total: &mut u32,
    budget_exceeded_cells: &mut usize,
    errors: &mut Vec<String>,
) {
    if !ids.insert(cell.cell_id.clone()) {
        errors.push(format!(
            "duplicate mounted write errno cell_id `{}`",
            cell.cell_id
        ));
    }
    if !cell.cell_id.starts_with("ewb_") {
        errors.push(format!(
            "cell_id `{}` must start with ewb_",
            cell.cell_id
        ));
    }
    if !ALLOWED_FILESYSTEMS.contains(&cell.filesystem.as_str()) {
        errors.push(format!(
            "cell `{}` has unsupported filesystem `{}`",
            cell.cell_id, cell.filesystem
        ));
    }
    if ALLOWED_OPERATION_CLASSES.contains(&cell.operation_class.as_str()) {
        operations_covered.insert(cell.operation_class.clone());
    } else {
        errors.push(format!(
            "cell `{}` has unsupported operation_class `{}`",
            cell.cell_id, cell.operation_class
        ));
    }
    let key = (cell.filesystem.clone(), cell.operation_class.clone());
    if !cell_keys.insert(key) {
        errors.push(format!(
            "cell `{}` duplicates the (filesystem, operation_class) pair (`{}`, `{}`)",
            cell.cell_id, cell.filesystem, cell.operation_class
        ));
    }
    if !ALLOWED_NORMALIZED_ERRNOS.contains(&cell.normalized_errno.as_str()) {
        errors.push(format!(
            "cell `{}` has unsupported normalized_errno `{}`",
            cell.cell_id, cell.normalized_errno
        ));
    }
    if !ALLOWED_USER_FACING_CLASSES.contains(&cell.user_facing_class.as_str()) {
        errors.push(format!(
            "cell `{}` has unsupported user_facing_class `{}`",
            cell.cell_id, cell.user_facing_class
        ));
    }
    if !cell.remediation_id.starts_with("rem_") {
        errors.push(format!(
            "cell `{}` remediation_id must use the rem_ prefix",
            cell.cell_id
        ));
    }
    if !ALLOWED_REDACTION_POLICIES.contains(&cell.redaction_policy.as_str()) {
        errors.push(format!(
            "cell `{}` has unsupported redaction_policy `{}`",
            cell.cell_id, cell.redaction_policy
        ));
    }
    if cell.artifact_fields.is_empty() {
        errors.push(format!(
            "cell `{}` must declare at least one artifact_field",
            cell.cell_id
        ));
    }
    for required in [
        "operation_id",
        "scenario_id",
        "raw_errno",
        "normalized_errno",
        "remediation_id",
    ] {
        if !cell.artifact_fields.iter().any(|field| field == required) {
            errors.push(format!(
                "cell `{}` artifact_fields missing `{required}`",
                cell.cell_id
            ));
        }
    }

    validate_errno_class_consistency(cell, errors);
    validate_broad_fallback_invariants(
        cell,
        max_budget,
        broad_fallback_total,
        budget_exceeded_cells,
        errors,
    );
}

fn validate_errno_class_consistency(
    cell: &MountedWriteErrnoCell,
    errors: &mut Vec<String>,
) {
    let expected_errnos: &[&str] = match cell.user_facing_class.as_str() {
        "default_permissions_eacces" => &["EACCES", "EPERM"],
        "unsupported_operation" => &["ENOSYS", "ENOTSUP", "EOPNOTSUPP", "ENAMETOOLONG"],
        "stale_snapshot_refused" => &["ESTALE", "EROFS"],
        "repair_serialization_blocked" => &["EBUSY", "EROFS"],
        "host_capability_skip" => &["ENOTCONN", "ENOSYS"],
        "broad_fallback" => &["EIO", "EINVAL"],
        _ => &[],
    };
    if !expected_errnos.is_empty()
        && !expected_errnos
            .iter()
            .any(|expected| *expected == cell.normalized_errno)
    {
        errors.push(format!(
            "cell `{}` normalized_errno `{}` does not match user_facing_class `{}` expectations",
            cell.cell_id, cell.normalized_errno, cell.user_facing_class
        ));
    }
    if cell.user_facing_class == "default_permissions_eacces"
        && cell.filesystem != "btrfs"
        && cell.operation_class == "btrfs_default_permissions_ownership"
    {
        errors.push(format!(
            "cell `{}` btrfs_default_permissions_ownership requires filesystem=btrfs",
            cell.cell_id
        ));
    }
}

fn validate_broad_fallback_invariants(
    cell: &MountedWriteErrnoCell,
    max_budget: u32,
    broad_fallback_total: &mut u32,
    budget_exceeded_cells: &mut usize,
    errors: &mut Vec<String>,
) {
    let is_broad = cell.user_facing_class == "broad_fallback";
    *broad_fallback_total = broad_fallback_total.saturating_add(cell.broad_fallback_count);

    if is_broad {
        if cell.broad_fallback_justification.trim().is_empty() {
            errors.push(format!(
                "cell `{}` broad_fallback class must declare broad_fallback_justification",
                cell.cell_id
            ));
        }
        if !cell.follow_up_bead.starts_with("bd-") {
            errors.push(format!(
                "cell `{}` broad_fallback class must link a follow_up_bead (bd-...)",
                cell.cell_id
            ));
        }
        if cell.broad_fallback_count == 0 {
            errors.push(format!(
                "cell `{}` broad_fallback class must record a positive broad_fallback_count",
                cell.cell_id
            ));
        }
    } else {
        if cell.broad_fallback_count != 0 {
            errors.push(format!(
                "cell `{}` non-broad class must leave broad_fallback_count=0",
                cell.cell_id
            ));
        }
        if !cell.broad_fallback_justification.trim().is_empty() {
            errors.push(format!(
                "cell `{}` non-broad class must leave broad_fallback_justification empty",
                cell.cell_id
            ));
        }
        if !cell.follow_up_bead.is_empty() && !cell.follow_up_bead.starts_with("bd-") {
            errors.push(format!(
                "cell `{}` follow_up_bead must look like bd-..., got `{}`",
                cell.cell_id, cell.follow_up_bead
            ));
        }
    }

    if cell.broad_fallback_count > max_budget {
        *budget_exceeded_cells += 1;
        errors.push(format!(
            "cell `{}` broad_fallback_count {} exceeds max_broad_fallback_budget_per_cell {}; create a follow-up bead and split the fallback before merging",
            cell.cell_id, cell.broad_fallback_count, max_budget
        ));
    }
}

fn validate_operation_coverage(seen: &BTreeSet<String>, errors: &mut Vec<String>) {
    for required in REQUIRED_OPERATION_COVERAGE {
        if !seen.contains(required) {
            errors.push(format!(
                "mounted write errno budget missing required operation_class `{required}`"
            ));
        }
    }
}

fn validate_filesystem_pair_coverage(
    catalog: &MountedWriteErrnoBudget,
    errors: &mut Vec<String>,
) {
    let permission_filesystems: BTreeSet<&str> = catalog
        .cells
        .iter()
        .filter(|cell| cell.operation_class == "permission_denied")
        .map(|cell| cell.filesystem.as_str())
        .collect();
    for required in ALLOWED_FILESYSTEMS {
        if !permission_filesystems.contains(required) {
            errors.push(format!(
                "mounted write errno budget must include a permission_denied cell for filesystem `{required}`"
            ));
        }
    }
    let unsupported_filesystems: BTreeSet<&str> = catalog
        .cells
        .iter()
        .filter(|cell| cell.operation_class == "unsupported_operation")
        .map(|cell| cell.filesystem.as_str())
        .collect();
    for required in ALLOWED_FILESYSTEMS {
        if !unsupported_filesystems.contains(required) {
            errors.push(format!(
                "mounted write errno budget must include an unsupported_operation cell for filesystem `{required}`"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_catalog() -> MountedWriteErrnoBudget {
        parse_mounted_write_errno_budget(DEFAULT_MOUNTED_WRITE_ERRNO_BUDGET_JSON)
            .expect("default mounted write errno budget parses")
    }

    #[test]
    fn default_catalog_validates_required_coverage() {
        let report = validate_default_mounted_write_errno_budget()
            .expect("default mounted write errno budget validates");
        assert_eq!(report.bead_id, "bd-6t32i");
        for op in REQUIRED_OPERATION_COVERAGE {
            assert!(
                report.operations_covered.iter().any(|o| o == op),
                "missing operation {op}"
            );
        }
        assert_eq!(report.budget_exceeded_cell_count, 0);
    }

    #[test]
    fn missing_required_operation_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog
            .cells
            .retain(|cell| cell.operation_class != "stale_repair_lease");
        let report = validate_mounted_write_errno_budget(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required operation_class `stale_repair_lease`"))
        );
    }

    #[test]
    fn missing_writeback_cache_operation_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog
            .cells
            .retain(|cell| cell.operation_class != "writeback_cache_gate_refusal");
        let report = validate_mounted_write_errno_budget(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing required operation_class `writeback_cache_gate_refusal`"))
        );
    }

    #[test]
    fn permission_denied_must_cover_both_filesystems() {
        let mut catalog = fixture_catalog();
        catalog
            .cells
            .retain(|cell| !(cell.operation_class == "permission_denied" && cell.filesystem == "btrfs"));
        let report = validate_mounted_write_errno_budget(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("permission_denied cell for filesystem `btrfs`"))
        );
    }

    #[test]
    fn unsupported_operation_must_cover_both_filesystems() {
        let mut catalog = fixture_catalog();
        catalog
            .cells
            .retain(|cell| !(cell.operation_class == "unsupported_operation" && cell.filesystem == "ext4"));
        let report = validate_mounted_write_errno_budget(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported_operation cell for filesystem `ext4`"))
        );
    }

    #[test]
    fn duplicate_filesystem_operation_pair_is_rejected() {
        let mut catalog = fixture_catalog();
        let template = catalog.cells[0].clone();
        let mut clone = template.clone();
        clone.cell_id = format!("{}_dup", clone.cell_id);
        catalog.cells.push(clone);
        let report = validate_mounted_write_errno_budget(&catalog);
        assert!(report.errors.iter().any(|err| err
            .contains("duplicates the (filesystem, operation_class) pair")));
    }

    #[test]
    fn duplicate_cell_id_is_rejected() {
        let mut catalog = fixture_catalog();
        let dup = catalog.cells[0].cell_id.clone();
        catalog.cells[1].cell_id = dup;
        let report = validate_mounted_write_errno_budget(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("duplicate mounted write errno cell_id"))
        );
    }

    #[test]
    fn cell_id_prefix_is_enforced() {
        let mut catalog = fixture_catalog();
        catalog.cells[0].cell_id = "cell_001".to_owned();
        let report = validate_mounted_write_errno_budget(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must start with ewb_"))
        );
    }

    #[test]
    fn errno_must_match_user_facing_class() {
        let mut catalog = fixture_catalog();
        let cell = catalog
            .cells
            .iter_mut()
            .find(|c| c.user_facing_class == "default_permissions_eacces")
            .expect("default permissions cell exists");
        cell.normalized_errno = "EIO".to_owned();
        let report = validate_mounted_write_errno_budget(&catalog);
        assert!(report.errors.iter().any(|err| err
            .contains("does not match user_facing_class `default_permissions_eacces`")));
    }

    #[test]
    fn unsupported_normalized_errno_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog.cells[0].normalized_errno = "EUNICORN".to_owned();
        let report = validate_mounted_write_errno_budget(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported normalized_errno"))
        );
    }

    #[test]
    fn malformed_remediation_id_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog.cells[0].remediation_id = "fix-it".to_owned();
        let report = validate_mounted_write_errno_budget(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("remediation_id must use the rem_ prefix"))
        );
    }

    #[test]
    fn missing_required_artifact_field_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog.cells[0]
            .artifact_fields
            .retain(|f| f != "raw_errno");
        let report = validate_mounted_write_errno_budget(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("artifact_fields missing `raw_errno`"))
        );
    }

    #[test]
    fn broad_fallback_class_requires_justification() {
        let mut catalog = fixture_catalog();
        let cell = catalog
            .cells
            .iter_mut()
            .find(|c| c.user_facing_class == "broad_fallback")
            .expect("broad fallback cell exists");
        cell.broad_fallback_justification = String::new();
        let report = validate_mounted_write_errno_budget(&catalog);
        assert!(report.errors.iter().any(|err| err
            .contains("broad_fallback class must declare broad_fallback_justification")));
    }

    #[test]
    fn broad_fallback_class_requires_follow_up_bead() {
        let mut catalog = fixture_catalog();
        let cell = catalog
            .cells
            .iter_mut()
            .find(|c| c.user_facing_class == "broad_fallback")
            .expect("broad fallback cell exists");
        cell.follow_up_bead = String::new();
        let report = validate_mounted_write_errno_budget(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must link a follow_up_bead"))
        );
    }

    #[test]
    fn broad_fallback_class_requires_positive_count() {
        let mut catalog = fixture_catalog();
        let cell = catalog
            .cells
            .iter_mut()
            .find(|c| c.user_facing_class == "broad_fallback")
            .expect("broad fallback cell exists");
        cell.broad_fallback_count = 0;
        let report = validate_mounted_write_errno_budget(&catalog);
        assert!(report.errors.iter().any(|err| err
            .contains("broad_fallback class must record a positive broad_fallback_count")));
    }

    #[test]
    fn non_broad_class_must_leave_count_zero() {
        let mut catalog = fixture_catalog();
        let cell = catalog
            .cells
            .iter_mut()
            .find(|c| c.user_facing_class != "broad_fallback")
            .expect("non-broad cell exists");
        cell.broad_fallback_count = 5;
        let report = validate_mounted_write_errno_budget(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("non-broad class must leave broad_fallback_count=0"))
        );
    }

    #[test]
    fn budget_exceeded_cell_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog.max_broad_fallback_budget_per_cell = 1;
        let cell = catalog
            .cells
            .iter_mut()
            .find(|c| c.user_facing_class == "broad_fallback")
            .expect("broad fallback cell exists");
        cell.broad_fallback_count = 5;
        let report = validate_mounted_write_errno_budget(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("exceeds max_broad_fallback_budget_per_cell"))
        );
        assert_eq!(report.budget_exceeded_cell_count, 1);
    }

    #[test]
    fn zero_max_budget_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog.max_broad_fallback_budget_per_cell = 0;
        let report = validate_mounted_write_errno_budget(&catalog);
        assert!(report.errors.iter().any(|err| err
            .contains("max_broad_fallback_budget_per_cell must be positive")));
    }

    #[test]
    fn empty_artifact_fields_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog.cells[0].artifact_fields.clear();
        let report = validate_mounted_write_errno_budget(&catalog);
        assert!(report.errors.iter().any(|err| err
            .contains("must declare at least one artifact_field")));
    }

    #[test]
    fn empty_cells_list_is_rejected() {
        let mut catalog = fixture_catalog();
        catalog.cells.clear();
        let report = validate_mounted_write_errno_budget(&catalog);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("at least one cell"))
        );
    }
}
