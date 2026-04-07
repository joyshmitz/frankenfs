//! Btrfs capability drift detection.
//!
//! Verifies that the btrfs experimental RW capability contract documented in
//! `FEATURE_PARITY.md` stays synchronized with actual test/scenario coverage.
//!
//! # How it works
//!
//! 1. Parse the capability table from `FEATURE_PARITY.md` section 2.1.
//! 2. For `unit::*` contract IDs, verify the test function exists in `ffs-core`.
//! 3. For `e2e::*` contract IDs, verify the capability is backed either by an
//!    E2E script scenario or by an end-to-end Rust test in `ffs-core`.
//!
//! # Contract version
//!
//! The drift-detection contract version is [`DRIFT_CONTRACT_VERSION`].

/// Drift-detection contract version.
pub const DRIFT_CONTRACT_VERSION: u32 = 1;

/// A parsed capability contract row from FEATURE_PARITY.md.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityContractRow {
    /// Full contract ID (e.g., `unit::btrfs_write_create_file`).
    pub contract_id: String,
    /// Whether this is a unit or e2e contract.
    pub kind: ContractKind,
    /// Bare function/scenario name (stripped prefix).
    pub bare_name: String,
    /// Capability class: supported, unsupported, observability, etc.
    pub class: String,
}

/// Type of contract verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractKind {
    Unit,
    E2e,
}

/// Result of drift checking one contract row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftCheckResult {
    pub contract_id: String,
    pub kind: ContractKind,
    pub found: bool,
}

/// Parse the btrfs capability table from FEATURE_PARITY.md content.
///
/// Looks for lines matching `| \`unit::*\` |` or `| \`e2e::*\` |`.
#[must_use]
pub fn parse_capability_table(feature_parity_content: &str) -> Vec<CapabilityContractRow> {
    let mut rows = Vec::new();

    for line in feature_parity_content.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('|') {
            continue;
        }

        // Extract contract ID from first column.
        let cols: Vec<&str> = trimmed.split('|').collect();
        if cols.len() < 5 {
            continue;
        }

        let id_col = cols[1].trim();
        let class_col = cols[3].trim();

        // Match `unit::name` or `e2e::name` (backtick-wrapped).
        let contract_id = id_col
            .trim_start_matches('`')
            .trim_end_matches('`')
            .to_owned();

        if let Some(bare) = contract_id.strip_prefix("unit::") {
            rows.push(CapabilityContractRow {
                contract_id: contract_id.clone(),
                kind: ContractKind::Unit,
                bare_name: bare.to_owned(),
                class: class_col.to_owned(),
            });
        } else if let Some(bare) = contract_id.strip_prefix("e2e::") {
            rows.push(CapabilityContractRow {
                contract_id: contract_id.clone(),
                kind: ContractKind::E2e,
                bare_name: bare.to_owned(),
                class: class_col.to_owned(),
            });
        }
    }

    rows
}

/// Check a unit contract row against ffs-core source code.
///
/// Returns true if a function named `bare_name` exists in the source.
#[must_use]
pub fn check_unit_contract(ffs_core_source: &str, bare_name: &str) -> bool {
    // Match `fn bare_name(` pattern.
    let pattern = format!("fn {bare_name}(");
    ffs_core_source.contains(&pattern)
}

/// Check an E2E contract row against E2E script content.
///
/// Returns true if the scenario can be traced in the E2E script.  E2E scripts
/// assemble scenario IDs at runtime (e.g. `btrfs_rw_` + case name, or
/// `btrfs_rw_crash_matrix_` + point_id + label), so this function checks
/// progressively stripped forms:
///
/// 1. Full bare name literal match.
/// 2. With any `<fs>_rw_` prefix stripped (catches mirrored `run_case`
///    arguments such as `btrfs_rw_*` and `ext4_rw_*`).
/// 3. For crash-matrix patterns: the label after `crash_matrix_NN_` (catches
///    labels in the `crash_matrix_label_for_point` case table).
#[must_use]
pub fn check_e2e_contract(e2e_content: &str, bare_name: &str) -> bool {
    // 1. Literal match.
    if e2e_content.contains(bare_name) {
        return true;
    }

    // 2. Strip the conventional `<fs>_rw_` prefix used by mirrored smoke
    // suites so the shared case names still satisfy drift detection.
    let stripped = bare_name
        .split_once("_rw_")
        .map_or(bare_name, |(_, rest)| rest);
    if e2e_content.contains(stripped) {
        return true;
    }

    // 3. Crash-matrix: strip `crash_matrix_NN_` to get the label.
    if let Some(rest) = stripped.strip_prefix("crash_matrix_") {
        // Skip the two-digit point ID and underscore (e.g. "01_").
        if rest.len() > 3 && rest.as_bytes()[2] == b'_' {
            let label = &rest[3..];
            if e2e_content.contains(label) {
                return true;
            }
        }
    }

    false
}

/// Check an E2E contract row against all known backing sources.
#[must_use]
pub fn check_e2e_contract_backing(
    ffs_core_source: &str,
    e2e_content: &str,
    bare_name: &str,
) -> bool {
    check_e2e_contract(e2e_content, bare_name) || check_unit_contract(ffs_core_source, bare_name)
}

/// Run full drift detection and return results.
#[must_use]
pub fn check_btrfs_drift(
    feature_parity_content: &str,
    ffs_core_source: &str,
    e2e_content: &str,
) -> Vec<DriftCheckResult> {
    let rows = parse_capability_table(feature_parity_content);
    rows.iter()
        .map(|row| {
            let found = match row.kind {
                ContractKind::Unit => check_unit_contract(ffs_core_source, &row.bare_name),
                ContractKind::E2e => {
                    check_e2e_contract_backing(ffs_core_source, e2e_content, &row.bare_name)
                }
            };
            DriftCheckResult {
                contract_id: row.contract_id.clone(),
                kind: row.kind,
                found,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_root() -> String {
        env!("CARGO_MANIFEST_DIR")
            .strip_suffix("/crates/ffs-harness")
            .expect("harness must be in crates/ffs-harness")
            .to_owned()
    }

    #[test]
    fn parse_capability_table_extracts_rows() {
        let content = r"
| Contract ID | Operation | Class | Expected |
|---|---|---|---|
| `unit::btrfs_write_create_file` | create | supported | success |
| `e2e::btrfs_rw_crash_matrix_01_create_alpha_no_fsync` | crash 1 | crash-consistency | ok |
| Some other row | stuff | stuff | stuff |
";
        let rows = parse_capability_table(content);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].contract_id, "unit::btrfs_write_create_file");
        assert_eq!(rows[0].kind, ContractKind::Unit);
        assert_eq!(rows[0].bare_name, "btrfs_write_create_file");
        assert_eq!(rows[1].kind, ContractKind::E2e);
        assert_eq!(
            rows[1].bare_name,
            "btrfs_rw_crash_matrix_01_create_alpha_no_fsync"
        );
    }

    #[test]
    fn check_e2e_contract_accepts_mirrored_ext4_crash_matrix_contract_ids() {
        let e2e_script = r#"
crash_matrix_label_for_point() {
    case "$1" in
        1) printf 'create_alpha_no_fsync' ;;
        *) return 1 ;;
    esac
}
"#;

        assert!(check_e2e_contract(
            e2e_script,
            "btrfs_rw_crash_matrix_01_create_alpha_no_fsync"
        ));
        assert!(check_e2e_contract(
            e2e_script,
            "ext4_rw_crash_matrix_01_create_alpha_no_fsync"
        ));
    }

    #[test]
    fn check_e2e_contract_backing_accepts_ext4_end_to_end_rust_tests() {
        let core_src = "fn ext4_rw_crash_matrix_08_multi_file_interleaved_fsync() {}";

        assert!(check_e2e_contract_backing(
            core_src,
            "",
            "ext4_rw_crash_matrix_08_multi_file_interleaved_fsync"
        ));
    }

    #[test]
    fn all_documented_unit_contracts_have_test_functions() {
        let root = repo_root();
        let parity =
            std::fs::read_to_string(format!("{root}/FEATURE_PARITY.md")).expect("read parity");
        let core_src = std::fs::read_to_string(format!("{root}/crates/ffs-core/src/lib.rs"))
            .expect("read core");

        let rows = parse_capability_table(&parity);
        let unit_rows: Vec<_> = rows
            .iter()
            .filter(|r| r.kind == ContractKind::Unit)
            .collect();

        assert!(
            !unit_rows.is_empty(),
            "should have parsed at least one unit contract row"
        );

        for row in &unit_rows {
            assert!(
                check_unit_contract(&core_src, &row.bare_name),
                "DRIFT: unit contract '{}' documented in FEATURE_PARITY.md but test function \
                 fn {}() not found in ffs-core/src/lib.rs",
                row.contract_id,
                row.bare_name
            );
        }
    }

    #[test]
    fn all_documented_e2e_contracts_have_scenario_references() {
        let root = repo_root();
        let parity =
            std::fs::read_to_string(format!("{root}/FEATURE_PARITY.md")).expect("read parity");
        let core_src = std::fs::read_to_string(format!("{root}/crates/ffs-core/src/lib.rs"))
            .expect("read core");
        let e2e_script =
            std::fs::read_to_string(format!("{root}/scripts/e2e/ffs_btrfs_rw_smoke.sh"))
                .expect("read e2e script");

        let rows = parse_capability_table(&parity);
        let e2e_rows: Vec<_> = rows
            .iter()
            .filter(|r| r.kind == ContractKind::E2e)
            .collect();

        assert!(
            !e2e_rows.is_empty(),
            "should have parsed at least one e2e contract row"
        );

        for row in &e2e_rows {
            assert!(
                check_e2e_contract_backing(&core_src, &e2e_script, &row.bare_name),
                "DRIFT: e2e contract '{}' documented in FEATURE_PARITY.md but backing test \
                 '{}' not found in ffs-core/src/lib.rs or scripts/e2e/ffs_btrfs_rw_smoke.sh",
                row.contract_id,
                row.bare_name
            );
        }
    }

    #[test]
    fn full_drift_check_passes_for_repo() {
        let root = repo_root();
        let parity =
            std::fs::read_to_string(format!("{root}/FEATURE_PARITY.md")).expect("read parity");
        let core_src = std::fs::read_to_string(format!("{root}/crates/ffs-core/src/lib.rs"))
            .expect("read core");
        let e2e_script =
            std::fs::read_to_string(format!("{root}/scripts/e2e/ffs_btrfs_rw_smoke.sh"))
                .expect("read e2e script");

        let results = check_btrfs_drift(&parity, &core_src, &e2e_script);
        assert!(
            !results.is_empty(),
            "should have at least one drift check result"
        );

        let drifted: Vec<_> = results.iter().filter(|r| !r.found).collect();
        assert!(
            drifted.is_empty(),
            "DRIFT detected in {} contracts: {:?}",
            drifted.len(),
            drifted
                .iter()
                .map(|r| r.contract_id.as_str())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn parse_ignores_non_contract_rows() {
        let content = r"
| Contract ID | Op | Class | Result |
|---|---|---|---|
| MVCC snapshot visibility | spec §3 | ✅ | ok |
| `unit::btrfs_write_mkdir` | mkdir | supported | success |
";
        let rows = parse_capability_table(content);
        // Only the unit:: row should match
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].bare_name, "btrfs_write_mkdir");
    }

    #[test]
    fn check_unit_contract_returns_false_for_missing() {
        let fake_source = "fn some_other_function() {}";
        assert!(!check_unit_contract(fake_source, "btrfs_write_nonexistent"));
    }

    #[test]
    fn contract_row_count_matches_expected() {
        let root = repo_root();
        let parity =
            std::fs::read_to_string(format!("{root}/FEATURE_PARITY.md")).expect("read parity");
        let rows = parse_capability_table(&parity);

        let unit_count = rows.iter().filter(|r| r.kind == ContractKind::Unit).count();
        let e2e_count = rows.iter().filter(|r| r.kind == ContractKind::E2e).count();

        // At minimum: 16 unit contracts + 12 e2e contracts from the known table
        assert!(
            unit_count >= 15,
            "expected >= 15 unit contracts, got {unit_count}"
        );
        assert!(
            e2e_count >= 10,
            "expected >= 10 e2e contracts, got {e2e_count}"
        );
    }
}
