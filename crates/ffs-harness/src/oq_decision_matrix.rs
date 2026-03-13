//! OQ (Open Question) decision integration validation matrix.
//!
//! Maps each of the 7 accepted OQ decisions to their implementation evidence:
//! - Decision document location
//! - Unit test function(s)
//! - E2E script(s)
//! - FEATURE_PARITY.md cross-reference
//! - Structured logging target/fields
//!
//! # Contract version
//!
//! The decision-matrix version is [`MATRIX_VERSION`].

use serde::{Deserialize, Serialize};

/// Decision-matrix contract version. Bump on structural changes.
pub const MATRIX_VERSION: u32 = 1;

/// Number of OQ decisions that must be fully resolved.
pub const EXPECTED_OQ_COUNT: usize = 7;

/// A single OQ decision with its validation evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OqDecision {
    /// OQ identifier (e.g., "OQ1").
    pub id: String,
    /// Short title of the decision.
    pub title: String,
    /// Resolution status.
    pub status: DecisionStatus,
    /// Path to the decision document (relative to repo root, if exists).
    pub decision_doc: Option<String>,
    /// Bead ID that closed this OQ.
    pub closing_bead: String,
    /// Unit test patterns that validate this decision.
    pub unit_test_patterns: Vec<String>,
    /// E2E script(s) that validate this decision.
    pub e2e_scripts: Vec<String>,
    /// Implementation crate(s) that contain the decision's code.
    pub impl_crates: Vec<String>,
    /// Structured logging target (if applicable).
    pub log_target: Option<String>,
}

/// Status of an OQ decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionStatus {
    /// Decision has been formally resolved.
    Resolved,
}

/// Build the canonical OQ decision matrix.
#[must_use]
pub fn canonical_matrix() -> Vec<OqDecision> {
    vec![
        OqDecision {
            id: "OQ1".to_owned(),
            title: "Native-mode on-disk boundary and mutation contract".to_owned(),
            status: DecisionStatus::Resolved,
            decision_doc: Some("docs/oq1-native-mode-boundary.md".to_owned()),
            closing_bead: "bd-h6nz.6.1".to_owned(),
            unit_test_patterns: vec![
                "mount_mode_default_is_compat".to_owned(),
                "mode_violation_errno".to_owned(),
            ],
            e2e_scripts: vec!["scripts/e2e/ffs_mount_mode_e2e.sh".to_owned()],
            impl_crates: vec!["ffs-types".to_owned(), "ffs-core".to_owned()],
            log_target: Some("ffs::core".to_owned()),
        },
        OqDecision {
            id: "OQ2".to_owned(),
            title: "Conflict-resolution policy beyond FCW".to_owned(),
            status: DecisionStatus::Resolved,
            decision_doc: None,
            closing_bead: "bd-h6nz.6.2".to_owned(),
            unit_test_patterns: vec!["fcw".to_owned(), "fairness".to_owned()],
            e2e_scripts: vec![],
            impl_crates: vec!["ffs-mvcc".to_owned()],
            log_target: None,
        },
        OqDecision {
            id: "OQ3".to_owned(),
            title: "Repair-symbol invalidation/refresh policy under heavy writes".to_owned(),
            status: DecisionStatus::Resolved,
            decision_doc: None,
            closing_bead: "bd-h6nz.6.3".to_owned(),
            unit_test_patterns: vec!["refresh_policy".to_owned(), "staleness".to_owned()],
            e2e_scripts: vec!["scripts/e2e/ffs_refresh_policy_e2e.sh".to_owned()],
            impl_crates: vec!["ffs-repair".to_owned()],
            log_target: Some("ffs::repair".to_owned()),
        },
        OqDecision {
            id: "OQ4".to_owned(),
            title: "FUSE writeback-mode interaction with MVCC dirty tracking".to_owned(),
            status: DecisionStatus::Resolved,
            decision_doc: None,
            closing_bead: "bd-h6nz.6.4".to_owned(),
            unit_test_patterns: vec!["log_contract".to_owned(), "writeback".to_owned()],
            e2e_scripts: vec!["scripts/e2e/ffs_log_contract_e2e.sh".to_owned()],
            impl_crates: vec!["ffs-core".to_owned(), "ffs-fuse".to_owned()],
            log_target: Some("ffs::core".to_owned()),
        },
        OqDecision {
            id: "OQ5".to_owned(),
            title: "Multi-host repair scope and safety model".to_owned(),
            status: DecisionStatus::Resolved,
            decision_doc: None,
            closing_bead: "bd-h6nz.6.5".to_owned(),
            unit_test_patterns: vec!["repair".to_owned(), "coordination".to_owned()],
            e2e_scripts: vec!["scripts/e2e/ffs_log_contract_e2e.sh".to_owned()],
            impl_crates: vec!["ffs-cli".to_owned()],
            log_target: None,
        },
        OqDecision {
            id: "OQ6".to_owned(),
            title: "Inode generation number lifecycle and reuse policy".to_owned(),
            status: DecisionStatus::Resolved,
            decision_doc: Some("docs/generation-policy.md".to_owned()),
            closing_bead: "bd-h6nz.6.6".to_owned(),
            unit_test_patterns: vec!["generation".to_owned(), "bumps_generation".to_owned()],
            e2e_scripts: vec![],
            impl_crates: vec!["ffs-inode".to_owned(), "ffs-core".to_owned()],
            log_target: Some("ffs::inode::generation".to_owned()),
        },
        OqDecision {
            id: "OQ7".to_owned(),
            title: "Durable version-store persistence format".to_owned(),
            status: DecisionStatus::Resolved,
            decision_doc: Some("docs/oq7-version-store-format.md".to_owned()),
            closing_bead: "bd-h6nz.6.7".to_owned(),
            unit_test_patterns: vec!["oq7".to_owned(), "wal".to_owned(), "persist".to_owned()],
            e2e_scripts: vec!["scripts/e2e/ffs_version_store_format_e2e.sh".to_owned()],
            impl_crates: vec!["ffs-mvcc".to_owned()],
            log_target: None,
        },
    ]
}

/// Validate that all decision documents exist on disk.
#[must_use]
pub fn check_decision_docs(repo_root: &str) -> Vec<DocCheckResult> {
    let matrix = canonical_matrix();
    matrix
        .iter()
        .filter_map(|d| {
            d.decision_doc.as_ref().map(|doc_path| {
                let full_path = format!("{repo_root}/{doc_path}");
                let exists = std::path::Path::new(&full_path).exists();
                DocCheckResult {
                    oq_id: d.id.clone(),
                    doc_path: doc_path.clone(),
                    exists,
                }
            })
        })
        .collect()
}

/// Result of checking a decision document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocCheckResult {
    pub oq_id: String,
    pub doc_path: String,
    pub exists: bool,
}

/// Validate that all E2E scripts exist on disk.
#[must_use]
pub fn check_e2e_scripts(repo_root: &str) -> Vec<ScriptCheckResult> {
    let matrix = canonical_matrix();
    matrix
        .iter()
        .flat_map(|d| {
            d.e2e_scripts.iter().map(move |script| {
                let full_path = format!("{repo_root}/{script}");
                let exists = std::path::Path::new(&full_path).exists();
                ScriptCheckResult {
                    oq_id: d.id.clone(),
                    script_path: script.clone(),
                    exists,
                }
            })
        })
        .collect()
}

/// Result of checking an E2E script.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptCheckResult {
    pub oq_id: String,
    pub script_path: String,
    pub exists: bool,
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
    fn matrix_has_all_seven_decisions() {
        let matrix = canonical_matrix();
        assert_eq!(matrix.len(), EXPECTED_OQ_COUNT);
    }

    #[test]
    fn all_decisions_are_resolved() {
        let matrix = canonical_matrix();
        for d in &matrix {
            assert_eq!(
                d.status,
                DecisionStatus::Resolved,
                "{} should be Resolved",
                d.id
            );
        }
    }

    #[test]
    fn decision_ids_are_sequential() {
        let matrix = canonical_matrix();
        for (i, d) in matrix.iter().enumerate() {
            let expected = format!("OQ{}", i + 1);
            assert_eq!(d.id, expected, "decision at index {i} has wrong id");
        }
    }

    #[test]
    fn every_decision_has_at_least_one_test_pattern() {
        let matrix = canonical_matrix();
        for d in &matrix {
            assert!(
                !d.unit_test_patterns.is_empty(),
                "{} should have at least one unit test pattern",
                d.id
            );
        }
    }

    #[test]
    fn every_decision_has_at_least_one_impl_crate() {
        let matrix = canonical_matrix();
        for d in &matrix {
            assert!(
                !d.impl_crates.is_empty(),
                "{} should have at least one impl crate",
                d.id
            );
        }
    }

    #[test]
    fn decision_documents_exist_on_disk() {
        let root = repo_root();
        let results = check_decision_docs(&root);
        for r in &results {
            assert!(
                r.exists,
                "Decision doc for {} not found: {}",
                r.oq_id, r.doc_path
            );
        }
    }

    #[test]
    fn e2e_scripts_exist_on_disk() {
        let root = repo_root();
        let results = check_e2e_scripts(&root);
        for r in &results {
            assert!(
                r.exists,
                "E2E script for {} not found: {}",
                r.oq_id, r.script_path
            );
        }
    }

    #[test]
    fn matrix_json_round_trips() {
        let matrix = canonical_matrix();
        let json = serde_json::to_string(&matrix).expect("serialize");
        let parsed: Vec<OqDecision> = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.len(), matrix.len());
        assert_eq!(parsed[0].id, matrix[0].id);
    }

    #[test]
    fn no_decision_has_empty_title() {
        let matrix = canonical_matrix();
        for d in &matrix {
            assert!(!d.title.is_empty(), "{} has empty title", d.id);
        }
    }

    #[test]
    fn all_closing_beads_reference_epic_6() {
        let matrix = canonical_matrix();
        for d in &matrix {
            assert!(
                d.closing_bead.starts_with("bd-h6nz.6."),
                "{} closing_bead should reference epic 6: {}",
                d.id,
                d.closing_bead
            );
        }
    }
}
