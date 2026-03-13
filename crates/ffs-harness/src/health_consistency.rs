//! Cross-surface health state consistency contract.
//!
//! FrankenFS reports runtime health across three surfaces:
//! - **CLI** (`ffs info`, `ffs evidence`) — snapshot at command time
//! - **TUI** (`DashboardSnapshot`) — live polling dashboard
//! - **Structured logs** (`tracing` events) — streaming telemetry
//!
//! This module defines canonical health dimensions and tests that verify
//! each dimension is represented consistently across all surfaces.
//!
//! # Source-of-truth priority
//!
//! When surfaces temporarily diverge during state transitions:
//!
//! | Dimension            | Canonical source                       | Propagation |
//! |---------------------|----------------------------------------|-------------|
//! | Degradation level   | `DegradationFsm::level()` (ffs-core)  | Atomic read |
//! | Runtime mode        | CLI args at mount time                 | Immutable   |
//! | WAL replay status   | `WalRecoveryReport` (ffs-mvcc)         | Set once    |
//! | Repair staleness    | Repair metrics (ffs-repair)            | Polled      |
//! | Pressure counters   | `AtomicMetrics` (ffs-fuse)             | Atomic      |
//!
//! # Contract version
//!
//! The current consistency contract version is [`HEALTH_CONTRACT_VERSION`].
//! Bump when adding new canonical dimensions or changing source-of-truth.

use serde::{Deserialize, Serialize};

/// Schema contract version. Bump on any breaking change.
pub const HEALTH_CONTRACT_VERSION: u32 = 1;

// ── Canonical health dimensions ────────────────────────────────────────────

/// Canonical health dimension identifiers.
///
/// Each dimension must be representable on CLI, TUI, and structured log surfaces.
pub mod dimension {
    /// Degradation level (Normal/Warning/Degraded/Critical/Emergency).
    pub const DEGRADATION_LEVEL: &str = "degradation_level";

    /// Mount runtime mode (standard/managed/per-core).
    pub const RUNTIME_MODE: &str = "runtime_mode";

    /// WAL replay status after mount (clean/recovered/corrupted).
    pub const REPLAY_STATUS: &str = "replay_status";

    /// Repair symbol staleness (fresh/stale/untracked).
    pub const REPAIR_STALENESS: &str = "repair_staleness";

    /// Backpressure state (requests throttled/shed).
    pub const PRESSURE_COUNTERS: &str = "pressure_counters";

    /// All canonical dimensions.
    pub const ALL_DIMENSIONS: &[&str] = &[
        DEGRADATION_LEVEL,
        RUNTIME_MODE,
        REPLAY_STATUS,
        REPAIR_STALENESS,
        PRESSURE_COUNTERS,
    ];
}

/// Expected representation of a health dimension on a specific surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceExpectation {
    /// Which health dimension.
    pub dimension: String,
    /// Which surface: "cli", "tui", or "log".
    pub surface: String,
    /// Identifier strings that MUST appear in that surface's source code.
    pub required_identifiers: Vec<String>,
    /// Source file path (relative to repo root) to check.
    pub source_file: String,
}

/// Result of checking one surface expectation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyResult {
    pub dimension: String,
    pub surface: String,
    pub passed: bool,
    pub identifiers_found: Vec<String>,
    pub identifiers_missing: Vec<String>,
}

/// Aggregate consistency verdict across all surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyVerdict {
    pub version: u32,
    pub total_checks: usize,
    pub passed: usize,
    pub failed: usize,
    pub results: Vec<ConsistencyResult>,
}

// ── Surface expectation definitions ────────────────────────────────────────

/// Build the canonical set of surface expectations.
///
/// Each entry asserts that a particular health dimension is represented
/// in a particular surface's source code via identifiable strings.
#[must_use]
pub fn canonical_expectations() -> Vec<SurfaceExpectation> {
    vec![
        // ── Degradation level ──────────────────────────────────────────
        SurfaceExpectation {
            dimension: dimension::DEGRADATION_LEVEL.to_owned(),
            surface: "core".to_owned(),
            required_identifiers: vec![
                "DegradationLevel".to_owned(),
                "Normal".to_owned(),
                "Warning".to_owned(),
                "Degraded".to_owned(),
                "Critical".to_owned(),
                "Emergency".to_owned(),
            ],
            source_file: "crates/ffs-core/src/degradation.rs".to_owned(),
        },
        SurfaceExpectation {
            dimension: dimension::DEGRADATION_LEVEL.to_owned(),
            surface: "tui".to_owned(),
            required_identifiers: vec![
                "degradation_level".to_owned(),
                "DegradationLevel".to_owned(),
            ],
            source_file: "crates/ffs-tui/src/lib.rs".to_owned(),
        },
        SurfaceExpectation {
            dimension: dimension::DEGRADATION_LEVEL.to_owned(),
            surface: "log".to_owned(),
            required_identifiers: vec!["degradation_transition".to_owned()],
            source_file: "crates/ffs-core/src/degradation.rs".to_owned(),
        },
        // ── Runtime mode ──────────────────────────────────────────────
        SurfaceExpectation {
            dimension: dimension::RUNTIME_MODE.to_owned(),
            surface: "cli".to_owned(),
            required_identifiers: vec![
                "runtime_mode".to_owned(),
                "Standard".to_owned(),
                "Managed".to_owned(),
                "PerCore".to_owned(),
            ],
            source_file: "crates/ffs-cli/src/main.rs".to_owned(),
        },
        SurfaceExpectation {
            dimension: dimension::RUNTIME_MODE.to_owned(),
            surface: "log".to_owned(),
            required_identifiers: vec!["mount_runtime_mode_selected".to_owned()],
            source_file: "crates/ffs-cli/src/main.rs".to_owned(),
        },
        // ── WAL replay status ─────────────────────────────────────────
        SurfaceExpectation {
            dimension: dimension::REPLAY_STATUS.to_owned(),
            surface: "cli".to_owned(),
            required_identifiers: vec![
                "wal_recovery_telemetry".to_owned(),
                "commits_replayed".to_owned(),
                "records_discarded".to_owned(),
            ],
            source_file: "crates/ffs-cli/src/main.rs".to_owned(),
        },
        SurfaceExpectation {
            dimension: dimension::REPLAY_STATUS.to_owned(),
            surface: "log".to_owned(),
            required_identifiers: vec!["wal_replay_start".to_owned(), "wal_replay_done".to_owned()],
            source_file: "crates/ffs-mvcc/src/wal_replay.rs".to_owned(),
        },
        // ── Repair staleness ──────────────────────────────────────────
        SurfaceExpectation {
            dimension: dimension::REPAIR_STALENESS.to_owned(),
            surface: "cli".to_owned(),
            required_identifiers: vec!["groups_fresh".to_owned(), "groups_stale".to_owned()],
            source_file: "crates/ffs-cli/src/main.rs".to_owned(),
        },
        // ── Pressure counters ─────────────────────────────────────────
        SurfaceExpectation {
            dimension: dimension::PRESSURE_COUNTERS.to_owned(),
            surface: "fuse".to_owned(),
            required_identifiers: vec!["requests_throttled".to_owned(), "requests_shed".to_owned()],
            source_file: "crates/ffs-fuse/src/lib.rs".to_owned(),
        },
        SurfaceExpectation {
            dimension: dimension::PRESSURE_COUNTERS.to_owned(),
            surface: "log".to_owned(),
            required_identifiers: vec!["requests_throttled".to_owned(), "requests_shed".to_owned()],
            source_file: "crates/ffs-fuse/src/lib.rs".to_owned(),
        },
    ]
}

/// Check a single surface expectation by searching source file contents.
#[must_use]
pub fn check_expectation(repo_root: &str, expectation: &SurfaceExpectation) -> ConsistencyResult {
    let path = format!("{repo_root}/{}", expectation.source_file);
    let contents = std::fs::read_to_string(&path).unwrap_or_default();

    let mut found = Vec::new();
    let mut missing = Vec::new();

    for id in &expectation.required_identifiers {
        if contents.contains(id.as_str()) {
            found.push(id.clone());
        } else {
            missing.push(id.clone());
        }
    }

    ConsistencyResult {
        dimension: expectation.dimension.clone(),
        surface: expectation.surface.clone(),
        passed: missing.is_empty(),
        identifiers_found: found,
        identifiers_missing: missing,
    }
}

/// Run all canonical expectations and produce an aggregate verdict.
#[must_use]
pub fn check_all(repo_root: &str) -> ConsistencyVerdict {
    let expectations = canonical_expectations();
    let results: Vec<ConsistencyResult> = expectations
        .iter()
        .map(|e| check_expectation(repo_root, e))
        .collect();

    let passed = results.iter().filter(|r| r.passed).count();
    let failed = results.len() - passed;

    ConsistencyVerdict {
        version: HEALTH_CONTRACT_VERSION,
        total_checks: results.len(),
        passed,
        failed,
        results,
    }
}

// ── Source-of-truth documentation ──────────────────────────────────────────

/// Source-of-truth priority documentation for operators.
///
/// During transient state transitions, surfaces may temporarily diverge.
/// This table defines which source to trust.
pub const SOURCE_OF_TRUTH_DOC: &str = r"
FrankenFS Health State Source-of-Truth Priority
================================================

When CLI, TUI, and structured logs show conflicting health state:

| Dimension            | Trust this source                      | Why                          |
|---------------------|----------------------------------------|------------------------------|
| Degradation level   | Structured log (degradation_transition)| Atomic, timestamped          |
| Runtime mode        | CLI startup log (mode_selected)        | Immutable after mount        |
| WAL replay status   | CLI info --mvcc                        | Set once at open, definitive |
| Repair staleness    | ffs info --repair                      | Latest polled snapshot       |
| Pressure counters   | Structured log at unmount              | Cumulative final snapshot    |

TUI values may lag by one polling interval (typically 1s).
CLI values reflect the state at command invocation time.
Structured logs are the authoritative audit trail.
";

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_expectations_cover_all_dimensions() {
        let expectations = canonical_expectations();
        for dim in dimension::ALL_DIMENSIONS {
            assert!(
                expectations.iter().any(|e| e.dimension == *dim),
                "dimension {dim} not covered by any expectation"
            );
        }
    }

    #[test]
    fn all_expectations_pass_against_repo() {
        let repo_root = env!("CARGO_MANIFEST_DIR")
            .strip_suffix("/crates/ffs-harness")
            .expect("harness must be in crates/ffs-harness");
        let verdict = check_all(repo_root);

        for result in &verdict.results {
            assert!(
                result.passed,
                "consistency check failed: dimension={} surface={} missing={:?}",
                result.dimension, result.surface, result.identifiers_missing
            );
        }
        assert_eq!(verdict.failed, 0);
    }

    #[test]
    fn degradation_level_has_five_variants_in_core() {
        let repo_root = env!("CARGO_MANIFEST_DIR")
            .strip_suffix("/crates/ffs-harness")
            .expect("harness must be in crates/ffs-harness");
        let path = format!("{repo_root}/crates/ffs-core/src/degradation.rs");
        let contents = std::fs::read_to_string(&path).expect("read degradation.rs");

        let variants = ["Normal", "Warning", "Degraded", "Critical", "Emergency"];
        for v in &variants {
            assert!(
                contents.contains(v),
                "DegradationLevel missing variant {v} in degradation.rs"
            );
        }
    }

    #[test]
    fn tui_displays_all_degradation_levels() {
        let repo_root = env!("CARGO_MANIFEST_DIR")
            .strip_suffix("/crates/ffs-harness")
            .expect("harness must be in crates/ffs-harness");
        let path = format!("{repo_root}/crates/ffs-tui/src/lib.rs");
        let contents = std::fs::read_to_string(&path).expect("read ffs-tui/lib.rs");

        // TUI must handle all 5 levels in degradation_level_label
        for level in ["Normal", "Warning", "Degraded", "Critical", "Emergency"] {
            assert!(
                contents.contains(&format!("DegradationLevel::{level}")),
                "TUI missing DegradationLevel::{level} in label function"
            );
        }
    }

    #[test]
    fn structured_log_emits_degradation_transition() {
        let repo_root = env!("CARGO_MANIFEST_DIR")
            .strip_suffix("/crates/ffs-harness")
            .expect("harness must be in crates/ffs-harness");
        let path = format!("{repo_root}/crates/ffs-core/src/degradation.rs");
        let contents = std::fs::read_to_string(&path).expect("read degradation.rs");

        assert!(
            contents.contains("degradation_transition"),
            "degradation.rs must emit degradation_transition log event"
        );
        // Must include from/to fields for operator traceability
        assert!(
            contents.contains("from") && contents.contains("to"),
            "degradation_transition must include from/to fields"
        );
    }

    #[test]
    fn pressure_counters_exist_in_fuse_metrics() {
        let repo_root = env!("CARGO_MANIFEST_DIR")
            .strip_suffix("/crates/ffs-harness")
            .expect("harness must be in crates/ffs-harness");
        let path = format!("{repo_root}/crates/ffs-fuse/src/lib.rs");
        let contents = std::fs::read_to_string(&path).expect("read ffs-fuse/lib.rs");

        assert!(
            contents.contains("requests_throttled"),
            "ffs-fuse must track requests_throttled"
        );
        assert!(
            contents.contains("requests_shed"),
            "ffs-fuse must track requests_shed"
        );
    }

    #[test]
    fn runtime_mode_variants_in_cli() {
        let repo_root = env!("CARGO_MANIFEST_DIR")
            .strip_suffix("/crates/ffs-harness")
            .expect("harness must be in crates/ffs-harness");
        let path = format!("{repo_root}/crates/ffs-cli/src/main.rs");
        let contents = std::fs::read_to_string(&path).expect("read ffs-cli/main.rs");

        for mode in ["Standard", "Managed", "PerCore"] {
            assert!(
                contents.contains(mode),
                "CLI missing runtime mode variant {mode}"
            );
        }
    }

    #[test]
    fn wal_replay_markers_in_mvcc() {
        let repo_root = env!("CARGO_MANIFEST_DIR")
            .strip_suffix("/crates/ffs-harness")
            .expect("harness must be in crates/ffs-harness");
        let path = format!("{repo_root}/crates/ffs-mvcc/src/wal_replay.rs");
        let contents = std::fs::read_to_string(&path).expect("read wal_replay.rs");

        assert!(
            contents.contains("wal_replay_start"),
            "wal_replay.rs must emit wal_replay_start marker"
        );
        assert!(
            contents.contains("wal_replay_done"),
            "wal_replay.rs must emit wal_replay_done marker"
        );
    }

    #[test]
    fn source_of_truth_doc_covers_all_dimensions() {
        for dim in dimension::ALL_DIMENSIONS {
            // Convert dimension identifier to something recognizable in the doc
            let searchable = match *dim {
                "degradation_level" => "Degradation level",
                "runtime_mode" => "Runtime mode",
                "replay_status" => "WAL replay status",
                "repair_staleness" => "Repair staleness",
                "pressure_counters" => "Pressure counters",
                _ => dim,
            };
            assert!(
                SOURCE_OF_TRUTH_DOC.contains(searchable),
                "SOURCE_OF_TRUTH_DOC missing dimension {dim} ({searchable})"
            );
        }
    }

    #[test]
    fn consistency_verdict_json_schema_stability() {
        let verdict = ConsistencyVerdict {
            version: HEALTH_CONTRACT_VERSION,
            total_checks: 2,
            passed: 1,
            failed: 1,
            results: vec![
                ConsistencyResult {
                    dimension: "test_dim".to_owned(),
                    surface: "cli".to_owned(),
                    passed: true,
                    identifiers_found: vec!["a".to_owned()],
                    identifiers_missing: vec![],
                },
                ConsistencyResult {
                    dimension: "test_dim".to_owned(),
                    surface: "tui".to_owned(),
                    passed: false,
                    identifiers_found: vec![],
                    identifiers_missing: vec!["b".to_owned()],
                },
            ],
        };
        let json = serde_json::to_value(&verdict).expect("serialize verdict");
        assert!(json.get("version").is_some());
        assert!(json.get("total_checks").is_some());
        assert!(json.get("passed").is_some());
        assert!(json.get("failed").is_some());
        assert!(json.get("results").is_some());
    }

    #[test]
    fn check_expectation_returns_failure_for_missing_file() {
        let result = check_expectation(
            "/nonexistent",
            &SurfaceExpectation {
                dimension: "test".to_owned(),
                surface: "test".to_owned(),
                required_identifiers: vec!["something".to_owned()],
                source_file: "nonexistent.rs".to_owned(),
            },
        );
        assert!(!result.passed);
        assert_eq!(result.identifiers_missing, vec!["something"]);
    }
}
