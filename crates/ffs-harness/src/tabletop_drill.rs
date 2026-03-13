//! Operator tabletop drill runner and remediation-gap tracker.
//!
//! Validates that the full operator tooling chain is complete for three
//! canonical incident scenarios:
//!
//! 1. **Replay anomaly** — mount failure due to WAL replay error.
//! 2. **Corruption with partial repair** — scrub finds damage, repair is partial.
//! 3. **Sustained pressure** — backpressure escalates through degradation levels.
//!
//! Each drill validates: runbook exists and has required sections, CLI commands
//! are reachable, evidence presets cover the event types, error taxonomy codes
//! are defined, and structured log markers are emitted.

use serde::{Deserialize, Serialize};

/// Number of canonical drill scenarios.
pub const DRILL_COUNT: usize = 3;

/// A tabletop drill scenario definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrillScenario {
    /// Stable identifier (e.g., `"drill-replay-anomaly"`).
    pub id: String,
    /// Human-readable drill title.
    pub title: String,
    /// Error taxonomy code(s) exercised by this drill.
    pub error_codes: Vec<String>,
    /// Evidence preset that operators should use for this incident.
    pub evidence_preset: String,
    /// Runbook path to follow during the drill.
    pub runbook_path: String,
    /// Required runbook sections (headings that must exist).
    pub required_runbook_sections: Vec<String>,
    /// CLI commands the operator would execute during this drill.
    pub cli_commands: Vec<String>,
    /// Structured log markers that should be emitted during this incident.
    pub log_markers: Vec<String>,
    /// Source files that must contain the log markers.
    pub log_marker_sources: Vec<String>,
}

/// Build the canonical set of drill scenarios.
#[must_use]
pub fn canonical_drills() -> Vec<DrillScenario> {
    vec![
        DrillScenario {
            id: "drill-replay-anomaly".to_owned(),
            title: "Mount failure due to WAL replay anomaly".to_owned(),
            error_codes: vec!["FFS-RPL-001".to_owned(), "FFS-RPL-002".to_owned()],
            evidence_preset: "replay-anomalies".to_owned(),
            runbook_path: "docs/runbooks/replay-failure-triage.md".to_owned(),
            required_runbook_sections: vec![
                "Quick Reference".to_owned(),
                "Inspect Replay State".to_owned(),
                "Check Structured Logs".to_owned(),
                "Corruption Recovery".to_owned(),
                "Escalation".to_owned(),
            ],
            cli_commands: vec![
                "ffs info --mvcc".to_owned(),
                "ffs evidence --preset replay-anomalies".to_owned(),
            ],
            log_markers: vec![
                "wal_replay_start".to_owned(),
                "wal_replay_done".to_owned(),
                "wal_replay_truncated_tail".to_owned(),
            ],
            log_marker_sources: vec!["crates/ffs-mvcc/src/wal_replay.rs".to_owned()],
        },
        DrillScenario {
            id: "drill-corruption-partial-repair".to_owned(),
            title: "Corruption detected with partial repair success".to_owned(),
            error_codes: vec![
                "FFS-IOC-001".to_owned(),
                "FFS-RPR-001".to_owned(),
                "FFS-RPR-002".to_owned(),
            ],
            evidence_preset: "repair-failures".to_owned(),
            runbook_path: "docs/runbooks/corruption-recovery.md".to_owned(),
            required_runbook_sections: vec![
                "Quick Reference".to_owned(),
                "Detection".to_owned(),
                "Evidence Ledger".to_owned(),
                "Repair Decision".to_owned(),
                "Post-Repair Verification".to_owned(),
            ],
            cli_commands: vec![
                "ffs repair".to_owned(),
                "ffs evidence --preset repair-failures".to_owned(),
            ],
            log_markers: vec!["scrub_complete".to_owned(), "repair_complete".to_owned()],
            log_marker_sources: vec![
                "crates/ffs-cli/src/main.rs".to_owned(),
                "crates/ffs-cli/src/cmd_repair.rs".to_owned(),
            ],
        },
        DrillScenario {
            id: "drill-sustained-pressure".to_owned(),
            title: "Sustained pressure causing throttle/shed behavior".to_owned(),
            error_codes: vec!["FFS-PRS-001".to_owned(), "FFS-PRS-002".to_owned()],
            evidence_preset: "pressure-transitions".to_owned(),
            runbook_path: "docs/runbooks/backpressure-investigation.md".to_owned(),
            required_runbook_sections: vec![
                "Quick Reference".to_owned(),
                "Degradation Analysis".to_owned(),
                "Throttle Events".to_owned(),
                "Shed Events".to_owned(),
                "Safe Escalation".to_owned(),
            ],
            cli_commands: vec![
                "ffs evidence --preset pressure-transitions".to_owned(),
                "ffs mount --runtime-mode".to_owned(),
            ],
            log_markers: vec![
                "degradation_transition".to_owned(),
                "backpressure".to_owned(),
            ],
            log_marker_sources: vec![
                "crates/ffs-core/src/degradation.rs".to_owned(),
                "crates/ffs-repair/src/evidence.rs".to_owned(),
            ],
        },
    ]
}

/// A single drill check with its pass/fail outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrillCheckResult {
    /// Drill scenario ID.
    pub drill_id: String,
    /// What was checked.
    pub check: String,
    /// Whether the check passed.
    pub passed: bool,
    /// Detail message.
    pub detail: String,
}

/// Result of a full drill execution (all checks for one scenario).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrillResult {
    pub drill_id: String,
    pub title: String,
    pub checks: Vec<DrillCheckResult>,
    pub passed: bool,
    pub gaps: Vec<RemediationGap>,
}

/// A gap discovered during a drill that needs follow-up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationGap {
    pub drill_id: String,
    pub category: GapCategory,
    pub description: String,
}

/// Category of remediation gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapCategory {
    /// Runbook missing or incomplete.
    Runbook,
    /// CLI command not available.
    CliCommand,
    /// Structured log marker missing.
    LogMarker,
    /// Error code not defined in taxonomy.
    ErrorCode,
    /// Evidence preset not covering events.
    EvidencePreset,
}

/// Execute all checks for a single drill scenario against the repo.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn execute_drill(drill: &DrillScenario, repo_root: &str) -> DrillResult {
    let mut checks = Vec::new();
    let mut gaps = Vec::new();

    // Check 1: Runbook exists
    let runbook_full = format!("{repo_root}/{}", drill.runbook_path);
    let runbook_exists = std::path::Path::new(&runbook_full).exists();
    checks.push(DrillCheckResult {
        drill_id: drill.id.clone(),
        check: "runbook_exists".to_owned(),
        passed: runbook_exists,
        detail: if runbook_exists {
            format!("Runbook found: {}", drill.runbook_path)
        } else {
            format!("Runbook missing: {}", drill.runbook_path)
        },
    });
    if !runbook_exists {
        gaps.push(RemediationGap {
            drill_id: drill.id.clone(),
            category: GapCategory::Runbook,
            description: format!("Runbook not found: {}", drill.runbook_path),
        });
    }

    // Check 2: Runbook has required sections
    if runbook_exists {
        let content = std::fs::read_to_string(&runbook_full).unwrap_or_default();
        let mut sections_found = 0;
        for section in &drill.required_runbook_sections {
            if content.contains(section.as_str()) {
                sections_found += 1;
            } else {
                gaps.push(RemediationGap {
                    drill_id: drill.id.clone(),
                    category: GapCategory::Runbook,
                    description: format!(
                        "Runbook missing section '{}' in {}",
                        section, drill.runbook_path
                    ),
                });
            }
        }
        checks.push(DrillCheckResult {
            drill_id: drill.id.clone(),
            check: "runbook_sections".to_owned(),
            passed: sections_found == drill.required_runbook_sections.len(),
            detail: format!(
                "{}/{} required sections found",
                sections_found,
                drill.required_runbook_sections.len()
            ),
        });
    }

    // Check 3: Error codes exist in taxonomy
    let taxonomy_src_path = format!("{repo_root}/crates/ffs-harness/src/error_taxonomy.rs");
    let taxonomy_src = std::fs::read_to_string(&taxonomy_src_path).unwrap_or_default();
    let mut codes_found = 0;
    for code in &drill.error_codes {
        if taxonomy_src.contains(code.as_str()) {
            codes_found += 1;
        } else {
            gaps.push(RemediationGap {
                drill_id: drill.id.clone(),
                category: GapCategory::ErrorCode,
                description: format!("Error code {code} not found in error taxonomy"),
            });
        }
    }
    checks.push(DrillCheckResult {
        drill_id: drill.id.clone(),
        check: "error_codes".to_owned(),
        passed: codes_found == drill.error_codes.len(),
        detail: format!(
            "{}/{} error codes found",
            codes_found,
            drill.error_codes.len()
        ),
    });

    // Check 4: Evidence preset referenced in evidence command
    let evidence_cmd_path = format!("{repo_root}/crates/ffs-cli/src/cmd_evidence.rs");
    let evidence_src = std::fs::read_to_string(&evidence_cmd_path).unwrap_or_default();
    let preset_found = evidence_src.contains(&drill.evidence_preset);
    checks.push(DrillCheckResult {
        drill_id: drill.id.clone(),
        check: "evidence_preset".to_owned(),
        passed: preset_found,
        detail: if preset_found {
            format!(
                "Preset '{}' found in evidence command",
                drill.evidence_preset
            )
        } else {
            format!("Preset '{}' not found", drill.evidence_preset)
        },
    });
    if !preset_found {
        gaps.push(RemediationGap {
            drill_id: drill.id.clone(),
            category: GapCategory::EvidencePreset,
            description: format!(
                "Evidence preset '{}' not found in cmd_evidence.rs",
                drill.evidence_preset
            ),
        });
    }

    // Check 5: Log markers exist in source files
    let mut markers_found = 0;
    let markers_total = drill.log_markers.len();
    for marker in &drill.log_markers {
        let found = drill.log_marker_sources.iter().any(|src| {
            let path = format!("{repo_root}/{src}");
            std::fs::read_to_string(&path).is_ok_and(|content| content.contains(marker.as_str()))
        });
        if found {
            markers_found += 1;
        } else {
            gaps.push(RemediationGap {
                drill_id: drill.id.clone(),
                category: GapCategory::LogMarker,
                description: format!("Log marker '{marker}' not found in source files"),
            });
        }
    }
    checks.push(DrillCheckResult {
        drill_id: drill.id.clone(),
        check: "log_markers".to_owned(),
        passed: markers_found == markers_total,
        detail: format!("{markers_found}/{markers_total} log markers found in sources"),
    });

    // Check 6: CLI command patterns referenced in runbook
    if runbook_exists {
        let content = std::fs::read_to_string(&runbook_full).unwrap_or_default();
        let mut cmds_found = 0;
        for cmd in &drill.cli_commands {
            // Check for the command root (e.g., "ffs repair" or "ffs evidence --preset")
            let cmd_root = cmd.split_whitespace().take(3).collect::<Vec<_>>().join(" ");
            if content.contains(&cmd_root) || content.contains(cmd.as_str()) {
                cmds_found += 1;
            } else {
                gaps.push(RemediationGap {
                    drill_id: drill.id.clone(),
                    category: GapCategory::CliCommand,
                    description: format!("CLI command '{cmd}' not referenced in runbook"),
                });
            }
        }
        checks.push(DrillCheckResult {
            drill_id: drill.id.clone(),
            check: "cli_commands_in_runbook".to_owned(),
            passed: cmds_found == drill.cli_commands.len(),
            detail: format!(
                "{}/{} CLI commands referenced in runbook",
                cmds_found,
                drill.cli_commands.len()
            ),
        });
    }

    let all_passed = checks.iter().all(|c| c.passed);
    DrillResult {
        drill_id: drill.id.clone(),
        title: drill.title.clone(),
        checks,
        passed: all_passed,
        gaps,
    }
}

/// Execute all canonical drills and return aggregated results.
#[must_use]
pub fn execute_all_drills(repo_root: &str) -> Vec<DrillResult> {
    canonical_drills()
        .iter()
        .map(|d| execute_drill(d, repo_root))
        .collect()
}

/// Collect all remediation gaps across all drills.
#[must_use]
pub fn collect_gaps(results: &[DrillResult]) -> Vec<RemediationGap> {
    results.iter().flat_map(|r| r.gaps.clone()).collect()
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
    fn has_all_three_drill_scenarios() {
        let drills = canonical_drills();
        assert_eq!(drills.len(), DRILL_COUNT);
    }

    #[test]
    fn drill_ids_are_unique() {
        let drills = canonical_drills();
        let ids: std::collections::HashSet<&str> = drills.iter().map(|d| d.id.as_str()).collect();
        assert_eq!(ids.len(), drills.len(), "drill IDs must be unique");
    }

    #[test]
    fn every_drill_has_error_codes() {
        let drills = canonical_drills();
        for d in &drills {
            assert!(
                !d.error_codes.is_empty(),
                "drill {} has no error codes",
                d.id
            );
        }
    }

    #[test]
    fn every_drill_has_log_markers() {
        let drills = canonical_drills();
        for d in &drills {
            assert!(
                !d.log_markers.is_empty(),
                "drill {} has no log markers",
                d.id
            );
        }
    }

    #[test]
    fn every_drill_has_cli_commands() {
        let drills = canonical_drills();
        for d in &drills {
            assert!(
                !d.cli_commands.is_empty(),
                "drill {} has no CLI commands",
                d.id
            );
        }
    }

    #[test]
    fn replay_drill_passes() {
        let root = repo_root();
        let drills = canonical_drills();
        let replay = &drills[0];
        assert_eq!(replay.id, "drill-replay-anomaly");
        let result = execute_drill(replay, &root);
        for check in &result.checks {
            assert!(
                check.passed,
                "replay drill check '{}' failed: {}",
                check.check, check.detail
            );
        }
    }

    #[test]
    fn corruption_drill_passes() {
        let root = repo_root();
        let drills = canonical_drills();
        let corruption = &drills[1];
        assert_eq!(corruption.id, "drill-corruption-partial-repair");
        let result = execute_drill(corruption, &root);
        for check in &result.checks {
            assert!(
                check.passed,
                "corruption drill check '{}' failed: {}",
                check.check, check.detail
            );
        }
    }

    #[test]
    fn pressure_drill_passes() {
        let root = repo_root();
        let drills = canonical_drills();
        let pressure = &drills[2];
        assert_eq!(pressure.id, "drill-sustained-pressure");
        let result = execute_drill(pressure, &root);
        for check in &result.checks {
            assert!(
                check.passed,
                "pressure drill check '{}' failed: {}",
                check.check, check.detail
            );
        }
    }

    #[test]
    fn no_remediation_gaps_in_canonical_drills() {
        let root = repo_root();
        let results = execute_all_drills(&root);
        let gaps = collect_gaps(&results);
        assert!(
            gaps.is_empty(),
            "found {} remediation gaps: {:?}",
            gaps.len(),
            gaps.iter()
                .map(|g| format!("[{}] {}", g.drill_id, g.description))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn drill_result_json_round_trips() {
        let root = repo_root();
        let results = execute_all_drills(&root);
        let json = serde_json::to_string(&results).expect("serialize");
        let parsed: Vec<DrillResult> = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.len(), results.len());
        assert_eq!(parsed[0].drill_id, results[0].drill_id);
    }

    #[test]
    fn drill_covers_all_three_runbooks() {
        let drills = canonical_drills();
        let runbooks: std::collections::HashSet<&str> =
            drills.iter().map(|d| d.runbook_path.as_str()).collect();
        assert!(runbooks.contains("docs/runbooks/replay-failure-triage.md"));
        assert!(runbooks.contains("docs/runbooks/corruption-recovery.md"));
        assert!(runbooks.contains("docs/runbooks/backpressure-investigation.md"));
    }

    #[test]
    fn drill_covers_all_three_evidence_presets() {
        let drills = canonical_drills();
        let presets: std::collections::HashSet<&str> =
            drills.iter().map(|d| d.evidence_preset.as_str()).collect();
        assert!(presets.contains("replay-anomalies"));
        assert!(presets.contains("repair-failures"));
        assert!(presets.contains("pressure-transitions"));
    }

    #[test]
    fn gap_detection_works_for_missing_file() {
        let drill = DrillScenario {
            id: "test-missing".to_owned(),
            title: "Test".to_owned(),
            error_codes: vec!["FFS-CFG-001".to_owned()],
            evidence_preset: "replay-anomalies".to_owned(),
            runbook_path: "docs/runbooks/nonexistent.md".to_owned(),
            required_runbook_sections: vec!["Quick Reference".to_owned()],
            cli_commands: vec!["ffs info".to_owned()],
            log_markers: vec!["nonexistent_marker".to_owned()],
            log_marker_sources: vec!["crates/ffs-harness/src/tabletop_drill.rs".to_owned()],
        };
        let root = repo_root();
        let result = execute_drill(&drill, &root);
        assert!(!result.passed, "drill with missing runbook should fail");
        assert!(!result.gaps.is_empty(), "should have gaps");
        assert!(
            result
                .gaps
                .iter()
                .any(|g| g.category == GapCategory::Runbook),
            "should have runbook gap"
        );
    }
}
