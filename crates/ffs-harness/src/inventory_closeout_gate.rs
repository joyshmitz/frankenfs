#![forbid(unsafe_code)]

//! Inventory closeout and stale-note budget gate.
//!
//! Tracks bd-rpjp9: a closeout gate over the open-ended fuzz/conformance
//! inventory that fails closed if any high-risk vague note remains untriaged.
//! Each row carries a state (completed_artifact, linked_bead, explicit_non
//! _goal, long_campaign, host_blocked, stale_allowed_until, duplicate_of,
//! false_positive). Stale-allowed rows must declare an expiry, owner,
//! user-risk rationale, and a linked bead or non-goal; otherwise the
//! inventory cannot close.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fs, path::Path};

pub const INVENTORY_CLOSEOUT_GATE_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_INVENTORY_CLOSEOUT_GATE_PATH: &str =
    "tests/inventory-closeout-gate/inventory_closeout_gate.json";
const DEFAULT_INVENTORY_CLOSEOUT_GATE_JSON: &str =
    include_str!("../../../tests/inventory-closeout-gate/inventory_closeout_gate.json");

const ALLOWED_ROW_STATES: [&str; 8] = [
    "completed_artifact",
    "linked_bead",
    "explicit_non_goal",
    "long_campaign",
    "host_blocked",
    "stale_allowed_until",
    "duplicate_of",
    "false_positive",
];

const ALLOWED_RISK_SURFACES: [&str; 8] = [
    "parser",
    "mounted_path",
    "repair",
    "fuzz",
    "golden",
    "xfstests",
    "performance",
    "readme_feature_parity",
];

const HIGH_RISK_SURFACES: [&str; 8] = ALLOWED_RISK_SURFACES;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryCloseoutGate {
    pub schema_version: u32,
    pub gate_id: String,
    pub bead_id: String,
    pub now_unix: u64,
    pub rows: Vec<InventoryCloseoutRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryCloseoutRow {
    pub row_id: String,
    pub source_path: String,
    pub matched_snippet_hash: String,
    pub risk_surface: String,
    pub state: String,
    #[serde(default)]
    pub linked_bead_or_artifact: String,
    #[serde(default)]
    pub duplicate_of: String,
    #[serde(default)]
    pub stale_expiry_unix: u64,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub user_risk_rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryCloseoutReport {
    pub schema_version: u32,
    pub gate_id: String,
    pub bead_id: String,
    pub total_rows: usize,
    pub completed_rows: usize,
    pub stale_allowed_rows: usize,
    pub false_positive_rows: usize,
    pub high_risk_surfaces_seen: Vec<String>,
    pub valid: bool,
    pub errors: Vec<String>,
}

pub fn parse_inventory_closeout_gate(text: &str) -> Result<InventoryCloseoutGate> {
    serde_json::from_str(text)
        .map_err(|err| anyhow::anyhow!("failed to parse inventory closeout gate JSON: {err}"))
}

pub fn load_inventory_closeout_gate(path: &Path) -> Result<InventoryCloseoutGate> {
    let text = fs::read_to_string(path).map_err(|err| {
        anyhow::anyhow!(
            "failed to read inventory closeout gate `{}`: {err}",
            path.display()
        )
    })?;
    parse_inventory_closeout_gate(&text)
}

pub fn validate_default_inventory_closeout_gate() -> Result<InventoryCloseoutReport> {
    let gate = parse_inventory_closeout_gate(DEFAULT_INVENTORY_CLOSEOUT_GATE_JSON)?;
    let report = validate_inventory_closeout_gate(&gate);
    fail_on_inventory_closeout_gate_errors(&report)?;
    Ok(report)
}

pub fn fail_on_inventory_closeout_gate_errors(report: &InventoryCloseoutReport) -> Result<()> {
    if report.valid {
        return Ok(());
    }
    bail!(
        "inventory closeout gate failed with {} error(s): {}",
        report.errors.len(),
        report.errors.join("; ")
    );
}

#[must_use]
pub fn validate_inventory_closeout_gate(gate: &InventoryCloseoutGate) -> InventoryCloseoutReport {
    let mut errors = Vec::new();
    let mut ids = BTreeSet::new();
    let mut high_risk_surfaces = BTreeSet::new();
    let mut completed = 0_usize;
    let mut stale_allowed = 0_usize;
    let mut false_positive = 0_usize;

    validate_top_level(gate, &mut errors);

    let row_id_set: BTreeSet<&str> = gate.rows.iter().map(|row| row.row_id.as_str()).collect();

    for row in &gate.rows {
        validate_row(
            row,
            gate.now_unix,
            &row_id_set,
            &mut ids,
            &mut high_risk_surfaces,
            &mut completed,
            &mut stale_allowed,
            &mut false_positive,
            &mut errors,
        );
    }

    validate_high_risk_coverage(&high_risk_surfaces, &mut errors);

    InventoryCloseoutReport {
        schema_version: gate.schema_version,
        gate_id: gate.gate_id.clone(),
        bead_id: gate.bead_id.clone(),
        total_rows: gate.rows.len(),
        completed_rows: completed,
        stale_allowed_rows: stale_allowed,
        false_positive_rows: false_positive,
        high_risk_surfaces_seen: high_risk_surfaces.into_iter().collect(),
        valid: errors.is_empty(),
        errors,
    }
}

fn validate_top_level(gate: &InventoryCloseoutGate, errors: &mut Vec<String>) {
    if gate.schema_version != INVENTORY_CLOSEOUT_GATE_SCHEMA_VERSION {
        errors.push(format!(
            "inventory closeout gate schema_version must be {INVENTORY_CLOSEOUT_GATE_SCHEMA_VERSION}, got {}",
            gate.schema_version
        ));
    }
    if gate.gate_id.trim().is_empty() {
        errors.push("inventory closeout gate missing gate_id".to_owned());
    }
    if !gate.bead_id.starts_with("bd-") {
        errors.push(format!(
            "inventory closeout gate bead_id must look like bd-..., got `{}`",
            gate.bead_id
        ));
    }
    if gate.now_unix == 0 {
        errors.push("inventory closeout gate now_unix must be positive".to_owned());
    }
    if gate.rows.is_empty() {
        errors.push("inventory closeout gate must declare at least one row".to_owned());
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_row(
    row: &InventoryCloseoutRow,
    now_unix: u64,
    row_id_set: &BTreeSet<&str>,
    ids: &mut BTreeSet<String>,
    high_risk_surfaces: &mut BTreeSet<String>,
    completed: &mut usize,
    stale_allowed: &mut usize,
    false_positive: &mut usize,
    errors: &mut Vec<String>,
) {
    if !ids.insert(row.row_id.clone()) {
        errors.push(format!(
            "duplicate inventory closeout row_id `{}`",
            row.row_id
        ));
    }
    if !row.row_id.starts_with("inv_") {
        errors.push(format!("row_id `{}` must start with inv_", row.row_id));
    }
    if row.source_path.trim().is_empty() {
        errors.push(format!("row `{}` missing source_path", row.row_id));
    }
    if row.matched_snippet_hash.trim().is_empty() {
        errors.push(format!("row `{}` missing matched_snippet_hash", row.row_id));
    }
    if !ALLOWED_RISK_SURFACES.contains(&row.risk_surface.as_str()) {
        errors.push(format!(
            "row `{}` has unsupported risk_surface `{}`",
            row.row_id, row.risk_surface
        ));
    }
    if HIGH_RISK_SURFACES.contains(&row.risk_surface.as_str()) {
        high_risk_surfaces.insert(row.risk_surface.clone());
    }
    if !ALLOWED_ROW_STATES.contains(&row.state.as_str()) {
        errors.push(format!(
            "row `{}` has unsupported state `{}`",
            row.row_id, row.state
        ));
        return;
    }

    match row.state.as_str() {
        "completed_artifact" | "linked_bead" => {
            *completed += 1;
            validate_linked_bead_or_artifact_state(row, errors);
        }
        "explicit_non_goal" | "long_campaign" => {
            *completed += 1;
            validate_explicit_state(row, errors);
        }
        "host_blocked" => {
            *completed += 1;
            validate_host_blocked_state(row, errors);
        }
        "stale_allowed_until" => {
            *stale_allowed += 1;
            validate_stale_allowed_state(row, now_unix, errors);
        }
        "duplicate_of" => {
            validate_duplicate_state(row, row_id_set, errors);
        }
        "false_positive" => {
            *false_positive += 1;
            validate_false_positive_state(row, errors);
        }
        _ => {}
    }
}

fn validate_linked_bead_or_artifact_state(row: &InventoryCloseoutRow, errors: &mut Vec<String>) {
    if row.linked_bead_or_artifact.trim().is_empty() {
        errors.push(format!(
            "row `{}` state requires linked_bead_or_artifact",
            row.row_id
        ));
    } else if row.state == "linked_bead" && !row.linked_bead_or_artifact.starts_with("bd-") {
        errors.push(format!(
            "row `{}` linked_bead state requires linked_bead_or_artifact starting with bd-",
            row.row_id
        ));
    } else if row.state == "completed_artifact" && !row.linked_bead_or_artifact.contains('/') {
        errors.push(format!(
            "row `{}` completed_artifact state requires an artifact path",
            row.row_id
        ));
    }
}

fn validate_explicit_state(row: &InventoryCloseoutRow, errors: &mut Vec<String>) {
    if row.user_risk_rationale.trim().is_empty() {
        errors.push(format!(
            "row `{}` {} state requires user_risk_rationale",
            row.row_id, row.state
        ));
    }
    if row.owner.trim().is_empty() {
        errors.push(format!(
            "row `{}` {} state requires owner",
            row.row_id, row.state
        ));
    }
}

fn validate_host_blocked_state(row: &InventoryCloseoutRow, errors: &mut Vec<String>) {
    if row.user_risk_rationale.trim().is_empty() {
        errors.push(format!(
            "row `{}` host_blocked state requires user_risk_rationale",
            row.row_id
        ));
    }
    if !row.linked_bead_or_artifact.starts_with("bd-") && !row.linked_bead_or_artifact.contains('/')
    {
        errors.push(format!(
            "row `{}` host_blocked state requires linked bead or artifact path",
            row.row_id
        ));
    }
}

fn validate_stale_allowed_state(
    row: &InventoryCloseoutRow,
    now_unix: u64,
    errors: &mut Vec<String>,
) {
    if row.stale_expiry_unix == 0 {
        errors.push(format!(
            "row `{}` stale_allowed_until requires stale_expiry_unix",
            row.row_id
        ));
    } else if row.stale_expiry_unix <= now_unix {
        errors.push(format!(
            "row `{}` stale_expiry_unix must be in the future (now_unix={now_unix})",
            row.row_id
        ));
    }
    if row.owner.trim().is_empty() {
        errors.push(format!(
            "row `{}` stale_allowed_until requires owner",
            row.row_id
        ));
    }
    if row.user_risk_rationale.trim().is_empty() {
        errors.push(format!(
            "row `{}` stale_allowed_until requires user_risk_rationale",
            row.row_id
        ));
    }
    if row.linked_bead_or_artifact.trim().is_empty() {
        errors.push(format!(
            "row `{}` stale_allowed_until requires linked bead or non-goal artifact",
            row.row_id
        ));
    }
}

fn validate_duplicate_state(
    row: &InventoryCloseoutRow,
    row_id_set: &BTreeSet<&str>,
    errors: &mut Vec<String>,
) {
    if row.duplicate_of.trim().is_empty() {
        errors.push(format!(
            "row `{}` duplicate_of state requires duplicate_of pointer",
            row.row_id
        ));
    } else if !row_id_set.contains(row.duplicate_of.as_str()) {
        errors.push(format!(
            "row `{}` duplicate_of `{}` does not match any other row_id",
            row.row_id, row.duplicate_of
        ));
    } else if row.duplicate_of == row.row_id {
        errors.push(format!(
            "row `{}` duplicate_of cannot point to itself",
            row.row_id
        ));
    }
}

fn validate_false_positive_state(row: &InventoryCloseoutRow, errors: &mut Vec<String>) {
    if row.user_risk_rationale.trim().is_empty() {
        errors.push(format!(
            "row `{}` false_positive state requires user_risk_rationale",
            row.row_id
        ));
    }
    if row.owner.trim().is_empty() {
        errors.push(format!(
            "row `{}` false_positive state requires owner",
            row.row_id
        ));
    }
}

fn validate_high_risk_coverage(high_risk_surfaces: &BTreeSet<String>, errors: &mut Vec<String>) {
    for required in HIGH_RISK_SURFACES {
        if !high_risk_surfaces.contains(required) {
            errors.push(format!(
                "inventory closeout gate must classify at least one row from risk_surface `{required}`"
            ));
        }
    }
}

#[must_use]
pub fn render_inventory_closeout_gate_markdown(report: &InventoryCloseoutReport) -> String {
    let mut out = String::new();
    out.push_str("# Inventory Closeout Gate\n\n");
    out.push_str("- gate: `");
    out.push_str(&report.gate_id);
    out.push_str("`\n");
    out.push_str("- schema version: `");
    out.push_str(&report.schema_version.to_string());
    out.push_str("`\n");
    out.push_str("- bead: `");
    out.push_str(&report.bead_id);
    out.push_str("`\n");
    out.push_str("- valid: `");
    out.push_str(if report.valid { "true" } else { "false" });
    out.push_str("`\n");
    out.push_str("- rows: `");
    out.push_str(&report.total_rows.to_string());
    out.push_str("`\n");
    out.push_str("- completed rows: `");
    out.push_str(&report.completed_rows.to_string());
    out.push_str("`\n");
    out.push_str("- stale-allowed rows: `");
    out.push_str(&report.stale_allowed_rows.to_string());
    out.push_str("`\n");
    out.push_str("- false-positive rows: `");
    out.push_str(&report.false_positive_rows.to_string());
    out.push_str("`\n\n");
    out.push_str("## High-Risk Surfaces\n");
    for surface in &report.high_risk_surfaces_seen {
        out.push_str("- `");
        out.push_str(surface);
        out.push_str("`\n");
    }
    if !report.errors.is_empty() {
        out.push_str("\n## Errors\n");
        for error in &report.errors {
            out.push_str("- ");
            out.push_str(error);
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, bail};

    fn fixture_gate() -> Result<InventoryCloseoutGate> {
        parse_inventory_closeout_gate(DEFAULT_INVENTORY_CLOSEOUT_GATE_JSON)
            .context("default inventory closeout gate parses")
    }

    fn first_row_mut(gate: &mut InventoryCloseoutGate) -> Result<&mut InventoryCloseoutRow> {
        gate.rows
            .first_mut()
            .context("fixture gate includes at least one row")
    }

    fn first_two_rows_mut(
        gate: &mut InventoryCloseoutGate,
    ) -> Result<(&mut InventoryCloseoutRow, &mut InventoryCloseoutRow)> {
        let (first, rest) = gate
            .rows
            .split_first_mut()
            .context("fixture gate includes at least one row")?;
        let second = rest
            .first_mut()
            .context("fixture gate includes at least two rows")?;
        Ok((first, second))
    }

    fn row_by_state_mut<'a>(
        gate: &'a mut InventoryCloseoutGate,
        state: &str,
    ) -> Result<&'a mut InventoryCloseoutRow> {
        gate.rows
            .iter_mut()
            .find(|row| row.state == state)
            .with_context(|| format!("fixture gate includes state {state}"))
    }

    #[test]
    fn default_gate_validates_high_risk_coverage() -> Result<()> {
        let report = validate_default_inventory_closeout_gate()?;
        assert_eq!(report.bead_id, "bd-rpjp9");
        for surface in HIGH_RISK_SURFACES {
            assert!(
                report.high_risk_surfaces_seen.iter().any(|s| s == surface),
                "missing surface {surface}"
            );
        }
        Ok(())
    }

    #[test]
    fn missing_high_risk_surface_is_rejected() -> Result<()> {
        let mut gate = fixture_gate()?;
        gate.rows.retain(|r| r.risk_surface != "fuzz");
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must classify at least one row from risk_surface `fuzz`"))
        );
        Ok(())
    }

    #[test]
    fn missing_xfstests_surface_is_rejected() -> Result<()> {
        let mut gate = fixture_gate()?;
        gate.rows.retain(|r| r.risk_surface != "xfstests");
        let report = validate_inventory_closeout_gate(&gate);
        assert!(report.errors.iter().any(|err| err.contains("`xfstests`")));
        Ok(())
    }

    #[test]
    fn duplicate_row_id_is_rejected() -> Result<()> {
        let mut gate = fixture_gate()?;
        let (first, second) = first_two_rows_mut(&mut gate)?;
        second.row_id = first.row_id.clone();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("duplicate inventory closeout row_id"))
        );
        Ok(())
    }

    #[test]
    fn row_id_prefix_is_enforced() -> Result<()> {
        let mut gate = fixture_gate()?;
        first_row_mut(&mut gate)?.row_id = "x_001".to_owned();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must start with inv_"))
        );
        Ok(())
    }

    #[test]
    fn linked_bead_state_requires_bd_prefix() -> Result<()> {
        let mut gate = fixture_gate()?;
        let row = row_by_state_mut(&mut gate, "linked_bead")?;
        row.linked_bead_or_artifact = "PROJ-1".to_owned();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(report.errors.iter().any(|err| {
            err.contains("linked_bead state requires linked_bead_or_artifact starting with bd-")
        }));
        Ok(())
    }

    #[test]
    fn completed_artifact_state_requires_artifact_path() -> Result<()> {
        let mut gate = fixture_gate()?;
        let row = row_by_state_mut(&mut gate, "completed_artifact")?;
        row.linked_bead_or_artifact = "no-slash-no-path".to_owned();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("completed_artifact state requires an artifact path"))
        );
        Ok(())
    }

    #[test]
    fn stale_allowed_requires_future_expiry() -> Result<()> {
        let mut gate = fixture_gate()?;
        let stale_expiry_unix = gate.now_unix.saturating_sub(1);
        let row = row_by_state_mut(&mut gate, "stale_allowed_until")?;
        row.stale_expiry_unix = stale_expiry_unix;
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("stale_expiry_unix must be in the future"))
        );
        Ok(())
    }

    #[test]
    fn stale_allowed_requires_owner() -> Result<()> {
        let mut gate = fixture_gate()?;
        let row = row_by_state_mut(&mut gate, "stale_allowed_until")?;
        row.owner = String::new();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("stale_allowed_until requires owner"))
        );
        Ok(())
    }

    #[test]
    fn stale_allowed_requires_user_risk_rationale() -> Result<()> {
        let mut gate = fixture_gate()?;
        let row = row_by_state_mut(&mut gate, "stale_allowed_until")?;
        row.user_risk_rationale = String::new();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("stale_allowed_until requires user_risk_rationale"))
        );
        Ok(())
    }

    #[test]
    fn stale_allowed_requires_linked_bead_or_artifact() -> Result<()> {
        let mut gate = fixture_gate()?;
        let row = row_by_state_mut(&mut gate, "stale_allowed_until")?;
        row.linked_bead_or_artifact = String::new();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(report.errors.iter().any(|err| {
            err.contains("stale_allowed_until requires linked bead or non-goal artifact")
        }));
        Ok(())
    }

    #[test]
    fn duplicate_of_must_match_existing_row() -> Result<()> {
        let mut gate = fixture_gate()?;
        let row = row_by_state_mut(&mut gate, "duplicate_of")?;
        row.duplicate_of = "inv_does_not_exist".to_owned();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("does not match any other row_id"))
        );
        Ok(())
    }

    #[test]
    fn duplicate_of_cannot_point_to_self() -> Result<()> {
        let mut gate = fixture_gate()?;
        let row = row_by_state_mut(&mut gate, "duplicate_of")?;
        row.duplicate_of = row.row_id.clone();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("duplicate_of cannot point to itself"))
        );
        Ok(())
    }

    #[test]
    fn explicit_non_goal_requires_rationale_and_owner() -> Result<()> {
        let mut gate = fixture_gate()?;
        let row = row_by_state_mut(&mut gate, "explicit_non_goal")?;
        row.user_risk_rationale = String::new();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("requires user_risk_rationale"))
        );
        Ok(())
    }

    #[test]
    fn host_blocked_requires_linked_bead_or_artifact() -> Result<()> {
        let mut gate = fixture_gate()?;
        let row = row_by_state_mut(&mut gate, "host_blocked")?;
        row.linked_bead_or_artifact = "no-prefix-no-slash".to_owned();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(report.errors.iter().any(|err| err
            .contains("host_blocked state requires linked bead or artifact path")));
        Ok(())
    }

    #[test]
    fn false_positive_requires_owner_and_rationale() -> Result<()> {
        let mut gate = fixture_gate()?;
        let row = row_by_state_mut(&mut gate, "false_positive")?;
        row.owner = String::new();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("false_positive state requires owner"))
        );
        Ok(())
    }

    #[test]
    fn unsupported_state_is_rejected() -> Result<()> {
        let mut gate = fixture_gate()?;
        first_row_mut(&mut gate)?.state = "completely_made_up".to_owned();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported state"))
        );
        Ok(())
    }

    #[test]
    fn unsupported_risk_surface_is_rejected() -> Result<()> {
        let mut gate = fixture_gate()?;
        first_row_mut(&mut gate)?.risk_surface = "telepathy".to_owned();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported risk_surface"))
        );
        Ok(())
    }

    #[test]
    fn missing_matched_snippet_hash_is_rejected() -> Result<()> {
        let mut gate = fixture_gate()?;
        first_row_mut(&mut gate)?.matched_snippet_hash = String::new();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing matched_snippet_hash"))
        );
        Ok(())
    }

    #[test]
    fn empty_rows_list_is_rejected() -> Result<()> {
        let mut gate = fixture_gate()?;
        gate.rows.clear();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("at least one row"))
        );
        Ok(())
    }

    #[test]
    fn now_unix_must_be_positive() -> Result<()> {
        let mut gate = fixture_gate()?;
        gate.now_unix = 0;
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("now_unix must be positive"))
        );
        Ok(())
    }

    #[test]
    fn render_inventory_closeout_gate_markdown_default_gate() -> Result<()> {
        let report = validate_default_inventory_closeout_gate()?;
        let markdown = render_inventory_closeout_gate_markdown(&report);
        insta::assert_snapshot!(
            "render_inventory_closeout_gate_markdown_default_gate",
            markdown
        );
        Ok(())
    }

    #[test]
    fn inventory_closeout_gate_report_json_shape() -> Result<()> {
        let report = validate_default_inventory_closeout_gate()?;
        let json = serde_json::to_string_pretty(&report)?;
        insta::assert_snapshot!("inventory_closeout_gate_report_json_shape", json);
        let parsed: InventoryCloseoutReport = serde_json::from_str(&json)?;
        assert_eq!(parsed, report);
        Ok(())
    }

    #[test]
    fn fail_on_errors_rejects_invalid_report() -> Result<()> {
        let mut gate = fixture_gate()?;
        first_row_mut(&mut gate)?.risk_surface = "telepathy".to_owned();
        let report = validate_inventory_closeout_gate(&gate);
        let err = match fail_on_inventory_closeout_gate_errors(&report) {
            Ok(()) => bail!("invalid report fails closed"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("inventory closeout gate failed"));
        assert!(err.to_string().contains("unsupported risk_surface"));
        Ok(())
    }
}
