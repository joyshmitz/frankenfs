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
use std::collections::BTreeSet;

pub const INVENTORY_CLOSEOUT_GATE_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_INVENTORY_CLOSEOUT_GATE_PATH: &str =
    "tests/inventory-closeout-gate/inventory_closeout_gate.json";
const DEFAULT_INVENTORY_CLOSEOUT_GATE_JSON: &str = include_str!(
    "../../../tests/inventory-closeout-gate/inventory_closeout_gate.json"
);

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
    serde_json::from_str(text).map_err(|err| {
        anyhow::anyhow!("failed to parse inventory closeout gate JSON: {err}")
    })
}

pub fn validate_default_inventory_closeout_gate() -> Result<InventoryCloseoutReport> {
    let gate = parse_inventory_closeout_gate(DEFAULT_INVENTORY_CLOSEOUT_GATE_JSON)?;
    let report = validate_inventory_closeout_gate(&gate);
    if !report.valid {
        bail!(
            "inventory closeout gate failed with {} error(s): {}",
            report.errors.len(),
            report.errors.join("; ")
        );
    }
    Ok(report)
}

#[must_use]
pub fn validate_inventory_closeout_gate(
    gate: &InventoryCloseoutGate,
) -> InventoryCloseoutReport {
    let mut errors = Vec::new();
    let mut ids = BTreeSet::new();
    let mut high_risk_surfaces = BTreeSet::new();
    let mut completed = 0_usize;
    let mut stale_allowed = 0_usize;
    let mut false_positive = 0_usize;

    validate_top_level(gate, &mut errors);

    let row_id_set: BTreeSet<&str> =
        gate.rows.iter().map(|row| row.row_id.as_str()).collect();

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
        errors.push(format!(
            "row `{}` missing matched_snippet_hash",
            row.row_id
        ));
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

fn validate_linked_bead_or_artifact_state(
    row: &InventoryCloseoutRow,
    errors: &mut Vec<String>,
) {
    if row.linked_bead_or_artifact.trim().is_empty() {
        errors.push(format!(
            "row `{}` state requires linked_bead_or_artifact",
            row.row_id
        ));
    } else if row.state == "linked_bead"
        && !row.linked_bead_or_artifact.starts_with("bd-")
    {
        errors.push(format!(
            "row `{}` linked_bead state requires linked_bead_or_artifact starting with bd-",
            row.row_id
        ));
    } else if row.state == "completed_artifact"
        && !row.linked_bead_or_artifact.contains('/')
    {
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
    if !row.linked_bead_or_artifact.starts_with("bd-")
        && !row.linked_bead_or_artifact.contains('/')
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

fn validate_false_positive_state(
    row: &InventoryCloseoutRow,
    errors: &mut Vec<String>,
) {
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

fn validate_high_risk_coverage(
    high_risk_surfaces: &BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    for required in HIGH_RISK_SURFACES {
        if !high_risk_surfaces.contains(required) {
            errors.push(format!(
                "inventory closeout gate must classify at least one row from risk_surface `{required}`"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_gate() -> InventoryCloseoutGate {
        parse_inventory_closeout_gate(DEFAULT_INVENTORY_CLOSEOUT_GATE_JSON)
            .expect("default inventory closeout gate parses")
    }

    #[test]
    fn default_gate_validates_high_risk_coverage() {
        let report = validate_default_inventory_closeout_gate()
            .expect("default inventory closeout gate validates");
        assert_eq!(report.bead_id, "bd-rpjp9");
        for surface in HIGH_RISK_SURFACES {
            assert!(
                report
                    .high_risk_surfaces_seen
                    .iter()
                    .any(|s| s == surface),
                "missing surface {surface}"
            );
        }
    }

    #[test]
    fn missing_high_risk_surface_is_rejected() {
        let mut gate = fixture_gate();
        gate.rows.retain(|r| r.risk_surface != "fuzz");
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must classify at least one row from risk_surface `fuzz`"))
        );
    }

    #[test]
    fn missing_xfstests_surface_is_rejected() {
        let mut gate = fixture_gate();
        gate.rows.retain(|r| r.risk_surface != "xfstests");
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("`xfstests`"))
        );
    }

    #[test]
    fn duplicate_row_id_is_rejected() {
        let mut gate = fixture_gate();
        let dup = gate.rows[0].row_id.clone();
        gate.rows[1].row_id = dup;
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("duplicate inventory closeout row_id"))
        );
    }

    #[test]
    fn row_id_prefix_is_enforced() {
        let mut gate = fixture_gate();
        gate.rows[0].row_id = "x_001".to_owned();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("must start with inv_"))
        );
    }

    #[test]
    fn linked_bead_state_requires_bd_prefix() {
        let mut gate = fixture_gate();
        let row = gate
            .rows
            .iter_mut()
            .find(|r| r.state == "linked_bead")
            .expect("linked_bead row exists");
        row.linked_bead_or_artifact = "PROJ-1".to_owned();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(report.errors.iter().any(|err| err
            .contains("linked_bead state requires linked_bead_or_artifact starting with bd-")));
    }

    #[test]
    fn completed_artifact_state_requires_artifact_path() {
        let mut gate = fixture_gate();
        let row = gate
            .rows
            .iter_mut()
            .find(|r| r.state == "completed_artifact")
            .expect("completed artifact row exists");
        row.linked_bead_or_artifact = "no-slash-no-path".to_owned();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(report.errors.iter().any(|err| err
            .contains("completed_artifact state requires an artifact path")));
    }

    #[test]
    fn stale_allowed_requires_future_expiry() {
        let mut gate = fixture_gate();
        let row = gate
            .rows
            .iter_mut()
            .find(|r| r.state == "stale_allowed_until")
            .expect("stale_allowed row exists");
        row.stale_expiry_unix = gate.now_unix.saturating_sub(1);
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("stale_expiry_unix must be in the future"))
        );
    }

    #[test]
    fn stale_allowed_requires_owner() {
        let mut gate = fixture_gate();
        let row = gate
            .rows
            .iter_mut()
            .find(|r| r.state == "stale_allowed_until")
            .expect("stale_allowed row exists");
        row.owner = String::new();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("stale_allowed_until requires owner"))
        );
    }

    #[test]
    fn stale_allowed_requires_user_risk_rationale() {
        let mut gate = fixture_gate();
        let row = gate
            .rows
            .iter_mut()
            .find(|r| r.state == "stale_allowed_until")
            .expect("stale_allowed row exists");
        row.user_risk_rationale = String::new();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(report.errors.iter().any(|err| err
            .contains("stale_allowed_until requires user_risk_rationale")));
    }

    #[test]
    fn stale_allowed_requires_linked_bead_or_artifact() {
        let mut gate = fixture_gate();
        let row = gate
            .rows
            .iter_mut()
            .find(|r| r.state == "stale_allowed_until")
            .expect("stale_allowed row exists");
        row.linked_bead_or_artifact = String::new();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(report.errors.iter().any(|err| err
            .contains("stale_allowed_until requires linked bead or non-goal artifact")));
    }

    #[test]
    fn duplicate_of_must_match_existing_row() {
        let mut gate = fixture_gate();
        let row = gate
            .rows
            .iter_mut()
            .find(|r| r.state == "duplicate_of")
            .expect("duplicate_of row exists");
        row.duplicate_of = "inv_does_not_exist".to_owned();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("does not match any other row_id"))
        );
    }

    #[test]
    fn duplicate_of_cannot_point_to_self() {
        let mut gate = fixture_gate();
        let row = gate
            .rows
            .iter_mut()
            .find(|r| r.state == "duplicate_of")
            .expect("duplicate_of row exists");
        row.duplicate_of = row.row_id.clone();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("duplicate_of cannot point to itself"))
        );
    }

    #[test]
    fn explicit_non_goal_requires_rationale_and_owner() {
        let mut gate = fixture_gate();
        let row = gate
            .rows
            .iter_mut()
            .find(|r| r.state == "explicit_non_goal")
            .expect("non-goal row exists");
        row.user_risk_rationale = String::new();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(report
            .errors
            .iter()
            .any(|err| err.contains("requires user_risk_rationale")));
    }

    #[test]
    fn host_blocked_requires_linked_bead_or_artifact() {
        let mut gate = fixture_gate();
        let row = gate
            .rows
            .iter_mut()
            .find(|r| r.state == "host_blocked")
            .expect("host_blocked row exists");
        row.linked_bead_or_artifact = "no-prefix-no-slash".to_owned();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(report.errors.iter().any(|err| err
            .contains("host_blocked state requires linked bead or artifact path")));
    }

    #[test]
    fn false_positive_requires_owner_and_rationale() {
        let mut gate = fixture_gate();
        let row = gate
            .rows
            .iter_mut()
            .find(|r| r.state == "false_positive")
            .expect("false_positive row exists");
        row.owner = String::new();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("false_positive state requires owner"))
        );
    }

    #[test]
    fn unsupported_state_is_rejected() {
        let mut gate = fixture_gate();
        gate.rows[0].state = "completely_made_up".to_owned();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported state"))
        );
    }

    #[test]
    fn unsupported_risk_surface_is_rejected() {
        let mut gate = fixture_gate();
        gate.rows[0].risk_surface = "telepathy".to_owned();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("unsupported risk_surface"))
        );
    }

    #[test]
    fn missing_matched_snippet_hash_is_rejected() {
        let mut gate = fixture_gate();
        gate.rows[0].matched_snippet_hash = String::new();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("missing matched_snippet_hash"))
        );
    }

    #[test]
    fn empty_rows_list_is_rejected() {
        let mut gate = fixture_gate();
        gate.rows.clear();
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("at least one row"))
        );
    }

    #[test]
    fn now_unix_must_be_positive() {
        let mut gate = fixture_gate();
        gate.now_unix = 0;
        let report = validate_inventory_closeout_gate(&gate);
        assert!(
            report
                .errors
                .iter()
                .any(|err| err.contains("now_unix must be positive"))
        );
    }
}
