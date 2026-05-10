#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use serde_json::Value;

const SAMPLE_MANIFEST: &str = r#"
{
  "schema_version": 1,
  "gate_id": "bd-ckivp-v12-program-gate",
  "generated_at": "2026-05-10T04:00:00Z",
  "git_head": "sample",
  "environment": {
    "kernel": "Linux sample",
    "rustc": "rustc 1.0.0",
    "cargo": "cargo 1.0.0",
    "ffs_harness_version": "0.1.0"
  },
  "scenario_count": 14,
  "pass_count": 14,
  "fail_count": 0,
  "timeout_count": 0,
  "skip_count": 0,
  "release_recommendation": "PROCEED",
  "release_recommendation_reason": "all scenarios passed",
  "command_transcript": "artifacts/release_gate/v12/command_transcript.tsv",
  "waiver_document": "docs/release/V1.2_test_waivers.md",
  "scenarios": [
    {"scenario":1,"name":"perf","status":"PASS","duration_ms":10,"budget_ms":300000,"started_at":"2026-05-10T04:00:00Z","finished_at":"2026-05-10T04:00:01Z","evidence_paths":["a"],"child_gate_bead":"bd-m5wf.1.7","exit_code":0,"stderr_tail":""},
    {"scenario":2,"name":"writeback","status":"PASS","duration_ms":10,"budget_ms":300000,"started_at":"2026-05-10T04:00:00Z","finished_at":"2026-05-10T04:00:01Z","evidence_paths":["a"],"child_gate_bead":"bd-m5wf.2.5","exit_code":0,"stderr_tail":""},
    {"scenario":3,"name":"safe merge","status":"PASS","duration_ms":10,"budget_ms":300000,"started_at":"2026-05-10T04:00:00Z","finished_at":"2026-05-10T04:00:01Z","evidence_paths":["a"],"child_gate_bead":"bd-m5wf.3.5","exit_code":0,"stderr_tail":""},
    {"scenario":4,"name":"adaptive","status":"PASS","duration_ms":10,"budget_ms":300000,"started_at":"2026-05-10T04:00:00Z","finished_at":"2026-05-10T04:00:01Z","evidence_paths":["a"],"child_gate_bead":"bd-m5wf.4.5","exit_code":0,"stderr_tail":""},
    {"scenario":5,"name":"repair","status":"PASS","duration_ms":10,"budget_ms":300000,"started_at":"2026-05-10T04:00:00Z","finished_at":"2026-05-10T04:00:01Z","evidence_paths":["a"],"child_gate_bead":"bd-m5wf.5.5","exit_code":0,"stderr_tail":""},
    {"scenario":6,"name":"btrfs","status":"PASS","duration_ms":10,"budget_ms":300000,"started_at":"2026-05-10T04:00:00Z","finished_at":"2026-05-10T04:00:01Z","evidence_paths":["a"],"child_gate_bead":"bd-m5wf.6.5","exit_code":0,"stderr_tail":""},
    {"scenario":7,"name":"xfstests","status":"PASS","duration_ms":10,"budget_ms":300000,"started_at":"2026-05-10T04:00:00Z","finished_at":"2026-05-10T04:00:01Z","evidence_paths":["a"],"child_gate_bead":"bd-m5wf.7.5","exit_code":0,"stderr_tail":""},
    {"scenario":8,"name":"observability","status":"PASS","duration_ms":10,"budget_ms":300000,"started_at":"2026-05-10T04:00:00Z","finished_at":"2026-05-10T04:00:01Z","evidence_paths":["a"],"child_gate_bead":"bd-m5wf.8.7","exit_code":0,"stderr_tail":""},
    {"scenario":9,"name":"coverage","status":"PASS","duration_ms":10,"budget_ms":300000,"started_at":"2026-05-10T04:00:00Z","finished_at":"2026-05-10T04:00:01Z","evidence_paths":["a"],"child_gate_bead":"bd-m5wf.9.5","exit_code":0,"stderr_tail":""},
    {"scenario":10,"name":"fmt","status":"PASS","duration_ms":10,"budget_ms":300000,"started_at":"2026-05-10T04:00:00Z","finished_at":"2026-05-10T04:00:01Z","evidence_paths":["a"],"child_gate_bead":"bd-ckivp","exit_code":0,"stderr_tail":""},
    {"scenario":11,"name":"clippy","status":"PASS","duration_ms":10,"budget_ms":300000,"started_at":"2026-05-10T04:00:00Z","finished_at":"2026-05-10T04:00:01Z","evidence_paths":["a"],"child_gate_bead":"bd-ckivp","exit_code":0,"stderr_tail":""},
    {"scenario":12,"name":"tests","status":"PASS","duration_ms":10,"budget_ms":300000,"started_at":"2026-05-10T04:00:00Z","finished_at":"2026-05-10T04:00:01Z","evidence_paths":["a"],"child_gate_bead":"bd-ckivp","exit_code":0,"stderr_tail":""},
    {"scenario":13,"name":"cli","status":"PASS","duration_ms":10,"budget_ms":300000,"started_at":"2026-05-10T04:00:00Z","finished_at":"2026-05-10T04:00:01Z","evidence_paths":["a"],"child_gate_bead":"bd-ckivp","exit_code":0,"stderr_tail":""},
    {"scenario":14,"name":"logging","status":"PASS","duration_ms":10,"budget_ms":300000,"started_at":"2026-05-10T04:00:00Z","finished_at":"2026-05-10T04:00:01Z","evidence_paths":["a"],"child_gate_bead":"bd-ckivp","exit_code":0,"stderr_tail":""}
  ]
}
"#;

#[test]
fn v12_manifest_covers_all_fourteen_scenarios() {
    let manifest: Value = serde_json::from_str(SAMPLE_MANIFEST).expect("sample manifest parses");
    validate_manifest(&manifest, true).expect("manifest contract is valid");
}

#[test]
fn v12_manifest_rejects_missing_scenario_numbers() {
    let mut manifest: Value =
        serde_json::from_str(SAMPLE_MANIFEST).expect("sample manifest parses");
    manifest["scenarios"].as_array_mut().expect("array").pop();
    assert!(validate_manifest(&manifest, true).is_err());
}

#[test]
fn v12_manifest_allows_timeout_to_exceed_budget_only_when_status_timeout() {
    let mut manifest: Value =
        serde_json::from_str(SAMPLE_MANIFEST).expect("sample manifest parses");
    manifest["scenarios"].as_array_mut().expect("array")[0]["duration_ms"] = Value::from(400_000);
    assert!(validate_manifest(&manifest, true).is_err());
    {
        let first = &mut manifest["scenarios"].as_array_mut().expect("array")[0];
        first["status"] = Value::from("TIMEOUT");
        first["exit_code"] = Value::from(124);
    }
    assert!(validate_manifest(&manifest, true).is_ok());
}

fn validate_manifest(manifest: &Value, require_fourteen: bool) -> Result<(), String> {
    let scenarios = manifest
        .get("scenarios")
        .and_then(Value::as_array)
        .ok_or_else(|| "scenarios must be an array".to_owned())?;
    if require_fourteen && scenarios.len() != 14 {
        return Err(format!("expected 14 scenarios, got {}", scenarios.len()));
    }
    let recommendation = required_str(manifest, "release_recommendation")?;
    if !["PROCEED", "NO-PROCEED", "PASS-WITH-WAIVERS"].contains(&recommendation.as_str()) {
        return Err(format!("invalid recommendation: {recommendation}"));
    }

    let mut seen = BTreeSet::new();
    for scenario in scenarios {
        validate_scenario(scenario)?;
        let number = required_u64(scenario, "scenario")?;
        if !seen.insert(number) {
            return Err(format!("duplicate scenario: {number}"));
        }
    }
    if require_fourteen {
        let expected = (1..=14).collect::<BTreeSet<_>>();
        if seen != expected {
            return Err(format!("scenario coverage gap: {seen:?}"));
        }
    }
    Ok(())
}

fn validate_scenario(scenario: &Value) -> Result<(), String> {
    let status = required_str(scenario, "status")?;
    if !["PASS", "FAIL", "TIMEOUT", "SKIP"].contains(&status.as_str()) {
        return Err(format!("invalid status: {status}"));
    }
    for field in [
        "name",
        "started_at",
        "finished_at",
        "child_gate_bead",
        "stderr_tail",
    ] {
        required_str(scenario, field)?;
    }
    let duration_ms = required_u64(scenario, "duration_ms")?;
    let budget_ms = required_u64(scenario, "budget_ms")?;
    required_i64(scenario, "exit_code")?;
    let evidence = scenario
        .get("evidence_paths")
        .and_then(Value::as_array)
        .ok_or_else(|| "evidence_paths must be an array".to_owned())?;
    if evidence.is_empty() {
        return Err("evidence_paths must not be empty".to_owned());
    }
    if status != "TIMEOUT" && duration_ms > budget_ms {
        return Err(format!(
            "scenario exceeded budget without TIMEOUT: {duration_ms} > {budget_ms}"
        ));
    }
    Ok(())
}

fn required_str(value: &Value, field: &str) -> Result<String, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("missing string field: {field}"))
}

fn required_u64(value: &Value, field: &str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing integer field: {field}"))
}

fn required_i64(value: &Value, field: &str) -> Result<i64, String> {
    value
        .get(field)
        .and_then(Value::as_i64)
        .ok_or_else(|| format!("missing signed integer field: {field}"))
}
