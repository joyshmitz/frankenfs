#!/usr/bin/env bash
# ffs_docs_status_drift_e2e.sh - smoke gate for bd-jtu4q.
#
# Proves public docs/status wording is generated from support-state accounting
# and ambition evidence rows, and fails closed on overclaims or stale flat
# parity wording.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_docs_status_drift}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_CAPTURE_VISIBILITY="${FFS_DOCS_STATUS_DRIFT_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_DOCS_STATUS_DRIFT_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_DOCS_STATUS_DRIFT_SKIP_SELF_CHECK:-0}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

run_rch_capture() {
    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" e2e_rch_capture "$@"
}

scenario_result() {
    local scenario_id="$1"
    local status="$2"
    local detail="$3"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${status}|detail=${detail}"
    if [[ "$status" == "PASS" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    TOTAL=$((TOTAL + 1))
}

e2e_init "ffs_docs_status_drift"

REPORT_JSON="${E2E_LOG_DIR}/docs_status_drift.json"
REPORT_MD="${E2E_LOG_DIR}/docs_status_drift.md"
REPORT_RAW="${E2E_LOG_DIR}/docs_status_drift.raw"
REPORT_MD_RAW="${E2E_LOG_DIR}/docs_status_drift_md.raw"
RCH_INPUT_DIR="$REPO_ROOT/artifacts/rch_input/$(basename "$E2E_LOG_DIR")/docs_status_drift"
mkdir -p "$RCH_INPUT_DIR"
ISSUES_JSONL="${RCH_INPUT_DIR}/issues.jsonl"
BAD_UPGRADE_JSON="${RCH_INPUT_DIR}/bad_upgrade_snippets.json"
BAD_FLAT_JSON="${RCH_INPUT_DIR}/bad_flat_snippets.json"
BAD_RELEASE_GATE_JSON="${RCH_INPUT_DIR}/bad_release_gate_snippets.json"
BAD_UPGRADE_RAW="${E2E_LOG_DIR}/bad_upgrade.raw"
BAD_FLAT_RAW="${E2E_LOG_DIR}/bad_flat.raw"
BAD_RELEASE_GATE_RAW="${E2E_LOG_DIR}/bad_release_gate.raw"
UNIT_LOG="${E2E_LOG_DIR}/unit_tests.log"
cp .beads/issues.jsonl "$ISSUES_JSONL"

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_DOCS_STATUS_DRIFT_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

emit_valid_report() {
    python3 - <<'PY'
import json

statuses = [
    "validated",
    "experimental",
    "detection-only",
    "dry-run-only",
    "parse-only",
    "opt-in mutating",
    "disabled",
    "unsupported",
    "deferred",
    "stale-evidence",
    "host-blocked",
    "security-refused",
]
targets = [
    "README.md",
    "FEATURE_PARITY.md",
    "COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md",
    "PLAN_TO_PORT_FRANKENFS_TO_RUST.md",
    "EXISTING_EXT4_BTRFS_STRUCTURE.md",
    "PROPOSED_ARCHITECTURE.md",
    "CLI help/status text",
    "scripts/e2e/README.md",
    "proof-bundle summaries",
]
observations = []
for index, status in enumerate(statuses):
    observations.append({
        "feature_id": f"fixture_feature_{index}",
        "docs_target": targets[index % len(targets)],
        "section_anchor": f"fixture-anchor-{index}",
        "source_support_state_row": f"fixture_feature_{index}:{status}",
        "gate_artifact_hash": "sha256:" + f"{index:064d}"[-64:],
        "generated_wording_id": f"docs.fixture.{index}",
        "observed_wording_hash": "sha256:" + f"{index + 1:064d}"[-64:],
        "drift_classification": "matches",
        "remediation_id": "bd-rchk0",
        "expected_public_status": status,
        "output_path": f"artifacts/docs-status/fixture-{index}.json",
        "reproduction_command": "cargo run -p ffs-harness -- validate-docs-status-drift",
    })
for target in targets:
    if target not in {row["docs_target"] for row in observations}:
        observations.append({
            "feature_id": f"fixture_target_{len(observations)}",
            "docs_target": target,
            "section_anchor": "fixture-extra-target",
            "source_support_state_row": "fixture:validated",
            "gate_artifact_hash": "sha256:" + "1" * 64,
            "generated_wording_id": "docs.fixture.extra",
            "observed_wording_hash": "sha256:" + "2" * 64,
            "drift_classification": "matches",
            "remediation_id": "bd-rchk0",
            "expected_public_status": "validated",
            "output_path": "artifacts/docs-status/fixture-extra.json",
            "reproduction_command": "cargo run -p ffs-harness -- validate-docs-status-drift",
        })
contracts = [
    {
        "feature_id": "mount.rw.ext4",
        "docs_target": "FEATURE_PARITY.md",
        "final_state": "experimental",
        "target_state": "validated",
        "controlling_lane": "mounted_differential_oracle",
        "missing_artifact": "fresh mounted ext4 proof lane",
        "remediation_id": "bd-rchk0",
    },
    {
        "feature_id": "mount.rw.btrfs",
        "docs_target": "FEATURE_PARITY.md",
        "final_state": "experimental",
        "target_state": "validated",
        "controlling_lane": "mounted_differential_oracle",
        "missing_artifact": "fresh mounted btrfs proof lane",
        "remediation_id": "bd-rchk0",
    },
    {
        "feature_id": "repair.rw.writeback",
        "docs_target": "README.md",
        "final_state": "hidden",
        "target_state": "opt-in mutating",
        "controlling_lane": "repair_writeback",
        "missing_artifact": "fresh repair writeback proof lane",
        "remediation_id": "bd-rchk0",
    },
    {
        "feature_id": "writeback_cache",
        "docs_target": "FEATURE_PARITY.md",
        "final_state": "disabled",
        "target_state": "validated",
        "controlling_lane": "writeback_cache",
        "missing_artifact": "fresh writeback cache proof lane",
        "remediation_id": "bd-rchk0",
    },
    {
        "feature_id": "xfstests.baseline",
        "docs_target": "FEATURE_PARITY.md",
        "final_state": "hidden",
        "target_state": "experimental",
        "controlling_lane": "xfstests",
        "missing_artifact": "fresh permissioned xfstests baseline proof lane",
        "remediation_id": "bd-rchk3",
    },
    {
        "feature_id": "swarm.responsiveness",
        "docs_target": "README.md",
        "final_state": "hidden",
        "target_state": "validated",
        "controlling_lane": "swarm_tail_latency",
        "missing_artifact": "fresh permissioned large-host swarm proof lane",
        "remediation_id": "bd-rchk0.53.8",
    },
]
report = {
    "docs_status_drift_version": 1,
    "release_gate_pass": True,
    "errors": [],
    "observation_count": len(observations),
    "observations": observations,
    "drift_classification_counts": {"matches": len(observations)},
    "release_gate_wording_observation_count": len(contracts),
    "release_gate_wording_contracts": contracts,
    "release_gate_wording_drift_classification_counts": {"matches": len(contracts)},
}
print(json.dumps(report, indent=2, sort_keys=True))
PY
}

emit_markdown_report() {
    cat <<'MD'
# FrankenFS Docs Status Drift

- release gate: pass
- public statuses: validated, experimental, host-blocked
- release-gate wording: xfstests.baseline and swarm.responsiveness stay scoped
MD
}

case "$fixture_case" in
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)" >&2
        exit 1
        ;;
    complete)
        ;;
    *)
        echo "unknown docs status drift fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

echo "[RCH] remote worker=fixture exit=0" >&2
case "$command_text" in
    *"cargo test -p ffs-harness --lib -- docs_status_drift"*)
        for name in \
            default_snippets_match_generated_wording \
            report_json_shape \
            markdown_renders_release_gate_contracts \
            rejects_hand_upgraded_claims \
            rejects_flat_parity_wording \
            rejects_release_gate_overclaim \
            requires_remediation_ids \
            counts_public_statuses \
            preserves_structured_log_fields \
            validates_required_docs_targets \
            fail_closed_on_missing_support_rows; do
            printf 'test docs_status_drift::tests::%s ... ok\n' "$name"
        done
        exit 0
        ;;
    *"bad_upgrade_snippets.json"*)
        printf '%s\n' \
            "error: feature_id=rw_background_repair docs_target=README.md expected_wording_id=docs.rw-background-repair.host-blocked observed_wording_hash=sha256:fixture source_support_state_row=rw_background_repair:host_blocked drift_classification=stronger-than-evidence remediation_id=bd-bqgy8" >&2
        exit 1
        ;;
    *"bad_flat_snippets.json"*)
        printf '%s\n' \
            "error: feature_id=mounted_write_paths drift_classification=stale-flat-parity" >&2
        exit 1
        ;;
    *"bad_release_gate_snippets.json"*)
        printf '%s\n' \
            "error: feature_id=xfstests.baseline docs_target=FEATURE_PARITY.md docs_wording_id=feature_parity.xfstests final_state=hidden target_state=experimental controlling_lane=xfstests missing_artifact=fresh permissioned xfstests baseline proof lane drift_classification=stronger-than-release-gate remediation_id=bd-rchk3" >&2
        exit 1
        ;;
    *"--format markdown"*)
        emit_markdown_report
        exit 0
        ;;
    *)
        emit_valid_report
        exit 0
        ;;
esac
SH
    chmod +x "$stub_path"
}

extract_child_result_json() {
    local log_path="$1"
    sed -n 's/^JSON summary written: //p' "$log_path" | tail -n 1
}

run_fixture_child() {
    local stub_path="$1"
    local fixture_case="$2"
    local child_log="$E2E_LOG_DIR/docs_status_drift_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_DOCS_STATUS_DRIFT_SELF_CHECK=0 \
        FFS_DOCS_STATUS_DRIFT_SKIP_SELF_CHECK=1 \
        FFS_DOCS_STATUS_DRIFT_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=8 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_docs_status_drift_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic docs status drift wrapper self-check"
    local stub_path child_info child_status child_log result_path report_path markdown_path unit_log
    stub_path="$E2E_LOG_DIR/rch-docs-status-drift-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    report_path="$(dirname "$result_path")/docs_status_drift.json"
    markdown_path="$(dirname "$result_path")/docs_status_drift.md"
    unit_log="$(dirname "$result_path")/unit_tests.log"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$report_path" ]] \
        && [[ -f "$markdown_path" ]] \
        && [[ -f "$unit_log" ]] \
        && jq -e '
            .verdict == "PASS"
            and ([.scenarios[] | select(.scenario_id == "docs_status_report_renders" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "docs_status_surface_status_coverage" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "docs_status_log_tokens" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "docs_status_hand_upgrade_fails" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "docs_status_flat_parity_fails" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "docs_status_release_gate_overclaim_fails" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "docs_status_unit_tests" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && jq -e '
            .release_gate_pass == true
            and .observation_count >= 12
            and .drift_classification_counts.matches == .observation_count
            and ([.observations[].expected_public_status] | unique | length) >= 12
            and ([.observations[].docs_target] | unique | length) >= 9
            and (.release_gate_wording_contracts | length) >= 6
            and .release_gate_wording_drift_classification_counts.matches == .release_gate_wording_observation_count
        ' "$report_path" >/dev/null \
        && grep -q "# FrankenFS Docs Status Drift" "$markdown_path" \
        && grep -q "swarm.responsiveness" "$markdown_path" \
        && grep -q "docs_status_drift::tests::default_snippets_match_generated_wording" "$unit_log"; then
        scenario_result "docs_status_fixture_complete_self_check" "PASS" "result=${result_path} report=${report_path} markdown=${markdown_path}"
    else
        scenario_result "docs_status_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "docs status drift complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "docs_status_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "docs_status_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "docs status drift local fallback fixture self-check failed"
    fi
}

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass "docs status drift wrapper self-check"
    exit 0
fi

e2e_step "Scenario 1: module and CLI are wired"
if grep -q "pub mod docs_status_drift" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-docs-status-drift" crates/ffs-harness/src/main.rs; then
    scenario_result "docs_status_wired" "PASS" "module and CLI command exported"
else
    scenario_result "docs_status_wired" "FAIL" "missing module export or CLI command"
fi

e2e_step "Scenario 2: CLI renders JSON and Markdown reports"
if run_rch_capture "$REPORT_RAW" cargo run --quiet -p ffs-harness -- validate-docs-status-drift \
    --issues "$ISSUES_JSONL" \
    --feature-parity FEATURE_PARITY.md \
    && run_rch_capture "$REPORT_MD_RAW" cargo run --quiet -p ffs-harness -- validate-docs-status-drift \
        --issues "$ISSUES_JSONL" \
        --feature-parity FEATURE_PARITY.md \
        --format markdown; then
    if python3 - "$REPORT_RAW" "$REPORT_JSON" "$REPORT_MD_RAW" "$REPORT_MD" <<'PY'
import json
import sys

json_raw, json_report, md_raw, md_report = sys.argv[1:5]
text = open(json_raw, encoding="utf-8", errors="replace").read()
decoder = json.JSONDecoder()
for index, char in enumerate(text):
    if char != "{":
        continue
    try:
        obj, _ = decoder.raw_decode(text[index:])
    except json.JSONDecodeError:
        continue
    if isinstance(obj, dict) and "docs_status_drift_version" in obj:
        with open(json_report, "w", encoding="utf-8") as handle:
            json.dump(obj, handle, indent=2, sort_keys=True)
            handle.write("\n")
        break
else:
    raise SystemExit("docs-status JSON object not found in rch output")

markdown = open(md_raw, encoding="utf-8", errors="replace").read()
marker = "# FrankenFS Docs Status Drift"
index = markdown.find(marker)
if index < 0:
    raise SystemExit("docs-status Markdown marker not found")
with open(md_report, "w", encoding="utf-8") as handle:
    handle.write(markdown[index:])
PY
    then
        scenario_result "docs_status_report_renders" "PASS" "JSON and Markdown reports captured"
    else
        scenario_result "docs_status_report_renders" "FAIL" "missing JSON or Markdown output"
    fi
else
    scenario_result "docs_status_report_renders" "FAIL" "CLI command failed"
fi

e2e_step "Scenario 3: required surfaces and public statuses are covered"
if python3 - "$REPORT_JSON" <<'PY'
import json
import sys

data = json.loads(open(sys.argv[1], encoding="utf-8").read())
if not data.get("release_gate_pass"):
    raise SystemExit(f"release gate should pass: {data.get('errors')}")
required_statuses = {
    "validated",
    "experimental",
    "detection-only",
    "dry-run-only",
    "parse-only",
    "opt-in mutating",
    "disabled",
    "unsupported",
    "deferred",
    "stale-evidence",
    "host-blocked",
    "security-refused",
}
required_targets = {
    "README.md",
    "FEATURE_PARITY.md",
    "COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md",
    "PLAN_TO_PORT_FRANKENFS_TO_RUST.md",
    "EXISTING_EXT4_BTRFS_STRUCTURE.md",
    "PROPOSED_ARCHITECTURE.md",
    "CLI help/status text",
    "scripts/e2e/README.md",
    "proof-bundle summaries",
}
statuses = {row["expected_public_status"] for row in data.get("observations", [])}
targets = {row["docs_target"] for row in data.get("observations", [])}
missing_statuses = sorted(required_statuses - statuses)
missing_targets = sorted(required_targets - targets)
if missing_statuses or missing_targets:
    raise SystemExit(f"missing statuses={missing_statuses} targets={missing_targets}")
if data.get("drift_classification_counts", {}).get("matches") != data.get("observation_count"):
    raise SystemExit("all default snippets should match generated wording")
release_contracts = {
    row["feature_id"]: row for row in data.get("release_gate_wording_contracts", [])
}
for feature in [
    "mount.rw.ext4",
    "mount.rw.btrfs",
    "repair.rw.writeback",
    "writeback_cache",
    "xfstests.baseline",
    "swarm.responsiveness",
]:
    if feature not in release_contracts:
        raise SystemExit(f"missing release-gate wording contract {feature}")
for feature, field in [
    ("xfstests.baseline", "controlling_lane"),
    ("xfstests.baseline", "missing_artifact"),
    ("xfstests.baseline", "remediation_id"),
    ("swarm.responsiveness", "docs_target"),
    ("writeback_cache", "final_state"),
    ("repair.rw.writeback", "target_state"),
]:
    if not release_contracts[feature].get(field):
        raise SystemExit(f"missing {field} for {feature}")
if data.get("release_gate_wording_drift_classification_counts", {}).get("matches") != data.get("release_gate_wording_observation_count"):
    raise SystemExit("all default release-gate wording snippets should match")
PY
then
    scenario_result "docs_status_surface_status_coverage" "PASS" "required surfaces and statuses represented"
else
    scenario_result "docs_status_surface_status_coverage" "FAIL" "surface/status coverage validation failed"
fi

e2e_step "Scenario 4: structured drift log fields are present"
TOKENS_FOUND=0
for token in \
    "docs_target" \
    "section_anchor" \
    "feature_id" \
    "source_support_state_row" \
    "gate_artifact_hash" \
    "generated_wording_id" \
    "observed_wording_hash" \
    "drift_classification" \
    "remediation_id" \
    "output_path" \
    "reproduction_command"; do
    if grep -q "\"${token}\"" "$REPORT_JSON"; then
        TOKENS_FOUND=$((TOKENS_FOUND + 1))
    fi
done

if [[ $TOKENS_FOUND -eq 11 ]]; then
    scenario_result "docs_status_log_tokens" "PASS" "all structured drift tokens present"
else
    scenario_result "docs_status_log_tokens" "FAIL" "only ${TOKENS_FOUND}/11 log tokens present"
fi

e2e_step "Scenario 5: hand-upgraded claim fails closed"
cat >"$BAD_UPGRADE_JSON" <<'JSON'
{
  "snippets": [
    {
      "feature_id": "rw_background_repair",
      "docs_target": "README.md",
      "section_anchor": "mounted-self-healing",
      "observed_text": "rw_background_repair is validated and fully supported for production automatic repair."
    }
  ]
}
JSON
if run_rch_capture "$BAD_UPGRADE_RAW" cargo run --quiet -p ffs-harness -- validate-docs-status-drift \
    --issues "$ISSUES_JSONL" \
    --feature-parity FEATURE_PARITY.md \
    --snippets "$BAD_UPGRADE_JSON"; then
    scenario_result "docs_status_hand_upgrade_fails" "FAIL" "bad upgrade unexpectedly passed"
else
    if grep -q "feature_id=rw_background_repair" "$BAD_UPGRADE_RAW" \
        && grep -q "docs_target=README.md" "$BAD_UPGRADE_RAW" \
        && grep -q "expected_wording_id=docs.rw-background-repair.host-blocked" "$BAD_UPGRADE_RAW" \
        && grep -q "observed_wording_hash=" "$BAD_UPGRADE_RAW" \
        && grep -q "source_support_state_row=rw_background_repair:host_blocked" "$BAD_UPGRADE_RAW" \
        && grep -q "drift_classification=stronger-than-evidence" "$BAD_UPGRADE_RAW" \
        && grep -q "remediation_id=bd-bqgy8" "$BAD_UPGRADE_RAW"; then
        scenario_result "docs_status_hand_upgrade_fails" "PASS" "bad upgrade failed with exact diagnostic fields"
    else
        scenario_result "docs_status_hand_upgrade_fails" "FAIL" "failure did not include exact drift diagnostics"
    fi
fi

e2e_step "Scenario 6: stale flat parity claim fails closed"
cat >"$BAD_FLAT_JSON" <<'JSON'
{
  "snippets": [
    {
      "feature_id": "mounted_write_paths",
      "docs_target": "README.md",
      "section_anchor": "project-status",
      "observed_text": "FrankenFS has 100 percent parity, including mounted write paths."
    }
  ]
}
JSON
if run_rch_capture "$BAD_FLAT_RAW" cargo run --quiet -p ffs-harness -- validate-docs-status-drift \
    --issues "$ISSUES_JSONL" \
    --feature-parity FEATURE_PARITY.md \
    --snippets "$BAD_FLAT_JSON"; then
    scenario_result "docs_status_flat_parity_fails" "FAIL" "flat parity wording unexpectedly passed"
else
    if grep -q "feature_id=mounted_write_paths" "$BAD_FLAT_RAW" \
        && grep -q "drift_classification=stale-flat-parity" "$BAD_FLAT_RAW"; then
        scenario_result "docs_status_flat_parity_fails" "PASS" "flat parity wording failed closed"
    else
        scenario_result "docs_status_flat_parity_fails" "FAIL" "failure did not name stale flat parity drift"
    fi
fi

e2e_step "Scenario 7: release-gate wording overclaim fails closed"
cat >"$BAD_RELEASE_GATE_JSON" <<'JSON'
{
  "snippets": [
    {
      "feature_id": "xfstests.baseline",
      "docs_target": "FEATURE_PARITY.md",
      "section_anchor": "xfstests-readiness",
      "observed_text": "feature_parity.xfstests: xfstests.baseline is validated by fresh release-gate evidence."
    }
  ]
}
JSON
if run_rch_capture "$BAD_RELEASE_GATE_RAW" cargo run --quiet -p ffs-harness -- validate-docs-status-drift \
    --issues "$ISSUES_JSONL" \
    --feature-parity FEATURE_PARITY.md \
    --snippets "$BAD_RELEASE_GATE_JSON"; then
    scenario_result "docs_status_release_gate_overclaim_fails" "FAIL" "release-gate overclaim unexpectedly passed"
else
    if grep -q "feature_id=xfstests.baseline" "$BAD_RELEASE_GATE_RAW" \
        && grep -q "docs_target=FEATURE_PARITY.md" "$BAD_RELEASE_GATE_RAW" \
        && grep -q "docs_wording_id=feature_parity.xfstests" "$BAD_RELEASE_GATE_RAW" \
        && grep -q "final_state=hidden" "$BAD_RELEASE_GATE_RAW" \
        && grep -q "target_state=experimental" "$BAD_RELEASE_GATE_RAW" \
        && grep -q "controlling_lane=xfstests" "$BAD_RELEASE_GATE_RAW" \
        && grep -q "missing_artifact=fresh permissioned xfstests baseline proof lane" "$BAD_RELEASE_GATE_RAW" \
        && grep -q "drift_classification=stronger-than-release-gate" "$BAD_RELEASE_GATE_RAW" \
        && grep -q "remediation_id=bd-rchk3" "$BAD_RELEASE_GATE_RAW"; then
        scenario_result "docs_status_release_gate_overclaim_fails" "PASS" "release-gate overclaim failed with lane/remediation diagnostics"
    else
        scenario_result "docs_status_release_gate_overclaim_fails" "FAIL" "failure did not include release-gate drift diagnostics"
    fi
fi

e2e_step "Scenario 8: unit/schema tests pass"
if run_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib -- docs_status_drift; then
    TESTS_RUN=$(grep -c "test docs_status_drift::tests::" "$UNIT_LOG" 2>/dev/null || echo "0")
    if [[ $TESTS_RUN -ge 10 ]]; then
        scenario_result "docs_status_unit_tests" "PASS" "unit tests passed (${TESTS_RUN} tests)"
    else
        scenario_result "docs_status_unit_tests" "FAIL" "too few tests: ${TESTS_RUN}"
    fi
else
    scenario_result "docs_status_unit_tests" "FAIL" "unit tests failed"
fi

e2e_step "Summary"
e2e_log "SUMMARY|total=${TOTAL}|passed=${PASS_COUNT}|failed=${FAIL_COUNT}"

if [[ $FAIL_COUNT -eq 0 ]]; then
    e2e_pass "ffs_docs_status_drift completed"
else
    e2e_fail "ffs_docs_status_drift failed ${FAIL_COUNT}/${TOTAL} scenarios"
fi
