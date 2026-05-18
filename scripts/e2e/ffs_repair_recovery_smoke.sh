#!/usr/bin/env bash
# ffs_repair_recovery_smoke.sh - Deterministic corruption/recovery E2E smoke

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-info}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_repair_recovery_smoke}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_CAPTURE_VISIBILITY="${FFS_REPAIR_RECOVERY_SMOKE_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_REPAIR_RECOVERY_SMOKE_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_REPAIR_RECOVERY_SMOKE_SKIP_SELF_CHECK:-0}"

REPAIR_E2E_TEST="${REPAIR_E2E_TEST:-e2e_survive_five_percent_random_block_corruption_with_daemon}"
REPAIR_FIXTURE_SIZE_MB="${REPAIR_FIXTURE_SIZE_MB:-16}"
PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

for rch_env_var in CARGO_TARGET_DIR RUST_LOG RUST_BACKTRACE FFS_REPAIR_E2E_ARTIFACT_DIR FFS_REPAIR_E2E_ARTIFACT_STDOUT; do
    e2e_rch_add_env_allowlist "$rch_env_var"
done

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

run_rch_capture() {
    local output_path="$1"
    shift

    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" e2e_rch_capture "$output_path" "$@"
}

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_REPAIR_RECOVERY_SMOKE_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

case "$fixture_case" in
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)" >&2
        exit 1
        ;;
    complete)
        echo "[RCH] remote worker=fixture exit=0" >&2
        ;;
    missing_remote_evidence)
        ;;
    *)
        echo "unknown repair recovery smoke fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"cargo test -p ffs-repair e2e_survive_five_percent_random_block_corruption_with_daemon -- --nocapture"*)
        printf '%s\n' \
            "test pipeline::tests::e2e_survive_five_percent_random_block_corruption_with_daemon ... ok" \
            'FFS_REPAIR_E2E_ARTIFACT|name=before_checksums.txt|json="sha256-a  file-a\nsha256-b  file-b\n"' \
            'FFS_REPAIR_E2E_ARTIFACT|name=after_checksums.txt|json="sha256-a  file-a\nsha256-b  file-b\n"' \
            'FFS_REPAIR_E2E_ARTIFACT|name=corruption_plan.json|json="{\"corruption_percent\":5,\"corrupted_blocks\":[1,2,3],\"total_corrupted_blocks\":3}\n"' \
            'FFS_REPAIR_E2E_ARTIFACT|name=recovery_evidence.jsonl|json="{\"event_type\":\"corruption_detected\",\"block\":1}\n{\"event_type\":\"repair_succeeded\",\"block\":1}\n"'
        ;;
    *)
        echo "unexpected fixture command: $command_text" >&2
        exit 64
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
    local child_log="$E2E_LOG_DIR/repair_recovery_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_REPAIR_RECOVERY_SMOKE_SELF_CHECK=0 \
        FFS_REPAIR_RECOVERY_SMOKE_SKIP_SELF_CHECK=1 \
        FFS_REPAIR_RECOVERY_SMOKE_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=8 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_repair_recovery_smoke.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic repair recovery smoke wrapper self-check"
    local stub_path child_info child_status child_log result_path result_dir artifact_dir test_log
    stub_path="$E2E_LOG_DIR/rch-repair-recovery-smoke-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    result_dir="$(dirname "$result_path")"
    artifact_dir="$result_dir/repair"
    test_log="$result_dir/repair_recovery_rch.log"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$test_log" ]] \
        && have_artifacts "$artifact_dir" \
        && cmp "$artifact_dir/before_checksums.txt" "$artifact_dir/after_checksums.txt" >/dev/null \
        && jq -e '
            .verdict == "PASS"
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "repair_recovery_fixture_image_prepared" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "repair_recovery_rch_test_passed" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "repair_recovery_rch_artifacts_materialized" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "repair_recovery_checksums_match" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "repair_recovery_evidence_ledger_valid" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && jq -e '
            .corruption_percent == 5
            and .corrupted_blocks == [1, 2, 3]
            and .total_corrupted_blocks == 3
        ' "$artifact_dir/corruption_plan.json" >/dev/null \
        && grep -q "e2e_survive_five_percent_random_block_corruption_with_daemon" "$test_log"; then
        scenario_result "repair_recovery_fixture_complete_self_check" "PASS" "result=${result_path} artifact_dir=${artifact_dir}"
    else
        scenario_result "repair_recovery_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Repair recovery complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "repair_recovery_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "repair_recovery_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Repair recovery local fallback fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "missing_remote_evidence")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL"' "$result_path" >/dev/null \
        && grep -q "RCH_REMOTE_EVIDENCE_MISSING" "$child_log"; then
        scenario_result "repair_recovery_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "repair_recovery_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Repair recovery missing remote evidence fixture self-check failed"
    fi
}

print_rch_log() {
    local output_path="$1"
    if [[ -s "$output_path" ]]; then
        tee -a "$E2E_LOG_FILE" <"$output_path"
    fi
}

have_repair_e2e_test() {
    if command -v rg >/dev/null 2>&1; then
        rg -q "fn ${REPAIR_E2E_TEST}\\(" "$REPO_ROOT/crates/ffs-repair/src/pipeline.rs"
        return $?
    fi
    grep -q "fn ${REPAIR_E2E_TEST}(" "$REPO_ROOT/crates/ffs-repair/src/pipeline.rs"
}

have_artifacts() {
    local artifact_dir="$1"
    local name
    for name in before_checksums.txt after_checksums.txt corruption_plan.json recovery_evidence.jsonl; do
        if [[ ! -f "$artifact_dir/$name" ]]; then
            return 1
        fi
    done
    return 0
}

extract_repair_artifacts_from_rch_log() {
    local log_path="$1"
    local artifact_dir="$2"

    e2e_assert python3 - "$log_path" "$artifact_dir" <<'PY'
import json
import pathlib
import sys

log_path = pathlib.Path(sys.argv[1])
artifact_dir = pathlib.Path(sys.argv[2])
prefix = "FFS_REPAIR_E2E_ARTIFACT|name="
expected = {
    "before_checksums.txt",
    "after_checksums.txt",
    "corruption_plan.json",
    "recovery_evidence.jsonl",
}
found = {}

for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
    if prefix not in line:
        continue
    payload = line.split(prefix, 1)[1]
    name, sep, json_payload = payload.partition("|json=")
    if sep != "|json=" or name not in expected:
        continue
    found[name] = json.loads(json_payload)

missing = sorted(expected - set(found))
if missing:
    raise SystemExit(f"missing repair stdout artifacts: {missing}")

artifact_dir.mkdir(parents=True, exist_ok=True)
for name, text in found.items():
    (artifact_dir / name).write_text(text, encoding="utf-8")
PY
}

e2e_init "ffs_repair_recovery_smoke"
e2e_print_env

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

e2e_step "Phase 1: prerequisites"
if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    e2e_skip "rch not found; this test requires offloaded cargo execution"
fi
if ! command -v sha256sum >/dev/null 2>&1; then
    e2e_skip "sha256sum not found"
fi
if ! have_repair_e2e_test; then
    e2e_skip "repair pipeline test '${REPAIR_E2E_TEST}' not found; skipping until recovery pipeline is available"
fi

ARTIFACT_DIR="$E2E_LOG_DIR/repair"
RCH_ARTIFACT_DIR="$REPO_ROOT/artifacts/rch_output/$(basename "$E2E_LOG_DIR")/repair"
mkdir -p "$ARTIFACT_DIR"
mkdir -p "$RCH_ARTIFACT_DIR"

e2e_step "Phase 2: produce ext4 fixture image"
EXT4_FIXTURE="$ARTIFACT_DIR/ext4_fixture.img"
e2e_create_ext4_image "$EXT4_FIXTURE" "$REPAIR_FIXTURE_SIZE_MB"
e2e_assert_file "$EXT4_FIXTURE"
e2e_assert sha256sum "$EXT4_FIXTURE"
scenario_result "repair_recovery_fixture_image_prepared" "PASS" "ext4 fixture image prepared and checksummed"

e2e_step "Phase 3: run deterministic corruption/recovery scenario"
export FFS_REPAIR_E2E_ARTIFACT_DIR="$RCH_ARTIFACT_DIR"
export FFS_REPAIR_E2E_ARTIFACT_STDOUT=1
REPAIR_RCH_LOG="$E2E_LOG_DIR/repair_recovery_rch.log"
if run_rch_capture "$REPAIR_RCH_LOG" cargo test -p ffs-repair "$REPAIR_E2E_TEST" -- --nocapture; then
    scenario_result "repair_recovery_rch_test_passed" "PASS" "repair recovery test passed through RCH"
else
    print_rch_log "$REPAIR_RCH_LOG"
    scenario_result "repair_recovery_rch_test_passed" "FAIL" "repair recovery RCH test failed"
    e2e_fail "repair recovery RCH test failed"
fi

if ! command -v python3 >/dev/null 2>&1; then
    e2e_skip "python3 not found; required for repair artifact extraction"
fi
extract_repair_artifacts_from_rch_log "$REPAIR_RCH_LOG" "$ARTIFACT_DIR"
if ! have_artifacts "$ARTIFACT_DIR"; then
    print_rch_log "$REPAIR_RCH_LOG"
    scenario_result "repair_recovery_rch_artifacts_materialized" "FAIL" "stdout artifacts missing from ${ARTIFACT_DIR}"
    e2e_fail "repair test passed via RCH but expected stdout artifacts were not materialized"
fi
scenario_result "repair_recovery_rch_artifacts_materialized" "PASS" "repair artifacts reconstructed from RCH stdout transcript"

e2e_step "Phase 4: verify artifacts and recovery equivalence"
e2e_assert_file "$ARTIFACT_DIR/before_checksums.txt"
e2e_assert_file "$ARTIFACT_DIR/after_checksums.txt"
e2e_assert_file "$ARTIFACT_DIR/corruption_plan.json"
e2e_assert_file "$ARTIFACT_DIR/recovery_evidence.jsonl"
e2e_assert cmp "$ARTIFACT_DIR/before_checksums.txt" "$ARTIFACT_DIR/after_checksums.txt"
scenario_result "repair_recovery_checksums_match" "PASS" "before and after block checksums match"

if ! command -v python3 >/dev/null 2>&1; then
    e2e_skip "python3 not found; required for repair artifact validation"
fi
FFS_REPAIR_ARTIFACT_DIR="$ARTIFACT_DIR" e2e_assert python3 -c "import json, os, pathlib; d=pathlib.Path(os.environ['FFS_REPAIR_ARTIFACT_DIR']); plan=json.loads((d/'corruption_plan.json').read_text()); pct=int(plan['corruption_percent']); blocks=plan['corrupted_blocks']; total=int(plan['total_corrupted_blocks']); assert 1 <= pct <= 5, pct; assert total == len(blocks) and total > 0, total; assert len(set(blocks)) == len(blocks), 'duplicate corrupted blocks'; before=(d/'before_checksums.txt').read_text().strip().splitlines(); after=(d/'after_checksums.txt').read_text().strip().splitlines(); assert before and after and before == after, 'checksum mismatch'; lines=[line for line in (d/'recovery_evidence.jsonl').read_text().splitlines() if line.strip()]; assert lines, 'empty evidence ledger'; events={json.loads(line).get('event_type') for line in lines}; assert 'corruption_detected' in events, events; assert 'repair_succeeded' in events, events"
scenario_result "repair_recovery_evidence_ledger_valid" "PASS" "corruption plan and evidence ledger validated"

e2e_run wc -l "$ARTIFACT_DIR/recovery_evidence.jsonl"

e2e_pass
