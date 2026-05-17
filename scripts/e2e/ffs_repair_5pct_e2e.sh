#!/usr/bin/env bash
# ffs_repair_5pct_e2e.sh - Deterministic 5% corruption auto-repair E2E
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_repair_5pct}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-300}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-2}"
RCH_CAPTURE_VISIBILITY="${FFS_REPAIR_5PCT_RCH_VISIBILITY:-summary}"
SELF_CHECK="${FFS_REPAIR_5PCT_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_REPAIR_5PCT_SKIP_SELF_CHECK:-0}"

for rch_env_var in CARGO_TARGET_DIR FFS_REPAIR_E2E_ARTIFACT_DIR FFS_REPAIR_E2E_ARTIFACT_STDOUT; do
    case ",${RCH_ENV_ALLOWLIST:-}," in
        *",${rch_env_var},"*) ;;
        *) export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}${rch_env_var}" ;;
    esac
done

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

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
    local status=0
    local pid
    local deadline
    local remote_exit=""
    local required_artifact="${RCH_REQUIRED_ARTIFACT:-}"
    local required_artifact_deadline=0
    local wait_status
    local had_errexit=0

    case $- in
        *e*) had_errexit=1 ;;
    esac

    : >"$output_path"
    set +e
    RCH_LOG_LEVEL="${RCH_LOG_LEVEL:-info}" \
        RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" \
        "${RCH_BIN:-rch}" exec -- "$@" >"$output_path" 2>&1 &
    pid=$!
    if [[ "$had_errexit" -eq 1 ]]; then
        set -e
    fi

    deadline=$((SECONDS + RCH_COMMAND_TIMEOUT_SECS))
    while kill -0 "$pid" >/dev/null 2>&1; do
        remote_exit="$(sed -n 's/.*Remote command finished: exit=\([0-9][0-9]*\).*/\1/p' "$output_path" | tail -n 1)"
        if [[ -n "$remote_exit" && -n "$required_artifact" && -e "$required_artifact" ]]; then
            e2e_log "RCH_REQUIRED_ARTIFACT_READY|artifact=${required_artifact}|output=${output_path}"
            sleep "$RCH_ARTIFACT_RETRIEVAL_GRACE_SECS"
            if kill -0 "$pid" >/dev/null 2>&1; then
                e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REQUIRED_ARTIFACT|exit=${remote_exit}|output=${output_path}|command=$*"
                kill -TERM "$pid" >/dev/null 2>&1 || true
                e2e_rch_cancel_matching_queue_entry "$@"
            fi
            break
        fi
        if [[ -n "$remote_exit" && -n "$required_artifact" && "$required_artifact_deadline" -eq 0 ]]; then
            required_artifact_deadline=$((SECONDS + RCH_ARTIFACT_RETRIEVAL_GRACE_SECS))
        fi
        if [[ -n "$remote_exit" && -n "$required_artifact" && "$required_artifact_deadline" -gt 0 ]] \
            && ((SECONDS >= required_artifact_deadline)); then
            e2e_log "RCH_REQUIRED_ARTIFACT_MISSING|artifact=${required_artifact}|output=${output_path}|command=$*"
            kill -TERM "$pid" >/dev/null 2>&1 || true
            e2e_rch_cancel_matching_queue_entry "$@"
            status=99
            break
        fi
        if [[ -n "$remote_exit" && -z "$required_artifact" ]]; then
            sleep "$RCH_ARTIFACT_RETRIEVAL_GRACE_SECS"
            if kill -0 "$pid" >/dev/null 2>&1; then
                e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|exit=${remote_exit}|output=${output_path}|command=$*"
                kill -TERM "$pid" >/dev/null 2>&1 || true
                e2e_rch_cancel_matching_queue_entry "$@"
            fi
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|output=${output_path}|command=$*"
            kill -TERM "$pid" >/dev/null 2>&1 || true
            e2e_rch_cancel_matching_queue_entry "$@"
            status=124
            break
        fi
        sleep 2
    done

    set +e
    wait "$pid" >/dev/null 2>&1
    wait_status=$?
    if [[ "$had_errexit" -eq 1 ]]; then
        set -e
    fi
    if [[ $status -eq 0 && -n "$remote_exit" ]]; then
        status="$remote_exit"
    elif [[ $status -eq 0 ]]; then
        status="$wait_status"
    fi

    if grep -Fq "[RCH] local" "$output_path" || grep -Fq "exec called with non-compilation command" "$output_path"; then
        e2e_log "RCH_LOCAL_FALLBACK_REJECTED|output=${output_path}|command=$*"
        printf 'RCH_LOCAL_FALLBACK_REJECTED|output=%s\n' "$output_path" >>"$output_path"
        return 99
    fi
    if [[ $status -eq 0 ]]; then
        if ! grep -Fq "[RCH] remote" "$output_path" && ! grep -Fq "Remote command finished: exit=0" "$output_path"; then
            e2e_log "RCH_REMOTE_EVIDENCE_MISSING|output=${output_path}|command=$*"
            printf 'RCH_REMOTE_EVIDENCE_MISSING|output=%s\n' "$output_path" >>"$output_path"
            return 99
        fi
        return 0
    fi
    if [[ $status -eq 124 ]] && grep -q "Remote command finished: exit=0" "$output_path"; then
        e2e_log "RCH_ARTIFACT_RETRIEVAL_STOPPED_AFTER_REMOTE_EXIT|output=${output_path}|command=$*"
        return 0
    fi
    return "$status"
}

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_REPAIR_5PCT_FIXTURE_CASE:-complete}"

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
        echo "unknown repair 5pct fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

case "$command_text" in
    *"cargo test -p ffs-repair e2e_survive_five_percent_random_block_corruption_with_daemon -- --nocapture"*)
        printf '%s\n' \
            "test e2e_survive_five_percent_random_block_corruption_with_daemon ... ok" \
            'FFS_REPAIR_E2E_ARTIFACT|name=before_checksums.txt|json="sha256-a  file-a\nsha256-b  file-b\n"' \
            'FFS_REPAIR_E2E_ARTIFACT|name=after_checksums.txt|json="sha256-a  file-a\nsha256-b  file-b\n"' \
            'FFS_REPAIR_E2E_ARTIFACT|name=corruption_plan.json|json="{\"corruption_percent\":5,\"total_corrupted_blocks\":3}\n"' \
            'FFS_REPAIR_E2E_ARTIFACT|name=recovery_evidence.jsonl|json="{\"event\":\"repair_complete\",\"repaired_blocks\":3}\n"'
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
    local child_log="$E2E_LOG_DIR/repair_5pct_fixture_${fixture_case}.log"

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_REPAIR_5PCT_SELF_CHECK=0 \
        FFS_REPAIR_5PCT_SKIP_SELF_CHECK=1 \
        FFS_REPAIR_5PCT_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=8 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_repair_5pct_e2e.sh" >"$child_log" 2>&1
    local child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic repair 5pct wrapper self-check"
    local stub_path child_info child_status child_log result_path result_dir artifact_dir test_log
    stub_path="$E2E_LOG_DIR/rch-repair-5pct-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    result_dir="$(dirname "$result_path")"
    artifact_dir="$result_dir/repair_5pct"
    test_log="$result_dir/repair_5pct_cargo_test.log"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && [[ -f "$test_log" ]] \
        && have_repair_artifacts "$artifact_dir" \
        && cmp "$artifact_dir/before_checksums.txt" "$artifact_dir/after_checksums.txt" >/dev/null \
        && jq -e '
            .verdict == "PASS"
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "repair_5pct_remote_cargo_test" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "repair_5pct_artifacts_present" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "repair_5pct_checksum_equality" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "repair_5pct_corruption_plan" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "repair_5pct_recovery_evidence" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null \
        && grep -q "e2e_survive_five_percent_random_block_corruption_with_daemon" "$test_log" \
        && grep -q "repair_5pct_artifacts_reconstructed_from_rch_stdout" "$child_log"; then
        scenario_result "repair_5pct_fixture_complete_self_check" "PASS" "result=${result_path} artifact_dir=${artifact_dir}"
    else
        scenario_result "repair_5pct_fixture_complete_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Repair 5pct complete fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null; then
        scenario_result "repair_5pct_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "repair_5pct_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Repair 5pct local fallback fixture self-check failed"
    fi

    child_info="$(run_fixture_child "$stub_path" "missing_remote_evidence")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL"' "$result_path" >/dev/null \
        && grep -q "RCH_REMOTE_EVIDENCE_MISSING" "$child_log"; then
        scenario_result "repair_5pct_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "repair_5pct_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        e2e_fail "Repair 5pct missing remote evidence fixture self-check failed"
    fi
}

have_repair_artifacts() {
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

    python3 - "$log_path" "$artifact_dir" <<'PY'
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

e2e_init "ffs_repair_5pct_e2e"
e2e_print_env

if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

e2e_step "Run 5% corruption auto-repair scenario"
ARTIFACT_DIR="$E2E_LOG_DIR/repair_5pct"
RCH_ARTIFACT_DIR="$REPO_ROOT/artifacts/rch_output/$(basename "$E2E_LOG_DIR")/repair_5pct"
mkdir -p "$ARTIFACT_DIR"
mkdir -p "$RCH_ARTIFACT_DIR"
TEST_LOG="$E2E_LOG_DIR/repair_5pct_cargo_test.log"

export FFS_REPAIR_E2E_ARTIFACT_DIR="$RCH_ARTIFACT_DIR"
export FFS_REPAIR_E2E_ARTIFACT_STDOUT=1

if run_rch_capture "$TEST_LOG" cargo test -p ffs-repair e2e_survive_five_percent_random_block_corruption_with_daemon -- --nocapture; then
    scenario_result "repair_5pct_remote_cargo_test" "PASS" "focused repair corruption test passed via RCH"
else
    cat "$TEST_LOG"
    scenario_result "repair_5pct_remote_cargo_test" "FAIL" "focused repair corruption test failed"
fi

if have_repair_artifacts "$RCH_ARTIFACT_DIR"; then
    ARTIFACT_DIR="$RCH_ARTIFACT_DIR"
elif extract_repair_artifacts_from_rch_log "$TEST_LOG" "$ARTIFACT_DIR"; then
    e2e_log "repair_5pct_artifacts_reconstructed_from_rch_stdout=$ARTIFACT_DIR"
fi

e2e_step "Validate generated artifacts"
if have_repair_artifacts "$ARTIFACT_DIR"; then
    scenario_result "repair_5pct_artifacts_present" "PASS" "expected repair artifacts present"
else
    scenario_result "repair_5pct_artifacts_present" "FAIL" "missing one or more expected repair artifacts"
fi

# End-to-end guarantee: recovered content must exactly match baseline.
if cmp "$ARTIFACT_DIR/before_checksums.txt" "$ARTIFACT_DIR/after_checksums.txt"; then
    scenario_result "repair_5pct_checksum_equality" "PASS" "recovered content checksums match baseline"
else
    scenario_result "repair_5pct_checksum_equality" "FAIL" "recovered content checksums differ"
fi

if command -v python3 >/dev/null 2>&1; then
    if python3 -c "import json, pathlib; p = pathlib.Path('$ARTIFACT_DIR/corruption_plan.json'); d = json.loads(p.read_text()); assert d['corruption_percent'] == 5; assert d['total_corrupted_blocks'] > 0"; then
        scenario_result "repair_5pct_corruption_plan" "PASS" "corruption plan records nonzero 5 percent corruption"
    else
        scenario_result "repair_5pct_corruption_plan" "FAIL" "corruption plan contract failed"
    fi
fi

if evidence_lines="$(wc -l <"$ARTIFACT_DIR/recovery_evidence.jsonl")" && [[ "$evidence_lines" -gt 0 ]]; then
    e2e_log "repair_5pct_recovery_evidence_lines=${evidence_lines}"
    scenario_result "repair_5pct_recovery_evidence" "PASS" "recovery evidence JSONL is non-empty"
else
    scenario_result "repair_5pct_recovery_evidence" "FAIL" "recovery evidence JSONL is empty or unreadable"
fi

if [[ "$FAIL_COUNT" -eq 0 ]]; then
    e2e_pass
else
    e2e_fail "repair 5pct scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
