#!/usr/bin/env bash
# run_fuzz.sh - Run a single fuzz target for a specified duration.
#
# Usage: ./fuzz/scripts/run_fuzz.sh <target> [duration_secs]
#
# Examples:
#   ./fuzz/scripts/run_fuzz.sh fuzz_ext4_metadata 60
#   ./fuzz/scripts/run_fuzz.sh fuzz_wal_replay 300

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$FUZZ_DIR/.." && pwd)"

write_fixture_rch_stub() {
    local stub_path="$1"
    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected fixture rch invocation: $*" >&2
    exit 64
fi

case "${FFS_FUZZ_RCH_FIXTURE_CASE:-remote_success}" in
    remote_success)
        echo "[RCH] remote worker=fixture"
        echo "Remote command finished: exit=0"
        exit 0
        ;;
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)"
        exit 0
        ;;
    missing_remote_evidence)
        echo "fixture completed without remote marker"
        exit 0
        ;;
    target_failure)
        echo "[RCH] remote worker=fixture"
        echo "Remote command finished: exit=1"
        exit 1
        ;;
    *)
        echo "unknown fixture case: ${FFS_FUZZ_RCH_FIXTURE_CASE:-}" >&2
        exit 64
        ;;
esac
SH
    chmod +x "$stub_path"
}

run_fixture_case() {
    local stub_path="$1"
    local work_dir="$2"
    local fixture_case="$3"
    local expected_status="$4"
    local required_marker="$5"
    local child_log="$work_dir/${fixture_case}.child.log"
    local fuzz_log="$work_dir/${fixture_case}.fuzz.log"
    local child_status

    set +e
    FFS_FUZZ_RCH_SELF_TEST=0 \
        FFS_FUZZ_RCH_FIXTURE_CASE="$fixture_case" \
        FFS_FUZZ_LOG_PATH="$fuzz_log" \
        RCH_BIN="$stub_path" \
        "$REPO_ROOT/fuzz/scripts/run_fuzz.sh" fuzz_ext4_metadata 1 >"$child_log" 2>&1
    child_status=$?
    set -e

    if [[ "$child_status" != "$expected_status" ]]; then
        echo "FUZZ_RCH_SELF_TEST_FAIL|script=run_fuzz|case=${fixture_case}|expected=${expected_status}|actual=${child_status}|log=${child_log}"
        return 1
    fi
    if [[ -n "$required_marker" ]] && ! grep -Fq "$required_marker" "$child_log" "$fuzz_log"; then
        echo "FUZZ_RCH_SELF_TEST_FAIL|script=run_fuzz|case=${fixture_case}|missing_marker=${required_marker}|log=${child_log}|fuzz_log=${fuzz_log}"
        return 1
    fi

    echo "FUZZ_RCH_SELF_TEST_PASS|script=run_fuzz|case=${fixture_case}|status=${child_status}|log=${child_log}|fuzz_log=${fuzz_log}"
}

run_self_test() {
    local work_dir stub_path
    work_dir="$(mktemp -d -t ffs_fuzz_run_fuzz_self_test_XXXXXX)"
    stub_path="$work_dir/rch-fixture"
    write_fixture_rch_stub "$stub_path"

    run_fixture_case "$stub_path" "$work_dir" remote_success 0 "[RCH] remote"
    run_fixture_case "$stub_path" "$work_dir" local_fallback 99 "RCH_LOCAL_FALLBACK_REJECTED"
    run_fixture_case "$stub_path" "$work_dir" missing_remote_evidence 99 "RCH_REMOTE_EVIDENCE_MISSING"
    run_fixture_case "$stub_path" "$work_dir" target_failure 1 "Remote command finished: exit=1"
    echo "FUZZ_RCH_SELF_TEST_DONE|script=run_fuzz|work_dir=${work_dir}"
}

if [[ "${FFS_FUZZ_RCH_SELF_TEST:-0}" == "1" ]]; then
    cd "$REPO_ROOT"
    run_self_test
    exit 0
fi

TARGET="${1:?Usage: run_fuzz.sh <target> [duration_secs]}"
DURATION="${2:-60}"

cd "$REPO_ROOT"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_run_fuzz}"
export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"

run_remote_cargo_capture() {
    local output_path="$1"
    local status=0
    shift

    : >"$output_path"
    set +e
    RCH_LOG_LEVEL="${FFS_FUZZ_RCH_LOG_LEVEL:-error}" \
        RCH_VISIBILITY="${FFS_FUZZ_RCH_VISIBILITY:-summary}" \
        "${RCH_BIN:-rch}" exec -- cargo "$@" >"$output_path" 2>&1
    status=$?

    if grep -Fq "[RCH] local" "$output_path" || grep -Fq "exec called with non-compilation command" "$output_path"; then
        printf 'RCH_LOCAL_FALLBACK_REJECTED|output=%s|command=cargo %s\n' "$output_path" "$*" | tee -a "$output_path"
        return 99
    fi
    if [[ $status -eq 0 ]] && ! grep -Fq "[RCH] remote" "$output_path" && ! grep -Fq "Remote command finished: exit=0" "$output_path"; then
        printf 'RCH_REMOTE_EVIDENCE_MISSING|output=%s|command=cargo %s\n' "$output_path" "$*" | tee -a "$output_path"
        return 99
    fi

    return "$status"
}

echo "=== Fuzz target: $TARGET ==="
echo "Duration: ${DURATION}s"
echo "Corpus: fuzz/corpus/$TARGET"
echo "Target dir: $CARGO_TARGET_DIR"
echo ""

DICT_ARGS=()
if [[ "$TARGET" == *ext4* ]]; then
    DICT_ARGS=(-dict=fuzz/dictionaries/ext4.dict)
elif [[ "$TARGET" == *btrfs* ]]; then
    DICT_ARGS=(-dict=fuzz/dictionaries/btrfs.dict)
fi

FUZZ_LOG="${FFS_FUZZ_LOG_PATH:-fuzz/${TARGET}_$(date +%Y%m%d_%H%M%S).log}"
RUN_STATUS=0

set +e
run_remote_cargo_capture "$FUZZ_LOG" run --manifest-path fuzz/Cargo.toml --bin "$TARGET" \
    -- \
    -max_total_time="$DURATION" \
    -max_len=65536 \
    "${DICT_ARGS[@]}"
RUN_STATUS=$?
set -e

cat "$FUZZ_LOG"

echo ""
if [[ $RUN_STATUS -eq 0 ]]; then
    echo "=== Fuzz run complete ==="
else
    echo "=== Fuzz run failed: status=${RUN_STATUS}, log=${FUZZ_LOG} ==="
    exit "$RUN_STATUS"
fi
