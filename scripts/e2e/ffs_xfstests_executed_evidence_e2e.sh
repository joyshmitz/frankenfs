#!/usr/bin/env bash
# ffs_xfstests_executed_evidence_e2e.sh - xfstests execution for ExecutedEvidence capture
#
# bd-xuo95.30 (G1): Run the permissioned xfstests lane for real.
#
# This script is designed to be invoked by ExecutedEvidence::run() and sets the
# required environment variables for real xfstests execution with the ACK.
#
# Exit codes:
#   0 - xfstests completed successfully (all selected tests passed or are allowlisted)
#   1 - xfstests detected failures
#   2 - prerequisite check failed (xfstests not available)
#
# The script intentionally does NOT source lib.sh to keep stdout/stderr clean
# for ExecutedEvidence hash capture. Logging goes to artifacts, not console.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

XFSTESTS_DIR="${XFSTESTS_DIR:-$PROJECT_ROOT/third_party/xfstests-dev}"
ARTIFACT_DIR="${ARTIFACT_DIR:-$PROJECT_ROOT/artifacts/e2e/xfstests_evidence_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$ARTIFACT_DIR"

check_xfstests_available() {
    if [[ ! -x "$XFSTESTS_DIR/check" ]]; then
        echo "SKIP: xfstests not available at $XFSTESTS_DIR/check" >&2
        echo '{"outcome":"skipped","reason":"xfstests_not_available","xfstests_dir":"'"$XFSTESTS_DIR"'"}' > "$ARTIFACT_DIR/evidence_outcome.json"
        exit 2
    fi
}

check_xfstests_available

export XFSTESTS_MODE="run"
export XFSTESTS_DRY_RUN="0"
export XFSTESTS_REAL_RUN_ACK="xfstests-may-mutate-test-and-scratch-devices"
export XFSTESTS_STRICT="${XFSTESTS_STRICT:-0}"
export XFSTESTS_FILTER="${XFSTESTS_FILTER:-all}"

echo "=== xfstests ExecutedEvidence Run ===" >&2
echo "Time: $(date -Iseconds)" >&2
echo "XFSTESTS_DIR: $XFSTESTS_DIR" >&2
echo "XFSTESTS_REAL_RUN_ACK: $XFSTESTS_REAL_RUN_ACK" >&2
echo "ARTIFACT_DIR: $ARTIFACT_DIR" >&2
echo "" >&2

XFSTESTS_RC=0
"$SCRIPT_DIR/ffs_xfstests_e2e.sh" 2>&1 | tee "$ARTIFACT_DIR/xfstests_run.log" || XFSTESTS_RC=$?

echo "" >&2
echo "=== xfstests completed with exit code $XFSTESTS_RC ===" >&2
echo "Artifacts: $ARTIFACT_DIR" >&2

if [[ $XFSTESTS_RC -eq 0 ]]; then
    echo '{"outcome":"success","exit_code":0,"artifact_dir":"'"$ARTIFACT_DIR"'"}' > "$ARTIFACT_DIR/evidence_outcome.json"
else
    echo '{"outcome":"failed","exit_code":'"$XFSTESTS_RC"',"artifact_dir":"'"$ARTIFACT_DIR"'"}' > "$ARTIFACT_DIR/evidence_outcome.json"
fi

exit $XFSTESTS_RC
