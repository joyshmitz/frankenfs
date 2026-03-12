#!/usr/bin/env bash
# run_gate.sh - Verification runner that executes E2E scripts and aggregates results.
#
# Runs one or more E2E scripts from the scenario catalog or by explicit path,
# collects SCENARIO_RESULT markers, and produces a gate-level JSON manifest.
#
# Usage:
#   ./scripts/e2e/run_gate.sh [OPTIONS] [SCRIPT...]
#
# Options:
#   --gate-id ID      Gate identifier for the manifest (default: "manual_gate")
#   --ci              Enable CI mode: retries failed scripts up to 2 times
#   --retries N       Override max retry count (default: 2 in CI mode, 0 otherwise)
#   --catalog         Run all scripts registered in scenario_catalog.json
#   --conformance     Check script conformance before running
#
# If no scripts are specified, runs all scripts from the catalog.
#
# Exit codes:
#   0 - All scripts passed
#   1 - One or more scripts failed

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

# Defaults
GATE_ID="manual_gate"
CI_MODE=false
MAX_RETRIES=0
USE_CATALOG=false
CHECK_CONFORMANCE=false
SCRIPTS=()

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --gate-id)
            GATE_ID="$2"
            shift 2
            ;;
        --ci)
            CI_MODE=true
            MAX_RETRIES=2
            shift
            ;;
        --retries)
            MAX_RETRIES="$2"
            shift 2
            ;;
        --catalog)
            USE_CATALOG=true
            shift
            ;;
        --conformance)
            CHECK_CONFORMANCE=true
            shift
            ;;
        -*)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
        *)
            SCRIPTS+=("$1")
            shift
            ;;
    esac
done

# If --catalog or no scripts specified, discover from catalog
if [[ "$USE_CATALOG" == "true" ]] || [[ ${#SCRIPTS[@]} -eq 0 ]]; then
    CATALOG="$REPO_ROOT/scripts/e2e/scenario_catalog.json"
    if [[ ! -f "$CATALOG" ]]; then
        echo "ERROR: scenario_catalog.json not found at $CATALOG" >&2
        exit 1
    fi
    if ! command -v jq >/dev/null 2>&1; then
        echo "ERROR: jq is required for catalog mode" >&2
        exit 1
    fi
    mapfile -t SCRIPTS < <(jq -r '.suites[].script' "$CATALOG")
fi

if [[ ${#SCRIPTS[@]} -eq 0 ]]; then
    echo "No scripts to run."
    exit 0
fi

# Gate-level output directory
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
GATE_DIR="$REPO_ROOT/artifacts/gates/${TIMESTAMP}_${GATE_ID}"
mkdir -p "$GATE_DIR"

echo "=== Verification Gate: $GATE_ID ==="
echo "Scripts: ${#SCRIPTS[@]}"
echo "CI mode: $CI_MODE"
echo "Max retries: $MAX_RETRIES"
echo "Output: $GATE_DIR"
echo ""

GATE_START=$(date +%s)
PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0
SCRIPT_RESULTS_JSON="["
FIRST_RESULT=true

# Capture git context
GIT_COMMIT=$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH=$(git -C "$REPO_ROOT" branch --show-current 2>/dev/null || echo "unknown")
if git -C "$REPO_ROOT" diff --quiet 2>/dev/null; then
    GIT_CLEAN="true"
else
    GIT_CLEAN="false"
fi

for script in "${SCRIPTS[@]}"; do
    script_path="$REPO_ROOT/$script"
    if [[ ! -f "$script_path" ]]; then
        echo "WARNING: Script not found: $script_path"
        continue
    fi

    # Optional conformance check
    if [[ "$CHECK_CONFORMANCE" == "true" ]]; then
        CONFORMANCE_OK=true
        script_content=$(<"$script_path")
        if ! echo "$script_content" | grep -q 'set -euo pipefail'; then
            echo "  CONFORMANCE: missing 'set -euo pipefail'"
            CONFORMANCE_OK=false
        fi
        if ! echo "$script_content" | grep -q 'e2e_init'; then
            echo "  CONFORMANCE: missing e2e_init call"
            CONFORMANCE_OK=false
        fi
        if ! echo "$script_content" | grep -q 'SCENARIO_RESULT\|scenario_result'; then
            echo "  CONFORMANCE: no SCENARIO_RESULT markers"
            CONFORMANCE_OK=false
        fi
        if [[ "$CONFORMANCE_OK" == "false" ]]; then
            echo "  CONFORMANCE WARNING: $script has convention violations"
        fi
    fi

    echo "--- Running: $script ---"
    TOTAL=$((TOTAL + 1))

    attempts=0
    script_passed=false
    script_output=""

    while (( attempts <= MAX_RETRIES )); do
        attempts=$((attempts + 1))
        if (( attempts > 1 )); then
            echo "  Retry attempt $attempts/$((MAX_RETRIES + 1))..."
        fi

        script_log="$GATE_DIR/$(basename "$script" .sh)_attempt${attempts}.log"
        script_exit=0
        bash "$script_path" > "$script_log" 2>&1 || script_exit=$?

        if [[ $script_exit -eq 0 ]]; then
            script_passed=true
            script_output="$script_log"
            break
        fi
        script_output="$script_log"
    done

    # Extract scenario results from the output
    scenarios_json="["
    scenarios_first=true
    if [[ -n "$script_output" && -f "$script_output" ]]; then
        while IFS= read -r line; do
            sid=$(echo "$line" | sed -n 's/.*scenario_id=\([^|]*\).*/\1/p')
            outcome=$(echo "$line" | sed -n 's/.*outcome=\([^|]*\).*/\1/p')
            [[ -z "$outcome" ]] && outcome=$(echo "$line" | sed -n 's/.*status=\([^|]*\).*/\1/p')
            detail=$(echo "$line" | sed -n 's/.*detail=\(.*\)/\1/p')
            [[ -z "$sid" || -z "$outcome" ]] && continue
            detail=$(echo "$detail" | sed 's/\\/\\\\/g; s/"/\\"/g')

            if [[ "$scenarios_first" == "true" ]]; then
                scenarios_first=false
            else
                scenarios_json+=","
            fi
            if [[ -n "$detail" ]]; then
                scenarios_json+="{\"scenario_id\":\"$sid\",\"outcome\":\"$outcome\",\"detail\":\"$detail\"}"
            else
                scenarios_json+="{\"scenario_id\":\"$sid\",\"outcome\":\"$outcome\"}"
            fi
        done < <(grep "SCENARIO_RESULT" "$script_output" 2>/dev/null || true)
    fi
    scenarios_json+="]"

    if [[ "$script_passed" == "true" ]]; then
        echo "  PASS ($attempts attempt(s))"
        PASS_COUNT=$((PASS_COUNT + 1))
        result_verdict="PASS"
    else
        echo "  FAIL after $attempts attempt(s)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        result_verdict="FAIL"
    fi

    if [[ "$FIRST_RESULT" == "true" ]]; then
        FIRST_RESULT=false
    else
        SCRIPT_RESULTS_JSON+=","
    fi
    SCRIPT_RESULTS_JSON+="{\"script\":\"$script\",\"verdict\":\"$result_verdict\",\"attempts\":$attempts,\"scenarios\":$scenarios_json}"
done

SCRIPT_RESULTS_JSON+="]"

GATE_END=$(date +%s)
GATE_DURATION=$((GATE_END - GATE_START))

# Determine gate verdict
if [[ $FAIL_COUNT -gt 0 ]]; then
    GATE_VERDICT="FAIL"
else
    GATE_VERDICT="PASS"
fi

# Write gate manifest
MANIFEST_PATH="$GATE_DIR/gate_manifest.json"
cat > "$MANIFEST_PATH" <<ENDJSON
{
  "schema_version": 1,
  "runner_contract_version": 1,
  "gate_id": "$GATE_ID",
  "run_id": "$(basename "$GATE_DIR")",
  "created_at": "$(date -Iseconds)",
  "ci_mode": $CI_MODE,
  "max_retries": $MAX_RETRIES,
  "git_context": {
    "commit": "$GIT_COMMIT",
    "branch": "$GIT_BRANCH",
    "clean": $GIT_CLEAN
  },
  "scripts_total": $TOTAL,
  "scripts_passed": $PASS_COUNT,
  "scripts_failed": $FAIL_COUNT,
  "verdict": "$GATE_VERDICT",
  "duration_secs": $GATE_DURATION,
  "script_results": $SCRIPT_RESULTS_JSON
}
ENDJSON

echo ""
echo "=== Gate Summary ==="
echo "Gate: $GATE_ID"
echo "Verdict: $GATE_VERDICT"
echo "Scripts: $PASS_COUNT/$TOTAL passed"
echo "Duration: ${GATE_DURATION}s"
echo "Manifest: $MANIFEST_PATH"

if [[ $FAIL_COUNT -gt 0 ]]; then
    exit 1
else
    exit 0
fi
