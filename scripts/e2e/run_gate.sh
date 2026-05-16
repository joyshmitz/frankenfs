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
GATE_ROOT="$REPO_ROOT/artifacts/gates"
mkdir -p "$GATE_ROOT"
GATE_DIR=$(mktemp -d "$GATE_ROOT/${TIMESTAMP}_${GATE_ID}_XXXXXX")

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

gate_json_escape() {
    local value="$1"

    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\t'/\\t}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\n'/\\n}"

    printf '%s\n' "$value"
}

gate_marker_field_count() {
    local haystack="$1"
    local needle="$2"
    local count=0

    while [[ "$haystack" == *"$needle"* ]]; do
        haystack="${haystack#*"$needle"}"
        count=$((count + 1))
    done

    printf '%s\n' "$count"
}

gate_scenario_id_is_valid() {
    local value="$1"

    [[ "$value" =~ ^[a-z][a-z0-9]*(_[a-z0-9]+){2,}$ ]]
}

gate_outcome_is_valid() {
    local value="$1"

    [[ "$value" == "PASS" || "$value" == "FAIL" ]]
}

check_direct_cargo_conformance() {
    local script_path="$1"
    awk '
        function trim(value) {
            sub(/^[[:space:]]+/, "", value)
            sub(/[[:space:]]+$/, "", value)
            return value
        }

        function allowed_rch_line(line) {
            return line ~ /(^|[[:space:]])(rch|"[$][{]?RCH_BIN[^[:space:]]*"?|[$]RCH_BIN)[[:space:]]+exec[[:space:]]+--[[:space:]]+cargo[[:space:]]/ \
                || line ~ /run_rch_(capture|stdout_capture|cargo)[^#]*[[:space:]]cargo[[:space:]]+(run|test|check|clippy|bench|build)([[:space:]]|$)/ \
                || line ~ /run_remote_cargo[[:space:]]+(run|test|check|clippy|bench|build)([[:space:]]|$)/
        }

        function direct_cargo_line(line) {
            return line ~ /^cargo[[:space:]]+(run|test|check|clippy|bench|build)([[:space:]]|$)/ \
                || line ~ /^if[[:space:]]+!?[[:space:]]*cargo[[:space:]]+(run|test|check|clippy|bench|build)([[:space:]]|$)/ \
                || line ~ /^e2e_assert[[:space:]]+cargo[[:space:]]+(run|test|check|clippy|bench|build)([[:space:]]|$)/ \
                || line ~ /^([[:alnum:]_]+|local[[:space:]]+[[:alnum:]_]+)=\([^)]*cargo[[:space:]]+(run|test|check|clippy|bench|build)([[:space:]]|$)/ \
                || line ~ /(^|[;&|])[[:space:]]*cargo[[:space:]]+(run|test|check|clippy|bench|build)([[:space:]]|$)/
        }

        /(^|[[:space:]])(rch|"[$][{]?RCH_BIN[^[:space:]]*"?|[$]RCH_BIN)[[:space:]]+exec[[:space:]]+--/ || /run_rch_/ {
            rch_command = 1
        }

        /bash[[:space:]]+-lc[[:space:]]+'\''/ && (rch_command || prior ~ /rch|run_rch_/ || $0 ~ /rch|run_rch_/) {
            remote_block = 1
            rch_command = 0
        }

        {
            line = trim($0)
            if (remote_block) {
                if (line ~ /^'\''([[:space:]]|_|\\|$)/) {
                    remote_block = 0
                }
                prior = $0
                next
            }
            if (line == "" || line ~ /^#/) {
                prior = $0
                next
            }
            if (line ~ /rch-local-ok/ || allowed_rch_line(line)) {
                prior = $0
                next
            }
            if (direct_cargo_line(line)) {
                printf "%s:%d: direct cargo invocation must use rch exec or an approved RCH helper: %s\n", FILENAME, FNR, line
                failed = 1
            }
            if (line !~ /\\$/ && line !~ /(^|[[:space:]])(rch|"[$][{]?RCH_BIN[^[:space:]]*"?|[$]RCH_BIN)[[:space:]]+exec[[:space:]]+--/ && line !~ /run_rch_/) {
                rch_command = 0
            }
            prior = $0
        }

        END {
            exit failed ? 1 : 0
        }
    ' "$script_path"
}

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
        if ! grep -q 'set -euo pipefail' "$script_path"; then
            echo "  CONFORMANCE: missing 'set -euo pipefail'"
            CONFORMANCE_OK=false
        fi
        if ! grep -q 'e2e_init' "$script_path"; then
            echo "  CONFORMANCE: missing e2e_init call"
            CONFORMANCE_OK=false
        fi
        if ! grep -q 'SCENARIO_RESULT\|scenario_result' "$script_path"; then
            echo "  CONFORMANCE: no SCENARIO_RESULT markers"
            CONFORMANCE_OK=false
        fi
        if ! cargo_conformance_output="$(check_direct_cargo_conformance "$script_path")"; then
            echo "$cargo_conformance_output" | sed 's/^/  CONFORMANCE: /'
            CONFORMANCE_OK=false
        fi
        if [[ "$CONFORMANCE_OK" == "false" ]]; then
            echo "  CONFORMANCE FAIL: $script has convention violations"
            exit 1
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
            sid_count=$(gate_marker_field_count "$line" "|scenario_id=")
            outcome_count=$(gate_marker_field_count "$line" "|outcome=")
            detail_count=$(gate_marker_field_count "$line" "|detail=")
            sid=$(echo "$line" | sed -n 's/.*scenario_id=\([^|]*\).*/\1/p')
            outcome=$(echo "$line" | sed -n 's/.*outcome=\([^|]*\).*/\1/p')
            detail=$(echo "$line" | sed -n 's/.*detail=\(.*\)/\1/p')
            [[ -z "$sid" || -z "$outcome" ]] && continue
            [[ "$sid_count" -eq 1 ]] || continue
            [[ "$outcome_count" -eq 1 ]] || continue
            [[ "$detail_count" -le 1 ]] || continue
            gate_scenario_id_is_valid "$sid" || continue
            gate_outcome_is_valid "$outcome" || continue

            sid=$(gate_json_escape "$sid")
            outcome=$(gate_json_escape "$outcome")
            detail=$(gate_json_escape "$detail")

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
        done < <(grep "^SCENARIO_RESULT|" "$script_output" 2>/dev/null || true)
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
    script_json=$(gate_json_escape "$script")
    result_verdict_json=$(gate_json_escape "$result_verdict")
    SCRIPT_RESULTS_JSON+="{\"script\":\"$script_json\",\"verdict\":\"$result_verdict_json\",\"attempts\":$attempts,\"scenarios\":$scenarios_json}"
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
