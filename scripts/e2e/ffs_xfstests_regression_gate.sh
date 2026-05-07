#!/usr/bin/env bash
# ffs_xfstests_regression_gate.sh - CI gate that detects xfstests regressions.
#
# Compares current xfstests results against baseline and:
# - Exits 0 if no regressions (previously-passing tests still pass)
# - Exits 1 if any regression detected (pass→fail or pass→skip)
# - Reports newly-passing tests as positive progress
#
# Modes:
# - If XFSTESTS_RESULTS_JSON is set, uses existing results (post-hoc analysis)
# - Otherwise, runs ffs_xfstests_e2e.sh first to generate results
#
# Environment:
#   XFSTESTS_RESULTS_JSON   Path to existing results JSON (optional)
#   XFSTESTS_BASELINE_JSON  Path to baseline (default: scripts/e2e/xfstests_baseline.json)
#   XFSTESTS_ALLOWLIST_JSON Path to allowlist (default: scripts/e2e/xfstests_allowlist.json)
#   XFSTESTS_STRICT         If 1, any failure (not just regression) is an error

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

e2e_init "ffs_xfstests_regression_gate"
e2e_print_env

XFSTESTS_RESULTS_JSON="${XFSTESTS_RESULTS_JSON:-}"
XFSTESTS_BASELINE_JSON="${XFSTESTS_BASELINE_JSON:-$REPO_ROOT/scripts/e2e/xfstests_baseline.json}"
XFSTESTS_ALLOWLIST_JSON="${XFSTESTS_ALLOWLIST_JSON:-$REPO_ROOT/scripts/e2e/xfstests_allowlist.json}"
XFSTESTS_STRICT="${XFSTESTS_STRICT:-0}"
FFS_HARNESS_BIN="${FFS_HARNESS_BIN:-$REPO_ROOT/target/debug/ffs-harness}"

ARTIFACT_DIR="$E2E_LOG_DIR/regression_gate"
GATE_REPORT="$ARTIFACT_DIR/gate_report.json"
mkdir -p "$ARTIFACT_DIR"
XFSTESTS_CHILD_RC=0

write_empty_comparison_report() {
    local verdict="$1"
    local reason="$2"
    cat >"$GATE_REPORT" <<EOF
{
  "gate": "xfstests_regression",
  "verdict": "$verdict",
  "reason": "$reason",
  "regressions": [],
  "new_passes": [],
  "total_compared": 0
}
EOF
}

finish_missing_input() {
    local non_strict_reason="$1"
    local strict_reason="$2"

    if [[ "$XFSTESTS_STRICT" == "1" ]]; then
        write_empty_comparison_report "fail" "$strict_reason"
        e2e_fail "$strict_reason"
    fi

    write_empty_comparison_report "pass" "$non_strict_reason"
    e2e_pass
    exit 0
}

# ── Step 1: Obtain results ────────────────────────────────────────

if [[ -n "$XFSTESTS_RESULTS_JSON" ]] && [[ -f "$XFSTESTS_RESULTS_JSON" ]]; then
    e2e_step "Using existing xfstests results"
    e2e_log "Results: $XFSTESTS_RESULTS_JSON"
    RESULTS_JSON="$XFSTESTS_RESULTS_JSON"
elif [[ -n "$XFSTESTS_RESULTS_JSON" ]]; then
    e2e_step "Using existing xfstests results"
    e2e_log "Requested results file missing: $XFSTESTS_RESULTS_JSON"
    finish_missing_input \
        "requested results file missing; no results to compare" \
        "strict mode requires an existing XFSTESTS_RESULTS_JSON"
else
    e2e_step "Running xfstests to generate results"
    GENERATED_RESULTS_PATH_FILE="$ARTIFACT_DIR/generated_results_path.txt"
    # Run xfstests E2E, capturing its artifacts.
    XFSTESTS_ALLOWLIST_JSON="$XFSTESTS_ALLOWLIST_JSON" \
    XFSTESTS_BASELINE_JSON="$XFSTESTS_BASELINE_JSON" \
    XFSTESTS_RESULTS_PATH_OUT="$GENERATED_RESULTS_PATH_FILE" \
        bash "$REPO_ROOT/scripts/e2e/ffs_xfstests_e2e.sh" || XFSTESTS_CHILD_RC=$?
    e2e_log "xfstests child exit code: $XFSTESTS_CHILD_RC"

    RESULTS_JSON=""
    if [[ -f "$GENERATED_RESULTS_PATH_FILE" ]]; then
        RESULTS_JSON="$(<"$GENERATED_RESULTS_PATH_FILE")"
    fi

    if [[ -z "$RESULTS_JSON" || ! -f "$RESULTS_JSON" ]]; then
        e2e_log "No xfstests results found; handling as missing comparison input"
        finish_missing_input \
            "no results to compare" \
            "strict mode requires xfstests results to compare"
    fi
    e2e_log "Found results: $RESULTS_JSON"
fi

# ── Step 2: Compare against baseline ──────────────────────────────

e2e_step "Comparing results against baseline"

if [[ ! -f "$XFSTESTS_BASELINE_JSON" ]]; then
    e2e_log "No baseline found at $XFSTESTS_BASELINE_JSON; handling as missing comparison input"
    finish_missing_input \
        "no baseline to compare against" \
        "strict mode requires XFSTESTS_BASELINE_JSON"
fi

# Use python3 for comparison (portable, no Rust binary dependency for gate)
if ! command -v python3 >/dev/null 2>&1; then
    e2e_log "python3 required for regression gate"
    e2e_fail "python3 not available"
fi

GATE_RC=0
python3 - "$RESULTS_JSON" "$XFSTESTS_BASELINE_JSON" "$XFSTESTS_ALLOWLIST_JSON" "$GATE_REPORT" "$XFSTESTS_STRICT" "$XFSTESTS_CHILD_RC" <<'PY' || GATE_RC=$?
import json
import pathlib
import sys

results_path = pathlib.Path(sys.argv[1])
baseline_path = pathlib.Path(sys.argv[2])
allowlist_path = pathlib.Path(sys.argv[3])
report_path = pathlib.Path(sys.argv[4])
strict = int(sys.argv[5])
child_exit_code = int(sys.argv[6])

results = json.loads(results_path.read_text(encoding="utf-8"))
baseline = json.loads(baseline_path.read_text(encoding="utf-8"))

# Load allowlist. Only explicit non-pass dispositions may exempt a
# regression. Tracking statuses such as likely_pass are evidence notes, not
# permission to mask pass-to-fail drift.
REGRESSION_EXEMPT_STATUSES = {"known_fail", "wont_fix"}
allowlist_by_id = {}
if allowlist_path.exists():
    allowlist = json.loads(allowlist_path.read_text(encoding="utf-8"))
    for entry in allowlist:
        test_id = entry.get("test_id")
        if isinstance(test_id, str) and test_id:
            allowlist_by_id[test_id] = entry

# Build status maps
current_status = {}
for test in results.get("tests", []):
    current_status[test["id"]] = test["status"]

baseline_status = {}
for entry in baseline:
    baseline_status[entry["test_id"]] = entry["expected_status"]

regressions = []
new_passes = []
unchanged = []
total_compared = 0
current_failures = []

for test_id, actual in current_status.items():
    if actual == "failed":
        current_failures.append({
            "test_id": test_id,
            "baseline": baseline_status.get(test_id),
            "current": actual,
        })

for test_id, expected in baseline_status.items():
    actual = current_status.get(test_id)
    if actual is None:
        continue
    total_compared += 1

    if expected == actual:
        unchanged.append(test_id)
        continue

    # Regression: was passing, now failing or skipped
    if expected == "passed" and actual in ("failed", "skipped", "not_run"):
        allowlist_entry = allowlist_by_id.get(test_id, {})
        allowlist_status = allowlist_entry.get("status")
        is_allowlisted = allowlist_status in REGRESSION_EXEMPT_STATUSES
        regressions.append({
            "test_id": test_id,
            "baseline": expected,
            "current": actual,
            "allowlisted": is_allowlisted,
            "allowlist_status": allowlist_status,
        })
    # Improvement: was failing/skipped, now passing
    elif expected in ("failed", "skipped", "not_run") and actual == "passed":
        new_passes.append({
            "test_id": test_id,
            "baseline": expected,
            "current": actual,
        })

# Determine verdict
unexpected_regressions = [r for r in regressions if not r["allowlisted"]]
child_run_failed = child_exit_code != 0
if unexpected_regressions:
    verdict = "fail"
elif strict and (current_failures or regressions or child_run_failed):
    verdict = "fail"
else:
    verdict = "pass"

report = {
    "gate": "xfstests_regression",
    "verdict": verdict,
    "total_compared": total_compared,
    "unchanged_count": len(unchanged),
    "regression_count": len(regressions),
    "unexpected_regression_count": len(unexpected_regressions),
    "new_pass_count": len(new_passes),
    "current_failure_count": len(current_failures),
    "child_exit_code": child_exit_code,
    "child_run_failed": child_run_failed,
    "regressions": regressions,
    "new_passes": new_passes,
    "current_failures": current_failures,
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

# Print summary to stderr for human consumption
print(f"\n{'='*50}", file=sys.stderr)
print(f"XFSTESTS REGRESSION GATE: {verdict.upper()}", file=sys.stderr)
print(f"{'='*50}", file=sys.stderr)
print(f"Compared: {total_compared} tests", file=sys.stderr)
print(f"Unchanged: {len(unchanged)}", file=sys.stderr)
print(f"New passes: {len(new_passes)}", file=sys.stderr)
print(f"Regressions: {len(regressions)} ({len(unexpected_regressions)} unexpected)", file=sys.stderr)
print(f"Current failures: {len(current_failures)}", file=sys.stderr)
print(f"Child exit code: {child_exit_code}", file=sys.stderr)
if strict and child_run_failed:
    print("Strict mode treats the xfstests child failure as blocking.", file=sys.stderr)
if strict and current_failures:
    print("Strict mode treats current failed rows as blocking.", file=sys.stderr)

if new_passes:
    print(f"\n  New passes (update baseline!):", file=sys.stderr)
    for p in new_passes:
        print(f"    {p['test_id']}: {p['baseline']} -> {p['current']}", file=sys.stderr)

if regressions:
    print(f"\n  Regressions:", file=sys.stderr)
    for r in regressions:
        tag = " [allowlisted]" if r["allowlisted"] else " ** BLOCKING **"
        status = r.get("allowlist_status")
        status_note = f" allowlist_status={status}" if status else ""
        print(f"    {r['test_id']}: {r['baseline']} -> {r['current']}{tag}{status_note}", file=sys.stderr)

if current_failures:
    print(f"\n  Current failures:", file=sys.stderr)
    for failure in current_failures:
        baseline = failure.get("baseline")
        baseline_note = f" baseline={baseline}" if baseline is not None else " baseline=<missing>"
        print(f"    {failure['test_id']}: current={failure['current']}{baseline_note}", file=sys.stderr)

print(f"\nReport: {report_path}", file=sys.stderr)
sys.exit(0 if verdict == "pass" else 1)
PY

# ── Step 3: Report result ─────────────────────────────────────────

e2e_step "Gate result"
e2e_log "Gate report: $GATE_REPORT"

if [[ -f "$GATE_REPORT" ]]; then
    e2e_log "Report contents:"
    cat "$GATE_REPORT" >&2 || true
fi

if [[ $GATE_RC -ne 0 ]]; then
    e2e_fail "xfstests regression gate FAILED — see $GATE_REPORT"
fi

e2e_pass
exit 0
