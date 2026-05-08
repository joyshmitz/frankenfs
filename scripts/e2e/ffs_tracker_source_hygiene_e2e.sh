#!/usr/bin/env bash
# ffs_tracker_source_hygiene_e2e.sh - non-mutating tracker source hygiene report.
#
# This suite reads the Beads JSONL store, classifies FrankenFS-local issue IDs
# separately from foreign-looking rows, and writes an artifact for agent triage.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

scenario_result() {
    local scenario_id="$1"
    local outcome="$2"
    local detail="$3"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}|detail=${detail}"
    if [[ "$outcome" == "PASS" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    TOTAL=$((TOTAL + 1))
}

e2e_init "ffs_tracker_source_hygiene"

ISSUES_JSONL="${TRACKER_SOURCE_HYGIENE_ISSUES:-$REPO_ROOT/.beads/issues.jsonl}"
REPORT_JSON="${E2E_LOG_DIR}/tracker_source_hygiene_report.json"
STRICT_MODE=0
STRICT_JSON=false

case "${TRACKER_SOURCE_HYGIENE_STRICT:-0}" in
    1|true|TRUE|yes|YES)
        STRICT_MODE=1
        STRICT_JSON=true
        ;;
esac

e2e_step "Preflight"
if ! command -v jq >/dev/null 2>&1; then
    scenario_result "tracker_source_hygiene_jsonl_parses" "FAIL" "jq not found"
    e2e_fail "jq is required for tracker source hygiene reporting"
fi
if [[ ! -f "$ISSUES_JSONL" ]]; then
    scenario_result "tracker_source_hygiene_jsonl_parses" "FAIL" "issues JSONL missing: $ISSUES_JSONL"
    e2e_fail "issues JSONL missing: $ISSUES_JSONL"
fi

e2e_step "Parse tracker JSONL and emit report"
if jq -s \
    --arg run_id "$(basename "$E2E_LOG_DIR")" \
    --arg issues_path "$ISSUES_JSONL" \
    --argjson strict "$STRICT_JSON" \
    '
    . as $issues
    | def issue_status($id):
        ([$issues[] | select(.id == $id) | .status][0] // "missing");
    def local_issue:
        ((.id // "") | test("^(bd|frankenfs)-"));
    def foreign_issue:
        (local_issue | not);
    def open_issue:
        ((.status // "open") == "open");
    def issue_prefix:
        ((.id // "") | capture("^(?<prefix>[^-]+(?:-[^-]+)?)").prefix // "unknown");
    def blocking_dependencies:
        (.dependencies // [])
        | map(select((.type // "") == "blocks"))
        | map(.depends_on_id as $dep_id | {id: $dep_id, status: issue_status($dep_id)})
        | map(select(.status != "closed"));
    def ready_issue:
        local_issue
        and open_issue
        and ((.issue_type // "") != "epic")
        and ((blocking_dependencies | length) == 0);
    def issue_sample:
        {
            id: (.id // ""),
            title: (.title // ""),
            status: (.status // "open"),
            priority: (.priority // null),
            issue_type: (.issue_type // null),
            source_repo: (.source_repo // null)
        };
    def issue_work_row:
        issue_sample + {
            assignee: (.assignee // .owner // null),
            blocked_by: blocking_dependencies
        };
    def foreign_open_count:
        ([.[] | select(foreign_issue and open_issue)] | length);
    {
        schema_version: 1,
        run_id: $run_id,
        created_at: (now | strftime("%Y-%m-%dT%H:%M:%SZ")),
        issues_path: $issues_path,
        strict: $strict,
        status: (if ($strict and (foreign_open_count > 0)) then "fail" else "pass" end),
        mutation_policy: "report-only; this command never deletes, rewrites, closes, or edits tracker rows",
        classifier: {
            local_id_regex: "^(bd|frankenfs)-",
            local_rule: "FrankenFS-local rows use bd-* or frankenfs-* issue IDs",
            foreign_rule: "Rows with other issue ID prefixes are reported as foreign-looking"
        },
        total_rows: length,
        local_total: ([.[] | select(local_issue)] | length),
        foreign_total: ([.[] | select(foreign_issue)] | length),
        open_total: ([.[] | select(open_issue)] | length),
        local_open: ([.[] | select(local_issue and open_issue)] | length),
        foreign_open: foreign_open_count,
        excluded_foreign_open_count: foreign_open_count,
        excluded_foreign_by_prefix: (
            [.[] | select(foreign_issue and open_issue) | issue_prefix]
            | group_by(.)
            | map({prefix: .[0], count: length})
            | sort_by(.prefix)
        ),
        local_open_ids: ([.[] | select(local_issue and open_issue) | .id] | sort),
        local_open_rows: ([.[] | select(local_issue and open_issue) | issue_work_row] | sort_by(.priority, .id)),
        source_aware_ready_rows: ([.[] | select(ready_issue) | issue_work_row] | sort_by(.priority, .id)),
        foreign_open_samples: ([.[] | select(foreign_issue and open_issue) | issue_sample] | sort_by(.id) | .[0:20]),
        reproduction_commands: [
            "./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh",
            "jq -s '\''[.[] | select(((.id // \"\") | test(\"^(bd|frankenfs)-\") | not) and ((.status // \"open\") == \"open\")) | {id,title,status,priority,source_repo}]'\'' .beads/issues.jsonl",
            "jq -s '\''[.[] | select(((.id // \"\") | test(\"^(bd|frankenfs)-\")) and ((.status // \"open\") == \"open\")) | {id,title,status,priority,issue_type,assignee,owner}] | sort_by(.priority, .id)'\'' .beads/issues.jsonl",
            "TRACKER_SOURCE_HYGIENE_STRICT=1 ./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh"
        ]
    }
    ' "$ISSUES_JSONL" >"$REPORT_JSON"; then
    scenario_result "tracker_source_hygiene_jsonl_parses" "PASS" "parsed $ISSUES_JSONL"
else
    scenario_result "tracker_source_hygiene_jsonl_parses" "FAIL" "jq could not parse $ISSUES_JSONL"
    e2e_fail "tracker JSONL parse failed: $ISSUES_JSONL"
fi

if jq -e '
    .schema_version == 1
    and (.total_rows | type == "number")
    and (.open_total | type == "number")
    and (.local_open | type == "number")
    and (.foreign_open | type == "number")
    and (.excluded_foreign_open_count | type == "number")
    and (.local_open_ids | type == "array")
    and (.local_open_rows | type == "array")
    and (.source_aware_ready_rows | type == "array")
    and (.foreign_open_samples | type == "array")
    and (.excluded_foreign_by_prefix | type == "array")
    and (.reproduction_commands | type == "array")
    and (.mutation_policy | test("report-only"))
' "$REPORT_JSON" >/dev/null; then
    scenario_result "tracker_source_hygiene_report_emitted" "PASS" "report=$REPORT_JSON"
else
    scenario_result "tracker_source_hygiene_report_emitted" "FAIL" "report schema check failed"
fi

FOREIGN_OPEN_COUNT="$(jq -r '.foreign_open' "$REPORT_JSON")"
LOCAL_OPEN_COUNT="$(jq -r '.local_open' "$REPORT_JSON")"
READY_COUNT="$(jq -r '.source_aware_ready_rows | length' "$REPORT_JSON")"
if [[ "$FOREIGN_OPEN_COUNT" =~ ^[0-9]+$ && "$LOCAL_OPEN_COUNT" =~ ^[0-9]+$ ]]; then
    scenario_result "tracker_source_hygiene_foreign_rows_classified" "PASS" "local_open=${LOCAL_OPEN_COUNT} source_aware_ready=${READY_COUNT} foreign_open=${FOREIGN_OPEN_COUNT}"
else
    scenario_result "tracker_source_hygiene_foreign_rows_classified" "FAIL" "invalid open counts in $REPORT_JSON"
fi

if jq -e '
    (.local_open_rows | type == "array")
    and (.source_aware_ready_rows | type == "array")
    and all(.source_aware_ready_rows[]; (.blocked_by | length) == 0)
    and any(.reproduction_commands[]; contains("bd|frankenfs"))
' "$REPORT_JSON" >/dev/null; then
    scenario_result "tracker_source_hygiene_source_aware_wrapper" "PASS" "ready_rows=${READY_COUNT} excluded_foreign=${FOREIGN_OPEN_COUNT}"
else
    scenario_result "tracker_source_hygiene_source_aware_wrapper" "FAIL" "source-aware wrapper fields missing or inconsistent"
fi

EXPECTATION_DETAIL=""
EXPECTATION_FAILED=0

check_expected_count() {
    local field_name="$1"
    local actual="$2"
    local expected="$3"

    if [[ -z "$expected" ]]; then
        return 0
    fi

    EXPECTATION_DETAIL="${EXPECTATION_DETAIL}${field_name}=${actual}/${expected} "
    if [[ "$actual" != "$expected" ]]; then
        EXPECTATION_FAILED=1
    fi
}

EXPECTED_LOCAL_OPEN="${TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_OPEN:-}"
EXPECTED_FOREIGN_OPEN="${TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_OPEN:-}"
EXPECTED_READY="${TRACKER_SOURCE_HYGIENE_EXPECT_READY:-}"
EXPECTED_FOREIGN_SAMPLE_COUNT="${TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_SAMPLE_COUNT:-}"
FOREIGN_SAMPLE_COUNT="$(jq -r '.foreign_open_samples | length' "$REPORT_JSON")"

check_expected_count "local_open" "$LOCAL_OPEN_COUNT" "$EXPECTED_LOCAL_OPEN"
check_expected_count "foreign_open" "$FOREIGN_OPEN_COUNT" "$EXPECTED_FOREIGN_OPEN"
check_expected_count "source_aware_ready" "$READY_COUNT" "$EXPECTED_READY"
check_expected_count "foreign_sample_count" "$FOREIGN_SAMPLE_COUNT" "$EXPECTED_FOREIGN_SAMPLE_COUNT"

if [[ -n "$EXPECTATION_DETAIL" ]]; then
    if [[ "$EXPECTATION_FAILED" -eq 0 ]]; then
        scenario_result "tracker_source_hygiene_expected_fixture_counts" "PASS" "${EXPECTATION_DETAIL% }"
    else
        scenario_result "tracker_source_hygiene_expected_fixture_counts" "FAIL" "${EXPECTATION_DETAIL% }"
    fi
fi

if [[ "$STRICT_MODE" -eq 1 && "$FOREIGN_OPEN_COUNT" -gt 0 ]]; then
    scenario_result "tracker_source_hygiene_strict_mode" "FAIL" "strict mode found foreign_open=${FOREIGN_OPEN_COUNT}"
else
    if [[ "$STRICT_MODE" -eq 1 ]]; then
        scenario_result "tracker_source_hygiene_strict_mode" "PASS" "strict mode found no foreign open rows"
    else
        scenario_result "tracker_source_hygiene_strict_mode" "PASS" "default_non_destructive foreign_open=${FOREIGN_OPEN_COUNT}"
    fi
fi

if [[ "$FAIL_COUNT" -eq 0 ]]; then
    e2e_pass
else
    e2e_fail "Tracker source hygiene failed ${FAIL_COUNT}/${TOTAL} scenarios; report=$REPORT_JSON"
fi
