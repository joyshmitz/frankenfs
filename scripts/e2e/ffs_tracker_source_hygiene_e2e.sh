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
REPORT_CANONICAL_JSON="${E2E_LOG_DIR}/tracker_source_hygiene_report.canonical.json"
REPORT_MISMATCH_GOLDEN_JSON="${E2E_LOG_DIR}/tracker_source_hygiene_report.mismatched_golden.json"
LOCAL_OPEN_JSONL="${E2E_LOG_DIR}/tracker_source_hygiene_local_open.jsonl"
SOURCE_AWARE_READY_JSONL="${E2E_LOG_DIR}/tracker_source_hygiene_source_aware_ready.jsonl"
LOCAL_NONCLAIMABLE_JSONL="${E2E_LOG_DIR}/tracker_source_hygiene_local_nonclaimable.jsonl"
LOCAL_OPEN_SHA256="${LOCAL_OPEN_JSONL}.sha256"
SOURCE_AWARE_READY_SHA256="${SOURCE_AWARE_READY_JSONL}.sha256"
LOCAL_NONCLAIMABLE_SHA256="${LOCAL_NONCLAIMABLE_JSONL}.sha256"
STRICT_MODE=0
STRICT_JSON=false
STALE_IN_PROGRESS_SECONDS="${TRACKER_SOURCE_HYGIENE_STALE_IN_PROGRESS_SECONDS:-21600}"
REPORT_NOW_EPOCH="${TRACKER_SOURCE_HYGIENE_NOW_EPOCH:-$(date -u +%s)}"
EXPECTED_GOLDEN="${TRACKER_SOURCE_HYGIENE_EXPECT_GOLDEN:-}"
EXPECT_GOLDEN_MISMATCH=0
DEFAULT_FIXTURE_SELF_CHECK=1
DEFAULT_FIXTURE_ISSUES="$REPO_ROOT/tests/fixtures/tracker_source_hygiene.jsonl"
DEFAULT_FIXTURE_GOLDEN="$REPO_ROOT/tests/fixtures/tracker_source_hygiene_report.golden.json"
FIXTURE_SELF_CHECK_LOG="${E2E_LOG_DIR}/tracker_source_hygiene_fixture_self_check.log"

case "${TRACKER_SOURCE_HYGIENE_STRICT:-0}" in
    1|true|TRUE|yes|YES)
        STRICT_MODE=1
        STRICT_JSON=true
        ;;
esac
case "${TRACKER_SOURCE_HYGIENE_EXPECT_GOLDEN_MISMATCH:-0}" in
    1|true|TRUE|yes|YES)
        EXPECT_GOLDEN_MISMATCH=1
        ;;
esac
case "${TRACKER_SOURCE_HYGIENE_DEFAULT_FIXTURE_SELF_CHECK:-1}" in
    0|false|FALSE|no|NO)
        DEFAULT_FIXTURE_SELF_CHECK=0
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
if [[ ! "$STALE_IN_PROGRESS_SECONDS" =~ ^[0-9]+$ ]]; then
    scenario_result "tracker_source_hygiene_jsonl_parses" "FAIL" "invalid stale threshold: $STALE_IN_PROGRESS_SECONDS"
    e2e_fail "TRACKER_SOURCE_HYGIENE_STALE_IN_PROGRESS_SECONDS must be a non-negative integer"
fi
if [[ ! "$REPORT_NOW_EPOCH" =~ ^[0-9]+$ ]]; then
    scenario_result "tracker_source_hygiene_jsonl_parses" "FAIL" "invalid report epoch: $REPORT_NOW_EPOCH"
    e2e_fail "TRACKER_SOURCE_HYGIENE_NOW_EPOCH must be a non-negative integer"
fi
if [[ -n "$EXPECTED_GOLDEN" && ! -f "$EXPECTED_GOLDEN" ]]; then
    scenario_result "tracker_source_hygiene_jsonl_parses" "FAIL" "golden missing: $EXPECTED_GOLDEN"
    e2e_fail "TRACKER_SOURCE_HYGIENE_EXPECT_GOLDEN does not exist: $EXPECTED_GOLDEN"
fi
if [[ "$EXPECT_GOLDEN_MISMATCH" -eq 1 && -z "$EXPECTED_GOLDEN" ]]; then
    scenario_result "tracker_source_hygiene_jsonl_parses" "FAIL" "golden mismatch self-test requires TRACKER_SOURCE_HYGIENE_EXPECT_GOLDEN"
    e2e_fail "TRACKER_SOURCE_HYGIENE_EXPECT_GOLDEN_MISMATCH requires TRACKER_SOURCE_HYGIENE_EXPECT_GOLDEN"
fi

e2e_step "Parse tracker JSONL and emit report"
if jq -s \
    --arg run_id "$(basename "$E2E_LOG_DIR")" \
    --arg issues_path "$ISSUES_JSONL" \
    --arg local_open_jsonl "$LOCAL_OPEN_JSONL" \
    --arg source_aware_ready_jsonl "$SOURCE_AWARE_READY_JSONL" \
    --arg local_nonclaimable_jsonl "$LOCAL_NONCLAIMABLE_JSONL" \
    --arg local_open_sha256 "$LOCAL_OPEN_SHA256" \
    --arg source_aware_ready_sha256 "$SOURCE_AWARE_READY_SHA256" \
    --arg local_nonclaimable_sha256 "$LOCAL_NONCLAIMABLE_SHA256" \
    --arg xfstests_ack "${XFSTESTS_REAL_RUN_ACK:-}" \
    --arg swarm_enable "${FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD:-}" \
    --arg swarm_ack "${FFS_SWARM_WORKLOAD_REAL_RUN_ACK:-}" \
    --argjson strict "$STRICT_JSON" \
    --argjson stale_in_progress_seconds "$STALE_IN_PROGRESS_SECONDS" \
    --argjson report_now_epoch "$REPORT_NOW_EPOCH" \
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
    def in_progress_issue:
        ((.status // "open") == "in_progress");
    def normalized_iso8601:
        if type == "string" then
            sub("\\.[0-9]+Z$"; "Z")
        else
            null
        end;
    def activity_epoch:
        ((.updated_at // .created_at // null) | normalized_iso8601 | fromdateiso8601?);
    def issue_prefix:
        ((.id // "") | capture("^(?<prefix>[^-]+(?:-[^-]+)?)").prefix // "unknown");
    def owner_hint:
        ([(.id // ""), (.title // ""), (.description // "")] | join(" ")) as $text
        | if (($text | test("franken_networkx|networkx"; "i")) or ((.id // "") | startswith("franken_networkx-"))) then
            "franken_networkx"
        elif (($text | test("frankenscipy"; "i")) or ((.id // "") | startswith("frankenscipy-"))) then
            "frankenscipy"
        elif (($text | test("frankenfs"; "i")) or ((.id // "") | test("^(bd|frankenfs)-"))) then
            "frankenfs"
        else
            "unknown"
        end;
    def issue_text:
        [
            (.id // ""),
            (.title // ""),
            (.description // ""),
            (.notes // ""),
            ((.labels // []) | join(" "))
        ] | join(" ");
    def blocking_dependencies:
        (.dependencies // [])
        | map(select((.type // "") == "blocks"))
        | map(.depends_on_id as $dep_id | {id: $dep_id, status: issue_status($dep_id)})
        | map(select(.status != "closed"));
    def xfstests_ack_present:
        $xfstests_ack == "xfstests-may-mutate-test-and-scratch-devices";
    def swarm_ack_present:
        ($swarm_enable == "1")
        and ($swarm_ack == "swarm-workload-may-use-permissioned-large-host");
    def permission_gate:
        issue_text as $text
        | if (($text | test("XFSTESTS_REAL_RUN_ACK|xfstests-may-mutate-test-and-scratch-devices|real xfstests run|execute[^.]*xfstests baseline|run[^.]*xfstests baseline"; "i")) and (xfstests_ack_present | not)) then
            {
                gate_kind: "xfstests_real_run",
                required_env: "XFSTESTS_REAL_RUN_ACK",
                required_value: "xfstests-may-mutate-test-and-scratch-devices",
                present: false
            }
        elif (($text | test("FFS_SWARM_WORKLOAD_REAL_RUN_ACK|swarm-workload-may-use-permissioned-large-host|large-host|large host|permissioned.*swarm"; "i")) and (swarm_ack_present | not)) then
            {
                gate_kind: "large_host_swarm_real_run",
                required_env: "FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD,FFS_SWARM_WORKLOAD_REAL_RUN_ACK",
                required_value: "1,swarm-workload-may-use-permissioned-large-host",
                present: false
            }
        else
            null
        end;
    def ready_issue:
        local_issue
        and open_issue
        and ((.issue_type // "") != "epic")
        and ((blocking_dependencies | length) == 0)
        and ((permission_gate // null) == null);
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
    def nonclaimable_row($reason; $gate):
        issue_work_row + {
            reason: $reason,
            permission_gate: $gate
        };
    def issue_progress_row:
        activity_epoch as $activity_epoch
        | issue_work_row + {
            created_at: (.created_at // null),
            updated_at: (.updated_at // null),
            last_activity_epoch: $activity_epoch,
            age_seconds: (
                if $activity_epoch == null then
                    null
                else
                    (($report_now_epoch - $activity_epoch) | floor)
                end
            ),
            stale_after_seconds: $stale_in_progress_seconds,
            stale: (
                if $activity_epoch == null then
                    true
                else
                    (($report_now_epoch - $activity_epoch) >= $stale_in_progress_seconds)
                end
            )
        };
    def foreign_group_row:
        issue_sample + {
            prefix: issue_prefix,
            owner_hint: owner_hint
        };
    def foreign_open_count:
        ([.[] | select(foreign_issue and open_issue)] | length);
    def local_open_rows_arr:
        [.[] | select(local_issue and open_issue) | issue_work_row] | sort_by(.priority, .id);
    def source_aware_ready_rows_arr:
        [.[] | select(ready_issue) | issue_work_row] | sort_by(.priority, .id);
    def permission_gated_rows_arr:
        [.[] | select(local_issue and open_issue and ((.issue_type // "") != "epic") and ((permission_gate // null) != null)) | issue_work_row + {permission_gate: permission_gate}]
        | sort_by(.priority, .id);
    def blocked_local_rows_arr:
        [.[] | select(local_issue and open_issue and ((.issue_type // "") != "epic") and ((permission_gate // null) == null) and ((blocking_dependencies | length) > 0)) | issue_work_row]
        | sort_by(.priority, .id);
    def local_epic_rows_arr:
        [.[] | select(local_issue and open_issue and ((.issue_type // "") == "epic")) | issue_sample]
        | sort_by(.priority, .id);
    def local_nonclaimable_rows_arr:
        [.[] | select(local_issue and open_issue) |
            if ((.issue_type // "") == "epic") then
                nonclaimable_row("epic"; null)
            elif ((permission_gate // null) != null) then
                nonclaimable_row("permission_gated"; permission_gate)
            elif ((blocking_dependencies | length) > 0) then
                nonclaimable_row("blocked"; null)
            else
                empty
            end
        ]
        | sort_by(.priority, .id);
    def local_in_progress_rows_arr:
        [.[] | select(local_issue and in_progress_issue) | issue_progress_row]
        | sort_by(.priority, .id);
    def stale_in_progress_rows_arr:
        [local_in_progress_rows_arr[] | select(.stale)]
        | sort_by(.priority, .id);
    def foreign_in_progress_rows_arr:
        [.[] | select(foreign_issue and in_progress_issue) | issue_progress_row]
        | sort_by(.priority, .id);
    def foreign_stale_in_progress_rows_arr:
        [foreign_in_progress_rows_arr[] | select(.stale)]
        | sort_by(.priority, .id);
    {
        schema_version: 1,
        run_id: $run_id,
        created_at: (now | strftime("%Y-%m-%dT%H:%M:%SZ")),
        issues_path: $issues_path,
        strict: $strict,
        report_now_epoch: $report_now_epoch,
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
        foreign_in_progress: (foreign_in_progress_rows_arr | length),
        excluded_foreign_open_count: foreign_open_count,
        excluded_foreign_in_progress_count: (foreign_in_progress_rows_arr | length),
        excluded_foreign_stale_in_progress_count: (foreign_stale_in_progress_rows_arr | length),
        excluded_foreign_by_prefix: (
            [.[] | select(foreign_issue and open_issue) | issue_prefix]
            | group_by(.)
            | map({prefix: .[0], count: length})
            | sort_by(.prefix)
        ),
        foreign_group_summaries: (
            [.[] | select(foreign_issue and open_issue) | foreign_group_row]
            | sort_by(.prefix, .id)
            | group_by(.prefix)
            | map({
                prefix: .[0].prefix,
                count: length,
                owner_hints: (
                    ([.[].owner_hint] | unique) as $hints
                    | if (($hints | length) > 1 and ($hints | index("unknown"))) then
                        ($hints | map(select(. != "unknown")))
                    else
                        $hints
                    end
                ),
                sample_ids: ([.[].id] | .[0:10]),
                sample_titles: ([.[].title] | .[0:3])
            })
            | sort_by(.prefix)
        ),
        local_open_ids: ([.[] | select(local_issue and open_issue) | .id] | sort),
        local_open_rows: local_open_rows_arr,
        source_aware_ready_rows: source_aware_ready_rows_arr,
        source_aware_queue_state: (
            source_aware_ready_rows_arr as $ready_rows
            | permission_gated_rows_arr as $permission_gated
            | blocked_local_rows_arr as $blocked_rows
            | local_epic_rows_arr as $epic_rows
            | local_nonclaimable_rows_arr as $nonclaimable_rows
            | local_in_progress_rows_arr as $in_progress_rows
            | stale_in_progress_rows_arr as $stale_rows
            | foreign_in_progress_rows_arr as $foreign_in_progress_rows
            | foreign_stale_in_progress_rows_arr as $foreign_stale_rows
            | {
                schema_version: 1,
                verdict: (
                    if ($ready_rows | length) > 0 then
                        "ready"
                    elif ($stale_rows | length) > 0 then
                        "stale_in_progress"
                    elif (($permission_gated | length) > 0 and ($blocked_rows | length) > 0) then
                        "blocked_or_permission_gated"
                    elif ($permission_gated | length) > 0 then
                        "permission_gated"
                    elif ($blocked_rows | length) > 0 then
                        "blocked"
                    elif ($epic_rows | length) > 0 then
                        "epic_only"
                    elif ($foreign_stale_rows | length) > 0 then
                        "foreign_stale_in_progress"
                    else
                        "empty"
                    end
                ),
                claimable_count: ($ready_rows | length),
                local_open_count: (local_open_rows_arr | length),
                local_epic_count: ($epic_rows | length),
                blocked_local_count: ($blocked_rows | length),
                permission_gated_count: ($permission_gated | length),
                local_nonclaimable_count: ($nonclaimable_rows | length),
                local_in_progress_count: ($in_progress_rows | length),
                stale_in_progress_count: ($stale_rows | length),
                excluded_foreign_open_count: foreign_open_count,
                excluded_foreign_in_progress_count: ($foreign_in_progress_rows | length),
                excluded_foreign_stale_in_progress_count: ($foreign_stale_rows | length),
                excluded_foreign_stale_in_progress_ids: ($foreign_stale_rows | map(.id)),
                claimable_ids: ($ready_rows | map(.id)),
                local_epic_ids: ($epic_rows | map(.id)),
                blocked_local_ids: ($blocked_rows | map(.id)),
                permission_gated_ids: ($permission_gated | map(.id)),
                local_nonclaimable_ids: ($nonclaimable_rows | map(.id)),
                local_in_progress_ids: ($in_progress_rows | map(.id)),
                stale_in_progress_ids: ($stale_rows | map(.id)),
                next_safe_actions: (
                    if ($ready_rows | length) > 0 then
                        ["claim one source_aware_ready row before creating fallback work"]
                    elif ($stale_rows | length) > 0 then
                        ["inspect stale_in_progress_ids and Agent Mail before reopening stalled claims"]
                    elif ($permission_gated | length) > 0 then
                        ["request the exact permission ACK before running permissioned rows", "create or claim only non-mutating fallback work"]
                    elif ($blocked_rows | length) > 0 then
                        ["inspect blocked_local_ids and unblock prerequisites first"]
                    elif ($epic_rows | length) > 0 then
                        ["create a narrow child bead under the open epic before editing code"]
                    elif ($foreign_stale_rows | length) > 0 then
                        ["inspect excluded_foreign_stale_in_progress_ids and Agent Mail before reopening stale foreign claims", "avoid claiming foreign rows as FrankenFS work"]
                    else
                        ["run idea-wizard or a testing skill to create a new narrow bead"]
                    end
                )
            }
        ),
        local_graph_exports: {
            schema_version: 1,
            mutation_policy: "report-only; exports copy matching source rows without editing tracker state",
            local_open: {
                path: $local_open_jsonl,
                checksum_path: $local_open_sha256,
                row_count: (local_open_rows_arr | length),
                id_count: ([.[] | select(local_issue and open_issue) | .id] | unique | length),
                consumer_hint: "Use this JSONL as a local-only tracker input when br or bv output is polluted by foreign rows."
            },
            source_aware_ready: {
                path: $source_aware_ready_jsonl,
                checksum_path: $source_aware_ready_sha256,
                row_count: (source_aware_ready_rows_arr | length),
                id_count: ([.[] | select(ready_issue) | .id] | unique | length),
                consumer_hint: "Use this JSONL for claimable FrankenFS rows; it excludes epics, blocked rows, foreign rows, and permission-gated rows without the required ACK."
            },
            local_nonclaimable: {
                path: $local_nonclaimable_jsonl,
                checksum_path: $local_nonclaimable_sha256,
                row_count: (local_nonclaimable_rows_arr | length),
                id_count: (local_nonclaimable_rows_arr | map(.id) | unique | length),
                consumer_hint: "Use this JSONL to explain why local open rows are not claimable; reasons are epic, permission_gated, or blocked."
            }
        },
        permission_gated_rows: permission_gated_rows_arr,
        blocked_local_rows: blocked_local_rows_arr,
        local_nonclaimable_rows: local_nonclaimable_rows_arr,
        local_in_progress_rows: local_in_progress_rows_arr,
        stale_in_progress_rows: stale_in_progress_rows_arr,
        foreign_open_samples: ([.[] | select(foreign_issue and open_issue) | issue_sample] | sort_by(.id) | .[0:20]),
        foreign_in_progress_samples: (foreign_in_progress_rows_arr | .[0:20]),
        foreign_stale_in_progress_samples: (foreign_stale_in_progress_rows_arr | .[0:20]),
        reproduction_commands: [
            "./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh",
            "jq -s '\''[.[] | select(((.id // \"\") | test(\"^(bd|frankenfs)-\") | not) and ((.status // \"open\") == \"open\")) | {id,title,status,priority,source_repo}]'\'' .beads/issues.jsonl",
            "jq -s '\''[.[] | select(((.id // \"\") | test(\"^(bd|frankenfs)-\")) and ((.status // \"open\") == \"open\")) | {id,title,status,priority,issue_type,assignee,owner}] | sort_by(.priority, .id)'\'' .beads/issues.jsonl",
            "jq -c '\''select(((.id // \"\") | test(\"^(bd|frankenfs)-\")) and ((.status // \"open\") == \"open\"))'\'' .beads/issues.jsonl > tracker_source_hygiene_local_open.jsonl",
            "XFSTESTS_REAL_RUN_ACK=xfstests-may-mutate-test-and-scratch-devices ./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh",
            "FFS_ENABLE_PERMISSIONED_SWARM_WORKLOAD=1 FFS_SWARM_WORKLOAD_REAL_RUN_ACK=swarm-workload-may-use-permissioned-large-host ./scripts/e2e/ffs_tracker_source_hygiene_e2e.sh",
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
    and (.foreign_in_progress | type == "number")
    and (.excluded_foreign_open_count | type == "number")
    and (.excluded_foreign_in_progress_count | type == "number")
    and (.excluded_foreign_stale_in_progress_count | type == "number")
    and (.local_open_ids | type == "array")
    and (.local_open_rows | type == "array")
    and (.source_aware_ready_rows | type == "array")
    and (.source_aware_queue_state.schema_version == 1)
    and (.source_aware_queue_state.verdict as $verdict | (["ready", "stale_in_progress", "blocked_or_permission_gated", "permission_gated", "blocked", "epic_only", "foreign_stale_in_progress", "empty"] | index($verdict)) != null)
    and (.source_aware_queue_state.claimable_count == (.source_aware_ready_rows | length))
    and (.source_aware_queue_state.local_open_count == .local_open)
    and (.source_aware_queue_state.permission_gated_count == (.permission_gated_rows | length))
    and (.source_aware_queue_state.local_nonclaimable_count == (.local_nonclaimable_rows | length))
    and (.source_aware_queue_state.local_in_progress_count == (.local_in_progress_rows | length))
    and (.source_aware_queue_state.stale_in_progress_count == (.stale_in_progress_rows | length))
    and (.source_aware_queue_state.excluded_foreign_in_progress_count == .excluded_foreign_in_progress_count)
    and (.source_aware_queue_state.excluded_foreign_stale_in_progress_count == .excluded_foreign_stale_in_progress_count)
    and (.source_aware_queue_state.excluded_foreign_stale_in_progress_ids | type == "array")
    and (.source_aware_queue_state.blocked_local_ids | type == "array")
    and (.source_aware_queue_state.local_nonclaimable_ids | type == "array")
    and (.source_aware_queue_state.stale_in_progress_ids | type == "array")
    and (.source_aware_queue_state.next_safe_actions | type == "array")
    and (.local_graph_exports.schema_version == 1)
    and (.local_graph_exports.local_open.path | test("tracker_source_hygiene_local_open\\.jsonl$"))
    and (.local_graph_exports.source_aware_ready.path | test("tracker_source_hygiene_source_aware_ready\\.jsonl$"))
    and (.local_graph_exports.local_nonclaimable.path | test("tracker_source_hygiene_local_nonclaimable\\.jsonl$"))
    and (.local_graph_exports.local_open.checksum_path | test("\\.sha256$"))
    and (.local_graph_exports.source_aware_ready.checksum_path | test("\\.sha256$"))
    and (.local_graph_exports.local_nonclaimable.checksum_path | test("\\.sha256$"))
    and (.permission_gated_rows | type == "array")
    and (.local_nonclaimable_rows | type == "array")
    and (.foreign_open_samples | type == "array")
    and (.foreign_in_progress_samples | type == "array")
    and (.foreign_stale_in_progress_samples | type == "array")
    and (.excluded_foreign_by_prefix | type == "array")
    and (.foreign_group_summaries | type == "array")
    and (.reproduction_commands | type == "array")
    and (.mutation_policy | test("report-only"))
' "$REPORT_JSON" >/dev/null; then
    scenario_result "tracker_source_hygiene_report_emitted" "PASS" "report=$REPORT_JSON"
else
    scenario_result "tracker_source_hygiene_report_emitted" "FAIL" "report schema check failed"
fi

e2e_step "Emit local-only tracker graph artifacts"
if jq -c --slurpfile report "$REPORT_JSON" \
    '(.id // "") as $issue_id | select(($report[0].local_open_ids | index($issue_id)) != null)' \
    "$ISSUES_JSONL" >"$LOCAL_OPEN_JSONL" \
    && jq -c --slurpfile report "$REPORT_JSON" \
        '(.id // "") as $issue_id | ($report[0].source_aware_ready_rows | map(.id)) as $ready_ids | select(($ready_ids | index($issue_id)) != null)' \
        "$ISSUES_JSONL" >"$SOURCE_AWARE_READY_JSONL" \
    && jq -c '.local_nonclaimable_rows[]' "$REPORT_JSON" >"$LOCAL_NONCLAIMABLE_JSONL" \
    && sha256sum "$LOCAL_OPEN_JSONL" >"$LOCAL_OPEN_SHA256" \
    && sha256sum "$SOURCE_AWARE_READY_JSONL" >"$SOURCE_AWARE_READY_SHA256" \
    && sha256sum "$LOCAL_NONCLAIMABLE_JSONL" >"$LOCAL_NONCLAIMABLE_SHA256"; then
    scenario_result "tracker_source_hygiene_local_graph_exports_written" "PASS" "local_open=$LOCAL_OPEN_JSONL ready=$SOURCE_AWARE_READY_JSONL"
else
    scenario_result "tracker_source_hygiene_local_graph_exports_written" "FAIL" "failed to write local graph exports"
fi

FOREIGN_OPEN_COUNT="$(jq -r '.foreign_open' "$REPORT_JSON")"
FOREIGN_IN_PROGRESS_COUNT="$(jq -r '.foreign_in_progress' "$REPORT_JSON")"
FOREIGN_STALE_IN_PROGRESS_COUNT="$(jq -r '.excluded_foreign_stale_in_progress_count' "$REPORT_JSON")"
LOCAL_OPEN_COUNT="$(jq -r '.local_open' "$REPORT_JSON")"
READY_COUNT="$(jq -r '.source_aware_ready_rows | length' "$REPORT_JSON")"
LOCAL_NONCLAIMABLE_COUNT="$(jq -r '.local_nonclaimable_rows | length' "$REPORT_JSON")"
if [[ "$FOREIGN_OPEN_COUNT" =~ ^[0-9]+$ && "$LOCAL_OPEN_COUNT" =~ ^[0-9]+$ ]]; then
    scenario_result "tracker_source_hygiene_foreign_rows_classified" "PASS" "local_open=${LOCAL_OPEN_COUNT} source_aware_ready=${READY_COUNT} foreign_open=${FOREIGN_OPEN_COUNT}"
else
    scenario_result "tracker_source_hygiene_foreign_rows_classified" "FAIL" "invalid open counts in $REPORT_JSON"
fi
if [[ "$FOREIGN_IN_PROGRESS_COUNT" =~ ^[0-9]+$ && "$FOREIGN_STALE_IN_PROGRESS_COUNT" =~ ^[0-9]+$ ]]; then
    scenario_result "tracker_source_hygiene_foreign_in_progress_classified" "PASS" "foreign_in_progress=${FOREIGN_IN_PROGRESS_COUNT} foreign_stale_in_progress=${FOREIGN_STALE_IN_PROGRESS_COUNT}"
else
    scenario_result "tracker_source_hygiene_foreign_in_progress_classified" "FAIL" "invalid foreign in-progress counts in $REPORT_JSON"
fi

if jq -s --slurpfile report "$REPORT_JSON" '
    def local_issue:
        ((.id // "") | test("^(bd|frankenfs)-"));
    def open_issue:
        ((.status // "open") == "open");
    def sorted_ids:
        map(.id // "") | sort;
    (length == $report[0].local_graph_exports.local_open.row_count)
    and (sorted_ids == ($report[0].local_open_ids | sort))
    and all(.[]; local_issue and open_issue)
' "$LOCAL_OPEN_JSONL" >/dev/null \
    && jq -s --slurpfile report "$REPORT_JSON" '
        def local_issue:
            ((.id // "") | test("^(bd|frankenfs)-"));
        def open_issue:
            ((.status // "open") == "open");
        def sorted_ids:
            map(.id // "") | sort;
        (length == $report[0].local_graph_exports.source_aware_ready.row_count)
        and (sorted_ids == ($report[0].source_aware_ready_rows | map(.id) | sort))
        and all(.[]; local_issue and open_issue)
    ' "$SOURCE_AWARE_READY_JSONL" >/dev/null \
    && sha256sum -c "$LOCAL_OPEN_SHA256" >/dev/null \
    && sha256sum -c "$SOURCE_AWARE_READY_SHA256" >/dev/null \
    && sha256sum -c "$LOCAL_NONCLAIMABLE_SHA256" >/dev/null; then
    scenario_result "tracker_source_hygiene_local_graph_exports_valid" "PASS" "local_open=${LOCAL_OPEN_COUNT} source_aware_ready=${READY_COUNT}"
else
    scenario_result "tracker_source_hygiene_local_graph_exports_valid" "FAIL" "local graph export validation failed"
fi

if jq -s --slurpfile report "$REPORT_JSON" '
    def sorted_ids:
        map(.id // "") | sort;
    (length == $report[0].local_graph_exports.local_nonclaimable.row_count)
    and (sorted_ids == ($report[0].local_nonclaimable_rows | map(.id) | sort))
    and all(.[]; (.reason as $reason | (["epic", "permission_gated", "blocked"] | index($reason)) != null))
    and all(.[] | select(.reason == "permission_gated"); (.permission_gate.present == false))
    and all(.[] | select(.reason == "blocked"); (.blocked_by | length) > 0)
    and all(.[] | select(.reason == "epic"); ((.issue_type // "") == "epic"))
' "$LOCAL_NONCLAIMABLE_JSONL" >/dev/null; then
    scenario_result "tracker_source_hygiene_local_nonclaimable_exports_valid" "PASS" "local_nonclaimable=${LOCAL_NONCLAIMABLE_COUNT}"
else
    scenario_result "tracker_source_hygiene_local_nonclaimable_exports_valid" "FAIL" "local nonclaimable export validation failed"
fi

if jq -e '
    (.local_open_rows | type == "array")
    and (.source_aware_ready_rows | type == "array")
    and (.permission_gated_rows | type == "array")
    and (.blocked_local_rows | type == "array")
    and (.local_nonclaimable_rows | type == "array")
    and (.local_in_progress_rows | type == "array")
    and (.stale_in_progress_rows | type == "array")
    and (.foreign_in_progress_samples | type == "array")
    and (.foreign_stale_in_progress_samples | type == "array")
    and all(.source_aware_ready_rows[]; (.blocked_by | length) == 0)
    and all(.source_aware_ready_rows[]; has("permission_gate") | not)
    and all(.permission_gated_rows[]; (.permission_gate.present == false))
    and all(.blocked_local_rows[]; (.blocked_by | length) > 0)
    and all(.local_nonclaimable_rows[]; (.reason as $reason | (["epic", "permission_gated", "blocked"] | index($reason)) != null))
    and all(.local_in_progress_rows[]; .status == "in_progress")
    and all(.stale_in_progress_rows[]; .status == "in_progress" and .stale == true)
    and all(.foreign_in_progress_samples[]; .status == "in_progress")
    and all(.foreign_stale_in_progress_samples[]; .status == "in_progress" and .stale == true)
    and (.source_aware_queue_state.claimable_ids == (.source_aware_ready_rows | map(.id)))
    and (.source_aware_queue_state.permission_gated_ids == (.permission_gated_rows | map(.id)))
    and (.source_aware_queue_state.blocked_local_ids == (.blocked_local_rows | map(.id)))
    and (.source_aware_queue_state.local_nonclaimable_ids == (.local_nonclaimable_rows | map(.id)))
    and (.source_aware_queue_state.local_in_progress_ids == (.local_in_progress_rows | map(.id)))
    and (.source_aware_queue_state.stale_in_progress_ids == (.stale_in_progress_rows | map(.id)))
    and any(.reproduction_commands[]; contains("bd|frankenfs"))
' "$REPORT_JSON" >/dev/null; then
    scenario_result "tracker_source_hygiene_source_aware_wrapper" "PASS" "ready_rows=${READY_COUNT} excluded_foreign=${FOREIGN_OPEN_COUNT}"
else
    scenario_result "tracker_source_hygiene_source_aware_wrapper" "FAIL" "source-aware wrapper fields missing or inconsistent"
fi

if [[ -n "$EXPECTED_GOLDEN" ]]; then
    if jq -S '
        .run_id = "[RUN_ID]"
        | .created_at = "[TIMESTAMP]"
        | .issues_path = "[ISSUES_JSONL]"
        | .local_graph_exports.local_open.path = "[LOCAL_OPEN_JSONL]"
        | .local_graph_exports.local_open.checksum_path = "[LOCAL_OPEN_SHA256]"
        | .local_graph_exports.source_aware_ready.path = "[SOURCE_AWARE_READY_JSONL]"
        | .local_graph_exports.source_aware_ready.checksum_path = "[SOURCE_AWARE_READY_SHA256]"
        | .local_graph_exports.local_nonclaimable.path = "[LOCAL_NONCLAIMABLE_JSONL]"
        | .local_graph_exports.local_nonclaimable.checksum_path = "[LOCAL_NONCLAIMABLE_SHA256]"
    ' "$REPORT_JSON" >"$REPORT_CANONICAL_JSON" \
        && diff -u "$EXPECTED_GOLDEN" "$REPORT_CANONICAL_JSON" >"${REPORT_CANONICAL_JSON}.diff"; then
        scenario_result "tracker_source_hygiene_golden_report_matches" "PASS" "golden=$EXPECTED_GOLDEN"
    else
        scenario_result "tracker_source_hygiene_golden_report_matches" "FAIL" "golden mismatch diff=${REPORT_CANONICAL_JSON}.diff"
    fi
fi

if [[ "$EXPECT_GOLDEN_MISMATCH" -eq 1 ]]; then
    if jq '.source_aware_queue_state.verdict = "intentional-mismatch-for-fail-closed-test"' \
        "$EXPECTED_GOLDEN" >"$REPORT_MISMATCH_GOLDEN_JSON" \
        && ! diff -u "$REPORT_MISMATCH_GOLDEN_JSON" "$REPORT_CANONICAL_JSON" >"${REPORT_MISMATCH_GOLDEN_JSON}.diff"; then
        scenario_result "tracker_source_hygiene_golden_mismatch_fails_closed" "PASS" "diff=${REPORT_MISMATCH_GOLDEN_JSON}.diff"
    else
        scenario_result "tracker_source_hygiene_golden_mismatch_fails_closed" "FAIL" "mismatched golden was not rejected"
    fi
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
EXPECTED_PERMISSION_GATED="${TRACKER_SOURCE_HYGIENE_EXPECT_PERMISSION_GATED:-}"
EXPECTED_LOCAL_NONCLAIMABLE="${TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_NONCLAIMABLE:-}"
EXPECTED_IN_PROGRESS="${TRACKER_SOURCE_HYGIENE_EXPECT_IN_PROGRESS:-}"
EXPECTED_STALE_IN_PROGRESS="${TRACKER_SOURCE_HYGIENE_EXPECT_STALE_IN_PROGRESS:-}"
EXPECTED_FOREIGN_IN_PROGRESS="${TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_IN_PROGRESS:-}"
EXPECTED_FOREIGN_STALE_IN_PROGRESS="${TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_STALE_IN_PROGRESS:-}"
EXPECTED_FOREIGN_SAMPLE_COUNT="${TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_SAMPLE_COUNT:-}"
EXPECTED_FOREIGN_GROUP_COUNT="${TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_GROUP_COUNT:-}"
FOREIGN_SAMPLE_COUNT="$(jq -r '.foreign_open_samples | length' "$REPORT_JSON")"
FOREIGN_GROUP_COUNT="$(jq -r '.foreign_group_summaries | length' "$REPORT_JSON")"
PERMISSION_GATED_COUNT="$(jq -r '.permission_gated_rows | length' "$REPORT_JSON")"
IN_PROGRESS_COUNT="$(jq -r '.local_in_progress_rows | length' "$REPORT_JSON")"
STALE_IN_PROGRESS_COUNT="$(jq -r '.stale_in_progress_rows | length' "$REPORT_JSON")"

check_expected_count "local_open" "$LOCAL_OPEN_COUNT" "$EXPECTED_LOCAL_OPEN"
check_expected_count "foreign_open" "$FOREIGN_OPEN_COUNT" "$EXPECTED_FOREIGN_OPEN"
check_expected_count "source_aware_ready" "$READY_COUNT" "$EXPECTED_READY"
check_expected_count "permission_gated" "$PERMISSION_GATED_COUNT" "$EXPECTED_PERMISSION_GATED"
check_expected_count "local_nonclaimable" "$LOCAL_NONCLAIMABLE_COUNT" "$EXPECTED_LOCAL_NONCLAIMABLE"
check_expected_count "local_in_progress" "$IN_PROGRESS_COUNT" "$EXPECTED_IN_PROGRESS"
check_expected_count "stale_in_progress" "$STALE_IN_PROGRESS_COUNT" "$EXPECTED_STALE_IN_PROGRESS"
check_expected_count "foreign_in_progress" "$FOREIGN_IN_PROGRESS_COUNT" "$EXPECTED_FOREIGN_IN_PROGRESS"
check_expected_count "foreign_stale_in_progress" "$FOREIGN_STALE_IN_PROGRESS_COUNT" "$EXPECTED_FOREIGN_STALE_IN_PROGRESS"
check_expected_count "foreign_sample_count" "$FOREIGN_SAMPLE_COUNT" "$EXPECTED_FOREIGN_SAMPLE_COUNT"
check_expected_count "foreign_group_count" "$FOREIGN_GROUP_COUNT" "$EXPECTED_FOREIGN_GROUP_COUNT"

if [[ -n "$EXPECTATION_DETAIL" ]]; then
    if [[ "$EXPECTATION_FAILED" -eq 0 ]]; then
        scenario_result "tracker_source_hygiene_expected_fixture_counts" "PASS" "${EXPECTATION_DETAIL% }"
    else
        scenario_result "tracker_source_hygiene_expected_fixture_counts" "FAIL" "${EXPECTATION_DETAIL% }"
    fi
fi

if [[ "$DEFAULT_FIXTURE_SELF_CHECK" -eq 1 \
    && -z "${TRACKER_SOURCE_HYGIENE_ISSUES:-}" \
    && -z "$EXPECTED_GOLDEN" \
    && "$STRICT_MODE" -eq 0 ]]; then
    e2e_step "Default fixture/golden self-check"
    if TRACKER_SOURCE_HYGIENE_DEFAULT_FIXTURE_SELF_CHECK=0 \
        TRACKER_SOURCE_HYGIENE_ISSUES="$DEFAULT_FIXTURE_ISSUES" \
        TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_OPEN=5 \
        TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_OPEN=22 \
        TRACKER_SOURCE_HYGIENE_EXPECT_READY=2 \
        TRACKER_SOURCE_HYGIENE_EXPECT_PERMISSION_GATED=1 \
        TRACKER_SOURCE_HYGIENE_EXPECT_LOCAL_NONCLAIMABLE=3 \
        TRACKER_SOURCE_HYGIENE_EXPECT_IN_PROGRESS=2 \
        TRACKER_SOURCE_HYGIENE_EXPECT_STALE_IN_PROGRESS=1 \
        TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_IN_PROGRESS=2 \
        TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_STALE_IN_PROGRESS=1 \
        TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_SAMPLE_COUNT=20 \
        TRACKER_SOURCE_HYGIENE_EXPECT_FOREIGN_GROUP_COUNT=1 \
        TRACKER_SOURCE_HYGIENE_NOW_EPOCH=2000000000 \
        TRACKER_SOURCE_HYGIENE_STALE_IN_PROGRESS_SECONDS=3600 \
        TRACKER_SOURCE_HYGIENE_EXPECT_GOLDEN="$DEFAULT_FIXTURE_GOLDEN" \
        TRACKER_SOURCE_HYGIENE_EXPECT_GOLDEN_MISMATCH=1 \
        "$REPO_ROOT/scripts/e2e/ffs_tracker_source_hygiene_e2e.sh" \
        >"$FIXTURE_SELF_CHECK_LOG" 2>&1; then
        scenario_result "tracker_source_hygiene_default_fixture_golden_self_check" "PASS" "log=$FIXTURE_SELF_CHECK_LOG"
    else
        scenario_result "tracker_source_hygiene_default_fixture_golden_self_check" "FAIL" "log=$FIXTURE_SELF_CHECK_LOG"
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
