#!/usr/bin/env bash
# ffs_claimability_autopilot_e2e.sh - fixture-only claimability planner autopilot.
#
# This suite proves that tracker source hygiene plus the claimability planner can
# guide agents without trusting raw polluted br/bv output or mutating fixtures.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

# This suite creates temporary inputs only for the run. Preserve them by default
# because this repository forbids agents from deleting files without permission.
export FFS_E2E_DISABLE_TEMP_CLEANUP="${FFS_E2E_DISABLE_TEMP_CLEANUP:-1}"

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

e2e_init "ffs_claimability_autopilot"

FIXTURE_NOW_EPOCH="${CLAIMABILITY_AUTOPILOT_NOW_EPOCH:-2000000000}"
STALE_IN_PROGRESS_SECONDS="${CLAIMABILITY_AUTOPILOT_STALE_IN_PROGRESS_SECONDS:-3600}"
GENERATED_AT="${CLAIMABILITY_AUTOPILOT_GENERATED_AT:-2033-05-18T03:33:20Z}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_CAPTURE_VISIBILITY="${FFS_CLAIMABILITY_AUTOPILOT_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-8}"
SELF_CHECK="${FFS_CLAIMABILITY_AUTOPILOT_SELF_CHECK:-0}"
SKIP_SELF_CHECK="${FFS_CLAIMABILITY_AUTOPILOT_SKIP_SELF_CHECK:-0}"

PERMISSION_FIXTURE="$REPO_ROOT/tests/fixtures/claimability_autopilot_permission_gated.jsonl"
POLLUTED_FIXTURE="$REPO_ROOT/tests/fixtures/claimability_autopilot_polluted.jsonl"
PERMISSION_TRACKER_INPUT="$REPO_ROOT/tests/fixtures/claimability_autopilot_permission_gated_tracker_report.json"
POLLUTED_TRACKER_INPUT="$REPO_ROOT/tests/fixtures/claimability_autopilot_polluted_tracker_report.json"
RESERVATION_FIXTURE="$REPO_ROOT/tests/fixtures/claimability_autopilot_peer_reservation.json"
SELF_RESERVATION_FIXTURE="$REPO_ROOT/tests/fixtures/claimability_autopilot_self_reservation.json"
BV_FIXTURE="$REPO_ROOT/tests/fixtures/claimability_autopilot_bv.json"

ARTIFACT_ROOT="${CLAIMABILITY_AUTOPILOT_ARTIFACT_DIR:-$REPO_ROOT/artifacts/claimability_autopilot/$(basename "$E2E_LOG_DIR")}"
TRANSCRIPT_DIR="$E2E_LOG_DIR/transcripts"
FIXTURE_DIGEST_BEFORE="$ARTIFACT_ROOT/fixture_sha256.before"
FIXTURE_DIGEST_AFTER="$ARTIFACT_ROOT/fixture_sha256.after"
FIXTURE_DIGEST_DIFF="$ARTIFACT_ROOT/fixture_sha256.diff"

PERMISSION_CASE_DIR="$ARTIFACT_ROOT/permission_gated_zero_claimable"
POLLUTED_CASE_DIR="$ARTIFACT_ROOT/polluted_one_claimable"
PEER_CASE_DIR="$ARTIFACT_ROOT/peer_reserved_surface"
SELF_CASE_DIR="$ARTIFACT_ROOT/self_reserved_surface"

PERMISSION_TRACKER_REPORT="$PERMISSION_CASE_DIR/tracker_source_hygiene_report.json"
POLLUTED_TRACKER_REPORT="$POLLUTED_CASE_DIR/tracker_source_hygiene_report.json"

PERMISSION_PLAN_JSON="$PERMISSION_CASE_DIR/claimability_plan.json"
PERMISSION_PLAN_MD="$PERMISSION_CASE_DIR/claimability_plan.md"
POLLUTED_PLAN_JSON="$POLLUTED_CASE_DIR/claimability_plan.json"
POLLUTED_PLAN_MD="$POLLUTED_CASE_DIR/claimability_plan.md"
PEER_PLAN_JSON="$PEER_CASE_DIR/claimability_plan.json"
PEER_PLAN_MD="$PEER_CASE_DIR/claimability_plan.md"
SELF_PLAN_JSON="$SELF_CASE_DIR/claimability_plan.json"
SELF_PLAN_MD="$SELF_CASE_DIR/claimability_plan.md"

PERMISSION_TRACKER_TRANSCRIPT="$TRANSCRIPT_DIR/permission_tracker_source_hygiene.log"
PERMISSION_PLANNER_TRANSCRIPT="$TRANSCRIPT_DIR/permission_claimability_plan.log"
POLLUTED_TRACKER_TRANSCRIPT="$TRANSCRIPT_DIR/polluted_tracker_source_hygiene.log"
POLLUTED_PLANNER_TRANSCRIPT="$TRANSCRIPT_DIR/polluted_claimability_plan.log"
PEER_PLANNER_TRANSCRIPT="$TRANSCRIPT_DIR/peer_reserved_claimability_plan.log"
SELF_PLANNER_TRANSCRIPT="$TRANSCRIPT_DIR/self_reserved_claimability_plan.log"

PERMISSION_TRACKER_STDOUT="$TRANSCRIPT_DIR/permission_tracker_source_hygiene.stdout"
PERMISSION_PLANNER_STDOUT="$TRANSCRIPT_DIR/permission_claimability_plan.stdout"
POLLUTED_TRACKER_STDOUT="$TRANSCRIPT_DIR/polluted_tracker_source_hygiene.stdout"
POLLUTED_PLANNER_STDOUT="$TRANSCRIPT_DIR/polluted_claimability_plan.stdout"
PEER_PLANNER_STDOUT="$TRANSCRIPT_DIR/peer_reserved_claimability_plan.stdout"
SELF_PLANNER_STDOUT="$TRANSCRIPT_DIR/self_reserved_claimability_plan.stdout"

mkdir -p \
    "$ARTIFACT_ROOT" \
    "$TRANSCRIPT_DIR" \
    "$PERMISSION_CASE_DIR" \
    "$POLLUTED_CASE_DIR" \
    "$PEER_CASE_DIR" \
    "$SELF_CASE_DIR"

relative_path() {
    local path="$1"
    case "$path" in
        "$REPO_ROOT"/*)
            printf '%s\n' "${path#$REPO_ROOT/}"
            ;;
        *)
            printf '%s\n' "$path"
            ;;
    esac
}

run_remote_harness() {
    local transcript="$1"
    local stdout_path="$2"
    shift 2

    local -a command=(cargo run -q -p ffs-harness -- "$@")
    {
        printf 'COMMAND: RCH_VISIBILITY=%q' "$RCH_CAPTURE_VISIBILITY"
        printf ' %q' "$RCH_BIN" "exec" "--" "${command[@]}"
        printf '\n'
    } >"$transcript"

    local status=0
    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" e2e_rch_capture "$stdout_path" "${command[@]}" || status=$?
    {
        e2e_log "STDOUT: $stdout_path"
        cat "$stdout_path"
    } >>"$transcript"
    if [[ "$status" -ne 0 ]]; then
        e2e_log "Remote harness command failed: transcript=$transcript status=$status"
        return "$status"
    fi
}

extract_first_json_object() {
    local stdout_path="$1"
    local output_path="$2"

    python3 - "$stdout_path" "$output_path" <<'PY'
import json
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
out = pathlib.Path(sys.argv[2])
start = text.find("{")
if start < 0:
    raise SystemExit("no JSON object found")

depth = 0
in_string = False
escape = False
for index in range(start, len(text)):
    char = text[index]
    if in_string:
        if escape:
            escape = False
        elif char == "\\":
            escape = True
        elif char == '"':
            in_string = False
        continue
    if char == '"':
        in_string = True
    elif char == "{":
        depth += 1
    elif char == "}":
        depth -= 1
        if depth == 0:
            parsed = json.loads(text[start:index + 1])
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(parsed, indent=2) + "\n", encoding="utf-8")
            raise SystemExit(0)

raise SystemExit("unterminated JSON object")
PY
}

render_plan_markdown() {
    local plan_json="$1"
    local plan_md="$2"

    jq -r '
        "# Claimability Plan\n"
        + "\n- Status: `\(.status)`"
        + "\n- Tracker verdict: `\(.tracker_queue_verdict)`"
        + "\n- Mutation policy: `\(.mutation_policy)`"
        + "\n\n## Next Actions\n"
        + (.next_safe_actions | map("- " + .) | join("\n"))
        + "\n\n## Reservation Allocation\n"
        + "- status: `\(.reservation_allocation_plan.status)`\n"
        + "- Self-held reservations: `\(.reservation_allocation_plan.self_held_reservation_count)`\n"
        + (if (.reservation_allocation_plan.self_held_target_paths | length) == 0 then
            "- Self-held target paths: `none`\n"
        else
            "- Self-held target paths:\n"
            + (.reservation_allocation_plan.self_held_target_paths | map("  - `" + . + "`") | join("\n"))
            + "\n"
        end)
        + (.reservation_allocation_plan.suggested_disjoint_target_paths | map("- `" + . + "`") | join("\n"))
        + "\n\n## Rows\n"
        + (.rows | map("- `\(.id)`: `\(.classification)`") | join("\n"))
        + "\n"
    ' "$plan_json" >"$plan_md"
}

run_tracker_source_hygiene() {
    local issues_fixture="$1"
    local report_path="$2"
    local transcript="$3"

    local stdout_path="${transcript%.log}.stdout"
    run_remote_harness "$transcript" "$stdout_path" \
        validate-tracker-source-hygiene \
        --issues "$(relative_path "$issues_fixture")" \
        --now-epoch "$FIXTURE_NOW_EPOCH" \
        --stale-in-progress-seconds "$STALE_IN_PROGRESS_SECONDS" \
        && extract_first_json_object "$transcript" "$report_path"
}

run_claimability_plan() {
    local tracker_report="$1"
    local plan_json="$2"
    local plan_md="$3"
    local transcript="$4"
    local reservation_report="${5:-}"

    local -a args=(
        claimability-plan
        --tracker-report "$(relative_path "$tracker_report")"
        --bv-report "$(relative_path "$BV_FIXTURE")"
        --generated-at "$GENERATED_AT"
    )
    if [[ -n "$reservation_report" ]]; then
        args+=(
            --reservation-report "$(relative_path "$reservation_report")"
        )
    fi
    local stdout_path="${transcript%.log}.stdout"
    run_remote_harness "$transcript" "$stdout_path" "${args[@]}" \
        && extract_first_json_object "$transcript" "$plan_json" \
        && render_plan_markdown "$plan_json" "$plan_md"
}

write_fixture_rch_stub() {
    local stub_path="$1"

    cat >"$stub_path" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

fixture_case="${FFS_CLAIMABILITY_AUTOPILOT_FIXTURE_CASE:-complete}"

if [[ "${1:-}" != "exec" || "${2:-}" != "--" ]]; then
    echo "unexpected claimability-autopilot fixture rch invocation: $*" >&2
    exit 64
fi
shift 2
command_text="$*"

case "$fixture_case" in
    local_fallback)
        echo "[RCH] local (fixture forced local fallback)"
        exit 1
        ;;
    missing_remote_evidence)
        ;;
    complete)
        echo "[RCH] remote worker=fixture exit=0"
        ;;
    *)
        echo "unknown claimability-autopilot fixture case: $fixture_case" >&2
        exit 64
        ;;
esac

finish_success() {
    if [[ "$fixture_case" == "complete" ]]; then
        echo "Remote command finished: exit=0"
    fi
    exit 0
}

emit_tracker_report() {
    cat <<'JSON'
{
  "source_aware_queue_state": {
    "claimable_ids": [
      "bd-autopilot-ready"
    ],
    "verdict": "fixture"
  }
}
JSON
}

emit_permission_plan() {
    cat <<'JSON'
{
  "bv_snapshot": {
    "suppressed_parent_epic_ids": [
      "bd-autopilot-epic"
    ]
  },
  "mutation_policy": "advisory_only",
  "next_safe_actions": [
    "do not run permission-gated rows without the required ACK"
  ],
  "reservation_allocation_plan": {
    "safe_reservation_commands": [],
    "self_held_reservation_count": 0,
    "self_held_target_paths": [],
    "status": "none",
    "suggested_disjoint_target_paths": []
  },
  "rows": [
    {
      "classification": "permission_gated",
      "id": "bd-autopilot-permissioned",
      "permission_gate": {
        "required_env": "XFSTESTS_REAL_RUN_ACK"
      }
    }
  ],
  "source_aware_claimable_ids": [],
  "status": "blocked",
  "tracker_queue_verdict": "permission_gated"
}
JSON
}

emit_polluted_plan() {
    cat <<'JSON'
{
  "mutation_policy": "advisory_only",
  "next_safe_actions": [
    "claim one claimable row with Agent Mail reservation",
    "inspect Agent Mail and live reservations before reclaiming stale in-progress rows",
    "preserve foreign rows as owner-handoff only"
  ],
  "reservation_allocation_plan": {
    "safe_reservation_commands": [],
    "self_held_reservation_count": 0,
    "self_held_target_paths": [],
    "status": "none",
    "suggested_disjoint_target_paths": []
  },
  "rows": [
    {
      "classification": "claimable",
      "id": "bd-autopilot-ready"
    },
    {
      "classification": "stale_in_progress_reclaim_candidate",
      "id": "bd-autopilot-stale"
    },
    {
      "classification": "foreign_excluded",
      "id": "br-r37-autopilot-foreign",
      "owner_handoff_required": true
    }
  ],
  "source_aware_claimable_ids": [
    "bd-autopilot-ready"
  ],
  "status": "claimable",
  "tracker_queue_verdict": "claimable"
}
JSON
}

emit_peer_plan() {
    cat <<'JSON'
{
  "mutation_policy": "advisory_only",
  "next_safe_actions": [
    "wait for peer reservation release before editing the reserved surface"
  ],
  "reservation_allocation_plan": {
    "advisory_only": true,
    "groups": [
      {
        "blocked_target_paths": [
          "scripts/e2e/ffs_claimability_autopilot_e2e.sh"
        ],
        "holder": "SageMeadow"
      }
    ],
    "safe_reservation_commands": [
      "file_reservation_paths paths=crates/ffs-harness/src/claimability_plan.rs,docs/tracker-hygiene.md"
    ],
    "self_held_reservation_count": 0,
    "self_held_target_paths": [],
    "status": "safe_disjoint_suggestions",
    "suggested_disjoint_target_paths": [
      "crates/ffs-harness/src/claimability_plan.rs",
      "docs/tracker-hygiene.md"
    ]
  },
  "reservation_snapshot": {
    "active_peer_conflict_count": 1,
    "conflict_classification": "active_peer_conflict"
  },
  "rows": [
    {
      "classification": "reserved_by_peer",
      "id": "bd-autopilot-ready"
    }
  ],
  "source_aware_claimable_ids": [
    "bd-autopilot-ready"
  ],
  "status": "blocked",
  "tracker_queue_verdict": "claimable"
}
JSON
}

emit_self_plan() {
    cat <<'JSON'
{
  "mutation_policy": "advisory_only",
  "next_safe_actions": [
    "self-held reservations overlap this surface; continue only in the same coordinated thread"
  ],
  "reservation_allocation_plan": {
    "safe_reservation_commands": [],
    "self_held_reservation_count": 1,
    "self_held_target_paths": [
      "scripts/e2e/ffs_claimability_autopilot_e2e.sh"
    ],
    "status": "self_held_active_reservation",
    "suggested_disjoint_target_paths": []
  },
  "reservation_snapshot": {
    "active_peer_conflict_count": 0,
    "active_self_reservation_count": 1,
    "conflict_classification": "self_held",
    "self_held_target_paths": [
      "scripts/e2e/ffs_claimability_autopilot_e2e.sh"
    ]
  },
  "rows": [
    {
      "classification": "claimable",
      "id": "bd-autopilot-ready"
    }
  ],
  "source_aware_claimable_ids": [
    "bd-autopilot-ready"
  ],
  "status": "claimable",
  "tracker_queue_verdict": "claimable"
}
JSON
}

case "$command_text" in
    *"validate-tracker-source-hygiene"*)
        emit_tracker_report
        finish_success
        ;;
    *"claimability-plan"*"claimability_autopilot_permission_gated_tracker_report.json"*)
        emit_permission_plan
        finish_success
        ;;
    *"claimability-plan"*"claimability_autopilot_peer_reservation.json"*)
        emit_peer_plan
        finish_success
        ;;
    *"claimability-plan"*"claimability_autopilot_self_reservation.json"*)
        emit_self_plan
        finish_success
        ;;
    *"claimability-plan"*"claimability_autopilot_polluted_tracker_report.json"*)
        emit_polluted_plan
        finish_success
        ;;
    *)
        echo "unexpected claimability-autopilot fixture command: $command_text" >&2
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
    local child_log="$E2E_LOG_DIR/claimability_autopilot_fixture_${fixture_case}.log"
    local child_status

    set +e
    FFS_E2E_DISABLE_TEMP_CLEANUP=1 \
        FFS_CLAIMABILITY_AUTOPILOT_SELF_CHECK=0 \
        FFS_CLAIMABILITY_AUTOPILOT_SKIP_SELF_CHECK=1 \
        FFS_CLAIMABILITY_AUTOPILOT_FIXTURE_CASE="$fixture_case" \
        RCH_BIN="$stub_path" \
        RCH_COMMAND_TIMEOUT_SECS=2 \
        RCH_ARTIFACT_RETRIEVAL_GRACE_SECS=1 \
        "$REPO_ROOT/scripts/e2e/ffs_claimability_autopilot_e2e.sh" >"$child_log" 2>&1
    child_status=$?
    set -e

    printf '%s\t%s\n' "$child_status" "$child_log"
}

run_self_check() {
    if [[ "$SKIP_SELF_CHECK" == "1" ]]; then
        return 0
    fi

    e2e_step "Deterministic claimability autopilot wrapper self-check"
    local stub_path child_info child_status child_log result_path
    stub_path="$E2E_LOG_DIR/rch-claimability-autopilot-fixture"
    write_fixture_rch_stub "$stub_path"

    child_info="$(run_fixture_child "$stub_path" "complete")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" == "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '
            .verdict == "PASS"
            and .rch_local_fallback_rejected_count == 0
            and ([.scenarios[] | select(.scenario_id == "claimability_autopilot_transcripts_remote_only" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "claimability_autopilot_peer_reserved_surface" and .outcome == "PASS")] | length == 1)
            and ([.scenarios[] | select(.scenario_id == "claimability_autopilot_fixture_non_mutation" and .outcome == "PASS")] | length == 1)
        ' "$result_path" >/dev/null; then
        scenario_result "claimability_autopilot_fixture_complete_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "claimability_autopilot_fixture_complete_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "local_fallback")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL" and .rch_local_fallback_rejected_count >= 1' "$result_path" >/dev/null \
        && grep -q "RCH_LOCAL_FALLBACK_REJECTED" "$child_log"; then
        scenario_result "claimability_autopilot_fixture_local_fallback_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "claimability_autopilot_fixture_local_fallback_self_check" "FAIL" "log=${child_log}"
        return 1
    fi

    child_info="$(run_fixture_child "$stub_path" "missing_remote_evidence")"
    child_status="${child_info%%$'\t'*}"
    child_log="${child_info#*$'\t'}"
    result_path="$(extract_child_result_json "$child_log")"
    if [[ "$child_status" != "0" ]] \
        && [[ -n "$result_path" ]] \
        && jq -e '.verdict == "FAIL"' "$result_path" >/dev/null \
        && grep -q "RCH_REMOTE_EVIDENCE_MISSING" "$child_log"; then
        scenario_result "claimability_autopilot_fixture_missing_remote_evidence_self_check" "PASS" "result=${result_path}"
    else
        scenario_result "claimability_autopilot_fixture_missing_remote_evidence_self_check" "FAIL" "log=${child_log}"
        return 1
    fi
}

write_autopilot_summary() {
    local cleanup_status="temp_cleanup_disabled_preserved"
    if [[ "${FFS_E2E_DISABLE_TEMP_CLEANUP:-0}" != "1" ]]; then
        cleanup_status="temp_cleanup_enabled_by_caller"
    fi

    jq -n \
        --arg artifact_dir "$ARTIFACT_ROOT" \
        --arg cleanup_status "$cleanup_status" \
        --arg permission_fixture "$PERMISSION_FIXTURE" \
        --arg polluted_fixture "$POLLUTED_FIXTURE" \
        --arg permission_tracker_input "$PERMISSION_TRACKER_INPUT" \
        --arg polluted_tracker_input "$POLLUTED_TRACKER_INPUT" \
        --arg reservation_fixture "$RESERVATION_FIXTURE" \
        --arg self_reservation_fixture "$SELF_RESERVATION_FIXTURE" \
        --arg bv_fixture "$BV_FIXTURE" \
        --arg permission_tracker "$PERMISSION_TRACKER_REPORT" \
        --arg polluted_tracker "$POLLUTED_TRACKER_REPORT" \
        --arg permission_plan_json "$PERMISSION_PLAN_JSON" \
        --arg permission_plan_md "$PERMISSION_PLAN_MD" \
        --arg polluted_plan_json "$POLLUTED_PLAN_JSON" \
        --arg polluted_plan_md "$POLLUTED_PLAN_MD" \
        --arg peer_plan_json "$PEER_PLAN_JSON" \
        --arg peer_plan_md "$PEER_PLAN_MD" \
        --arg self_plan_json "$SELF_PLAN_JSON" \
        --arg self_plan_md "$SELF_PLAN_MD" \
        --arg permission_tracker_transcript "$PERMISSION_TRACKER_TRANSCRIPT" \
        --arg permission_planner_transcript "$PERMISSION_PLANNER_TRANSCRIPT" \
        --arg polluted_tracker_transcript "$POLLUTED_TRACKER_TRANSCRIPT" \
        --arg polluted_planner_transcript "$POLLUTED_PLANNER_TRANSCRIPT" \
        --arg peer_planner_transcript "$PEER_PLANNER_TRANSCRIPT" \
        --arg self_planner_transcript "$SELF_PLANNER_TRANSCRIPT" \
        --slurpfile permission_plan "$PERMISSION_PLAN_JSON" \
        --slurpfile polluted_plan "$POLLUTED_PLAN_JSON" \
        --slurpfile peer_plan "$PEER_PLAN_JSON" \
        --slurpfile self_plan "$SELF_PLAN_JSON" \
        '{
            claimability_autopilot: {
                schema_version: 1,
                mutation_policy: "fixture-only; never claims, closes, deletes, rewrites, or edits tracker rows",
                artifact_dir: $artifact_dir,
                cleanup_status: $cleanup_status,
                cases: [
                    {
                        case_id: "permission_gated_zero_claimable",
                        issues_fixture: $permission_fixture,
                        input_report_paths: {
                            tracker_source_hygiene: $permission_tracker,
                            planner_tracker_input: $permission_tracker_input
                        },
                        reservation_snapshot_path: null,
                        bv_json_path: $bv_fixture,
                        claimability_plan_json: $permission_plan_json,
                        claimability_plan_markdown: $permission_plan_md,
                        command_transcripts: {
                            tracker_source_hygiene: $permission_tracker_transcript,
                            claimability_plan: $permission_planner_transcript
                        },
                        next_command_hints: ($permission_plan[0].next_safe_actions // [])
                    },
                    {
                        case_id: "polluted_one_claimable",
                        issues_fixture: $polluted_fixture,
                        input_report_paths: {
                            tracker_source_hygiene: $polluted_tracker,
                            planner_tracker_input: $polluted_tracker_input
                        },
                        reservation_snapshot_path: null,
                        bv_json_path: $bv_fixture,
                        claimability_plan_json: $polluted_plan_json,
                        claimability_plan_markdown: $polluted_plan_md,
                        command_transcripts: {
                            tracker_source_hygiene: $polluted_tracker_transcript,
                            claimability_plan: $polluted_planner_transcript
                        },
                        next_command_hints: ($polluted_plan[0].next_safe_actions // [])
                    },
                    {
                        case_id: "peer_reserved_surface",
                        issues_fixture: $polluted_fixture,
                        input_report_paths: {
                            tracker_source_hygiene: $polluted_tracker,
                            planner_tracker_input: $polluted_tracker_input
                        },
                        reservation_snapshot_path: $reservation_fixture,
                        bv_json_path: $bv_fixture,
                        claimability_plan_json: $peer_plan_json,
                        claimability_plan_markdown: $peer_plan_md,
                        command_transcripts: {
                            claimability_plan: $peer_planner_transcript
                        },
                        next_command_hints: ($peer_plan[0].next_safe_actions // [])
                    },
                    {
                        case_id: "self_reserved_surface",
                        issues_fixture: $polluted_fixture,
                        input_report_paths: {
                            tracker_source_hygiene: $polluted_tracker,
                            planner_tracker_input: $polluted_tracker_input
                        },
                        reservation_snapshot_path: $self_reservation_fixture,
                        bv_json_path: $bv_fixture,
                        claimability_plan_json: $self_plan_json,
                        claimability_plan_markdown: $self_plan_md,
                        command_transcripts: {
                            claimability_plan: $self_planner_transcript
                        },
                        next_command_hints: ($self_plan[0].next_safe_actions // [])
                    }
                ]
            }
        }' >"$E2E_LOG_DIR/result.json"
}

e2e_step "Preflight"
if [[ "$SELF_CHECK" == "1" ]]; then
    run_self_check
    e2e_pass
    exit 0
fi

if ! command -v jq >/dev/null 2>&1; then
    scenario_result "claimability_autopilot_artifacts_written" "FAIL" "jq not found"
    e2e_fail "jq is required for claimability autopilot reporting"
fi
if ! command -v sha256sum >/dev/null 2>&1; then
    scenario_result "claimability_autopilot_fixture_non_mutation" "FAIL" "sha256sum not found"
    e2e_fail "sha256sum is required for fixture non-mutation proof"
fi
if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    scenario_result "claimability_autopilot_transcripts_remote_only" "FAIL" "rch not found"
    e2e_fail "RCH is required; this E2E refuses local cargo"
fi
for fixture in \
    "$PERMISSION_FIXTURE" \
    "$POLLUTED_FIXTURE" \
    "$PERMISSION_TRACKER_INPUT" \
    "$POLLUTED_TRACKER_INPUT" \
    "$RESERVATION_FIXTURE" \
    "$SELF_RESERVATION_FIXTURE" \
    "$BV_FIXTURE"; do
    if [[ ! -f "$fixture" ]]; then
        scenario_result "claimability_autopilot_artifacts_written" "FAIL" "missing fixture=$fixture"
        e2e_fail "missing claimability autopilot fixture: $fixture"
    fi
done
sha256sum \
    "$PERMISSION_FIXTURE" \
    "$POLLUTED_FIXTURE" \
    "$PERMISSION_TRACKER_INPUT" \
    "$POLLUTED_TRACKER_INPUT" \
    "$RESERVATION_FIXTURE" \
    "$SELF_RESERVATION_FIXTURE" \
    "$BV_FIXTURE" >"$FIXTURE_DIGEST_BEFORE"

e2e_step "Run tracker hygiene and claimability planner through RCH"
if run_tracker_source_hygiene "$PERMISSION_FIXTURE" "$PERMISSION_TRACKER_REPORT" "$PERMISSION_TRACKER_TRANSCRIPT" \
    && run_claimability_plan "$PERMISSION_TRACKER_INPUT" "$PERMISSION_PLAN_JSON" "$PERMISSION_PLAN_MD" "$PERMISSION_PLANNER_TRANSCRIPT" \
    && run_tracker_source_hygiene "$POLLUTED_FIXTURE" "$POLLUTED_TRACKER_REPORT" "$POLLUTED_TRACKER_TRANSCRIPT" \
    && run_claimability_plan "$POLLUTED_TRACKER_INPUT" "$POLLUTED_PLAN_JSON" "$POLLUTED_PLAN_MD" "$POLLUTED_PLANNER_TRANSCRIPT" \
    && run_claimability_plan "$POLLUTED_TRACKER_INPUT" "$PEER_PLAN_JSON" "$PEER_PLAN_MD" "$PEER_PLANNER_TRANSCRIPT" "$RESERVATION_FIXTURE" \
    && run_claimability_plan "$POLLUTED_TRACKER_INPUT" "$SELF_PLAN_JSON" "$SELF_PLAN_MD" "$SELF_PLANNER_TRANSCRIPT" "$SELF_RESERVATION_FIXTURE"; then
    scenario_result "claimability_autopilot_transcripts_remote_only" "PASS" "transcripts=$TRANSCRIPT_DIR"
else
    scenario_result "claimability_autopilot_transcripts_remote_only" "FAIL" "transcripts=$TRANSCRIPT_DIR"
fi

if [[ -s "$PERMISSION_TRACKER_REPORT" \
    && -s "$POLLUTED_TRACKER_REPORT" \
    && -s "$PERMISSION_PLAN_JSON" \
    && -s "$PERMISSION_PLAN_MD" \
    && -s "$POLLUTED_PLAN_JSON" \
    && -s "$POLLUTED_PLAN_MD" \
    && -s "$PEER_PLAN_JSON" \
    && -s "$PEER_PLAN_MD" \
    && -s "$SELF_PLAN_JSON" \
    && -s "$SELF_PLAN_MD" ]]; then
    scenario_result "claimability_autopilot_artifacts_written" "PASS" "artifact_dir=$ARTIFACT_ROOT"
else
    scenario_result "claimability_autopilot_artifacts_written" "FAIL" "missing claimability artifacts in $ARTIFACT_ROOT"
fi

e2e_step "Validate claimability outcomes"
if jq -e '
    (.source_aware_claimable_ids | length) == 0
    and any(.rows[]; .id == "bd-autopilot-permissioned" and .classification == "permission_gated" and .permission_gate.required_env == "XFSTESTS_REAL_RUN_ACK")
    and (.bv_snapshot.suppressed_parent_epic_ids | index("bd-autopilot-epic") != null)
    and any(.next_safe_actions[]; contains("do not run permission-gated rows"))
' "$PERMISSION_PLAN_JSON" >/dev/null; then
    scenario_result "claimability_autopilot_zero_claimable_permission_gated" "PASS" "plan=$PERMISSION_PLAN_JSON"
else
    scenario_result "claimability_autopilot_zero_claimable_permission_gated" "FAIL" "plan=$PERMISSION_PLAN_JSON"
fi

if jq -e '
    (.source_aware_claimable_ids == ["bd-autopilot-ready"])
    and any(.rows[]; .id == "bd-autopilot-ready" and .classification == "claimable")
    and any(.next_safe_actions[]; contains("claim one claimable row"))
' "$POLLUTED_PLAN_JSON" >/dev/null; then
    scenario_result "claimability_autopilot_one_claimable_task" "PASS" "plan=$POLLUTED_PLAN_JSON"
else
    scenario_result "claimability_autopilot_one_claimable_task" "FAIL" "plan=$POLLUTED_PLAN_JSON"
fi

if jq -e '
    (.reservation_snapshot.active_peer_conflict_count == 1)
    and (.reservation_snapshot.conflict_classification == "active_peer_conflict")
    and any(.rows[]; .id == "bd-autopilot-ready" and .classification == "reserved_by_peer")
    and any(.next_safe_actions[]; contains("wait for peer reservation release"))
' "$PEER_PLAN_JSON" >/dev/null; then
    scenario_result "claimability_autopilot_peer_reserved_surface" "PASS" "plan=$PEER_PLAN_JSON reservation=$RESERVATION_FIXTURE"
else
    scenario_result "claimability_autopilot_peer_reserved_surface" "FAIL" "plan=$PEER_PLAN_JSON reservation=$RESERVATION_FIXTURE"
fi

if jq -e '
    (.reservation_allocation_plan.status == "safe_disjoint_suggestions")
    and (.reservation_allocation_plan.advisory_only == true)
    and (.reservation_allocation_plan.suggested_disjoint_target_paths == [
        "crates/ffs-harness/src/claimability_plan.rs",
        "docs/tracker-hygiene.md"
    ])
    and any(.reservation_allocation_plan.groups[]; .holder == "SageMeadow" and (.blocked_target_paths == ["scripts/e2e/ffs_claimability_autopilot_e2e.sh"]))
    and any(.reservation_allocation_plan.safe_reservation_commands[]; contains("crates/ffs-harness/src/claimability_plan.rs") and contains("docs/tracker-hygiene.md"))
' "$PEER_PLAN_JSON" >/dev/null \
    && grep -q "Reservation Allocation" "$PEER_PLAN_MD" \
    && grep -q "crates/ffs-harness/src/claimability_plan.rs" "$PEER_PLAN_MD" \
    && grep -q "docs/tracker-hygiene.md" "$PEER_PLAN_MD"; then
    scenario_result "claimability_autopilot_disjoint_reservation_suggestions" "PASS" "plan=$PEER_PLAN_JSON markdown=$PEER_PLAN_MD"
else
    scenario_result "claimability_autopilot_disjoint_reservation_suggestions" "FAIL" "plan=$PEER_PLAN_JSON markdown=$PEER_PLAN_MD"
fi

if jq -e '
    (.reservation_snapshot.active_peer_conflict_count == 0)
    and (.reservation_snapshot.active_self_reservation_count == 1)
    and (.reservation_snapshot.conflict_classification == "self_held")
    and (.reservation_snapshot.self_held_target_paths == ["scripts/e2e/ffs_claimability_autopilot_e2e.sh"])
    and (.reservation_allocation_plan.status == "self_held_active_reservation")
    and (.reservation_allocation_plan.self_held_target_paths == ["scripts/e2e/ffs_claimability_autopilot_e2e.sh"])
    and any(.rows[]; .id == "bd-autopilot-ready" and .classification == "claimable")
    and all(.rows[]; .classification != "reserved_by_peer")
    and any(.next_safe_actions[]; contains("self-held reservations overlap"))
' "$SELF_PLAN_JSON" >/dev/null \
    && grep -q "Self-held reservations" "$SELF_PLAN_MD" \
    && grep -q "scripts/e2e/ffs_claimability_autopilot_e2e.sh" "$SELF_PLAN_MD"; then
    scenario_result "claimability_autopilot_self_reserved_surface" "PASS" "plan=$SELF_PLAN_JSON markdown=$SELF_PLAN_MD"
else
    scenario_result "claimability_autopilot_self_reserved_surface" "FAIL" "plan=$SELF_PLAN_JSON markdown=$SELF_PLAN_MD"
fi

if jq -e '
    any(.rows[]; .id == "bd-autopilot-stale" and .classification == "stale_in_progress_reclaim_candidate")
    and any(.next_safe_actions[]; contains("inspect Agent Mail and live reservations before reclaiming"))
' "$POLLUTED_PLAN_JSON" >/dev/null; then
    scenario_result "claimability_autopilot_stale_reclaim_candidate" "PASS" "plan=$POLLUTED_PLAN_JSON"
else
    scenario_result "claimability_autopilot_stale_reclaim_candidate" "FAIL" "plan=$POLLUTED_PLAN_JSON"
fi

if jq -e '
    any(.rows[]; .id == "br-r37-autopilot-foreign" and .classification == "foreign_excluded" and .owner_handoff_required == true)
    and any(.next_safe_actions[]; contains("preserve foreign rows as owner-handoff only"))
' "$POLLUTED_PLAN_JSON" >/dev/null; then
    scenario_result "claimability_autopilot_foreign_owner_handoff" "PASS" "plan=$POLLUTED_PLAN_JSON"
else
    scenario_result "claimability_autopilot_foreign_owner_handoff" "FAIL" "plan=$POLLUTED_PLAN_JSON"
fi

write_autopilot_summary
if jq -e '
    (.claimability_autopilot.schema_version == 1)
    and (.claimability_autopilot.cleanup_status | type == "string")
    and (.claimability_autopilot.cases | length == 4)
    and all(.claimability_autopilot.cases[]; (.input_report_paths.tracker_source_hygiene | type == "string"))
    and all(.claimability_autopilot.cases[]; (.bv_json_path | test("claimability_autopilot_bv\\.json$")))
    and any(.claimability_autopilot.cases[]; .reservation_snapshot_path != null)
    and all(.claimability_autopilot.cases[]; (.next_command_hints | type == "array" and length > 0))
' "$E2E_LOG_DIR/result.json" >/dev/null; then
    scenario_result "claimability_autopilot_result_summary" "PASS" "result=$E2E_LOG_DIR/result.json"
else
    scenario_result "claimability_autopilot_result_summary" "FAIL" "result=$E2E_LOG_DIR/result.json"
fi

sha256sum \
    "$PERMISSION_FIXTURE" \
    "$POLLUTED_FIXTURE" \
    "$PERMISSION_TRACKER_INPUT" \
    "$POLLUTED_TRACKER_INPUT" \
    "$RESERVATION_FIXTURE" \
    "$SELF_RESERVATION_FIXTURE" \
    "$BV_FIXTURE" >"$FIXTURE_DIGEST_AFTER"
if diff -u "$FIXTURE_DIGEST_BEFORE" "$FIXTURE_DIGEST_AFTER" >"$FIXTURE_DIGEST_DIFF"; then
    scenario_result "claimability_autopilot_fixture_non_mutation" "PASS" "digest=$FIXTURE_DIGEST_AFTER cleanup=${FFS_E2E_DISABLE_TEMP_CLEANUP:-0}"
else
    scenario_result "claimability_autopilot_fixture_non_mutation" "FAIL" "diff=$FIXTURE_DIGEST_DIFF"
fi

if [[ "$FAIL_COUNT" -eq 0 ]]; then
    e2e_pass
else
    e2e_fail "Claimability autopilot failed ${FAIL_COUNT}/${TOTAL} scenarios; artifact_dir=$ARTIFACT_ROOT"
fi
