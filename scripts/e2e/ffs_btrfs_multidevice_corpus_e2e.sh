#!/usr/bin/env bash
# ffs_btrfs_multidevice_corpus_e2e.sh - non-permissioned btrfs multi-device corpus gate.

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_btrfs_multidevice_corpus}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_ARTIFACT_RETRIEVAL_GRACE_SECS="${RCH_ARTIFACT_RETRIEVAL_GRACE_SECS:-4}"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

scenario_result() {
    local scenario_id="$1"
    local outcome="$2"
    local detail="${3:-}"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}|detail=${detail}"
    if [[ "$outcome" == "PASS" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    TOTAL=$((TOTAL + 1))
}

extract_report_json() {
    local raw_path="$1"
    local report_path="$2"
    python3 - "$raw_path" "$report_path" <<'PY'
import json
import pathlib
import re
import sys

raw_path, report_path = sys.argv[1:]
text = pathlib.Path(raw_path).read_text(encoding="utf-8", errors="replace")
text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
decoder = json.JSONDecoder()
for index, char in enumerate(text):
    if char != "{":
        continue
    try:
        obj, _ = decoder.raw_decode(text[index:])
    except json.JSONDecodeError:
        continue
    if isinstance(obj, dict) and "corpus_id" in obj and "scenario_count" in obj:
        pathlib.Path(report_path).write_text(
            json.dumps(obj, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        break
else:
    raise SystemExit("btrfs multi-device corpus report JSON object not found")
PY
}

e2e_init "ffs_btrfs_multidevice_corpus"

CORPUS_JSON="$REPO_ROOT/tests/btrfs-multidevice-corpus/btrfs_multidevice_corpus.json"
RCH_INPUT_DIR="$REPO_ROOT/artifacts/rch_input/$(basename "$E2E_LOG_DIR")/btrfs_multidevice_corpus"
REPORT_JSON="$E2E_LOG_DIR/btrfs_multidevice_corpus_report.json"
VALIDATE_RAW="$E2E_LOG_DIR/btrfs_multidevice_corpus_validate.raw"
MARKDOWN_RAW="$E2E_LOG_DIR/btrfs_multidevice_corpus_markdown.raw"
INVALID_JSON="$RCH_INPUT_DIR/btrfs_multidevice_corpus_invalid.json"
INVALID_RAW="$E2E_LOG_DIR/btrfs_multidevice_corpus_invalid.raw"
UNIT_LOG="$E2E_LOG_DIR/btrfs_multidevice_corpus_unit_tests.log"
UNIT_TESTS_OK=0
mkdir -p "$RCH_INPUT_DIR"

e2e_step "Scenario 1: btrfs multi-device corpus CLI is wired"
if grep -q "pub mod btrfs_multidevice_corpus" crates/ffs-harness/src/lib.rs \
    && grep -q "validate-btrfs-multidevice-corpus" crates/ffs-harness/src/main.rs \
    && grep -q "ffs_btrfs_multidevice_corpus" scripts/e2e/scenario_catalog.json; then
    scenario_result "btrfs_multidevice_corpus_cli_wired" "PASS" "module, CLI command, and catalog suite are exported"
else
    scenario_result "btrfs_multidevice_corpus_cli_wired" "FAIL" "missing module export, CLI command, or catalog suite"
fi

e2e_step "Scenario 2: checked-in btrfs multi-device corpus validates"
if e2e_rch_capture "$VALIDATE_RAW" cargo run --quiet -p ffs-harness -- \
    validate-btrfs-multidevice-corpus \
    --corpus "$CORPUS_JSON" \
    && extract_report_json "$VALIDATE_RAW" "$REPORT_JSON"; then
    scenario_result "btrfs_multidevice_corpus_validates" "PASS" "checked-in corpus accepted"
else
    cat "$VALIDATE_RAW"
    scenario_result "btrfs_multidevice_corpus_validates" "FAIL" "checked-in corpus rejected"
fi

e2e_step "Scenario 3: corpus report preserves scenario-kind and profile coverage"
if python3 - "$REPORT_JSON" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
required_kinds = {
    "healthy_assembly",
    "device_order_permutation",
    "missing_device",
    "duplicate_device_id",
    "stale_superblock",
    "unsupported_profile",
}
required_profiles = {"raid1", "raid5"}
if not report["valid"]:
    raise SystemExit(report["errors"])
if report["scenario_count"] < 6:
    raise SystemExit("expected at least six multi-device scenarios")
missing_kinds = required_kinds - set(report["scenario_kinds"])
if missing_kinds:
    raise SystemExit(f"missing scenario kinds: {sorted(missing_kinds)}")
missing_profiles = required_profiles - set(report["profiles"])
if missing_profiles:
    raise SystemExit(f"missing profiles: {sorted(missing_profiles)}")
PY
then
    scenario_result "btrfs_multidevice_corpus_coverage" "PASS" "scenario kinds and profiles verified"
else
    scenario_result "btrfs_multidevice_corpus_coverage" "FAIL" "multi-device coverage contract failed"
fi

e2e_step "Scenario 4: invalid btrfs multi-device corpus fails closed"
jq 'del(.scenarios[0].devices[0].image_hash)' "$CORPUS_JSON" >"$INVALID_JSON"
if e2e_rch_capture "$INVALID_RAW" cargo run --quiet -p ffs-harness -- \
    validate-btrfs-multidevice-corpus \
    --corpus "$INVALID_JSON"; then
    scenario_result "btrfs_multidevice_corpus_invalid_rejected" "FAIL" "invalid corpus unexpectedly passed"
elif grep -q "image_hash" "$INVALID_RAW" \
    || grep -q "failed to parse btrfs multi-device corpus JSON" "$INVALID_RAW"; then
    scenario_result "btrfs_multidevice_corpus_invalid_rejected" "PASS" "missing device image hash is rejected"
else
    cat "$INVALID_RAW"
    scenario_result "btrfs_multidevice_corpus_invalid_rejected" "FAIL" "invalid corpus failed without actionable diagnostics"
fi

e2e_step "Scenario 5: Markdown summary and docs contract are wired"
if e2e_rch_capture "$MARKDOWN_RAW" cargo run --quiet -p ffs-harness -- \
    validate-btrfs-multidevice-corpus \
    --corpus "$CORPUS_JSON" \
    --format markdown \
    && grep -q "# Btrfs Multi-Device Corpus" "$MARKDOWN_RAW" \
    && grep -q "unsupported_profile" "$MARKDOWN_RAW" \
    && grep -q "Btrfs Multi-Device Corpus Contract" scripts/e2e/README.md; then
    scenario_result "btrfs_multidevice_corpus_markdown_docs" "PASS" "Markdown summary and docs wording are present"
else
    cat "$MARKDOWN_RAW"
    scenario_result "btrfs_multidevice_corpus_markdown_docs" "FAIL" "Markdown summary or docs contract missing"
fi

e2e_step "Scenario 6: btrfs multi-device corpus unit tests pass"
if e2e_rch_capture "$UNIT_LOG" cargo test -p ffs-harness --lib btrfs_multidevice_corpus -- --nocapture; then
    UNIT_TESTS_OK=1
    for test_name in \
        "default_corpus_validates_required_kinds" \
        "render_markdown_summarizes_default_corpus" \
        "malformed_device_image_hash_is_rejected"; do
        if ! grep -q "$test_name" "$UNIT_LOG"; then
            UNIT_TESTS_OK=0
        fi
    done
fi

if ((UNIT_TESTS_OK == 1)); then
    scenario_result "btrfs_multidevice_corpus_unit_tests" "PASS" "focused unit tests passed"
else
    cat "$UNIT_LOG"
    scenario_result "btrfs_multidevice_corpus_unit_tests" "FAIL" "focused unit tests failed"
fi

e2e_log "Btrfs multi-device corpus: $CORPUS_JSON"
e2e_log "Validation report: $REPORT_JSON"

if ((FAIL_COUNT == 0)); then
    e2e_log "Btrfs multi-device corpus scenarios passed: $PASS_COUNT/$TOTAL"
    e2e_pass
else
    e2e_fail "Btrfs multi-device corpus scenarios failed: ${FAIL_COUNT}/${TOTAL}"
fi
