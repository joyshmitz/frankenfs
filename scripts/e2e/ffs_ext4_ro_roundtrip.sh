#!/usr/bin/env bash
# ffs_ext4_ro_roundtrip.sh - ext4 read-only round-trip E2E test for FrankenFS
#
# Validates ext4 read-path fidelity by comparing an image extracted via
# debugfs with the FUSE-mounted view:
# - fixture image preparation
# - ffs inspect metadata verification
# - read-only mount lifecycle
# - full tree + content hash manifest equality

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"
export REPO_ROOT

source "$REPO_ROOT/scripts/e2e/lib.sh"

export RUST_LOG="${RUST_LOG:-trace}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenfs_ext4_ro_roundtrip}"
export FFS_AUTO_UNMOUNT="${FFS_AUTO_UNMOUNT:-0}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_VISIBILITY="${RCH_VISIBILITY:-summary}"
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-900}"
FFS_CLI_BIN="${FFS_CLI_BIN:-$CARGO_TARGET_DIR/release/ffs-cli}"

for rch_env_var in CARGO_TARGET_DIR RUST_LOG RUST_BACKTRACE FFS_AUTO_UNMOUNT; do
    case ",${RCH_ENV_ALLOWLIST:-}," in
        *",${rch_env_var},"*) ;;
        *) export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}${rch_env_var}" ;;
    esac
done

e2e_init "ffs_ext4_ro_roundtrip"
e2e_print_env

CURRENT_MOUNT_PID=""
CURRENT_MOUNT_LOG=""
CURRENT_MOUNT_POINT=""
MAX_DURATION_SECS="${EXT4_ROUNDTRIP_MAX_SECS:-30}"
BLAKE3_BACKEND=""
PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0
ROUNDTRIP_START_TIME=""

if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    e2e_skip "rch not found; this suite requires offloaded cargo execution"
fi

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

cancel_matching_rch_queue_entry() {
    local command_text="$*"
    local queue_json
    local ids
    if ! command -v jq >/dev/null 2>&1; then
        return 0
    fi
    queue_json="$("$RCH_BIN" queue --json 2>/dev/null || true)"
    if [[ -z "$queue_json" ]]; then
        return 0
    fi
    ids="$(jq -r --arg cmd "$command_text" '
        .data.active_builds[]?
        | select(.project_id | startswith("frankenfs-"))
        | select(.command == $cmd)
        | .id
    ' <<<"$queue_json" || true)"
    for id in $ids; do
        if "$RCH_BIN" cancel "$id" >/dev/null 2>&1; then
            e2e_log "RCH_STALE_QUEUE_CANCELLED|id=${id}|command=${command_text}"
        fi
    done
}

run_rch_capture() {
    local output_path="$1"
    local status=0
    local pid
    local deadline
    local remote_exit=""
    local required_artifact="${RCH_REQUIRED_ARTIFACT:-}"
    local wait_status
    shift

    : >"$output_path"
    set +e
    RCH_VISIBILITY="$RCH_VISIBILITY" "$RCH_BIN" exec -- "$@" >"$output_path" 2>&1 &
    pid=$!
    set -e

    deadline=$((SECONDS + RCH_COMMAND_TIMEOUT_SECS))
    while kill -0 "$pid" >/dev/null 2>&1; do
        remote_exit="$(sed -n 's/.*Remote command finished: exit=\([0-9][0-9]*\).*/\1/p' "$output_path" | tail -n 1)"
        if [[ -n "$remote_exit" && -n "$required_artifact" && -e "$required_artifact" ]]; then
            e2e_log "RCH_REQUIRED_ARTIFACT_READY|artifact=${required_artifact}|output=${output_path}"
            kill -TERM "$pid" >/dev/null 2>&1 || true
            cancel_matching_rch_queue_entry "$@"
            break
        fi
        if ((SECONDS >= deadline)); then
            e2e_log "RCH_TIMEOUT|seconds=${RCH_COMMAND_TIMEOUT_SECS}|output=${output_path}"
            kill -TERM "$pid" >/dev/null 2>&1 || true
            cancel_matching_rch_queue_entry "$@"
            status=124
            break
        fi
        sleep 2
    done

    set +e
    wait "$pid" >/dev/null 2>&1
    wait_status=$?
    set -e
    if [[ $status -eq 0 ]]; then
        if [[ -n "$remote_exit" ]]; then
            status="$remote_exit"
        else
            status="$wait_status"
        fi
    fi

    if grep -Fq "[RCH] local" "$output_path" || grep -Fq "exec called with non-compilation command" "$output_path"; then
        e2e_log "RCH_LOCAL_FALLBACK_REJECTED|output=${output_path}"
        printf 'RCH_LOCAL_FALLBACK_REJECTED|output=%s\n' "$output_path" >>"$output_path"
        return 99
    fi
    if [[ $status -eq 0 ]]; then
        if ! grep -Fq "[RCH] remote" "$output_path" && ! grep -Fq "Remote command finished: exit=0" "$output_path"; then
            e2e_log "RCH_REMOTE_EVIDENCE_MISSING|output=${output_path}"
            printf 'RCH_REMOTE_EVIDENCE_MISSING|output=%s\n' "$output_path" >>"$output_path"
            return 99
        fi
        return 0
    fi
    return "$status"
}

print_rch_log() {
    local output_path="$1"
    if [[ -s "$output_path" ]]; then
        tee -a "$E2E_LOG_FILE" <"$output_path"
    fi
}

run_remote_build() {
    local output_path="$E2E_LOG_DIR/build_ffs_cli.log"

    if RCH_REQUIRED_ARTIFACT="$FFS_CLI_BIN" run_rch_capture "$output_path" cargo build -p ffs-cli --release; then
        if [[ ! -x "$FFS_CLI_BIN" ]]; then
            scenario_result \
                "ext4_ro_roundtrip_cli_build" \
                "FAIL" \
                "ffs-cli build succeeded but binary missing at ${FFS_CLI_BIN}; log=${output_path}"
            e2e_fail "ffs-cli binary missing after RCH build: $FFS_CLI_BIN"
        fi
        scenario_result \
            "ext4_ro_roundtrip_cli_build" \
            "PASS" \
            "ffs-cli release build; binary=${FFS_CLI_BIN}; log=${output_path}"
    else
        print_rch_log "$output_path"
        scenario_result \
            "ext4_ro_roundtrip_cli_build" \
            "FAIL" \
            "ffs-cli release build failed; log=${output_path}"
        e2e_fail "ffs-cli release build failed"
    fi
}

require_tools() {
    if ! command -v python3 >/dev/null 2>&1; then
        e2e_skip "python3 not found (required for manifest + metadata checks)"
    fi
    if ! command -v debugfs >/dev/null 2>&1; then
        e2e_skip "debugfs not found (required for reference extraction)"
    fi
    if ! command -v mountpoint >/dev/null 2>&1; then
        e2e_skip "mountpoint utility not found"
    fi
    if command -v b3sum >/dev/null 2>&1; then
        BLAKE3_BACKEND="b3sum"
        return
    fi
    if python3 - <<'PY' >/dev/null 2>&1
import importlib.util
import sys
sys.exit(0 if importlib.util.find_spec("blake3") else 1)
PY
    then
        BLAKE3_BACKEND="python-blake3"
        return
    fi

    BLAKE3_BACKEND="python-sha256"
}

prepare_ext4_image() {
    local work_image="$1"
    local default_fixture="$REPO_ROOT/tests/fixtures/images/ext4_small.img"
    local configured_image="${EXT4_ROUNDTRIP_IMAGE:-}"

    if [[ -n "$configured_image" ]]; then
        if [[ ! -f "$configured_image" ]]; then
            e2e_fail "Configured EXT4_ROUNDTRIP_IMAGE does not exist: $configured_image"
        fi
        e2e_step "Using configured ext4 image fixture"
        e2e_assert cp "$configured_image" "$work_image"
        e2e_log "Fixture source: $configured_image"
        return
    fi

    if [[ -f "$default_fixture" ]]; then
        e2e_step "Using default ext4 image fixture"
        e2e_assert cp "$default_fixture" "$work_image"
        e2e_log "Fixture source: $default_fixture"
        return
    fi

    e2e_step "Creating fallback ext4 fixture image"
    e2e_log "No fixture image found under tests/fixtures/images; generating deterministic fallback"
    e2e_create_ext4_image "$work_image" 64
}

build_reference_tree() {
    local image="$1"
    local reference_root="$2"

    e2e_assert mkdir -p "$reference_root"
    e2e_assert debugfs -R "rdump / $reference_root" "$image"
}

build_blake3_manifest() {
    local root="$1"
    local output_path="$2"
    local label="$3"
    local backend="$4"

    e2e_assert python3 - "$root" "$output_path" "$label" "$backend" <<'PY'
import json
import os
import pathlib
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
output_path = pathlib.Path(sys.argv[2])
label = sys.argv[3]
backend = sys.argv[4]

if backend == "python-blake3":
    try:
        import blake3
    except ImportError as exc:
        raise SystemExit(f"{label}: python backend requested but blake3 module missing: {exc}") from exc
elif backend == "python-sha256":
    import hashlib

if not root.exists():
    raise SystemExit(f"{label}: root path does not exist: {root}")

entries = []
for path in sorted(root.rglob("*"), key=lambda p: p.as_posix()):
    rel = path.relative_to(root).as_posix()
    if not rel:
        continue
    if path.is_dir():
        entries.append({"path": rel, "kind": "dir"})
        continue
    if path.is_symlink():
        entries.append(
            {
                "path": rel,
                "kind": "symlink",
                "target": os.readlink(path),
            }
        )
        continue
    if path.is_file():
        if backend == "b3sum":
            digest = subprocess.check_output(["b3sum", str(path)], text=True).split()[0]
            digest_key = "blake3"
        elif backend == "python-blake3":
            digest = blake3.blake3(path.read_bytes()).hexdigest()
            digest_key = "blake3"
        elif backend == "python-sha256":
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            digest_key = "sha256"
        else:
            raise SystemExit(f"{label}: unsupported content hash backend: {backend}")
        entry = {
            "path": rel,
            "kind": "file",
            "size": path.stat().st_size,
        }
        entry[digest_key] = digest
        entries.append(entry)
        continue
    entries.append({"path": rel, "kind": "other"})

payload = {
    "root": str(root),
    "entry_count": len(entries),
    "hash_backend": backend,
    "entries": entries,
}
output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
print(f"{label}: wrote {len(entries)} entries -> {output_path} (backend={backend})")
PY
}

assert_manifests_equal() {
    local expected="$1"
    local actual="$2"

    e2e_assert python3 - "$expected" "$actual" <<'PY'
import json
import sys

expected = json.loads(open(sys.argv[1], encoding="utf-8").read())
actual = json.loads(open(sys.argv[2], encoding="utf-8").read())

e_entries = expected["entries"]
a_entries = actual["entries"]

if e_entries != a_entries:
    e_map = {(entry["path"], entry["kind"]): entry for entry in e_entries}
    a_map = {(entry["path"], entry["kind"]): entry for entry in a_entries}

    missing = sorted(set(e_map.keys()) - set(a_map.keys()))
    unexpected = sorted(set(a_map.keys()) - set(e_map.keys()))
    mismatched = []
    for key in sorted(set(e_map.keys()) & set(a_map.keys())):
        if e_map[key] != a_map[key]:
            mismatched.append(key)
        if len(mismatched) >= 20:
            break

    print("Manifest mismatch detected")
    print(f"  expected_entries={len(e_entries)} actual_entries={len(a_entries)}")
    if missing:
        print("  missing entries (sample):", missing[:20])
    if unexpected:
        print("  unexpected entries (sample):", unexpected[:20])
    if mismatched:
        print("  content mismatches (sample):", mismatched[:20])
    raise SystemExit(1)

print(f"Manifest comparison OK ({len(e_entries)} entries)")
PY
}

assert_inspect_metadata() {
    local inspect_json="$1"

    e2e_assert python3 - "$inspect_json" <<'PY'
import json
import sys

data = json.loads(open(sys.argv[1], encoding="utf-8").read())

if data.get("filesystem") != "ext4":
    raise SystemExit(f"expected filesystem=ext4, got {data.get('filesystem')!r}")

required_positive_ints = ("block_size", "inodes_count", "blocks_count")
for key in required_positive_ints:
    value = data.get(key)
    if not isinstance(value, int) or value <= 0:
        raise SystemExit(f"invalid {key}: {value!r}")

required_non_negative_ints = ("free_blocks_total", "free_inodes_total")
for key in required_non_negative_ints:
    value = data.get(key)
    if not isinstance(value, int) or value < 0:
        raise SystemExit(f"invalid {key}: {value!r}")

if data.get("free_space_mismatch") is not None:
    raise SystemExit(f"group descriptor mismatch reported: {data['free_space_mismatch']!r}")

orph = data.get("orphan_diagnostics")
if orph is not None:
    count = orph.get("count")
    samples = orph.get("sample_inodes")
    if not isinstance(count, int) or count < 0:
        raise SystemExit(f"invalid orphan count: {count!r}")
    if not isinstance(samples, list):
        raise SystemExit(f"invalid orphan sample list: {samples!r}")

print("Inspect metadata assertions OK")
PY
}

wait_for_mount_ready() {
    local mount_point="$1"
    local pid="$2"
    local timeout_seconds="${3:-20}"
    local elapsed=0

    while true; do
        if mountpoint -q "$mount_point" 2>/dev/null; then
            return 0
        fi
        if [[ -n "${CURRENT_MOUNT_LOG:-}" ]] && [[ -f "$CURRENT_MOUNT_LOG" ]]; then
            if grep -q "INIT response" "$CURRENT_MOUNT_LOG"; then
                return 0
            fi
        fi

        sleep 0.5
        elapsed=$((elapsed + 1))

        if ! kill -0 "$pid" 2>/dev/null; then
            return 1
        fi
        if [[ $elapsed -ge $((timeout_seconds * 2)) ]]; then
            return 2
        fi
    done
}

start_mount_ro() {
    local image="$1"
    local mount_point="$2"
    local timeout_seconds="${3:-20}"

    if [[ "${SKIP_MOUNT:-0}" == "1" ]]; then
        scenario_result \
            "ext4_ro_roundtrip_mount_manifest" \
            "PASS" \
            "skipped: mount tests skipped with SKIP_MOUNT=1"
        e2e_skip "mount tests skipped (SKIP_MOUNT=1)"
    fi
    if [[ ! -e /dev/fuse ]]; then
        scenario_result \
            "ext4_ro_roundtrip_mount_manifest" \
            "PASS" \
            "skipped: /dev/fuse not available"
        e2e_skip "/dev/fuse not available"
    fi
    if [[ ! -r /dev/fuse ]] || [[ ! -w /dev/fuse ]]; then
        scenario_result \
            "ext4_ro_roundtrip_mount_manifest" \
            "PASS" \
            "skipped: /dev/fuse not accessible"
        e2e_skip "/dev/fuse not accessible"
    fi

    mkdir -p "$mount_point"
    E2E_MOUNT_POINT="$mount_point"
    CURRENT_MOUNT_POINT="$mount_point"
    CURRENT_MOUNT_LOG="$E2E_LOG_DIR/mount_ro.log"

    local cmd=("$FFS_CLI_BIN" mount "$image" "$mount_point")
    e2e_log "Starting mount command: ${cmd[*]}"
    e2e_log "Mount log: $CURRENT_MOUNT_LOG"
    "${cmd[@]}" >"$CURRENT_MOUNT_LOG" 2>&1 &
    CURRENT_MOUNT_PID=$!

    local ready_result=0
    if wait_for_mount_ready "$mount_point" "$CURRENT_MOUNT_PID" "$timeout_seconds"; then
        ready_result=0
    else
        ready_result=$?
    fi

    if [[ $ready_result -eq 0 ]]; then
        e2e_log "Mount ready at $mount_point (pid=$CURRENT_MOUNT_PID)"
        return 0
    fi

    local mount_rc=0
    if kill -0 "$CURRENT_MOUNT_PID" 2>/dev/null; then
        kill "$CURRENT_MOUNT_PID" 2>/dev/null || true
        wait "$CURRENT_MOUNT_PID" 2>/dev/null || true
        mount_rc=124
    else
        wait "$CURRENT_MOUNT_PID" 2>/dev/null || mount_rc=$?
    fi

    e2e_log "Mount failed (rc=$mount_rc), tailing log:"
    e2e_run tail -n 120 "$CURRENT_MOUNT_LOG" || true

    if grep -qiE "option allow_other only allowed if 'user_allow_other' is set" "$CURRENT_MOUNT_LOG"; then
        scenario_result \
            "ext4_ro_roundtrip_mount_manifest" \
            "PASS" \
            "skipped: FUSE user_allow_other not enabled; log=${CURRENT_MOUNT_LOG}"
        e2e_skip "FUSE is present but user_allow_other is not enabled in /etc/fuse.conf"
    fi
    if grep -qiE "fusermount3: mount failed: Permission denied|fusermount: failed to open /dev/fuse: Operation not permitted|fusermount: mount failed: Operation not permitted" "$CURRENT_MOUNT_LOG"; then
        scenario_result \
            "ext4_ro_roundtrip_mount_manifest" \
            "PASS" \
            "skipped: FUSE mount not permitted in this environment; log=${CURRENT_MOUNT_LOG}"
        e2e_skip "FUSE is present but mount is not permitted in this environment"
    fi
    if [[ $ready_result -eq 2 ]]; then
        e2e_fail "Mount timed out after ${timeout_seconds}s"
    fi
    e2e_fail "Mount process exited before mount became ready"
}

stop_mount() {
    local mount_point="${1:-$CURRENT_MOUNT_POINT}"

    e2e_unmount "$mount_point"

    if [[ -n "$CURRENT_MOUNT_PID" ]] && kill -0 "$CURRENT_MOUNT_PID" 2>/dev/null; then
        kill "$CURRENT_MOUNT_PID" 2>/dev/null || true
        sleep 0.5
        if kill -0 "$CURRENT_MOUNT_PID" 2>/dev/null; then
            kill -9 "$CURRENT_MOUNT_PID" 2>/dev/null || true
        fi
    fi
    if [[ -n "$CURRENT_MOUNT_PID" ]]; then
        wait "$CURRENT_MOUNT_PID" 2>/dev/null || true
    fi

    CURRENT_MOUNT_PID=""
    CURRENT_MOUNT_POINT=""
}

verify_journal_replay_reporting() {
    local mount_log="$1"
    if grep -q "crash recovery:" "$mount_log"; then
        if grep -q "journal replay:" "$mount_log"; then
            e2e_log "Journal replay evidence present in mount log"
        else
            e2e_log "Crash recovery reported with zero replayed journal transactions (journal likely empty)"
        fi
    else
        e2e_log "No crash recovery required; journal replay check not applicable for this image"
    fi
}

e2e_step "Phase 1: Preconditions and build"
require_tools
e2e_log "Content hash backend: $BLAKE3_BACKEND"
run_remote_build
e2e_assert_file "$FFS_CLI_BIN"
ROUNDTRIP_START_TIME="$(date +%s)"

e2e_step "Phase 2: Fixture preparation"
WORK_IMAGE="$E2E_TEMP_DIR/ext4_roundtrip_work.img"
prepare_ext4_image "$WORK_IMAGE"
e2e_assert_file "$WORK_IMAGE"
scenario_result \
    "ext4_ro_roundtrip_fixture_prepared" \
    "PASS" \
    "work image ready at ${WORK_IMAGE}"

REFERENCE_ROOT="$E2E_TEMP_DIR/reference_tree"
REFERENCE_MANIFEST="$E2E_LOG_DIR/reference_manifest.json"
MOUNT_MANIFEST="$E2E_LOG_DIR/mount_manifest.json"
INSPECT_JSON="$E2E_LOG_DIR/inspect_ext4.json"

e2e_step "Phase 3: Build debugfs reference extraction + manifest"
build_reference_tree "$WORK_IMAGE" "$REFERENCE_ROOT"
build_blake3_manifest "$REFERENCE_ROOT" "$REFERENCE_MANIFEST" "reference" "$BLAKE3_BACKEND"
e2e_assert_file "$REFERENCE_MANIFEST"
scenario_result \
    "ext4_ro_roundtrip_reference_manifest" \
    "PASS" \
    "debugfs reference manifest built at ${REFERENCE_MANIFEST}"

e2e_step "Phase 4: Inspect metadata (superblock/group/inode signals)"
e2e_assert bash -lc "RUST_LOG=off \"$FFS_CLI_BIN\" inspect \"$WORK_IMAGE\" --json > \"$INSPECT_JSON\""
e2e_assert_file "$INSPECT_JSON"
assert_inspect_metadata "$INSPECT_JSON"
scenario_result \
    "ext4_ro_roundtrip_inspect_metadata" \
    "PASS" \
    "inspect metadata assertions passed; json=${INSPECT_JSON}"

e2e_step "Phase 5: Read-only mount + full tree/BLAKE3 verification"
MOUNT_POINT="$E2E_TEMP_DIR/mnt_ext4_roundtrip"
start_mount_ro "$WORK_IMAGE" "$MOUNT_POINT" 20
build_blake3_manifest "$MOUNT_POINT" "$MOUNT_MANIFEST" "mounted" "$BLAKE3_BACKEND"
assert_manifests_equal "$REFERENCE_MANIFEST" "$MOUNT_MANIFEST"
verify_journal_replay_reporting "$CURRENT_MOUNT_LOG"
stop_mount "$MOUNT_POINT"
scenario_result \
    "ext4_ro_roundtrip_mount_manifest" \
    "PASS" \
    "mounted tree manifest matched reference; manifest=${MOUNT_MANIFEST}"

if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
    e2e_fail "Failed to unmount mount point: $MOUNT_POINT"
fi

e2e_step "Phase 6: Runtime bound check"
elapsed_secs=$(( $(date +%s) - ROUNDTRIP_START_TIME ))
e2e_log "Elapsed seconds: $elapsed_secs"
if (( elapsed_secs > MAX_DURATION_SECS )); then
    e2e_fail "Round-trip exceeded time budget: ${elapsed_secs}s > ${MAX_DURATION_SECS}s"
fi
scenario_result \
    "ext4_ro_roundtrip_runtime_bound" \
    "PASS" \
    "roundtrip runtime ${elapsed_secs}s <= ${MAX_DURATION_SECS}s"

e2e_log "Scenario totals: passed=${PASS_COUNT} failed=${FAIL_COUNT} total=${TOTAL}"
e2e_pass
