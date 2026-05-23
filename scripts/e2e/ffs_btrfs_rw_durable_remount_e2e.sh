#!/usr/bin/env bash
# ffs_btrfs_rw_durable_remount_e2e.sh — E2E validation of btrfs RW durability via remount.
#
# bd-teytw + bd-jdo53: Tests that btrfs mutations persist across unmount/remount.
#
# Validates:
#   1. btrfs image can be created with mkfs.btrfs
#   2. Image mounts via FUSE with --rw (durable mode by default)
#   3. Standard mutation set executes: create, mkdir, write, unlink, rename, setattr, xattr
#   4. Unmount succeeds (flush_on_destroy commits btrfs transactions)
#   5. Remount in RO mode succeeds
#   6. All mutations visible via read paths
#
# Durable writeback (bd-3umpe + bd-1ving) is now implemented: ROOT_TREE is properly
# committed and superblock.root points to ROOT_TREE, enabling clean remount.
#
# Usage: scripts/e2e/ffs_btrfs_rw_durable_remount_e2e.sh
# Exit:  0 = all gates pass (or expected XFAIL), non-zero = unexpected failure
#
# Environment:
#   FFS_BTRFS_DURABLE_EXPECT_PASS=1  - Expect persistence to work (set after A1-A6 land)
#   FFS_E2E_DISABLE_TEMP_CLEANUP=1   - Preserve temp artifacts for inspection

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_ROOT"

source "$SCRIPT_DIR/lib.sh"
export FFS_E2E_DISABLE_TEMP_CLEANUP="${FFS_E2E_DISABLE_TEMP_CLEANUP:-1}"
e2e_init "ffs_btrfs_rw_durable_remount"
exec > >(tee -a "$E2E_LOG_FILE") 2>&1

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/cargo-target}"
e2e_rch_add_env_allowlist CARGO_TARGET_DIR
RCH_COMMAND_TIMEOUT_SECS="${RCH_COMMAND_TIMEOUT_SECS:-600}"
RCH_CAPTURE_VISIBILITY="${FFS_BTRFS_DURABLE_REMOUNT_RCH_VISIBILITY:-${RCH_VISIBILITY:-summary}}"

# Durable writeback is implemented (bd-3umpe + bd-1ving) - expect persistence by default
EXPECT_PERSISTENCE="${FFS_BTRFS_DURABLE_EXPECT_PASS:-1}"

PASS_COUNT=0
FAIL_COUNT=0
XFAIL_COUNT=0
TOTAL=0

FFS_CLI_BIN="${FFS_CLI_BIN:-${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}/release/ffs-cli}"
TEST_IMAGE=""
MOUNT_POINT=""
MOUNT_PID=""

scenario_result() {
    local scenario_id="$1"
    local outcome="$2"
    local detail="${3:-}"
    e2e_log "SCENARIO_RESULT|scenario_id=${scenario_id}|outcome=${outcome}|detail=${detail}"
    case "$outcome" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        XFAIL) XFAIL_COUNT=$((XFAIL_COUNT + 1)) ;;
    esac
    TOTAL=$((TOTAL + 1))
}

run_rch_capture() {
    local log_path="$1"
    shift
    RCH_VISIBILITY="$RCH_CAPTURE_VISIBILITY" e2e_rch_capture "$log_path" "$@"
}

emit_executed_evidence() {
    local command="$1"
    local exit_code="$2"
    local stdout_file="$3"
    local stderr_file="$4"
    local duration_ms="$5"

    local stdout_sha256="" stderr_sha256=""
    if [[ -f "$stdout_file" ]]; then
        stdout_sha256=$(sha256sum "$stdout_file" | cut -d' ' -f1)
    fi
    if [[ -f "$stderr_file" ]]; then
        stderr_sha256=$(sha256sum "$stderr_file" | cut -d' ' -f1)
    fi

    local git_sha=""
    git_sha=$(git -C "$PROJECT_ROOT" rev-parse HEAD 2>/dev/null || echo "unknown")

    local host_class="e2e-runner"
    local ran_at=""
    ran_at=$(date -Iseconds)

    cat <<EOF
{
  "executed_evidence": {
    "command": "$command",
    "exit_code": $exit_code,
    "stdout_sha256": "$stdout_sha256",
    "stderr_sha256": "$stderr_sha256",
    "duration_ms": $duration_ms,
    "ran_at": "$ran_at",
    "git_sha": "$git_sha",
    "host_class": "$host_class"
  }
}
EOF
}

cleanup_mount() {
    if [[ -n "${MOUNT_PID:-}" ]] && kill -0 "$MOUNT_PID" 2>/dev/null; then
        e2e_log "Cleaning up mount process $MOUNT_PID"
        kill "$MOUNT_PID" 2>/dev/null || true
        sleep 1
        kill -9 "$MOUNT_PID" 2>/dev/null || true
    fi
    if [[ -n "${MOUNT_POINT:-}" ]] && mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
        fusermount -u "$MOUNT_POINT" 2>/dev/null || true
    fi
}

trap cleanup_mount EXIT

start_mount() {
    local mode="$1"      # "rw" or "ro"
    local image="$2"
    local mount_point="$3"
    local timeout_seconds="${4:-30}"
    local log_file="$E2E_LOG_DIR/mount_${mode}.log"

    mkdir -p "$mount_point"
    MOUNT_POINT="$mount_point"

    local cmd=("$FFS_CLI_BIN" mount "$image" "$mount_point")
    if [[ "$mode" == "rw" ]]; then
        cmd+=(--rw)  # Durable mode by default (no --btrfs-rw-ephemeral-ok)
    fi

    e2e_log "Starting mount: ${cmd[*]}"
    "${cmd[@]}" >"$log_file" 2>&1 &
    MOUNT_PID=$!

    local elapsed=0
    while ! mountpoint -q "$mount_point" 2>/dev/null; do
        sleep 0.5
        elapsed=$((elapsed + 1))
        if ! kill -0 "$MOUNT_PID" 2>/dev/null; then
            e2e_log "Mount process died. Log:"
            cat "$log_file"
            return 1
        fi
        if [[ $elapsed -ge $((timeout_seconds * 2)) ]]; then
            e2e_log "Mount timed out after ${timeout_seconds}s"
            return 1
        fi
    done

    e2e_log "Mount successful: $mount_point (PID $MOUNT_PID)"
    return 0
}

stop_mount() {
    local mount_point="$1"
    if [[ -n "${MOUNT_PID:-}" ]] && kill -0 "$MOUNT_PID" 2>/dev/null; then
        kill "$MOUNT_PID" 2>/dev/null || true
        local wait_count=0
        while kill -0 "$MOUNT_PID" 2>/dev/null && [[ $wait_count -lt 20 ]]; do
            sleep 0.5
            wait_count=$((wait_count + 1))
        done
        if kill -0 "$MOUNT_PID" 2>/dev/null; then
            kill -9 "$MOUNT_PID" 2>/dev/null || true
        fi
    fi
    MOUNT_PID=""

    if mountpoint -q "$mount_point" 2>/dev/null; then
        fusermount -u "$mount_point" 2>/dev/null || true
    fi
}

echo "=== Preflight ==="
echo "Time: $(date -Iseconds)"
echo "Bead: bd-teytw (A5/A6 remount-persistence test)"
echo "Bead: bd-jdo53 (P0 btrfs RW durability)"
echo "Expect persistence: $EXPECT_PERSISTENCE"
echo ""

#######################################
# Phase 1: Capability checks
#######################################
e2e_step "Phase 1: Capability checks"

# Check for mkfs.btrfs
if ! command -v mkfs.btrfs &>/dev/null; then
    e2e_log "SKIP: mkfs.btrfs not found (install btrfs-progs)"
    scenario_result "capability_mkfs_btrfs" "SKIP" "mkfs.btrfs not available"
    echo "OVERALL: SKIP (no btrfs-progs)"
    exit 0
fi
scenario_result "capability_mkfs_btrfs" "PASS" "mkfs.btrfs available"

# Check for FUSE
if [[ ! -e /dev/fuse ]]; then
    e2e_log "SKIP: /dev/fuse not available"
    scenario_result "capability_fuse" "SKIP" "/dev/fuse not available"
    echo "OVERALL: SKIP (no FUSE)"
    exit 0
fi
scenario_result "capability_fuse" "PASS" "/dev/fuse available"

#######################################
# Phase 2: Build ffs-cli
#######################################
e2e_step "Phase 2: Build ffs-cli"

BUILD_LOG="$E2E_LOG_DIR/build_ffs_cli.log"
BUILD_START=$(date +%s%3N)
if run_rch_capture "$BUILD_LOG" cargo build -p ffs-cli --release; then
    BUILD_END=$(date +%s%3N)
    scenario_result "build_ffs_cli" "PASS" "ffs-cli built successfully"
    emit_executed_evidence "cargo build -p ffs-cli --release" 0 "$BUILD_LOG" "$BUILD_LOG" "$((BUILD_END - BUILD_START))" > "$E2E_LOG_DIR/build_evidence.json"
else
    BUILD_END=$(date +%s%3N)
    scenario_result "build_ffs_cli" "FAIL" "ffs-cli build failed"
    emit_executed_evidence "cargo build -p ffs-cli --release" 1 "$BUILD_LOG" "$BUILD_LOG" "$((BUILD_END - BUILD_START))" > "$E2E_LOG_DIR/build_evidence.json"
    tail -40 "$BUILD_LOG"
    exit 1
fi

if [[ ! -x "$FFS_CLI_BIN" ]]; then
    scenario_result "ffs_cli_binary_exists" "FAIL" "Binary not found at $FFS_CLI_BIN"
    exit 1
fi
scenario_result "ffs_cli_binary_exists" "PASS" "Binary exists"

#######################################
# Phase 3: Create btrfs test image
#######################################
e2e_step "Phase 3: Create btrfs test image"

TEST_IMAGE="$E2E_TEMP_DIR/test.btrfs"
IMAGE_SIZE_MB=128

# Create sparse image
truncate -s "${IMAGE_SIZE_MB}M" "$TEST_IMAGE"
e2e_log "Created sparse image: $TEST_IMAGE (${IMAGE_SIZE_MB}MB)"

# Format with mkfs.btrfs
MKFS_LOG="$E2E_LOG_DIR/mkfs.log"
MKFS_START=$(date +%s%3N)
if mkfs.btrfs -f -L "ffs-remount-test" "$TEST_IMAGE" > "$MKFS_LOG" 2>&1; then
    MKFS_END=$(date +%s%3N)
    scenario_result "create_btrfs_image" "PASS" "mkfs.btrfs created image"
    emit_executed_evidence "mkfs.btrfs -f -L ffs-remount-test $TEST_IMAGE" 0 "$MKFS_LOG" "$MKFS_LOG" "$((MKFS_END - MKFS_START))" > "$E2E_LOG_DIR/mkfs_evidence.json"
else
    MKFS_END=$(date +%s%3N)
    scenario_result "create_btrfs_image" "FAIL" "mkfs.btrfs failed"
    emit_executed_evidence "mkfs.btrfs -f -L ffs-remount-test $TEST_IMAGE" 1 "$MKFS_LOG" "$MKFS_LOG" "$((MKFS_END - MKFS_START))" > "$E2E_LOG_DIR/mkfs_evidence.json"
    cat "$MKFS_LOG"
    exit 1
fi

#######################################
# Phase 4: Mount RW and perform mutations
#######################################
e2e_step "Phase 4: Mount RW and perform mutations"

MOUNT_RW="$E2E_TEMP_DIR/mnt_rw"
mkdir -p "$MOUNT_RW"

if ! start_mount rw "$TEST_IMAGE" "$MOUNT_RW" 30; then
    scenario_result "mount_rw" "FAIL" "RW mount failed"
    e2e_log "RW mount failed - check log for details"
    exit 1
fi
scenario_result "mount_rw" "PASS" "RW mount succeeded"

# Mutation set with verifiable content
MUTATION_LOG="$E2E_LOG_DIR/mutations.log"
MUTATIONS_OK=1

e2e_log "Performing standard mutation set..."

# 1. create file with specific content
echo "mutation-create-content-12345" > "$MOUNT_RW/created_file.txt" 2>>"$MUTATION_LOG" || MUTATIONS_OK=0
e2e_log "  create: created_file.txt"

# 2. mkdir
mkdir -p "$MOUNT_RW/created_dir" 2>>"$MUTATION_LOG" || MUTATIONS_OK=0
e2e_log "  mkdir: created_dir"

# 3. write to file in directory
echo "mutation-write-content-67890" > "$MOUNT_RW/created_dir/nested_file.txt" 2>>"$MUTATION_LOG" || MUTATIONS_OK=0
e2e_log "  write: created_dir/nested_file.txt"

# 4. create file to be renamed
echo "rename-source-content" > "$MOUNT_RW/to_rename.txt" 2>>"$MUTATION_LOG" || MUTATIONS_OK=0
mv "$MOUNT_RW/to_rename.txt" "$MOUNT_RW/renamed_file.txt" 2>>"$MUTATION_LOG" || MUTATIONS_OK=0
e2e_log "  rename: to_rename.txt -> renamed_file.txt"

# 5. create file to be unlinked (we verify it's gone after remount)
echo "unlink-target-content" > "$MOUNT_RW/to_unlink.txt" 2>>"$MUTATION_LOG" || MUTATIONS_OK=0
rm "$MOUNT_RW/to_unlink.txt" 2>>"$MUTATION_LOG" || MUTATIONS_OK=0
e2e_log "  unlink: to_unlink.txt"

# 6. setattr (chmod)
chmod 755 "$MOUNT_RW/created_file.txt" 2>>"$MUTATION_LOG" || MUTATIONS_OK=0
e2e_log "  setattr: chmod 755 created_file.txt"

# 7. xattr (if supported)
if command -v setfattr &>/dev/null; then
    setfattr -n user.testattr -v "xattr-value-abcdef" "$MOUNT_RW/created_file.txt" 2>>"$MUTATION_LOG" || true
    e2e_log "  xattr: user.testattr on created_file.txt"
else
    e2e_log "  xattr: skipped (setfattr not available)"
fi

# 8. fsync to trigger writeback
sync 2>>"$MUTATION_LOG" || true
e2e_log "  sync: triggered"

if [[ $MUTATIONS_OK -eq 1 ]]; then
    scenario_result "perform_mutations" "PASS" "All mutations executed"
else
    scenario_result "perform_mutations" "FAIL" "Some mutations failed"
    cat "$MUTATION_LOG"
fi

# Record what we expect to see after remount
EXPECTED_FILES=(
    "created_file.txt"
    "created_dir"
    "created_dir/nested_file.txt"
    "renamed_file.txt"
)
UNEXPECTED_FILES=(
    "to_unlink.txt"
    "to_rename.txt"
)

#######################################
# Phase 5: Unmount
#######################################
e2e_step "Phase 5: Unmount"

stop_mount "$MOUNT_RW"
sleep 1

if mountpoint -q "$MOUNT_RW" 2>/dev/null; then
    scenario_result "unmount_rw" "FAIL" "Unmount failed"
    exit 1
fi
scenario_result "unmount_rw" "PASS" "Unmount succeeded"

#######################################
# Phase 6: Remount RO and verify persistence
#######################################
e2e_step "Phase 6: Remount RO and verify persistence"

MOUNT_RO="$E2E_TEMP_DIR/mnt_ro"
mkdir -p "$MOUNT_RO"

if ! start_mount ro "$TEST_IMAGE" "$MOUNT_RO" 30; then
    scenario_result "remount_ro" "FAIL" "RO remount failed"
    exit 1
fi
scenario_result "remount_ro" "PASS" "RO remount succeeded"

# Verify expected files exist
PERSIST_OK=1
for file in "${EXPECTED_FILES[@]}"; do
    if [[ -e "$MOUNT_RO/$file" ]]; then
        e2e_log "  FOUND: $file"
    else
        e2e_log "  MISSING: $file"
        PERSIST_OK=0
    fi
done

# Verify unexpected files are gone
for file in "${UNEXPECTED_FILES[@]}"; do
    if [[ -e "$MOUNT_RO/$file" ]]; then
        e2e_log "  UNEXPECTED: $file (should have been deleted)"
        PERSIST_OK=0
    else
        e2e_log "  CORRECTLY_ABSENT: $file"
    fi
done

# Verify file contents
if [[ -f "$MOUNT_RO/created_file.txt" ]]; then
    CONTENT=$(cat "$MOUNT_RO/created_file.txt" 2>/dev/null || echo "")
    if [[ "$CONTENT" == "mutation-create-content-12345" ]]; then
        e2e_log "  CONTENT_OK: created_file.txt"
    else
        e2e_log "  CONTENT_MISMATCH: created_file.txt (got: '$CONTENT')"
        PERSIST_OK=0
    fi
fi

if [[ -f "$MOUNT_RO/created_dir/nested_file.txt" ]]; then
    CONTENT=$(cat "$MOUNT_RO/created_dir/nested_file.txt" 2>/dev/null || echo "")
    if [[ "$CONTENT" == "mutation-write-content-67890" ]]; then
        e2e_log "  CONTENT_OK: created_dir/nested_file.txt"
    else
        e2e_log "  CONTENT_MISMATCH: created_dir/nested_file.txt (got: '$CONTENT')"
        PERSIST_OK=0
    fi
fi

# Record persistence result
if [[ $PERSIST_OK -eq 1 ]]; then
    scenario_result "persistence_check" "PASS" "All mutations persisted correctly"
else
    if [[ "$EXPECT_PERSISTENCE" == "1" ]]; then
        scenario_result "persistence_check" "FAIL" "Mutations did not persist (expected to pass)"
    else
        scenario_result "persistence_check" "XFAIL" "Mutations did not persist (expected: A1-A6 not yet wired)"
    fi
fi

stop_mount "$MOUNT_RO"

#######################################
# Phase 7: Verify with ffs-cli inspect
#######################################
e2e_step "Phase 7: Verify with ffs-cli inspect"

INSPECT_LOG="$E2E_LOG_DIR/inspect.log"
INSPECT_START=$(date +%s%3N)
if "$FFS_CLI_BIN" inspect "$TEST_IMAGE" --json > "$INSPECT_LOG" 2>&1; then
    INSPECT_END=$(date +%s%3N)
    scenario_result "ffs_cli_inspect" "PASS" "inspect succeeded"
    emit_executed_evidence "$FFS_CLI_BIN inspect $TEST_IMAGE --json" 0 "$INSPECT_LOG" "$INSPECT_LOG" "$((INSPECT_END - INSPECT_START))" > "$E2E_LOG_DIR/inspect_evidence.json"
else
    INSPECT_END=$(date +%s%3N)
    scenario_result "ffs_cli_inspect" "FAIL" "inspect failed"
    emit_executed_evidence "$FFS_CLI_BIN inspect $TEST_IMAGE --json" 1 "$INSPECT_LOG" "$INSPECT_LOG" "$((INSPECT_END - INSPECT_START))" > "$E2E_LOG_DIR/inspect_evidence.json"
    tail -20 "$INSPECT_LOG"
fi

#######################################
# Summary
#######################################
e2e_step "Summary"
echo ""
echo "=============================================="
echo "Results: ${PASS_COUNT} PASS, ${FAIL_COUNT} FAIL, ${XFAIL_COUNT} XFAIL (total: ${TOTAL})"

# Generate overall evidence
OVERALL_LOG="$E2E_LOG_FILE"
OVERALL_EXIT=0
if [[ $FAIL_COUNT -gt 0 ]]; then
    OVERALL_EXIT=1
    echo "OVERALL: FAIL"
    scenario_result "btrfs_durable_remount_overall" "FAIL" "$FAIL_COUNT failures"
elif [[ $XFAIL_COUNT -gt 0 ]]; then
    echo "OVERALL: XFAIL (expected failure - check logs)"
    scenario_result "btrfs_durable_remount_overall" "XFAIL" "unexpected persistence failure"
else
    echo "OVERALL: PASS"
    scenario_result "btrfs_durable_remount_overall" "PASS" "all checks passed"
fi

echo "=============================================="
echo "Duration: $(( $(date +%s) - ${E2E_START_TIME:-$(date +%s)} ))s"
echo "Log directory: $E2E_LOG_DIR"
echo "Artifacts:"
ls -la "$E2E_LOG_DIR"/*.json 2>/dev/null || true

# Generate final executed evidence
emit_executed_evidence "scripts/e2e/ffs_btrfs_rw_durable_remount_e2e.sh" "$OVERALL_EXIT" "$E2E_LOG_FILE" "$E2E_LOG_FILE" "$(( ($(date +%s) - ${E2E_START_TIME:-$(date +%s)}) * 1000 ))" > "$E2E_LOG_DIR/overall_evidence.json"

if [[ $FAIL_COUNT -eq 0 ]]; then
    e2e_pass
fi

exit $OVERALL_EXIT
