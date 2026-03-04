#!/usr/bin/env bash
# lib.sh - Shared helpers for E2E tests
#
# Source this file in E2E scripts:
#   source "$(dirname "$0")/lib.sh"

# Strict mode
set -euo pipefail
# Note: We intentionally don't set IFS to avoid command parsing issues

# Colors (if terminal supports them)
if [[ -t 1 ]] && command -v tput &>/dev/null; then
    RED=$(tput setaf 1)
    GREEN=$(tput setaf 2)
    YELLOW=$(tput setaf 3)
    BLUE=$(tput setaf 4)
    RESET=$(tput sgr0)
else
    RED="" GREEN="" YELLOW="" BLUE="" RESET=""
fi

# Global state
E2E_START_TIME=""
E2E_LOG_DIR=""
E2E_LOG_FILE=""
E2E_TEMP_DIR=""
E2E_MOUNT_POINT=""
E2E_CLEANUP_ITEMS=()

#######################################
# Initialize E2E test environment
# Creates log directory and temp directory
# Arguments:
#   $1 - Test name (used for directory naming)
#######################################
e2e_init() {
    local test_name="${1:-e2e}"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)

    E2E_START_TIME=$(date +%s)

    # Create log directory
    E2E_LOG_DIR="${REPO_ROOT:-$(pwd)}/artifacts/e2e/${timestamp}_${test_name}"
    mkdir -p "$E2E_LOG_DIR"
    E2E_LOG_FILE="$E2E_LOG_DIR/run.log"

    # Create temp directory
    E2E_TEMP_DIR=$(mktemp -d -t "ffs_e2e_XXXXXX")
    E2E_CLEANUP_ITEMS+=("$E2E_TEMP_DIR")

    # Set up cleanup trap
    trap e2e_cleanup EXIT

    # Start logging
    e2e_log "=============================================="
    e2e_log "E2E Test: $test_name"
    e2e_log "=============================================="
    e2e_log "Started: $(date -Iseconds)"
    e2e_log "Log directory: $E2E_LOG_DIR"
    e2e_log "Temp directory: $E2E_TEMP_DIR"
    e2e_log ""
}

#######################################
# Log message to both stdout and log file
# Arguments:
#   $* - Message to log
#######################################
e2e_log() {
    local msg="$*"
    echo "$msg"
    [[ -n "${E2E_LOG_FILE:-}" ]] && echo "$msg" >> "$E2E_LOG_FILE"
}

#######################################
# Log a step with timestamp
# Arguments:
#   $1 - Step description
#######################################
e2e_step() {
    local step="$1"
    e2e_log ""
    e2e_log "=== $step ==="
    e2e_log "Time: $(date -Iseconds)"
}

#######################################
# Validate E2E scenario catalog contract
# Arguments:
#   $1 - Catalog path (default: $REPO_ROOT/scripts/e2e/scenario_catalog.json)
#######################################
e2e_validate_scenario_catalog() {
    local repo_root catalog_path
    repo_root="${REPO_ROOT:-$(pwd)}"
    catalog_path="${1:-$repo_root/scripts/e2e/scenario_catalog.json}"

    e2e_step "Scenario Catalog Validation"

    if [[ ! -f "$catalog_path" ]]; then
        e2e_fail "Scenario catalog missing: $catalog_path"
    fi
    if ! command -v jq >/dev/null 2>&1; then
        e2e_fail "jq is required for scenario catalog validation"
    fi

    local id_regex
    id_regex="$(jq -r '.scenario_id_regex // empty' "$catalog_path")"
    if [[ -z "$id_regex" ]]; then
        e2e_fail "scenario_id_regex missing from $catalog_path"
    fi

    local duplicate_taxonomy
    duplicate_taxonomy="$(jq -r '.taxonomy[]' "$catalog_path" | sort | uniq -d || true)"
    if [[ -n "$duplicate_taxonomy" ]]; then
        e2e_fail "Duplicate taxonomy categories in scenario catalog: $duplicate_taxonomy"
    fi

    local duplicate_ids
    duplicate_ids="$(
        jq -r '
            .suites[].scenarios[]
            | select((.status // "active") == "active" and has("id"))
            | .id
        ' "$catalog_path" | sort | uniq -d || true
    )"
    if [[ -n "$duplicate_ids" ]]; then
        e2e_fail "Duplicate active scenario IDs in scenario catalog: $duplicate_ids"
    fi

    while IFS=$'\t' read -r suite_id script_rel; do
        [[ -n "$suite_id" ]] || continue
        local script_path
        script_path="$repo_root/$script_rel"
        if [[ ! -f "$script_path" ]]; then
            e2e_fail "Scenario catalog suite '$suite_id' references missing script: $script_rel"
        fi

        local -A seen_categories=()
        local active_count=0

        while IFS= read -r scenario_b64; do
            [[ -n "$scenario_b64" ]] || continue
            local scenario_json
            scenario_json="$(printf '%s' "$scenario_b64" | base64 --decode)"

            local status category evidence scenario_id scenario_pattern
            status="$(jq -r '.status // "active"' <<<"$scenario_json")"
            category="$(jq -r '.category // empty' <<<"$scenario_json")"
            evidence="$(jq -r '.evidence // empty' <<<"$scenario_json")"
            scenario_id="$(jq -r '.id // empty' <<<"$scenario_json")"
            scenario_pattern="$(jq -r '.id_pattern // empty' <<<"$scenario_json")"

            if [[ -z "$category" ]]; then
                e2e_fail "Suite '$suite_id' has scenario without category"
            fi
            if ! jq -e --arg category "$category" '.taxonomy | index($category)' "$catalog_path" >/dev/null; then
                e2e_fail "Suite '$suite_id' uses unknown category '$category'"
            fi

            if [[ "$status" != "active" ]]; then
                continue
            fi

            active_count=$((active_count + 1))
            seen_categories["$category"]=1

            if [[ -z "$scenario_id" && -z "$scenario_pattern" ]]; then
                e2e_fail "Suite '$suite_id' active scenario must define id or id_pattern"
            fi
            if [[ -n "$scenario_id" && ! "$scenario_id" =~ $id_regex ]]; then
                e2e_fail "Suite '$suite_id' scenario ID does not match regex: $scenario_id"
            fi
            if [[ -z "$evidence" ]]; then
                e2e_fail "Suite '$suite_id' active scenario is missing evidence marker"
            fi
            if ! grep -Fq "$evidence" "$script_path"; then
                e2e_fail "Suite '$suite_id' evidence marker not found in $script_rel: $evidence"
            fi
        done < <(
            jq -r --arg suite_id "$suite_id" '
                .suites[]
                | select(.suite_id == $suite_id)
                | .scenarios[]
                | @base64
            ' "$catalog_path"
        )

        if (( active_count == 0 )); then
            e2e_fail "Suite '$suite_id' has no active scenarios in catalog"
        fi

        while IFS= read -r required_category; do
            [[ -n "$required_category" ]] || continue
            if [[ -z "${seen_categories[$required_category]:-}" ]]; then
                e2e_fail "Suite '$suite_id' missing required active category '$required_category'"
            fi
        done < <(
            jq -r --arg suite_id "$suite_id" '
                .suites[]
                | select(.suite_id == $suite_id)
                | .required_categories[]?
            ' "$catalog_path"
        )

        e2e_log "Scenario catalog suite validated: $suite_id (active_scenarios=$active_count)"
    done < <(jq -r '.suites[] | [.suite_id, .script] | @tsv' "$catalog_path")

    while IFS=$'\t' read -r gate_id category; do
        [[ -n "$gate_id" && -n "$category" ]] || continue
        if ! jq -e --arg category "$category" '.taxonomy | index($category)' "$catalog_path" >/dev/null; then
            e2e_fail "Gate '$gate_id' uses unknown required category '$category'"
        fi
    done < <(
        jq -r '
            .gate_minimums[]? as $gate
            | $gate.required_categories[]?
            | [$gate.gate_id, .]
            | @tsv
        ' "$catalog_path"
    )

    e2e_log "Scenario catalog validation passed: $catalog_path"
}

#######################################
# Run a command and log output
# Arguments:
#   $* - Command to run
# Returns:
#   Exit code of command (stored in E2E_LAST_EXIT_CODE)
#######################################
e2e_run() {
    local start_time end_time duration
    local output_file

    e2e_log "Running: $*"
    start_time=$(date +%s.%N)

    output_file=$(mktemp)

    # Run command and capture exit code without triggering set -e
    # Use a subshell to capture the real exit code before || true masks it
    E2E_LAST_EXIT_CODE=0
    "$@" > "$output_file" 2>&1 || E2E_LAST_EXIT_CODE=$?

    # Log output (limit to reasonable size)
    head -500 "$output_file" | while IFS= read -r line; do
        e2e_log "  $line"
    done
    rm -f "$output_file"

    end_time=$(date +%s.%N)
    duration=$(echo "$end_time - $start_time" | bc 2>/dev/null || echo "N/A")

    e2e_log "Exit code: $E2E_LAST_EXIT_CODE (duration: ${duration}s)"
    return "$E2E_LAST_EXIT_CODE"
}

#######################################
# Assert a command succeeds
# Arguments:
#   $* - Command to run
#######################################
e2e_assert() {
    if ! e2e_run "$@"; then
        e2e_fail "Assertion failed: $*"
    fi
}

#######################################
# Assert a file exists
# Arguments:
#   $1 - File path
#######################################
e2e_assert_file() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        e2e_fail "File not found: $file"
    fi
    e2e_log "File exists: $file"
}

#######################################
# Assert a directory exists
# Arguments:
#   $1 - Directory path
#######################################
e2e_assert_dir() {
    local dir="$1"
    if [[ ! -d "$dir" ]]; then
        e2e_fail "Directory not found: $dir"
    fi
    e2e_log "Directory exists: $dir"
}

#######################################
# Skip test with message (exit 0)
# Arguments:
#   $1 - Skip reason
#######################################
e2e_skip() {
    local reason="$1"
    e2e_log ""
    e2e_log "${YELLOW}SKIPPED${RESET}: $reason"
    e2e_log ""
    exit 0
}

#######################################
# Fail test with message (exit 1)
# Arguments:
#   $1 - Failure reason
#######################################
e2e_fail() {
    local reason="$1"
    e2e_log ""
    e2e_log "${RED}FAILED${RESET}: $reason"
    e2e_log ""
    e2e_log "Log file: $E2E_LOG_FILE"
    e2e_log ""
    e2e_log "Last 50 lines of log:"
    tail -50 "$E2E_LOG_FILE" 2>/dev/null | while IFS= read -r line; do
        echo "  $line"
    done
    exit 1
}

#######################################
# Pass test with summary
#######################################
e2e_pass() {
    local end_time duration

    end_time=$(date +%s)
    duration=$((end_time - E2E_START_TIME))

    e2e_log ""
    e2e_log "=============================================="
    e2e_log "${GREEN}PASSED${RESET}"
    e2e_log "=============================================="
    e2e_log "Duration: ${duration}s"
    e2e_log "Log file: $E2E_LOG_FILE"
    e2e_log ""
}

#######################################
# Print environment information
#######################################
e2e_print_env() {
    e2e_step "Environment"

    e2e_log "System:"
    e2e_log "  $(uname -a)"
    e2e_log "  User: $(id)"
    e2e_log ""

    e2e_log "Rust toolchain:"
    if command -v rustc &>/dev/null; then
        rustc -Vv 2>&1 | while IFS= read -r line; do e2e_log "  $line"; done
        cargo -V 2>&1 | while IFS= read -r line; do e2e_log "  $line"; done
    else
        e2e_log "  rustc not found"
    fi
    e2e_log ""

    e2e_log "FUSE:"
    if [[ -e /dev/fuse ]]; then
        ls -l /dev/fuse 2>&1 | while IFS= read -r line; do e2e_log "  $line"; done
    else
        e2e_log "  /dev/fuse not found"
    fi
    if command -v fusermount3 &>/dev/null; then
        e2e_log "  $(fusermount3 --version 2>&1 | head -1)"
    elif command -v fusermount &>/dev/null; then
        e2e_log "  $(fusermount --version 2>&1 | head -1)"
    else
        e2e_log "  fusermount not found"
    fi
    e2e_log ""

    e2e_log "Filesystem tools:"
    for tool in mkfs.ext4 debugfs; do
        if command -v "$tool" &>/dev/null; then
            e2e_log "  $tool: $(which "$tool")"
        else
            e2e_log "  $tool: not found"
        fi
    done
    e2e_log ""
}

#######################################
# Create a test ext4 image
# Arguments:
#   $1 - Output image path
#   $2 - Size in MiB (default: 16)
#######################################
e2e_create_ext4_image() {
    local img_path="$1"
    local size_mb="${2:-16}"

    e2e_step "Creating ext4 test image"
    e2e_log "Path: $img_path"
    e2e_log "Size: ${size_mb} MiB"

    # Check tools
    if ! command -v mkfs.ext4 &>/dev/null; then
        e2e_skip "mkfs.ext4 not found"
    fi
    if ! command -v debugfs &>/dev/null; then
        e2e_skip "debugfs not found"
    fi

    # Create image
    dd if=/dev/zero of="$img_path" bs=1M count="$size_mb" status=none

    # Format
    mkfs.ext4 -F -O extent,filetype -L e2e_test "$img_path" >/dev/null 2>&1

    # Populate with debugfs
    local tmp_dir
    tmp_dir=$(mktemp -d)

    echo "FrankenFS E2E Test File" > "$tmp_dir/readme.txt"
    echo "Hello from E2E test!" > "$tmp_dir/hello.txt"

    debugfs -w "$img_path" <<EOF >/dev/null 2>&1
mkdir testdir
write $tmp_dir/readme.txt readme.txt
write $tmp_dir/hello.txt testdir/hello.txt
EOF

    rm -rf "$tmp_dir"

    e2e_log "Image created successfully"
}

#######################################
# Mount an image via ffs mount
# Arguments:
#   $1 - Image path
#   $2 - Mount point
#######################################
e2e_mount() {
    local img_path="$1"
    local mnt_point="$2"

    # Check FUSE availability
    if [[ ! -e /dev/fuse ]]; then
        e2e_skip "/dev/fuse not available"
    fi
    if [[ ! -r /dev/fuse ]] || [[ ! -w /dev/fuse ]]; then
        e2e_skip "/dev/fuse not accessible"
    fi

    mkdir -p "$mnt_point"
    E2E_MOUNT_POINT="$mnt_point"

    e2e_log "Mounting: $img_path -> $mnt_point"
    cargo run -p ffs-cli --release -- mount "$img_path" "$mnt_point" &
    local mount_pid=$!

    # Wait for mount to be ready
    local timeout=10
    local elapsed=0
    while ! mountpoint -q "$mnt_point" 2>/dev/null; do
        sleep 0.5
        elapsed=$((elapsed + 1))
        if [[ $elapsed -ge $((timeout * 2)) ]]; then
            kill "$mount_pid" 2>/dev/null || true
            e2e_fail "Mount timed out after ${timeout}s"
        fi
    done

    e2e_log "Mount ready (PID: $mount_pid)"
}

#######################################
# Unmount a FUSE mount
# Arguments:
#   $1 - Mount point (optional, uses E2E_MOUNT_POINT if not provided)
#######################################
e2e_unmount() {
    local mnt_point="${1:-$E2E_MOUNT_POINT}"

    if [[ -z "$mnt_point" ]]; then
        return 0
    fi

    if ! mountpoint -q "$mnt_point" 2>/dev/null; then
        e2e_log "Not mounted: $mnt_point"
        return 0
    fi

    e2e_log "Unmounting: $mnt_point"

    if command -v fusermount3 &>/dev/null; then
        fusermount3 -u "$mnt_point" 2>/dev/null || true
    elif command -v fusermount &>/dev/null; then
        fusermount -u "$mnt_point" 2>/dev/null || true
    else
        umount "$mnt_point" 2>/dev/null || true
    fi

    # Fallback for orphaned/stuck FUSE mounts where fusermount fails.
    if mountpoint -q "$mnt_point" 2>/dev/null; then
        umount "$mnt_point" 2>/dev/null || umount -l "$mnt_point" 2>/dev/null || true
    fi

    # Give it a moment
    sleep 0.5

    if mountpoint -q "$mnt_point" 2>/dev/null; then
        e2e_log "WARNING: Mount point still mounted after unmount attempt"
    fi
}

#######################################
# Cleanup function (called on EXIT)
#######################################
e2e_cleanup() {
    local exit_code=$?

    # Unmount any active mount
    e2e_unmount "${E2E_MOUNT_POINT:-}" 2>/dev/null || true

    # Remove temp directories
    for item in "${E2E_CLEANUP_ITEMS[@]:-}"; do
        if [[ -d "$item" ]]; then
            rm -rf "$item" 2>/dev/null || true
        fi
    done

    return "$exit_code"
}
