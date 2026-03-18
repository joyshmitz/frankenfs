#!/usr/bin/env bash
# nightly_fuzz.sh - Run all fuzz targets for a campaign and produce JSON summary.
#
# Usage: ./fuzz/scripts/nightly_fuzz.sh [duration_per_target_secs]
#
# Default: 300 seconds (5 minutes) per target.
# For a full 24-hour campaign: 12342 seconds per target (7 targets * 12342 ≈ 86400).

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$FUZZ_DIR/.." && pwd)"
cd "$REPO_ROOT"

DURATION="${1:-300}"
CAMPAIGN_ID="nightly_$(date +%Y%m%d_%H%M%S)"
RESULTS_DIR="$FUZZ_DIR/campaigns/$CAMPAIGN_ID"
mkdir -p "$RESULTS_DIR"

TARGETS=(
    fuzz_ext4_metadata
    fuzz_btrfs_metadata
    fuzz_ext4_xattr
    fuzz_ext4_dir_extent
    fuzz_wal_replay
    fuzz_mvcc_operations
    fuzz_extent_tree
)

echo "=== Nightly Fuzz Campaign: $CAMPAIGN_ID ==="
echo "Targets: ${#TARGETS[@]}"
echo "Duration per target: ${DURATION}s"
echo "Results: $RESULTS_DIR"
echo ""

SUMMARY_JSON="$RESULTS_DIR/summary.json"
RESULTS=()
TOTAL_CRASHES=0
CAMPAIGN_START=$(date +%s)

for target in "${TARGETS[@]}"; do
    echo "--- Running: $target ---"
    TARGET_LOG="$RESULTS_DIR/${target}.log"
    TARGET_START=$(date +%s)
    TARGET_RC=0

    DICT_FLAG=""
    if [[ "$target" == *ext4* ]]; then
        DICT_FLAG="-dict=fuzz/dictionaries/ext4.dict"
    elif [[ "$target" == *btrfs* ]]; then
        DICT_FLAG="-dict=fuzz/dictionaries/btrfs.dict"
    fi

    cargo fuzz run "$target" \
        -- \
        -max_total_time="$DURATION" \
        -max_len=65536 \
        $DICT_FLAG \
        > "$TARGET_LOG" 2>&1 || TARGET_RC=$?

    TARGET_END=$(date +%s)
    TARGET_DURATION=$((TARGET_END - TARGET_START))

    # Count crashes in the artifacts directory
    CRASH_COUNT=0
    CRASH_DIR="$FUZZ_DIR/artifacts/$target"
    if [[ -d "$CRASH_DIR" ]]; then
        CRASH_COUNT=$(find "$CRASH_DIR" -name "crash-*" -type f 2>/dev/null | wc -l)
        TOTAL_CRASHES=$((TOTAL_CRASHES + CRASH_COUNT))
    fi

    # Extract corpus size
    CORPUS_SIZE=0
    CORPUS_DIR="$FUZZ_DIR/corpus/$target"
    if [[ -d "$CORPUS_DIR" ]]; then
        CORPUS_SIZE=$(find "$CORPUS_DIR" -type f 2>/dev/null | wc -l)
    fi

    STATUS="ok"
    if [[ $TARGET_RC -ne 0 ]] && [[ $CRASH_COUNT -gt 0 ]]; then
        STATUS="crashes_found"
    elif [[ $TARGET_RC -ne 0 ]]; then
        STATUS="error"
    fi

    echo "  Status: $STATUS (rc=$TARGET_RC, crashes=$CRASH_COUNT, corpus=$CORPUS_SIZE, ${TARGET_DURATION}s)"

    RESULTS+=("{\"target\":\"$target\",\"status\":\"$STATUS\",\"exit_code\":$TARGET_RC,\"crashes\":$CRASH_COUNT,\"corpus_size\":$CORPUS_SIZE,\"duration_secs\":$TARGET_DURATION}")
done

CAMPAIGN_END=$(date +%s)
CAMPAIGN_DURATION=$((CAMPAIGN_END - CAMPAIGN_START))

# Build results array
RESULTS_ARRAY="["
for i in "${!RESULTS[@]}"; do
    if [[ $i -gt 0 ]]; then
        RESULTS_ARRAY+=","
    fi
    RESULTS_ARRAY+="${RESULTS[$i]}"
done
RESULTS_ARRAY+="]"

# Write summary
cat > "$SUMMARY_JSON" <<EOF
{
  "schema_version": 1,
  "campaign_id": "$CAMPAIGN_ID",
  "created_at": "$(date -Iseconds)",
  "duration_per_target_secs": $DURATION,
  "totals": {
    "duration_secs": $CAMPAIGN_DURATION,
    "targets": ${#TARGETS[@]},
    "crashes": $TOTAL_CRASHES
  },
  "commit_sha": "$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)",
  "config": "default",
  "targets": $RESULTS_ARRAY
}
EOF

echo ""
echo "=== Campaign Summary ==="
echo "Campaign: $CAMPAIGN_ID"
echo "Duration: ${CAMPAIGN_DURATION}s"
echo "Total crashes: $TOTAL_CRASHES"
echo "Summary: $SUMMARY_JSON"

if [[ $TOTAL_CRASHES -gt 0 ]]; then
    echo ""
    echo "WARNING: $TOTAL_CRASHES crash(es) found! Check artifacts/ for details."
    exit 1
fi

exit 0
