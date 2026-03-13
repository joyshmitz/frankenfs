#!/usr/bin/env bash
# flamegraph_generate.sh — Generate CPU flamegraph SVGs for key hot paths.
#
# Requires: cargo-flamegraph (cargo install flamegraph)
# Usage:    scripts/flamegraph_generate.sh [--out-dir DIR]
#
# Generates flamegraphs for three critical paths:
#   1. Mount-to-first-read latency (ext4 inspect as proxy)
#   2. Large sequential read path (block cache workload)
#   3. Concurrent writer contention (MVCC WAL throughput)
#
# Output: SVG files in artifacts/flamegraphs/ (or specified --out-dir)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

OUT_DIR="${PROJECT_ROOT}/artifacts/flamegraphs"
DATE_TAG="$(date -u +%Y%m%d)"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

mkdir -p "$OUT_DIR"

echo "=== FrankenFS Flamegraph Generation ==="
echo "Date: ${DATE_TAG}"
echo "Output: ${OUT_DIR}"
echo ""

# Check for cargo-flamegraph
if ! command -v cargo-flamegraph &>/dev/null && ! cargo flamegraph --help &>/dev/null 2>&1; then
    echo "ERROR: cargo-flamegraph not installed."
    echo "Install with: cargo install flamegraph"
    echo ""
    echo "Alternative: use perf + inferno manually:"
    echo "  perf record -g -- <command>"
    echo "  perf script | inferno-collapse-perf | inferno-flamegraph > out.svg"
    exit 1
fi

# Check for perf support
if ! command -v perf &>/dev/null; then
    echo "WARNING: perf not found. Flamegraphs may use dtrace or fail."
    echo "Install with: sudo apt install linux-tools-common linux-tools-\$(uname -r)"
fi

# Ensure release build exists
echo "--- Building release profile ---"
cargo build --release -p ffs-cli -p ffs-harness 2>&1 | tail -3

# Check for conformance fixture
EXT4_REF=""
for candidate in \
    "conformance/golden/ext4_8mb_reference.ext4" \
    "tests/fixtures/ext4_test.img"; do
    if [[ -f "$candidate" ]]; then
        EXT4_REF="$candidate"
        break
    fi
done

echo ""

# ── Flamegraph 1: Mount-to-first-read (ext4 inspect as proxy) ──────────
echo "--- Flamegraph 1/3: Mount-to-first-read (ext4 inspect) ---"
FG1="${OUT_DIR}/flamegraph_mount_inspect_${DATE_TAG}.svg"
if [[ -n "$EXT4_REF" ]]; then
    cargo flamegraph \
        --bin ffs-cli \
        --output "$FG1" \
        --root \
        -- inspect "$EXT4_REF" --json >/dev/null 2>&1 || {
        echo "  WARN: flamegraph generation failed (may need root/perf_event_paranoid)"
        echo "  Try: echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid"
    }
    if [[ -f "$FG1" ]]; then
        echo "  OK: $FG1 ($(du -h "$FG1" | cut -f1))"
    fi
else
    echo "  SKIP: No ext4 reference image found"
fi

# ── Flamegraph 2: Block cache sequential scan ──────────────────────────
echo "--- Flamegraph 2/3: Block cache sequential scan ---"
FG2="${OUT_DIR}/flamegraph_block_cache_seq_${DATE_TAG}.svg"
cargo flamegraph \
    --bench arc_cache \
    -p ffs-block \
    --output "$FG2" \
    --root \
    -- --bench "block_cache_arc_sequential_scan" 2>/dev/null || {
    echo "  WARN: flamegraph generation failed for block cache bench"
}
if [[ -f "$FG2" ]]; then
    echo "  OK: $FG2 ($(du -h "$FG2" | cut -f1))"
fi

# ── Flamegraph 3: WAL throughput (MVCC contention) ─────────────────────
echo "--- Flamegraph 3/3: WAL commit throughput ---"
FG3="${OUT_DIR}/flamegraph_wal_throughput_${DATE_TAG}.svg"
cargo flamegraph \
    --bench wal_throughput \
    -p ffs-mvcc \
    --output "$FG3" \
    --root \
    -- --bench "wal_commit_4k_sync" 2>/dev/null || {
    echo "  WARN: flamegraph generation failed for WAL throughput bench"
}
if [[ -f "$FG3" ]]; then
    echo "  OK: $FG3 ($(du -h "$FG3" | cut -f1))"
fi

echo ""
echo "=== Flamegraph Generation Complete ==="
GENERATED=$(find "$OUT_DIR" -name "flamegraph_*_${DATE_TAG}.svg" 2>/dev/null | wc -l)
echo "Generated: ${GENERATED}/3 flamegraphs in ${OUT_DIR}"

if [[ "$GENERATED" -eq 0 ]]; then
    echo ""
    echo "No flamegraphs generated. Common fixes:"
    echo "  1. Install cargo-flamegraph: cargo install flamegraph"
    echo "  2. Allow perf events: echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid"
    echo "  3. Run with sudo if needed: sudo scripts/flamegraph_generate.sh"
    exit 1
fi
