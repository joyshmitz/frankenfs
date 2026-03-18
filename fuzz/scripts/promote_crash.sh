#!/usr/bin/env bash
# promote_crash.sh - Promote a fuzz crash artifact to a regression test
#
# Workflow:
#   1. Minimize the crash input using `cargo fuzz tmin`
#   2. Copy the minimized input to the regression corpus
#   3. Generate a regression test stub with metadata tags
#
# Usage:
#   ./fuzz/scripts/promote_crash.sh <target> <crash_file> [--skip-minimize]
#
# Example:
#   ./fuzz/scripts/promote_crash.sh fuzz_ext4_metadata fuzz/artifacts/crash-abc123
#
# Output:
#   - Corpus seed copied to tests/fuzz_corpus/
#   - Regression test stub printed to stdout (paste into test file)

set -euo pipefail

cd "$(dirname "$0")/../.."
REPO_ROOT="$(pwd)"

log() { echo "[promote] $*" >&2; }

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <target> <crash_file> [--skip-minimize]" >&2
    exit 1
fi

TARGET="$1"
CRASH_FILE="$2"
SKIP_MINIMIZE="${3:-}"

if [[ ! -f "$CRASH_FILE" ]]; then
    log "ERROR: crash file not found: $CRASH_FILE"
    exit 1
fi

TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
COMMIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
INPUT_SIZE=$(stat -c%s "$CRASH_FILE" 2>/dev/null || stat -f%z "$CRASH_FILE" 2>/dev/null || echo "0")
SEED_NAME="regression_${TARGET}_${TIMESTAMP}_${INPUT_SIZE}bytes"

# Step 1: Minimize (unless skipped)
MINIMIZED_FILE="$CRASH_FILE"
MINIMIZED="false"
if [[ "$SKIP_MINIMIZE" != "--skip-minimize" ]]; then
    log "Minimizing crash input..."
    MIN_OUTPUT="${CRASH_FILE}.minimized"
    if cargo fuzz tmin "$TARGET" --fuzz-dir fuzz -- "$CRASH_FILE" 2>/dev/null; then
        # tmin overwrites the input in-place or produces adjacent output
        MINIMIZED="true"
        log "Minimization complete"
    else
        log "WARN: minimization failed, using original crash input"
    fi
fi

# Step 2: Copy to regression corpus
DEST="${REPO_ROOT}/tests/fuzz_corpus/${SEED_NAME}"
cp "$CRASH_FILE" "$DEST"
log "Corpus seed: $DEST"

# Step 3: Generate regression test stub
cat <<EOF

/// Regression test promoted from fuzz crash.
///
/// - Fuzz target: \`${TARGET}\`
/// - Campaign: \`${TIMESTAMP}\`
/// - Commit at discovery: \`${COMMIT_SHA}\`
/// - Promoted: \`$(date -u +%Y-%m-%d)\`
/// - Minimized: \`${MINIMIZED}\`
/// - Corpus seed: \`${SEED_NAME}\`
#[test]
fn ${SEED_NAME}() {
    let seed = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fuzz_corpus/${SEED_NAME}")
    ).expect("regression seed must exist");

    // Feed to the same parser as the fuzz target — must not panic.
    let _ = ffs_ondisk::Ext4Superblock::parse_superblock_region(&seed);
    let _ = ffs_ondisk::Ext4Inode::parse_from_bytes(&seed);
    let _ = ffs_ondisk::Ext4GroupDesc::parse_from_bytes(&seed, 32);
    let _ = ffs_ondisk::Ext4GroupDesc::parse_from_bytes(&seed, 64);
    let _ = ffs_ondisk::parse_dir_block(&seed, 4096);
    let _ = ffs_ondisk::BtrfsSuperblock::parse_superblock_region(&seed);
}
EOF

log "Done. Paste the test stub above into your regression test file."
log "Metadata: target=${TARGET} campaign=${TIMESTAMP} commit=${COMMIT_SHA} minimized=${MINIMIZED}"
