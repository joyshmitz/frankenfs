#!/usr/bin/env bash
# verify_golden.sh — Verify golden output integrity + run conformance checks.
#
# Usage:
#   scripts/verify_golden.sh           # verify all
#   scripts/verify_golden.sh --update  # regenerate checksums after intentional changes
#   scripts/verify_golden.sh --checksums-only
#
# Exit codes:
#   0 — all golden outputs intact
#   1 — checksum mismatch (behavioral change detected)
#
# This script is the canonical verification gate for the isomorphism
# proof protocol. Any optimization PR MUST run this and demonstrate
# no checksum changes (or provide an isomorphism proof explaining why
# changes are acceptable).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC} $1"; }
fail() { echo -e "${RED}FAIL${NC} $1"; FAILED=1; }
warn() { echo -e "${YELLOW}WARN${NC} $1"; }

FAILED=0
CHECKSUMS_ONLY=0

cargo_exec() {
    rch exec -- cargo "$@"
}

usage() {
    cat <<'EOF'
Usage:
  scripts/verify_golden.sh
  scripts/verify_golden.sh --update
  scripts/verify_golden.sh --checksums-only

Options:
  --update          Regenerate checksum manifests after intentional changes.
  --checksums-only  Verify checksum manifests and git-tracked entries only.
EOF
}

write_json_checksums() {
    local dir="$1"
    local out="$2"
    (
        cd "$dir"
        mapfile -t files < <(find . -maxdepth 1 -type f -name '*.json' -printf '%f\n' | sort)
        if [[ ${#files[@]} -eq 0 ]]; then
            echo "no JSON checksum inputs found in $dir" >&2
            return 1
        fi
        sha256sum "${files[@]}" > "$out"
    )
}

write_conformance_golden_checksums() {
    (
        cd conformance/golden
        mapfile -t files < <(
            find . -maxdepth 1 -type f \( -name '*.json' -o -name '*.txt' \) -printf '%f\n' | sort
        )
        if [[ ${#files[@]} -eq 0 ]]; then
            echo "no conformance golden checksum inputs found" >&2
            return 1
        fi
        sha256sum "${files[@]}" > checksums.sha256
    )
}

verify_manifest_entries_tracked() {
    local dir="$1"
    local manifest="$2"
    local label="$3"
    local line digest file path
    local untracked=0

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        digest="${line%% *}"
        file="${line#*  }"
        if [ "$file" = "$line" ]; then
            file="${line#* }"
        fi
        file="${file#\*}"

        if [ -z "$digest" ] || [ -z "$file" ] || [ "$file" = "$line" ]; then
            fail "$label checksum manifest has malformed entry: $line"
            untracked=1
            continue
        fi

        if [[ "$file" = /* || "$file" = ".." || "$file" = ../* || "$file" = */../* || "$file" = */.. ]]; then
            fail "$label checksum manifest references path outside its directory: $file"
            untracked=1
            continue
        fi

        path="$dir/$file"
        if ! git ls-files --error-unmatch -- "$path" >/dev/null 2>&1; then
            fail "$label checksum manifest references untracked or ignored file: $file"
            untracked=1
        fi
    done < "$dir/$manifest"

    if [ "$untracked" -eq 0 ]; then
        pass "$label checksum entries are tracked by git"
    fi
}

case "${1:-}" in
    "")
        ;;
    "--checksums-only")
        CHECKSUMS_ONLY=1
        ;;
    "--update")
        echo "Updating checksums..."
        write_json_checksums conformance/fixtures checksums.sha256
        write_conformance_golden_checksums
        write_json_checksums tests/fixtures/golden checksums.txt
        echo "Checksums updated. Review and commit."
        exit 0
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

echo "=== Golden Output Verification ==="
echo ""

# ── 1. Fixture checksums ────────────────────────────────────────
echo "--- Fixture checksums ---"
if (cd conformance/fixtures && sha256sum -c checksums.sha256 --quiet 2>/dev/null); then
    pass "conformance/fixtures/ checksums match"
else
    fail "conformance/fixtures/ checksums MISMATCH"
    echo "  Run: scripts/verify_golden.sh --update  (after verifying changes are correct)"
fi
verify_manifest_entries_tracked conformance/fixtures checksums.sha256 "conformance/fixtures"

# ── 2. Golden reference checksums ────────────────────────────────
echo "--- Golden reference checksums ---"
if (cd conformance/golden && sha256sum -c checksums.sha256 --quiet 2>/dev/null); then
    pass "conformance/golden/ checksums match"
else
    fail "conformance/golden/ checksums MISMATCH"
    echo "  Run: scripts/verify_golden.sh --update  (after verifying changes are correct)"
fi
verify_manifest_entries_tracked conformance/golden checksums.sha256 "conformance/golden"

# ── 3. Legacy fixture checksums ───────────────────────────────────
echo "--- Legacy fixture checksums ---"
if (cd tests/fixtures/golden && sha256sum -c checksums.txt --quiet 2>/dev/null); then
    pass "tests/fixtures/golden/ checksums match"
else
    fail "tests/fixtures/golden/ checksums MISMATCH"
    echo "  Run: scripts/verify_golden.sh --update  (after verifying changes are correct)"
fi
verify_manifest_entries_tracked tests/fixtures/golden checksums.txt "tests/fixtures/golden"

if [ "$CHECKSUMS_ONLY" -eq 1 ]; then
    echo ""
    if [ "$FAILED" -eq 0 ]; then
        echo -e "${GREEN}All checksum manifest checks passed.${NC}"
        exit 0
    fi
    echo -e "${RED}Checksum manifest verification FAILED.${NC}"
    exit 1
fi

# ── 4. Parity report consistency ─────────────────────────────────
echo "--- Parity report ---"
if cargo_exec test -p ffs-harness -- parity_report_matches_feature_parity_md --quiet 2>/dev/null; then
    pass "ParityReport matches FEATURE_PARITY.md"
else
    fail "ParityReport vs FEATURE_PARITY.md mismatch"
fi

# ── 5. Conformance fixture validation ────────────────────────────
echo "--- Conformance fixtures ---"
if cargo_exec test -p ffs-harness --test conformance --quiet 2>/dev/null; then
    pass "all conformance fixtures validate"
else
    fail "conformance fixture validation failed"
fi

# ── 6. Golden JSON structural validation ─────────────────────────
echo "--- Golden JSON validation ---"
if cargo_exec test -p ffs-harness --test kernel_reference golden_json_parses_and_is_consistent --quiet 2>/dev/null; then
    pass "golden JSON parses and is consistent"
else
    fail "golden JSON validation failed"
fi

# ── 7. Summary ───────────────────────────────────────────────────
echo ""
if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}All golden output checks passed.${NC}"
    echo "Safe to proceed with optimization — behavior is unchanged."
else
    echo -e "${RED}Golden output verification FAILED.${NC}"
    echo ""
    echo "If changes are intentional, provide an isomorphism proof:"
    echo "  1. Copy docs/templates/ISOMORPHISM_PROOF_TEMPLATE.md into your PR description"
    echo "  2. Fill out each field"
    echo "  3. Run: scripts/verify_golden.sh --update"
    echo "  4. Commit the updated checksums"
    exit 1
fi
