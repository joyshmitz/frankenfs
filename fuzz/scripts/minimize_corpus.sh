#!/usr/bin/env bash
# minimize_corpus.sh - Guarded cargo-fuzz corpus minimization helper.
#
# cargo-fuzz minimization can consume substantial local CPU and rch does not
# safely offload cargo-fuzz cmin/tmin subcommands today. This script therefore
# fails closed unless the operator explicitly acknowledges local minimization.
#
# Usage:
#   FFS_ALLOW_LOCAL_CARGO_FUZZ_MINIMIZE=cargo-fuzz-minimization-may-run-locally \
#       ./fuzz/scripts/minimize_corpus.sh <target> [corpus_dir]
#   ./fuzz/scripts/minimize_corpus.sh --dry-run <target> [corpus_dir]

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$FUZZ_DIR/.." && pwd)"
cd "$REPO_ROOT"

ACK_VALUE="cargo-fuzz-minimization-may-run-locally"
DRY_RUN=0

usage() {
    cat <<EOF
Usage: minimize_corpus.sh [--dry-run] <target> [corpus_dir]

Minimizes a fuzz corpus with cargo fuzz cmin only when explicitly allowed:
  FFS_ALLOW_LOCAL_CARGO_FUZZ_MINIMIZE=${ACK_VALUE}

Use --dry-run to print the command without executing cargo fuzz.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "Unknown arg: $1" >&2
            usage >&2
            exit 2
            ;;
        *)
            break
            ;;
    esac
done

TARGET="${1:-}"
CORPUS_DIR="${2:-}"

if [[ -z "$TARGET" ]]; then
    usage >&2
    exit 1
fi

cmd=(cargo fuzz cmin "$TARGET" --fuzz-dir fuzz)
if [[ -n "$CORPUS_DIR" ]]; then
    cmd+=("$CORPUS_DIR")
fi

printf 'Minimization command:'
printf ' %q' "${cmd[@]}"
printf '\n'

if [[ "$DRY_RUN" == "1" ]]; then
    exit 0
fi

if [[ "${FFS_ALLOW_LOCAL_CARGO_FUZZ_MINIMIZE:-}" != "$ACK_VALUE" ]]; then
    echo "ERROR: refusing cargo fuzz cmin without explicit local minimization acknowledgement." >&2
    echo "Set FFS_ALLOW_LOCAL_CARGO_FUZZ_MINIMIZE=${ACK_VALUE} to allow this CPU-heavy local operation." >&2
    exit 3
fi

exec "${cmd[@]}"
