#!/usr/bin/env bash
# generate_seeds.sh - Generate initial seed corpus for fuzzers.

set -euo pipefail

cd "$(dirname "$0")/../.."

CORPUS_ROOT="${FUZZ_CORPUS_ROOT:-fuzz/corpus}"

echo "Generating seeds..."
mapfile -t targets < <(
    find fuzz/fuzz_targets -maxdepth 1 -name '*.rs' -printf '%f\n' \
        | sed 's/\.rs$//' \
        | sort
)

for t in "${targets[@]}"; do
    mkdir -p "$CORPUS_ROOT/$t"
    : > "$CORPUS_ROOT/$t/seed_empty"
    printf '\x00' > "$CORPUS_ROOT/$t/seed_byte"
done

echo "Generated seed_empty and seed_byte for ${#targets[@]} targets under ${CORPUS_ROOT}"
