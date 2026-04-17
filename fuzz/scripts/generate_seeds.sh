#!/usr/bin/env bash
# generate_seeds.sh - Generate initial seed corpus for fuzzers.

set -euo pipefail

cd "$(dirname "$0")/../.."

echo "Generating seeds..."
mapfile -t targets < <(
    find fuzz/fuzz_targets -maxdepth 1 -name '*.rs' -printf '%f\n' \
        | sed 's/\.rs$//' \
        | sort
)

for t in "${targets[@]}"; do
    mkdir -p "fuzz/corpus/$t"
    : > "fuzz/corpus/$t/seed_empty"
    printf '\x00' > "fuzz/corpus/$t/seed_byte"
done
