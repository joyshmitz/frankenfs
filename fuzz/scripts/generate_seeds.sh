#!/usr/bin/env bash
# generate_seeds.sh - Generate initial seed corpus for fuzzers.
echo "Generating seeds..."
targets=("fuzz_ext4_metadata" "fuzz_btrfs_metadata" "fuzz_ext4_dir_extent" "fuzz_ext4_xattr")
for t in "${targets[@]}"; do
    mkdir -p "fuzz/corpus/$t"
    touch "fuzz/corpus/$t/seed_0"
done
