#!/bin/bash
pkill -9 -f python
rm -f /data/projects/frankenfs/*.log
rm -f /data/projects/frankenfs/*.out
rm -f /data/projects/frankenfs/*.txt
rm -f /data/projects/frankenfs/*.jsonl
# Keep README.md and Cargo.toml etc
