#!/usr/bin/env bash
# Smoke-test the flamegraph helper with a small sample/time budget. The helper
# still routes cargo work through rch unless FFS_FLAMEGRAPH_USE_RCH=0 is set.

set -euo pipefail

cd "$(dirname "$0")/.."

OUT_DIR="${1:-profiles/smoke}"
mkdir -p "$OUT_DIR"

scripts/flamegraph_generate.sh \
    --target cli \
    --samples 100 \
    --duration 5 \
    --out-dir "$OUT_DIR" \
    --smoke

python3 - "$OUT_DIR/flamegraph_cli_inspect.svg" "$OUT_DIR/flamegraph_cli_inspect.meta.json" <<'PY'
import json
import pathlib
import sys
import xml.etree.ElementTree as ET

svg = pathlib.Path(sys.argv[1])
meta = pathlib.Path(sys.argv[2])
ET.parse(svg)
data = json.loads(meta.read_text(encoding="utf-8"))
assert data["samples"] >= 1, data
assert data["duration_ms"] > 0, data
PY
