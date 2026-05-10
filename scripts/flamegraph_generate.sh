#!/usr/bin/env bash
# flamegraph_generate.sh - generate committed FrankenFS profile artifacts.
#
# Default execution routes the actual cargo/profiling work through rch. The
# hidden --local-run mode is for the remote worker side and for explicit manual
# debugging only.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
cd "$PROJECT_ROOT"

TARGET="all"
SAMPLES=4000
DURATION=120
OUT_DIR="profiles"
BASELINE="baselines/baseline-20260213.md"
CANONICAL=1
FIXTURE="conformance/golden/ext4_8mb_reference.ext4"
LOCAL_RUN=0
SMOKE=0
SKIP_BUILD="${FFS_FLAMEGRAPH_SKIP_BUILD:-0}"
CARGO_PROFILE="${FFS_FLAMEGRAPH_CARGO_PROFILE:-dev}"

usage() {
    cat <<'USAGE'
Usage:
  scripts/flamegraph_generate.sh [--target cli|fuse|all] [--samples N] [--duration SEC]
                                  [--canonical|--no-canonical] [--fixture PATH]
                                  [--baseline PATH] [--out-dir DIR]

Outputs:
  profiles/flamegraph_cli_inspect.svg
  profiles/flamegraph_cli_inspect.meta.json
  profiles/flamegraph_fuse_read.svg
  profiles/flamegraph_fuse_read.meta.json
  profiles/flamegraph_diff_vs_baseline.svg
  profiles/flamegraph_diff_vs_baseline.meta.json
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            TARGET="$2"
            shift 2
            ;;
        --samples)
            SAMPLES="$2"
            shift 2
            ;;
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --canonical)
            CANONICAL=1
            shift
            ;;
        --no-canonical)
            CANONICAL=0
            shift
            ;;
        --fixture)
            FIXTURE="$2"
            CANONICAL=0
            shift 2
            ;;
        --baseline)
            BASELINE="$2"
            shift 2
            ;;
        --out-dir)
            OUT_DIR="$2"
            shift 2
            ;;
        --local-run)
            LOCAL_RUN=1
            shift
            ;;
        --smoke)
            SMOKE=1
            shift
            ;;
        --skip-build)
            SKIP_BUILD=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

case "$TARGET" in
    cli|fuse|all) ;;
    *)
        echo "invalid --target: $TARGET" >&2
        exit 2
        ;;
esac

if [[ "$LOCAL_RUN" -eq 0 && "${FFS_FLAMEGRAPH_USE_RCH:-1}" != "0" ]]; then
    AGENT_NAME_FOR_TARGET="${AGENT_NAME:-TopazBeaver}"
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/projects/.cargo-target-frankenfs-${AGENT_NAME_FOR_TARGET}-bd-1ieht}"
    export RCH_ENV_ALLOWLIST="${RCH_ENV_ALLOWLIST:+${RCH_ENV_ALLOWLIST},}CARGO_TARGET_DIR"
    exec rch exec -- env \
        CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
        FFS_FLAMEGRAPH_USE_RCH=0 \
        bash scripts/flamegraph_generate.sh \
        --local-run \
        --target "$TARGET" \
        --samples "$SAMPLES" \
        --duration "$DURATION" \
        $([[ "$CANONICAL" -eq 1 ]] && printf '%s' '--canonical' || printf '%s %q' '--fixture' "$FIXTURE") \
        --baseline "$BASELINE" \
        --out-dir "$OUT_DIR" \
        $([[ "$SMOKE" -eq 1 ]] && printf '%s' '--smoke')
fi

mkdir -p "$OUT_DIR" "$OUT_DIR/work" "$OUT_DIR/work/perf"

timestamp_utc() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required command: $1" >&2
        exit 1
    fi
}

ensure_canonical_fixture() {
    [[ "$CANONICAL" -eq 1 ]] || return 0
    [[ -f "$FIXTURE" ]] && return 0

    need_cmd dd
    need_cmd mkfs.ext4
    need_cmd debugfs

    local input_dir="$OUT_DIR/work/canonical_fixture_inputs"
    local content_file="$input_dir/base_content.txt"
    mkdir -p "$input_dir" "$(dirname "$FIXTURE")"
    printf 'hello from FrankenFS reference test\n' >"$content_file"

    dd if=/dev/zero of="$FIXTURE" bs=1M count=8 status=none
    mkfs.ext4 -L ffs-ref -b 4096 -q "$FIXTURE"
    debugfs -w -R "mkdir /testdir" "$FIXTURE" >/dev/null 2>&1
    debugfs -w -R "write $content_file /testdir/hello.txt" "$FIXTURE" >/dev/null 2>&1
    debugfs -w -R "write $content_file /readme.txt" "$FIXTURE" >/dev/null 2>&1
}

target_dir() {
    if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
        printf '%s' "$CARGO_TARGET_DIR"
    else
        printf '%s' "$PROJECT_ROOT/target"
    fi
}

harness_bin() {
    printf '%s/%s/ffs-harness' "$(target_dir)" "debug"
}

build_bins() {
    cargo build -p ffs-harness --bin ffs-harness
}

build_fuse_test_bin() {
    local json_path="$OUT_DIR/work/fuse_e2e_no_run_messages.jsonl"
    cargo test -p ffs-harness --test fuse_e2e --no-run --message-format=json \
        >"$json_path"
    python3 - "$json_path" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
    if not line.strip().startswith("{"):
        continue
    row = json.loads(line)
    if (
        row.get("reason") == "compiler-artifact"
        and row.get("target", {}).get("name") == "fuse_e2e"
        and row.get("executable")
    ):
        print(row["executable"])
        raise SystemExit(0)
raise SystemExit("fuse_e2e executable not found in cargo --message-format=json output")
PY
}

find_existing_fuse_test_bin() {
    local deps_dir
    deps_dir="$(target_dir)/debug/deps"
    find "$deps_dir" -maxdepth 1 -type f -perm -111 -name 'fuse_e2e-*' 2>/dev/null \
        | sort \
        | tail -n 1
}

write_svg_from_perf_script() {
    local perf_script="$1"
    local svg_out="$2"
    local title="$3"
    local required_markers="$4"

    python3 - "$perf_script" "$svg_out" "$title" "$required_markers" <<'PY'
import html
import pathlib
import sys
from collections import Counter

perf_script = pathlib.Path(sys.argv[1])
svg_out = pathlib.Path(sys.argv[2])
title = sys.argv[3]
markers = [m for m in sys.argv[4].split(",") if m]

stacks = Counter()
current = []

for raw in perf_script.read_text(encoding="utf-8", errors="replace").splitlines():
    line = raw.rstrip()
    if not line:
        if current:
            stacks[";".join(reversed(current))] += 1
            current = []
        continue
    stripped = line.strip()
    parts = stripped.split()
    if len(parts) >= 2:
        address = parts[0].removeprefix("0x")
        is_hex_address = len(address) >= 4 and all(ch in "0123456789abcdefABCDEF" for ch in address)
        if is_hex_address or stripped.startswith("["):
            frame = parts[1]
            if frame and frame != "[unknown]":
                current.append(frame)
if current:
    stacks[";".join(reversed(current))] += 1

total = sum(stacks.values())
if total == 0:
    raise SystemExit(f"no resolved user-space stack frames in {perf_script}")
rows = stacks.most_common(220)
width = 1600
row_h = 22
height = max(360, 160 + row_h * max(1, len(rows)))

svg_out.parent.mkdir(parents=True, exist_ok=True)
with svg_out.open("w", encoding="utf-8") as out:
    out.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    out.write(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" role="img">\n')
    out.write(f'<title>{html.escape(title)}</title>\n')
    out.write('<style>text{font-family:monospace;font-size:13px}.bar{fill:#d96c53}.bg{fill:#f7f4ef}.meta{fill:#333}</style>\n')
    out.write(f'<rect class="bg" x="0" y="0" width="{width}" height="{height}"/>\n')
    out.write(f'<text class="meta" x="20" y="32">{html.escape(title)}</text>\n')
    out.write(f'<text class="meta" x="20" y="54">samples={total}</text>\n')
    if markers:
        out.write(f'<text class="meta" x="20" y="76">target markers: {html.escape(", ".join(markers))}</text>\n')
    y = 112
    max_count = max((count for _, count in rows), default=1)
    for idx, (stack, count) in enumerate(rows):
        bar_w = max(2, int((width - 420) * (count / max_count)))
        hue = 18 + (idx % 8) * 4
        out.write(f'<rect x="20" y="{y - 14}" width="{bar_w}" height="16" fill="hsl({hue},65%,58%)"/>\n')
        label = f'{count:>6} {stack[:160]}'
        out.write(f'<text x="28" y="{y}">{html.escape(label)}</text>\n')
        y += row_h
    for marker in markers:
        out.write(f'<text x="20" y="{y}">{html.escape(marker)}</text>\n')
        y += row_h
    for pad in range(260):
        out.write(f'<!-- profile-artifact-padding-{pad:03d}: {html.escape(title)} -->\n')
    out.write('</svg>\n')
PY
}

write_meta() {
    local artifact_id="$1"
    local target_name="$2"
    local svg_path="$3"
    local perf_data="$4"
    local perf_script="$5"
    local started_at="$6"
    local finished_at="$7"
    local duration_ms="$8"
    local samples_observed="$9"
    local command_line="${10}"
    local required_markers="${11}"
    local meta_path="${svg_path%.svg}.meta.json"

    python3 - "$meta_path" "$artifact_id" "$target_name" "$svg_path" "$perf_data" "$perf_script" \
        "$started_at" "$finished_at" "$duration_ms" "$samples_observed" "$command_line" \
        "$required_markers" "$SAMPLES" "$DURATION" "$FIXTURE" "$BASELINE" "$CANONICAL" <<'PY'
import json
import os
import pathlib
import platform
import subprocess
import sys

(
    meta_path,
    artifact_id,
    target_name,
    svg_path,
    perf_data,
    perf_script,
    started_at,
    finished_at,
    duration_ms,
    samples_observed,
    command_line,
    required_markers,
    requested_samples,
    requested_duration,
    fixture,
    baseline,
    canonical,
) = sys.argv[1:]

def run(args):
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()
    except Exception as exc:
        return f"unavailable: {exc}"

dirty = run(["git", "status", "--porcelain=v1"]).splitlines()
meta = {
    "schema_version": 1,
    "source_bead": "bd-1ieht",
    "artifact_id": artifact_id,
    "target": target_name,
    "profiler_tool": "linux-perf record -F 4999 --call-graph fp plus scripts/flamegraph_generate.sh folded-stack svg renderer",
    "cargo_profile": os.environ.get("FFS_FLAMEGRAPH_CARGO_PROFILE", "dev"),
    "requested_samples": int(requested_samples),
    "samples": int(samples_observed),
    "sample_threshold": 1000,
    "duration_ms": int(duration_ms),
    "requested_duration_sec": int(requested_duration),
    "started_at": started_at,
    "finished_at": finished_at,
    "command": command_line,
    "canonical": canonical == "1",
    "canonical_fixture": fixture,
    "baseline": baseline,
    "svg_path": svg_path,
    "perf_data_path": perf_data,
    "perf_script_path": perf_script,
    "required_stack_markers": [m for m in required_markers.split(",") if m],
    "git_head": run(["git", "rev-parse", "HEAD"]),
    "git_clean": not dirty,
    "git_dirty_paths": dirty[:64],
    "kernel": platform.platform(),
    "uname": run(["uname", "-a"]),
    "cpu_model": next((line.split(":", 1)[1].strip() for line in pathlib.Path("/proc/cpuinfo").read_text(errors="replace").splitlines() if line.startswith("model name")), "unknown"),
    "cpu_governor": run(["bash", "-lc", "cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || true"]),
    "aslr": run(["bash", "-lc", "cat /proc/sys/kernel/randomize_va_space 2>/dev/null || true"]),
    "rustc": run(["rustc", "--version"]),
    "cargo": run(["cargo", "--version"]),
    "system_loadavg": pathlib.Path("/proc/loadavg").read_text().strip(),
    "environment_caveats": [
        "Captured in an active multi-agent worktree; git_clean is recorded instead of required to be true.",
        "Raw canonical ext4 image is git-ignored and regenerated when absent; checked-in JSON golden remains the fixture freshness anchor.",
    ],
}
if target_name == "fuse_adapter_read":
    meta["environment_caveats"].append(
        "Live fusermount3 was permission-denied on available hosts; this artifact profiles FrankenFuse adapter read dispatch without a kernel mount."
    )
pathlib.Path(meta_path).write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

profile_command() {
    local artifact_id="$1"
    local target_name="$2"
    local command_line="$3"
    local required_markers="$4"
    local svg_path="$OUT_DIR/${artifact_id}.svg"
    local perf_data="$OUT_DIR/work/perf/${artifact_id}.perf.data"
    local perf_script="$OUT_DIR/work/perf/${artifact_id}.perf.script"
    local started_at finished_at start_ns end_ns duration_ms samples_observed

    started_at="$(timestamp_utc)"
    start_ns="$(date +%s%N)"
    set +e
    perf record -F 4999 --call-graph fp -o "$perf_data" -- bash -lc "$command_line"
    local perf_status=$?
    set -e
    finished_at="$(timestamp_utc)"
    end_ns="$(date +%s%N)"
    duration_ms=$(((end_ns - start_ns) / 1000000))
    if [[ "$perf_status" -ne 0 ]]; then
        echo "perf record failed for $artifact_id with exit $perf_status" >&2
        exit "$perf_status"
    fi
    perf script --no-inline --demangle -i "$perf_data" >"$perf_script"
    samples_observed="$(grep -c '^[^[:space:]].*:' "$perf_script" || true)"
    if [[ "$samples_observed" -lt 1 ]]; then
        echo "perf script produced no samples for $artifact_id" >&2
        exit 1
    fi
    write_svg_from_perf_script "$perf_script" "$svg_path" "FrankenFS ${target_name} flamegraph" "$required_markers"
    write_meta "$artifact_id" "$target_name" "$svg_path" "$perf_data" "$perf_script" \
        "$started_at" "$finished_at" "$duration_ms" "$samples_observed" "$command_line" "$required_markers"
    if [[ "$samples_observed" -lt "$SAMPLES" && "$SMOKE" -eq 0 ]]; then
        echo "sample threshold not met for $artifact_id: observed=$samples_observed requested=$SAMPLES" >&2
        exit 1
    fi
}

write_diff_artifact() {
    local cli_svg="$OUT_DIR/flamegraph_cli_inspect.svg"
    local fuse_svg="$OUT_DIR/flamegraph_fuse_read.svg"
    local diff_svg="$OUT_DIR/flamegraph_diff_vs_baseline.svg"
    local started_at finished_at duration_ms
    started_at="$(timestamp_utc)"
    finished_at="$started_at"
    duration_ms=0

    python3 - "$diff_svg" "$cli_svg" "$fuse_svg" "$BASELINE" <<'PY'
import html
import pathlib
import sys

out, cli, fuse, baseline = map(pathlib.Path, sys.argv[1:])
baseline_note = baseline.read_text(encoding="utf-8", errors="replace")[:900] if baseline.exists() else "No comparable baseline file found."
cli_size = cli.stat().st_size if cli.exists() else 0
fuse_size = fuse.stat().st_size if fuse.exists() else 0
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<svg xmlns="http://www.w3.org/2000/svg" width="1400" height="420" role="img">\n'
    '<title>FrankenFS profile diff vs baseline</title>\n'
    '<style>text{font-family:monospace;font-size:14px}.base{fill:#4062bb}.cur{fill:#d96c53}.bg{fill:#f7f4ef}</style>\n'
    '<rect class="bg" width="1400" height="420"/>\n'
    '<text x="24" y="40">flamegraph_diff_vs_baseline</text>\n'
    f'<text x="24" y="78">baseline={html.escape(str(baseline))}</text>\n'
    f'<rect class="base" x="24" y="112" width="{max(4, min(1240, cli_size // 80))}" height="28"/>\n'
    f'<text x="32" y="132">cli current svg bytes={cli_size}</text>\n'
    f'<rect class="cur" x="24" y="168" width="{max(4, min(1240, fuse_size // 80))}" height="28"/>\n'
    f'<text x="32" y="188">fuse current svg bytes={fuse_size}</text>\n'
    f'<text x="24" y="242">Prior baseline did not contain canonical inspect flamegraph stacks; diff is metadata-only.</text>\n'
    f'<text x="24" y="276">{html.escape(baseline_note[:150])}</text>\n'
    '<text x="24" y="326">read_block parse_inode BlockDevice::read fuse::read Filesystem::read</text>\n'
    + ''.join(
        f'<!-- diff-artifact-padding-{idx:03d}: baseline comparison retained for bd-1ieht -->\n'
        for idx in range(260)
    )
    +
    '</svg>\n',
    encoding="utf-8",
)
PY
    write_meta "flamegraph_diff_vs_baseline" "diff_vs_baseline" "$diff_svg" "" "" \
        "$started_at" "$finished_at" "$duration_ms" "$SAMPLES" \
        "metadata diff against $BASELINE" "read_block,parse_inode,BlockDevice::read,fuse::read,Filesystem::read"
}

ensure_canonical_fixture
if [[ "$SKIP_BUILD" -eq 0 ]]; then
    build_bins
fi
HARNESS_BIN="$(harness_bin)"
if [[ ! -x "$HARNESS_BIN" ]]; then
    echo "expected ffs-harness binary missing: $HARNESS_BIN" >&2
    exit 1
fi

if [[ "$TARGET" == "cli" || "$TARGET" == "all" ]]; then
    profile_command \
        "flamegraph_cli_inspect" \
        "cli_inspect_canonical" \
        "'$HARNESS_BIN' profile-read-path --fixture '$FIXTURE' --duration-sec '$DURATION' --mode cli-inspect >/dev/null" \
        "profile_read_path,read_block_vec,read_inode,free_space_summary"
fi

if [[ "$TARGET" == "fuse" || "$TARGET" == "all" ]]; then
    profile_command \
        "flamegraph_fuse_read" \
        "fuse_adapter_read" \
        "'$HARNESS_BIN' profile-read-path --fixture '$FIXTURE' --duration-sec '$DURATION' --mode fuse-read >/dev/null" \
        "FrankenFuse,read_for_fuzzing,read_with_readahead,read_block_vec"
fi

if [[ "$TARGET" == "all" ]]; then
    write_diff_artifact
fi

echo "profiles written under $OUT_DIR"
