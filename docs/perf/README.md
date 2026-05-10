# FrankenFS Performance Evidence

`profiles/` contains committed profile artifacts that are safe for release and
review workflows. Raw `perf.data`, generated fixture images, and scratch inputs
stay under `profiles/work/`, which is ignored.

## Canonical Read-Path Flamegraphs

Regenerate the current read-path artifacts with:

```bash
AGENT_NAME="${AGENT_NAME:-TopazBeaver}" \
CARGO_TARGET_DIR=/data/projects/.cargo-target-frankenfs-${AGENT_NAME:-TopazBeaver}-bd-1ieht \
scripts/flamegraph_generate.sh --target all --samples 4000 --duration 120 --canonical
```

The helper routes cargo work through `rch` by default. It writes:

| Artifact | Meaning |
|---|---|
| `profiles/flamegraph_cli_inspect.svg` | `ffs-cli inspect` against the canonical ext4 reference image |
| `profiles/flamegraph_fuse_read.svg` | FUSE adapter read dispatch profile through `FrankenFuse::read_for_fuzzing` |
| `profiles/flamegraph_diff_vs_baseline.svg` | baseline comparison summary against `baselines/baseline-20260213.md` |

Each SVG has a sibling `*.meta.json` with sample counts, command line,
toolchain, kernel, CPU, ASLR, governor, git head, and clean-tree status.

The current host denied live `fusermount3` mounts, so the FUSE artifact uses the
same adapter read/readahead/backend path without a kernel mount. Re-run on a
host with permitted FUSE mounts if a kernel-mounted trace is required.

Run the smoke path with:

```bash
scripts/flamegraph_smoke.sh
```

Run the committed-artifact guard with:

```bash
RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR \
CARGO_TARGET_DIR=/data/projects/.cargo-target-frankenfs-${AGENT_NAME:-TopazBeaver}-bd-1ieht \
rch exec -- cargo test -p ffs-harness --test profile_artifacts
```
