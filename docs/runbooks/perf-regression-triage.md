# Performance Regression Triage Runbook

Systematic procedure for investigating, confirming, and resolving performance
regressions detected by the FrankenFS benchmark guard.

## Prerequisites

- Access to the repository with `cargo` and `rch` configured
- `benchmarks/thresholds.toml` present with per-operation thresholds
- At least one baseline JSON in `benchmarks/baselines/`
- `scripts/benchmark_record.sh` executable

## Quick Reference: Triage Decision Tree

```
Guard fires on operation X
│
├─ Is delta within noise floor?
│   └─ YES → Pass. No action needed.
│
├─ Is sample size < 3?
│   └─ YES → Inconclusive. Collect more runs:
│           scripts/benchmark_record.sh --runs 10
│
├─ Is the result statistically significant (p < 0.05)?
│   └─ NO → Likely noise. Re-run to confirm:
│          scripts/benchmark_record.sh --runs 10 --compare
│
├─ Is Cohen's d < 0.2 (negligible effect)?
│   └─ YES → Noise despite significance (underpowered test). Pass.
│
├─ Classify by benchmark family:
│   ├─ Parser (ffs-ondisk): CPU-bound, low variance
│   │   └─ Likely a real code regression. Check recent commits to ffs-ondisk.
│   │
│   ├─ Mount (ffs-fuse): FUSE syscall, high variance
│   │   └─ Check kernel/FUSE driver changes. Re-run on reference hardware.
│   │
│   ├─ MetadataOps / BlockCache / WritePath: moderate variance
│   │   └─ Check I/O scheduler, memory pressure, recent code changes.
│   │
│   ├─ Concurrency: scheduling-sensitive, high variance
│   │   └─ Check CPU count, load average, scheduler affinity.
│   │
│   ├─ Repair: CPU-heavy erasure coding
│   │   └─ Check SIMD/codegen changes, CPU thermal throttling.
│   │
│   └─ DegradedMode: intentionally stressed, widest thresholds
│       └─ Tightest check: did headroom or pressure levels change?
│
├─ Is hysteresis tracker confirming (2+ of last 3 runs fail)?
│   ├─ NO → Single-run flake. Monitor next run.
│   └─ YES → Confirmed regression. Proceed to resolution.
│
└─ Resolution:
    ├─ Code regression → bisect, fix, re-baseline
    ├─ Environment change → update host profile normalization factor
    └─ Threshold too tight → widen in benchmarks/thresholds.toml with rationale
```

## Step-by-Step Procedure

### Step 1: Identify the Failing Operation

Guard output includes the operation ID and family. Look for lines like:

```
FAIL  metadata_parity_cli  delta=+24.3%  effect=0.87(large)  p=0.002
WARN  block_cache_arc_scan  delta=+13.1%  effect=0.41(small)  p=0.031
```

Cross-reference the operation in the taxonomy:

```bash
rch exec -- cargo test -p ffs-harness --lib -- taxonomy_json_export --exact 2>&1 \
  | grep -A3 "operation_id.*FAILING_OP"
```

Or inspect `benchmarks/thresholds.toml` for per-operation overrides:

```bash
grep -A4 'FAILING_OP' benchmarks/thresholds.toml
```

### Step 2: Collect Fresh Multi-Run Samples

Single-run comparisons are unreliable. Collect at least 10 measured runs:

```bash
# Record fresh baseline with 10 runs and compare against stored baseline
scripts/benchmark_record.sh --runs 10 --compare

# Inspect per-operation hyperfine results
ls baselines/hyperfine/$(date +%Y%m%d)/
```

The raw JSON files contain per-run timing arrays suitable for statistical
comparison.

### Step 3: Evaluate Statistical Significance

The comparator pipeline (`perf_comparison.rs`) applies these gates in order:

| Gate | Condition | Verdict |
|------|-----------|---------|
| Noise floor | `delta% <= noise_floor_percent` | Pass |
| Insufficient data | `n < 3` per sample | Inconclusive (envelope only) |
| Not significant | `p >= 0.05` (Welch's t-test) | Pass (downgraded) |
| Negligible effect | `\|Cohen's d\| < 0.2` | Pass (downgraded) |
| Significant + meaningful | `p < 0.05` and `\|d\| >= 0.2` | Envelope verdict applies |

Run the harness comparison test to exercise the full pipeline:

```bash
rch exec -- cargo test -p ffs-harness --lib -- perf_comparison --nocapture
```

### Step 4: Check Hysteresis State

A single failing run may be a flake. The hysteresis tracker requires
`DEFAULT_HYSTERESIS_REQUIRED` (2) confirming runs within a
`DEFAULT_HYSTERESIS_WINDOW` (3) run window before escalating:

| Consecutive Pattern | Hysteresis Verdict |
|--------------------|--------------------|
| Fail | EarlyWarning (monitor) |
| Fail, Fail | ConfirmedFail (act) |
| Fail, Pass | NoSignal (cleared) |
| Warn, Warn | ConfirmedWarn (investigate) |
| Fail, Pass, Fail | EarlyWarning (not yet confirmed) |

If this is a first-time failure, re-run before escalating:

```bash
scripts/benchmark_record.sh --runs 10 --compare
```

### Step 5: Classify the Root Cause

#### 5a. Code Regression (Parser/Compute Path)

Symptoms: deterministic delta, reproduces across hosts, appeared after a
specific commit.

```bash
# Find the introducing commit
git log --oneline --since="3 days ago" -- crates/ffs-ondisk/ crates/ffs-core/

# Bisect if unclear
git bisect start HEAD <last_known_good>
git bisect run scripts/benchmark_record.sh --runs 5 --compare
```

#### 5b. Runtime/Environment Change

Symptoms: delta appears only on specific host profile, does not reproduce on
reference hardware, or appeared without code changes.

```bash
# Check host profile normalization
rch exec -- cargo test -p ffs-harness --lib -- host_profile --nocapture

# Compare against reference host
# Reference (csd-threadripper): normalization_factor = 1.0
# CI (GitHub Actions): normalization_factor = 0.15
# rch VPS: normalization_factor = 0.25
```

Environment checklist:
- [ ] CPU frequency scaling / thermal throttling
- [ ] I/O scheduler changes (check `cat /sys/block/*/queue/scheduler`)
- [ ] Kernel version upgrade (especially FUSE for Mount family)
- [ ] Memory pressure (check `free -h`, swap usage)
- [ ] Background load (check `uptime`, load average)

#### 5c. Threshold Needs Adjustment

Symptoms: CV% (coefficient of variation) for the operation is high relative to
the noise floor, or thresholds were set without sufficient calibration runs.

Threshold calibration procedure:
1. Run 5-10 baseline recordings on stable hardware
2. Calculate CV% across runs
3. Set noise floor to `1.5 * CV%`
4. Set warn threshold to `3 * CV%`, fail to `5 * CV%`
5. Update `benchmarks/thresholds.toml`:

```toml
[operation_thresholds.OPERATION_ID]
# Recalibrated YYYY-MM-DD: CV% was X.X% over N runs on HOST.
warn_percent = NEW_WARN
fail_percent = NEW_FAIL
noise_floor_percent = NEW_NOISE
```

### Step 6: Resolve and Re-Baseline

After fixing the root cause:

```bash
# Run full benchmark suite to generate new baseline
scripts/benchmark_record.sh --runs 10

# Verify the fix
scripts/benchmark_record.sh --runs 10 --compare

# Run E2E validation
scripts/e2e/ffs_benchmark_taxonomy_e2e.sh
scripts/e2e/ffs_perf_comparison_e2e.sh
```

## Evidence Checklist

Before reverting code or adjusting thresholds, collect:

- [ ] Multi-run comparison output (at least 10 measured runs)
- [ ] Operation family and applicable envelope thresholds
- [ ] Cohen's d (effect size) and p-value from Welch's t-test
- [ ] Hysteresis state (confirmed vs early-warning)
- [ ] CV% of both baseline and current samples
- [ ] Host profile and normalization factor used
- [ ] `git log` of relevant crate since last known-good baseline
- [ ] Environment snapshot (kernel, CPU governor, I/O scheduler, load)

## Default Acceptance Envelopes by Family

| Family | Noise Floor | Warn | Fail | Rationale |
|--------|------------|------|------|-----------|
| Parser | 3% | 8% | 15% | CPU-bound, sub-ms, low variance |
| Mount | 10% | 25% | 50% | FUSE kernel roundtrip, high variance |
| MetadataOps | 5% | 10% | 20% | Mixed I/O + CPU |
| BlockCache | 5% | 12% | 25% | Allocator-sensitive |
| WritePath | 5% | 12% | 25% | I/O scheduler variance |
| Concurrency | 8% | 20% | 40% | Thread scheduling sensitive |
| Repair | 5% | 10% | 20% | CPU-heavy erasure coding |
| DegradedMode | 15% | 30% | 60% | Intentionally stressed |

## Key File Locations

| Artifact | Path |
|----------|------|
| Threshold config | `benchmarks/thresholds.toml` |
| Taxonomy registry | `crates/ffs-harness/src/benchmark_taxonomy.rs` |
| Statistical comparator | `crates/ffs-harness/src/perf_comparison.rs` |
| Legacy threshold gate | `crates/ffs-harness/src/perf_regression.rs` |
| Baseline recorder | `scripts/benchmark_record.sh` |
| Stored baselines | `benchmarks/baselines/` |
| E2E taxonomy validation | `scripts/e2e/ffs_benchmark_taxonomy_e2e.sh` |
| E2E comparator validation | `scripts/e2e/ffs_perf_comparison_e2e.sh` |
| Log contract schema | `crates/ffs-harness/src/log_contract.rs` |
| This runbook | `docs/runbooks/perf-regression-triage.md` |
