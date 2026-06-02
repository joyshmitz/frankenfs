# bd-xmh5g.5 - ffs-fuse per-core steal-plan allocation removal

Agent: PlumFern
Date: 2026-06-02
Crate: `ffs-fuse`
Lever: remove the temporary `Vec<i64>` allocation in `PerCoreDispatcher::steal_plan_for` and compute total, receiver depth, and donor in one ordered scan.

## Profile target

`cargo bench --profile release-perf -p ffs-fuse --bench mount_runtime` identified `mount_runtime_per_core_should_steal` as the slowest per-core route/planning microbench in the current ffs-fuse profile.

| Benchmark | Mean |
| --- | ---: |
| `mount_runtime_per_core_route_inode` | 2.4089 ns |
| `mount_runtime_per_core_route_lookup` | 2.3964 ns |
| `mount_runtime_per_core_should_steal` | 36.285 ns |
| `mount_runtime_per_core_aggregate_metrics` | 50.509 ns |
| `mount_runtime_metrics_record_throughput` | 11.502 ns |
| `mount_runtime_backpressure_normal` | 0.53821 ns |
| `mount_runtime_backpressure_degraded` | 1.1697 ns |
| `mount_runtime_backpressure_emergency` | 1.5052 ns |

The route benchmarks are already sub-3 ns. `should_steal` was still paying an allocation-shaped cost to materialize every pending depth before selecting a donor.

## Baseline

Command:

```sh
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary timeout 700 rch exec -- cargo bench --profile release-perf -p ffs-fuse --bench mount_runtime -- mount_runtime_per_core_should_steal --warm-up-time 1 --measurement-time 2 --sample-size 20 --noplot
```

Worker: `vmi1227854`

Criterion result:

```text
mount_runtime_per_core_should_steal
time: [37.201 ns 40.859 ns 45.587 ns]
```

## Alien recommendation card

Primitive: per-core, share-nothing queue-depth control with hot-path allocation removed.

Source fit:
- `/data/projects/alien_cs_graveyard/alien_cs_graveyard.md` scheduler/runtime guidance flags per-core work queues and queue-depth hot paths as places where allocation and shared queue churn create avoidable tail and throughput cost.
- The measured `should_steal` path is a scheduler decision over per-core queue depths, so the safe primitive is to keep the same decision rule but make the observation pass allocation-free.

EV score:

| Candidate | Impact | Confidence | Effort | Score |
| --- | ---: | ---: | ---: | ---: |
| Allocation-free ordered scan for `steal_plan_for` | 4 | 3 | 1 | 12.0 |

Fallback: restore the prior `pending_depths()` materialization if the golden rows, focused tests, or Criterion result regress.

## After

Command:

```sh
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary timeout 700 rch exec -- cargo bench --profile release-perf -p ffs-fuse --bench mount_runtime -- mount_runtime_per_core_should_steal --warm-up-time 1 --measurement-time 2 --sample-size 20 --noplot
```

Worker: `vmi1149989`

Criterion result:

```text
mount_runtime_per_core_should_steal
time: [10.007 ns 11.031 ns 12.010 ns]
```

Delta: 40.859 ns to 11.031 ns, -73.00%.

## Behavior proof

Ordering preserved: yes. The new implementation reads `pending_depth(idx)` in ascending index order, matching the old `pending_depths()` construction order.

Tie-breaking unchanged: yes. The old donor rule was `max_by_key((depth, Reverse(idx)))`, meaning highest pending depth wins and equal depths choose the lowest core index. The new donor update keeps an existing donor when it has higher depth or the same depth with a lower index.

Saturating arithmetic unchanged: yes. Pending depth still clamps negative values through `pending_depth(idx)`, and total still uses `i64::saturating_add`.

Threshold behavior unchanged: yes. Receiver bounds checks, idle-total check, average formula, sanitized threshold, and `mine >= avg / threshold` branch are unchanged.

Floating point: identical expression, `total as f64 / n as f64`.

RNG seeds: N/A.

Golden output sha256:

```text
dbf8ca6977d646f75b5c16ae901f75b14b8ca1247f4fd7e3fbd174a7d8303774
```

Golden rows:

```text
STEAL_PLAN_GOLDEN	idle_total	None
STEAL_PLAN_GOLDEN	balanced	None
STEAL_PLAN_GOLDEN	lowest_tie	Some(receiver=0,donor=1,receiver_pending=0,donor_pending=9,avg=5.500,transfer=4)
STEAL_PLAN_GOLDEN	receiver_busy	None
STEAL_PLAN_GOLDEN	negative_depths	Some(receiver=1,donor=2,receiver_pending=0,donor_pending=8,avg=4.000,transfer=4)
STEAL_PLAN_GOLDEN	invalid_threshold	Some(receiver=0,donor=1,receiver_pending=1,donor_pending=9,avg=5.000,transfer=4)
STEAL_PLAN_GOLDEN	out_of_range	None
```

## Validation

All commands were crate-scoped or local formatting/diff checks.

```text
PASS rch vmi1293453: cargo test -p ffs-fuse steal_plan -- --nocapture
PASS rch vmi1149989: cargo check -p ffs-fuse --all-targets
PASS rch vmi1149989: cargo clippy -p ffs-fuse --all-targets -- -D warnings
PASS local: cargo fmt --package ffs-fuse --check
PASS local: git diff --check
```
