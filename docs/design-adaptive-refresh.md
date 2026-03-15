# Design: Adaptive Repair Symbol Refresh (bd-m5wf.4.1)

## Problem

FrankenFS repair symbols become stale when source blocks are written after
the last refresh. The current `RefreshPolicy::Lazy` uses a fixed age timeout
(default 30s) to trigger re-encoding. This is suboptimal:

- **Under heavy writes**, 30s accumulates thousands of stale blocks, increasing
  the probability of unrecoverable corruption if a crash occurs during this window.
- **Under idle workloads**, 30s triggers unnecessary refreshes when zero blocks
  have actually changed.

A write-count-aware trigger can cap the number of stale blocks regardless of
write rate, while a hybrid approach takes the best of both.

## Expected-Loss Model

### Objective

Minimize the expected loss rate (cost per second of operation):

```
E[loss] = P(data_loss | stale_symbols) * data_loss_cost + refresh_io_cost / refresh_interval
```

### Data Loss Probability

When `S` source blocks exist and `K` have been written since the last refresh,
the repair symbols for those `K` blocks are stale. If a crash occurs AND
corruption hits a stale block, recovery fails:

```
P(data_loss) = P(crash) * (K / S) * P(corruption | crash)
```

- `P(crash)` = `crash_rate_per_sec` (default: ~3.17e-8, i.e., 1 crash/year)
- `K / S` = stale fraction (0..1)
- `P(corruption | crash)` = posterior corruption probability from `DurabilityAutopilot`

### Policy Definitions

| Policy | Refresh trigger | Avg stale blocks | Refresh frequency |
|--------|----------------|-----------------|-------------------|
| **Age-only** | Every `T` seconds | `write_rate * T / 2` | `1 / T` per second |
| **Block-count** | Every `N` writes | `N / 2` | `write_rate / N` per second |
| **Hybrid** | `min(T, N / write_rate)` | `min(write_rate * T, N) / 2` | `max(1/T, write_rate/N)` per second |

### Expected Loss Per Second

**Age-only** (timeout `T`, write rate `r`):
```
E[loss] = crash_rate * min(r*T/2, S)/S * P(corruption) * data_loss_cost + refresh_io_cost / T
```

**Block-count** (threshold `N`, write rate `r`):
```
E[loss] = crash_rate * min(N/2, S)/S * P(corruption) * data_loss_cost + refresh_io_cost * r / N
```

**Hybrid** (both `T` and `N`):
```
effective_window = min(T, N/r)
E[loss] = crash_rate * min(r*effective_window/2, S)/S * P(corruption) * data_loss_cost + refresh_io_cost / effective_window
```

## Policy Comparison Across Workload Profiles

Using default parameters: `data_loss_cost = 1e6`, `refresh_io_cost = 0.01`,
`crash_rate = 3.17e-8/s`, `corruption_prob = 0.01`, `source_blocks = 32768`,
`age_timeout = 30s`, `block_threshold = 500`.

| Profile | Write rate | Age-only stale | Block-count stale | Age-only loss/s | Block-count loss/s |
|---------|-----------|---------------|------------------|----------------|-------------------|
| **Idle** (0.01/s) | 0.01 | 0.15 blocks | 250 blocks | ~3.3e-4 (refresh dominates) | ~2e-7 (refresh negligible) |
| **Light** (1/s) | 1 | 15 blocks | 250 blocks | ~3.4e-4 | ~2.4e-5 |
| **Heavy** (100/s) | 100 | 1500 blocks | 250 blocks | ~3.5e-4 | ~2.0e-3 |
| **Burst** (1000/s) | 1000 | 15000 (capped 32768) | 250 blocks | ~3.5e-4 | ~2.0e-2 |

### Key Insight: Refresh I/O Cost Dominates Under Default Parameters

With `refresh_io_cost = 0.01` and `crash_rate = 3.17e-8`, the refresh I/O cost
is ~6 orders of magnitude larger than the expected data loss cost. This means:

- At **low write rates**, age-only is expensive because it refreshes every 30s
  regardless of whether any blocks changed.
- At **high write rates**, block-count is expensive because it refreshes
  `write_rate / threshold` times per second.
- The **hybrid** inherits the worst of both at extreme write rates.

### When Does Block-Count Dominate?

Block-count triggers dominate when `data_loss_cost` is high enough that the
stale-fraction reduction outweighs the extra refresh frequency cost. This
happens when:

```
data_loss_cost * crash_rate * corruption_prob >> refresh_io_cost
```

For the default crash rate and corruption probability, block-count dominance
requires `data_loss_cost >> refresh_io_cost / (crash_rate * corruption_prob)`
= `0.01 / (3.17e-8 * 0.01)` = ~31.5 million. Since the default `data_loss_cost`
is 1 million, we're at the threshold — block-count becomes beneficial only under
very high write rates or elevated corruption risk.

## Decision Boundary

The `block_count_dominance_threshold()` method finds the write rate at which
block-count loss equals age-only loss via binary search. Above this rate,
block-count triggers should be preferred.

## Recommendations

1. **Default policy should remain age-only** for most groups, since refresh I/O
   cost dominates under typical parameters.
2. **Block-count triggers should be enabled** for groups with elevated corruption
   risk (high posterior from `DurabilityAutopilot`) or when `data_loss_cost` is
   configured very high (e.g., metadata groups).
3. **Hybrid is optimal** when both conditions apply: the group has both high
   write rates AND high corruption risk.
4. The `RefreshLossModel::compare_policies()` method should be called by the
   adaptive autopilot to select the trigger policy per group based on observed
   workload and posterior corruption estimates.

## Implementation

The `RefreshLossModel` struct is implemented in `crates/ffs-repair/src/autopilot.rs`
alongside the existing `DurabilityAutopilot`. Key types:

- `RefreshLossModel` — parameterized expected-loss calculator
- `WorkloadProfile` — workload characterization (Idle/Light/Heavy/Burst)
- `RefreshPolicyComparison` — comparison result with best policy selection
- `RefreshTriggerPolicy` — selected policy (AgeOnly/BlockCount/Hybrid)

10 unit tests verify the model across all profiles and edge cases.
