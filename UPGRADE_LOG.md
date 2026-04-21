# Upgrade Log

## 2026-04-21: asupersync 0.2.5 → 0.3.0

**Commits:**
- `83907c2` chore(deps): bump asupersync 0.2.5 → 0.3.0 (crates.io v0.3.0)
- `a6bb60d` fix(ffs-core): update tests for asupersync 0.3 threshold changes

**Breaking changes in asupersync 0.3:**

The `SystemPressure::degradation_level()` thresholds changed:

| Level | Old threshold | New threshold | Old label  | New label  |
|-------|--------------|---------------|------------|------------|
| 0     | >= 0.50      | >= 0.90       | normal     | normal     |
| 1     | >= 0.30      | >= 0.65       | warning    | light      |
| 2     | >= 0.15      | >= 0.35       | degraded   | moderate   |
| 3     | >= 0.05      | >= 0.10       | critical   | heavy      |
| 4     | < 0.05       | < 0.10        | emergency  | emergency  |

**Migration:**
- All test assertions using headroom values were updated
- `DegradationLevel` doc comments updated to reflect new boundaries
- Internal FrankenFS level names (Warning, Degraded, Critical) kept unchanged
