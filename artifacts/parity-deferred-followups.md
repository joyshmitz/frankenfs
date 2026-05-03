# Deferred Parity Follow-Up Coverage (bd-39lau)

Audit date: 2026-05-02 America/New_York / 2026-05-03 UTC.

Scope: closed beads whose `close_reason` matches `deferred` case-insensitively.
The requested `br list --status=closed --json | jq ...` path only returned the
default page. The full no-db query failed with:

```text
DATABASE_ERROR internal error: OpenRead failed: could not open storage cursor on root page 373
```

I used `.beads/issues.jsonl` as the durable source of truth:

```bash
jq -sr '[.[] | select(.status=="closed" and ((.close_reason // "") | test("deferred";"i")))] | length' .beads/issues.jsonl
```

Result: 44 closed beads matched. All 44 have a follow-up bead, completed
follow-up coverage, or an explicit non-goal/status downgrade. No new bead was
needed from this pass.

## Coverage Summary

| Deferred source bead(s) | Gap class | Follow-up coverage / disposition |
|---|---|---|
| bd-14jb.1 | false-positive vocabulary | `deferred reclamation` is an epoch-reclamation term in a completed MVCC GC bead, not a parity deferral. |
| bd-1fqq | false-positive vocabulary | `DeferredArcCache` is a type/path name in completed cache transaction tests, not a parity deferral. |
| bd-m5wf.2.5 | false-positive vocabulary | `deferred visibility` is the writeback-cache epoch-barrier semantic under a completed verification gate. |
| bd-29o | write-path scope deferral | Follow-up `bd-zge` exists and is closed; mounted/write hardening remains covered by open `bd-rchk0.3` and `bd-iub5w`. |
| bd-3rdi0 | extent write-path fuzz expansion | Follow-up coverage exists through closed extent mutation hardening beads (`bd-zge.4`, `bd-a5wh`, `bd-xh0ia`) plus open fuzz/conformance lane `bd-rchk7`. |
| bd-4ogh, bd-85ja | btrfs LZO compression | Follow-up `bd-t6h9` exists and is closed; malformed/size hardening also covered by closed `bd-id7f7` and `bd-xscni`. |
| bd-hoh5n | mounted background auto-scrub scope | Later lifecycle work exists: closed `bd-rchk6` and `bd-4h62v` for read-only mounted repair/scrub, plus open `bd-rchk0.1`, `bd-rchk0.1.4`, `bd-wjsuj`, and `bd-rchk7.3` for rw serialization and mounted repaired-read coverage. |
| bd-nzv3 | umbrella post-V1 hardening | Open follow-ups `bd-rchk7`, `bd-mpcse`, `bd-ch373`, `bd-naww5`, and `bd-9er6s` preserve the incremental hardening work outside the flat parity denominator. |
| bd-nzv3.10.2, bd-nzv3.23.2, bd-nzv3.23.3, bd-qthq | ext4 fast-commit e2e/corrupt-envelope/evidence hardening | Follow-up coverage exists through closed `bd-k9zm`, `bd-p8c4q`, `bd-v62xw`, `bd-6rg9o`, and `bd-jhg7z`; future adversarial replay expansion is covered by open `bd-rchk0.5.5`. |
| bd-nzv3.13.1, bd-nzv3.13.2, bd-nzv3.13.3, bd-nzv3.24, bd-nzv3.24.1, bd-nzv3.24.2, bd-nzv3.24.3 | btrfs multi-device RAID fixtures, degraded-mode, diagnostics | Open follow-up `bd-ch373` owns the multi-device corpus, degraded proof, operator e2e, logging, and safety evidence. |
| bd-nzv3.14.2, bd-nzv3.15, bd-nzv3.15.1, bd-nzv3.16, bd-nzv3.16.1, bd-nzv3.16.2, bd-nzv3.16.3, bd-nzv3.25.1, bd-nzv3.25.3 | btrfs send/receive export/apply/roundtrip beyond parse-only | Open follow-up `bd-naww5` owns export/apply parity, roundtrip regression, operator e2e, structured logging, and traceability. |
| bd-nzv3.21.1, bd-nzv3.21.2, bd-nzv3.21.3, bd-nzv3.3.3, bd-nzv3.4.2 | ext4 casefold fixtures, Unicode collisions, mutation/e2e evidence | Open follow-up `bd-9er6s` owns Unicode collision, mounted conformance, e2e/logging, and safety evidence. |
| bd-nzv3.22, bd-nzv3.22.1, bd-nzv3.22.2, bd-nzv3.22.3, bd-nzv3.5.2, bd-nzv3.6.1, bd-nzv3.7.1, bd-nzv3.7.2 | ext4 fscrypt key-managed fixtures/key-state/mutation/e2e beyond V1 nokey mode | V1 scope is explicit nokey mode. Completed follow-up coverage exists for nokey/raw-name/ioctl behavior (`bd-x8o96`, `bd-y9zeg`, `bd-4hzfa`, `bd-4qb1o`, `bd-3yy9k`); tiered docs/accounting follow-up `bd-mpcse` prevents flat parity wording from overclaiming full key-managed fscrypt readiness. |
| bd-nzv3.26.3 | btrfs tree-log recovery oracle and diagnostic snapshots | Follow-up coverage exists through closed `bd-l5d7c` and `bd-lk0l`; broader crash/replay expansion is covered by open `bd-rchk0.5.5`. |
| bd-okxi | btrfs free-space-cache performance optimization | Explicit non-correctness deferral. Open performance gates `bd-rchk5` and `bd-hol07` own profiling, claim-tier mapping, and future regression bead creation if this becomes a bottleneck. |

## Guardrail

The companion registry at `docs/reports/DEFERRED_PARITY_AUDIT.md` and harness
command `ffs-harness validate-deferred-parity-audit` make the highest-risk
families machine-checkable. This artifact is the human coverage ledger for the
full 44-row closed-as-deferred scan.
