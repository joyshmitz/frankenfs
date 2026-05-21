# FrankenFS G4 Soak/Canary Campaign - bd-xuo95.33

- Date: 2026-05-21 UTC
- Campaign ID: `bd-xuo95.33-g4-soak-canary-20260521`
- Git HEAD measured: `bf70d601edc37a077ce7102e3462a3f80f602a67` on `main`
- Verdict: `pass`
- Raw artifact directory: `baselines/hyperfine/20260521-bd-xuo95-33-soak`

## Counted Results

| Lane | Result | Real dated numbers | Evidence |
| --- | --- | --- | --- |
| Manifest validation | PASS | valid=true; profiles=4; workloads=7; long profiles=3 | `baselines/hyperfine/20260521-bd-xuo95-33-soak/manifest_report.json`; `[RCH] remote ts1 (122.5s)` |
| Harness unit contract | PASS | 18 passed, 0 failed, 2007 filtered out | `baselines/hyperfine/20260521-bd-xuo95-33-soak/soak_canary_unit.stderr`; `[RCH] remote ts1 (120.3s)` |
| Repair recovery E2E | PASS | 1 passed, 0 failed, 432 filtered out | `baselines/hyperfine/20260521-bd-xuo95-33-soak/repair_recovery_remote.stderr`; `[RCH] remote vmi1264463 (421.9s)` |
| Mounted FUSE canary | PASS | 9 iterations, 9 pass, 0 fail, 937 ms total wall time | `baselines/hyperfine/20260521-bd-xuo95-33-soak/mounted_canary_iterations.tsv` |

## Mounted Canary Timing

| Mode | Iterations | Passes | Mount attempts | Duration min/mean/max ms |
| --- | ---: | ---: | ---: | --- |
| cold | 3 | 3 | 3 | 86/89.33/92 |
| warm | 3 | 3 | 6 | 123/129.67/137 |
| recovery | 3 | 3 | 3 | 88/93.33/100 |

## Rejected Evidence

- `repair_recovery.stderr`: `rch` fell back local, so the result is not counted; remote retry passed on `vmi1264463`.
- `ffs_cli_build.stderr` and `ffs_cli_build_remote.stderr`: both build attempts used `rch` but fell back local due active project contention; they are retained as rejected build evidence and not counted as cargo validation proof.

## Raw Hashes

| Artifact | SHA-256 | Bytes |
| --- | --- | ---: |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/ffs_cli_build.stderr` | `0c53a8de9644a3309e6be88b529ffd8e4a4f7b8df9b63590d102a4f2688a951c` | 6467 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/ffs_cli_build.stdout` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/ffs_cli_build_remote.stderr` | `71a0e99ffce19e0037433b1830c2cb49ac80953d058afbc80b96adb3615f0232` | 539 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/ffs_cli_build_remote.stdout` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/manifest_report.json` | `bf33245ad7d45fbb7d9ae9061de67b777cbf1ab1930690fa5896868eff9b6bf7` | 23554 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/manifest_summary.md` | `00eee2a43fcde3cbdf05fe9dd2de41a5fcbef89416bb73edc368461e1ac46304` | 2615 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/manifest_validation.stderr` | `011b5dbc8297e11ef2feed5192e53a7c6e7a9eae5ea82a9b72b9de11a4b9f3ac` | 14932 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/manifest_validation.stdout` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mkfs_mount_probe.stderr` | `6ce7960c36ed800a70a2d0233b96242a78e4a56d9e4eedd40a22c92e5eca5ab6` | 27 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mkfs_mount_recovery_probe.stderr` | `6ce7960c36ed800a70a2d0233b96242a78e4a56d9e4eedd40a22c92e5eca5ab6` | 27 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_cold_1.stderr` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_cold_1.stdout` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_cold_1_report.json` | `0997266b8266565bd85bc2ce318a3f11f1ccb7e869d700f65cb28896dd7b4c7b` | 1374 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_cold_2.stderr` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_cold_2.stdout` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_cold_2_report.json` | `d71a946ad75e10909269c99bdb1b49873d9385722c70dc3de00f3a6773191389` | 1374 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_cold_3.stderr` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_cold_3.stdout` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_cold_3_report.json` | `0995586883e926336cfefa49fd0123ab6b39ee018ec15a58be4a58cb5e9ab1df` | 1374 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_recovery_1.stderr` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_recovery_1.stdout` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_recovery_1_report.json` | `51656fa04b22ba713dbe94f6fdde9260899d96ca07247624024d11e67a342d84` | 1419 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_recovery_2.stderr` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_recovery_2.stdout` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_recovery_2_report.json` | `4f6a8512c1a04329d150fa298aae6d14ba53c2d51f76ae3b7e6253e7b93d9095` | 1419 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_recovery_3.stderr` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_recovery_3.stdout` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_recovery_3_report.json` | `fb2c3d3dde36251893b7a3acc8435018ea2bb8f1a66b4c723d4b219481be3dfc` | 1419 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_warm_1.stderr` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_warm_1.stdout` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_warm_1_report.json` | `f9676bd014a65bb9c3f9b203bbcfe7a1fb11040b34ec5a13fa470fe0af3747e6` | 1895 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_warm_2.stderr` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_warm_2.stdout` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_warm_2_report.json` | `46844fb55fbfb4c6b122c40c40866424fc795dde734b69f62a4cca370e63e7b6` | 1895 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_warm_3.stderr` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_warm_3.stdout` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mount_warm_3_report.json` | `a1a368396deec9ca7114af7b11a17f0b7d118c62b1921eb46179c543db45986e` | 1895 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/mounted_canary_iterations.tsv` | `4b48cf725192fcbdaeed4d4a4d7ec99b94586eb471e70b0df1d08afab7fbebc4` | 2060 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/repair_recovery.stderr` | `ee1ccf71707d4e31a80651f954194391b189849ad7ba52ef591151f43593b964` | 5902 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/repair_recovery_remote.stderr` | `d06ea3c919110d04183ed857a4d71b65d19370e74e217827b9a0626ec32e5300` | 105950 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/repair_recovery_remote.stdout` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/sample_artifact_manifest.json` | `f1bb5df8c38e4548c03bd1623e9ba581a17c4001323cd99850b0b291ee00ad79` | 24165 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/soak_canary_unit.stderr` | `146c01b8e77df1b0cc2d13307f930cde6104fda45ae83882ae1cf8b37ef57fd2` | 28200 |
| `baselines/hyperfine/20260521-bd-xuo95-33-soak/soak_canary_unit.stdout` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0 |
