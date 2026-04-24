# Conformance Divergences - MVCC WAL on-disk format

Every intentional deviation from the FrankenFS MVCC WAL record format must be
catalogued here. The `conformance_wal_golden.rs` suite currently has no accepted
format divergences: header bytes, commit records, checksums, ordering, short
record handling, and corruption reporting are expected to match the in-tree WAL
spec exactly.

When an implementation change intentionally alters the WAL format, update the
crate-level layout documentation in `crates/ffs-mvcc/src/wal.rs`, add the new
golden coverage, and record the accepted divergence here in the same change.
