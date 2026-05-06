#![no_main]
//! Fuzz target for the ext4 *_extra timestamp bit-pack helpers
//! `Ext4Inode::extra_nsec` and `extra_epoch` (bd-fqzsz).
//!
//! Companion to bd-834zk proptest layer (32 cases of the bit-pack
//! algebra). This target lifts the algebra to libfuzzer scale (>1M
//! iterations/session) with corpus learning across mask-edge u32
//! values, sign-bit boundaries, and pathological bit patterns. For
//! arbitrary u32 input, asserts:
//!
//!   MR-1 — Bit-pack inverse:
//!          (extra_nsec(x) << 2) | extra_epoch(x) == x
//!   MR-2 — Epoch bound:    extra_epoch(x) ≤ 3
//!   MR-3 — Nsec bound:     extra_nsec(x)  ≤ 0x3FFF_FFFF
//!   MR-4 — Disjoint encoding: nsec_only ⇒ epoch == 0;
//!                             epoch_only ⇒ nsec == 0
//!   MR-5 — Never panics:   implicit — any panic crashes the fuzzer.
//!
//! The helpers are on the hot path for every inode timestamp read
//! on ext4 v6+ filesystems. A regression that swapped the masks
//! (epoch ⇔ nsec) would silently corrupt every timestamp on every
//! ext4 image — invisible to substring tests but caught here as a
//! fuzzer failure.

use ffs_ondisk::Ext4Inode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let extra = u32::from_le_bytes(data[0..4].try_into().unwrap());

    let nsec = Ext4Inode::extra_nsec(extra);
    let epoch = Ext4Inode::extra_epoch(extra);

    // MR-1 Bit-pack inverse.
    assert_eq!(
        (nsec << 2) | epoch,
        extra,
        "bit-pack inverse violated: nsec={nsec:#x} epoch={epoch:#x} extra={extra:#x}"
    );

    // MR-2 Epoch bound.
    assert!(epoch <= 3, "epoch {epoch} exceeds 2-bit range");

    // MR-3 Nsec bound.
    assert!(nsec <= 0x3FFF_FFFF, "nsec {nsec:#x} exceeds 30-bit range");

    // MR-4 Disjoint encoding.
    let nsec_only = nsec << 2;
    assert_eq!(
        Ext4Inode::extra_epoch(nsec_only),
        0,
        "nsec-only payload {nsec_only:#x} reported nonzero epoch"
    );
    assert_eq!(
        Ext4Inode::extra_nsec(nsec_only),
        nsec,
        "nsec-only payload {nsec_only:#x} did not round-trip nsec"
    );
    let epoch_only = epoch;
    assert_eq!(
        Ext4Inode::extra_nsec(epoch_only),
        0,
        "epoch-only payload {epoch_only:#x} reported nonzero nsec"
    );
    assert_eq!(
        Ext4Inode::extra_epoch(epoch_only),
        epoch,
        "epoch-only payload {epoch_only:#x} did not round-trip epoch"
    );
});
