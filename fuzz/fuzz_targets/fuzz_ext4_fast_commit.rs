#![no_main]

use ffs_journal::replay_fast_commit;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = replay_fast_commit(data);
    let second = replay_fast_commit(data);

    match (first, second) {
        (Ok(first), Ok(second)) => {
            assert_eq!(
                first, second,
                "fast-commit replay should be deterministic for successful parses"
            );

            assert!(
                first.transactions_found <= first.blocks_scanned,
                "committed transactions cannot exceed scanned HEAD blocks"
            );
            assert!(
                first.transactions_found + first.incomplete_transactions <= first.blocks_scanned,
                "each scanned HEAD can contribute at most one committed or discarded transaction"
            );
            assert!(
                first.operations.is_empty() || first.transactions_found > 0,
                "replayed operations require at least one committed transaction"
            );

            if first.transactions_found == 0 {
                assert_eq!(
                    first.last_tid, 0,
                    "without a committed transaction there must be no replayed tid"
                );
                assert!(
                    first.operations.is_empty(),
                    "operations should only be committed after a valid TAIL tag"
                );
            }

            if !first.fallback_required {
                assert_eq!(
                    first.incomplete_transactions, 0,
                    "clean replay should not discard incomplete transactions"
                );
            }
        }
        (Err(first), Err(second)) => {
            assert_eq!(
                first.to_string(),
                second.to_string(),
                "fast-commit replay should deterministically reject the same malformed input"
            );
        }
        (left, right) => {
            panic!(
                "fast-commit replay changed success/failure mode: left={left:?} right={right:?}"
            );
        }
    };
});
