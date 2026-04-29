#![no_main]

use ffs_repair::por::{
    compute_authenticator, verify_authenticator, AuthenticatorTable, PorKey, AUTHENTICATOR_SIZE,
};
use libfuzzer_sys::fuzz_target;

const KEY_BYTES: usize = 32;
const U64_BYTES: usize = 8;
const MAX_BLOCKS: usize = 8;
const MAX_BLOCK_BYTES: usize = 1024;

fn derive_key(data: &[u8]) -> PorKey {
    let mut key = [0_u8; KEY_BYTES];
    let len = data.len().min(KEY_BYTES);
    key[..len].copy_from_slice(&data[..len]);
    key
}

fn derive_base_index(data: &[u8]) -> u64 {
    let mut bytes = [0_u8; U64_BYTES];
    let end = (KEY_BYTES + U64_BYTES).min(data.len());
    if end > KEY_BYTES {
        bytes[..end - KEY_BYTES].copy_from_slice(&data[KEY_BYTES..end]);
    }
    u64::from_le_bytes(bytes)
}

fn derive_blocks(data: &[u8]) -> Vec<Vec<u8>> {
    let tail = data.get(KEY_BYTES + U64_BYTES..).unwrap_or(&[]);
    if tail.is_empty() {
        return vec![Vec::new()];
    }

    let requested = usize::from(tail[0] % MAX_BLOCKS as u8) + 1;
    let mut blocks = Vec::with_capacity(requested);
    let mut cursor = 1;

    for _ in 0..requested {
        if cursor >= tail.len() {
            blocks.push(Vec::new());
            continue;
        }

        let declared = usize::from(tail[cursor]);
        cursor += 1;
        let take = declared
            .min(MAX_BLOCK_BYTES)
            .min(tail.len().saturating_sub(cursor));
        let block = tail[cursor..cursor + take].to_vec();
        cursor += take;
        blocks.push(block);
    }

    blocks
}

fn mutate_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut mutated = bytes.to_vec();
    if mutated.is_empty() {
        mutated.push(1);
    } else {
        mutated[0] ^= 1;
    }
    mutated
}

fuzz_target!(|data: &[u8]| {
    let key = derive_key(data);
    let base_index = derive_base_index(data);
    let blocks = derive_blocks(data);

    // The harness intentionally exercises base_index values up to u64::MAX
    // (e.g., to validate the per-block bind-to-index assertion under
    // wrapping_add), so the index sequence must wrap rather than panic on
    // overflow inside the harness itself. compute_authenticator and
    // verify_authenticator both accept any u64 index.
    let block_index = |offset: usize| base_index.wrapping_add(offset as u64);

    let built = AuthenticatorTable::build(
        &key,
        blocks
            .iter()
            .enumerate()
            .map(|(offset, block)| (block_index(offset), block.as_slice())),
    );

    assert_eq!(
        built.len(),
        blocks.len(),
        "table length must match block count"
    );
    assert_eq!(
        built.storage_bytes(),
        built.len() * AUTHENTICATOR_SIZE,
        "table storage must track authenticator count"
    );

    let mut manual = AuthenticatorTable::with_capacity(blocks.len());
    for (offset, block) in blocks.iter().enumerate() {
        let index = block_index(offset);
        let auth = compute_authenticator(&key, index, block);
        assert!(
            verify_authenticator(&key, index, block, &auth),
            "fresh authenticators must always verify"
        );
        assert_eq!(
            built.get(offset),
            Some(&auth),
            "table build must expose the authenticator for every block"
        );
        manual.push(auth);
        assert_eq!(
            manual.get(offset),
            Some(&auth),
            "manual table must expose the authenticator it just stored"
        );
        assert_eq!(
            built.get(offset),
            manual.get(offset),
            "table build must match per-block authenticator computation"
        );

        let mut mutated_auth = auth;
        mutated_auth[0] ^= 1;
        assert!(
            !verify_authenticator(&key, index, block, &mutated_auth),
            "bit-flipped authenticators must fail verification"
        );

        let mut wrong_key = key;
        wrong_key[0] ^= 1;
        assert!(
            !verify_authenticator(&wrong_key, index, block, &auth),
            "verification must bind the authenticator to its key"
        );

        assert!(
            !verify_authenticator(&key, index.wrapping_add(1), block, &auth),
            "verification must bind the authenticator to its block index"
        );

        let mutated_block = mutate_bytes(block);
        assert!(
            !verify_authenticator(&key, index, &mutated_block, &auth),
            "verification must reject mutated block contents"
        );
    }
});
