use anyhow::Result;

pub fn parse_btrfs_root_item_bytenr(data: &[u8]) -> Result<u64> {
    if data.len() < 184 {
        anyhow::bail!(
            "btrfs root item payload too short: expected at least 184 bytes, got {}",
            data.len()
        );
    }
    let mut bytenr_raw = [0_u8; 8];
    bytenr_raw.copy_from_slice(&data[176..184]);
    let bytenr = u64::from_le_bytes(bytenr_raw);
    if bytenr == 0 {
        anyhow::bail!("btrfs root item bytenr must be non-zero");
    }
    Ok(bytenr)
}

pub fn parse_btrfs_block_group_total_bytes(data: &[u8]) -> Result<u64> {
    if data.len() < 16 {
        anyhow::bail!(
            "btrfs block-group payload too short: expected at least 16 bytes, got {}",
            data.len()
        );
    }
    let mut total_raw = [0_u8; 8];
    total_raw.copy_from_slice(&data[8..16]);
    let total_bytes = u64::from_le_bytes(total_raw);
    if total_bytes == 0 {
        anyhow::bail!("btrfs block-group total_bytes must be non-zero");
    }
    Ok(total_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_item_payload(bytenr: u64) -> Vec<u8> {
        let mut payload = vec![0_u8; 184];
        payload[176..184].copy_from_slice(&bytenr.to_le_bytes());
        payload
    }

    fn block_group_payload(total_bytes: u64) -> Vec<u8> {
        let mut payload = vec![0_u8; 16];
        payload[8..16].copy_from_slice(&total_bytes.to_le_bytes());
        payload
    }

    #[test]
    fn parse_root_item_bytenr_rejects_empty_payload() {
        let err = parse_btrfs_root_item_bytenr(&[]).expect_err("empty payload must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("too short"), "error must mention length: {msg}");
        assert!(msg.contains("184"), "error must mention required size: {msg}");
        assert!(msg.ends_with("got 0"), "error must report actual length: {msg}");
    }

    #[test]
    fn parse_root_item_bytenr_rejects_one_byte_under_minimum() {
        let err = parse_btrfs_root_item_bytenr(&[0xFF_u8; 183])
            .expect_err("183-byte payload must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("too short"), "error must mention length: {msg}");
        assert!(msg.ends_with("got 183"), "error must report actual length: {msg}");
    }

    #[test]
    fn parse_root_item_bytenr_rejects_zero_bytenr_at_minimum_length() {
        let err = parse_btrfs_root_item_bytenr(&root_item_payload(0))
            .expect_err("zero bytenr must be rejected");
        assert!(
            err.to_string().contains("non-zero"),
            "error must mention non-zero rule: {err}"
        );
    }

    #[test]
    fn parse_root_item_bytenr_accepts_minimum_length_with_valid_bytenr() {
        let bytenr = parse_btrfs_root_item_bytenr(&root_item_payload(0x0000_1234_5678_9ABC))
            .expect("valid bytenr should parse");
        assert_eq!(bytenr, 0x0000_1234_5678_9ABC);
    }

    #[test]
    fn parse_root_item_bytenr_accepts_payload_longer_than_minimum() {
        let mut payload = root_item_payload(0xCAFE_BABE_F00D_BAAD);
        payload.extend(std::iter::repeat_n(0xFF_u8, 64));
        let bytenr = parse_btrfs_root_item_bytenr(&payload)
            .expect("oversized payload must still parse");
        assert_eq!(bytenr, 0xCAFE_BABE_F00D_BAAD);
    }

    #[test]
    fn parse_root_item_bytenr_decodes_little_endian_at_offset_176() {
        let mut payload = vec![0xAB_u8; 184];
        payload[176..184].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        let bytenr =
            parse_btrfs_root_item_bytenr(&payload).expect("little-endian pattern must decode");
        assert_eq!(bytenr, 0x0807_0605_0403_0201);
    }

    #[test]
    fn parse_root_item_bytenr_ignores_bytes_outside_offset_window() {
        let mut payload = vec![0xAA_u8; 184];
        payload[176..184].copy_from_slice(&[0_u8; 8]);
        let err = parse_btrfs_root_item_bytenr(&payload)
            .expect_err("zero bytenr in window must be rejected despite surrounding noise");
        assert!(err.to_string().contains("non-zero"));
    }

    #[test]
    fn parse_root_item_bytenr_accepts_u64_max() {
        let bytenr =
            parse_btrfs_root_item_bytenr(&root_item_payload(u64::MAX)).expect("u64::MAX is non-zero");
        assert_eq!(bytenr, u64::MAX);
    }

    #[test]
    fn parse_root_item_bytenr_only_reads_offset_176_to_184() {
        // Decoy non-zero bytes elsewhere must not be mistaken for bytenr.
        let mut payload = vec![0_u8; 184];
        payload[0..8].copy_from_slice(&0xDEAD_BEEF_u64.to_le_bytes());
        payload[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        let err = parse_btrfs_root_item_bytenr(&payload)
            .expect_err("decoy bytes outside the bytenr window must not be parsed as bytenr");
        assert!(err.to_string().contains("non-zero"));
    }

    #[test]
    fn parse_block_group_total_bytes_rejects_empty_payload() {
        let err = parse_btrfs_block_group_total_bytes(&[])
            .expect_err("empty block-group payload must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("too short"), "error must mention length: {msg}");
        assert!(msg.contains("16"), "error must mention required size: {msg}");
        assert!(msg.ends_with("got 0"), "error must report actual length: {msg}");
    }

    #[test]
    fn parse_block_group_total_bytes_rejects_one_byte_under_minimum() {
        let err = parse_btrfs_block_group_total_bytes(&[0xFF_u8; 15])
            .expect_err("15-byte payload must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("too short"), "error must mention length: {msg}");
        assert!(msg.ends_with("got 15"), "error must report actual length: {msg}");
    }

    #[test]
    fn parse_block_group_total_bytes_rejects_zero_total() {
        let err = parse_btrfs_block_group_total_bytes(&block_group_payload(0))
            .expect_err("zero total_bytes must be rejected");
        assert!(err.to_string().contains("non-zero"));
    }

    #[test]
    fn parse_block_group_total_bytes_accepts_minimum_length_with_valid_total() {
        let total =
            parse_btrfs_block_group_total_bytes(&block_group_payload(8 * 1024 * 1024))
                .expect("valid total_bytes must parse");
        assert_eq!(total, 8 * 1024 * 1024);
    }

    #[test]
    fn parse_block_group_total_bytes_accepts_payload_longer_than_minimum() {
        let mut payload = block_group_payload(0x4000_0000);
        payload.extend(std::iter::repeat_n(0x55_u8, 32));
        let total = parse_btrfs_block_group_total_bytes(&payload)
            .expect("oversized payload must still parse");
        assert_eq!(total, 0x4000_0000);
    }

    #[test]
    fn parse_block_group_total_bytes_decodes_little_endian_at_offset_8() {
        let mut payload = vec![0xCC_u8; 16];
        payload[8..16].copy_from_slice(&[0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]);
        let total = parse_btrfs_block_group_total_bytes(&payload)
            .expect("little-endian pattern must decode");
        assert_eq!(total, 0x8070_6050_4030_2010);
    }

    #[test]
    fn parse_block_group_total_bytes_only_reads_offset_8_to_16() {
        // First 8 bytes hold used_bytes (irrelevant here); ensure parser
        // never reads from them as a fallback.
        let mut payload = vec![0_u8; 16];
        payload[0..8].copy_from_slice(&u64::MAX.to_le_bytes());
        let err = parse_btrfs_block_group_total_bytes(&payload)
            .expect_err("decoy in first 8 bytes must not become total_bytes");
        assert!(err.to_string().contains("non-zero"));
    }

    #[test]
    fn parse_block_group_total_bytes_accepts_u64_max() {
        let total = parse_btrfs_block_group_total_bytes(&block_group_payload(u64::MAX))
            .expect("u64::MAX is non-zero");
        assert_eq!(total, u64::MAX);
    }
}
