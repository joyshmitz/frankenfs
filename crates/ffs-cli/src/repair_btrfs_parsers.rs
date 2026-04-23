use anyhow::{bail, Result};

pub fn parse_btrfs_root_item_bytenr(data: &[u8]) -> Result<u64> {
    if data.len() < 184 {
        bail!(
            "btrfs root item payload too short: expected at least 184 bytes, got {}",
            data.len()
        );
    }
    let mut bytenr_raw = [0_u8; 8];
    bytenr_raw.copy_from_slice(&data[176..184]);
    let bytenr = u64::from_le_bytes(bytenr_raw);
    if bytenr == 0 {
        bail!("btrfs root item bytenr must be non-zero");
    }
    Ok(bytenr)
}

pub fn parse_btrfs_block_group_total_bytes(data: &[u8]) -> Result<u64> {
    if data.len() < 16 {
        bail!(
            "btrfs block-group payload too short: expected at least 16 bytes, got {}",
            data.len()
        );
    }
    let mut total_raw = [0_u8; 8];
    total_raw.copy_from_slice(&data[8..16]);
    let total_bytes = u64::from_le_bytes(total_raw);
    if total_bytes == 0 {
        bail!("btrfs block-group total_bytes must be non-zero");
    }
    Ok(total_bytes)
}
