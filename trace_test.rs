use std::convert::TryFrom;
fn main() {
    let block_len = 16384;
    let raw_data_offset = 15936u32;
    let BTRFS_HEADER_SIZE = 101usize;
    let data_offset = raw_data_offset.checked_add(u32::try_from(BTRFS_HEADER_SIZE).unwrap()).unwrap();
    let data_size = 160u32;
    let data_end = usize::try_from(data_offset)
        .ok()
        .and_then(|off| off.checked_add(usize::try_from(data_size).unwrap()))
        .unwrap();
    println!("data_end: {}, block_len: {}, failed: {}", data_end, block_len, data_end > block_len);
}
