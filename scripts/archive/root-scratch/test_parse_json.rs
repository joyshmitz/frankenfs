use std::fs;
use ffs_ondisk::btrfs::parse_leaf_items;
use serde_json::Value;

fn main() {
    let json = fs::read_to_string("conformance/fixtures/btrfs_leaf_node.json").unwrap();
    let fixture: Value = serde_json::from_str(&json).unwrap();
    let size = fixture["size"].as_u64().unwrap() as usize;
    let mut buf = vec![0u8; size];
    for write in fixture["writes"].as_array().unwrap() {
        let offset = write["offset"].as_u64().unwrap() as usize;
        let hex = write["hex"].as_str().unwrap();
        let bytes = hex::decode(hex).unwrap();
        buf[offset..offset + bytes.len()].copy_from_slice(&bytes);
    }
    
    let (_, items) = parse_leaf_items(&buf).unwrap();
    for (i, item) in items.iter().enumerate() {
        println!("item {}: data_offset={}, data_size={}", i, item.data_offset, item.data_size);
    }
}
