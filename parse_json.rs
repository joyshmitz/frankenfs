use std::fs;
fn main() {
    let s = fs::read_to_string("conformance/fixtures/btrfs_fstree_leaf.json").unwrap();
    let json: serde_json::Value = serde_json::from_str(&s).unwrap();
    let writes = json["writes"].as_array().unwrap();
    for w in writes {
        if w["offset"].as_u64().unwrap() == 101 {
            let hex_str = w["hex"].as_str().unwrap();
            println!("Length: {}", hex_str.len());
            println!("String: {}", hex_str);
            let bytes = hex::decode(hex_str).unwrap();
            let key_obj = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
            let item_type = bytes[8];
            let key_off = u64::from_le_bytes(bytes[9..17].try_into().unwrap());
            let data_off = u32::from_le_bytes(bytes[17..21].try_into().unwrap());
            let data_size = u32::from_le_bytes(bytes[21..25].try_into().unwrap());
            println!("obj: {}, type: {}, key_off: {}, data_off: {}, size: {}", key_obj, item_type, key_off, data_off, data_size);
        }
    }
}
