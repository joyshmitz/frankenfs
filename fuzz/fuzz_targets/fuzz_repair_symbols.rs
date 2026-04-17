#![no_main]

use ffs_repair::symbol::{RepairBlockHeader, RepairGroupDescExt, SymbolDigest};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let block_header_first = RepairBlockHeader::parse(data);
    let block_header_second = RepairBlockHeader::parse(data);
    assert_eq!(
        block_header_first, block_header_second,
        "repair block header parsing should be deterministic"
    );
    if let Ok(header) = block_header_first {
        assert_eq!(
            RepairBlockHeader::parse(&header.to_bytes()),
            Ok(header.clone()),
            "repair block headers should round-trip through their canonical encoding"
        );
        assert_eq!(
            header.payload_size(),
            usize::from(header.symbol_count) * usize::from(header.symbol_size),
            "payload_size should match the encoded symbol geometry"
        );
    }

    let group_desc_first = RepairGroupDescExt::parse(data);
    let group_desc_second = RepairGroupDescExt::parse(data);
    assert_eq!(
        group_desc_first, group_desc_second,
        "repair group descriptor parsing should be deterministic"
    );
    if let Ok(desc) = group_desc_first {
        assert_eq!(
            RepairGroupDescExt::parse(&desc.to_bytes()),
            Ok(desc.clone()),
            "repair group descriptors should round-trip through their canonical encoding"
        );
    }

    let symbol_digest_first = SymbolDigest::parse(data);
    let symbol_digest_second = SymbolDigest::parse(data);
    assert_eq!(
        symbol_digest_first, symbol_digest_second,
        "symbol digest parsing should be deterministic"
    );
    if let Ok(digest) = symbol_digest_first {
        assert_eq!(
            SymbolDigest::parse(&digest.to_bytes()),
            Ok(digest),
            "symbol digests should round-trip through their canonical encoding"
        );
    }
});
