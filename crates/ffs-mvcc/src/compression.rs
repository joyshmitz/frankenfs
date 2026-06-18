//! Version chain compression for MVCC block versions.
//!
//! This module provides memory-efficient storage for block version chains
//! by deduplicating identical consecutive versions and enforcing configurable
//! chain length limits.
//!
//! # Strategies
//!
//! 1. **Identical-version dedup**: When a new version has bytes identical to
//!    the previous version in the chain, store an `Identical` marker instead
//!    of duplicating the data. The commit sequence is still recorded for
//!    correct FCW conflict detection.
//!
//! 2. **Chain length capping**: Configurable maximum chain length per block.
//!    When exceeded, the oldest versions beyond the limit are pruned
//!    (respecting active snapshots).
//!
//! # Resolving compressed versions
//!
//! Use [`resolve_data_with`] to walk backward through a version chain and find
//! the actual bytes for an `Identical` marker, decompressing if necessary.

use ffs_block::{AlignedVec, BlockBuf, DEFAULT_BLOCK_ALIGNMENT};
use serde::de::{EnumAccess, VariantAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;

/// Compressed representation of block version data.
///
/// Instead of always storing a full `Vec<u8>`, this enum allows
/// memory-efficient alternatives when the data hasn't changed,
/// or when compressed using standard algorithms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionData {
    /// Full block data stored as a shared aligned block buffer.
    Full(Arc<AlignedVec>),
    /// Data is byte-identical to the previous version in the chain.
    /// No data is stored; resolve by walking backward.
    Identical,
    /// Zstd compressed block data.
    Zstd(Vec<u8>),
    /// Brotli compressed block data.
    Brotli(Vec<u8>),
}

impl VersionData {
    #[must_use]
    pub fn full(bytes: Vec<u8>) -> Self {
        Self::Full(Arc::new(AlignedVec::from_vec(
            bytes,
            DEFAULT_BLOCK_ALIGNMENT,
        )))
    }

    /// Returns `true` if this version is a dedup marker (no data stored).
    #[must_use]
    pub fn is_identical(&self) -> bool {
        matches!(self, Self::Identical)
    }

    /// Returns `true` if this version stores full data inline.
    #[must_use]
    pub fn is_full(&self) -> bool {
        matches!(self, Self::Full(_))
    }

    /// Memory used by this version's data (0 for `Identical`).
    #[must_use]
    pub fn memory_bytes(&self) -> usize {
        match self {
            Self::Full(bytes) => bytes.len(),
            Self::Zstd(bytes) | Self::Brotli(bytes) => bytes.len(),
            Self::Identical => 0,
        }
    }
}

impl Serialize for VersionData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Full(bytes) => {
                serializer.serialize_newtype_variant("VersionData", 0, "Full", bytes.as_slice())
            }
            Self::Identical => serializer.serialize_unit_variant("VersionData", 1, "Identical"),
            Self::Zstd(bytes) => {
                serializer.serialize_newtype_variant("VersionData", 2, "Zstd", bytes)
            }
            Self::Brotli(bytes) => {
                serializer.serialize_newtype_variant("VersionData", 3, "Brotli", bytes)
            }
        }
    }
}

impl<'de> Deserialize<'de> for VersionData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_enum(
            "VersionData",
            &["Full", "Identical", "Zstd", "Brotli"],
            VersionDataVisitor,
        )
    }
}

#[derive(Deserialize)]
#[serde(field_identifier)]
enum VersionDataVariant {
    Full,
    Identical,
    Zstd,
    Brotli,
}

struct VersionDataVisitor;

impl<'de> Visitor<'de> for VersionDataVisitor {
    type Value = VersionData;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an MVCC version-data variant")
    }

    fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
    where
        A: EnumAccess<'de>,
    {
        let (variant, variant_access) = data.variant::<VersionDataVariant>()?;
        match variant {
            VersionDataVariant::Full => {
                let bytes = variant_access.newtype_variant::<Vec<u8>>()?;
                Ok(VersionData::full(bytes))
            }
            VersionDataVariant::Identical => {
                variant_access.unit_variant()?;
                Ok(VersionData::Identical)
            }
            VersionDataVariant::Zstd => {
                let bytes = variant_access.newtype_variant::<Vec<u8>>()?;
                Ok(VersionData::Zstd(bytes))
            }
            VersionDataVariant::Brotli => {
                let bytes = variant_access.newtype_variant::<Vec<u8>>()?;
                Ok(VersionData::Brotli(bytes))
            }
        }
    }
}

/// Resolve the actual bytes for a version at `index` in a chain.
///
/// If the version at `index` is `Identical`, walks backward through the
/// chain until a `Full` or compressed version is found. Returns `None`
/// only if the chain is malformed.
///
/// # Arguments
///
/// * `chain` - Slice of `(VersionData, ...)` tuples or items with a `.data` field.
/// * `index` - Index of the version to resolve.
pub fn resolve_data_with<'a, T, F>(
    chain: &'a [T],
    index: usize,
    get_data: F,
) -> Option<Cow<'a, [u8]>>
where
    F: Fn(&'a T) -> &'a VersionData,
{
    if index >= chain.len() {
        return None;
    }
    let mut i = index;
    loop {
        match get_data(&chain[i]) {
            VersionData::Full(bytes) => return Some(Cow::Borrowed(bytes.as_slice())),
            VersionData::Zstd(bytes) => {
                return match zstd::decode_all(bytes.as_slice()) {
                    Ok(decoded) => Some(Cow::Owned(decoded)),
                    Err(e) => {
                        tracing::error!(
                            index,
                            compressed_len = bytes.len(),
                            error = %e,
                            "mvcc_zstd_decompression_failed"
                        );
                        None
                    }
                };
            }
            VersionData::Brotli(bytes) => {
                let mut decoded = Vec::new();
                let mut decompressor = brotli::Decompressor::new(bytes.as_slice(), 4096);
                return match std::io::Read::read_to_end(&mut decompressor, &mut decoded) {
                    Ok(_) => Some(Cow::Owned(decoded)),
                    Err(e) => {
                        tracing::error!(
                            index,
                            compressed_len = bytes.len(),
                            error = %e,
                            "mvcc_brotli_decompression_failed"
                        );
                        None
                    }
                };
            }
            VersionData::Identical => {
                if i == 0 {
                    return None;
                }
                i -= 1;
            }
        }
    }
}

pub fn resolve_block_buf_with<T, F>(chain: &[T], index: usize, get_data: F) -> Option<BlockBuf>
where
    F: Fn(&T) -> &VersionData,
{
    if index >= chain.len() {
        return None;
    }
    let mut i = index;
    loop {
        match get_data(&chain[i]) {
            VersionData::Full(bytes) => {
                return Some(BlockBuf::from_shared_aligned(Arc::clone(bytes)));
            }
            VersionData::Zstd(bytes) => {
                return match zstd::decode_all(bytes.as_slice()) {
                    Ok(decoded) => Some(BlockBuf::new(decoded)),
                    Err(e) => {
                        tracing::error!(
                            index,
                            compressed_len = bytes.len(),
                            error = %e,
                            "mvcc_zstd_decompression_failed"
                        );
                        None
                    }
                };
            }
            VersionData::Brotli(bytes) => {
                let mut decoded = Vec::new();
                let mut decompressor = brotli::Decompressor::new(bytes.as_slice(), 4096);
                return match std::io::Read::read_to_end(&mut decompressor, &mut decoded) {
                    Ok(_) => Some(BlockBuf::new(decoded)),
                    Err(e) => {
                        tracing::error!(
                            index,
                            compressed_len = bytes.len(),
                            error = %e,
                            "mvcc_brotli_decompression_failed"
                        );
                        None
                    }
                };
            }
            VersionData::Identical => {
                if i == 0 {
                    return None;
                }
                i -= 1;
            }
        }
    }
}

/// Compression algorithm options for MVCC blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompressionAlgo {
    None,
    Zstd { level: i32 },
    Brotli { level: u32 },
}

/// Configuration for version chain compression behavior.
///
/// Controls dedup, compression algorithm, and chain length limits.
#[derive(Debug, Clone)]
pub struct CompressionPolicy {
    /// Enable dedup of identical consecutive versions.
    pub dedup_identical: bool,

    /// Maximum number of versions to retain per block.
    pub max_chain_length: Option<usize>,

    /// The compression algorithm to apply to new blocks.
    pub algo: CompressionAlgo,
}

impl Default for CompressionPolicy {
    fn default() -> Self {
        Self {
            dedup_identical: true,
            max_chain_length: Some(64),
            // No compression by default: upstream ext4/btrfs keep dirty data
            // uncompressed in the page cache, and zstd-compressing every dirty
            // block in the MVCC version store costs ~29us/block of pure CPU on
            // the commit hot path (46x slower 1 MiB writes) — pure waste on
            // incompressible data, which is stored `Full` after the failed
            // attempt anyway. Compression stays available via
            // `CompressionPolicy::with_*`/explicit policies for memory-bound
            // version-history use (bd-i5gwr).
            algo: CompressionAlgo::None,
        }
    }
}

impl CompressionPolicy {
    /// Create a policy with no compression (full data always stored, no cap).
    #[must_use]
    pub fn none() -> Self {
        Self {
            dedup_identical: false,
            max_chain_length: None,
            algo: CompressionAlgo::None,
        }
    }

    /// Create a policy with dedup but no chain cap.
    #[must_use]
    pub fn dedup_only() -> Self {
        Self {
            dedup_identical: true,
            max_chain_length: None,
            algo: CompressionAlgo::None,
        }
    }
}

/// Statistics about compression effectiveness.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompressionStats {
    /// Number of versions stored as `Full`.
    pub full_versions: usize,
    /// Number of versions stored as `Identical` (deduped).
    pub identical_versions: usize,
    /// Total bytes saved by dedup (sum of block sizes that would have been stored).
    pub bytes_saved: usize,
    /// Total bytes stored (sum of Full version data).
    pub bytes_stored: usize,
}

impl CompressionStats {
    /// Dedup ratio: fraction of versions that were deduplicated.
    /// Returns 0.0 if no versions exist.
    #[must_use]
    pub fn dedup_ratio(&self) -> f64 {
        let total = self.full_versions + self.identical_versions;
        if total == 0 {
            return 0.0;
        }
        self.identical_versions as f64 / total as f64
    }

    /// Compression ratio: bytes_stored / (bytes_stored + bytes_saved).
    /// Returns 1.0 if nothing was saved, 0.0 if everything was deduped.
    #[must_use]
    pub fn compression_ratio(&self) -> f64 {
        let total = self.bytes_stored + self.bytes_saved;
        if total == 0 {
            return 1.0;
        }
        self.bytes_stored as f64 / total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_data_full_roundtrip() {
        let data = VersionData::full(vec![1, 2, 3]);
        assert!(data.is_full());
        assert!(!data.is_identical());
        assert_eq!(data.memory_bytes(), 3);
    }

    #[test]
    fn version_data_identical() {
        let data = VersionData::Identical;
        assert!(data.is_identical());
        assert!(!data.is_full());
        assert_eq!(data.memory_bytes(), 0);
    }

    #[test]
    fn resolve_full_at_index() {
        let chain = vec![
            VersionData::full(vec![0xAA]),
            VersionData::full(vec![0xBB]),
        ];
        let result = resolve_data_with(&chain, 1, |d| d);
        assert_eq!(result.as_deref(), Some(&[0xBB][..]));
    }

    #[test]
    fn resolve_identical_walks_back() {
        let chain = vec![
            VersionData::full(vec![0xAA]),
            VersionData::Identical,
            VersionData::Identical,
        ];
        // Index 2 is Identical -> walks to 1 (Identical) -> walks to 0 (Full)
        let result = resolve_data_with(&chain, 2, |d| d);
        assert_eq!(result.as_deref(), Some(&[0xAA][..]));
    }

    #[test]
    fn resolve_identical_at_zero_returns_none() {
        let chain = vec![VersionData::Identical];
        let result = resolve_data_with(&chain, 0, |d| d);
        assert!(result.is_none());
    }

    #[test]
    fn resolve_corrupt_zstd_returns_none() {
        // A corrupt Zstd payload (e.g. disk corruption) must resolve to None
        // rather than panic, so the caller falls back to repair instead of
        // surfacing garbage. These bytes lack the zstd frame magic
        // (0x28 0xB5 0x2F 0xFD), so zstd::decode_all errors.
        let chain = vec![VersionData::Zstd(vec![0xFF, 0x00, 0x12, 0x34, 0x56, 0x78])];
        let result = resolve_data_with(&chain, 0, |d| d);
        assert!(result.is_none(), "corrupt zstd must resolve to None");
    }

    #[test]
    fn resolve_mixed_chain() {
        let chain = vec![
            VersionData::full(vec![1]), // 0
            VersionData::Identical,     // 1 -> resolves to [1]
            VersionData::full(vec![2]), // 2
            VersionData::Identical,     // 3 -> resolves to [2]
            VersionData::Identical,     // 4 -> resolves to [2]
        ];
        assert_eq!(
            resolve_data_with(&chain, 0, |d| d).as_deref(),
            Some(&[1][..])
        );
        assert_eq!(
            resolve_data_with(&chain, 1, |d| d).as_deref(),
            Some(&[1][..])
        );
        assert_eq!(
            resolve_data_with(&chain, 2, |d| d).as_deref(),
            Some(&[2][..])
        );
        assert_eq!(
            resolve_data_with(&chain, 3, |d| d).as_deref(),
            Some(&[2][..])
        );
        assert_eq!(
            resolve_data_with(&chain, 4, |d| d).as_deref(),
            Some(&[2][..])
        );
    }

    #[test]
    fn compression_stats_dedup_ratio() {
        let stats = CompressionStats {
            full_versions: 7,
            identical_versions: 3,
            bytes_saved: 300,
            bytes_stored: 700,
        };
        let ratio = stats.dedup_ratio();
        assert!((ratio - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn compression_stats_empty() {
        let stats = CompressionStats::default();
        assert!(stats.dedup_ratio().abs() < f64::EPSILON);
        assert!((stats.compression_ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn policy_defaults() {
        let policy = CompressionPolicy::default();
        assert!(policy.dedup_identical);
        assert_eq!(policy.max_chain_length, Some(64));
        // Default is no compression: dirty MVCC versions stay uncompressed
        // (matching upstream's page cache), zstd-per-block was a 46x write cost
        // (bd-i5gwr). Compression is opt-in via explicit policies.
        assert_eq!(policy.algo, CompressionAlgo::None);
    }

    #[test]
    fn policy_none() {
        let policy = CompressionPolicy::none();
        assert!(!policy.dedup_identical);
        assert_eq!(policy.max_chain_length, None);
        assert_eq!(policy.algo, CompressionAlgo::None);
    }

    // ── Property-based tests (proptest) ────────────────────────────────────

    use proptest::prelude::*;

    /// Strategy that generates a version chain of Full and Identical entries.
    /// Ensures the chain starts with Full so resolve always succeeds.
    fn version_chain_strategy() -> impl Strategy<Value = Vec<VersionData>> {
        proptest::collection::vec(any::<bool>(), 1..16).prop_flat_map(|bools| {
            let len = bools.len();
            proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..32), len..=len)
                .prop_map(move |datas| {
                    let mut chain = Vec::with_capacity(len);
                    for (i, is_identical) in bools.iter().enumerate() {
                        if i == 0 || !is_identical {
                            chain.push(VersionData::full(datas[i].clone()));
                        } else {
                            chain.push(VersionData::Identical);
                        }
                    }
                    chain
                })
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// VersionData::Full memory_bytes matches data length.
        #[test]
        fn proptest_version_data_full_memory_bytes(
            data in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let vd = VersionData::full(data.clone());
            prop_assert_eq!(vd.memory_bytes(), data.len());
            prop_assert!(vd.is_full());
            prop_assert!(!vd.is_identical());
        }

        /// VersionData::Identical always has zero memory_bytes.
        #[test]
        fn proptest_version_data_identical_zero_memory(
            _seed in any::<u64>(),
        ) {
            let vd = VersionData::Identical;
            prop_assert_eq!(vd.memory_bytes(), 0);
            prop_assert!(vd.is_identical());
            prop_assert!(!vd.is_full());
        }

        /// resolve_data_with on a valid chain always returns Some for any index.
        #[test]
        fn proptest_resolve_data_with_always_resolves(
            chain in version_chain_strategy(),
        ) {
            for i in 0..chain.len() {
                let result = resolve_data_with(&chain, i, |d| d);
                prop_assert!(result.is_some(), "resolve failed at index {}", i);
            }
        }

        /// resolve_data_with returns the same data for consecutive Identical entries.
        #[test]
        fn proptest_resolve_identical_same_as_predecessor(
            chain in version_chain_strategy(),
        ) {
            for i in 1..chain.len() {
                if chain[i].is_identical() {
                    let prev = resolve_data_with(&chain, i - 1, |d| d);
                    let curr = resolve_data_with(&chain, i, |d| d);
                    prop_assert_eq!(
                        prev.as_deref(), curr.as_deref(),
                        "Identical at index {} should match predecessor", i,
                    );
                }
            }
        }

        /// Appending Identical markers preserves existing resolutions and extends the tail.
        #[test]
        fn proptest_appended_identical_suffix_resolves_to_original_tail(
            chain in version_chain_strategy(),
            suffix_len in 1_usize..8,
        ) {
            let mut extended = chain.clone();
            for _ in 0..suffix_len {
                extended.push(VersionData::Identical);
            }

            for i in 0..chain.len() {
                let before = resolve_data_with(&chain, i, |d| d).map(std::borrow::Cow::into_owned);
                let after =
                    resolve_data_with(&extended, i, |d| d).map(std::borrow::Cow::into_owned);
                prop_assert_eq!(
                    after.as_deref(),
                    before.as_deref(),
                    "prefix index {} changed after appending identical suffix",
                    i,
                );
            }

            let expected_tail = resolve_data_with(&chain, chain.len() - 1, |d| d)
                .map(std::borrow::Cow::into_owned);
            for i in chain.len()..extended.len() {
                let resolved =
                    resolve_data_with(&extended, i, |d| d).map(std::borrow::Cow::into_owned);
                prop_assert_eq!(
                    resolved.as_deref(),
                    expected_tail.as_deref(),
                    "suffix index {} did not resolve to original tail",
                    i,
                );
            }
        }

        /// CompressionStats dedup_ratio is always in [0.0, 1.0].
        #[test]
        fn proptest_compression_stats_dedup_ratio_bounded(
            full in 0_usize..100,
            identical in 0_usize..100,
            stored in 0_usize..10000,
            saved in 0_usize..10000,
        ) {
            let stats = CompressionStats {
                full_versions: full,
                identical_versions: identical,
                bytes_saved: saved,
                bytes_stored: stored,
            };
            let ratio = stats.dedup_ratio();
            prop_assert!((0.0..=1.0).contains(&ratio), "dedup_ratio {} out of range", ratio);
        }

        /// CompressionStats compression_ratio is always in [0.0, 1.0].
        #[test]
        fn proptest_compression_stats_compression_ratio_bounded(
            full in 0_usize..100,
            identical in 0_usize..100,
            stored in 0_usize..10000,
            saved in 0_usize..10000,
        ) {
            let stats = CompressionStats {
                full_versions: full,
                identical_versions: identical,
                bytes_saved: saved,
                bytes_stored: stored,
            };
            let ratio = stats.compression_ratio();
            prop_assert!((0.0..=1.0).contains(&ratio), "compression_ratio {} out of range", ratio);
        }
    }
}
