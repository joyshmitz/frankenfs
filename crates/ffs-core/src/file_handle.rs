#![forbid(unsafe_code)]

//! NFS-style file handles for `name_to_handle_at(2)` / `open_by_handle_at(2)`.
//!
//! A file handle is an opaque byte buffer that lets a caller resume access to
//! an inode across unmount/remount, without keeping a path. The kernel routes
//! `name_to_handle_at` to the filesystem driver to obtain the handle and
//! `open_by_handle_at` (typically root-only via `CAP_DAC_READ_SEARCH`) to
//! re-open it.
//!
//! For ext4 the on-disk handle is a `(u32 ino, u32 generation)` pair encoded
//! in 8 bytes. FrankenFS uses 64-bit inode numbers (the `InodeNumber` type),
//! so the wire format here widens to:
//!
//! ```text
//! offset  size  field
//! 0       8     inode number (little-endian u64)
//! 8       4     NFS generation cookie (little-endian u32)
//! ```
//!
//! Total: [`FILE_HANDLE_LEN`] = 12 bytes. `FUSE_FILEHANDLE_LEN` is 128 bytes
//! so this comfortably fits inside the kernel's `f_handle.f_handle[]`. An
//! `open_by_handle_at` caller decodes the bytes, looks up the inode, and
//! verifies that the on-disk generation still matches — if the inode has
//! been freed and reused, the generation cookie has been bumped (see
//! [`ffs_inode::create_inode`]) and the lookup returns
//! [`HandleError::Stale`] rather than silently resolving to the new inode.

use ffs_error::FfsError;
use ffs_types::InodeNumber;

/// On-disk size of a FrankenFS NFS-style file handle.
pub const FILE_HANDLE_LEN: usize = 12;

/// Failure modes for handle decode + verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandleError {
    /// The byte buffer was the wrong length to be a FrankenFS handle.
    BadLength { actual: usize, expected: usize },
    /// The buffer parsed but its generation cookie does not match the
    /// current on-disk inode generation. Surface as `ESTALE` to userspace
    /// per the `open_by_handle_at(2)` contract.
    Stale {
        ino: InodeNumber,
        expected_generation: u32,
        observed_generation: u32,
    },
}

impl HandleError {
    /// Map to the libc errno that `open_by_handle_at(2)` userspace expects.
    #[must_use]
    pub fn to_errno(&self) -> i32 {
        match self {
            Self::BadLength { .. } => libc::EINVAL,
            Self::Stale { .. } => libc::ESTALE,
        }
    }
}

impl From<HandleError> for FfsError {
    fn from(err: HandleError) -> Self {
        Self::Io(std::io::Error::from_raw_os_error(err.to_errno()))
    }
}

/// Encode `(ino, generation)` into a fixed-size handle buffer.
#[must_use]
pub fn encode(ino: InodeNumber, generation: u32) -> [u8; FILE_HANDLE_LEN] {
    let mut out = [0_u8; FILE_HANDLE_LEN];
    out[0..8].copy_from_slice(&ino.0.to_le_bytes());
    out[8..12].copy_from_slice(&generation.to_le_bytes());
    out
}

/// Decode a handle buffer back into `(ino, generation)`.
///
/// Returns [`HandleError::BadLength`] if the buffer is not exactly
/// [`FILE_HANDLE_LEN`] bytes. Generation validation is the caller's
/// responsibility — use [`verify`] once the current inode attrs are known.
pub fn decode(bytes: &[u8]) -> Result<(InodeNumber, u32), HandleError> {
    if bytes.len() != FILE_HANDLE_LEN {
        return Err(HandleError::BadLength {
            actual: bytes.len(),
            expected: FILE_HANDLE_LEN,
        });
    }
    let ino = u64::from_le_bytes(bytes[0..8].try_into().unwrap_or([0; 8]));
    let generation = u32::from_le_bytes(bytes[8..12].try_into().unwrap_or([0; 4]));
    Ok((InodeNumber(ino), generation))
}

/// Compare the handle's generation against the live one and return
/// [`HandleError::Stale`] on mismatch.
pub fn verify(
    ino: InodeNumber,
    handle_generation: u32,
    live_generation: u32,
) -> Result<(), HandleError> {
    if handle_generation == live_generation {
        Ok(())
    } else {
        Err(HandleError::Stale {
            ino,
            expected_generation: handle_generation,
            observed_generation: live_generation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trip() {
        let ino = InodeNumber(0x1122_3344_5566_7788);
        let generation = 0xCAFE_BABE_u32;
        let bytes = encode(ino, generation);
        assert_eq!(bytes.len(), FILE_HANDLE_LEN);
        let (ino_back, gen_back) = decode(&bytes).expect("decode");
        assert_eq!(ino_back, ino);
        assert_eq!(gen_back, generation);
    }

    #[test]
    fn encode_layout_is_little_endian() {
        let ino = InodeNumber(0x0102_0304_0506_0708);
        let generation = 0x090A_0B0C_u32;
        let bytes = encode(ino, generation);
        assert_eq!(
            bytes,
            [
                0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x0C, 0x0B, 0x0A, 0x09
            ]
        );
    }

    #[test]
    fn decode_rejects_short_buffer() {
        let err = decode(&[0_u8; FILE_HANDLE_LEN - 1]).unwrap_err();
        assert!(matches!(
            err,
            HandleError::BadLength {
                actual,
                expected,
            } if actual == FILE_HANDLE_LEN - 1 && expected == FILE_HANDLE_LEN
        ));
        assert_eq!(err.to_errno(), libc::EINVAL);
    }

    #[test]
    fn decode_rejects_long_buffer() {
        let err = decode(&[0_u8; FILE_HANDLE_LEN + 4]).unwrap_err();
        assert!(matches!(err, HandleError::BadLength { .. }));
    }

    #[test]
    fn verify_succeeds_when_generations_match() {
        verify(InodeNumber(42), 7, 7).expect("matching generations");
    }

    #[test]
    fn verify_returns_stale_with_full_context_on_mismatch() {
        let err = verify(InodeNumber(42), 7, 8).unwrap_err();
        assert!(matches!(
            err,
            HandleError::Stale {
                ino,
                expected_generation: 7,
                observed_generation: 8,
            } if ino == InodeNumber(42)
        ));
        assert_eq!(err.to_errno(), libc::ESTALE);
    }

    #[test]
    fn handle_error_maps_to_ffs_error_with_correct_errno() {
        let bad: FfsError = HandleError::BadLength {
            actual: 0,
            expected: FILE_HANDLE_LEN,
        }
        .into();
        assert_eq!(bad.to_errno(), libc::EINVAL);

        let stale: FfsError = HandleError::Stale {
            ino: InodeNumber(1),
            expected_generation: 1,
            observed_generation: 2,
        }
        .into();
        assert_eq!(stale.to_errno(), libc::ESTALE);
    }
}
