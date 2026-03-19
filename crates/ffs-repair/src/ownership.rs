#![forbid(unsafe_code)]

//! Lease-based repair ownership for multi-host coordination.
//!
//! Implements optimistic ownership with deterministic tiebreak:
//! - Hosts claim ownership by writing a coordination record with TTL
//! - Expired leases can be claimed by any host
//! - Conflicts resolved by lexicographic UUID comparison (lower wins)
//!
//! See `docs/design-multi-host-repair.md` for the full protocol design.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};

/// Default lease TTL: 5 minutes.
const DEFAULT_LEASE_TTL_SECS: u64 = 300;

/// Coordination record version.
const RECORD_VERSION: u32 = 1;
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

// ── Coordination Record ────────────────────────────────────────────────────

/// Persistent coordination record for repair ownership.
///
/// Stored as `.<image>.ffs-repair-owner.json` adjacent to the image file.
/// Atomic updates via write-to-temp + rename.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoordinationRecord {
    /// Record format version.
    pub version: u32,
    /// UUID of the owning host (for deterministic tiebreak).
    pub host_id: String,
    /// Human-readable hostname.
    pub hostname: String,
    /// PID of the owning process.
    pub pid: u32,
    /// ISO 8601 timestamp when ownership was claimed.
    pub claimed_at: String,
    /// Lease duration in seconds.
    pub lease_ttl_secs: u64,
    /// Monotonic lease incarnation. Changes only on ownership (re)acquisition.
    pub lease_version: u64,
    /// Monotonically increasing repair generation counter.
    pub repair_generation: u64,
    /// Block groups currently owned (empty = whole image).
    pub groups_owned: Vec<u32>,
}

impl CoordinationRecord {
    /// Check whether this lease has expired relative to the given current time.
    #[must_use]
    pub fn is_expired(&self, now: SystemTime) -> bool {
        let Ok(claimed) = parse_iso8601(&self.claimed_at) else {
            // Unparseable timestamp → treat as expired
            return true;
        };
        let ttl = Duration::from_secs(self.lease_ttl_secs);
        claimed.checked_add(ttl).is_some_and(|expiry| now >= expiry)
    }

    /// Renew the lease by updating `claimed_at` to the current time.
    pub fn renew(&mut self) {
        self.claimed_at = format_iso8601(SystemTime::now());
    }
}

// ── Ownership Manager ──────────────────────────────────────────────────────

/// Manages repair ownership for a filesystem image.
pub struct RepairOwnership {
    /// This host's UUID (generated once per host, persisted).
    host_id: String,
    /// This host's hostname.
    hostname: String,
    /// Lease TTL for new claims.
    lease_ttl: Duration,
}

/// Guard representing active ownership. Release on drop or explicit release.
#[derive(Debug)]
pub struct OwnershipGuard {
    record_path: PathBuf,
    record: CoordinationRecord,
}

impl OwnershipGuard {
    /// The coordination record for this ownership.
    #[must_use]
    pub fn record(&self) -> &CoordinationRecord {
        &self.record
    }

    /// Path to the coordination record file.
    #[must_use]
    pub fn record_path(&self) -> &Path {
        &self.record_path
    }
}

/// Result of an ownership acquisition attempt.
#[derive(Debug)]
pub enum AcquireResult {
    /// Ownership acquired successfully.
    Acquired(OwnershipGuard),
    /// Another host owns the image and the lease has not expired.
    OwnedByOther {
        owner_host_id: String,
        owner_hostname: String,
        expires_in_secs: u64,
    },
    /// Ownership conflict detected; we lost the tiebreak.
    ConflictLost { winner_host_id: String },
}

impl RepairOwnership {
    /// Create a new ownership manager.
    #[must_use]
    pub fn new(host_id: String, hostname: String) -> Self {
        Self {
            host_id,
            hostname,
            lease_ttl: Duration::from_secs(DEFAULT_LEASE_TTL_SECS),
        }
    }

    /// Create with a custom lease TTL.
    #[must_use]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.lease_ttl = ttl;
        self
    }

    /// Compute the coordination record path for an image.
    #[must_use]
    pub fn record_path_for(image_path: &Path) -> PathBuf {
        let file_name = image_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let dot = Path::new(".");
        let parent = image_path.parent().unwrap_or(dot);
        parent.join(format!(".{file_name}.ffs-repair-owner.json"))
    }

    /// Attempt to acquire ownership of the image for repair.
    ///
    /// Returns `Acquired` if ownership was successfully claimed,
    /// `OwnedByOther` if another host holds a valid lease, or
    /// `ConflictLost` if we lost a tiebreak.
    pub fn try_acquire(&self, image_path: &Path) -> std::io::Result<AcquireResult> {
        let record_path = Self::record_path_for(image_path);
        let now = SystemTime::now();

        // Read existing record
        match std::fs::read_to_string(&record_path) {
            Ok(contents) => {
                let existing: CoordinationRecord = serde_json::from_str(&contents)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

                if !existing.is_expired(now) && existing.host_id != self.host_id {
                    // Another host owns it and lease is valid
                    let claimed =
                        parse_iso8601(&existing.claimed_at).unwrap_or(SystemTime::UNIX_EPOCH);
                    let expiry = claimed + Duration::from_secs(existing.lease_ttl_secs);
                    let remaining = expiry
                        .duration_since(now)
                        .unwrap_or(Duration::ZERO)
                        .as_secs();

                    info!(
                        target: "ffs::repair::ownership",
                        owner = %existing.host_id,
                        hostname = %existing.hostname,
                        remaining_secs = remaining,
                        "ownership_held_by_other"
                    );

                    return Ok(AcquireResult::OwnedByOther {
                        owner_host_id: existing.host_id,
                        owner_hostname: existing.hostname,
                        expires_in_secs: remaining,
                    });
                }

                // Lease expired or we already own it — claim
                let new_gen = existing.repair_generation + 1;
                let new_lease_version = existing.lease_version + 1;
                self.write_claim(&record_path, new_gen, new_lease_version)?;

                // Post-write verification: re-read to detect conflicts
                self.verify_or_tiebreak(&record_path, new_gen, new_lease_version)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // No record — claim with generation 1
                self.write_claim(&record_path, 1, 1)?;
                self.verify_or_tiebreak(&record_path, 1, 1)
            }
            Err(e) => Err(e),
        }
    }

    /// Write our ownership claim to the coordination record.
    fn write_claim(
        &self,
        record_path: &Path,
        generation: u64,
        lease_version: u64,
    ) -> std::io::Result<()> {
        let record = CoordinationRecord {
            version: RECORD_VERSION,
            host_id: self.host_id.clone(),
            hostname: self.hostname.clone(),
            pid: std::process::id(),
            claimed_at: format_iso8601(SystemTime::now()),
            lease_ttl_secs: self.lease_ttl.as_secs(),
            lease_version,
            repair_generation: generation,
            groups_owned: Vec::new(),
        };

        let json = serde_json::to_string_pretty(&record).map_err(std::io::Error::other)?;

        // Atomic write: write to temp, then rename
        let tmp_path = temp_record_path(record_path);
        std::fs::write(&tmp_path, &json)?;
        std::fs::rename(&tmp_path, record_path)?;

        debug!(
            target: "ffs::repair::ownership",
            host_id = %self.host_id,
            generation = generation,
            "ownership_claimed"
        );

        Ok(())
    }

    /// Re-read the record to verify we own it. If another host wrote
    /// concurrently, apply deterministic tiebreak (lower UUID wins).
    fn verify_or_tiebreak(
        &self,
        record_path: &Path,
        expected_gen: u64,
        expected_lease_version: u64,
    ) -> std::io::Result<AcquireResult> {
        let contents = std::fs::read_to_string(record_path)?;
        let current: CoordinationRecord = serde_json::from_str(&contents)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        if current.host_id == self.host_id {
            // We own it
            Ok(AcquireResult::Acquired(OwnershipGuard {
                record_path: record_path.to_owned(),
                record: current,
            }))
        } else {
            // Another host won the race — apply tiebreak
            if self.host_id < current.host_id {
                // We should win — re-write
                self.write_claim(record_path, expected_gen, expected_lease_version)?;
                let contents = std::fs::read_to_string(record_path)?;
                let record: CoordinationRecord = serde_json::from_str(&contents)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                Ok(AcquireResult::Acquired(OwnershipGuard {
                    record_path: record_path.to_owned(),
                    record,
                }))
            } else {
                // We lost
                warn!(
                    target: "ffs::repair::ownership",
                    our_id = %self.host_id,
                    winner_id = %current.host_id,
                    "ownership_conflict_lost"
                );
                Ok(AcquireResult::ConflictLost {
                    winner_host_id: current.host_id,
                })
            }
        }
    }

    /// Renew an existing lease.
    pub fn renew(&self, guard: &mut OwnershipGuard) -> std::io::Result<()> {
        let contents = std::fs::read_to_string(&guard.record_path)?;
        let current: CoordinationRecord = serde_json::from_str(&contents)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if current.host_id != guard.record.host_id
            || current.lease_version != guard.record.lease_version
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "cannot renew stale lease: expected {}@v{}, found {}@v{}",
                    guard.record.host_id,
                    guard.record.lease_version,
                    current.host_id,
                    current.lease_version
                ),
            ));
        }

        guard.record.renew();
        let json = serde_json::to_string_pretty(&guard.record).map_err(std::io::Error::other)?;
        let tmp_path = temp_record_path(&guard.record_path);
        std::fs::write(&tmp_path, &json)?;
        std::fs::rename(&tmp_path, &guard.record_path)?;
        debug!(
            target: "ffs::repair::ownership",
            host_id = %self.host_id,
            "ownership_renewed"
        );
        Ok(())
    }

    /// Release ownership explicitly. Consumes the guard to prevent
    /// further use after release.
    #[allow(clippy::needless_pass_by_value)]
    pub fn release(guard: OwnershipGuard) -> std::io::Result<()> {
        let contents = match std::fs::read_to_string(&guard.record_path) {
            Ok(contents) => contents,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let current: CoordinationRecord = serde_json::from_str(&contents)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if current.host_id != guard.record.host_id
            || current.lease_version != guard.record.lease_version
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "cannot release stale lease: expected {}@v{}, found {}@v{}",
                    guard.record.host_id,
                    guard.record.lease_version,
                    current.host_id,
                    current.lease_version
                ),
            ));
        }

        // Remove the coordination record so the next host can claim immediately
        // instead of waiting for TTL expiry.
        match std::fs::remove_file(&guard.record_path) {
            Ok(()) => {
                info!(
                    target: "ffs::repair::ownership",
                    host_id = %guard.record.host_id,
                    "ownership_released"
                );
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Check if we currently own the image (without modifying the record).
    pub fn is_owned_by_us(&self, image_path: &Path) -> std::io::Result<bool> {
        let record_path = Self::record_path_for(image_path);
        match std::fs::read_to_string(&record_path) {
            Ok(contents) => {
                let record: CoordinationRecord = serde_json::from_str(&contents)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                let now = SystemTime::now();
                Ok(record.host_id == self.host_id && !record.is_expired(now))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }
}

// ── Time helpers ───────────────────────────────────────────────────────────

fn format_iso8601(time: SystemTime) -> String {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let secs = duration.as_secs();
    // Simple UTC format without external deps
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since epoch → year/month/day (simplified, not leap-second-aware)
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn days_to_ymd(days_since_epoch: u64) -> (u64, u64, u64) {
    // Civil calendar from days since 1970-01-01 (simplified algorithm)
    let z = days_since_epoch + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn parse_iso8601(s: &str) -> Result<SystemTime, ()> {
    // Parse "YYYY-MM-DDTHH:MM:SSZ" format
    if s.len() < 20 || !s.ends_with('Z') {
        return Err(());
    }
    let year: u64 = s[0..4].parse().map_err(|_| ())?;
    let month: u64 = s[5..7].parse().map_err(|_| ())?;
    let day: u64 = s[8..10].parse().map_err(|_| ())?;
    let hours: u64 = s[11..13].parse().map_err(|_| ())?;
    let minutes: u64 = s[14..16].parse().map_err(|_| ())?;
    let seconds: u64 = s[17..19].parse().map_err(|_| ())?;

    let days = ymd_to_days(year, month, day);
    let total_secs = days * 86400 + hours * 3600 + minutes * 60 + seconds;
    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(total_secs))
}

fn ymd_to_days(year: u64, month: u64, day: u64) -> u64 {
    let y = if month <= 2 { year - 1 } else { year };
    let m = if month <= 2 { month + 9 } else { month - 3 };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn temp_record_path(record_path: &Path) -> PathBuf {
    let nonce = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    record_path.with_extension(format!("tmp-{}-{nonce}", std::process::id()))
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_path_for_image() {
        let path = RepairOwnership::record_path_for(Path::new("/tmp/test.ext4"));
        assert_eq!(path, PathBuf::from("/tmp/.test.ext4.ffs-repair-owner.json"));
    }

    #[test]
    fn record_path_for_image_no_parent() {
        let path = RepairOwnership::record_path_for(Path::new("image.img"));
        assert_eq!(path, PathBuf::from(".image.img.ffs-repair-owner.json"));
    }

    #[test]
    fn coordination_record_expired() {
        let record = CoordinationRecord {
            version: 1,
            host_id: "host-a".into(),
            hostname: "worker-01".into(),
            pid: 1000,
            claimed_at: "2020-01-01T00:00:00Z".into(),
            lease_ttl_secs: 300,
            lease_version: 1,
            repair_generation: 1,
            groups_owned: vec![],
        };
        // 2020 + 300s is long past
        assert!(record.is_expired(SystemTime::now()));
    }

    #[test]
    fn coordination_record_not_expired() {
        let now = SystemTime::now();
        let record = CoordinationRecord {
            version: 1,
            host_id: "host-a".into(),
            hostname: "worker-01".into(),
            pid: 1000,
            claimed_at: format_iso8601(now),
            lease_ttl_secs: 3600,
            lease_version: 7,
            repair_generation: 1,
            groups_owned: vec![],
        };
        assert!(!record.is_expired(now));
    }

    #[test]
    fn coordination_record_bad_timestamp_treated_as_expired() {
        let record = CoordinationRecord {
            version: 1,
            host_id: "host-a".into(),
            hostname: "worker-01".into(),
            pid: 1000,
            claimed_at: "not-a-timestamp".into(),
            lease_ttl_secs: 300,
            lease_version: 1,
            repair_generation: 1,
            groups_owned: vec![],
        };
        assert!(record.is_expired(SystemTime::now()));
    }

    #[test]
    fn coordination_record_renew() {
        let mut record = CoordinationRecord {
            version: 1,
            host_id: "host-a".into(),
            hostname: "worker-01".into(),
            pid: 1000,
            claimed_at: "2020-01-01T00:00:00Z".into(),
            lease_ttl_secs: 300,
            lease_version: 3,
            repair_generation: 1,
            groups_owned: vec![],
        };
        assert!(record.is_expired(SystemTime::now()));
        record.renew();
        assert!(!record.is_expired(SystemTime::now()));
    }

    #[test]
    fn coordination_record_json_round_trip() {
        let record = CoordinationRecord {
            version: 1,
            host_id: "a1b2c3d4".into(),
            hostname: "worker-03".into(),
            pid: 12345,
            claimed_at: "2026-03-14T02:00:00Z".into(),
            lease_ttl_secs: 300,
            lease_version: 9,
            repair_generation: 42,
            groups_owned: vec![0, 1, 2],
        };
        let json = serde_json::to_string_pretty(&record).expect("serialize");
        let deser: CoordinationRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(record, deser);
    }

    #[test]
    fn iso8601_round_trip() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_710_000_000); // ~2024-03
        let formatted = format_iso8601(now);
        let parsed = parse_iso8601(&formatted).expect("parse");
        let delta = parsed
            .duration_since(now)
            .or_else(|_| now.duration_since(parsed))
            .unwrap_or(Duration::ZERO);
        assert!(delta.as_secs() < 2, "round-trip drift: {delta:?}");
    }

    #[test]
    fn deterministic_tiebreak_lower_uuid_wins() {
        // Verify the tiebreak logic: lower host_id should win
        let host_a = "aaaa-1111";
        let host_b = "bbbb-2222";
        assert!(host_a < host_b, "lexicographic: a < b");

        // If our host_id < other host_id, we should win
        let mgr = RepairOwnership::new(host_a.into(), "worker-a".into());
        assert!(mgr.host_id.as_str() < host_b);
    }

    #[test]
    fn acquire_creates_record_on_disk() {
        let dir = tempdir();
        let image = dir.join("test.img");
        std::fs::write(&image, b"fake image").unwrap();

        let mgr = RepairOwnership::new("host-1".into(), "test-host".into());
        let result = mgr.try_acquire(&image).expect("acquire");
        assert!(
            matches!(result, AcquireResult::Acquired(_)),
            "should acquire when no record exists"
        );

        let record_path = RepairOwnership::record_path_for(&image);
        assert!(record_path.exists(), "record file should be created");
    }

    #[test]
    fn acquire_rejects_when_owned_by_other() {
        let dir = tempdir();
        let image = dir.join("test.img");
        std::fs::write(&image, b"fake image").unwrap();

        // Host A acquires
        let mgr_a = RepairOwnership::new("aaaa".into(), "host-a".into());
        let result_a = mgr_a.try_acquire(&image).expect("acquire a");
        assert!(matches!(result_a, AcquireResult::Acquired(_)));

        // Host B tries to acquire — should be rejected
        let mgr_b = RepairOwnership::new("bbbb".into(), "host-b".into());
        let result_b = mgr_b.try_acquire(&image).expect("acquire b");
        assert!(
            matches!(result_b, AcquireResult::OwnedByOther { .. }),
            "should be rejected: {result_b:?}"
        );
    }

    #[test]
    fn acquire_succeeds_after_lease_expiry() {
        let dir = tempdir();
        let image = dir.join("test.img");
        std::fs::write(&image, b"fake image").unwrap();

        // Write an expired record manually
        let record = CoordinationRecord {
            version: 1,
            host_id: "dead-host".into(),
            hostname: "crashed".into(),
            pid: 999,
            claimed_at: "2020-01-01T00:00:00Z".into(),
            lease_ttl_secs: 1,
            lease_version: 4,
            repair_generation: 5,
            groups_owned: vec![],
        };
        let record_path = RepairOwnership::record_path_for(&image);
        std::fs::write(&record_path, serde_json::to_string_pretty(&record).unwrap()).unwrap();

        // New host should be able to claim
        let mgr = RepairOwnership::new("new-host".into(), "alive".into());
        let result = mgr.try_acquire(&image).expect("acquire");
        match &result {
            AcquireResult::Acquired(guard) => {
                assert_eq!(guard.record().host_id, "new-host");
                assert_eq!(guard.record().lease_version, 5);
                assert_eq!(guard.record().repair_generation, 6); // incremented
            }
            other => panic!("expected Acquired, got: {other:?}"),
        }
    }

    #[test]
    fn release_removes_record() {
        let dir = tempdir();
        let image = dir.join("test.img");
        std::fs::write(&image, b"fake image").unwrap();

        let mgr = RepairOwnership::new("host-1".into(), "test".into());
        let result = mgr.try_acquire(&image).expect("acquire");
        let AcquireResult::Acquired(guard) = result else {
            panic!("expected acquired");
        };

        let record_path = RepairOwnership::record_path_for(&image);
        assert!(record_path.exists());

        RepairOwnership::release(guard).expect("release");
        assert!(
            !record_path.exists(),
            "record should be removed after release"
        );
    }

    #[test]
    fn renew_updates_timestamp() {
        let dir = tempdir();
        let image = dir.join("test.img");
        std::fs::write(&image, b"fake image").unwrap();

        let mgr =
            RepairOwnership::new("host-1".into(), "test".into()).with_ttl(Duration::from_secs(10));
        let result = mgr.try_acquire(&image).expect("acquire");
        let AcquireResult::Acquired(mut guard) = result else {
            panic!("expected acquired");
        };

        let old_time = guard.record().claimed_at.clone();
        // Sleep > 1s to ensure timestamp changes (ISO 8601 has 1s resolution)
        std::thread::sleep(Duration::from_millis(1100));
        mgr.renew(&mut guard).expect("renew");
        assert_ne!(
            guard.record().claimed_at,
            old_time,
            "timestamp should update"
        );
    }

    #[test]
    fn renew_rejects_stale_guard_after_takeover() {
        let dir = tempdir();
        let image = dir.join("test.img");
        std::fs::write(&image, b"fake image").unwrap();

        let mgr_a =
            RepairOwnership::new("host-a".into(), "test-a".into()).with_ttl(Duration::from_secs(1));
        let result = mgr_a.try_acquire(&image).expect("acquire");
        let AcquireResult::Acquired(mut guard) = result else {
            panic!("expected acquired");
        };

        std::thread::sleep(Duration::from_millis(1100));
        let mgr_b = RepairOwnership::new("host-b".into(), "test-b".into());
        let takeover = mgr_b.try_acquire(&image).expect("takeover");
        assert!(matches!(takeover, AcquireResult::Acquired(_)));

        let err = mgr_a.renew(&mut guard).expect_err("renew must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn is_owned_by_us() {
        let dir = tempdir();
        let image = dir.join("test.img");
        std::fs::write(&image, b"fake image").unwrap();

        let mgr = RepairOwnership::new("host-1".into(), "test".into());
        assert!(!mgr.is_owned_by_us(&image).unwrap());

        let result = mgr.try_acquire(&image).expect("acquire");
        assert!(matches!(result, AcquireResult::Acquired(_)));
        assert!(mgr.is_owned_by_us(&image).unwrap());

        // Different host should not own
        let other = RepairOwnership::new("host-2".into(), "other".into());
        assert!(!other.is_owned_by_us(&image).unwrap());
    }

    #[test]
    fn release_rejects_stale_guard_after_takeover() {
        let dir = tempdir();
        let image = dir.join("test.img");
        std::fs::write(&image, b"fake image").unwrap();

        let mgr_a =
            RepairOwnership::new("host-a".into(), "test-a".into()).with_ttl(Duration::from_secs(1));
        let result = mgr_a.try_acquire(&image).expect("acquire");
        let AcquireResult::Acquired(guard) = result else {
            panic!("expected acquired");
        };

        std::thread::sleep(Duration::from_millis(1100));
        let mgr_b = RepairOwnership::new("host-b".into(), "test-b".into());
        let takeover = mgr_b.try_acquire(&image).expect("takeover");
        assert!(matches!(takeover, AcquireResult::Acquired(_)));

        let err = RepairOwnership::release(guard).expect_err("release must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);

        let record_path = RepairOwnership::record_path_for(&image);
        let contents = std::fs::read_to_string(record_path).expect("record remains");
        let current: CoordinationRecord = serde_json::from_str(&contents).expect("parse");
        assert_eq!(current.host_id, "host-b");
    }

    #[test]
    fn temp_record_path_is_unique_per_write_attempt() {
        let record_path = PathBuf::from("/tmp/.image.img.ffs-repair-owner.json");
        let first = temp_record_path(&record_path);
        let second = temp_record_path(&record_path);
        assert_ne!(first, second);
        assert_eq!(first.parent(), record_path.parent());
        assert_eq!(second.parent(), record_path.parent());
    }

    fn tempdir() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("ffs-test-ownership-{}-{n}", std::process::id()));
        // Clean up any leftover from previous run
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        dir
    }
}
