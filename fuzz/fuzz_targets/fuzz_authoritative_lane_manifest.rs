#![no_main]

use ffs_harness::authoritative_lane_manifest::{
    allowed_decision_tokens, evaluate_authoritative_lane, AuthoritativeLaneDecision,
    AuthoritativeLaneManifest, AUTHORITATIVE_LANE_MANIFEST_SCHEMA_VERSION,
};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;

const MAX_INPUT_BYTES: usize = 8 * 1024;
const ENVIRONMENT_KINDS: [&str; 6] = [
    "local_developer",
    "ci",
    "rch_authoritative",
    "soak",
    "unknown_lane",
    "",
];
const MOUNT_OPTIONS: [&str; 7] = [
    "rw",
    "ro",
    "default_permissions",
    "allow_other",
    "writeback_cache",
    "sync",
    "",
];

struct ByteCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn next_u8(&mut self) -> u8 {
        let value = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        value
    }

    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }

    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }

    fn next_bool(&mut self) -> bool {
        self.next_u8() & 1 == 1
    }

    fn choose<'b>(&mut self, values: &'b [&str]) -> &'b str {
        let Some(first) = values.first().copied() else {
            return "";
        };
        let index = usize::from(self.next_u8()) % values.len();
        match values.get(index).copied() {
            Some(value) => value,
            None => first,
        }
    }

    fn label(&mut self, prefix: &str) -> String {
        if self.next_u8().is_multiple_of(13) {
            return String::new();
        }

        let len = 1 + usize::from(self.next_u8() % 16);
        let mut value = String::with_capacity(prefix.len() + len);
        value.push_str(prefix);
        for _ in 0..len {
            let ch = match self.next_u8() % 18 {
                0 => 'a',
                1 => 'b',
                2 => 'c',
                3 => 'd',
                4 => 'e',
                5 => 'f',
                6 => 'g',
                7 => 'h',
                8 => 'i',
                9 => 'j',
                10 => '0',
                11 => '1',
                12 => '2',
                13 => '3',
                14 => '-',
                15 => '_',
                16 => ' ',
                _ => '/',
            };
            value.push(ch);
        }
        value
    }

    fn mount_options(&mut self) -> Vec<String> {
        let count = usize::from(self.next_u8() % 4);
        (0..count)
            .map(|_| self.choose(&MOUNT_OPTIONS).to_owned())
            .collect()
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    assert_allowed_decision_tokens();

    if let Ok(manifest) = serde_json::from_slice::<AuthoritativeLaneManifest>(data) {
        exercise_manifest(&manifest);
    }

    let mut cursor = ByteCursor::new(data);
    let manifest = manifest_from_bytes(&mut cursor);
    exercise_manifest(&manifest);
});

fn assert_allowed_decision_tokens() {
    let tokens = allowed_decision_tokens();
    assert_eq!(
        tokens,
        vec!["pass", "skip", "fail", "fail_closed_authoritative"],
        "authoritative lane decision token ordering must stay stable for manifest consumers"
    );
}

fn manifest_from_bytes(cursor: &mut ByteCursor<'_>) -> AuthoritativeLaneManifest {
    let expected_mount_options = cursor.mount_options();
    let observed_mount_options = match cursor.next_u8() % 4 {
        0 => expected_mount_options.clone(),
        1 => Vec::new(),
        2 => cursor.mount_options(),
        _ => {
            let mut reversed = expected_mount_options.clone();
            reversed.reverse();
            reversed
        }
    };

    let probe_at_unix = cursor.next_u64() % 10_000;
    let freshness_ttl_seconds = if cursor.next_u8().is_multiple_of(7) {
        0
    } else {
        1 + u64::from(cursor.next_u32() % 3_600)
    };
    let now_unix = match cursor.next_u8() % 4 {
        0 => probe_at_unix.saturating_sub(u64::from(cursor.next_u8())),
        1 => probe_at_unix,
        2 => probe_at_unix.saturating_add(freshness_ttl_seconds),
        _ => probe_at_unix
            .saturating_add(freshness_ttl_seconds)
            .saturating_add(1),
    };

    AuthoritativeLaneManifest {
        schema_version: if cursor.next_bool() {
            AUTHORITATIVE_LANE_MANIFEST_SCHEMA_VERSION
        } else {
            cursor.next_u32() % 4
        },
        manifest_id: cursor.label("manifest_"),
        bead_id: if cursor.next_bool() {
            format!("bd-{}", cursor.label("lane"))
        } else {
            cursor.label("ticket_")
        },
        lane_id: cursor.label("lane_"),
        environment_kind: cursor.choose(&ENVIRONMENT_KINDS).to_owned(),
        probe_version: cursor.label("probe_"),
        probe_at_unix,
        now_unix,
        freshness_ttl_seconds,
        kernel: cursor.label("linux_"),
        fuse_kernel_version: cursor.label("fuse_"),
        helper_binary_version: cursor.label("fuser_"),
        expected_mount_options,
        observed_mount_options,
        required_matrix_id: cursor.label("matrix_"),
        required_scenario_count: cursor.next_u32() % 8,
        observed_scenario_count: cursor.next_u32() % 12,
        mounted_logs_present: cursor.next_bool(),
        remediation_hint: cursor.label("rerun_"),
    }
}

fn exercise_manifest(manifest: &AuthoritativeLaneManifest) {
    let first = evaluate_authoritative_lane(manifest);
    let second = evaluate_authoritative_lane(manifest);
    assert_eq!(
        first, second,
        "authoritative lane decisions must be deterministic"
    );
    assert_eq!(
        decision_lane_id(&first),
        manifest.lane_id,
        "lane decisions must preserve the manifest lane_id"
    );

    match &first {
        AuthoritativeLaneDecision::Pass {
            lane_id,
            environment_kind,
        } => {
            assert_eq!(lane_id, &manifest.lane_id);
            assert_eq!(environment_kind, &manifest.environment_kind);
            assert_pass_prerequisites(manifest);
        }
        AuthoritativeLaneDecision::Skip {
            reason,
            remediation_hint,
            ..
        } => {
            assert_eq!(
                manifest.environment_kind, "local_developer",
                "only local developer lanes may produce ergonomic Skip decisions"
            );
            assert_actionable(reason, remediation_hint);
        }
        AuthoritativeLaneDecision::Fail {
            reason,
            remediation_hint,
            ..
        }
        | AuthoritativeLaneDecision::FailClosedAuthoritative {
            reason,
            remediation_hint,
            ..
        } => {
            assert_actionable(reason, remediation_hint);
        }
    }
}

fn decision_lane_id(decision: &AuthoritativeLaneDecision) -> &str {
    match decision {
        AuthoritativeLaneDecision::Pass { lane_id, .. }
        | AuthoritativeLaneDecision::Skip { lane_id, .. }
        | AuthoritativeLaneDecision::Fail { lane_id, .. }
        | AuthoritativeLaneDecision::FailClosedAuthoritative { lane_id, .. } => lane_id,
    }
}

fn assert_actionable(reason: &str, remediation_hint: &str) {
    assert!(
        !reason.trim().is_empty(),
        "non-pass lane decisions must carry a stable reason"
    );
    assert!(
        !remediation_hint.trim().is_empty(),
        "non-pass lane decisions must carry remediation"
    );
}

fn assert_pass_prerequisites(manifest: &AuthoritativeLaneManifest) {
    assert_eq!(
        manifest.schema_version, AUTHORITATIVE_LANE_MANIFEST_SCHEMA_VERSION,
        "Pass requires the current schema"
    );
    assert!(
        !manifest.lane_id.trim().is_empty(),
        "Pass requires lane identity"
    );
    assert!(
        manifest.bead_id.starts_with("bd-"),
        "Pass requires a Beads issue id"
    );
    assert!(
        matches!(
            manifest.environment_kind.as_str(),
            "ci" | "rch_authoritative" | "soak"
        ),
        "Pass requires an authoritative environment kind"
    );
    assert!(
        !manifest.remediation_hint.trim().is_empty(),
        "Pass still requires remediation context for future drift"
    );
    assert!(
        !manifest.probe_version.trim().is_empty(),
        "Pass requires a versioned probe"
    );
    assert_ne!(manifest.probe_at_unix, 0, "Pass requires a probe timestamp");
    assert_ne!(
        manifest.freshness_ttl_seconds, 0,
        "Pass requires a positive freshness TTL"
    );
    assert!(
        manifest.probe_at_unix <= manifest.now_unix,
        "Pass must not accept future-dated probe timestamps"
    );
    assert!(
        manifest.now_unix - manifest.probe_at_unix <= manifest.freshness_ttl_seconds,
        "Pass requires a fresh probe"
    );
    assert!(
        !manifest.kernel.trim().is_empty(),
        "Pass requires kernel identity"
    );
    assert!(
        !manifest.fuse_kernel_version.trim().is_empty(),
        "Pass requires FUSE kernel identity"
    );
    assert!(
        !manifest.helper_binary_version.trim().is_empty(),
        "Pass requires helper binary identity"
    );
    assert!(
        !manifest.expected_mount_options.is_empty(),
        "Pass requires expected mount options"
    );
    assert!(
        !manifest.observed_mount_options.is_empty(),
        "Pass requires observed mount options"
    );
    assert_eq!(
        mount_option_set(&manifest.expected_mount_options),
        mount_option_set(&manifest.observed_mount_options),
        "Pass requires observed mount options to match expected options"
    );
    assert!(
        !manifest.required_matrix_id.trim().is_empty(),
        "Pass requires a matrix id"
    );
    assert_ne!(
        manifest.required_scenario_count, 0,
        "Pass requires a non-empty scenario contract"
    );
    assert!(
        manifest.observed_scenario_count >= manifest.required_scenario_count,
        "Pass requires complete matrix coverage"
    );
    assert!(
        manifest.mounted_logs_present,
        "Pass requires mounted logs to be preserved"
    );
}

fn mount_option_set(options: &[String]) -> BTreeSet<&str> {
    options.iter().map(String::as_str).collect()
}
