#![no_main]

use ffs_harness::swarm_workload_harness::{
    fail_on_swarm_workload_harness_errors, render_swarm_workload_harness_markdown,
    validate_swarm_workload_harness_manifest_with_config, SwarmBackpressureState,
    SwarmCleanupPolicy, SwarmCleanupStatus, SwarmCommandPlan, SwarmCommandPlanMode,
    SwarmExpectedArtifact, SwarmFuseCapability, SwarmFuseCapabilityState,
    SwarmHarnessClassification, SwarmHarnessReleaseClaimState, SwarmHostFingerprint, SwarmHostLane,
    SwarmNumaObservation, SwarmPlacementIntent, SwarmQueueBackpressureCounters,
    SwarmRchOrLocalLane, SwarmResourceCaps, SwarmValidationVerdict, SwarmWorkloadClass,
    SwarmWorkloadHarnessManifest, SwarmWorkloadHarnessValidationConfig, SwarmWorkloadProfile,
    SwarmWorkloadScenario, SwarmWorkloadTargetHost,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 16 * 1024;
const REFERENCE_EPOCH_DAYS_2026_05_06: u32 = 20_579;
const REQUIRED_LOG_FIELDS: [&str; 18] = [
    "scenario_id",
    "host_fingerprint",
    "cpu_cores_logical",
    "numa_nodes",
    "ram_total_gb",
    "ram_available_gb",
    "storage_class",
    "fuse_capability",
    "kernel",
    "rch_or_local_lane",
    "worker_isolation_notes",
    "workload_profile_id",
    "workload_seeds",
    "queue_depth",
    "backpressure_state",
    "cleanup_status",
    "release_claim_state",
    "reproduction_command",
];
const WORKLOAD_CLASSES: [SwarmWorkloadClass; 5] = [
    SwarmWorkloadClass::MetadataStorm,
    SwarmWorkloadClass::AppendFsync,
    SwarmWorkloadClass::MixedReadWrite,
    SwarmWorkloadClass::ScrubRepairOverlap,
    SwarmWorkloadClass::CachePressure,
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

    fn next_u16(&mut self) -> u16 {
        u16::from_le_bytes([self.next_u8(), self.next_u8()])
    }

    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
            self.next_u8(),
        ])
    }

    fn next_bool(&mut self) -> bool {
        self.next_u8() & 1 == 1
    }

    fn next_bounded_u32(&mut self, max_exclusive: u32) -> u32 {
        if max_exclusive == 0 {
            0
        } else {
            self.next_u32() % max_exclusive
        }
    }

    fn next_f64(&mut self, max_exclusive: u32) -> f64 {
        f64::from(self.next_bounded_u32(max_exclusive)) + f64::from(self.next_u8()) / 255.0
    }

    fn next_label(&mut self, prefix: &str) -> String {
        if self.next_u8().is_multiple_of(17) {
            return String::new();
        }

        let len = 1 + usize::from(self.next_u8() % 16);
        let mut label = String::with_capacity(prefix.len() + len);
        label.push_str(prefix);
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
                16 => '.',
                _ => '/',
            };
            label.push(ch);
        }
        label
    }

    fn choose<T: Copy>(&mut self, values: &[T]) -> T {
        values[usize::from(self.next_u8()) % values.len()]
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    if let Ok(manifest) = serde_json::from_slice::<SwarmWorkloadHarnessManifest>(data) {
        exercise_manifest(&manifest);
        exercise_authoritative_guard(manifest);
    }

    let mut cursor = ByteCursor::new(data);
    let manifest = manifest_from_bytes(&mut cursor);
    exercise_manifest(&manifest);
    exercise_authoritative_guard(manifest);
});

fn exercise_manifest(manifest: &SwarmWorkloadHarnessManifest) {
    let config = SwarmWorkloadHarnessValidationConfig {
        reference_epoch_days: Some(REFERENCE_EPOCH_DAYS_2026_05_06),
        max_age_days: 30,
    };
    let report = validate_swarm_workload_harness_manifest_with_config(manifest, &config);
    let markdown = render_swarm_workload_harness_markdown(&report);
    let markdown_again = render_swarm_workload_harness_markdown(&report);

    assert_eq!(
        markdown, markdown_again,
        "swarm workload markdown rendering must be deterministic"
    );
    assert!(
        markdown.contains("# Swarm Workload Harness"),
        "markdown summary must keep its stable heading"
    );
    assert_eq!(
        report.valid,
        report.errors.is_empty(),
        "valid flag and error list must stay in lockstep"
    );

    if report.valid {
        fail_on_swarm_workload_harness_errors(&report).expect("valid report should not fail gate");
        assert!(
            report
                .scenario_verdicts
                .iter()
                .all(|row| row.verdict != SwarmValidationVerdict::Error),
            "valid report must not contain error verdict rows"
        );
        assert_authoritative_rows_are_permissioned(&report);
    } else {
        assert!(
            fail_on_swarm_workload_harness_errors(&report).is_err(),
            "invalid report must fail the gate"
        );
    }
}

fn assert_authoritative_rows_are_permissioned(
    report: &ffs_harness::swarm_workload_harness::SwarmWorkloadHarnessReport,
) {
    for row in &report.scenario_verdicts {
        if row.release_claim_state == "measured_authoritative" {
            assert!(
                row.host_meets_target,
                "authoritative swarm claims must meet the target host contract"
            );
            assert!(
                row.numa_authoritative,
                "authoritative swarm claims must include observable NUMA topology"
            );
            assert_eq!(
                row.host_lane, "permissioned_large_host",
                "authoritative swarm claims must use the permissioned large-host lane"
            );
        }
    }
}

fn exercise_authoritative_guard(mut manifest: SwarmWorkloadHarnessManifest) {
    if manifest.scenarios.is_empty() {
        manifest
            .scenarios
            .push(small_host_bad_authoritative_scenario());
    } else {
        manifest.scenarios[0] = small_host_bad_authoritative_scenario();
    }
    if manifest.workload_profiles.is_empty() {
        manifest
            .workload_profiles
            .push(profile_for_class(SwarmWorkloadClass::MetadataStorm, true));
    }
    manifest.scenarios[0].workload_profile_ids =
        vec![manifest.workload_profiles[0].workload_profile_id.clone()];

    let config = SwarmWorkloadHarnessValidationConfig {
        reference_epoch_days: Some(REFERENCE_EPOCH_DAYS_2026_05_06),
        max_age_days: 30,
    };
    let report = validate_swarm_workload_harness_manifest_with_config(&manifest, &config);
    assert!(
        !report.valid,
        "small-host measured_authoritative swarm claim must fail closed"
    );
    assert!(
        report.errors.iter().any(|error| error.contains("64-core"))
            || report
                .errors
                .iter()
                .any(|error| error.contains("permissioned_large_host"))
            || report.errors.iter().any(|error| error.contains("NUMA")),
        "authoritative guard should explain target, lane, or NUMA failure"
    );
}

fn manifest_from_bytes(cursor: &mut ByteCursor<'_>) -> SwarmWorkloadHarnessManifest {
    let mut profiles: Vec<SwarmWorkloadProfile> = Vec::new();
    let profile_count = usize::from(cursor.next_u8() % 7);
    for index in 0..profile_count {
        let class = cursor.choose(&WORKLOAD_CLASSES);
        let mut profile = profile_for_class(class, cursor.next_bool());
        if cursor.next_u8().is_multiple_of(9) {
            profile.workload_profile_id.clear();
        } else if cursor.next_u8().is_multiple_of(11) && !profiles.is_empty() {
            profile.workload_profile_id = profiles[0].workload_profile_id.clone();
        } else {
            profile.workload_profile_id = format!("{}_{}", class.label(), index);
        }
        profiles.push(profile);
    }
    if cursor.next_bool() {
        for class in WORKLOAD_CLASSES {
            profiles.push(profile_for_class(class, true));
        }
    }

    let profile_ids = profiles
        .iter()
        .map(|profile| profile.workload_profile_id.clone())
        .collect::<Vec<_>>();
    let mut scenarios = Vec::new();
    let scenario_count = usize::from(cursor.next_u8() % 4);
    for index in 0..scenario_count {
        scenarios.push(scenario_from_bytes(cursor, index, &profile_ids));
    }
    if scenarios.is_empty() && cursor.next_bool() {
        scenarios.push(small_host_bad_authoritative_scenario());
    }

    SwarmWorkloadHarnessManifest {
        schema_version: if cursor.next_u8().is_multiple_of(5) {
            cursor.next_u32()
        } else {
            1
        },
        manifest_id: cursor.next_label("swarm_manifest_"),
        generated_at: choose_generated_at(cursor),
        target_host: SwarmWorkloadTargetHost {
            min_cpu_cores_logical: cursor.next_bounded_u32(129),
            min_ram_total_gb: cursor.next_bounded_u32(513),
            min_ram_available_gb: cursor.next_bounded_u32(513),
            min_numa_nodes: cursor.next_bounded_u32(5),
        },
        workload_profiles: profiles,
        scenarios,
        required_log_fields: required_fields_from_bytes(cursor),
        proof_consumers: proof_consumers_from_bytes(cursor),
    }
}

fn choose_generated_at(cursor: &mut ByteCursor<'_>) -> String {
    match cursor.next_u8() % 5 {
        0 => String::new(),
        1 => "not-a-timestamp".to_owned(),
        2 => "2026-05-03T23:20:00Z".to_owned(),
        3 => "2026-06-20T00:00:00Z".to_owned(),
        _ => cursor.next_label("2026-05-"),
    }
}

fn required_fields_from_bytes(cursor: &mut ByteCursor<'_>) -> Vec<String> {
    if cursor.next_bool() {
        REQUIRED_LOG_FIELDS
            .iter()
            .map(|field| (*field).to_owned())
            .collect()
    } else {
        let count = usize::from(cursor.next_u8() % 8);
        (0..count)
            .map(|index| {
                if cursor.next_bool() {
                    REQUIRED_LOG_FIELDS[index % REQUIRED_LOG_FIELDS.len()].to_owned()
                } else {
                    cursor.next_label("field_")
                }
            })
            .collect()
    }
}

fn proof_consumers_from_bytes(cursor: &mut ByteCursor<'_>) -> Vec<String> {
    if cursor.next_bool() {
        vec!["bd-rchk0.53".to_owned(), "proof-bundle".to_owned()]
    } else {
        (0..usize::from(cursor.next_u8() % 4))
            .map(|_| cursor.next_label("consumer_"))
            .collect()
    }
}

fn profile_for_class(
    workload_class: SwarmWorkloadClass,
    valid_shape: bool,
) -> SwarmWorkloadProfile {
    let workload_profile_id = format!("{}_dry_run", workload_class.label());
    SwarmWorkloadProfile {
        workload_profile_id: workload_profile_id.clone(),
        workload_class,
        description: if valid_shape {
            format!("dry-run profile for {}", workload_class.label())
        } else {
            String::new()
        },
        command_plan: SwarmCommandPlan {
            plan_id: format!("{workload_profile_id}_plan"),
            plan_mode: if valid_shape {
                SwarmCommandPlanMode::DryRun
            } else {
                SwarmCommandPlanMode::PermissionedReal
            },
            exact_command: if valid_shape {
                "cargo run -p ffs-harness -- validate-swarm-workload-harness".to_owned()
            } else {
                String::new()
            },
            dry_run_only: valid_shape,
            mutates_host_filesystems: !valid_shape,
            expected_artifacts: if valid_shape {
                vec![SwarmExpectedArtifact {
                    path: format!("artifacts/performance/swarm/{workload_profile_id}.json"),
                    kind: "json_report".to_owned(),
                    required: true,
                }]
            } else {
                Vec::new()
            },
            resource_caps: SwarmResourceCaps {
                max_duration_secs: if valid_shape { 600 } else { 0 },
                max_threads: if valid_shape { 64 } else { 0 },
                max_memory_gb: if valid_shape { 64.0 } else { -1.0 },
                max_temp_storage_gb: if valid_shape { 16.0 } else { -1.0 },
                max_queue_depth: if valid_shape { 4096 } else { 0 },
            },
        },
        placement: SwarmPlacementIntent {
            shard_count: if valid_shape { 64 } else { 0 },
            core_allocation: if valid_shape {
                "spread across worker core groups".to_owned()
            } else {
                String::new()
            },
            numa_policy: if valid_shape {
                "pin shards across observed NUMA nodes".to_owned()
            } else {
                String::new()
            },
            queue_isolation: if valid_shape {
                "separate metadata, write, and repair queues".to_owned()
            } else {
                String::new()
            },
            cleanup_policy: if valid_shape {
                SwarmCleanupPolicy::NoHostMutation
            } else {
                SwarmCleanupPolicy::Missing
            },
        },
    }
}

fn scenario_from_bytes(
    cursor: &mut ByteCursor<'_>,
    index: usize,
    profile_ids: &[String],
) -> SwarmWorkloadScenario {
    let large_host = cursor.next_bool();
    let profile_count = usize::from(cursor.next_u8() % 4);
    let workload_profile_ids = if profile_ids.is_empty() {
        vec![cursor.next_label("unknown_profile_")]
    } else {
        (0..profile_count)
            .map(|_| profile_ids[usize::from(cursor.next_u8()) % profile_ids.len()].clone())
            .collect()
    };

    SwarmWorkloadScenario {
        scenario_id: format!("scenario_{index}_{}", cursor.next_u16()),
        host: host_from_bytes(cursor, large_host),
        workload_profile_ids,
        workload_seeds: (0..usize::from(cursor.next_u8() % 5))
            .map(|_| u64::from(cursor.next_u32()))
            .collect(),
        counters: SwarmQueueBackpressureCounters {
            max_queue_depth: cursor.next_bounded_u32(8192),
            average_queue_depth: cursor.next_f64(8192),
            backpressure_state: cursor.choose(&[
                SwarmBackpressureState::Healthy,
                SwarmBackpressureState::Throttled,
                SwarmBackpressureState::Critical,
                SwarmBackpressureState::Unknown,
            ]),
            throttle_events: u64::from(cursor.next_u32()),
            rejected_writes: u64::from(cursor.next_u32()),
            p99_latency_budget_us: cursor.next_f64(50_000),
        },
        cleanup_status: cursor.choose(&[
            SwarmCleanupStatus::NotStartedDryRun,
            SwarmCleanupStatus::Clean,
            SwarmCleanupStatus::PartialArtifactsPreserved,
            SwarmCleanupStatus::Failed,
            SwarmCleanupStatus::Unknown,
        ]),
        classification: cursor.choose(&[
            SwarmHarnessClassification::Pass,
            SwarmHarnessClassification::Warn,
            SwarmHarnessClassification::Fail,
            SwarmHarnessClassification::CapabilitySkip,
        ]),
        release_claim_state: cursor.choose(&[
            SwarmHarnessReleaseClaimState::Experimental,
            SwarmHarnessReleaseClaimState::PlanReady,
            SwarmHarnessReleaseClaimState::SmallHostSmoke,
            SwarmHarnessReleaseClaimState::CapabilitySkip,
            SwarmHarnessReleaseClaimState::MeasuredLocal,
            SwarmHarnessReleaseClaimState::MeasuredAuthoritative,
            SwarmHarnessReleaseClaimState::Blocked,
        ]),
        reproduction_command: cursor.next_label("cargo_run_"),
        raw_logs: vec![cursor.next_label("artifacts/raw_")],
        artifact_paths: vec![cursor.next_label("artifacts/report_")],
    }
}

fn host_from_bytes(cursor: &mut ByteCursor<'_>, large_host: bool) -> SwarmHostFingerprint {
    let numa_observable = large_host || cursor.next_bool();
    SwarmHostFingerprint {
        host_fingerprint: cursor.next_label(if large_host {
            "large_host_"
        } else {
            "small_host_"
        }),
        cpu_cores_logical: if large_host {
            64 + cursor.next_bounded_u32(128)
        } else {
            cursor.next_bounded_u32(64)
        },
        numa: SwarmNumaObservation {
            observable: numa_observable,
            node_count: if numa_observable {
                Some(1 + cursor.next_bounded_u32(4))
            } else {
                None
            },
            placement_intent: cursor.next_label("numa_"),
            missing_reason: if numa_observable {
                None
            } else {
                Some(cursor.next_label("missing_"))
            },
        },
        ram_total_gb: if large_host {
            256.0 + cursor.next_f64(512)
        } else {
            cursor.next_f64(256)
        },
        ram_available_gb: if large_host {
            192.0 + cursor.next_f64(256)
        } else {
            cursor.next_f64(256)
        },
        storage_class: cursor.next_label("nvme_"),
        fuse_capability: SwarmFuseCapability {
            state: cursor.choose(&[
                SwarmFuseCapabilityState::Available,
                SwarmFuseCapabilityState::Missing,
                SwarmFuseCapabilityState::Unknown,
                SwarmFuseCapabilityState::NotRequired,
            ]),
            detail: cursor.next_label("fuse_"),
        },
        kernel: cursor.next_label("linux_"),
        lane: if large_host {
            SwarmHostLane::PermissionedLargeHost
        } else {
            cursor.choose(&[
                SwarmHostLane::DeveloperSmoke,
                SwarmHostLane::RchWorker,
                SwarmHostLane::CiSmoke,
            ])
        },
        rch_or_local_lane: cursor.choose(&[
            SwarmRchOrLocalLane::Local,
            SwarmRchOrLocalLane::Rch,
            SwarmRchOrLocalLane::Ci,
            SwarmRchOrLocalLane::Unknown,
        ]),
        worker_isolation_notes: cursor.next_label("isolation_"),
    }
}

fn small_host_bad_authoritative_scenario() -> SwarmWorkloadScenario {
    SwarmWorkloadScenario {
        scenario_id: "small_host_bad_authoritative".to_owned(),
        host: SwarmHostFingerprint {
            host_fingerprint: "developer-smoke-8c-32gb".to_owned(),
            cpu_cores_logical: 8,
            numa: SwarmNumaObservation {
                observable: false,
                node_count: None,
                placement_intent: "no NUMA placement claim".to_owned(),
                missing_reason: Some("NUMA topology unavailable".to_owned()),
            },
            ram_total_gb: 32.0,
            ram_available_gb: 24.0,
            storage_class: "developer-nvme".to_owned(),
            fuse_capability: SwarmFuseCapability {
                state: SwarmFuseCapabilityState::Unknown,
                detail: "developer smoke does not prove permissioned FUSE capability".to_owned(),
            },
            kernel: "Linux developer-smoke".to_owned(),
            lane: SwarmHostLane::DeveloperSmoke,
            rch_or_local_lane: SwarmRchOrLocalLane::Local,
            worker_isolation_notes: "local smoke lane only".to_owned(),
        },
        workload_profile_ids: vec!["metadata_storm_dry_run".to_owned()],
        workload_seeds: vec![1],
        counters: SwarmQueueBackpressureCounters {
            max_queue_depth: 16,
            average_queue_depth: 4.0,
            backpressure_state: SwarmBackpressureState::Healthy,
            throttle_events: 0,
            rejected_writes: 0,
            p99_latency_budget_us: 25_000.0,
        },
        cleanup_status: SwarmCleanupStatus::NotStartedDryRun,
        classification: SwarmHarnessClassification::Pass,
        release_claim_state: SwarmHarnessReleaseClaimState::MeasuredAuthoritative,
        reproduction_command: "cargo run -p ffs-harness -- validate-swarm-workload-harness"
            .to_owned(),
        raw_logs: vec!["artifacts/performance/swarm/small-host/raw.log".to_owned()],
        artifact_paths: vec!["artifacts/performance/swarm/small-host/report.json".to_owned()],
    }
}
