#![no_main]

use ffs_harness::perf_regression::{
    classify_latency_regression, classify_throughput_regression, parse_baseline,
    BaselineMeasurement, PerfBaseline, RegressionThreshold,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 16 * 1024;
const OPERATIONS: [&str; 6] = [
    "metadata_parity_cli",
    "write_seq_4k",
    "read_random_4k",
    "repair_decode",
    "swarm_tail_latency",
    "",
];
const METRICS: [&str; 4] = ["latency", "throughput", "p99", ""];
const STATUSES: [&str; 5] = ["measured", "pending", "warn", "fail", ""];

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

    fn next_f64(&mut self, limit: u32) -> f64 {
        f64::from(self.next_u32() % limit) / 10.0
    }

    fn choose<'b>(&mut self, values: &'b [&'b str]) -> &'b str {
        values
            .get(usize::from(self.next_u8()) % values.len())
            .copied()
            .unwrap_or("")
    }

    fn label(&mut self, prefix: &str) -> String {
        if self.next_u8().is_multiple_of(17) {
            return String::new();
        }

        let len = 1 + usize::from(self.next_u8() % 16);
        let mut value = String::from(prefix);
        for _ in 0..len {
            let ch = match self.next_u8() % 16 {
                0 => 'a',
                1 => 'b',
                2 => 'c',
                3 => 'd',
                4 => 'e',
                5 => 'f',
                6 => '0',
                7 => '1',
                8 => '2',
                9 => '3',
                10 => '_',
                11 => '-',
                12 => '.',
                13 => '/',
                14 => ':',
                _ => 'z',
            };
            value.push(ch);
        }
        value
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    if let Ok(text) = std::str::from_utf8(data) {
        assert_eq!(
            parse_signature(text),
            parse_signature(text),
            "performance baseline parsing must be deterministic"
        );
        if let Ok(baseline) = parse_baseline(text) {
            exercise_baseline(&baseline);
        }
    }

    let mut cursor = ByteCursor::new(data);
    let baseline = baseline_from_bytes(&mut cursor);
    exercise_baseline(&baseline);
});

fn parse_signature(text: &str) -> Result<usize, String> {
    parse_baseline(text)
        .map(|baseline| baseline.measurements.len())
        .map_err(|err| err.to_string())
}

fn baseline_from_bytes(cursor: &mut ByteCursor<'_>) -> PerfBaseline {
    let measurement_count = usize::from(cursor.next_u8() % 8);
    let warn = cursor.next_f64(500) + 1.0;
    let fail = warn + cursor.next_f64(500) + 1.0;
    let measurements = (0..measurement_count)
        .map(|_| measurement_from_bytes(cursor))
        .collect();

    PerfBaseline {
        generated_at: cursor.label("2026-05-07T00:00:00Z"),
        commit: cursor.label("commit_"),
        branch: cursor.label("branch_"),
        p99_warn_threshold_percent: warn,
        p99_fail_threshold_percent: fail,
        measurements,
    }
}

fn measurement_from_bytes(cursor: &mut ByteCursor<'_>) -> BaselineMeasurement {
    BaselineMeasurement {
        operation: cursor.choose(&OPERATIONS).to_owned(),
        metric: cursor.choose(&METRICS).to_owned(),
        p50_us: cursor.next_f64(1_000_000),
        p95_us: cursor.next_f64(1_000_000),
        p99_us: cursor.next_f64(1_000_000),
        throughput_ops_sec: cursor.next_f64(1_000_000),
        status: cursor.choose(&STATUSES).to_owned(),
    }
}

fn exercise_baseline(baseline: &PerfBaseline) {
    assert!(
        baseline.p99_warn_threshold_percent.is_finite(),
        "warn threshold must stay finite"
    );
    assert!(
        baseline.p99_fail_threshold_percent.is_finite(),
        "fail threshold must stay finite"
    );

    let json = serde_json::to_string(baseline).expect("bounded baseline must serialize");
    let parsed = parse_baseline(&json).expect("self-serialized baseline must parse");
    assert_eq!(parsed.generated_at, baseline.generated_at);
    assert_eq!(parsed.commit, baseline.commit);
    assert_eq!(parsed.branch, baseline.branch);
    assert_eq!(parsed.measurements.len(), baseline.measurements.len());

    let threshold = RegressionThreshold::new(
        parsed.p99_warn_threshold_percent.max(0.1),
        parsed
            .p99_fail_threshold_percent
            .max(parsed.p99_warn_threshold_percent + 0.1),
    );

    for (left, right) in parsed.measurements.iter().zip(&baseline.measurements) {
        assert_eq!(left.operation, right.operation);
        assert_eq!(left.metric, right.metric);
        assert_eq!(left.status, right.status);
        assert_eq!(left.p50_us, right.p50_us);
        assert_eq!(left.p95_us, right.p95_us);
        assert_eq!(left.p99_us, right.p99_us);
        assert_eq!(left.throughput_ops_sec, right.throughput_ops_sec);

        let latency = classify_latency_regression(left.p99_us, right.p99_us, threshold);
        assert_eq!(latency.is_some(), left.p99_us > 0.0);
        let throughput = classify_throughput_regression(
            left.throughput_ops_sec,
            right.throughput_ops_sec,
            threshold,
        );
        assert_eq!(throughput.is_some(), left.throughput_ops_sec > 0.0);
    }
}
