use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use nix::sys::resource::{UsageWho, getrusage};
use nix::sys::time::TimeValLike;
use serde::Serialize;

#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Stage {
    HeaderProbe,
    BlankScan,
    FormatCli,
    FormatFallback,
    LibFormat,
    Keyslot,
    IntegrityInitialize,
    IntegritySync,
    HeaderSeal,
    Open,
    Mkfs,
    Mount,
}

#[derive(Debug, Default, Serialize)]
pub struct Measurement {
    calls: u64,
    failures: u64,
    elapsed_us: u64,
    counters_available: u8,
    user_cpu_us: u64,
    system_cpu_us: u64,
    child_user_cpu_us: u64,
    child_system_cpu_us: u64,
    input_blocks: u64,
    output_blocks: u64,
    throttled_periods: u64,
    throttled_us: u64,
}

#[derive(Debug, Serialize)]
pub struct VolumeProfile {
    pub device_bytes: u64,
    pub scanned_bytes: u64,
    pub initialized_bytes: u64,
    pub stages: [Measurement; 12],
    #[serde(skip)]
    cpu_stat: Option<PathBuf>,
}

impl Default for VolumeProfile {
    fn default() -> Self {
        let cpu_stat = std::fs::read_to_string("/proc/self/cgroup")
            .ok()
            .and_then(|text| {
                text.lines()
                    .find_map(|line| line.strip_prefix("0::"))
                    .map(|relative| {
                        Path::new("/sys/fs/cgroup")
                            .join(relative.trim_start_matches('/'))
                            .join("cpu.stat")
                    })
            });
        Self {
            device_bytes: 0,
            scanned_bytes: 0,
            initialized_bytes: 0,
            stages: std::array::from_fn(|_| Measurement::default()),
            cpu_stat,
        }
    }
}

impl VolumeProfile {
    pub fn format_completed(&self) -> bool {
        let seal = &self.stages[Stage::HeaderSeal as usize];
        seal.calls != 0 && seal.failures == 0
    }

    pub fn run<T, E>(
        &mut self,
        stage: Stage,
        work: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<T, E> {
        let before = Counters::read(self.cpu_stat.as_deref());
        let start = Instant::now();
        let result = work(self);
        let elapsed_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
        let after = Counters::read(self.cpu_stat.as_deref());
        let measurement = &mut self.stages[stage as usize];
        let available = before.available & after.available;
        measurement.counters_available = if measurement.calls == 0 {
            available
        } else {
            measurement.counters_available & available
        };
        measurement.calls += 1;
        measurement.failures += u64::from(result.is_err());
        measurement.elapsed_us = measurement.elapsed_us.saturating_add(elapsed_us);
        if measurement.counters_available & 1 != 0 {
            measurement.user_cpu_us += after.user_cpu_us.saturating_sub(before.user_cpu_us);
            measurement.system_cpu_us += after.system_cpu_us.saturating_sub(before.system_cpu_us);
        }
        if measurement.counters_available & 2 != 0 {
            measurement.child_user_cpu_us += after
                .child_user_cpu_us
                .saturating_sub(before.child_user_cpu_us);
            measurement.child_system_cpu_us += after
                .child_system_cpu_us
                .saturating_sub(before.child_system_cpu_us);
        }
        if measurement.counters_available & 3 == 3 {
            measurement.input_blocks += after.input_blocks.saturating_sub(before.input_blocks);
            measurement.output_blocks += after.output_blocks.saturating_sub(before.output_blocks);
        }
        if measurement.counters_available & 4 != 0 {
            measurement.throttled_periods += after
                .throttled_periods
                .saturating_sub(before.throttled_periods);
            measurement.throttled_us += after.throttled_us.saturating_sub(before.throttled_us);
        }
        result
    }
}

#[derive(Default)]
struct Counters {
    available: u8,
    user_cpu_us: u64,
    system_cpu_us: u64,
    child_user_cpu_us: u64,
    child_system_cpu_us: u64,
    input_blocks: u64,
    output_blocks: u64,
    throttled_periods: u64,
    throttled_us: u64,
}

impl Counters {
    fn read(cpu_stat: Option<&Path>) -> Self {
        let mut counters = Self::default();
        if let Ok(usage) = getrusage(UsageWho::RUSAGE_SELF) {
            counters.available |= 1;
            counters.user_cpu_us = nonnegative(usage.user_time().num_microseconds());
            counters.system_cpu_us = nonnegative(usage.system_time().num_microseconds());
            counters.input_blocks = nonnegative(usage.block_reads());
            counters.output_blocks = nonnegative(usage.block_writes());
        }
        if let Ok(usage) = getrusage(UsageWho::RUSAGE_CHILDREN) {
            counters.available |= 2;
            counters.child_user_cpu_us = nonnegative(usage.user_time().num_microseconds());
            counters.child_system_cpu_us = nonnegative(usage.system_time().num_microseconds());
            counters.input_blocks += nonnegative(usage.block_reads());
            counters.output_blocks += nonnegative(usage.block_writes());
        }
        if let Some((periods, micros)) = cpu_stat.and_then(read_throttling) {
            counters.available |= 4;
            counters.throttled_periods = periods;
            counters.throttled_us = micros;
        }
        counters
    }
}

fn nonnegative(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

fn read_throttling(path: &Path) -> Option<(u64, u64)> {
    let mut buffer = [0; 4096];
    let length = std::fs::File::open(path).ok()?.read(&mut buffer).ok()?;
    if length == buffer.len() {
        return None;
    }
    parse_throttling(std::str::from_utf8(&buffer[..length]).ok()?)
}

fn parse_throttling(text: &str) -> Option<(u64, u64)> {
    let mut periods = None;
    let mut micros = None;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        match fields.next()? {
            "nr_throttled" => periods = fields.next()?.parse().ok(),
            "throttled_usec" => micros = fields.next()?.parse().ok(),
            _ => {}
        }
    }
    Some((periods?, micros?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_and_nested_work_retains_outcomes_without_error_text() {
        let mut profile = VolumeProfile::default();
        let result: Result<(), &str> = profile.run(Stage::FormatFallback, |profile| {
            profile.run(Stage::Keyslot, |_| Err("PRIVATE_KEY_OR_PROVIDER_ERROR"))
        });
        assert_eq!(result, Err("PRIVATE_KEY_OR_PROVIDER_ERROR"));
        assert_eq!(profile.stages[Stage::FormatFallback as usize].calls, 1);
        assert_eq!(profile.stages[Stage::FormatFallback as usize].failures, 1);
        assert_eq!(profile.stages[Stage::Keyslot as usize].failures, 1);
        assert_eq!(profile.stages[Stage::BlankScan as usize].calls, 0);
        let json = serde_json::to_value(profile).unwrap();
        fn numeric_only(value: &serde_json::Value) {
            match value {
                serde_json::Value::Number(number) => assert!(number.is_u64()),
                serde_json::Value::Array(values) => values.iter().for_each(numeric_only),
                serde_json::Value::Object(fields) => fields.values().for_each(numeric_only),
                _ => panic!("non-numeric profiling value"),
            }
        }
        numeric_only(&json);
        assert!(!json.to_string().contains("PRIVATE_KEY_OR_PROVIDER_ERROR"));
    }

    #[test]
    fn completed_format_survives_later_filesystem_failure() {
        let mut profile = VolumeProfile::default();
        assert!(!profile.format_completed());
        profile.run(Stage::HeaderSeal, |_| Ok::<_, ()>(())).unwrap();
        let result = profile.run(Stage::Mkfs, |_| Err::<(), _>("filesystem failed"));
        assert_eq!(result, Err("filesystem failed"));
        assert!(profile.format_completed());
        assert_eq!(profile.stages[Stage::Mkfs as usize].failures, 1);
    }

    #[test]
    fn unavailable_throttling_is_not_reported_as_observed_zero() {
        assert_eq!(
            parse_throttling("usage_usec 9\nnr_throttled 0\nthrottled_usec 0\n"),
            Some((0, 0))
        );
        assert_eq!(parse_throttling("usage_usec 9\n"), None);
        assert_eq!(
            parse_throttling("nr_throttled bad\nthrottled_usec 2\n"),
            None
        );
    }
}
