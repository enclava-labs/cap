//! Numeric-only boot summary for capacity measurement (plan Stage E3).
//!
//! App telemetry begins too late to observe LUKS format/unlock, so init
//! records a fixed-schema JSON record once, just before marking ready, on the
//! shared `/run/enclava` emptyDir the workload already mounts. Every field is
//! a number; there are no log lines, paths, identifiers, or secrets in the
//! record. It is a snapshot bound to this boot, not a metrics service, and it
//! only ever reads this process's own cgroup peak — shared peaks are never
//! reset to manufacture per-app numbers.

use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use enclava_init::errors::Result;
use enclava_init::writes;

/// Fixed schema version. Consumers must treat missing fields as absent, not
/// zero, and ignore fields they do not know.
const SCHEMA_VERSION: u64 = 1;

/// Per-volume LUKS open timing in milliseconds plus whether the volume was
/// freshly formatted (1) or opened (0).
#[derive(Debug, Default, Clone, Copy)]
pub struct VolumeTiming {
    pub millis: u64,
    pub formatted: bool,
}

#[derive(Debug)]
pub struct BootStats {
    start: Instant,
    init_start_unix: u64,
    guest_mem_total_bytes: u64,
    mem_available_start_bytes: u64,
    mem_available_post_luks_bytes: u64,
    owner_seed_ms: u64,
    state_volume: VolumeTiming,
    tls_volume: VolumeTiming,
    tee_verify_ms: u64,
    component_seeds_ms: u64,
    bind_mounts_ms: u64,
}

impl BootStats {
    /// Capture boot anchor: unix timestamp and guest memory at process start.
    pub fn begin() -> Self {
        Self {
            start: Instant::now(),
            init_start_unix: unix_secs(),
            guest_mem_total_bytes: meminfo_bytes("MemTotal"),
            mem_available_start_bytes: meminfo_bytes("MemAvailable"),
            mem_available_post_luks_bytes: 0,
            owner_seed_ms: 0,
            state_volume: VolumeTiming::default(),
            tls_volume: VolumeTiming::default(),
            tee_verify_ms: 0,
            component_seeds_ms: 0,
            bind_mounts_ms: 0,
        }
    }

    /// Milliseconds elapsed since `begin()`; call around a phase to time it.
    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    pub fn record_owner_seed(&mut self, phase_start_ms: u64) {
        self.owner_seed_ms = self.elapsed_ms().saturating_sub(phase_start_ms);
    }

    pub fn record_state_volume(&mut self, phase_start_ms: u64, formatted: bool) {
        self.state_volume = VolumeTiming {
            millis: self.elapsed_ms().saturating_sub(phase_start_ms),
            formatted,
        };
    }

    pub fn record_tls_volume(&mut self, phase_start_ms: u64, formatted: bool) {
        self.tls_volume = VolumeTiming {
            millis: self.elapsed_ms().saturating_sub(phase_start_ms),
            formatted,
        };
    }

    /// Guest MemAvailable immediately after both LUKS volumes are open.
    pub fn record_post_luks_memory(&mut self) {
        self.mem_available_post_luks_bytes = meminfo_bytes("MemAvailable");
    }

    pub fn record_tee_verify(&mut self, phase_start_ms: u64) {
        self.tee_verify_ms = self.elapsed_ms().saturating_sub(phase_start_ms);
    }

    pub fn record_component_seeds(&mut self, phase_start_ms: u64) {
        self.component_seeds_ms = self.elapsed_ms().saturating_sub(phase_start_ms);
    }

    pub fn record_bind_mounts(&mut self, phase_start_ms: u64) {
        self.bind_mounts_ms = self.elapsed_ms().saturating_sub(phase_start_ms);
    }

    /// Serialize the fixed-schema record. Missing counters are emitted as 0;
    /// `init_cgroup_peak_bytes`/`mem_available_ready_bytes` are sampled now.
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"version\":{version},",
                "\"init_start_unix\":{init_start_unix},",
                "\"durations_ms\":{{",
                "\"owner_seed\":{owner_seed},",
                "\"state_volume\":{state_ms},",
                "\"tls_volume\":{tls_ms},",
                "\"tee_verify\":{tee_verify},",
                "\"component_seeds\":{component_seeds},",
                "\"bind_mounts\":{bind_mounts},",
                "\"total_to_ready\":{total}",
                "}},",
                "\"volume_formatted\":{{\"state\":{state_fmt},\"tls\":{tls_fmt}}},",
                "\"guest_mem_total_bytes\":{mem_total},",
                "\"guest_mem_available_bytes\":{{",
                "\"init_start\":{mem_start},",
                "\"post_luks\":{mem_post_luks},",
                "\"ready\":{mem_ready}",
                "}},",
                "\"init_cgroup_peak_bytes\":{cgroup_peak}",
                "}}",
            ),
            version = SCHEMA_VERSION,
            init_start_unix = self.init_start_unix,
            owner_seed = self.owner_seed_ms,
            state_ms = self.state_volume.millis,
            tls_ms = self.tls_volume.millis,
            tee_verify = self.tee_verify_ms,
            component_seeds = self.component_seeds_ms,
            bind_mounts = self.bind_mounts_ms,
            total = self.elapsed_ms(),
            state_fmt = self.state_volume.formatted as u8,
            tls_fmt = self.tls_volume.formatted as u8,
            mem_total = self.guest_mem_total_bytes,
            mem_start = self.mem_available_start_bytes,
            mem_post_luks = self.mem_available_post_luks_bytes,
            mem_ready = meminfo_bytes("MemAvailable"),
            cgroup_peak = self_cgroup_peak_bytes(),
        )
    }

    /// Write the record atomically with mode 0644 so the unprivileged workload
    /// (uid 10001, in group 10001) can read it over its attested channel.
    pub fn write(&self, path: &Path) -> Result<()> {
        writes::atomic_write(path, self.to_json().as_bytes(), 0o644)
    }
}

/// Path for the stats file: sibling of the ready file (`init-ready` ->
/// `init-stats.json`), on the same shared emptyDir the workload mounts.
pub fn stats_path_for(ready_file: &Path) -> PathBuf {
    ready_file.with_file_name("init-stats.json")
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn meminfo_bytes(field: &str) -> u64 {
    let Ok(text) = std::fs::read_to_string("/proc/meminfo") else {
        return 0;
    };
    parse_meminfo_kib(&text, field)
        .map(|kib| kib * 1024)
        .unwrap_or(0)
}

fn parse_meminfo_kib(text: &str, field: &str) -> Option<u64> {
    let prefix = format!("{field}:");
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(&prefix) {
            return rest
                .trim()
                .trim_end_matches(" kB")
                .trim()
                .parse::<u64>()
                .ok();
        }
    }
    None
}

/// This process's own cgroup peak, or 0 when unavailable. Ancestor peaks
/// include other containers and current usage is not a high-water counter.
fn self_cgroup_peak_bytes() -> u64 {
    let Ok(cgroup) = std::fs::read_to_string("/proc/self/cgroup") else {
        return 0;
    };
    let Some(rel) = cgroup.lines().find_map(|line| line.strip_prefix("0::")) else {
        return 0;
    };
    let dir = Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/'));
    std::fs::read_to_string(dir.join("memory.peak"))
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_path_is_ready_file_sibling() {
        assert_eq!(
            stats_path_for(Path::new("/run/enclava/init-ready")),
            PathBuf::from("/run/enclava/init-stats.json")
        );
    }

    #[test]
    fn json_is_fixed_numeric_schema() {
        let stats = BootStats {
            start: Instant::now(),
            init_start_unix: 1_700_000_000,
            guest_mem_total_bytes: 1024,
            mem_available_start_bytes: 512,
            mem_available_post_luks_bytes: 256,
            owner_seed_ms: 10,
            state_volume: VolumeTiming {
                millis: 20,
                formatted: true,
            },
            tls_volume: VolumeTiming {
                millis: 30,
                formatted: false,
            },
            tee_verify_ms: 40,
            component_seeds_ms: 50,
            bind_mounts_ms: 60,
        };
        let value: serde_json::Value = serde_json::from_str(&stats.to_json()).expect("valid json");
        assert_eq!(value["version"], 1);
        assert_eq!(value["init_start_unix"], 1_700_000_000);
        assert_eq!(value["durations_ms"]["state_volume"], 20);
        assert_eq!(value["durations_ms"]["tls_volume"], 30);
        assert_eq!(value["volume_formatted"]["state"], 1);
        assert_eq!(value["volume_formatted"]["tls"], 0);
        assert_eq!(value["guest_mem_total_bytes"], 1024);
        assert_eq!(value["guest_mem_available_bytes"]["init_start"], 512);
        assert_eq!(value["guest_mem_available_bytes"]["post_luks"], 256);
        assert!(value["guest_mem_available_bytes"]["ready"].is_u64());
        assert!(value["init_cgroup_peak_bytes"].is_u64());
    }

    #[test]
    fn meminfo_parser_reads_named_field() {
        let text = "MemTotal:       1873924 kB\nMemAvailable:   1500123 kB\n";
        assert_eq!(parse_meminfo_kib(text, "MemTotal"), Some(1_873_924));
        assert_eq!(parse_meminfo_kib(text, "MemAvailable"), Some(1_500_123));
        assert_eq!(parse_meminfo_kib(text, "Missing"), None);
    }
}
