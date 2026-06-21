use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hdrhistogram::Histogram;
use serde::Serialize;
use wiresurge_core::{Result, WireSurgeError, serialize_json};

mod hist;
pub use hist::LoadRecorder;

const LATENCY_MIN_MICROS: u64 = 1;
const LATENCY_MAX_MICROS: u64 = 60 * 60 * 1_000_000;
const LATENCY_SIGNIFICANT_DIGITS: u8 = 3;

#[derive(Debug, Clone)]
pub struct LatencyHistogram {
    histogram: Histogram<u64>,
    total_micros: u128,
    overflows: u64,
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self {
            histogram: Histogram::new_with_bounds(
                LATENCY_MIN_MICROS,
                LATENCY_MAX_MICROS,
                LATENCY_SIGNIFICANT_DIGITS,
            )
            .expect("static latency histogram bounds are valid"),
            total_micros: 0,
            overflows: 0,
        }
    }
}

impl LatencyHistogram {
    pub fn record(&mut self, duration: Duration) {
        let micros = duration
            .as_micros()
            .max(LATENCY_MIN_MICROS as u128)
            .min(u64::MAX as u128) as u64;
        if self.histogram.record(micros).is_ok() {
            self.total_micros += micros as u128;
        } else {
            self.overflows += 1;
        }
    }

    pub fn merge(&mut self, other: &Self) -> Result<()> {
        self.histogram.add(&other.histogram).map_err(|error| {
            WireSurgeError::new("latency_histogram_merge_failed", error.to_string())
        })?;
        self.total_micros += other.total_micros;
        self.overflows += other.overflows;
        Ok(())
    }

    pub fn len(&self) -> u64 {
        self.histogram.len()
    }

    pub fn is_empty(&self) -> bool {
        self.histogram.is_empty()
    }

    pub fn overflows(&self) -> u64 {
        self.overflows
    }

    pub fn min_ms(&self) -> f64 {
        if self.is_empty() {
            0.0
        } else {
            self.histogram.min() as f64 / 1000.0
        }
    }

    pub fn max_ms(&self) -> f64 {
        if self.is_empty() {
            0.0
        } else {
            self.histogram.max() as f64 / 1000.0
        }
    }

    pub fn average_ms(&self) -> f64 {
        if self.is_empty() {
            0.0
        } else {
            self.total_micros as f64 / self.len() as f64 / 1000.0
        }
    }

    pub fn percentile_ms(&self, quantile: f64) -> f64 {
        if self.is_empty() {
            0.0
        } else {
            self.histogram.value_at_quantile(quantile) as f64 / 1000.0
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WorkerStats {
    pub id: String,
    pub status: String,
    pub qps: f64,
    pub rps: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub error_rate: f64,
    pub timeout_rate: f64,
    pub open_connections: u64,
}

impl WorkerStats {
    pub fn idle(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status: "idle".to_string(),
            qps: 0.0,
            rps: 0.0,
            p50_ms: 0.0,
            p95_ms: 0.0,
            p99_ms: 0.0,
            error_rate: 0.0,
            timeout_rate: 0.0,
            open_connections: 0,
        }
    }

    pub fn to_json(&self) -> Result<String> {
        serialize_json(self)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RunnerStats {
    pub id: String,
    pub name: String,
    pub source: String,
    pub status: String,
    pub pid: u32,
    pub version: String,
    pub started_at: u64,
    pub last_heartbeat: u64,
    pub active_run_id: Option<String>,
    pub workers: Vec<WorkerStats>,
    pub qps: f64,
    pub rps: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub error_rate: f64,
    pub timeout_rate: f64,
    pub open_connections: u64,
    pub cpu_pct: f64,
    pub memory_bytes: u64,
}

impl RunnerStats {
    pub fn local(active_run_id: Option<String>, workers: usize) -> Self {
        let now = unix_timestamp();
        let worker_stats = (0..workers.max(1))
            .map(|index| WorkerStats::idle(format!("worker-{index}")))
            .collect::<Vec<_>>();
        Self {
            id: format!("local-{}", std::process::id()),
            name: "local-cli".to_string(),
            source: "cli".to_string(),
            status: "active".to_string(),
            pid: std::process::id(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            started_at: now,
            last_heartbeat: now,
            active_run_id,
            workers: worker_stats,
            qps: 0.0,
            rps: 0.0,
            p50_ms: 0.0,
            p95_ms: 0.0,
            p99_ms: 0.0,
            error_rate: 0.0,
            timeout_rate: 0.0,
            open_connections: 0,
            cpu_pct: 0.0,
            memory_bytes: 0,
        }
    }

    pub fn finish_with_latency(mut self, duration_ms: f64, success: bool) -> Self {
        self.status = "idle".to_string();
        self.last_heartbeat = unix_timestamp();
        self.rps = if duration_ms > 0.0 {
            1000.0 / duration_ms
        } else {
            0.0
        };
        self.qps = self.rps;
        self.p50_ms = duration_ms;
        self.p95_ms = duration_ms;
        self.p99_ms = duration_ms;
        self.error_rate = if success { 0.0 } else { 1.0 };
        if let Some(worker) = self.workers.first_mut() {
            worker.status = "idle".to_string();
            worker.rps = self.rps;
            worker.qps = self.qps;
            worker.p50_ms = duration_ms;
            worker.p95_ms = duration_ms;
            worker.p99_ms = duration_ms;
            worker.error_rate = self.error_rate;
        }
        self
    }

    pub fn to_json(&self) -> Result<String> {
        serialize_json(self)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReportSummary {
    pub id: String,
    pub started_at: u64,
    pub duration_ms: f64,
    pub workflow_hash: String,
    pub git_commit: Option<String>,
    pub status: String,
    pub total_requests: u64,
    pub total_errors: u64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub error_summary: String,
    pub redaction_status: String,
}

impl ReportSummary {
    pub fn single_request(id: impl Into<String>, duration_ms: f64, success: bool) -> Self {
        Self {
            id: id.into(),
            started_at: unix_timestamp(),
            duration_ms,
            workflow_hash: "single-request".to_string(),
            git_commit: None,
            status: if success { "passed" } else { "failed" }.to_string(),
            total_requests: 1,
            total_errors: if success { 0 } else { 1 },
            p50_ms: duration_ms,
            p95_ms: duration_ms,
            p99_ms: duration_ms,
            error_summary: if success { "none" } else { "request failed" }.to_string(),
            redaction_status: "redacted".to_string(),
        }
    }

    pub fn to_json(&self) -> Result<String> {
        serialize_json(&ReportSummaryOutput {
            id: &self.id,
            started_at: self.started_at,
            duration_ms: self.duration_ms,
            workflow_hash: &self.workflow_hash,
            git_commit: self.git_commit.as_deref(),
            status: &self.status,
            total_requests: self.total_requests,
            total_errors: self.total_errors,
            latency_percentiles: LatencyPercentiles {
                p50_ms: self.p50_ms,
                p95_ms: self.p95_ms,
                p99_ms: self.p99_ms,
            },
            error_summary: &self.error_summary,
            redaction_status: &self.redaction_status,
        })
    }

    pub fn to_json_value(&self) -> Result<serde_json::Value> {
        serde_json::to_value(ReportSummaryOutput {
            id: &self.id,
            started_at: self.started_at,
            duration_ms: self.duration_ms,
            workflow_hash: &self.workflow_hash,
            git_commit: self.git_commit.as_deref(),
            status: &self.status,
            total_requests: self.total_requests,
            total_errors: self.total_errors,
            latency_percentiles: LatencyPercentiles {
                p50_ms: self.p50_ms,
                p95_ms: self.p95_ms,
                p99_ms: self.p99_ms,
            },
            error_summary: &self.error_summary,
            redaction_status: &self.redaction_status,
        })
        .map_err(|error| {
            wiresurge_core::WireSurgeError::new("json_encode_failed", error.to_string())
        })
    }
}

#[derive(Serialize)]
struct ReportSummaryOutput<'a> {
    id: &'a str,
    started_at: u64,
    duration_ms: f64,
    workflow_hash: &'a str,
    git_commit: Option<&'a str>,
    status: &'a str,
    total_requests: u64,
    total_errors: u64,
    latency_percentiles: LatencyPercentiles,
    error_summary: &'a str,
    redaction_status: &'a str,
}

#[derive(Serialize)]
struct LatencyPercentiles {
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
}

pub fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runner_stats_include_workers() {
        let stats = RunnerStats::local(Some("run-1".to_string()), 2);
        let json = stats.to_json().unwrap();
        assert!(json.contains("\"active_run_id\":\"run-1\""));
        assert!(json.contains("worker-1"));
    }

    #[test]
    fn latency_histograms_merge_with_bounded_precision() {
        let mut left = LatencyHistogram::default();
        left.record(Duration::from_micros(100));
        left.record(Duration::from_micros(200));
        let mut right = LatencyHistogram::default();
        right.record(Duration::from_micros(300));
        left.merge(&right).unwrap();

        assert_eq!(left.len(), 3);
        assert_eq!(left.average_ms(), 0.2);
        assert!((0.299..=0.301).contains(&left.percentile_ms(0.99)));
        assert_eq!(left.overflows(), 0);
    }

    #[test]
    fn latency_histogram_counts_out_of_range_samples() {
        let mut histogram = LatencyHistogram::default();
        histogram.record(Duration::from_secs(2 * 60 * 60));
        assert!(histogram.is_empty());
        assert_eq!(histogram.overflows(), 1);
    }
}
