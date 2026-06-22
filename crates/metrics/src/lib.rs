use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use wiresurge_core::{Result, serialize_json};

mod hist;
pub use hist::LoadRecorder;

/// Point-in-time sample of a `load` run: aggregate plus one `WorkerStats` per
/// connection actor. `final_sample` marks the end-of-run frame.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct RunSnapshot {
    pub elapsed_s: f64,
    pub final_sample: bool,
    pub aggregate: AggregateStats,
    pub workers: Vec<WorkerStats>,
}

impl RunSnapshot {
    pub fn to_json(&self) -> Result<String> {
        serialize_json(self)
    }
}

/// Run-wide totals at a point in time. Rates are cumulative (counts over
/// `elapsed_s`); an instantaneous rate is derived by differencing two samples.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct AggregateStats {
    pub sent: u64,
    pub received: u64,
    pub timeouts: u64,
    pub errors: u64,
    pub conn_errors: u64,
    pub truncated: u64,
    pub bytes_in: u64,
    pub in_flight: u64,
    pub noerror: u64,
    pub recv_qps: f64,
    pub noerror_qps: f64,
    pub rcodes: BTreeMap<String, u64>,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
}

impl AggregateStats {
    pub fn from_recorder(recorder: &LoadRecorder, elapsed_s: f64, in_flight: u64) -> Self {
        let rate = |count: u64| {
            if elapsed_s > 0.0 {
                count as f64 / elapsed_s
            } else {
                0.0
            }
        };
        Self {
            sent: recorder.sent,
            received: recorder.received,
            timeouts: recorder.timeouts,
            errors: recorder.errors,
            conn_errors: recorder.conn_errors,
            truncated: recorder.truncated,
            bytes_in: recorder.bytes_in,
            in_flight,
            noerror: recorder.noerror(),
            recv_qps: rate(recorder.received),
            noerror_qps: rate(recorder.noerror()),
            rcodes: recorder.rcode_breakdown(),
            p50_ms: recorder.percentile_ms(0.50),
            p95_ms: recorder.percentile_ms(0.95),
            p99_ms: recorder.percentile_ms(0.99),
            max_ms: recorder.max_ms(),
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
    pub in_flight: u64,
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
            in_flight: 0,
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
        let rps = if duration_ms > 0.0 {
            1000.0 / duration_ms
        } else {
            0.0
        };
        let error_rate = if success { 0.0 } else { 1.0 };

        self.status = "idle".to_string();
        self.last_heartbeat = unix_timestamp();
        self.rps = rps;
        self.qps = rps;
        self.p50_ms = duration_ms;
        self.p95_ms = duration_ms;
        self.p99_ms = duration_ms;
        self.error_rate = error_rate;
        if let Some(worker) = self.workers.first_mut() {
            worker.status = "idle".to_string();
            worker.rps = rps;
            worker.qps = rps;
            worker.p50_ms = duration_ms;
            worker.p95_ms = duration_ms;
            worker.p99_ms = duration_ms;
            worker.error_rate = error_rate;
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

    fn output(&self) -> ReportSummaryOutput<'_> {
        ReportSummaryOutput {
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
        }
    }

    pub fn to_json(&self) -> Result<String> {
        serialize_json(&self.output())
    }

    pub fn to_json_value(&self) -> Result<serde_json::Value> {
        serde_json::to_value(self.output()).map_err(|error| {
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
    fn run_snapshot_serializes_aggregate_and_workers() {
        let mut recorder = LoadRecorder::default();
        recorder.on_sent();
        recorder.on_response(0, false, 64, 1_000);
        let worker = recorder.snapshot_worker("worker-0", "done", 2.0, 0);
        let snapshot = RunSnapshot {
            elapsed_s: 2.0,
            final_sample: true,
            aggregate: AggregateStats::from_recorder(&recorder, 2.0, 0),
            workers: vec![worker],
        };

        let json = snapshot.to_json().unwrap();
        assert!(json.contains("\"elapsed_s\":2.0"));
        assert!(json.contains("\"final_sample\":true"));
        assert!(json.contains("\"aggregate\""));
        assert!(json.contains("\"workers\""));
        assert!(json.contains("worker-0"));
        assert!(json.contains("\"p99_ms\""));
        assert_eq!(snapshot.aggregate.received, 1);
        assert_eq!(snapshot.aggregate.recv_qps, 0.5);
        assert_eq!(snapshot.aggregate.noerror_qps, 0.5);
    }
}
