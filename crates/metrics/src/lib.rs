use std::time::{SystemTime, UNIX_EPOCH};

use wiresurge_core::{json_array, json_object, json_string};

#[derive(Debug, Clone, PartialEq)]
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

    pub fn to_json(&self) -> String {
        json_object(&[
            ("id", json_string(&self.id)),
            ("status", json_string(&self.status)),
            ("qps", format_float(self.qps)),
            ("rps", format_float(self.rps)),
            ("p50_ms", format_float(self.p50_ms)),
            ("p95_ms", format_float(self.p95_ms)),
            ("p99_ms", format_float(self.p99_ms)),
            ("error_rate", format_float(self.error_rate)),
            ("timeout_rate", format_float(self.timeout_rate)),
            ("open_connections", self.open_connections.to_string()),
        ])
    }
}

#[derive(Debug, Clone, PartialEq)]
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

    pub fn to_json(&self) -> String {
        let workers = self
            .workers
            .iter()
            .map(WorkerStats::to_json)
            .collect::<Vec<_>>();
        json_object(&[
            ("id", json_string(&self.id)),
            ("name", json_string(&self.name)),
            ("source", json_string(&self.source)),
            ("status", json_string(&self.status)),
            ("pid", self.pid.to_string()),
            ("version", json_string(&self.version)),
            ("started_at", self.started_at.to_string()),
            ("last_heartbeat", self.last_heartbeat.to_string()),
            (
                "active_run_id",
                self.active_run_id
                    .as_ref()
                    .map(|id| json_string(id))
                    .unwrap_or_else(|| "null".to_string()),
            ),
            ("workers", json_array(&workers)),
            ("qps", format_float(self.qps)),
            ("rps", format_float(self.rps)),
            ("p50_ms", format_float(self.p50_ms)),
            ("p95_ms", format_float(self.p95_ms)),
            ("p99_ms", format_float(self.p99_ms)),
            ("error_rate", format_float(self.error_rate)),
            ("timeout_rate", format_float(self.timeout_rate)),
            ("open_connections", self.open_connections.to_string()),
            ("cpu_pct", format_float(self.cpu_pct)),
            ("memory_bytes", self.memory_bytes.to_string()),
        ])
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

    pub fn to_json(&self) -> String {
        json_object(&[
            ("id", json_string(&self.id)),
            ("started_at", self.started_at.to_string()),
            ("duration_ms", format_float(self.duration_ms)),
            ("workflow_hash", json_string(&self.workflow_hash)),
            (
                "git_commit",
                self.git_commit
                    .as_ref()
                    .map(|commit| json_string(commit))
                    .unwrap_or_else(|| "null".to_string()),
            ),
            ("status", json_string(&self.status)),
            ("total_requests", self.total_requests.to_string()),
            ("total_errors", self.total_errors.to_string()),
            (
                "latency_percentiles",
                json_object(&[
                    ("p50_ms", format_float(self.p50_ms)),
                    ("p95_ms", format_float(self.p95_ms)),
                    ("p99_ms", format_float(self.p99_ms)),
                ]),
            ),
            ("error_summary", json_string(&self.error_summary)),
            ("redaction_status", json_string(&self.redaction_status)),
        ])
    }
}

pub fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn format_float(value: f64) -> String {
    if value.is_finite() {
        format!("{value:.3}")
    } else {
        "0.000".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runner_stats_include_workers() {
        let stats = RunnerStats::local(Some("run-1".to_string()), 2);
        let json = stats.to_json();
        assert!(json.contains("\"active_run_id\":\"run-1\""));
        assert!(json.contains("worker-1"));
    }
}
