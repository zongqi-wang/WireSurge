use hdrhistogram::Histogram;

use crate::WorkerStats;

/// Per-connection load recorder. One lives inside each connection actor and is
/// merged into an aggregate off the hot path, so the high-rate send/receive
/// loop never contends on a shared lock.
#[derive(Clone)]
pub struct LoadRecorder {
    pub sent: u64,
    pub received: u64,
    pub timeouts: u64,
    pub errors: u64,
    pub conn_errors: u64,
    pub truncated: u64,
    pub bytes_in: u64,
    pub rcodes: [u64; 17],
    hist: Histogram<u64>,
}

impl Default for LoadRecorder {
    fn default() -> Self {
        Self {
            sent: 0,
            received: 0,
            timeouts: 0,
            errors: 0,
            conn_errors: 0,
            truncated: 0,
            bytes_in: 0,
            rcodes: [0; 17],
            hist: Histogram::new_with_bounds(1, 60_000_000, 3).expect("valid histogram bounds"),
        }
    }
}

impl LoadRecorder {
    pub fn on_sent(&mut self) {
        self.sent += 1;
    }

    pub fn on_response(&mut self, rcode: u16, truncated: bool, bytes_in: usize, latency_us: u64) {
        self.received += 1;
        self.bytes_in += bytes_in as u64;
        self.truncated += u64::from(truncated);
        self.rcodes[usize::from(rcode.min(16))] += 1;
        let _ = self.hist.record(latency_us.max(1));
    }

    pub fn on_timeout(&mut self) {
        self.timeouts += 1;
    }

    pub fn on_error(&mut self) {
        self.errors += 1;
    }

    pub fn on_conn_error(&mut self) {
        self.conn_errors += 1;
    }

    pub fn merge(&mut self, other: &LoadRecorder) {
        self.sent += other.sent;
        self.received += other.received;
        self.timeouts += other.timeouts;
        self.errors += other.errors;
        self.conn_errors += other.conn_errors;
        self.truncated += other.truncated;
        self.bytes_in += other.bytes_in;
        for (slot, value) in self.rcodes.iter_mut().zip(other.rcodes) {
            *slot += value;
        }
        self.hist.add(&other.hist).expect("compatible histograms");
    }

    pub fn min_ms(&self) -> f64 {
        if self.hist.is_empty() {
            0.0
        } else {
            self.hist.min() as f64 / 1000.0
        }
    }

    pub fn max_ms(&self) -> f64 {
        self.hist.max() as f64 / 1000.0
    }

    pub fn mean_ms(&self) -> f64 {
        self.hist.mean() / 1000.0
    }

    pub fn percentile_ms(&self, quantile: f64) -> f64 {
        self.hist.value_at_quantile(quantile) as f64 / 1000.0
    }

    pub fn noerror(&self) -> u64 {
        self.rcodes[0]
    }

    /// Per-worker view for a snapshot. Each actor holds one socket, so
    /// `open_connections` is 1 while connected (0 if the connect failed) and
    /// `in_flight` is the live query-queue depth.
    pub fn snapshot_worker(
        &self,
        id: impl Into<String>,
        status: &str,
        elapsed_s: f64,
        in_flight: u64,
    ) -> WorkerStats {
        let rate = |count: u64| {
            if elapsed_s > 0.0 {
                count as f64 / elapsed_s
            } else {
                0.0
            }
        };
        let open_connections = u64::from(status != "failed");
        WorkerStats {
            id: id.into(),
            status: status.to_string(),
            qps: rate(self.sent),
            rps: rate(self.received),
            p50_ms: self.percentile_ms(0.50),
            p95_ms: self.percentile_ms(0.95),
            p99_ms: self.percentile_ms(0.99),
            error_rate: rate(self.errors + self.conn_errors),
            timeout_rate: rate(self.timeouts),
            open_connections,
            in_flight,
        }
    }

    /// Non-zero rcode counts keyed by name (unknown rcodes as `rcodeN`).
    pub fn rcode_breakdown(&self) -> std::collections::BTreeMap<String, u64> {
        const NAMES: [&str; 11] = [
            "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "YXDOMAIN",
            "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE",
        ];
        self.rcodes
            .iter()
            .enumerate()
            .filter(|&(_, &count)| count > 0)
            .map(|(code, &count)| {
                let name = NAMES
                    .get(code)
                    .map(|name| name.to_string())
                    .unwrap_or_else(|| format!("rcode{code}"));
                (name, count)
            })
            .collect()
    }
}
