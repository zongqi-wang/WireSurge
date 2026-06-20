use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::time::sleep_until;
use tokio_util::sync::CancellationToken;
use wiresurge_core::{Result, WireSurgeError, serialize_json};
use wiresurge_corpus::{Corpus, SelectMode};
use wiresurge_dns::transport::do53::{TcpTransport, UdpTransport};
use wiresurge_dns::transport::{Connection, DnsRequest, Transport, TransportError};
use wiresurge_metrics::LoadRecorder;
use wiresurge_transport::ConnectTarget;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadProto {
    Do53Udp,
    Do53Tcp,
}

#[derive(Clone)]
pub struct LoadConfig {
    pub proto: LoadProto,
    pub target: ConnectTarget,
    pub corpus: Arc<Corpus>,
    pub qtype: u16,
    pub concurrency: usize,
    pub in_flight: usize,
    pub timeout: Duration,
    pub qps_cap: Option<f64>,
    pub duration: Option<Duration>,
    pub count: Option<u64>,
    pub randomize: bool,
    pub seed: u64,
}

impl LoadConfig {
    pub fn validate(&self) -> Result<()> {
        if self.concurrency == 0 {
            return Err(WireSurgeError::new(
                "invalid_concurrency",
                "concurrency must be at least 1",
            )
            .at("concurrency"));
        }
        if self.in_flight == 0 {
            return Err(WireSurgeError::new(
                "invalid_in_flight",
                "in-flight depth must be at least 1",
            )
            .at("in_flight"));
        }
        if self.duration.is_none() && self.count.is_none() {
            return Err(WireSurgeError::new(
                "invalid_stop_condition",
                "a duration (-l) or a count must be set",
            ));
        }
        Ok(())
    }
}

struct RateGate {
    start: Instant,
    qps: f64,
}

impl RateGate {
    async fn wait(&self, index: u64, cancel: &CancellationToken) {
        let scheduled = self.start + Duration::from_secs_f64(index as f64 / self.qps);
        tokio::select! {
            _ = sleep_until(scheduled.into()) => {}
            _ = cancel.cancelled() => {}
        }
    }
}

/// Shared, lock-free source of work. Every actor pulls query indexes from one
/// atomic counter, so a process-wide QPS cap and total count apply across all
/// connections without a hot lock.
struct WorkSource {
    seq: AtomicU64,
    count: Option<u64>,
    deadline: Option<Instant>,
    gate: Option<RateGate>,
    corpus: Arc<Corpus>,
    qtype: u16,
    seed: u64,
    mode: SelectMode,
}

impl WorkSource {
    async fn next(&self, cancel: &CancellationToken) -> Option<DnsRequest> {
        let index = self.seq.fetch_add(1, Ordering::Relaxed);
        if self.count.is_some_and(|n| index >= n) {
            return None;
        }
        if self.deadline.is_some_and(|d| Instant::now() >= d) {
            return None;
        }
        if let Some(gate) = &self.gate {
            gate.wait(index, cancel).await;
            if cancel.is_cancelled() {
                return None;
            }
        }
        let name = self.corpus.select(index, self.seed, self.mode);
        let wire = wiresurge_dns::build_query(0, name, self.qtype, None).ok()?;
        Some(DnsRequest { wire })
    }

    fn exhausted(&self) -> bool {
        let index = self.seq.load(Ordering::Relaxed);
        self.count.is_some_and(|n| index >= n) || self.deadline.is_some_and(|d| Instant::now() >= d)
    }
}

async fn run_actor<T: Transport>(
    target: ConnectTarget,
    work: Arc<WorkSource>,
    in_flight: usize,
    timeout: Duration,
    cancel: CancellationToken,
) -> LoadRecorder {
    let mut recorder = LoadRecorder::default();
    let conn = match T::connect(target).await {
        Ok(conn) => conn,
        Err(_) => {
            recorder.on_conn_error();
            return recorder;
        }
    };
    let cap = conn.caps().max_in_flight.min(in_flight);
    let conn_ref = &conn;
    let mut inflight = FuturesUnordered::new();

    loop {
        while inflight.len() < cap && !cancel.is_cancelled() {
            match work.next(&cancel).await {
                Some(request) => {
                    recorder.on_sent();
                    let started = Instant::now();
                    inflight.push(async move {
                        let result = conn_ref.exchange(request, timeout).await;
                        (result, started.elapsed())
                    });
                }
                None => break,
            }
        }

        if inflight.is_empty() {
            if cancel.is_cancelled() || work.exhausted() {
                break;
            }
            continue;
        }

        tokio::select! {
            _ = cancel.cancelled() => {
                while let Some((result, elapsed)) = inflight.next().await {
                    record(&mut recorder, result, elapsed);
                }
                break;
            }
            done = inflight.next() => {
                if let Some((result, elapsed)) = done {
                    record(&mut recorder, result, elapsed);
                }
            }
        }
    }

    conn.drain(timeout).await;
    recorder
}

fn record(
    recorder: &mut LoadRecorder,
    result: std::result::Result<wiresurge_dns::transport::DnsResponse, TransportError>,
    elapsed: Duration,
) {
    match result {
        Ok(response) => recorder.on_response(
            response.rcode,
            response.truncated,
            response.bytes_in,
            elapsed.as_micros().min(u64::MAX as u128) as u64,
        ),
        Err(TransportError::Timeout) => recorder.on_timeout(),
        Err(TransportError::ConnectionClosed) => recorder.on_conn_error(),
        Err(_) => recorder.on_error(),
    }
}

pub async fn run_load(config: LoadConfig, cancel: CancellationToken) -> Result<LoadStats> {
    config.validate()?;
    let start = Instant::now();
    let work = Arc::new(WorkSource {
        seq: AtomicU64::new(0),
        count: config.count,
        deadline: config.duration.map(|d| start + d),
        gate: config.qps_cap.map(|qps| RateGate { start, qps }),
        corpus: Arc::clone(&config.corpus),
        qtype: config.qtype,
        seed: config.seed,
        mode: if config.randomize {
            SelectMode::RandomReplace
        } else {
            SelectMode::Sequential
        },
    });

    let mut actors = Vec::with_capacity(config.concurrency);
    for _ in 0..config.concurrency {
        let target = config.target.clone();
        let work = Arc::clone(&work);
        let cancel = cancel.clone();
        let in_flight = config.in_flight;
        let timeout = config.timeout;
        let handle = match config.proto {
            LoadProto::Do53Udp => tokio::spawn(run_actor::<UdpTransport>(
                target, work, in_flight, timeout, cancel,
            )),
            LoadProto::Do53Tcp => tokio::spawn(run_actor::<TcpTransport>(
                target, work, in_flight, timeout, cancel,
            )),
        };
        actors.push(handle);
    }

    let mut aggregate = LoadRecorder::default();
    for actor in actors {
        if let Ok(recorder) = actor.await {
            aggregate.merge(&recorder);
        }
    }

    Ok(LoadStats {
        duration_s: start.elapsed().as_secs_f64(),
        recorder: aggregate,
        cancelled: cancel.is_cancelled(),
    })
}

pub struct LoadStats {
    pub duration_s: f64,
    pub recorder: LoadRecorder,
    pub cancelled: bool,
}

impl LoadStats {
    pub fn recv_qps(&self) -> f64 {
        if self.duration_s > 0.0 {
            self.recorder.received as f64 / self.duration_s
        } else {
            0.0
        }
    }

    pub fn to_json(&self) -> Result<String> {
        serialize_json(&serde_json::json!({
            "duration_s": self.duration_s,
            "sent": self.recorder.sent,
            "received": self.recorder.received,
            "timeouts": self.recorder.timeouts,
            "errors": self.recorder.errors,
            "conn_errors": self.recorder.conn_errors,
            "truncated": self.recorder.truncated,
            "recv_qps": self.recv_qps(),
            "latency_ms": {
                "min_ms": self.recorder.min_ms(),
                "mean_ms": self.recorder.mean_ms(),
                "p50_ms": self.recorder.percentile_ms(0.50),
                "p95_ms": self.recorder.percentile_ms(0.95),
                "p99_ms": self.recorder.percentile_ms(0.99),
                "max_ms": self.recorder.max_ms(),
            },
            "cancelled": self.cancelled,
        }))
    }
}
