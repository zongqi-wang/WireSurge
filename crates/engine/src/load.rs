use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::sync::watch;
use tokio::time::{MissedTickBehavior, sleep_until};
use tokio_util::sync::CancellationToken;
use wiresurge_core::{Result, WireSurgeError, serialize_json};
use wiresurge_corpus::{Corpus, SelectMode};
use wiresurge_dns::EdnsOption;
use wiresurge_dns::transport::do53::{TcpTransport, UdpTransport};
use wiresurge_dns::transport::doh::DohTransport;
use wiresurge_dns::transport::dot::DotTransport;
use wiresurge_dns::transport::{Connection, DnsRequest, Transport, TransportError};
use wiresurge_metrics::{AggregateStats, LoadRecorder, RunSnapshot, WorkerStats};
use wiresurge_transport::ConnectTarget;

/// Live-progress sampling cadence for `run_load_with_progress`.
pub struct ProgressConfig {
    pub interval: Duration,
}

/// Live slot one actor writes and the sampler reads. Stores the full recorder,
/// not reduced percentiles, so the sampler merges true histograms.
struct WorkerSlot {
    recorder: LoadRecorder,
    in_flight: u64,
    status: &'static str,
}

impl Default for WorkerSlot {
    fn default() -> Self {
        Self {
            recorder: LoadRecorder::default(),
            in_flight: 0,
            status: "starting",
        }
    }
}

/// Upper bound on how long a cancelled actor waits for in-flight queries to
/// finish before dropping them, so a signal interrupts promptly instead of
/// blocking up to the full per-request timeout on stalled queries.
const CANCEL_GRACE: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadProto {
    Do53Udp,
    Do53Tcp,
    Dot,
    Doh,
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
    /// EDNS0 OPT options attached to every query (all transports); empty for none.
    pub edns_options: Vec<EdnsOption>,
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
/// connections without a hot lock. Each corpus row's full wire message is
/// encoded once before the run clock starts (`wires`); `next` only clones the
/// matching prebuilt buffer (the transport patches in the transaction id at send
/// time), so the hot path never re-runs the DNS encoder per query.
struct WorkSource {
    seq: AtomicU64,
    count: Option<u64>,
    deadline: Option<Instant>,
    gate: Option<RateGate>,
    corpus: Arc<Corpus>,
    wires: Vec<Arc<[u8]>>,
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
        let row = self.corpus.select_index(index, self.seed, self.mode);
        Some(DnsRequest {
            wire: Arc::clone(&self.wires[row]),
        })
    }

    fn exhausted(&self) -> bool {
        let index = self.seq.load(Ordering::Relaxed);
        self.count.is_some_and(|n| index >= n) || self.deadline.is_some_and(|d| Instant::now() >= d)
    }
}

async fn run_actor<T: Transport>(
    worker_id: usize,
    target: ConnectTarget,
    work: Arc<WorkSource>,
    in_flight: usize,
    timeout: Duration,
    cancel: CancellationToken,
    slot: Option<(Arc<Mutex<WorkerSlot>>, Duration)>,
) -> (usize, LoadRecorder) {
    let mut recorder = LoadRecorder::default();
    let conn = match T::connect(target).await {
        Ok(conn) => conn,
        Err(_) => {
            recorder.on_conn_error();
            if let Some((slot, _)) = &slot {
                publish_slot(slot, &recorder, 0, "failed");
            }
            return (worker_id, recorder);
        }
    };
    let cap = conn.caps().max_in_flight.min(in_flight);
    let conn_ref = &conn;
    let mut inflight = FuturesUnordered::new();

    // No slot -> no interval -> no tick: zero cost on the measurement path.
    let mut ticker = slot.as_ref().map(|(_, interval)| {
        let mut ticker = tokio::time::interval(*interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        ticker
    });

    loop {
        // Stop feeding a dead connection. A closed transport (peer GOAWAY,
        // driver gone) makes exchange() fail synchronously; without this guard a
        // DoH actor would hot-spin, draining the shared WorkSource at CPU speed,
        // burning a core, and starving the healthy connections of the run's
        // count/QPS budget. There is no reconnect, so once closed this actor is
        // done after its in-flight queries settle.
        while inflight.len() < cap && !cancel.is_cancelled() && !conn_ref.is_closed() {
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
            if cancel.is_cancelled() || work.exhausted() || conn_ref.is_closed() {
                break;
            }
            continue;
        }

        tokio::select! {
            _ = cancel.cancelled() => {
                // Drain in-flight, but bounded by a short grace so a signal does
                // not wait up to the full per-request timeout on stalled queries.
                let grace = tokio::time::sleep(CANCEL_GRACE);
                tokio::pin!(grace);
                loop {
                    tokio::select! {
                        done = inflight.next() => match done {
                            Some((result, elapsed)) => record(&mut recorder, result, elapsed),
                            None => break,
                        },
                        _ = &mut grace => break,
                    }
                }
                break;
            }
            done = inflight.next() => {
                if let Some((result, elapsed)) = done {
                    record(&mut recorder, result, elapsed);
                }
            }
            _ = tick(ticker.as_mut()) => {
                if let Some((slot, _)) = &slot {
                    publish_slot(slot, &recorder, inflight.len() as u64, "running");
                }
            }
        }
    }

    conn.drain(CANCEL_GRACE.min(timeout)).await;
    if let Some((slot, _)) = &slot {
        publish_slot(slot, &recorder, 0, "done");
    }
    (worker_id, recorder)
}

/// Tick arm of the actor select. With no interval the future stays pending, so
/// the arm never fires.
async fn tick(ticker: Option<&mut tokio::time::Interval>) {
    match ticker {
        Some(ticker) => {
            ticker.tick().await;
        }
        None => std::future::pending().await,
    }
}

fn publish_slot(
    slot: &Arc<Mutex<WorkerSlot>>,
    recorder: &LoadRecorder,
    in_flight: u64,
    status: &'static str,
) {
    if let Ok(mut guard) = slot.lock() {
        guard.recorder = recorder.clone();
        guard.in_flight = in_flight;
        guard.status = status;
    }
}

async fn sample_progress(
    slots: Vec<Arc<Mutex<WorkerSlot>>>,
    sender: Arc<watch::Sender<RunSnapshot>>,
    start: Instant,
    interval: Duration,
    cancel: CancellationToken,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    ticker.tick().await; // first tick is immediate; skip the empty t=0 sample.
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = ticker.tick() => {
                let snapshot = collect_snapshot(&slots, start.elapsed().as_secs_f64(), false);
                if sender.send(snapshot).is_err() {
                    break;
                }
            }
        }
    }
}

fn collect_snapshot(
    slots: &[Arc<Mutex<WorkerSlot>>],
    elapsed_s: f64,
    final_sample: bool,
) -> RunSnapshot {
    let mut aggregate = LoadRecorder::default();
    let mut total_in_flight = 0u64;
    let mut workers = Vec::with_capacity(slots.len());
    for (index, slot) in slots.iter().enumerate() {
        let (recorder, in_flight, status) = match slot.lock() {
            Ok(guard) => (guard.recorder.clone(), guard.in_flight, guard.status),
            Err(_) => continue,
        };
        total_in_flight += in_flight;
        workers.push(recorder.snapshot_worker(
            format!("worker-{index}"),
            status,
            elapsed_s,
            in_flight,
        ));
        aggregate.merge(&recorder);
    }
    RunSnapshot {
        elapsed_s,
        final_sample,
        aggregate: AggregateStats::from_recorder(&aggregate, elapsed_s, total_in_flight),
        workers,
    }
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
    run_load_with_progress(config, cancel, None).await
}

/// Same as `run_load`, plus optional live progress. With `progress = None` no
/// slots, ticker, or sampler exist, so this path is identical to the batch run.
pub async fn run_load_with_progress(
    config: LoadConfig,
    cancel: CancellationToken,
    progress: Option<(ProgressConfig, watch::Sender<RunSnapshot>)>,
) -> Result<LoadStats> {
    config.validate()?;

    let edns_options = config.edns_options.as_slice();

    // Encode every corpus row's wire message once, before the run clock starts,
    // so the hot path only clones a prebuilt buffer and a large corpus cannot
    // delay the first send. A malformed name therefore surfaces here rather than
    // on first send.
    let wires = config
        .corpus
        .iter_rows()
        .map(|name| {
            wiresurge_dns::build_query(0, name, config.qtype, edns_options).map(Arc::<[u8]>::from)
        })
        .collect::<Result<Vec<_>>>()?;

    let start = Instant::now();
    let work = Arc::new(WorkSource {
        seq: AtomicU64::new(0),
        count: config.count,
        deadline: config.duration.map(|d| start + d),
        gate: config.qps_cap.map(|qps| RateGate { start, qps }),
        corpus: Arc::clone(&config.corpus),
        wires,
        seed: config.seed,
        mode: if config.randomize {
            SelectMode::RandomReplace
        } else {
            SelectMode::Sequential
        },
    });

    // Sender is shared (Arc) so the run loop can emit the final snapshot after
    // the sampler stops.
    let (slots, interval, sender, sampler) = match progress {
        Some((cfg, sender)) => {
            let sender = Arc::new(sender);
            let slots: Vec<Arc<Mutex<WorkerSlot>>> = (0..config.concurrency)
                .map(|_| Arc::new(Mutex::new(WorkerSlot::default())))
                .collect();
            let sampler = tokio::spawn(sample_progress(
                slots.clone(),
                Arc::clone(&sender),
                start,
                cfg.interval,
                cancel.clone(),
            ));
            (Some(slots), Some(cfg.interval), Some(sender), Some(sampler))
        }
        None => (None, None, None, None),
    };

    let mut actors = Vec::with_capacity(config.concurrency);
    for worker_id in 0..config.concurrency {
        let target = config.target.clone();
        let work = Arc::clone(&work);
        let cancel = cancel.clone();
        let in_flight = config.in_flight;
        let timeout = config.timeout;
        let slot = slots
            .as_ref()
            .map(|slots| (Arc::clone(&slots[worker_id]), interval.unwrap()));
        let handle = match config.proto {
            LoadProto::Do53Udp => tokio::spawn(run_actor::<UdpTransport>(
                worker_id, target, work, in_flight, timeout, cancel, slot,
            )),
            LoadProto::Do53Tcp => tokio::spawn(run_actor::<TcpTransport>(
                worker_id, target, work, in_flight, timeout, cancel, slot,
            )),
            LoadProto::Dot => tokio::spawn(run_actor::<DotTransport>(
                worker_id, target, work, in_flight, timeout, cancel, slot,
            )),
            LoadProto::Doh => tokio::spawn(run_actor::<DohTransport>(
                worker_id, target, work, in_flight, timeout, cancel, slot,
            )),
        };
        actors.push(handle);
    }

    let mut aggregate = LoadRecorder::default();
    let mut recorders = Vec::with_capacity(config.concurrency);
    for actor in actors {
        if let Ok((worker_id, recorder)) = actor.await {
            aggregate.merge(&recorder);
            recorders.push((worker_id, recorder));
        }
    }
    let duration_s = start.elapsed().as_secs_f64();
    let workers = recorders
        .into_iter()
        .map(|(worker_id, recorder)| {
            recorder.snapshot_worker(format!("worker-{worker_id}"), "done", duration_s, 0)
        })
        .collect::<Vec<_>>();

    // Final frame from the joined recorders, after the sampler stops.
    if let Some(sampler) = sampler {
        sampler.abort();
        let _ = sampler.await;
    }
    if let Some(sender) = sender {
        let _ = sender.send(RunSnapshot {
            elapsed_s: duration_s,
            final_sample: true,
            aggregate: AggregateStats::from_recorder(&aggregate, duration_s, 0),
            workers: workers.clone(),
        });
    }

    Ok(LoadStats {
        duration_s,
        recorder: aggregate,
        workers,
        cancelled: cancel.is_cancelled(),
    })
}

pub struct LoadStats {
    pub duration_s: f64,
    pub recorder: LoadRecorder,
    pub workers: Vec<WorkerStats>,
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

    /// Rate of NOERROR (rcode 0) responses. A response with any other rcode
    /// (REFUSED, SERVFAIL, ...) still counts toward `recv_qps`, so a server that
    /// cheaply rejects load reports a high `recv_qps` but a low `noerror_qps`;
    /// the latter is the only honest measure of resolved traffic.
    pub fn noerror_qps(&self) -> f64 {
        if self.duration_s > 0.0 {
            self.recorder.noerror() as f64 / self.duration_s
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
            "noerror_qps": self.noerror_qps(),
            "rcodes": self.recorder.rcode_breakdown(),
            "latency_ms": {
                "min_ms": self.recorder.min_ms(),
                "mean_ms": self.recorder.mean_ms(),
                "p50_ms": self.recorder.percentile_ms(0.50),
                "p95_ms": self.recorder.percentile_ms(0.95),
                "p99_ms": self.recorder.percentile_ms(0.99),
                "max_ms": self.recorder.max_ms(),
            },
            "workers": self.workers,
            "cancelled": self.cancelled,
        }))
    }
}
