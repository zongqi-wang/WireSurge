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

/// Conservative per-run limits (ADR 0002/0005): the CLI cannot silently
/// launch an extreme resource plan.
const MAX_CONCURRENCY: usize = 1024;
const MAX_IN_FLIGHT: usize = 1024;
const MAX_QPS: f64 = 1_000_000.0;
const MAX_AGGREGATE_IN_FLIGHT: usize = 4096;
const MAX_IN_FLIGHT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_CORPUS_ROWS: usize = 10_000_000;
/// Worst-case DNS wire message length (u16 length prefix).
const MAX_WIRE_LEN: u64 = u16::MAX as u64;
/// Longest admissible wall-clock run (ADR 0002); also the bound that keeps
/// every rate-gate wait within a representable `Duration`.
pub const MAX_RUN_SECS: f64 = 7.0 * 24.0 * 3600.0;

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
        ValidatedLoadPlan::new(self.clone()).map(|_| ())
    }
}

/// An admitted load plan. Constructed only by [`ValidatedLoadPlan::new`],
/// which enforces the ADR 0002 numeric domains and the ADR 0005 aggregate
/// resource budget; the engine executes only admitted plans.
#[derive(Clone)]
pub struct ValidatedLoadPlan {
    config: LoadConfig,
}

impl ValidatedLoadPlan {
    pub fn new(config: LoadConfig) -> Result<Self> {
        if config.concurrency == 0 {
            return Err(WireSurgeError::new(
                "invalid_concurrency",
                "concurrency must be at least 1",
            )
            .at("concurrency")
            .rejected());
        }
        if config.concurrency > MAX_CONCURRENCY {
            return Err(WireSurgeError::new(
                "invalid_concurrency",
                format!("concurrency must be at most {MAX_CONCURRENCY}"),
            )
            .at("concurrency")
            .rejected());
        }
        if config.in_flight == 0 {
            return Err(WireSurgeError::new(
                "invalid_in_flight",
                "in-flight depth must be at least 1",
            )
            .at("in_flight")
            .rejected());
        }
        if config.in_flight > MAX_IN_FLIGHT {
            return Err(WireSurgeError::new(
                "invalid_in_flight",
                format!("in-flight depth must be at most {MAX_IN_FLIGHT}"),
            )
            .at("in_flight")
            .rejected());
        }
        if let Some(qps) = config.qps_cap
            && (qps <= 0.0 || !qps.is_finite())
        {
            return Err(WireSurgeError::new(
                "invalid_qps",
                "qps cap must be a positive, finite number",
            )
            .at("qps_cap")
            .rejected());
        }
        if config.qps_cap.is_some_and(|qps| qps > MAX_QPS) {
            return Err(WireSurgeError::new(
                "invalid_qps",
                format!("qps cap must be at most {MAX_QPS}"),
            )
            .at("qps_cap")
            .rejected());
        }
        if config
            .duration
            .is_some_and(|d| d.is_zero() || d.as_secs_f64() > MAX_RUN_SECS)
        {
            return Err(WireSurgeError::new(
                "invalid_duration",
                format!("duration must be at most {MAX_RUN_SECS} seconds"),
            )
            .at("duration")
            .rejected());
        }
        if config.duration.is_none() && config.count.is_none() {
            return Err(WireSurgeError::new(
                "invalid_stop_condition",
                "a duration (-l) or a count must be set",
            )
            .rejected());
        }
        if config.timeout < Duration::from_millis(1) || config.timeout > Duration::from_secs(60) {
            return Err(WireSurgeError::new(
                "invalid_timeout",
                "timeout must be between 1ms and 60s",
            )
            .at("timeout")
            .rejected());
        }
        let budget = ResourceBudget::of(&config);
        budget.check()?;
        Ok(Self { config })
    }

    pub fn config(&self) -> &LoadConfig {
        &self.config
    }

    pub fn resource_budget(&self) -> ResourceBudget {
        ResourceBudget::of(&self.config)
    }
}

/// The ADR 0005 resource envelope of an admitted plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceBudget {
    pub total_in_flight: usize,
    pub in_flight_bytes: u64,
    pub corpus_rows: usize,
}

impl ResourceBudget {
    fn of(config: &LoadConfig) -> Self {
        let total_in_flight = config.concurrency.saturating_mul(config.in_flight);
        Self {
            total_in_flight,
            in_flight_bytes: (total_in_flight as u64).saturating_mul(MAX_WIRE_LEN),
            corpus_rows: config.corpus.len(),
        }
    }

    fn check(&self) -> Result<()> {
        if self.total_in_flight > MAX_AGGREGATE_IN_FLIGHT {
            return Err(WireSurgeError::new(
                "invalid_aggregate_in_flight",
                format!("connections times in-flight must be at most {MAX_AGGREGATE_IN_FLIGHT}"),
            )
            .at("concurrency")
            .rejected());
        }
        if self.in_flight_bytes > MAX_IN_FLIGHT_BYTES {
            return Err(WireSurgeError::new(
                "invalid_in_flight_bytes",
                "estimated in-flight bytes exceed the resource budget",
            )
            .at("in_flight")
            .rejected());
        }
        if self.corpus_rows > MAX_CORPUS_ROWS {
            return Err(WireSurgeError::new(
                "corpus_too_large",
                format!("corpus must have at most {MAX_CORPUS_ROWS} rows"),
            )
            .at("file")
            .rejected());
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
/// encoded once before the run clock starts (`wires`); `next` clones the
/// matching prebuilt buffer into an owned `Vec<u8>` (a thread-local
/// malloc+memcpy, no shared atomic refcount), and the transport patches in the
/// transaction id at send time, so the hot path never re-runs the DNS encoder.
struct WorkSource {
    seq: AtomicU64,
    count: Option<u64>,
    deadline: Option<Instant>,
    gate: Option<RateGate>,
    corpus: Arc<Corpus>,
    wires: Vec<Vec<u8>>,
    seed: u64,
    mode: SelectMode,
}

impl WorkSource {
    async fn next(&self, cancel: &CancellationToken) -> Option<DnsRequest> {
        let index = self.seq.fetch_add(1, Ordering::Relaxed);
        if self.count.is_some_and(|n| index >= n) {
            return None;
        }
        if let Some(gate) = &self.gate {
            // ADR 0002: refuse before waiting — the scheduled slot must be
            // inside the deadline (or the MAX_RUN_SECS cap when there is no
            // deadline). Comparing slot seconds before the wait also keeps
            // every wait within a representable Duration, so the schedule
            // cannot panic on overflow.
            let slot_secs = index as f64 / gate.qps;
            let budget_secs = self.deadline.map_or(MAX_RUN_SECS, |d| {
                d.saturating_duration_since(gate.start).as_secs_f64()
            });
            if slot_secs >= budget_secs {
                return None;
            }
            gate.wait(index, cancel).await;
            if cancel.is_cancelled() {
                return None;
            }
        } else if self.deadline.is_some_and(|d| Instant::now() >= d) {
            return None;
        }
        let row = self.corpus.select_index(index, self.seed, self.mode);
        Some(DnsRequest {
            wire: self.wires[row].clone(),
        })
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
    let conn = tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            recorder.on_conn_error();
            if let Some((slot, _)) = &slot {
                publish_slot(slot, &recorder, 0, "failed");
            }
            return (worker_id, recorder);
        }
        result = tokio::time::timeout(timeout, T::connect(target)) => match result {
            Ok(Ok(conn)) => conn,
            Ok(Err(_)) | Err(_) => {
                recorder.on_conn_error();
                if let Some((slot, _)) = &slot {
                    publish_slot(slot, &recorder, 0, "failed");
                }
                return (worker_id, recorder);
            }
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

    // `next()` returning `None` is permanent — the count is reached, the
    // scheduled slot is at/past the budget, or the deadline passed, all
    // monotonic — so the actor stops asking and cannot hot-spin (ADR 0002).
    let mut no_more_work = false;

    loop {
        // Stop feeding a dead connection. A closed transport (peer GOAWAY,
        // driver gone) makes exchange() fail synchronously; without this guard a
        // DoH actor would hot-spin, draining the shared WorkSource at CPU speed,
        // burning a core, and starving the healthy connections of the run's
        // count/QPS budget. There is no reconnect, so once closed this actor is
        // done after its in-flight queries settle.
        while inflight.len() < cap
            && !cancel.is_cancelled()
            && !conn_ref.is_closed()
            && !no_more_work
        {
            match work.next(&cancel).await {
                Some(request) => {
                    recorder.on_sent();
                    let started = Instant::now();
                    inflight.push(async move {
                        let result = conn_ref.exchange(request, timeout).await;
                        (result, started.elapsed())
                    });
                }
                None => {
                    no_more_work = true;
                    break;
                }
            }
        }

        if inflight.is_empty() {
            if no_more_work || cancel.is_cancelled() || conn_ref.is_closed() {
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

fn merge_actor_result(
    aggregate: &mut LoadRecorder,
    recorders: &mut Vec<(usize, LoadRecorder)>,
    index: usize,
    result: std::result::Result<(usize, LoadRecorder), tokio::task::JoinError>,
) {
    let (worker_id, recorder) = match result {
        Ok((worker_id, recorder)) => (worker_id, recorder),
        Err(_) => {
            let mut recorder = LoadRecorder::default();
            recorder.on_conn_error();
            (index, recorder)
        }
    };
    aggregate.merge(&recorder);
    recorders.push((worker_id, recorder));
}

pub async fn run_load(plan: ValidatedLoadPlan, cancel: CancellationToken) -> Result<LoadStats> {
    run_load_with_progress(plan, cancel, None).await
}

/// Same as `run_load`, plus optional live progress. With `progress = None` no
/// slots, ticker, or sampler exist, so this path is identical to the batch run.
pub async fn run_load_with_progress(
    plan: ValidatedLoadPlan,
    cancel: CancellationToken,
    progress: Option<(ProgressConfig, watch::Sender<RunSnapshot>)>,
) -> Result<LoadStats> {
    let config = plan.config();

    let edns_options = config.edns_options.as_slice();

    // Encode every corpus row's wire message once, before the run clock starts,
    // so the hot path only clones a prebuilt buffer and a large corpus cannot
    // delay the first send. A malformed name therefore surfaces here rather than
    // on first send.
    let wires = config
        .corpus
        .iter_rows()
        .map(|name| wiresurge_dns::build_query(0, name, config.qtype, edns_options))
        .collect::<Result<Vec<Vec<u8>>>>()?;

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
    for (index, actor) in actors.into_iter().enumerate() {
        merge_actor_result(&mut aggregate, &mut recorders, index, actor.await);
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

#[cfg(test)]
mod tests {
    use super::*;
    use wiresurge_corpus::Corpus;

    fn base_config() -> LoadConfig {
        LoadConfig {
            proto: LoadProto::Do53Udp,
            target: ConnectTarget::new("127.0.0.1:53".parse().unwrap()),
            corpus: Corpus::single("example.com"),
            qtype: 1,
            concurrency: 1,
            in_flight: 1,
            timeout: Duration::from_millis(100),
            qps_cap: None,
            duration: None,
            count: Some(1),
            randomize: false,
            seed: 0,
            edns_options: Vec::new(),
        }
    }

    #[test]
    fn validate_rejects_bad_qps_cap() {
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY, MAX_QPS + 1.0] {
            let mut config = base_config();
            config.qps_cap = Some(bad);
            assert_eq!(config.validate().unwrap_err().code, "invalid_qps", "{bad}");
        }
        let mut good = base_config();
        good.qps_cap = Some(100.0);
        assert!(good.validate().is_ok());
        assert!(base_config().validate().is_ok());
    }

    #[test]
    fn validate_rejects_oversized_duration() {
        let mut config = base_config();
        config.duration = Some(Duration::from_secs_f64(MAX_RUN_SECS + 1.0));
        let error = config.validate().unwrap_err();
        assert_eq!(error.code, "invalid_duration");
        assert!(error.rejected, "admission errors must map to exit 2");

        let mut zero = base_config();
        zero.duration = Some(Duration::ZERO);
        assert_eq!(zero.validate().unwrap_err().code, "invalid_duration");
    }

    #[test]
    fn validate_rejects_out_of_range_timeout() {
        let mut config = base_config();
        config.timeout = Duration::ZERO;
        assert_eq!(config.validate().unwrap_err().code, "invalid_timeout");
        config.timeout = Duration::from_secs(61);
        assert_eq!(config.validate().unwrap_err().code, "invalid_timeout");
    }

    #[test]
    fn validate_rejects_aggregate_in_flight_over_budget() {
        let mut ok = base_config();
        ok.concurrency = 64;
        ok.in_flight = 64; // 4096 == MAX_AGGREGATE_IN_FLIGHT
        assert!(ok.validate().is_ok());

        let mut over = base_config();
        over.concurrency = 65;
        over.in_flight = 64; // 4160 > 4096
        assert_eq!(
            over.validate().unwrap_err().code,
            "invalid_aggregate_in_flight"
        );
    }

    #[test]
    fn count_zero_is_an_admissible_empty_run() {
        let mut config = base_config();
        config.count = Some(0);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn resource_budget_reports_the_envelope() {
        let mut config = base_config();
        config.concurrency = 8;
        config.in_flight = 16;
        let plan = ValidatedLoadPlan::new(config).unwrap();
        let budget = plan.resource_budget();
        assert_eq!(budget.total_in_flight, 128);
        assert_eq!(budget.corpus_rows, 1);
    }

    #[tokio::test]
    async fn work_past_the_seven_day_budget_is_refused_without_a_deadline() {
        // A count-only run with a slow rate cap must refuse work whose
        // scheduled slot is at/past MAX_RUN_SECS (ADR 0002), so the actors
        // terminate instead of spinning on `None` (the `exhausted()` hot-spin
        // regression).
        let start = Instant::now();
        let source = WorkSource {
            seq: AtomicU64::new(604_800), // slot at start+7d == MAX_RUN_SECS
            count: None,
            deadline: None,
            gate: Some(RateGate { start, qps: 1.0 }),
            corpus: Corpus::single("example.com"),
            wires: vec![wiresurge_dns::build_query(0, "example.com", 1, &[]).unwrap()],
            seed: 0,
            mode: SelectMode::Sequential,
        };
        let cancel = CancellationToken::new();
        let result = tokio::select! {
            r = source.next(&cancel) => r,
            _ = tokio::time::sleep(Duration::from_millis(50)) => {
                panic!("next() waited for a slot past the 7-day budget");
            }
        };
        assert!(
            result.is_none(),
            "work scheduled past the 7-day budget must be refused"
        );
    }

    #[test]
    fn validate_rejects_out_of_range_concurrency_and_in_flight() {
        let mut too_many = base_config();
        too_many.concurrency = MAX_CONCURRENCY + 1;
        assert_eq!(too_many.validate().unwrap_err().code, "invalid_concurrency");
        let mut too_deep = base_config();
        too_deep.in_flight = MAX_IN_FLIGHT + 1;
        assert_eq!(too_deep.validate().unwrap_err().code, "invalid_in_flight");
    }

    #[test]
    fn merge_actor_result_records_join_error_as_conn_error() {
        let mut aggregate = LoadRecorder::default();
        let mut recorders = Vec::new();
        let join_err = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async { tokio::spawn(async { panic!("boom") }).await });
        assert!(join_err.is_err());
        merge_actor_result(
            &mut aggregate,
            &mut recorders,
            7,
            join_err.map(|_| unreachable!()),
        );
        assert_eq!(aggregate.conn_errors, 1);
        assert_eq!(recorders.len(), 1);
        assert_eq!(recorders[0].0, 7, "synthetic worker keyed by spawn index");

        let mut recorder = LoadRecorder::default();
        recorder.on_sent();
        merge_actor_result(&mut aggregate, &mut recorders, 8, Ok((3, recorder)));
        assert_eq!(aggregate.sent, 1);
        assert_eq!(recorders[1].0, 3, "Ok result keeps its own worker id");
    }

    #[tokio::test]
    async fn work_scheduled_past_the_deadline_is_never_admitted() {
        // ADR 0002: admission compares the query's *scheduled slot*
        // (start + n/qps) with the deadline BEFORE the rate-gate wait; a query
        // whose slot is at/past the deadline is refused without waiting. The
        // buggy implementation checks the wall clock before the wait and then
        // sleeps past the deadline, admitting the query.
        let start = Instant::now();
        let deadline = start + Duration::from_millis(400);
        let source = WorkSource {
            seq: AtomicU64::new(3),
            count: None,
            deadline: Some(deadline),
            gate: Some(RateGate { start, qps: 10.0 }),
            corpus: Corpus::single("example.com"),
            wires: vec![wiresurge_dns::build_query(0, "example.com", 1, &[]).unwrap()],
            seed: 0,
            mode: SelectMode::Sequential,
        };
        let cancel = CancellationToken::new();

        assert!(source.next(&cancel).await.is_some());

        // The next fetch happens at ~start+300ms, before the deadline passes,
        // for slot 4 at start+400ms == deadline. The 150ms sleep is only a
        // hang guard: it fires after the buggy slot at 400ms.
        let started = Instant::now();
        let result = tokio::select! {
            r = source.next(&cancel) => r,
            _ = tokio::time::sleep(Duration::from_millis(150)) => {
                panic!("next() waited for a slot scheduled past the deadline");
            }
        };
        assert!(
            result.is_none(),
            "work scheduled at/past the deadline was admitted (returned after {:?})",
            started.elapsed(),
        );
    }
}
