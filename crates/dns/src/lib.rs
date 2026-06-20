use domain::base::iana::OptionCode;
use domain::base::opt::UnknownOptData;
use domain::base::{Message, MessageBuilder, Name, Rtype};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use wiresurge_core::{Result, WireSurgeError, json_object, json_string};

const DNS_HEADER_LEN: usize = 12;
const MAX_DNS_MESSAGE_LEN: usize = u16::MAX as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsTransport {
    Udp,
    Tcp,
}

impl DnsTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
}

impl FromStr for DnsTransport {
    type Err = WireSurgeError;

    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "udp" => Ok(Self::Udp),
            "tcp" => Ok(Self::Tcp),
            _ => Err(WireSurgeError::new(
                "invalid_dns_transport",
                "DNS transport must be udp or tcp",
            )
            .at("protocol")),
        }
    }
}

/// A single EDNS0 OPT option: a caller-supplied option code plus its raw payload
/// bytes. The code is configurable (not hardcoded) so callers can emit real
/// options such as the Global Resolver DoT auth token (code 65184 / 0xFEA0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdnsOption {
    pub code: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DnsRunConfig {
    pub server: String,
    pub port: u16,
    pub transport: DnsTransport,
    pub qname: String,
    pub qtype: u16,
    pub count: u64,
    pub concurrency: usize,
    pub timeout: Duration,
    pub qps: Option<f64>,
    pub edns_option: Option<EdnsOption>,
}

impl DnsRunConfig {
    pub fn validate(&self) -> Result<()> {
        if self.server.trim().is_empty() {
            return Err(
                WireSurgeError::new("invalid_dns_server", "DNS server is required").at("server"),
            );
        }
        if self.count == 0 {
            return Err(WireSurgeError::new(
                "invalid_dns_count",
                "count must be greater than zero",
            )
            .at("count"));
        }
        if self.concurrency == 0 || self.concurrency > 4096 {
            return Err(WireSurgeError::new(
                "invalid_dns_concurrency",
                "concurrency must be between 1 and 4096",
            )
            .at("concurrency"));
        }
        if self.timeout.is_zero() {
            return Err(WireSurgeError::new(
                "invalid_dns_timeout",
                "timeout must be greater than zero",
            )
            .at("timeout"));
        }
        if let Some(qps) = self.qps
            && (!qps.is_finite() || qps <= 0.0)
        {
            return Err(WireSurgeError::new(
                "invalid_dns_qps",
                "qps must be a finite number greater than zero",
            )
            .at("qps"));
        }
        build_query(0, &self.qname, self.qtype, self.edns_option.as_ref())?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct DnsRunStats {
    pub target: String,
    pub transport: String,
    pub qname: String,
    pub qtype: u16,
    pub requested: u64,
    pub sent: u64,
    pub received: u64,
    pub timeouts: u64,
    pub errors: u64,
    pub mismatched: u64,
    pub truncated: u64,
    pub duration_ms: f64,
    pub min_latency_ms: f64,
    pub max_latency_ms: f64,
    pub average_latency_ms: f64,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub rcode_counts: [u64; 17],
    pub cancelled: bool,
    pub last_error: Option<String>,
}

impl DnsRunStats {
    pub fn to_json(&self) -> String {
        let rcode_counts = json_object(&[
            ("NOERROR", self.rcode_counts[0].to_string()),
            ("FORMERR", self.rcode_counts[1].to_string()),
            ("SERVFAIL", self.rcode_counts[2].to_string()),
            ("NXDOMAIN", self.rcode_counts[3].to_string()),
            ("NOTIMP", self.rcode_counts[4].to_string()),
            ("REFUSED", self.rcode_counts[5].to_string()),
            (
                "OTHER",
                self.rcode_counts[6..].iter().sum::<u64>().to_string(),
            ),
        ]);
        json_object(&[
            ("target", json_string(&self.target)),
            ("protocol", json_string(&self.transport)),
            ("qname", json_string(&self.qname)),
            ("qtype", self.qtype.to_string()),
            ("requested", self.requested.to_string()),
            ("sent", self.sent.to_string()),
            ("received", self.received.to_string()),
            ("timeouts", self.timeouts.to_string()),
            ("errors", self.errors.to_string()),
            ("mismatched", self.mismatched.to_string()),
            ("truncated", self.truncated.to_string()),
            ("duration_ms", format_float(self.duration_ms)),
            (
                "queries_per_second",
                format_float(if self.duration_ms > 0.0 {
                    self.received as f64 * 1000.0 / self.duration_ms
                } else {
                    0.0
                }),
            ),
            (
                "latency_ms",
                json_object(&[
                    ("min", format_float(self.min_latency_ms)),
                    ("max", format_float(self.max_latency_ms)),
                    ("average", format_float(self.average_latency_ms)),
                    ("p50", format_float(self.p50_latency_ms)),
                    ("p95", format_float(self.p95_latency_ms)),
                    ("p99", format_float(self.p99_latency_ms)),
                ]),
            ),
            ("rcode", rcode_counts),
            ("cancelled", self.cancelled.to_string()),
            (
                "last_error",
                self.last_error
                    .as_ref()
                    .map(|error| json_string(error))
                    .unwrap_or_else(|| "null".to_string()),
            ),
        ])
    }

    pub fn to_text(&self) -> String {
        format!(
            "DNS {} {}:{}\nquery: {} type {}\nrequested: {}  sent: {}  received: {}\ntimeouts: {}  errors: {}  mismatched: {}  truncated: {}\nlatency ms: min {:.3}  avg {:.3}  p95 {:.3}  p99 {:.3}  max {:.3}\nthroughput: {:.3} responses/s{}",
            self.transport,
            self.target.split(':').next().unwrap_or(&self.target),
            self.target.rsplit(':').next().unwrap_or("53"),
            self.qname,
            self.qtype,
            self.requested,
            self.sent,
            self.received,
            self.timeouts,
            self.errors,
            self.mismatched,
            self.truncated,
            self.min_latency_ms,
            self.average_latency_ms,
            self.p95_latency_ms,
            self.p99_latency_ms,
            self.max_latency_ms,
            if self.duration_ms > 0.0 {
                self.received as f64 * 1000.0 / self.duration_ms
            } else {
                0.0
            },
            if self.cancelled {
                "\nstatus: cancelled"
            } else {
                ""
            },
        )
    }
}

#[derive(Debug, Clone, Default)]
struct WorkerStats {
    sent: u64,
    received: u64,
    timeouts: u64,
    errors: u64,
    mismatched: u64,
    truncated: u64,
    rcode_counts: [u64; 17],
    latency: LatencyHistogram,
    last_error: Option<String>,
}

impl WorkerStats {
    fn observe_response(&mut self, response: &[u8], expected_id: u16, elapsed: Duration) {
        match parse_response_header(response, expected_id) {
            Ok(header) => {
                self.received += 1;
                self.truncated += u64::from(header.truncated);
                let bucket = usize::from(header.rcode.min(16));
                self.rcode_counts[bucket] += 1;
                self.latency.record(elapsed);
            }
            Err(error) if error.code == "dns_id_mismatch" => {
                self.mismatched += 1;
                self.last_error = Some(error.message);
            }
            Err(error) => {
                self.errors += 1;
                self.last_error = Some(error.message);
            }
        }
    }

    fn merge(&mut self, other: WorkerStats) {
        self.sent += other.sent;
        self.received += other.received;
        self.timeouts += other.timeouts;
        self.errors += other.errors;
        self.mismatched += other.mismatched;
        self.truncated += other.truncated;
        for (target, source) in self.rcode_counts.iter_mut().zip(other.rcode_counts) {
            *target += source;
        }
        self.latency.merge(&other.latency);
        if other.last_error.is_some() {
            self.last_error = other.last_error;
        }
    }
}

#[derive(Debug, Clone)]
struct LatencyHistogram {
    buckets: [u64; 64],
    count: u64,
    total_micros: u128,
    min_micros: u64,
    max_micros: u64,
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self {
            buckets: [0; 64],
            count: 0,
            total_micros: 0,
            min_micros: u64::MAX,
            max_micros: 0,
        }
    }
}

impl LatencyHistogram {
    fn record(&mut self, duration: Duration) {
        let micros = duration.as_micros().min(u64::MAX as u128) as u64;
        let bucket = latency_bucket(micros);
        self.buckets[bucket] += 1;
        self.count += 1;
        self.total_micros += micros as u128;
        self.min_micros = self.min_micros.min(micros);
        self.max_micros = self.max_micros.max(micros);
    }

    fn merge(&mut self, other: &Self) {
        for (target, source) in self.buckets.iter_mut().zip(other.buckets) {
            *target += source;
        }
        self.count += other.count;
        self.total_micros += other.total_micros;
        if other.count > 0 {
            self.min_micros = self.min_micros.min(other.min_micros);
            self.max_micros = self.max_micros.max(other.max_micros);
        }
    }

    fn min_ms(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.min_micros as f64 / 1000.0
        }
    }

    fn max_ms(&self) -> f64 {
        self.max_micros as f64 / 1000.0
    }

    fn average_ms(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.total_micros as f64 / self.count as f64 / 1000.0
        }
    }

    fn percentile_ms(&self, percentile: f64) -> f64 {
        if self.count == 0 {
            return 0.0;
        }
        let rank = (self.count as f64 * percentile).ceil().max(1.0) as u64;
        let mut seen = 0;
        for (index, count) in self.buckets.iter().enumerate() {
            seen += count;
            if seen >= rank {
                let upper_bound = if index == 63 {
                    u64::MAX
                } else {
                    1_u64 << index
                };
                return upper_bound as f64 / 1000.0;
            }
        }
        self.max_ms()
    }
}

fn latency_bucket(micros: u64) -> usize {
    if micros <= 1 {
        0
    } else {
        (u64::BITS - (micros - 1).leading_zeros()) as usize
    }
    .min(63)
}

#[derive(Debug, Clone, Copy)]
struct ResponseHeader {
    rcode: u16,
    truncated: bool,
}

pub fn run_dns(config: DnsRunConfig, cancellation: Arc<AtomicBool>) -> Result<DnsRunStats> {
    config.validate()?;
    let target = resolve_target(&config.server, config.port)?;
    let query_template = Arc::new(build_query(
        0,
        &config.qname,
        config.qtype,
        config.edns_option.as_ref(),
    )?);
    let config = Arc::new(config);
    let next_query = Arc::new(AtomicU64::new(0));
    let started = Instant::now();
    let mut workers = Vec::with_capacity(config.concurrency);

    for worker_id in 0..config.concurrency {
        let worker_config = Arc::clone(&config);
        let worker_query = Arc::clone(&query_template);
        let worker_counter = Arc::clone(&next_query);
        let worker_cancellation = Arc::clone(&cancellation);
        workers.push(thread::spawn(move || match worker_config.transport {
            DnsTransport::Udp => run_udp_worker(
                worker_id,
                target,
                worker_config,
                worker_query,
                worker_counter,
                worker_cancellation,
                started,
            ),
            DnsTransport::Tcp => run_tcp_worker(
                worker_id,
                target,
                worker_config,
                worker_query,
                worker_counter,
                worker_cancellation,
                started,
            ),
        }));
    }

    let mut aggregate = WorkerStats::default();
    for worker in workers {
        match worker.join() {
            Ok(stats) => aggregate.merge(stats),
            Err(_) => {
                aggregate.errors += 1;
                aggregate.last_error = Some("DNS worker panicked".to_string());
            }
        }
    }

    let duration_ms = started.elapsed().as_secs_f64() * 1000.0;
    Ok(DnsRunStats {
        target: target.to_string(),
        transport: config.transport.as_str().to_string(),
        qname: config.qname.clone(),
        qtype: config.qtype,
        requested: config.count,
        sent: aggregate.sent,
        received: aggregate.received,
        timeouts: aggregate.timeouts,
        errors: aggregate.errors,
        mismatched: aggregate.mismatched,
        truncated: aggregate.truncated,
        duration_ms,
        min_latency_ms: aggregate.latency.min_ms(),
        max_latency_ms: aggregate.latency.max_ms(),
        average_latency_ms: aggregate.latency.average_ms(),
        p50_latency_ms: aggregate.latency.percentile_ms(0.50),
        p95_latency_ms: aggregate.latency.percentile_ms(0.95),
        p99_latency_ms: aggregate.latency.percentile_ms(0.99),
        rcode_counts: aggregate.rcode_counts,
        cancelled: cancellation.load(Ordering::Acquire),
        last_error: aggregate.last_error,
    })
}

fn run_udp_worker(
    worker_id: usize,
    target: SocketAddr,
    config: Arc<DnsRunConfig>,
    query_template: Arc<Vec<u8>>,
    next_query: Arc<AtomicU64>,
    cancellation: Arc<AtomicBool>,
    run_started: Instant,
) -> WorkerStats {
    let mut stats = WorkerStats::default();
    let bind_address = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = match UdpSocket::bind(bind_address) {
        Ok(socket) => socket,
        Err(error) => {
            stats.errors += 1;
            stats.last_error = Some(format!("failed to bind UDP socket: {error}"));
            return stats;
        }
    };
    if let Err(error) = socket.connect(target) {
        stats.errors += 1;
        stats.last_error = Some(format!("failed to connect UDP socket: {error}"));
        return stats;
    }
    if let Err(error) = socket.set_read_timeout(Some(config.timeout)) {
        stats.errors += 1;
        stats.last_error = Some(format!("failed to set UDP read timeout: {error}"));
        return stats;
    }
    if let Err(error) = socket.set_write_timeout(Some(config.timeout)) {
        stats.errors += 1;
        stats.last_error = Some(format!("failed to set UDP write timeout: {error}"));
        return stats;
    }

    let mut query = (*query_template).clone();
    let mut response = vec![0_u8; MAX_DNS_MESSAGE_LEN];
    loop {
        let query_index = next_query.fetch_add(1, Ordering::Relaxed);
        if query_index >= config.count || cancellation.load(Ordering::Acquire) {
            break;
        }
        if !wait_for_rate_slot(query_index, config.qps, run_started, &cancellation) {
            break;
        }
        let transaction_id = transaction_id(worker_id, query_index);
        query[0..2].copy_from_slice(&transaction_id.to_be_bytes());
        stats.sent += 1;
        let attempt_started = Instant::now();
        let outcome = socket.send(&query).and_then(|_| socket.recv(&mut response));
        match outcome {
            Ok(received) => {
                stats.observe_response(
                    &response[..received],
                    transaction_id,
                    attempt_started.elapsed(),
                );
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                stats.timeouts += 1;
            }
            Err(error) => {
                stats.errors += 1;
                stats.last_error = Some(error.to_string());
            }
        }
    }
    stats
}

fn run_tcp_worker(
    worker_id: usize,
    target: SocketAddr,
    config: Arc<DnsRunConfig>,
    query_template: Arc<Vec<u8>>,
    next_query: Arc<AtomicU64>,
    cancellation: Arc<AtomicBool>,
    run_started: Instant,
) -> WorkerStats {
    let mut stats = WorkerStats::default();
    let mut stream = None;
    let mut query = (*query_template).clone();
    loop {
        let query_index = next_query.fetch_add(1, Ordering::Relaxed);
        if query_index >= config.count || cancellation.load(Ordering::Acquire) {
            break;
        }
        if !wait_for_rate_slot(query_index, config.qps, run_started, &cancellation) {
            break;
        }
        let transaction_id = transaction_id(worker_id, query_index);
        query[0..2].copy_from_slice(&transaction_id.to_be_bytes());
        stats.sent += 1;
        let attempt_started = Instant::now();
        match tcp_exchange(&mut stream, target, &query, config.timeout) {
            Ok(response) => {
                stats.observe_response(&response, transaction_id, attempt_started.elapsed());
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                stream = None;
                stats.timeouts += 1;
            }
            Err(error) => {
                stream = None;
                stats.errors += 1;
                stats.last_error = Some(error.to_string());
            }
        }
    }
    if let Some(stream) = stream {
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
    stats
}

fn tcp_exchange(
    stream: &mut Option<TcpStream>,
    target: SocketAddr,
    query: &[u8],
    operation_timeout: Duration,
) -> std::io::Result<Vec<u8>> {
    if stream.is_none() {
        let connected = TcpStream::connect_timeout(&target, operation_timeout)?;
        connected.set_nodelay(true)?;
        connected.set_read_timeout(Some(operation_timeout))?;
        connected.set_write_timeout(Some(operation_timeout))?;
        *stream = Some(connected);
    }
    let stream = stream.as_mut().expect("TCP stream was initialized");
    let frame = tcp_frame(query)?;
    stream.write_all(&frame)?;

    let mut response_len = [0_u8; 2];
    stream.read_exact(&mut response_len)?;
    let response_len = u16::from_be_bytes(response_len) as usize;
    if response_len < DNS_HEADER_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS TCP response is shorter than the header",
        ));
    }
    let mut response = vec![0_u8; response_len];
    stream.read_exact(&mut response)?;
    Ok(response)
}

fn tcp_frame(query: &[u8]) -> std::io::Result<Vec<u8>> {
    let query_len = u16::try_from(query.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "DNS query exceeds TCP length field",
        )
    })?;
    let mut frame = Vec::with_capacity(query.len() + 2);
    frame.extend_from_slice(&query_len.to_be_bytes());
    frame.extend_from_slice(query);
    Ok(frame)
}

fn wait_for_rate_slot(
    query_index: u64,
    qps: Option<f64>,
    run_started: Instant,
    cancellation: &AtomicBool,
) -> bool {
    let Some(qps) = qps else {
        return !cancellation.load(Ordering::Acquire);
    };
    let scheduled = run_started + Duration::from_secs_f64(query_index as f64 / qps);
    while scheduled > Instant::now() {
        if cancellation.load(Ordering::Acquire) {
            return false;
        }
        let remaining = scheduled.saturating_duration_since(Instant::now());
        thread::sleep(remaining.min(Duration::from_millis(10)));
    }
    !cancellation.load(Ordering::Acquire)
}

fn resolve_target(server: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(socket) = server.parse::<SocketAddr>() {
        return Ok(socket);
    }
    if let Ok(ip) = server.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    (server, port)
        .to_socket_addrs()
        .map_err(|error| {
            WireSurgeError::new("dns_target_resolution_failed", error.to_string())
                .at("server")
                .retryable(true)
        })?
        .next()
        .ok_or_else(|| {
            WireSurgeError::new(
                "dns_target_resolution_failed",
                "DNS target resolved to no addresses",
            )
            .at("server")
        })
}

fn transaction_id(worker_id: usize, query_index: u64) -> u16 {
    let mut value = query_index ^ ((worker_id as u64) << 32) ^ 0x9e37_79b9_7f4a_7c15;
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^= value >> 31;
    value as u16
}

fn parse_response_header(response: &[u8], expected_id: u16) -> Result<ResponseHeader> {
    let response = Message::from_octets(response).map_err(|error| {
        WireSurgeError::new("invalid_dns_response", error.to_string()).retryable(false)
    })?;
    if response.header().id() != expected_id {
        return Err(WireSurgeError::new(
            "dns_id_mismatch",
            format!(
                "expected transaction ID {expected_id}, received {}",
                response.header().id()
            ),
        ));
    }
    if !response.header().qr() {
        return Err(WireSurgeError::new(
            "invalid_dns_response",
            "DNS packet does not have the response bit set",
        ));
    }
    Ok(ResponseHeader {
        rcode: response.opt_rcode().to_int(),
        truncated: response.header().tc(),
    })
}

pub fn build_query(
    transaction_id: u16,
    qname: &str,
    qtype: u16,
    edns_option: Option<&EdnsOption>,
) -> Result<Vec<u8>> {
    let absolute_name = if qname.ends_with('.') {
        qname.to_string()
    } else {
        format!("{qname}.")
    };
    let name = absolute_name
        .parse::<Name<Vec<u8>>>()
        .map_err(|error| WireSurgeError::new("invalid_dns_name", error.to_string()).at("qname"))?;
    let mut message = MessageBuilder::new_vec();
    message.header_mut().set_id(transaction_id);
    message.header_mut().set_rd(true);
    let mut question = message.question();
    question
        .push((name, Rtype::from_int(qtype)))
        .map_err(|error| WireSurgeError::new("dns_encode_failed", error.to_string()).at("qname"))?;

    let packet = if let Some(edns) = edns_option {
        let option =
            UnknownOptData::new(OptionCode::from_int(edns.code), &edns.payload).map_err(|_| {
                WireSurgeError::new("invalid_edns_payload", "EDNS payload exceeds 65535 bytes")
                    .at("edns_payload")
            })?;
        let mut additional = question.additional();
        additional
            .opt(|opt| {
                opt.set_udp_payload_size(1232);
                opt.push(&option)
            })
            .map_err(|error| {
                WireSurgeError::new("dns_encode_failed", error.to_string()).at("edns_payload")
            })?;
        additional.finish()
    } else {
        question.finish()
    };
    if packet.len() > MAX_DNS_MESSAGE_LEN {
        return Err(WireSurgeError::new(
            "dns_message_too_large",
            "DNS query exceeds the 65535-byte message limit",
        ));
    }
    Ok(packet)
}

pub fn build_query_with_optional_edns0(
    qname: &str,
    qtype: u16,
    edns_option: Option<&EdnsOption>,
) -> Result<Vec<u8>> {
    build_query(0x1234, qname, qtype, edns_option)
}

pub fn parse_qtype(value: &str) -> Result<u16> {
    let qtype = match value.to_ascii_uppercase().as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "ANY" => 255,
        _ => value.parse::<u16>().map_err(|_| {
            WireSurgeError::new(
                "invalid_dns_qtype",
                "qtype must be A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, SRV, ANY, or a number",
            )
            .at("qtype")
        })?,
    };
    Ok(qtype)
}

pub fn decode_hex_payload(value: &str) -> Result<Vec<u8>> {
    let compact = value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    if compact.len() % 2 != 0 {
        return Err(WireSurgeError::new(
            "invalid_hex_payload",
            "hex payload must contain an even number of digits",
        )
        .at("edns_payload"));
    }
    compact
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("hex input is ASCII-addressable");
            u8::from_str_radix(pair, 16).map_err(|_| {
                WireSurgeError::new(
                    "invalid_hex_payload",
                    format!("'{pair}' is not a valid hexadecimal byte"),
                )
                .at("edns_payload")
            })
        })
        .collect()
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

    fn response_for(query: &[u8]) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2] = 0x81;
        response[3] = 0x80;
        response
    }

    #[test]
    fn encodes_transaction_id_and_edns0_option() {
        let option = EdnsOption {
            code: 65001,
            payload: vec![0xca, 0xfe],
        };
        let packet = build_query(0xbeef, "example.com", 1, Some(&option)).unwrap();
        assert_eq!(&packet[0..2], &0xbeef_u16.to_be_bytes());
        assert!(
            packet
                .windows(2)
                .any(|window| window == 65001_u16.to_be_bytes())
        );
        assert!(packet.ends_with(&[0xca, 0xfe]));
    }

    #[test]
    fn encodes_configurable_edns0_option_code() {
        // The Global Resolver DoT auth token rides in EDNS0 option 65184 (0xFEA0);
        // the option code must be caller-supplied, not hardcoded to 65001.
        let token = b"a-token-value".to_vec();
        let option = EdnsOption {
            code: 65184,
            payload: token.clone(),
        };
        let packet = build_query(0x1234, "example.com", 1, Some(&option)).unwrap();
        assert!(
            packet
                .windows(2)
                .any(|window| window == 65184_u16.to_be_bytes()),
            "option code 65184 must appear in the OPT record"
        );
        assert!(
            !packet
                .windows(2)
                .any(|window| window == 65001_u16.to_be_bytes()),
            "the old hardcoded 65001 code must not leak through"
        );
        assert!(packet.ends_with(&token));
    }

    #[test]
    fn parses_named_and_numeric_qtypes() {
        assert_eq!(parse_qtype("AAAA").unwrap(), 28);
        assert_eq!(parse_qtype("65").unwrap(), 65);
    }

    #[test]
    fn frames_tcp_query_and_parses_response() {
        let query = build_query(0x1234, "example.com", 1, None).unwrap();
        let frame = tcp_frame(&query).unwrap();
        assert_eq!(
            u16::from_be_bytes([frame[0], frame[1]]) as usize,
            query.len()
        );
        assert_eq!(&frame[2..], query);

        let response = response_for(&query);
        let header = parse_response_header(&response, 0x1234).unwrap();
        assert_eq!(header.rcode, 0);
        assert!(!header.truncated);
    }

    #[test]
    #[ignore = "requires permission to bind localhost UDP sockets"]
    fn runs_udp_queries() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let server_task = thread::spawn(move || {
            let mut buffer = vec![0_u8; 2048];
            for _ in 0..3 {
                let (size, peer) = server.recv_from(&mut buffer).unwrap();
                let response = response_for(&buffer[..size]);
                server.send_to(&response, peer).unwrap();
            }
        });
        let stats = run_dns(
            DnsRunConfig {
                server: address.ip().to_string(),
                port: address.port(),
                transport: DnsTransport::Udp,
                qname: "example.com".to_string(),
                qtype: 1,
                count: 3,
                concurrency: 1,
                timeout: Duration::from_secs(1),
                qps: None,
                edns_option: None,
            },
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        server_task.join().unwrap();
        assert_eq!(stats.sent, 3);
        assert_eq!(stats.received, 3);
        assert_eq!(stats.errors, 0);
    }

    #[test]
    #[ignore = "requires permission to bind localhost TCP sockets"]
    fn reuses_tcp_connection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_task = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for _ in 0..3 {
                let mut length = [0_u8; 2];
                stream.read_exact(&mut length).unwrap();
                let length = u16::from_be_bytes(length) as usize;
                let mut query = vec![0_u8; length];
                stream.read_exact(&mut query).unwrap();
                let response = response_for(&query);
                let mut frame = Vec::with_capacity(response.len() + 2);
                frame.extend_from_slice(&(response.len() as u16).to_be_bytes());
                frame.extend_from_slice(&response);
                stream.write_all(&frame).unwrap();
            }
        });
        let stats = run_dns(
            DnsRunConfig {
                server: address.ip().to_string(),
                port: address.port(),
                transport: DnsTransport::Tcp,
                qname: "example.com".to_string(),
                qtype: 1,
                count: 3,
                concurrency: 1,
                timeout: Duration::from_secs(1),
                qps: None,
                edns_option: None,
            },
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        server_task.join().unwrap();
        assert_eq!(stats.sent, 3);
        assert_eq!(stats.received, 3);
        assert_eq!(stats.errors, 0);
    }
}
