use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::opt::EdnsOption as HickoryEdnsOption;
use hickory_proto::rr::{DNSClass, Name, RecordType};
use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_util::sync::CancellationToken;
use wiresurge_core::{Result, WireSurgeError, serialize_json};
use wiresurge_metrics::LatencyHistogram;

pub mod transport;

const DNS_HEADER_LEN: usize = 12;
const MAX_DNS_MESSAGE_LEN: usize = u16::MAX as usize;
const MAX_EDNS_OPTION_PAYLOAD_LEN: usize = u16::MAX as usize - 4;

/// Derive a transaction id from a query index, mixing in a per-run seed so two
/// concurrent runs against the same target do not share an id stream.
pub fn derive_txid(query_index: u64, seed: u64) -> u16 {
    let mut value = query_index ^ seed ^ 0x9e37_79b9_7f4a_7c15;
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value as u16
}

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
    pub latency_overflows: u64,
    pub rcode_counts: [u64; 17],
    pub cancelled: bool,
    pub last_error: Option<String>,
}

impl DnsRunStats {
    pub fn to_json(&self) -> Result<String> {
        #[derive(Serialize)]
        struct Latency {
            min: f64,
            max: f64,
            average: f64,
            p50: f64,
            p95: f64,
            p99: f64,
            overflows: u64,
        }

        #[derive(Serialize)]
        struct Rcode {
            #[serde(rename = "NOERROR")]
            no_error: u64,
            #[serde(rename = "FORMERR")]
            format_error: u64,
            #[serde(rename = "SERVFAIL")]
            server_failure: u64,
            #[serde(rename = "NXDOMAIN")]
            name_error: u64,
            #[serde(rename = "NOTIMP")]
            not_implemented: u64,
            #[serde(rename = "REFUSED")]
            refused: u64,
            #[serde(rename = "OTHER")]
            other: u64,
        }

        #[derive(Serialize)]
        struct Output<'a> {
            target: &'a str,
            protocol: &'a str,
            qname: &'a str,
            qtype: u16,
            requested: u64,
            sent: u64,
            received: u64,
            timeouts: u64,
            errors: u64,
            mismatched: u64,
            truncated: u64,
            duration_ms: f64,
            queries_per_second: f64,
            latency_ms: Latency,
            rcode: Rcode,
            cancelled: bool,
            last_error: &'a Option<String>,
        }

        serialize_json(&Output {
            target: &self.target,
            protocol: &self.transport,
            qname: &self.qname,
            qtype: self.qtype,
            requested: self.requested,
            sent: self.sent,
            received: self.received,
            timeouts: self.timeouts,
            errors: self.errors,
            mismatched: self.mismatched,
            truncated: self.truncated,
            duration_ms: self.duration_ms,
            queries_per_second: if self.duration_ms > 0.0 {
                self.received as f64 * 1000.0 / self.duration_ms
            } else {
                0.0
            },
            latency_ms: Latency {
                min: self.min_latency_ms,
                max: self.max_latency_ms,
                average: self.average_latency_ms,
                p50: self.p50_latency_ms,
                p95: self.p95_latency_ms,
                p99: self.p99_latency_ms,
                overflows: self.latency_overflows,
            },
            rcode: Rcode {
                no_error: self.rcode_counts[0],
                format_error: self.rcode_counts[1],
                server_failure: self.rcode_counts[2],
                name_error: self.rcode_counts[3],
                not_implemented: self.rcode_counts[4],
                refused: self.rcode_counts[5],
                other: self.rcode_counts[6..].iter().sum(),
            },
            cancelled: self.cancelled,
            last_error: &self.last_error,
        })
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
    fn observe_response(
        &mut self,
        response: &[u8],
        expected_id: u16,
        expected_qname: &str,
        expected_qtype: u16,
        elapsed: Duration,
    ) -> bool {
        let parsed = match Message::from_vec(response) {
            Ok(msg) => msg,
            Err(error) => {
                self.errors += 1;
                self.last_error = Some(error.to_string());
                return true;
            }
        };
        if parsed.metadata.id != expected_id {
            self.mismatched += 1;
            self.last_error = Some(format!(
                "expected transaction ID {expected_id}, received {}",
                parsed.metadata.id
            ));
            return false;
        }
        if parsed.metadata.message_type != MessageType::Response
            || parsed.metadata.op_code != OpCode::Query
        {
            self.errors += 1;
            self.last_error = Some("DNS response has invalid header flags".to_string());
            return true;
        }
        let question_valid = (|| -> Result<()> {
            if parsed.queries.len() != 1 {
                return Err(WireSurgeError::new(
                    "dns_question_mismatch",
                    "DNS response must echo exactly one question",
                ));
            }
            let expected_name = parse_dns_name(expected_qname)?;
            let question = &parsed.queries[0];
            if question.name() != &expected_name
                || question.query_type() != RecordType::from(expected_qtype)
                || question.query_class() != DNSClass::IN
            {
                return Err(WireSurgeError::new(
                    "dns_question_mismatch",
                    "DNS response question does not match the request",
                ));
            }
            Ok(())
        })();
        if let Err(error) = question_valid {
            self.errors += 1;
            self.last_error = Some(error.message);
            return true;
        }
        self.received += 1;
        self.truncated += u64::from(parsed.metadata.truncation);
        let bucket = usize::from(u16::from(parsed.metadata.response_code).min(16));
        self.rcode_counts[bucket] += 1;
        self.latency.record(elapsed);
        true
    }

    fn merge(&mut self, other: WorkerStats) -> Result<()> {
        self.sent += other.sent;
        self.received += other.received;
        self.timeouts += other.timeouts;
        self.errors += other.errors;
        self.mismatched += other.mismatched;
        self.truncated += other.truncated;
        for (target, source) in self.rcode_counts.iter_mut().zip(other.rcode_counts) {
            *target += source;
        }
        self.latency.merge(&other.latency)?;
        if other.last_error.is_some() {
            self.last_error = other.last_error;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ResponseHeader {
    pub rcode: u16,
    pub truncated: bool,
}

pub async fn run_dns(config: DnsRunConfig, cancellation: CancellationToken) -> Result<DnsRunStats> {
    config.validate()?;
    let target = resolve_target(&config.server, config.port).await?;
    let query_template = Arc::new(build_query(
        0,
        &config.qname,
        config.qtype,
        config.edns_option.as_ref(),
    )?);
    let config = Arc::new(config);
    let next_query = Arc::new(AtomicU64::new(0));
    let started = Instant::now();
    let mut workers = JoinSet::new();

    for worker_id in 0..config.concurrency {
        let worker_config = Arc::clone(&config);
        let worker_query = Arc::clone(&query_template);
        let worker_counter = Arc::clone(&next_query);
        let worker_cancellation = cancellation.clone();
        workers.spawn(async move {
            match worker_config.transport {
                DnsTransport::Udp => {
                    run_udp_worker(
                        worker_id,
                        target,
                        worker_config,
                        worker_query,
                        worker_counter,
                        worker_cancellation,
                        started,
                    )
                    .await
                }
                DnsTransport::Tcp => {
                    run_tcp_worker(
                        worker_id,
                        target,
                        worker_config,
                        worker_query,
                        worker_counter,
                        worker_cancellation,
                        started,
                    )
                    .await
                }
            }
        });
    }

    let mut aggregate = WorkerStats::default();
    while let Some(worker) = workers.join_next().await {
        match worker {
            Ok(stats) => aggregate.merge(stats)?,
            Err(error) => {
                aggregate.errors += 1;
                aggregate.last_error = Some(format!("DNS worker failed: {error}"));
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
        latency_overflows: aggregate.latency.overflows(),
        rcode_counts: aggregate.rcode_counts,
        cancelled: cancellation.is_cancelled(),
        last_error: aggregate.last_error,
    })
}

async fn run_udp_worker(
    worker_id: usize,
    target: SocketAddr,
    config: Arc<DnsRunConfig>,
    query_template: Arc<Vec<u8>>,
    next_query: Arc<AtomicU64>,
    cancellation: CancellationToken,
    run_started: Instant,
) -> WorkerStats {
    let mut stats = WorkerStats::default();
    let bind_address = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = match UdpSocket::bind(bind_address).await {
        Ok(socket) => socket,
        Err(error) => {
            stats.errors += 1;
            stats.last_error = Some(format!("failed to bind UDP socket: {error}"));
            return stats;
        }
    };
    if let Err(error) = socket.connect(target).await {
        stats.errors += 1;
        stats.last_error = Some(format!("failed to connect UDP socket: {error}"));
        return stats;
    }
    let mut query = (*query_template).clone();
    let mut response = vec![0_u8; MAX_DNS_MESSAGE_LEN];
    'queries: loop {
        let query_index = next_query.fetch_add(1, Ordering::Relaxed);
        if query_index >= config.count || cancellation.is_cancelled() {
            break;
        }
        if !wait_for_rate_slot(query_index, config.qps, run_started, &cancellation).await {
            break;
        }
        let transaction_id = transaction_id(worker_id, query_index);
        query[0..2].copy_from_slice(&transaction_id.to_be_bytes());
        stats.sent += 1;
        let attempt_started = Instant::now();
        let send = tokio::select! {
            _ = cancellation.cancelled() => break,
            result = timeout(config.timeout, socket.send(&query)) => result,
        };
        match send {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                stats.errors += 1;
                stats.last_error = Some(error.to_string());
                continue;
            }
            Err(_) => {
                stats.timeouts += 1;
                continue;
            }
        }

        let deadline = Instant::now() + config.timeout;
        loop {
            let received = tokio::select! {
                _ = cancellation.cancelled() => break 'queries,
                result = timeout_at(deadline, socket.recv(&mut response)) => result,
            };
            match received {
                Ok(Ok(received)) => {
                    if stats.observe_response(
                        &response[..received],
                        transaction_id,
                        &config.qname,
                        config.qtype,
                        attempt_started.elapsed(),
                    ) {
                        break;
                    }
                }
                Ok(Err(error)) => {
                    stats.errors += 1;
                    stats.last_error = Some(error.to_string());
                    break;
                }
                Err(_) => {
                    stats.timeouts += 1;
                    break;
                }
            }
        }
    }
    stats
}

async fn run_tcp_worker(
    worker_id: usize,
    target: SocketAddr,
    config: Arc<DnsRunConfig>,
    query_template: Arc<Vec<u8>>,
    next_query: Arc<AtomicU64>,
    cancellation: CancellationToken,
    run_started: Instant,
) -> WorkerStats {
    let mut stats = WorkerStats::default();
    let mut stream = None;
    let mut query = (*query_template).clone();
    loop {
        let query_index = next_query.fetch_add(1, Ordering::Relaxed);
        if query_index >= config.count || cancellation.is_cancelled() {
            break;
        }
        if !wait_for_rate_slot(query_index, config.qps, run_started, &cancellation).await {
            break;
        }
        let transaction_id = transaction_id(worker_id, query_index);
        query[0..2].copy_from_slice(&transaction_id.to_be_bytes());
        stats.sent += 1;
        let attempt_started = Instant::now();
        let outcome = tokio::select! {
            _ = cancellation.cancelled() => break,
            result = timeout(config.timeout, tcp_exchange(&mut stream, target, &query)) => result,
        };
        match outcome {
            Ok(Ok(response)) => {
                stats.observe_response(
                    &response,
                    transaction_id,
                    &config.qname,
                    config.qtype,
                    attempt_started.elapsed(),
                );
            }
            Err(_) => {
                stream = None;
                stats.timeouts += 1;
            }
            Ok(Err(error)) => {
                stream = None;
                stats.errors += 1;
                stats.last_error = Some(error.to_string());
            }
        }
    }
    if let Some(mut stream) = stream {
        let _ = stream.shutdown().await;
    }
    stats
}

async fn tcp_exchange(
    stream: &mut Option<TcpStream>,
    target: SocketAddr,
    query: &[u8],
) -> std::io::Result<Vec<u8>> {
    if stream.is_none() {
        let connected = TcpStream::connect(target).await?;
        connected.set_nodelay(true)?;
        *stream = Some(connected);
    }
    let stream = stream.as_mut().expect("TCP stream was initialized");
    let frame = tcp_frame(query)?;
    stream.write_all(&frame).await?;

    let mut response_len = [0_u8; 2];
    stream.read_exact(&mut response_len).await?;
    let response_len = u16::from_be_bytes(response_len) as usize;
    if response_len < DNS_HEADER_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS TCP response is shorter than the header",
        ));
    }
    let mut response = vec![0_u8; response_len];
    stream.read_exact(&mut response).await?;
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

async fn wait_for_rate_slot(
    query_index: u64,
    qps: Option<f64>,
    run_started: Instant,
    cancellation: &CancellationToken,
) -> bool {
    let Some(qps) = qps else {
        return !cancellation.is_cancelled();
    };
    let scheduled = run_started + Duration::from_secs_f64(query_index as f64 / qps);
    tokio::select! {
        _ = cancellation.cancelled() => false,
        _ = tokio::time::sleep_until(scheduled) => true,
    }
}

async fn resolve_target(server: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(socket) = server.parse::<SocketAddr>() {
        return Ok(socket);
    }
    if let Ok(ip) = server.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    tokio::net::lookup_host((server, port))
        .await
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

pub fn parse_response_header(response: &[u8], expected_id: u16) -> Result<ResponseHeader> {
    let response = Message::from_vec(response).map_err(|error| {
        WireSurgeError::new("invalid_dns_response", error.to_string()).retryable(false)
    })?;
    if response.metadata.id != expected_id {
        return Err(WireSurgeError::new(
            "dns_id_mismatch",
            format!(
                "expected transaction ID {expected_id}, received {}",
                response.metadata.id
            ),
        ));
    }
    if response.metadata.message_type != MessageType::Response {
        return Err(WireSurgeError::new(
            "invalid_dns_response",
            "DNS packet does not have the response bit set",
        ));
    }
    if response.metadata.op_code != OpCode::Query {
        return Err(WireSurgeError::new(
            "invalid_dns_response",
            "DNS response has an unexpected opcode",
        ));
    }
    Ok(ResponseHeader {
        rcode: u16::from(response.metadata.response_code),
        truncated: response.metadata.truncation,
    })
}

fn parse_dns_name(qname: &str) -> Result<Name> {
    let absolute_name = if qname.ends_with('.') {
        qname.to_string()
    } else {
        format!("{qname}.")
    };
    Name::from_ascii(absolute_name)
        .map_err(|error| WireSurgeError::new("invalid_dns_name", error.to_string()).at("qname"))
}

pub fn build_query(
    transaction_id: u16,
    qname: &str,
    qtype: u16,
    edns_option: Option<&EdnsOption>,
) -> Result<Vec<u8>> {
    let name = parse_dns_name(qname)?;
    let mut message = Message::new(transaction_id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, RecordType::from(qtype)));

    if let Some(edns) = edns_option {
        if edns.payload.len() > MAX_EDNS_OPTION_PAYLOAD_LEN {
            return Err(WireSurgeError::new(
                "invalid_edns_payload",
                "EDNS option payload exceeds 65531 bytes",
            )
            .at("edns_payload"));
        }
        let mut extension = Edns::new();
        extension.set_max_payload(1232);
        extension
            .options_mut()
            .insert(HickoryEdnsOption::Unknown(edns.code, edns.payload.clone()));
        message.set_edns(extension);
    }
    let packet = message
        .to_vec()
        .map_err(|error| WireSurgeError::new("dns_encode_failed", error.to_string()).at("qname"))?;
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

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, UdpSocket as StdUdpSocket};
    use std::thread;

    use super::*;

    fn response_for(query: &[u8]) -> Vec<u8> {
        let query = Message::from_vec(query).unwrap();
        let mut response = Message::response(query.metadata.id, query.metadata.op_code);
        response.metadata.recursion_desired = query.metadata.recursion_desired;
        response.metadata.recursion_available = true;
        response.add_queries(query.queries);
        if let Some(edns) = query.edns {
            response.set_edns(edns);
        }
        response.to_vec().unwrap()
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
    fn rejects_header_only_response() {
        let response = [0x12, 0x34, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0];
        let header = parse_response_header(&response, 0x1234).unwrap();
        assert_eq!(header.rcode, 0);
    }

    #[test]
    fn observe_response_validates_question() {
        let query = build_query(0x1234, "example.com", 1, None).unwrap();
        let response = response_for(&query);
        let mut stats = WorkerStats::default();
        let result = stats.observe_response(
            &response,
            0x1234,
            "example.net",
            1,
            Duration::from_micros(100),
        );
        assert!(result, "question mismatch should mark as counted error");
        assert_eq!(stats.errors, 1);
    }

    #[tokio::test]
    #[ignore = "requires permission to bind localhost UDP sockets"]
    async fn runs_udp_queries() {
        let server = StdUdpSocket::bind("127.0.0.1:0").unwrap();
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
            CancellationToken::new(),
        )
        .await
        .unwrap();
        server_task.join().unwrap();
        assert_eq!(stats.sent, 3);
        assert_eq!(stats.received, 3);
        assert_eq!(stats.errors, 0);
    }

    #[tokio::test]
    #[ignore = "requires permission to bind localhost TCP sockets"]
    async fn reuses_tcp_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
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
            CancellationToken::new(),
        )
        .await
        .unwrap();
        server_task.join().unwrap();
        assert_eq!(stats.sent, 3);
        assert_eq!(stats.received, 3);
        assert_eq!(stats.errors, 0);
    }
}
