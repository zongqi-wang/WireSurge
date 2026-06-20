# WireSurge Async Load Engine — Definitive Implementation Plan (>= 20k QPS DoH, matching the fixed flame fork)

## Backbone decision

Adopt **Design 1's protocol-agnostic `Transport` trait + per-connection actor + `FuturesUnordered` multiplexer** as the structural backbone (verdict: `hits_20k=likely, confidence=high`), graft in **Design 3's DoT-first staging** (validate the engine on a hand-built txid demux before the riskier hyper H2 work lands), and **Design 2's Little's-Law sizing** for default knobs. Every verifier fix that is load-bearing for 20k is folded in below, in particular:

- **F1 (Design 1 highest risk):** `hyper` `SendRequest` is `&mut self` / `Clone`; the actor never shares one `&mut`. We give every DoH connection its own task that owns `SendRequest` + a `FuturesUnordered`, fed by an `mpsc` (channel-split, exactly like the DoT actor). This is also Design 3's F1 fix (no shared `&mut Conn` across submit+collect).
- **F2 (Designs 1+2+3):** gate every DoH submission on `send_request.ready().await` (poll_ready) and clamp effective per-conn depth to `min(-q, live peer SETTINGS_MAX_CONCURRENT_STREAMS)`; never count an over-cap RST as a query error. **Default pool shape flipped to honor the documented `max_streams: 100`** (architecture.html line 893): `-c 32 × -q 64`, not `24 × 128`.
- **F3 (Design 3):** one semaphore **per connection** of size `-q` (or a single global of size `c*q`), never one shared semaphore of size `-q` (that would cap total in-flight 16x low).
- **F4 (Design 2):** `ring` ships native code + a build script, so per `docs/dependency-policy.md` line 17 it requires an **ADR** (`docs/adr/0001-ring-crypto-provider.md`) and its license string (`ISC AND MIT AND OpenSSL`) is **not** on the `{MIT,Apache-2.0,BSD-3-Clause,Unicode-3.0}` allowlist — we add explicit `[licenses] allow` entries (`ISC`, and a clarification for ring's `OpenSSL`-style terms) in the same PR with justification, since `deny.toml` `confidence-threshold = 0.93` will otherwise fail.
- **F5 (Design 2):** `deny.toml` `[bans.workspace-dependencies] unused = "deny"` — every workspace dep must be consumed with `workspace = true` **in the same PR it is declared**. No "no-op PR1" that declares tokio without consuming it.
- **F6 (Design 1):** DoH `exchange` fully drains the response body (so hyper auto-emits `WINDOW_UPDATE`), parses the DNS body for rcode/tc, and treats HTTP status != 200 (e.g. 403 bad token) distinctly from a DNS error.
- **F7 (Design 1):** GOAWAY/`ConnectionClosed` reconnect uses bounded backoff + a per-actor reconnect-rate cap; in-flight on a dead connection are recorded as errors (never silently dropped, which would inflate apparent QPS).
- **F8 (all three):** native RPITIT `async fn` in trait with explicit `+ Send` return bounds; **no `async-trait`** (extra dep, per-call Box, cargo-deny surface). Engine is generic over `T: Transport`, monomorphized per protocol.

---

## 1. Final crate / module layout

Keep all existing crates and their public APIs intact. The synchronous `run_dns` path in `crates/dns/src/lib.rs` stays untouched and green through Stage 5; the async engine is additive behind a Cargo feature and a new `wiresurge load` subcommand, then becomes the default high-rate path at cutover (Stage 8).

```
crates/
  core/        # UNCHANGED. WireSurgeError, Result, json_object/json_string/json_array reused for NDJSON.
  transport/   # NEW crate: wiresurge-transport. The shared connection seam.
    src/
      lib.rs         # re-exports; ConnectTarget; BoxedStream type alias
      tls.rs         # rustls ClientConfig builders (ring provider), ALPN, SNI, resumption, relaxed-ALPN
      ppv2.rs        # PROXY protocol v2 header encode (hand-rolled, golden-byte tested) + ProxyHeader
      connect.rs     # connect_with_ppv2(): TCP dial to pod -> write PPv2 -> optional TLS -> BoxedStream
  corpus/      # NEW crate: wiresurge-corpus. mmap newline file + offset table + selection (-R)
    src/
      lib.rs         # Corpus, SelectMode, select(); Send+Sync wrapper over owned Mmap
      permute.rs     # seeded multiplicative/Feistel permutation (visit-each-once, no 1M Vec)
  dns/         # GROW. Keep build_query/EdnsOption/parse_qtype/parse_response_header PUBLIC & unchanged.
    src/
      lib.rs         # existing sync path stays; expose parse helpers `pub`
      wire.rs        # NEW: derive_txid, build_query_into(&mut Vec<u8>,...), response rcode/tc parse reuse
      transport/
        mod.rs       # Transport trait + DnsRequest/DnsResponse/TransportError + TransportCaps
        do53.rs      # UdpTransport (txid demux) + TcpTransport (length-prefixed pipeline, txid demux)
        dot.rs       # DotTransport: TLS ALPN "dot", split stream, writer task + reader task, txid demux
        doh.rs       # DohTransport: hyper h2, per-conn task owns SendRequest + FuturesUnordered
  http/        # UNCHANGED sync HTTP/1.1 runner (still used by `wiresurge run`).
  engine/      # GROW into the real load engine (today's run_request stubs stay for `wiresurge run`).
    src/
      lib.rs         # existing run_request/run_stored_request UNCHANGED
      load.rs        # LoadConfig, LoadStats, run_load() async entrypoint
      scheduler.rs   # WorkSource (rate credits -Q, in-flight -q, duration -l, count, randomize -R)
      actor.rs       # ConnectionActor<T: Transport>: connect, top-up loop, drain, reconnect
      pool.rs        # ConnPool<T>: spawns -c actors, aggregates LocalRecorder, warmup
  metrics/     # GROW. Keep RunnerStats/WorkerStats/ReportSummary JSON shapes.
    src/
      lib.rs         # UNCHANGED public structs
      hist.rs        # hdrhistogram-backed LocalRecorder + Aggregate (per-actor, merged off hot path)
      ndjson.rs      # flame-compatible NDJSON interval emitter + final summary (uses core json helpers)
  cli/         # GROW. New `load` subcommand + tokio runtime builder; existing `dns` path unchanged.
  plugins/ storage/   # UNCHANGED.
docs/adr/0001-ring-crypto-provider.md   # NEW: ADR for ring (native code + build script per policy §17)
```

---

## 2. Transport trait + connection-actor + scheduler types (real Rust)

### 2.1 The `Transport` trait (native RPITIT, `+ Send`, no async-trait)

```rust
// crates/dns/src/transport/mod.rs
use bytes::Bytes;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use wiresurge_core::Result;

/// One prepared query. `wire` is the full DNS message; for Do53/DoT it already
/// carries the EDNS 65184 token. `correlation` is the txid in wire[0..2] for
/// UDP/DoT/Do53-TCP; for DoH it is informational (hyper owns stream demux).
#[derive(Clone)]
pub struct DnsRequest {
    pub correlation: u16,
    pub wire: Bytes,
    pub qtype: u16,
    pub name_index: u64,   // reproducible scheduler trace
}

#[derive(Debug)]
pub struct DnsResponse {
    pub correlation: u16,  // echoed txid (UDP/DoT) or 0 (DoH)
    pub rcode: u16,
    pub truncated: bool,
    pub bytes_in: usize,
    pub latency_us: u64,
}

#[derive(Debug)]
pub enum TransportError {
    Timeout,
    Io(String),
    Protocol(String),
    Http { status: u16 },      // DoH non-200 (e.g. 403 bad token) — NOT a DNS error
    ConnectionClosed,          // GOAWAY / FIN -> actor reconnects with backoff
}

pub struct TransportCaps {
    /// Effective in-flight cap. DoH = min(-q, live peer SETTINGS_MAX_CONCURRENT_STREAMS).
    pub max_in_flight: usize,
    pub reuse_limit: Option<u64>,   // --connection-reuse N
}

#[derive(Clone)]
pub struct ConnectTarget {
    pub tcp_addr: SocketAddr,                 // where the socket actually opens (pod 10.208.34.245:443)
    pub sni: Option<String>,                  // configurable TLS SNI
    pub alpn: &'static [&'static [u8]],       // b"dot" | b"h2" | &[]
    pub proxy: Option<ProxyHeader>,           // mocked src + NLB VIP dst, INDEPENDENT of tcp_addr
    pub tls: Option<Arc<rustls::ClientConfig>>,
    pub alpn_relaxed: bool,                   // assume protocol if peer omits ALPN
    pub doh: Option<DohConfig>,               // base path, GET|POST, ?token=
}

/// `Transport` is NEVER used as `dyn`: the engine is generic over `T: Transport`
/// and monomorphized per protocol. `exchange` returns `impl Future + Send` so the
/// futures live in a multi-thread FuturesUnordered without async-trait/Box.
pub trait Transport: Send + Sync + 'static {
    fn connect(
        target: ConnectTarget,
        cancel: CancellationToken,
    ) -> impl Future<Output = Result<Self>> + Send
    where
        Self: Sized;

    fn caps(&self) -> TransportCaps;

    /// Submit one request; resolves when THIS request completes/times out.
    /// MUST allow many concurrent calls and correlate replies internally.
    fn exchange(
        &self,
        req: DnsRequest,
        timeout: Duration,
    ) -> impl Future<Output = std::result::Result<DnsResponse, TransportError>> + Send;

    /// Graceful drain: stop new exchanges, let in-flight finish (bounded by grace),
    /// then GOAWAY/close_notify. Defined order in §6.
    fn drain(self, grace: Duration) -> impl Future<Output = ()> + Send;
}
```

### 2.2 Connection actor (owns one connection + its own in-flight accounting)

```rust
// crates/engine/src/actor.rs
use futures_util::stream::{FuturesUnordered, StreamExt};

pub struct ActorConfig {
    pub in_flight: usize,         // -q depth per connection
    pub timeout: Duration,
    pub reuse_limit: Option<u64>, // --connection-reuse
    pub batch_delay: Duration,    // -d
    pub max_reconnects_per_sec: u32, // F7 reconnect-storm guard
}

pub struct ConnectionActor<T: Transport> {
    target: ConnectTarget,
    cfg: ActorConfig,
    cancel: CancellationToken,
    rec: LocalRecorder,           // per-actor metrics; merged periodically, no hot lock
}

impl<T: Transport> ConnectionActor<T> {
    pub async fn run(mut self, work: WorkSource) -> LocalRecorder {
        let mut conn = match T::connect(self.target.clone(), self.cancel.child_token()).await {
            Ok(c) => c,
            Err(e) => { self.rec.on_connect_error(&e); return self.rec; }
        };
        // F3: this cap is THIS connection's depth; total in-flight = c * cap.
        // F2: caps().max_in_flight already = min(-q, live peer stream limit).
        let mut cap = conn.caps().max_in_flight.min(self.cfg.in_flight);
        let mut sent_on_conn = 0u64;
        let mut backoff = ReconnectGuard::new(self.cfg.max_reconnects_per_sec);
        let mut inflight = FuturesUnordered::new();
        loop {
            while inflight.len() < cap {
                match work.next_request().await {       // -Q pacing + corpus select inside
                    Some(req) => {
                        inflight.push(conn.exchange(req, self.cfg.timeout));
                        sent_on_conn += 1;
                        self.rec.on_sent();
                    }
                    None => break,
                }
            }
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    while let Some(r) = inflight.next().await { self.rec.record(r); } // drain in-flight
                    conn.drain(self.cfg.timeout).await; break;
                }
                done = inflight.next(), if !inflight.is_empty() => {
                    match done {
                        Some(Ok(resp)) => self.rec.on_response(&resp),
                        Some(Err(TransportError::Timeout)) => self.rec.on_timeout(),
                        Some(Err(TransportError::ConnectionClosed)) => {
                            // F7: remaining inflight on dead conn count as errors, then reconnect w/ backoff.
                            while let Some(r) = inflight.next().await { self.rec.record_dead(r); }
                            backoff.wait(&self.cancel).await;
                            conn = match T::connect(self.target.clone(), self.cancel.child_token()).await {
                                Ok(c) => c, Err(e) => { self.rec.on_connect_error(&e); break; }
                            };
                            cap = conn.caps().max_in_flight.min(self.cfg.in_flight);
                            sent_on_conn = 0;
                        }
                        Some(Err(e)) => self.rec.on_error(e),
                        None => {}
                    }
                }
            }
            if work.is_exhausted() && inflight.is_empty() { conn.drain(self.cfg.timeout).await; break; }
            if let Some(limit) = self.cfg.reuse_limit
                && sent_on_conn >= limit && inflight.is_empty() {
                conn.drain(self.cfg.timeout).await;
                conn = T::connect(self.target.clone(), self.cancel.child_token()).await.unwrap_or_else(/* record + break */);
                sent_on_conn = 0;
            }
        }
        self.rec
    }
}
```

### 2.3 Scheduler / `WorkSource` (rate credits, depth, duration, randomize)

```rust
// crates/engine/src/scheduler.rs
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

#[derive(Clone)]
pub struct LoadConfig {
    pub proto: Proto,                  // Do53Udp | Do53Tcp | Dot | Doh
    pub target: ConnectTarget,
    pub concurrency: usize,            // -c   number of connection actors
    pub in_flight: usize,              // -q   per-connection depth
    pub batch_delay: Duration,         // -d
    pub connection_reuse: Option<u64>, // --connection-reuse N
    pub qps_cap: Option<f64>,          // -Q   per-process
    pub duration: Option<Duration>,    // -l
    pub count: Option<u64>,            // total queries (alt to -l)
    pub timeout: Duration,             // -t
    pub randomize: bool,               // -R
    pub corpus: Arc<Corpus>,           // -f
    pub qtype: u16,
    pub token: Option<TokenSpec>,      // lowered per transport (§5)
}

/// Clonable handle every actor pulls from. Lock-free counter + optional async rate gate.
#[derive(Clone)]
pub struct WorkSource {
    seq: Arc<AtomicU64>,
    limit: Option<u64>,
    deadline: Option<Instant>,
    gate: Option<Arc<RateGate>>,   // -Q token bucket, async sleep_until (NOT thread::sleep)
    corpus: Arc<Corpus>,
    seed: u64,
    template: Arc<QueryTemplate>,  // qtype + edns token; only name+txid change per query
    randomize: bool,
}

impl WorkSource {
    pub async fn next_request(&self) -> Option<DnsRequest> {
        let idx = self.seq.fetch_add(1, Ordering::Relaxed);
        if self.limit.is_some_and(|n| idx >= n) { return None; }
        if self.deadline.is_some_and(|d| Instant::now() >= d) { return None; }
        if let Some(g) = &self.gate { if !g.acquire(idx).await { return None; } }
        let mode = if self.randomize { SelectMode::RandomReplace } else { SelectMode::Sequential };
        let name = self.corpus.select(idx, self.seed, mode);
        Some(self.template.materialize(idx, name))   // build_query_into into a bounded buffer
    }
    pub fn is_exhausted(&self) -> bool { /* limit or deadline reached */ }
}

pub async fn run_load(cfg: LoadConfig, cancel: CancellationToken) -> wiresurge_core::Result<LoadStats>;
```

`RateGate::acquire` computes `scheduled = start + idx/qps` and `tokio::time::sleep_until(scheduled)` — an async sleep, replacing the current `thread::sleep` in `wait_for_rate_slot` (`dns/src/lib.rs:646`).

---

## 3. The async in-flight pipeline (the thing that kills `send().and_then(recv)`)

Current fatal serialization (verified): `socket.send(&query).and_then(|_| socket.recv(&mut response))` at `crates/dns/src/lib.rs:511` (UDP) and `tcp_exchange` write-then-read at `:602–605`. Max QPS = `workers / RTT`. New pipeline keeps `-q` requests outstanding **per connection**, multiplied across `-c` connections.

### 3.1 Do53-UDP (`do53.rs`)
One `tokio::net::UdpSocket` `connect()`ed to target. A dedicated **reader task** loops `recv` and dispatches each datagram by `txid = u16::from_be_bytes(buf[0..2])` into a sharded `Mutex<HashMap<u16, oneshot::Sender<DnsResponse>>>` (or a `Slab`). `exchange()` inserts a `oneshot` under a `Slab`-allocated txid, `send`s, then awaits the receiver under `tokio::time::timeout`. On timeout the slab entry is reaped so the entry frees and the actor slot reopens. Many `exchange` futures coexist.

### 3.2 Do53-TCP & DoT (`do53.rs` TCP / `dot.rs`)
Channel-split actor (Design 3's writer+reader split):
- `tokio::io::split(stream)` (rustls `TlsStream` for DoT, raw `TcpStream` for Do53-TCP).
- **Writer task** drains an `mpsc<(DnsRequest, oneshot::Sender)>`: allocate a per-connection txid from a `Slab` (at most `-q` live ids => guaranteed unique within the outstanding window), patch `wire[0..2]`, write `[u16 len][msg]` with `write_all` and **never** await a read.
- **Reader task** reads `[u16 len][msg]`, parses txid from `msg[0..2]`, parses rcode/tc via `parse_response_header` (reused from `dns/src/lib.rs:685`), completes the matching `oneshot`.
- `exchange()` = push to writer mpsc + await oneshot under `tokio::time::timeout`. DoT ALPN negotiates `dot`.

### 3.3 DoH (`doh.rs`) — F1 channel-split, hyper owns demux
**Each DoH connection is its own task** that owns the (`&mut`) `SendRequest` + a `FuturesUnordered<ResponseFut>` — fed by an `mpsc<(DnsRequest, oneshot::Sender)>`. `DohTransport::exchange(&self)` only pushes to that mpsc and awaits the oneshot, so concurrent `exchange(&self)` calls never touch `SendRequest` directly (resolves the `&mut` vs `&self` mismatch). The per-conn task loop:

```rust
// inside the spawned DoH connection task
loop {
  tokio::select! {
    Some((req, reply)) = submit_rx.recv(), if pending.len() < cap => {
      // F2: gate on readiness; Pending == at MAX_CONCURRENT_STREAMS, do not over-issue.
      if send_req.ready().await.is_err() { /* mark closed */ break; }
      let http_req = build_doh_request(&doh_cfg, &req.wire);   // POST body=wire OR GET ?dns=..&token=..
      let fut = send_req.send_request(http_req);               // hyper assigns stream id, multiplexes
      pending.push(async move { (req, reply, tokio::time::timeout(timeout, fut).await) });
    }
    Some((req, reply, res)) = pending.next(), if !pending.is_empty() => {
      // F6: classify HTTP status, fully drain body, parse DNS rcode/tc.
      let outcome = classify_doh(res).await; // 200 -> collect body -> Message::from_octets -> opt_rcode/tc
      let _ = reply.send(outcome);           // 403/5xx -> TransportError::Http{status}; closed -> ConnectionClosed
    }
    else => break,
  }
}
```

`pending` IS the `FuturesUnordered` (no separate `pending` Vec — resolves Design 3's "items never move pending->inflight" gap). The connection driver future from `http2::handshake` is `tokio::spawn`'d separately and owns `WINDOW_UPDATE`/`GOAWAY`/`PING` — which is exactly the set of things mainline flame got wrong by hand.

Throughput math (Little's Law): `QPS = c × min(q, peer_streams) / RTT`. Default `-c 32 × q≈64 / 5ms = 409k` theoretical; even at 15ms saturated-pod RTT, `32 × 64 / 0.015 = 136k` — comfortable headroom over 20k. We validate empirically on the m8gn host (Stage 9), not by trusting the formula.

---

## 4. Exact hyper / rustls / tokio tuning (reach 20k, dodge the 64KB stall)

### 4.1 rustls ClientConfig (`transport/src/tls.rs`) — shared by DoT + DoH
```rust
let provider = rustls::crypto::ring::default_provider();
let mut cfg = rustls::ClientConfig::builder_with_provider(provider.into())
    .with_safe_default_protocol_versions()?           // TLS 1.3 + 1.2 (CoreDNS customtls may need 1.2)
    .with_root_certificates(roots)                     // native|embedded|file; --insecure custom verifier behind a flag
    .with_no_client_auth();
cfg.alpn_protocols = match proto { Dot => vec![b"dot".to_vec()], Doh => vec![b"h2".to_vec()], _ => vec![] };
cfg.enable_sni = true;                                  // SNI from ConnectTarget.sni
cfg.resumption = rustls::client::Resumption::in_memory_sessions(256); // cheap reconnects
```
**Relaxed-ALPN (flame lesson #4):** after handshake inspect `tls.get_ref().1.alpn_protocol()`. `Some(b"h2")` (DoH) / `Some(b"dot")` (DoT) => proceed; `None` && `alpn_relaxed` => **assume the configured protocol**; a *conflicting* protocol (`http/1.1` for DoH) => hard error.

### 4.2 hyper H2 builder (`doh.rs`), per connection
```rust
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};

let (send_req, conn) = http2::Builder::new(TokioExecutor::new())
    .adaptive_window(true)                              // auto-tune + auto-flush WINDOW_UPDATE (flame lesson #2)
    .initial_connection_window_size(16 * 1024 * 1024)   // 16 MiB conn window: never the 64KB default that stalled flame
    .initial_stream_window_size(2 * 1024 * 1024)        // 2 MiB per stream (>> tiny DNS)
    .max_concurrent_reset_streams(0)                    // do not retain reset streams
    .max_send_buf_size(1024 * 1024)
    .keep_alive_interval(Some(Duration::from_secs(10))) // PING keepalive across bursts
    .keep_alive_timeout(Duration::from_secs(20))
    .keep_alive_while_idle(true)
    .handshake(TokioIo::new(tls_stream)).await?;
let driver = tokio::spawn(async move { if let Err(_e) = conn.await { /* signal ConnectionClosed */ } });
```
- No code path calls anything like `terminate_session`; a finished stream only frees a `FuturesUnordered` slot (flame lesson #1). Connections die only on driver `Err`, GOAWAY, or `--connection-reuse`.
- We fully drain each response body (`http_body_util::BodyExt::collect`) so hyper releases flow-control credit — load-bearing for lesson #2.
- **Stream-cap honoring (F2):** there is no hyper `Builder` getter for the peer's outbound `SETTINGS_MAX_CONCURRENT_STREAMS`; we rely on `send_req.ready().await` backpressure (`Pending` == at cap) AND default the pool so average streams/conn stay well under the documented `max_streams: 100`.

### 4.3 Default pool shape (F2 — flipped from the mis-sized 24×128)
`-c 32 --in-flight-per-conn 64` (capacity ~2048, avg streams/conn comfortably under 100). `--in-flight` global cap optional. Knobs are first-class; ladder (Stage 9) climbs `-c`/`-q` to find the true ceiling. DoT default `-c 64 -q 64`.

### 4.4 tokio runtime (`cli`, explicit builder — not `#[tokio::main]`)
```rust
let rt = tokio::runtime::Builder::new_multi_thread()
    .worker_threads(num_cpus().min(48))   // m8gn = 64 vCPU; leave headroom for driver/crypto/aggregator
    .enable_io().enable_time()
    .max_blocking_threads(8)              // corpus mmap scan + report writes only
    .thread_name("wiresurge-io")
    .build()?;
```
CPU is not the 20k ceiling on Graviton4; the pod/NLB is. TCP connector sets `set_nodelay(true)` (Nagle would add an RTT to latency-sensitive DNS).

---

## 5. PPv2 connector seam + token lowering

### 5.1 PPv2 (the connector seam) — `transport/src/connect.rs` + `ppv2.rs`
The TCP target is the **pod IP**; the PPv2 src/dst are the **mocked customer src + NLB VIP dst**, independent of the socket peer. So PPv2 must be the **first bytes on the freshly connected TCP stream, before any TLS ClientHello or DNS bytes**. We drive `hyper::client::conn::http2::handshake` on our own already-PPv2+TLS-wrapped stream via `TokioIo` — we do **not** use `hyper-util`'s legacy pooling `Client` (it hides byte ordering and connection identity).

```rust
pub async fn connect_with_ppv2(target: &ConnectTarget) -> Result<BoxedStream> {
    let mut tcp = tokio::net::TcpStream::connect(target.tcp_addr).await?; // dial the POD (10.208.34.245:443)
    tcp.set_nodelay(true)?;
    if let Some(p) = &target.proxy {
        tcp.write_all(&p.encode()).await?;   // PPv2 header FIRST, once per connection, before TLS/DNS
    }
    match &target.tls {
        None => Ok(Box::new(tcp)),           // Do53-TCP: DNS length-prefix bytes go next
        Some(cfg) => {
            let connector = tokio_rustls::TlsConnector::from(cfg.clone());
            let sni = rustls::pki_types::ServerName::try_from(
                target.sni.clone().unwrap_or_else(|| target.tcp_addr.ip().to_string()))?;
            Ok(Box::new(connector.connect(sni, tcp).await?))  // ClientHello rides on top of PPv2
        }
    }
}
```

**Hand-rolled PPv2 v2 encoder** (the dependency policy permits a small well-contained helper; `ppp` is a fallback if review prefers a reviewed crate — but a hand-rolled encoder avoids a dep + a cargo-deny line). TCPv4 layout (the GR case):
```
sig (12): 0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A
[12] 0x21              ver 2 | PROXY cmd
[13] 0x11              AF_INET | STREAM
[14..16] 0x00 0x0C     addr block len = 12
[16..20] src.ip        52.5.87.206 (MOCKED, independent of tcp_addr)
[20..24] dst.ip        10.216.20.227 (NLB VIP)
[24..26] src.port BE
[26..28] dst.port BE
```
IPv6 = family `0x21`, 36-byte addr block. CLI parse `--proxy SRC#SPORT-DST#DPORT`. Golden-byte test on the 28-byte IPv4 header + an integration test where the mock server reads the PPv2 header **before** the ClientHello, with PPv2 addrs != socket peer.

### 5.2 Token lowering — one logical `--token`, different wire placement
```rust
// crates/dns/src/wire.rs  (QueryTemplate)
pub enum TokenSpec { Value(String) }
```
- **Do53 / DoT:** EDNS0 OPT code **65184 (0xFEA0)**, value = ASCII token bytes, baked into every query via the existing `build_query(txid, name, qtype, Some(&EdnsOption{code:65184, payload}))` — reuses the landed configurable-code path verbatim (test `encodes_configurable_edns0_option_code` at `dns/src/lib.rs:855` already asserts 65184). No new DNS codec.
- **DoH:** token in the **URL query** `?token=<percent-encoded>`, baked into the `DohConfig` path **once at connection build time** (hot path just clones). The DNS body carries **no** token EDNS option. POST (default): `/dns-query?token=…`, body = raw `application/dns-message` wire (no base64). GET: `/dns-query?token=…&dns=<base64url-NO-PAD(wire)>` via `base64` `URL_SAFE_NO_PAD`. Percent-encoding the token uses a small well-contained helper, not a urlencoding crate.

`LoadConfig::validate()` rejects `--token` on plain `udp` sync transport and ignores `--edns-code` for DoH.

---

## 6. Drain / cancellation ordering (F7 + UAF safety)

`drain(grace)` order, both transports:
1. Stop topping up (no new `exchange`/submit).
2. `await` the existing `FuturesUnordered`/in-flight to completion, bounded by `grace` (`tokio::time::timeout`).
3. DoH: drop `SendRequest` so the spawned driver finishes outstanding streams and emits GOAWAY; then join the driver task. DoT/Do53: flush writer, `shutdown()` write half, read remaining responses until grace.

On per-query DoH timeout, dropping the `ResponseFut` must RST/cancel that stream so it does not linger against `MAX_CONCURRENT_STREAMS` over a long `-l` run — validated under sustained-timeout load. Late responses arriving after a DoT timeout are treated as stray (slab entry already reaped), never double-releasing a slot. SIGINT/SIGTERM route through `tokio::signal` into a `CancellationToken` that is checked inside the `exchange` timeout select (not only at the submit loop), so the deadline stops outstanding waits immediately rather than waiting up to `--timeout`.

---

## 7. Non-blocking corpus mmap + selection + `-R`

```rust
// crates/corpus/src/lib.rs
pub struct Corpus { _map: memmap2::Mmap, base: *const u8, offsets: Vec<(u32, u32)> }
unsafe impl Send for Corpus {}  // base points into the owned, never-mutated Mmap held in _map (outlives all rows via Arc)
unsafe impl Sync for Corpus {}

impl Corpus {
    /// Built on spawn_blocking BEFORE the run timer/actor loop starts. mmap is lazy-paged;
    /// we scan newlines once (memchr) to build the offset table. Directly guards the flame
    /// stale-clock "0 queries on >100k-line files" bug: the clock starts only after the index exists.
    pub fn load(path: &std::path::Path) -> Result<Arc<Corpus>> { /* mmap + newline scan */ }
    pub fn single(name: &str) -> Arc<Corpus>;        // back-compat: no -f
    pub fn len(&self) -> usize;
    pub fn row(&self, i: usize) -> &str;             // zero-copy slice into mmap
    pub fn select(&self, idx: u64, seed: u64, mode: SelectMode) -> &str {
        let n = self.len() as u64;
        let row = match mode {
            SelectMode::Sequential    => (idx % n) as usize,
            SelectMode::RandomReplace => (splitmix64(idx ^ seed) % n) as usize, // -R, allocation-free
            SelectMode::RandomPermute => permute_index(idx, n, seed),           // visit-each-once, no 1M Vec
        };
        self.row(row)
    }
}
```
mmap not read-to-`Vec<String>`; workers hold only `idx` + `Arc<Corpus>` (memory != workers × corpus). `&str` never outlives the `Arc<Corpus>`. Offset `(u32,u32)` caps a single file < 4 GiB (fine for 1M rows).

---

## 8. Flame-compatible NDJSON metrics via hdrhistogram

```rust
// crates/metrics/src/hist.rs
pub struct LocalRecorder {          // lives inside one ConnectionActor; never shared
    sent: u64, received: u64, timeouts: u64, errors: u64, mismatched: u64, truncated: u64,
    http_status: BTreeMap<u16,u64>, // DoH non-200 (403 bad token, etc.)
    rcodes: [u64; 17], bytes_in: u64,
    hist: hdrhistogram::Histogram<u64>,  // micros, 1..=60_000_000, 3 sig figs
}
```
Per-actor recorder, merged into an `Aggregate` via `mpsc` every ~250ms by one aggregator task (no shared hot lock at 20k+/s) — replaces the coarse power-of-two `LatencyHistogram` (`dns/src/lib.rs:281`) whose percentiles snap to power-of-two bounds. `hdrhistogram` gives true p50/p95/p99/p999.

NDJSON (`ndjson.rs`) built with the existing `wiresurge_core::json_object`/`json_string` helpers (no `serde_json`):
```jsonc
// per --interval (live): {"ts":..., "period_s":0.25, "sent":..., "received":..., "timeouts":..., "errors":...,
//   "qps":..., "rps":..., "min_ms":..., "p50_ms":..., "p95_ms":..., "p99_ms":..., "max_ms":...,
//   "in_flight":..., "open_conns":..., "rcode":{...}, "http_status":{...}}
// final: {"summary":true, "duration_s":..., full percentiles, "goaway_count":..., "reconnects":..., "cancelled":...}
```
Final summary keeps `DnsRunStats::to_json` field names (`requested/sent/received/timeouts/.../queries_per_second/latency_ms{...}/rcode{...}`) plus `conns/streams/in_flight_peak/goaway_count/reconnects` so downstream tooling and `wiresurge report` keep working.

---

## 9. Exact Cargo.toml dependency lines (pinned, default-features off, deny.toml-compliant)

Declared once in root `[workspace.dependencies]`, consumed `workspace = true`. **Each is consumed in the same PR it is added (F5 `unused = "deny"`).** Re-pin to the exact latest-reviewed patch at PR time and gate on `cargo tree --duplicates` (F3-dup) for transitive `windows-sys`/`socket2`/`rustls`/`hashbrown` collisions.

```toml
# Async runtime (Stage 1, consumed by transport crate + cli runtime in same PR)
tokio          = { version = "=1.47.1", default-features = false, features = ["rt-multi-thread","net","time","sync","macros","signal","io-util"] }
tokio-util     = { version = "=0.7.16", default-features = false, features = ["rt"] }   # CancellationToken
futures-util   = { version = "=0.3.31", default-features = false, features = ["std","async-await"] } # FuturesUnordered
bytes          = { version = "=1.10.1", default-features = false }

# TLS (Stage 4). ring provider -> ADR docs/adr/0001-ring-crypto-provider.md + ISC license allow entry.
rustls           = { version = "=0.23.35", default-features = false, features = ["std","ring","tls12"] }
tokio-rustls     = { version = "=0.26.4", default-features = false, features = ["ring","logging","tls12"] }
rustls-pki-types = { version = "=1.13.0" }

# DoH (Stage 6). http1 NOT enabled (DoH is h2-only). hyper-util only for rt::Tokio{Io,Executor}.
hyper          = { version = "=1.8.1", default-features = false, features = ["client","http2"] }
hyper-util     = { version = "=0.1.20", default-features = false, features = ["tokio"] }  # F-note: drop client/client-legacy
http           = { version = "=1.3.1", default-features = false }
http-body-util = { version = "=0.1.3", default-features = false }
base64         = { version = "=0.22.1", default-features = false, features = ["std"] }    # DoH GET base64url

# Corpus (Stage 2) + metrics (Stage 7). Both build-script-free / pure-Rust.
memmap2        = { version = "=0.9.8" }
hdrhistogram   = { version = "=7.5.4", default-features = false }   # no flate2/serde features -> minimal graph
```
deny.toml deltas (same PRs): add ADR for `ring`; add `[licenses] allow` entries to clear ring's `ISC`/OpenSSL-style terms at `confidence-threshold = 0.93` (F4). Single `rustls` (own connector, no `hyper-rustls`). `ring` (not `aws-lc-rs`) avoids a second native ADR and builds clean on `aarch64-unknown-linux-musl`. `domain` 0.12.1 std-only stays as the DNS codec.

---

## 10. Staged PR plan (ordered; each builds, tests, passes `cargo deny check` + `cargo tree --duplicates`)

**PR1 — Async runtime + transport-crate skeleton (deps consumed, not no-op).**
Add `tokio`, `tokio-util`, `futures-util`, `bytes`. Create `crates/transport` with `ConnectTarget`/`BoxedStream` + a plain-TCP connector (no TLS/PPv2 yet). Build the tokio runtime in `cli` and wire `CancellationToken` to the existing signal path. Define the `Transport` trait + `DnsRequest`/`DnsResponse`/`TransportError`/`TransportCaps` in `dns/src/transport/mod.rs`. F5: every new dep is consumed by a member with `workspace = true` in THIS PR. Accept: builds for `aarch64-unknown-linux-musl`; `cargo deny check` + `cargo tree --duplicates` green.

**PR2 — Corpus crate (`-f`, `-R`).** Add `memmap2`. mmap + offset scan on `spawn_blocking`, `select`, `permute`, `single`. Accept: 1M-line synthetic corpus loads without blocking and selection is non-zero (guards the flame large-file bug); `-R` permutation visits each row once for `count == len`; `&str` bounds correct.

**PR3 — Async Do53 (UDP + TCP) + scheduler/actor/pool.** Implement `do53.rs` (reader-task + slab/oneshot demux), `WorkSource`, `RateGate` (async `sleep_until`), `ConnectionActor<T>` (F3: per-conn semaphore/cap), `ConnPool<T>`, `hdrhistogram` `LocalRecorder`. New `wiresurge load <server>` subcommand: `-c -q -d -Q -l -t -R -f --count`. Add `hdrhistogram`. Accept: loopback UDP/TCP echo, send 1000 with `-q 64` over `-c 1`, assert all received and wall-time << `1000 × RTT` — **proves the one-in-flight loop is gone before any TLS/H2 complexity.**

**PR4 — TLS connector + DoT (the engine proof on a hand-built demux, Design 3 staging).** Add `rustls`, `tokio-rustls`, `rustls-pki-types`; write the `ring` ADR + license allow entries. `tls.rs` builders (ALPN/SNI/resumption/relaxed-ALPN). `dot.rs` writer+reader split over `tokio::io::split(TlsStream)`, txid demux, DelayQueue/timeout reaping. CLI `--protocol dot --sni --alpn --insecure`, token via EDNS 65184. Accept: DoT against a local rustls echo (ALPN `dot`), pipelined depth honored, txid demux correct, timeouts free slots, ALPN-absent path proceeds. **Go/no-go for the 20k claim before DoH.**

**PR5 — Do53 plain-TCP parity + PPv2 connector.** `ppv2.rs` encoder (TCPv4 + TCPv6) golden-byte test; wire `connect_with_ppv2` as the first write before TLS/DNS. CLI `--proxy SRC#SPORT-DST#DPORT`. Accept: integration test — mock server reads the PPv2 header **before** the ClientHello/DNS prefix, addrs != socket peer.

**PR6 — DoH over hyper h2 (the headline; reuses the proven core).** Add `hyper`, `hyper-util`, `http`, `http-body-util`, `base64`. `doh.rs`: per-conn task owns `SendRequest` + `FuturesUnordered` fed by mpsc (F1); §4.2 window/keepalive knobs; spawned driver; `ready()` gate (F2); GET/POST + `?token=`; full body drain + rcode/tc parse + HTTP-status classify (F6); GOAWAY/`--connection-reuse` drain (F7). CLI `--protocol doh --doh-path --doh-method get|post --token/--token-file`. Default pool `-c 32 -q 64` (F2). Accept: local h2 mock — one connection carries N concurrent streams, connection survives stream closes (guards terminate_session), long run does not stall (guards WINDOW_UPDATE), `-c 4 -q 50` >> 1490 QPS on loopback.

**PR7 — Metrics: NDJSON + final summary; drain/cancel polish.** `ndjson.rs` interval + summary lines (core json helpers), keep `DnsRunStats` field names, add `goaway_count/reconnects/in_flight_peak`. Ctrl-C mid-run yields a valid `cancelled:true` summary. Accept: percentile correctness vs known input; NDJSON schema snapshot.

**PR8 — Cutover + auto-ladder.** `wiresurge load` default for dot/doh/do53; ladder climbs `-c`/`-q` to find the timeout cliff. Deprecate `run_dns`/`LatencyHistogram` once parity is reached. Accept: end-to-end NDJSON + summary; ladder identifies the ceiling.

---

## 11. Build for aarch64 + deploy/run the ladder on the load-gen (validate >= 20k)

Build (from package dirs; per Brazil/standard rules use the gnu triple for the AL2023 target, musl as fallback):
```bash
# from the workspace root (cargo workspace, not Brazil here)
rustup target add aarch64-unknown-linux-gnu
cargo build --release --locked --target aarch64-unknown-linux-gnu -p wiresurge-cli \
  > /tmp/wiresurge-build.log 2>&1 && tail -n 20 /tmp/wiresurge-build.log
# musl fallback (deny.toml target) if gnu libc mismatch on AL2023:
#   rustup target add aarch64-unknown-linux-musl
#   cargo build --release --locked --target aarch64-unknown-linux-musl -p wiresurge-cli
ls -l target/aarch64-unknown-linux-gnu/release/wiresurge
cargo deny check && cargo tree --duplicates   # gate before shipping
```

Deploy via SSM to load-gen `i-04f95e498d3084dec` (acct 975049927136, us-west-2). Use ReadOnly/least-privilege creds per the production-safety rules; this is a load-gen host (test traffic), so confirm before any destructive action:
```bash
# stage the binary into S3 then pull on-host via SSM (no SSH key; SSM only)
aws s3 cp target/aarch64-unknown-linux-gnu/release/wiresurge \
  s3://<staging-bucket>/wiresurge --region us-west-2
aws ssm send-command --region us-west-2 \
  --instance-ids i-04f95e498d3084dec \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["aws s3 cp s3://<staging-bucket>/wiresurge /tmp/wiresurge","chmod +x /tmp/wiresurge","/tmp/wiresurge --help"]'
```

Run the DoH ladder on-host (PPv2 src 52.5.87.206 -> NLB VIP dst 10.216.20.227, TCP to pod 10.208.34.245:443), sweeping `-c`/`-q` and reading NDJSON QPS rather than trusting the formula:
```bash
aws ssm send-command --region us-west-2 --instance-ids i-04f95e498d3084dec \
  --document-name "AWS-RunShellScript" --parameters 'commands=[
  "for c in 16 32 48; do for q in 64 96; do \
     /tmp/wiresurge load 10.208.34.245:443 \
       --protocol doh --doh-path /dns-query --doh-method post \
       --proxy 52.5.87.206#0-10.216.20.227#443 \
       --token <TOKEN> --sni <SNI> --insecure \
       -f /tmp/corpus-1m.txt -R --type A \
       -c $c -q $q -t 2s -l 60 --output json --ndjson /tmp/doh-c$c-q$q.ndjson ; \
   done; done"]'
# success bar: avg_qps >= 20000 with <1% timeouts on at least one (c,q) cell.

# DoT comparison (token via EDNS 65184), same pool family:
/tmp/wiresurge load 10.208.34.245:853 --protocol dot --sni <SNI> --insecure \
  --proxy 52.5.87.206#0-10.216.20.227#853 --token <TOKEN> \
  -f /tmp/corpus-1m.txt -R --type A -c 64 -q 64 -t 2s -l 60 --output json
```
Validation: confirm one of the DoH `(c,q)` cells sustains `avg_qps >= 20000` at `<1%` timeouts in the NDJSON summary, and that DoT lands close behind. If a first DoH run underperforms, the likeliest cause (per the verdicts) is the peer stream cap — raise `-c` and lower `-q` rather than the reverse, and check the per-conn `ready()`-queue metric.
