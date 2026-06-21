# Load Engine Plan

Design for the asynchronous load engine, targeting >= 20k QPS DoH. This is a
design document; concrete types, signatures, and dependency pins live in the
source tree and `Cargo.toml`, not here.

## Backbone decision

The structural backbone is a protocol-agnostic `Transport` trait + a per-connection actor + a `FuturesUnordered` multiplexer. DoT lands first so the engine is validated on a hand-built txid demux before the riskier hyper H2 work, and default knobs are sized with Little's Law. The load-bearing design constraints for 20k QPS:

- **No shared `&mut` connection.** `hyper`'s `SendRequest` is `&mut self` / `Clone`, so every DoH connection gets its own task that owns `SendRequest` + a `FuturesUnordered`, fed by an `mpsc` — the same channel-split shape as the DoT actor. Submit and collect never share a `&mut Conn`.
- **Honor the peer stream cap.** Gate every DoH submission on connection readiness, clamp effective per-conn depth to `min(-q, live peer SETTINGS_MAX_CONCURRENT_STREAMS)`, and never count an over-cap RST as a query error. Default pool shape `-c 32 × -q 64` keeps average streams/conn under the documented `max_streams: 100` (see [Data and Connections](architecture/data-and-connections.md)).
- **One semaphore per connection** of size `-q` (or a single global of size `c*q`), never one shared semaphore of size `-q` — that would cap total in-flight 16× low.
- **`ring` requires an ADR.** It ships native code + a build script, which the [Dependency Policy](dependency-policy.md) requires an ADR for ([ADR 0001](adr/0001-ring-crypto-provider.md)). Its `ISC`/OpenSSL-style license terms are added to the `deny.toml` `[licenses] allow` list, or the `confidence-threshold = 0.93` gate fails.
- **DoH `exchange` fully drains the response body** (so hyper auto-emits `WINDOW_UPDATE`), parses the DNS body for rcode/tc, and treats HTTP status != 200 (e.g. 403 bad token) distinctly from a DNS error.
- **Bounded reconnect.** GOAWAY/connection-closed reconnect uses bounded backoff + a per-actor reconnect-rate cap; in-flight requests on a dead connection are recorded as errors, never silently dropped (which would inflate apparent QPS).
- **No `async-trait`.** The trait uses native RPITIT `async fn` with explicit `+ Send` return bounds (avoids an extra dep, per-call `Box`, and cargo-deny surface). The engine is generic over `T: Transport`, monomorphized per protocol.

## Crate / module layout

Existing crates and their public APIs stay intact. The synchronous `run_dns` path stays untouched and green; the async engine is additive behind a Cargo feature and a new `wiresurge load` subcommand, then becomes the default high-rate path at cutover.

- **`transport`** (new) — shared connection seam: `ConnectTarget`/`BoxedStream`, rustls `ClientConfig` builders (ring provider, ALPN, SNI, resumption, relaxed-ALPN), hand-rolled PROXY-protocol-v2 encoder, and `connect_with_ppv2` (TCP dial → PPv2 → optional TLS).
- **`corpus`** (new) — mmap newline file + offset table + selection (`-R`); seeded permutation for visit-each-once.
- **`dns`** (grow) — keep the existing sync path and parse helpers public; add a `Transport` trait + request/response/error/caps types and per-protocol implementations: UDP and TCP (Do53), DoT, DoH.
- **`engine`** (grow) — `LoadConfig`/`run_load`, the `WorkSource` scheduler (rate credits, depth, duration, count, randomize), the per-connection actor, and the connection pool.
- **`metrics`** (grow) — keep existing JSON shapes; add an hdrhistogram-backed per-actor recorder merged off the hot path, and an NDJSON emitter.
- **`cli`** (grow) — new `load` subcommand + explicit tokio runtime builder.
- **`http`, `core`, `plugins`, `storage`** — unchanged.

## The async in-flight pipeline

The current sync path serializes each query (send-then-recv), so max QPS = `workers / RTT`. The new pipeline keeps `-q` requests outstanding **per connection**, multiplied across `-c` connections.

- **Do53-UDP** — one connected `UdpSocket`. A dedicated reader task dispatches each datagram by txid into a slab of `oneshot` senders. `exchange()` allocates a txid, sends, and awaits its receiver under a timeout; on timeout the slab entry is reaped so the actor slot reopens. Many `exchange` futures coexist.
- **Do53-TCP & DoT** — channel-split actor over `tokio::io::split`. A writer task drains an mpsc, allocates a per-connection txid from a slab (unique within the outstanding window), and writes `[u16 len][msg]` without ever awaiting a read. A reader task parses each framed message's txid and rcode/tc and completes the matching `oneshot`. DoT negotiates ALPN `dot`.
- **DoH** — each connection is its own task owning `SendRequest` + a `FuturesUnordered`, fed by an mpsc. `exchange(&self)` only pushes to the mpsc and awaits a oneshot, so concurrent calls never touch `SendRequest` directly. The connection driver future is spawned separately and owns `WINDOW_UPDATE`/`GOAWAY`/`PING`.

Throughput (Little's Law): `QPS = c × min(q, peer_streams) / RTT`. The default `-c 32 × -q 64` gives ~136k at a 15ms saturated-pod RTT — comfortable headroom over 20k. Validated empirically, not by trusting the formula.

## hyper / rustls / tokio tuning

- **rustls** (shared by DoT + DoH) — ring provider selected explicitly; safe default protocol versions (TLS 1.3 + 1.2, since CoreDNS `customtls` may need 1.2); ALPN per protocol (`dot` / `h2`); SNI from the target; in-memory session resumption for cheap reconnects. An `--insecure` flag swaps in a relaxed cert verifier. **Relaxed-ALPN:** if the peer omits ALPN and `--alpn-relaxed` is set, assume the configured protocol; a *conflicting* protocol is a hard error.
- **hyper H2** (per connection) — adaptive flow-control window with a 16 MiB connection window (avoids the 64KB-default stall) and 2 MiB per stream; no retained reset streams; PING keepalive across bursts. A finished stream only frees a multiplexer slot — nothing tears down the session. Connections die only on driver error, GOAWAY, or `--connection-reuse`. Each response body is fully drained so hyper releases flow-control credit. The peer's `SETTINGS_MAX_CONCURRENT_STREAMS` is honored via send-readiness backpressure plus a pool default that keeps streams/conn well under `max_streams: 100`.
- **Default pool shape** — `-c 32 -q 64` for DoH (capacity ~2048), `-c 64 -q 64` for DoT. Knobs are first-class; the auto-ladder climbs `-c`/`-q` to find the true ceiling.
- **tokio runtime** — explicit multi-thread builder (not `#[tokio::main]`), worker threads capped with headroom for the driver/crypto/aggregator, a small blocking pool for corpus scan + report writes. CPU is not the 20k ceiling; the pod/NLB is. The TCP connector sets `set_nodelay(true)` (Nagle would add an RTT to latency-sensitive DNS).

## PPv2 connector seam + token lowering

The TCP target is the **pod IP**; the PPv2 src/dst are the **mocked customer src + NLB VIP dst**, independent of the socket peer. So PPv2 must be the **first bytes on the freshly connected TCP stream, before any TLS ClientHello or DNS bytes**. The engine drives the H2 handshake on its own already-PPv2+TLS-wrapped stream, rather than a pooling HTTP client that would hide byte ordering and connection identity.

The PPv2 v2 encoder is hand-rolled (the dependency policy permits a small well-contained helper; a reviewed crate is the fallback). TCPv4 header layout:

```
sig (12): 0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A
[12] 0x21              ver 2 | PROXY cmd
[13] 0x11              AF_INET | STREAM
[14..16] 0x00 0x0C     addr block len = 12
[16..20] src.ip        (MOCKED, independent of tcp_addr)
[20..24] dst.ip        (NLB VIP)
[24..26] src.port BE
[26..28] dst.port BE
```

IPv6 uses family `0x21` and a 36-byte addr block. CLI: `--proxy SRC#SPORT-DST#DPORT`.

**Token lowering** — one logical `--token`, different wire placement:

- **Do53 / DoT:** EDNS0 OPT code **65184 (0xFEA0)**, value = ASCII token bytes, baked into every query via the existing configurable-code path. No new DNS codec.
- **DoH:** token in the **URL query** `?token=<percent-encoded>`, baked into the request path once at connection build time (the hot path just clones). The DNS body carries no token. POST (default) sends the raw `application/dns-message` wire; GET sends `&dns=<base64url-no-pad(wire)>`.

Validation rejects `--token` on plain UDP sync transport and ignores `--edns-code` for DoH.

## Drain / cancellation ordering

`drain(grace)` for both transports: (1) stop topping up; (2) await in-flight to completion, bounded by `grace`; (3) DoH drops `SendRequest` so the driver finishes outstanding streams and emits GOAWAY, then joins the driver task — DoT/Do53 flush the writer, shut down the write half, and read remaining responses until grace.

On a per-query DoH timeout, dropping the response future RSTs/cancels that stream so it does not linger against `MAX_CONCURRENT_STREAMS` over a long run. Late responses after a DoT timeout are treated as stray (slab entry already reaped), never double-releasing a slot. SIGINT/SIGTERM route through `tokio::signal` into a `CancellationToken` checked inside the `exchange` timeout select — not only at the submit loop — so the deadline stops outstanding waits immediately rather than waiting up to `--timeout`.

## Corpus mmap + selection

The corpus is mmap'd and indexed by a one-time newline scan (memchr) on a blocking thread **before** the run clock starts, so large files never produce a "0 queries" run. Workers hold only an index + an `Arc<Corpus>` — memory is not workers × corpus — and read zero-copy `&str` slices that never outlive the map. Selection modes: sequential, random-with-replacement (allocation-free), and seeded permutation (visit-each-once, no 1M-entry Vec). A 32-bit offset pair caps a single file at < 4 GiB (fine for 1M rows).

## NDJSON metrics

A per-actor hdrhistogram recorder (microseconds, 3 significant figures) is merged into an aggregate via mpsc roughly every 250ms by one aggregator task — no shared hot lock at 20k+/s. This replaces the coarse power-of-two latency histogram, giving true p50/p95/p99/p999.

NDJSON is built with the existing `wiresurge_core` json helpers (no `serde_json`):

```jsonc
// per --interval (live): {"ts":..., "period_s":0.25, "sent":..., "received":..., "timeouts":..., "errors":...,
//   "qps":..., "rps":..., "min_ms":..., "p50_ms":..., "p95_ms":..., "p99_ms":..., "max_ms":...,
//   "in_flight":..., "open_conns":..., "rcode":{...}, "http_status":{...}}
// final: {"summary":true, "duration_s":..., full percentiles, "goaway_count":..., "reconnects":..., "cancelled":...}
```

The final summary keeps the existing `DnsRunStats` field names plus `conns/streams/in_flight_peak/goaway_count/reconnects`, so downstream tooling and `wiresurge report` keep working.

## Dependencies

New crates are declared once in root `[workspace.dependencies]`, pinned to exact reviewed versions, consumed with `workspace = true`, and gated on `cargo deny check` + `cargo tree --duplicates`:

- **Async runtime** — `tokio` (multi-thread, net, time, sync, signal, io-util), `tokio-util` (`CancellationToken`), `futures-util` (`FuturesUnordered`), `bytes`.
- **TLS** — `rustls` and `tokio-rustls` (both with the `ring` and `tls12` features), `rustls-native-certs` for the OS trust store. `rustls-pki-types` comes transitively. See [ADR 0001](adr/0001-ring-crypto-provider.md).
- **DoH** — `hyper` + `hyper-util` (h2 only, no http1, no legacy pooling client), `http`, `http-body-util`, `base64` (GET base64url).
- **Corpus / metrics** — `memmap2`, `hdrhistogram` (no flate2/serde features). Both are build-script-free / pure-Rust.

Single `rustls` in the tree (own connector, no `hyper-rustls`). `ring` (not `aws-lc-rs`) avoids a second native-build ADR and builds clean on `aarch64-unknown-linux-musl`. `domain` 0.12.1 std-only stays as the DNS codec.

## Validation

The load binary is built for `aarch64` and run against the target pod, sweeping `-c`/`-q`. Success bar: at least one `(c, q)` cell sustains `avg_qps >= 20000` at `<1%` timeouts in the NDJSON summary, with DoT close behind. If a DoH run underperforms, the likeliest cause is the peer stream cap — raise `-c` and lower `-q`, and check the per-conn readiness-queue metric.

Build commands, deploy steps, and the concrete target/host details live in a local-only runbook (`docs-local/load-gen-runbook.md`, git-ignored) and are not part of this public document.
