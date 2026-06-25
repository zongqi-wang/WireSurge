# Load Engine

This chapter describes the DNS load engine implemented by `wiresurge load`.
Future scenario compilation, auto-ladder scheduling, and desktop IPC are covered
by the [Implementation Plan](implementation-plan.md) and are not part of this
contract.

## Command Contract

```text
wiresurge load <server>
  [--protocol udp|tcp|dot|doh]
  [--name <domain> | --corpus <newline-file>]
  [--type <qtype>]
  [-c <connections>]
  [-q <in-flight-per-connection>]
  (--count <queries> | -l <seconds>)
  [--qps <process-wide-cap>]
  [--timeout-ms <milliseconds>]
```

The default protocol is UDP, with 32 connections and 64 in-flight queries per
connection. Exactly one count or duration stop condition is required. The
process-wide `--qps` cap and stop budget are shared by every connection.

DoH additionally requires an HTTPS `--url`; its host supplies the HTTP
authority and default SNI while `<server>` remains the socket peer. POST is the
default. `--doh-method get` sends the DNS message through the `dns` query
parameter using unpadded base64url.

Run `wiresurge load --help` for all TLS, EDNS, HTTP-parameter, corpus, PROXY,
and progress options.

## Ownership And Scheduling

`LoadConfig` is validated before traffic starts. The engine then:

1. Memory-maps or owns the corpus and encodes one DNS message per corpus row.
2. Creates one atomic work source for the count, deadline, rate cap, and corpus
   selection index.
3. Starts one Tokio task per connection.
4. Gives each task one transport connection and a `FuturesUnordered` set capped
   by the smaller of `-q` and the transport's local capacity.
5. Merges the connection-local recorders after all actors finish.

There is no shared mutable connection. Each actor owns one connected UDP socket,
TCP stream, TLS stream, or HTTP/2 sender. The work source uses one atomic query
index, so the requested count is not multiplied by the number of connections.
The rate gate schedules index `n` at `start + n / qps` and is also process-wide.

## Transport Behavior

| Protocol | Correlation | Local maximum in flight | Notes |
|---|---|---:|---|
| Do53 UDP | DNS transaction ID | 1024 | One connected socket and a reader task per actor. |
| Do53 TCP | DNS transaction ID | 256 | Length-prefixed messages over split reader/writer tasks. |
| DoT | DNS transaction ID | 256 | The framed TCP model over rustls with ALPN `dot`. |
| DoH | HTTP/2 stream | 256 | Low-level Hyper HTTP/2 connection; DNS ID remains zero. |

The requested `-q` is clamped to these local limits. Hyper also applies peer
HTTP/2 readiness and stream limits. DoH accepts any 2xx response with a valid
DNS body; other HTTP statuses are query errors.

Each actor connects once. A failed initial connection increments
`conn_errors`; a connection that closes during a run stops receiving new work.
Automatic reconnect and backoff are not implemented.

## Corpus Selection

`--corpus` memory-maps a newline-delimited file and creates byte-range indexes.
Blank lines are skipped, CRLF is accepted, and the corpus must contain at least
one row. DNS messages are encoded once before the run clock starts, then shared
by reference; the transport copies only the selected message and assigns the
transaction ID at send time.

The default mode walks rows sequentially and wraps. `--randomize` samples with
replacement using `--seed`. The corpus crate also implements an allocation-free
seeded permutation, but the CLI does not expose that mode yet.

## TLS, EDNS Options, And PROXY V2

DoT and DoH use rustls with the `ring` provider and native certificate roots.
SNI is configurable, and `--alpn-relaxed` permits a peer that omits ALPN while
still rejecting a conflicting protocol. `--insecure` disables certificate
verification and is intended only for controlled self-signed targets.

`--edns-option CODE:HEX` attaches an EDNS0 OPT option to every query. `CODE` is
a decimal `u16` and the payload is hex-encoded, matching `dig +ednsopt=CODE:HEX`
(OPT data is opaque binary per RFC 6891 §6.1.2). The flag is repeatable, so one
query can carry several options, including repeats of a single code. This is the
mechanism for any caller-defined OPT option: place the payload bytes under
whichever code the target expects.

`--http-param KEY=VALUE` appends a percent-encoded query parameter to the DoH
request URL; it is repeatable and rejected on any non-DoH protocol. The reserved
`dns` key is refused because the adapter owns the per-query `?dns=` payload.

`--proxy-src` and `--proxy-dst` must be supplied together, use the same IP
family, and describe metadata independently of the socket peer. WireSurge emits
PROXY protocol v2 as the first bytes on TCP/DoT/DoH connections or as a prefix
on every UDP datagram. Stream headers precede the TLS ClientHello.

## Metrics And Output

Each connection records sent and received counts, timeouts, query errors,
connection errors, truncated responses, received bytes, rcodes, and latency in
an HDR histogram. A NOERROR rate is reported separately from total receive rate
so fast error responses do not look like successful resolution throughput.

Human mode uses three output layers:

- A target, budget, and connection banner on stderr.
- Periodic cumulative samples on stderr when stderr is a TTY.
- A final aggregate summary and per-connection table on stdout.

`--no-progress` disables periodic samples. `--progress-interval` defaults to
1000 ms and is clamped to at least 50 ms because sampling clones and merges each
connection histogram. Samples are a scrolling log, not an in-place terminal
animation.

`--output json` disables all human and progress output. On success, stdout is
one JSON value and stderr is empty. The result includes:

```text
duration_s, sent, received, timeouts, errors, conn_errors, truncated,
recv_qps, noerror_qps, rcodes, latency_ms, workers, cancelled
```

The library's opt-in `run_load_with_progress` API publishes `RunSnapshot`
values through a Tokio watch channel. Each snapshot contains elapsed time,
aggregate metrics, and one `WorkerStats` record per connection; the final frame
is marked with `final_sample`. This is process-local latest-value delivery, not
an NDJSON stream, persistent history, or sidecar IPC protocol.

## Cancellation And Limits

Ctrl-C and SIGTERM cancel the shared token. Actors stop requesting work, collect
completed in-flight exchanges for up to 250 ms, invoke the transport drain hook,
and return final metrics. The CLI marks the run cancelled and returns the
signal-derived exit code.

Current limitations:

- No reconnect, auto-ladder, or cross-run connection reuse.
- No persisted load profile or load report.
- No sidecar IPC or durable live-metric history.
- No DNS-over-QUIC.
- No desktop safety allowlist or public-target confirmation flow.
- Progress sampling is enabled by the human TTY path only; JSON mode is final
  output only.

## Verification

Unit and integration coverage includes count/depth behavior, DoH, progress and
final snapshots, per-connection metrics, PROXY v2 framing, and stdout/stderr
separation. Run:

```sh
cargo test --workspace --locked
cargo test --workspace --locked -- --ignored
```

The ignored suite binds local UDP, TCP, TLS, and HTTP/2 fixtures.
