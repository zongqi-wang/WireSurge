# Current Implementation

The repository implements a usable Rust CLI foundation: local request storage, single-request HTTP execution, and a many-in-flight DNS load engine with live terminal progress. It does **not** yet implement the desktop application, scenario compiler, or full supervised engine described in the architecture chapters.

## Workspace Status

| Area | Current behavior | Important limits |
|---|---|---|
| `crates/core` | Serde-backed JSON/YAML request parsing, structured errors with field paths, ID generation, and output redaction. | The typed model still covers only the current flat request format, not the target scenario schema. JSONC comments are not accepted. |
| `crates/cli` | `clap` derive parsing; human-oriented help, suggestions, and terminal color; `schema`, `workspace`, request CRUD, `run`, `load`, runner/report reads, structured JSON errors, and a plugin manifest example. Load runs have a human banner, live TTY samples, a labeled summary, and per-connection results. | Secrets return `not_implemented`; report export is reserved; there is no internal IPC engine mode. |
| `crates/corpus` | Memory-mapped query-name corpus with sequential, random, and seeded-permutation selection for the load engine. | No directory watching, incremental loading, or streaming support. |
| `crates/http` | Async pooled Hyper client for HTTP/1.1, HTTP/2, HTTP and rustls HTTPS; decoded bodies, response limits, timing, redirects-as-results, and redaction. | Redirect following remains intentionally disabled. Each current engine run sends one request, so the pool becomes useful when multi-request execution lands. |
| `crates/dns` | DNS/EDNS0 messages via `hickory-proto` plus a protocol-agnostic `Transport`/`Connection` trait with many-in-flight Do53 UDP/TCP, DoT, and DoH connections (txid demux for Do53/DoT, HTTP/2 stream binding for DoH). | DNS-over-QUIC and scenario-step integration are not implemented. The query corpus is DNS names only. |
| `crates/engine` | Async orchestration for one stored or file-based HTTP request, dry runs, runner snapshots, and optional reports. The `load` module drives the many-in-flight DNS load engine across all transports. | `--parallel` is accepted but does not send parallel HTTP requests. There is no supervisor, ladder, task tree, or durable connection manager. |
| `crates/metrics` | Runner, worker, report, `RunSnapshot`, and aggregate models plus the `hdrhistogram`-backed `LoadRecorder`. Load progress merges per-connection histograms at a configured interval and emits a final snapshot. | The progress stream is process-local and opt-in; it is not persisted or exposed through IPC. Runner snapshots are still file snapshots rather than a continuously updated aggregation service. |
| `crates/transport` | `ConnectTarget`, rustls/ring TLS client config (ALPN, SNI, relaxed-ALPN, resumption), TCP/UDP/TLS connect helpers, and PROXY protocol v2 stream/datagram framing. | Load connections are owned for one run and are not reconnected after failure or reused across runs. |
| `crates/storage` | Local `.wiresurge` directories, YAML request files, runner JSON snapshots, and JSON/HTML report files. | No SQLite, keychain, crash-recovery journal, or content-addressed report assets. |
| `crates/plugins` | Draft manifest and capability types. | No plugin loader, WASM host, sandbox, registry, or ABI. |
| `apps/web` | Static HTML/CSS UI shell, including the proposed Runners view. | It is not a React application and is not wired to an engine. |
| `apps/desktop` | A README reserves the Tauri shell boundary. | No desktop application exists yet. |

## CLI Contract

The current command surface is:

```text
wiresurge schema <workspace|request|environment|scenario|run|report|runner>
wiresurge load <server> [--protocol udp|tcp|dot|doh] [--name <domain>|--corpus <file>] [--type <qtype>] [-c <conns>] [-q <in-flight>] (--count <n>|-l <secs>)
wiresurge workspace init|list|show [--output json]
wiresurge request create --json '{...}'
wiresurge request list|show|update|delete
wiresurge run <request-id|request.yaml> [--output json] [--report <dir>]
wiresurge runner list|stats [--output json]
wiresurge report list|show|export
wiresurge secret set|get|delete
wiresurge plugin manifest-example
```

`clap` rejects unknown flags, missing values, and malformed numeric inputs. Human mode provides discoverable help and suggestions. When `--output json` or `--output=json` is used, parse failures and command failures use the same structured envelope with `code`, `message`, `path`, `hint`, and `retryable` fields. Non-interactive commands do not prompt.

For `load`, human mode sends the run banner and optional live samples to stderr and the final summary to stdout. Live samples are enabled only on a TTY, can be disabled with `--no-progress`, and default to `--progress-interval 1000`; intervals below 50 ms are clamped. JSON mode disables the banner and progress, keeps stderr empty on success, and returns aggregate counters, NOERROR and receive rates, rcode counts, latency, cancellation state, and one worker record per connection.

## Quick Start

```sh
cargo run -p wiresurge-cli -- workspace init
cargo run -p wiresurge-cli -- request create --json \
  '{"id":"req-local","name":"Local","url":"http://127.0.0.1:8080"}'
cargo run -p wiresurge-cli -- request list --output json
cargo run -p wiresurge-cli -- run req-local --output json --dry-run
```

High-rate DNS load over Do53 (UDP/TCP), DoT, and DoH:

```sh
cargo run -p wiresurge-cli -- load 127.0.0.1 --name example.com --type A --count 1000
cargo run -p wiresurge-cli -- load 127.0.0.1 --protocol tcp \
  -c 8 -q 64 --count 1000 --qps 500 --output json
cargo run -p wiresurge-cli -- load 127.0.0.1 --protocol dot \
  --sni dns.example --edns-option 65001:cafe -l 10 --output json
cargo run -p wiresurge-cli -- load 127.0.0.1 --protocol doh \
  --url https://dns.example/dns-query --http-param key=value -l 10 --output json
```

`-c` sets connections, `-q` the in-flight queries per connection; exactly one of `--count` and `-l`/`--duration-s` is required. `--edns-option CODE:HEX` attaches a repeatable EDNS0 OPT option to every query (decimal code, hex payload, `dig +ednsopt` parity); `--http-param KEY=VALUE` appends repeatable DoH URL query parameters and is rejected on non-DoH protocols. `--proxy-src` and `--proxy-dst` enable PROXY v2 together: a stream preamble for TCP/DoT/DoH or a per-datagram prefix for UDP.

See [Load Engine](load-engine.md) for transport ownership, scheduling, output fields, and current limitations.

## Verification

```sh
cargo test --workspace --locked
cargo test --workspace --locked -- --ignored
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
mdbook build
```

The ignored tests bind localhost UDP, TCP, TLS, and HTTP/2 fixtures. CI runs the full command set above.
