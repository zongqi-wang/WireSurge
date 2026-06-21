# Current Implementation

The repository is an early Rust workspace scaffold. It validates the CLI and storage shape, implements an async HTTP runner and a many-in-flight DNS load engine, and establishes report and runner data models. It does **not** yet implement the full supervised engine described in the architecture chapters.

## Workspace Status

| Area | Current behavior | Important limits |
|---|---|---|
| `crates/core` | Serde-backed JSON/YAML request parsing, structured errors with field paths, ID generation, and output redaction. | The typed model still covers only the current flat request format, not the target workflow schema. JSONC comments are not accepted. |
| `crates/cli` | `clap` derive parsing; human-oriented help, suggestions, and terminal color; `schema`, `workspace`, request CRUD, `run`, `load`, runner/report reads, structured JSON errors, and a plugin manifest example. | Secrets return `not_implemented`; report export is reserved; there is no internal IPC engine mode. |
| `crates/corpus` | Memory-mapped query-name corpus with sequential, random, and seeded-permutation selection for the load engine. | No directory watching, incremental loading, or streaming support. |
| `crates/http` | Async pooled Hyper client for HTTP/1.1, HTTP/2, HTTP and rustls HTTPS; decoded bodies, response limits, timing, redirects-as-results, and redaction. | Redirect following remains intentionally disabled. Each current engine run sends one request, so the pool becomes useful when multi-request execution lands. |
| `crates/dns` | DNS/EDNS0 messages via `hickory-proto` plus a protocol-agnostic `Transport`/`Connection` trait with many-in-flight Do53 UDP/TCP, DoT, and DoH connections (txid demux for Do53/DoT, HTTP/2 stream binding for DoH). | DNS-over-QUIC and workflow-stage integration are not implemented. The query corpus is DNS names only. |
| `crates/engine` | Async orchestration for one stored or file-based HTTP request, dry runs, runner snapshots, and optional reports. The `load` module drives the many-in-flight DNS load engine across all transports. | `--parallel` is accepted but does not send parallel HTTP requests. There is no supervisor, ladder, task tree, or durable connection manager. |
| `crates/metrics` | Runner, worker, and report models plus the `hdrhistogram`-backed `LoadRecorder` for async load metrics. | Metrics are post-run snapshots rather than a live aggregation pipeline. |
| `crates/transport` | `ConnectTarget`, rustls/ring TLS client config (ALPN, SNI, relaxed-ALPN, resumption), and `connect_tcp`/`connect_udp`/`connect_tls` helpers shared by the load engine. | No connection reuse tracking across runs. |
| `crates/storage` | Local `.wiresurge` directories, YAML request files, runner JSON snapshots, and JSON/HTML report files. | No SQLite, keychain, crash-recovery journal, or content-addressed report assets. |
| `crates/plugins` | Draft manifest and capability types. | No plugin loader, WASM host, sandbox, registry, or ABI. |
| `apps/web` | Static UI shell, including the proposed Runners view. | It is not wired to an engine. |
| `apps/desktop` | A README reserves the Tauri shell boundary. | No desktop application exists yet. |

## CLI Contract

The current command surface is:

```text
wiresurge schema <workspace|request|environment|workflow|run|report|runner>
wiresurge load <server> [--protocol udp|tcp|dot|doh] [--name <domain>] [--type <qtype>] [-c <conns>] [-q <in-flight>] [--count <n>|-l <secs>]
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
  --sni dns.example --token secret -l 10 --output json
cargo run -p wiresurge-cli -- load 127.0.0.1 --protocol doh \
  --url https://dns.example/dns-query -l 10 --output json
```

`-c` sets connections, `-q` the in-flight queries per connection; `--count` and `-l`/`--duration-s` are mutually exclusive stop conditions. `--token` rides EDNS option 65184 on DoT and the `?token=` URL query on DoH, and is rejected on cleartext UDP/TCP.

## Verification

```sh
cargo test --workspace --locked
cargo test --workspace --locked -- --ignored
```

The ignored tests bind localhost UDP, TCP, and TLS sockets and exercise live transports. CI runs both commands.
