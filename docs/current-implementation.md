# Current Implementation

The repository is an early Rust workspace scaffold. It validates the CLI and storage shape, implements async HTTP and DNS runners, and establishes report and runner data models. It does **not** yet implement the full supervised engine described in the architecture chapters.

## Workspace Status

| Area | Current behavior | Important limits |
|---|---|---|
| `crates/core` | Serde-backed JSON/YAML request parsing, structured errors with field paths, ID generation, and output redaction. | The typed model still covers only the current flat request format, not the target workflow schema. JSONC comments are not accepted. |
| `crates/cli` | `clap` derive parsing; human-oriented help, suggestions, and terminal color; `schema`, `workspace`, request CRUD, `run`, `dns`, runner/report reads, structured JSON errors, and a plugin manifest example. | Secrets return `not_implemented`; report export is reserved; there is no internal IPC engine mode. |
| `crates/corpus` | Memory-mapped request file library for the async load engine. | No directory watching, incremental loading, or streaming support. |
| `crates/http` | Async pooled Hyper client for HTTP/1.1, HTTP/2, HTTP and rustls HTTPS; decoded bodies, response limits, timing, redirects-as-results, and redaction. | Redirect following remains intentionally disabled. Each current engine run sends one request, so the pool becomes useful when multi-request execution lands. |
| `crates/dns` | DNS/EDNS0 via `hickory-proto`; Tokio UDP/TCP workers, QPS pacing, deadlines, late-datagram filtering, reusable TCP connections, HDR percentiles, and cancellation tokens. | There is no DNS-over-TLS, DNS-over-HTTPS, DNS-over-QUIC, or workflow stage integration. `hickory-net` is reserved for that transport phase. |
| `crates/engine` | Async orchestration for one stored or file-based HTTP request, dry runs, runner snapshots, and optional reports. `load` module drives many-in-flight requests via the async load engine. | `--parallel` is accepted but does not send parallel HTTP requests. There is no supervisor, ladder, task tree, or durable connection manager. |
| `crates/metrics` | Runner, worker, and report models plus bounded `hdrhistogram` latency aggregation and `LoadRecorder` for async load metrics. | Metrics are post-run snapshots rather than a live aggregation pipeline. |
| `crates/transport` | `ConnectTarget`, `connect_tcp`, and `connect_udp` helpers used by DNS and engine transport layers. | No connection reuse tracking beyond the DNS crate's own TCP pool. |
| `crates/storage` | Local `.wiresurge` directories, YAML request files, runner JSON snapshots, and JSON/HTML report files. | No SQLite, keychain, crash-recovery journal, or content-addressed report assets. |
| `crates/plugins` | Draft manifest and capability types. | No plugin loader, WASM host, sandbox, registry, or ABI. |
| `apps/web` | Static UI shell, including the proposed Runners view. | It is not wired to an engine. |
| `apps/desktop` | A README reserves the Tauri shell boundary. | No desktop application exists yet. |

## CLI Contract

The current command surface is:

```text
wiresurge schema <workspace|request|environment|workflow|run|report|runner>
wiresurge dns <server> [--protocol udp|tcp] [--name <domain>] [--type <qtype>]
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

DNS over UDP and TCP:

```sh
cargo run -p wiresurge-cli -- dns 127.0.0.1 --name example.com --type A
cargo run -p wiresurge-cli -- dns 127.0.0.1 --protocol tcp \
  --count 1000 --concurrency 8 --qps 500 --output json
cargo run -p wiresurge-cli -- dns 127.0.0.1 \
  --edns-code 65184 --edns-payload-hex cafe --output json
```

`--edns-code` is used only when `--edns-payload-hex` is present. The backward-compatible default code is 65001.

## Verification

```sh
cargo test --workspace --locked
cargo test --workspace --locked -- --ignored
```

The ignored tests bind localhost UDP and TCP sockets and exercise live transports. CI runs both commands.
