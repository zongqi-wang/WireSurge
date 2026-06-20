# Current Implementation

The repository is an early Rust workspace scaffold. It validates the CLI and storage shape, implements a plain HTTP runner and a more capable DNS runner, and establishes report and runner data models. It does **not** yet implement the supervised async engine described in the architecture chapters.

## Workspace Status

| Area | Current behavior | Important limits |
|---|---|---|
| `crates/core` | Request schema, a small JSON/JSONC parser, request YAML serialization, structured errors, ID generation, and basic redaction. | The custom JSON/YAML implementation is replacement work under the library-first tenet. The YAML reader only handles the current flat request format. |
| `crates/cli` | `clap` derive parsing; human-oriented help, suggestions, and terminal color; `schema`, `workspace`, request CRUD, `run`, `dns`, runner/report reads, structured JSON errors, and a plugin manifest example. | Secrets return `not_implemented`; report export is reserved; there is no internal IPC engine mode. |
| `crates/http` | One blocking HTTP/1.1 request to an `http://` target with response status, headers, body, timing, and redaction. | The custom wire parser is replacement work. There is no HTTPS, HTTP/2, redirect following, pooling, chunk decoding, or real parallel execution. Each run sends one request. |
| `crates/dns` | DNS messages and EDNS0 via NLnet Labs `domain`; UDP/TCP execution with concurrent senders, optional QPS pacing, timeouts, caller-selected EDNS option codes, reusable TCP connections, latency percentiles, and cooperative signal cancellation. | Transport, signal, and histogram code is currently custom and synchronous. There is no DNS-over-TLS, DNS-over-HTTPS, workflow stage integration, or async runtime. |
| `crates/engine` | Orchestrates one stored or file-based HTTP request, dry runs, runner snapshots, and optional reports. | `--parallel` is accepted but does not send parallel HTTP requests. There is no supervisor, scheduler, ladder, task tree, or connection manager. |
| `crates/metrics` | Runner, worker, and single-request report summary models. | Metrics are snapshots rather than a live aggregation pipeline. |
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

`clap` rejects unknown flags, missing values, and malformed numeric inputs. Human mode provides discoverable help and suggestions. When `--output json` or `--output=json` is used, parse failures and domain failures use the same structured envelope with `code`, `message`, `path`, `hint`, and `retryable` fields. Non-interactive commands do not prompt.

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
