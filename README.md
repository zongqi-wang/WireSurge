# WireSurge

WireSurge is a local-first desktop and CLI tool for API exploration, protocol workflows, and high-rate traffic generation.

Read the [WireSurge Book](https://cedwang.dev/WireSurge/) for the consolidated architecture, current implementation status, policies, and roadmap. The Markdown source lives in [`docs/`](./docs/README.md) and is rendered with [mdBook](https://rust-lang.github.io/mdBook/).

## Current Implementation

This repository now contains the first Rust workspace scaffold:

- `crates/core`: schemas, request model, redaction, structured errors.
- `crates/cli`: the human-first `wiresurge` CLI, parsed by `clap`, with JSON machine mode.
- `crates/engine`: request execution orchestration, the many-in-flight load engine, runner heartbeat, reports.
- `crates/http`: pooled Hyper HTTP/1.1 and HTTP/2 client with rustls HTTPS.
- `crates/metrics`: runner, worker, and report summary models plus the load recorder.
- `crates/storage`: local `.wiresurge` workspace storage.
- `crates/dns`: DNS/EDNS0 messages via `hickory-proto` and a protocol-agnostic transport trait with Do53 UDP/TCP, DoT, and DoH connections.
- `crates/corpus`: memory-mapped query-name corpus with deterministic selection.
- `crates/transport`: `ConnectTarget`, rustls/ring TLS config, and the TCP/UDP/TLS connect helpers shared by the load engine.
- `crates/plugins`: plugin manifest draft types.

## Quick Start

```sh
cargo run -p wiresurge-cli -- workspace init
cargo run -p wiresurge-cli -- request create --json '{"id":"req-local","name":"Local","url":"http://127.0.0.1:8080"}'
cargo run -p wiresurge-cli -- request list --output json
cargo run -p wiresurge-cli -- run req-local --output json --dry-run
```

High-rate DNS load over Do53 (UDP/TCP), DoT, and DoH:

```sh
cargo run -p wiresurge-cli -- load 127.0.0.1 --name example.com --type A --count 1000
cargo run -p wiresurge-cli -- load 127.0.0.1 --protocol tcp -c 8 -q 64 --count 1000 --qps 500 --output json
cargo run -p wiresurge-cli -- load 127.0.0.1 --protocol dot --sni dns.example --token secret -l 10 --output json
cargo run -p wiresurge-cli -- load 127.0.0.1 --protocol doh --url https://dns.example/dns-query -l 10
```

Each connection (`-c`) keeps many queries in flight (`-q`) and pulls work from one shared, lock-free source so a process-wide `--qps` cap and `--count`/`-l` budget apply across all connections. Runs report send/receive counts, timeouts, errors, connection errors, truncation, throughput, and HDR latency percentiles. Ctrl-C and SIGTERM request cooperative Tokio cancellation.

External dependencies follow [the dependency policy](./docs/dependency-policy.md): narrow established libraries, minimal features, exact direct pins, a committed lockfile, and automated advisory/license/source checks.

Build the documentation locally with mdBook 0.5.3:

```sh
mdbook build
```

Run tests:

```sh
cargo test --workspace --locked
```

Live localhost transport tests are marked as integration tests and run in CI with:

```sh
cargo test --workspace -- --ignored
```

The static UI shell is available at [apps/web/index.html](./apps/web/index.html), including the planned Runners section.
