# WireSurge

WireSurge is a local-first desktop and CLI tool for API exploration, protocol workflows, and high-rate traffic generation.

Open [architecture.html](./architecture.html) in a browser to read the full plan.

## Current Implementation

This repository now contains the first Rust workspace scaffold:

- `crates/core`: schemas, request model, redaction, structured errors.
- `crates/cli`: the `wiresurge` agent-friendly CLI.
- `crates/engine`: request execution orchestration, runner heartbeat, reports.
- `crates/http`: std-only HTTP/1.1 runner for local HTTP targets.
- `crates/metrics`: runner, worker, and report summary models.
- `crates/storage`: local `.wiresurge` workspace storage.
- `crates/dns`: DNS/EDNS0 messages via NLnet Labs `domain`, plus WireSurge-owned UDP/TCP execution.
- `crates/plugins`: plugin manifest draft types.

## Quick Start

```sh
cargo run -p wiresurge-cli -- workspace init
cargo run -p wiresurge-cli -- request create --json '{"id":"req-local","name":"Local","url":"http://127.0.0.1:8080"}'
cargo run -p wiresurge-cli -- request list --output json
cargo run -p wiresurge-cli -- run req-local --output json --dry-run
```

DNS over UDP and TCP:

```sh
cargo run -p wiresurge-cli -- dns 127.0.0.1 --name example.com --type A
cargo run -p wiresurge-cli -- dns 127.0.0.1 --protocol tcp --count 1000 --concurrency 8 --qps 500 --output json
```

Each DNS sender owns one connected UDP socket or one reusable TCP connection. Runs report send/receive counts, timeouts, errors, response codes, truncation, throughput, and fixed-memory latency percentiles. Ctrl-C and SIGTERM request cooperative shutdown.

External dependencies follow [the dependency policy](./docs/dependency-policy.md): narrow established libraries, minimal features, exact direct pins, a committed lockfile, and automated advisory/license/source checks.

Run tests:

```sh
cargo test --workspace --locked
```

Live localhost transport tests are marked as integration tests and run in CI with:

```sh
cargo test --workspace -- --ignored
```

The static UI shell is available at [apps/web/index.html](./apps/web/index.html), including the planned Runners section.
