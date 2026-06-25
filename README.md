# WireSurge

[![CI](https://github.com/zongqi-wang/WireSurge/actions/workflows/ci.yml/badge.svg)](https://github.com/zongqi-wang/WireSurge/actions/workflows/ci.yml)

**WireSurge** is a local-first desktop and CLI tool for API exploration, protocol
workflows, and high-rate traffic generation. It pairs an API request workspace
with a controlled DNS load engine and a path toward composable protocol stages —
all running locally, with no account, cloud dependency, or telemetry.

Today the repository ships a native Rust CLI (`wiresurge`) and its engine
foundation. The desktop application, scenario compiler, and supervised engine
described in the architecture chapters are designed but not yet implemented; see
[Current Implementation](./docs/current-implementation.md) for exactly what is
shipped versus planned.

## Highlights

- **Many-in-flight DNS load engine** over Do53 (UDP/TCP), DoT, and DoH, with a
  shared lock-free work source, process-wide QPS pacing, and count/duration
  budgets.
- **Per-connection ownership** — each connection owns one socket and its own
  in-flight window; the requested query count is shared across all connections,
  not multiplied by them.
- **Human-first CLI** with discoverable help, suggestions, and terminal color,
  plus a stable `--output json` machine mode and structured error envelopes.
- **EDNS0 and PROXY v2** — attach arbitrary EDNS0 OPT options (`dig +ednsopt`
  parity) and emit PROXY protocol v2 on any transport.
- **HTTP/API requests** stored as local YAML, executed over a pooled Hyper
  HTTP/1.1 and HTTP/2 client with rustls HTTPS, with templating and redaction.
- **Reproducible builds** — a committed `Cargo.lock` plus `cargo-deny` checks
  for advisories, licenses, sources, and duplicate versions in CI.

## Requirements

- Rust **1.94.0** (pinned in [`rust-toolchain.toml`](./rust-toolchain.toml);
  `rustup` selects it automatically).
- [mdBook](https://rust-lang.github.io/mdBook/) **0.5.3**, only to build the
  documentation locally.

## Build and Install

```sh
# Build the whole workspace
cargo build --workspace --locked

# Run the CLI directly from source
cargo run -p wiresurge-cli -- --help

# Or install the binary onto your PATH
cargo install --path crates/cli --locked
```

The installed binary is named `wiresurge`. Examples below use `cargo run -p
wiresurge-cli --` so they work from a fresh checkout; substitute `wiresurge`
once installed.

## Quick Start

### API requests

```sh
cargo run -p wiresurge-cli -- workspace init
cargo run -p wiresurge-cli -- request create \
  --json '{"id":"req-local","name":"Local","url":"http://127.0.0.1:8080"}'
cargo run -p wiresurge-cli -- request list --output json
cargo run -p wiresurge-cli -- run req-local --output json --dry-run
```

### DNS load

```sh
# UDP, single name, fixed query count
cargo run -p wiresurge-cli -- load 127.0.0.1 --name example.com --type A --count 1000

# TCP, 8 connections x 64 in-flight, capped at 500 qps, JSON output
cargo run -p wiresurge-cli -- load 127.0.0.1 --protocol tcp \
  -c 8 -q 64 --count 1000 --qps 500 --output json

# DoT with a custom SNI and an EDNS0 option, for 10 seconds
cargo run -p wiresurge-cli -- load 127.0.0.1 --protocol dot \
  --sni dns.example --edns-option 65001:cafe -l 10 --output json

# DoH against an HTTPS endpoint, with an extra URL query parameter
cargo run -p wiresurge-cli -- load 127.0.0.1 --protocol doh \
  --url https://dns.example/dns-query --http-param key=value -l 10 --output json
```

Each connection (`-c`) keeps many queries in flight (`-q`) and pulls work from
one shared, lock-free source, so the process-wide `--qps` cap and the
`--count`/`-l` budget apply across all connections. Human mode prints a
target/budget banner, TTY-only live samples, a final summary, and a
per-connection table on completion. `--output json` writes one JSON value to
stdout and suppresses all progress. Ctrl-C and SIGTERM request cooperative
cancellation and return a signal-derived exit code.

## CLI Overview

| Command | Purpose |
|---|---|
| `wiresurge schema <resource>` | Print the JSON shape accepted by a resource (`workspace`, `request`, `environment`, `scenario`, `run`, `report`, `runner`). |
| `wiresurge load <server>` | Generate DNS load over UDP/TCP/DoT/DoH. |
| `wiresurge workspace init\|list\|show` | Manage the local `.wiresurge` workspace. |
| `wiresurge request create\|list\|show\|update\|delete` | CRUD for stored HTTP requests. |
| `wiresurge run <id\|file.yaml>` | Execute a stored request or a request/scenario file. |
| `wiresurge runner list\|stats` | Read local runner snapshots. |
| `wiresurge report list\|show` | Read local run reports. |
| `wiresurge secret`, `wiresurge plugin` | Reserved surfaces (secrets are planned; `plugin manifest-example` prints the draft manifest). |

Key `load` flags (run `wiresurge load --help` for the full list):

| Flag | Default | Meaning |
|---|---|---|
| `--protocol udp\|tcp\|dot\|doh` | `udp` | DNS transport. |
| `-c`, `--concurrency` | `32` | Connections, each with its own socket and in-flight window. |
| `-q`, `--in-flight` | `64` | In-flight queries per connection (clamped to the transport limit: 1024 UDP, 256 TCP/DoT/DoH). |
| `--count` / `-l`, `--duration-s` | — | Stop condition; exactly one is required. |
| `--qps` | unset | Process-wide query rate cap; unset means as fast as the target allows. |
| `--timeout-ms` | `2000` | Per-query timeout. |
| `--name` / `--corpus` | `example.com` | A single query name or a newline-delimited corpus file. |
| `--edns-option CODE:HEX` | — | Repeatable EDNS0 OPT option (decimal code, hex payload). |
| `--http-param KEY=VALUE` | — | Repeatable DoH URL query parameter (DoH only). |
| `--proxy-src` / `--proxy-dst` | — | PROXY protocol v2 source/destination; set both together. |
| `--sni`, `--alpn-relaxed`, `--insecure` | — | TLS controls for DoT/DoH. |

See the [Load Engine](./docs/load-engine.md) reference for transport ownership,
scheduling, output fields, and current limitations.

## Documentation

The consolidated architecture, implementation status, policies, and roadmap live
in the **[WireSurge Book](https://cedwang.dev/WireSurge/)**. The Markdown source
is under [`docs/`](./docs/README.md) and is rendered with mdBook 0.5.3:

```sh
mdbook build          # render to ./book
mdbook serve --open   # live-reloading local preview
```

Start with [Current Implementation](./docs/current-implementation.md) for shipped
behavior, then read the architecture chapters for the target system. The book
uses a consistent **Current / Target / Open question** vocabulary so the
distinction between what exists and what is planned is always explicit.

## Development

```sh
# Unit tests
cargo test --workspace --locked

# Live localhost transport tests (bind UDP, TCP, TLS, and HTTP/2 fixtures)
cargo test --workspace --locked -- --ignored

# Formatting and lints (enforced in CI)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings

# Dependency policy (advisories, licenses, sources, duplicates)
cargo deny check
```

Dependencies use narrow feature sets with intentionally broad direct version
requirements, while the committed `Cargo.lock` keeps builds reproducible.
[`cargo-deny`](./deny.toml) enforces the dependency policy in CI.

The static UI shell is at [`apps/web/index.html`](./apps/web/index.html); the
Tauri desktop shell boundary is reserved under
[`apps/desktop`](./apps/desktop/README.md). The desktop information architecture
and delivery milestones are documented in the
[Desktop UI Plan](./docs/ui-plan.md).

## License

See [`LICENSE`](./LICENSE).
