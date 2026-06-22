# Implementation Plan

The target design uses a supervised async engine, the same `wiresurge` executable as a desktop sidecar, hierarchical cancellation, shared immutable corpora, and connection-owner actors. The current Tokio transport foundation must grow toward those boundaries while preserving CLI and protocol behavior.

The CLI is human-first. Scripts and coding agents use the explicit `--output json` contract rather than defining the default terminal experience. EC2/Docker deployment remains out of scope.

## Phase Goals

| Phase | Status | Goal | Success criteria |
|---|---|---|---|
| 0. Repository foundation | Current | Buildable workspace, consolidated docs, examples, and CI. | Rust checks pass; mdBook builds and publishes to GitHub Pages. |
| 1. Human-first CLI | Partial | Discoverable terminal interface with stable machine mode. | `clap` owns parsing; nested help, validation, stable JSON errors, schemas, and dry runs work. |
| 2. HTTP/API MVP | Partial | HTTP/API is first-class. | The reviewed Hyper/rustls stack supports HTTPS, HTTP/2, decoded bodies, pooling, and timelines; redirect policy and multi-request execution are explicit. |
| 3. Metrics/reports/runners | Partial | Local observability before desktop. | Established histograms, live load snapshots, atomic reports, and runner snapshots share one model. |
| 4. Desktop/Runners UI | Planned | First UI surface controls local runners. | Runners view shows health, workers, saturation, throughput, latency, errors, and heartbeat. |
| 5. DNS/protocol stages | Partial | DNS and protocol composition foundation. | Hickory-based DNS/EDNS0, encrypted transports, and the stage model integrate with the engine. |
| 6. Multi-connection/auto-ladder | Partial | Controlled load engine. | Connection actors, bounded in-flight work, reconnect policy, and configurable ladders produce threshold-based results. |
| 7. Git/safety/secrets | Planned | Safe repeatable local workflows. | Keychain secrets, allowlists, redaction, Git metadata, and safety prompts exist. |
| 8. Plugins/site | Partial | Public growth path. | Published docs, plugin ABI, capability sandbox, examples, and optional registry exist. |

## Current Cut

The current repository implements:

- Rust workspace and CI.
- Human-first `wiresurge` CLI parsed by `clap`, with help, suggestions, strict flag validation, and JSON machine mode; several nested action sets remain string-based.
- Local `.wiresurge` workspace model.
- YAML request storage from JSON CLI input.
- Hyper HTTP/1.1 and HTTP/2 runner with rustls HTTPS and bounded decoded bodies.
- Runner stats snapshots under `.wiresurge/runners`.
- JSON/HTML reports from `--report`.
- Static UI shell with a Runners section.
- DNS/EDNS0 with caller-selected option codes and a plugin manifest foundation.
- A many-in-flight DNS load engine over Do53 UDP/TCP, DoT, and DoH, with a shared lock-free work source, process-wide QPS pacing, count/duration budgets, cooperative cancellation, live TTY samples, and per-connection final metrics.
- DNS message encoding, decoding, names, record types, and EDNS options use `hickory-proto`; encrypted transports (DoT/DoH) use `rustls` with the `ring` provider over the shared `transport` seam.
- Dependency admission rules and `cargo-deny` CI for reviewed sources, licenses, advisories, workspace declarations, and duplicate versions; the committed lockfile fixes the intentionally broad direct requirements.
- Consolidated mdBook source and GitHub Pages automation.

Serde/`yaml_serde`, Hyper/rustls, Tokio signals, and `hdrhistogram` have removed the scaffold's standards-heavy parser, HTTP wire, signal FFI, and histogram debt.

## Machine CLI Contract

```text
wiresurge schema <workspace|request|environment|workflow|run|report|runner>
wiresurge workspace init|list|show
wiresurge request create|list|show|update|delete --json '{...}'
wiresurge run <request-id|request.yaml> --output json --report <dir> --parallel <n> --fail-fast --verbose
wiresurge runner list|stats --output json
wiresurge report list|show|export
wiresurge secret set|get|delete
```

Every structured error includes `code`, `message`, `path`, `hint`, and `retryable` when `--output json` or `--output=json` is used. Human mode remains the default.

## Next Engineering Steps

1. Introduce the supervisor, cancellation tree, bounded queues, and public engine handle before adding broad protocol surface.
2. Compile the versioned workflow model into immutable run plans and integrate current HTTP and DNS execution behind stages.
3. Use the shared Hyper client for multi-request runs, then make redirect policy and phase timings configurable.
4. Expose the existing load snapshots through a stable engine event contract and add reconnect/backoff plus configurable drain deadlines.
5. Replace report/runner writes with atomic durable storage while preserving the JSON CLI contract.
6. Add configurable auto-ladder scheduling on top of the connection-actor load engine.
7. Add the Tauri sidecar and Runners view after lifecycle and event contracts are stable.
8. Add keychain secrets, safety allowlists, Git metadata, and redaction tests before public high-rate releases.

## Open Questions

- Should the CLI expose visit-each-once permutation separately from the current `--randomize` sampling-with-replacement mode?
- Is the default connection policy pooled, fresh per request, or explicit-only?
- What are the default drain, terminate, and force-kill deadlines?
- Does Windows ship in the first release or after macOS and Linux stabilize?
- Are reports committed by default or selected per run?
- Which import lands first: curl, OpenAPI, Postman, Bruno, Insomnia, or Yaak?
- How conservative are default limits for public internet targets?
