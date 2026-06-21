# Implementation Plan

The target design uses a supervised async engine, the same `wiresurge` executable as a desktop sidecar, hierarchical cancellation, shared immutable corpora, and connection-owner actors. The current Tokio transport foundation must grow toward those boundaries while preserving CLI and protocol behavior.

The CLI is human-first. Scripts and coding agents use the explicit `--output json` contract rather than defining the default terminal experience. EC2/Docker deployment remains out of scope.

## Phase Goals

| Phase | Status | Goal | Success criteria |
|---|---|---|---|
| 0. Repository foundation | Current | Buildable workspace, consolidated docs, examples, and CI. | Rust checks pass; mdBook builds and publishes to GitHub Pages. |
| 1. Human-first CLI | Partial | Discoverable terminal interface with stable machine mode. | `clap` owns parsing; nested help, validation, stable JSON errors, schemas, and dry runs work. |
| 2. HTTP/API MVP | Partial | HTTP/API is first-class. | The reviewed Hyper/rustls stack supports HTTPS, HTTP/2, decoded bodies, pooling, and timelines; redirect policy and multi-request execution are explicit. |
| 3. Metrics/reports/runners | Partial | Local observability before desktop. | Established histograms, live aggregation, atomic reports, and runner snapshots share one model. |
| 4. Desktop/Runners UI | Planned | First UI surface controls local runners. | Runners view shows health, workers, saturation, throughput, latency, errors, and heartbeat. |
| 5. DNS/protocol stages | Partial | DNS and protocol composition foundation. | Hickory-based DNS/EDNS0, encrypted transports, and the stage model integrate with the engine. |
| 6. Multi-worker/auto-ladder | Planned | Controlled load engine. | Worker sharding and configurable ladders produce threshold-based results. |
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
- DNS over Tokio UDP and TCP with concurrent tasks, reusable TCP connections, QPS pacing, JSON metrics, and cooperative cancellation.
- DNS message encoding, decoding, names, record types, and EDNS options use `hickory-proto`; future encrypted transports will evaluate `hickory-net`.
- Dependency admission rules and `cargo-deny` CI for reviewed sources, licenses, advisories, exact direct pins, and minimal features.
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
2. Add shared HTTP client ownership so multi-request runs reuse the existing Hyper pool, then make redirect policy and phase timings configurable.
3. Compile the versioned workflow model into immutable run plans and integrate current HTTP and DNS execution behind stages.
4. Replace report/runner snapshots with atomic durable storage while preserving the JSON CLI contract.
5. Add real multi-worker execution, connection managers, and configurable auto-ladder scheduling.
6. Add the Tauri sidecar and Runners view only after lifecycle and observability contracts are stable.
7. Add keychain secrets, safety allowlists, Git metadata, and redaction tests before public high-rate releases.

## Open Questions

- Must corpus randomization sample with replacement, visit every row once, or support both?
- Is the default connection policy pooled, fresh per request, or explicit-only?
- What are the default drain, terminate, and force-kill deadlines?
- Does Windows ship in the first release or after macOS and Linux stabilize?
- Are reports committed by default or selected per run?
- Which import lands first: curl, OpenAPI, Postman, Bruno, Insomnia, or Yaak?
- How conservative are default limits for public internet targets?
