# WireSurge Implementation Plan

> Architecture revision notice: the canonical design in `architecture.html` now uses a supervised async engine, the same
> `wiresurge` executable as a desktop sidecar, hierarchical cancellation, memory-mapped corpora, and connection-owner actors.
> The current scaffold described below predates that runtime design and should be refactored toward it before adding features.

## Summary

WireSurge starts as a local-first, agent-friendly CLI plus shared Rust core. The desktop UI follows once workflow storage, HTTP execution, metrics, runner stats, and reports are stable. EC2/Docker deployment is out of scope for now.

## Phase Goals

| Phase | Goal | Success Criteria |
|---|---|---|
| 0. Repo foundation | Buildable monorepo, docs, examples, and CI. | `cargo test --workspace` passes and `wiresurge --help` builds. |
| 1. Agent-friendly CLI | CLI can be driven by Codex/Claude without UI state. | `schema`, `workspace`, `request`, structured JSON errors, `--dry-run`, and `--output json` work. |
| 2. HTTP/API MVP | HTTP/API is first-class from day 1. | CLI can send local HTTP requests, capture status/headers/body/timing, and write JSON output. |
| 3. Metrics/reports/runners | Local observability exists before desktop. | Runs write runner snapshots and optional redacted HTML/JSON reports. |
| 4. Desktop/Runners UI | First UI surface shows workspaces and local runners. | Runners section displays runner health, worker stats, QPS, latency, errors, and last heartbeat. |
| 5. DNS/protocol stages | DNS and protocol composition foundation. | DNS/EDNS0 packet building and stage model are testable. |
| 6. Multi-thread/auto-ladder | Controlled load engine. | Worker sharding and configurable ladder policies produce threshold-based results. |
| 7. Git/safety/secrets | Safe repeatable local workflows. | Keychain secrets, allowlists, redaction, Git metadata, and safety prompts are implemented. |
| 8. Plugins/site | Public growth path. | Plugin ABI draft, sandbox examples, and public docs site are available. |

## Current Cut

This cut implements the foundation for phases 0-3:

- Rust workspace and CI.
- Agent-friendly `wiresurge` CLI.
- Local `.wiresurge` workspace model.
- YAML request storage from JSON CLI input.
- Std-only HTTP runner for `http://` targets.
- Runner stats snapshots under `.wiresurge/runners`.
- JSON/HTML reports from `--report`.
- Static UI shell with a Runners section.
- DNS/EDNS0 and plugin manifest foundations.
- DNS over UDP and TCP with concurrent senders, reusable TCP connections, QPS pacing, JSON metrics, and cooperative signal shutdown.
- DNS message encoding, decoding, names, record types, and EDNS options use NLnet Labs `domain`; its experimental transport features remain disabled.
- Dependency admission rules and `cargo-deny` CI enforce reviewed sources, licenses, advisories, exact direct pins, and minimal features.

## Agentic CLI Contract

```text
wiresurge schema <workspace|request|environment|workflow|run|report|runner>
wiresurge workspace init|list|show
wiresurge request create|list|show|update|delete --json '{...}'
wiresurge run <request-id|request.yaml> --output json --report <dir> --parallel <n> --fail-fast --verbose
wiresurge runner list|stats --output json
wiresurge report list|show|export
wiresurge secret set|get|delete
```

Every structured error includes `code`, `message`, `path`, `hint`, and `retryable` when `--output json` is used.

## Next Engineering Steps

1. Select a minimal-feature Rustls/Hyper stack for HTTPS, redirects, HTTP/2, and richer body handling using the dependency admission checklist.
2. Replace report/runners file snapshots with SQLite while preserving the JSON CLI shape.
3. Add Tauri shell wired to the local runner registry.
4. Add keychain-backed secrets and redaction tests.
5. Add real multi-worker execution and auto-ladder scheduling.
