# Desktop and Distribution

> **Target architecture.** The repository currently has a static web shell and a placeholder desktop directory. No Tauri app, sidecar IPC, release matrix, or download site is implemented.

## Desktop and Browser Roles

Shared React components are packaged in a Tauri desktop application. The desktop starts the packaged `wiresurge` executable in internal engine mode, sends asynchronous local IPC commands, and subscribes to events. The UI does not own sockets, scheduler state, or mutable engine resources.

| Surface | Role |
|---|---|
| Desktop | Scenario editor, keychain access, reports, logs, Git state, sidecar lifecycle, and Runners view. |
| Browser/WASM | Scenario editor, examples, report viewer, sanitized demos, and documentation playground. |

Browser/WASM mode cannot generate arbitrary traffic because browser APIs do not expose raw TCP, UDP, TLS, or packet control. It remains an editor and report surface unless explicitly connected to a local engine.

## Runners View

The target view displays process health, PID, engine version, run state, scheduler phase, workers, queue saturation, QPS/RPS, p50/p95/p99, errors, timeouts, open connections, CPU, memory, and last heartbeat.

Its kill-switch contract is:

1. **Stop:** send `CancelRun(Graceful)` and display drain progress.
2. **Terminate:** after the grace deadline, terminate the child process.
3. **Kill:** after a second deadline, use the platform kill API and mark the run interrupted.

Force kill is enabled only after cooperative cancellation is requested or the heartbeat is stale.

## Release Matrix

Portability is delivered with one self-contained artifact per operating system and CPU target.

| Artifact | Target | Purpose |
|---|---|---|
| macOS desktop | Universal arm64 + x86_64 | Tauri app plus packaged sidecar. |
| macOS CLI | Universal arm64 + x86_64 | Standalone CLI and internal engine mode. |
| Linux CLI | x86_64-musl + arm64-musl | Static-oriented binary with no required OpenSSL installation. |
| Windows CLI | x86_64 MSVC; arm64 later | Standalone executable with Windows control-event shutdown. |

Distribution rules:

- CLI builds do not depend on Tauri, Node.js, or a browser runtime.
- TLS uses a reviewed Rust implementation; certificate roots are configurable as native, embedded, or file-based.
- Release CI tests, signs where applicable, and publishes checksums for each artifact.
- WASM is not a substitute for the native CLI.

## Public Site

The initial public documentation is this mdBook on GitHub Pages. A broader static site can later add:

| Page | Purpose |
|---|---|
| Home | Explain the local-first programmable traffic workbench. |
| Download | Per-platform binaries, checksums, signatures, and release notes. |
| Docs | Scenario, CLI, examples, plugin, and safety guidance. |
| Examples | HTTP ladders, connection policies, DoT, PROXY protocol, and EDNS0. |
| Principles | No account, no cloud dependency, no telemetry, and protected secrets. |
| Plugin registry | Optional curated manifests while retaining local and Git installation. |

Public examples emphasize controlled testing of owned systems, repeatability, protocol inspection, safety limits, and explicit authorization rather than request volume alone.
