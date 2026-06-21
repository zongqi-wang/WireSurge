# Principles and Product

> **Target architecture.** The principles are stable product constraints. The three-surface product model and technology selection are design decisions; only the CLI and static web shell currently exist.

## Core Tenets

### No account required

Every core feature works without sign-in, registration, license checks, or hosted user identity.

### No cloud dependency

Workflow editing, execution, reports, secrets, plugins, and history work locally. Optional cloud sync may be considered later, but cannot become a prerequisite for core behavior.

### No telemetry

WireSurge does not collect product analytics, tracking data, crash uploads, or traffic metadata by default. Diagnostics are explicit local exports.

### Secure local secrets

The target application stores secrets through the operating system keychain. Sensitive values are obscured in the UI, logs, exports, reports, and screenshots by default.

### Explicit ownership

Every connection, queue, report writer, and run state machine has one owner. Components exchange bounded messages rather than sharing mutable hot-path state.

### Graceful termination

UI cancellation, Ctrl-C, and SIGTERM enter the same shutdown state machine. Persistent state remains recoverable when forced termination prevents cleanup.

### Established libraries over handrolled code

Standards-heavy and security-sensitive behavior uses established first-party or third-party libraries instead of bespoke reimplementations. This includes TLS, HTTP/1.1 and HTTP/2, async runtime and signals, DNS and EDNS0 messages, PROXY protocol framing, JSON/YAML serialization, CLI parsing, and latency histograms.

WireSurge owns the behavior that differentiates the product: scheduling, pacing, connection lifecycle, cancellation policy, workflow execution, and metrics semantics. Small, well-contained helpers can remain local. A custom parser, protocol codec, argument scanner, or cryptographic implementation is technical debt unless an architecture decision record documents why an established library cannot meet the requirement.

The current CLI uses `clap`, Serde, Tokio, Hyper/rustls, `hickory-proto`, and `hdrhistogram` for their respective standards-heavy concerns. WireSurge retains scheduling, pacing, connection ownership, cancellation policy, workflow semantics, and metrics aggregation.

## Product Shape

The target product has two user-facing surfaces and one internal engine mode. They share workflow files, schemas, protocol modules, lifecycle rules, and report formats.

| Surface | Purpose | Required capabilities |
|---|---|---|
| Desktop app | Explore APIs, compose workflows, run tests, inspect responses, and visualize load results. | Request editor, environments, live charts, logs, reports, and a Git-aware file browser. |
| CLI | Human-first terminal tool for running workflows, validating configuration, and reading results; scripts and agents use an explicit machine mode. | Rich help, suggestions, color on terminals, `--output json`, and the planned `init`, `run`, `ladder`, `validate`, `report`, `secret`, and `plugin` surface. |
| Engine sidecar | Run the core system as a desktop child process. | Local IPC, event streaming, cancellation, health snapshots, bounded shutdown, and no public daemon port. |

The CLI invokes the engine library directly. The desktop app starts the same `wiresurge` executable in an internal `engine --ipc` mode. Keeping the engine in a child process gives the frontend both cooperative cancellation and a reliable process-level kill switch.

## Technology Decision

**Selected target:** Rust core, Rust CLI, Tauri desktop shell, and React UI.

This combination prioritizes native performance, memory safety, controlled concurrency, protocol access, and small desktop distribution. The CLI remains independent of Tauri and Node.js.

| Choice | Fit | Strengths | Tradeoffs |
|---|---|---|---|
| Rust + Tauri + React | Selected | Native engine, safe concurrency, protocol ecosystem, compact desktop shell, shared core. | Steeper systems learning curve; UI still requires TypeScript and React. |
| Go + Wails | Fallback | Fast delivery, simple concurrency, strong static binary story. | Less precise control for parsing, TLS customization, and sandboxed extensions. |
| C++ + Qt | Not selected | Maximum low-level control and mature native UI. | High implementation complexity and greater memory/concurrency risk. |
| Zig | Research option | Low-level control and cross-compilation. | Ecosystem is not yet sufficient for the full TLS, HTTP, DNS, UI, plugin, and metrics scope. |
| Electron/TypeScript engine | Not selected | Fast UI iteration. | Poor center of gravity for high-rate networking and protocol manipulation. |

Portable means one self-contained artifact per operating system and CPU target, not one binary that runs on every platform. Mandatory system OpenSSL dependencies should be avoided; use a Rust TLS stack.

## Safety Model

WireSurge can generate meaningful traffic, including from automation. Safety controls are part of the product contract.

### Target safety

- Workspace target allowlists.
- Conservative default limits for QPS and duration.
- Explicit confirmation for public IP targets above configured thresholds.
- Dry-run mode that resolves variables and prints planned traffic.
- Non-interactive bypasses only through explicit controls such as `--yes`, allowlists, or signed run profiles.

### Secret safety

- OS keychain storage.
- Redaction by default in UI, logs, and reports.
- Local secret-access audit records.
- No secrets in workflow files unless intentionally marked unsafe.

The current scaffold provides dry runs and basic output redaction. It does not yet implement target allowlists, keychain storage, or signed run profiles.
