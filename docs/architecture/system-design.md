# System Design

> **Target architecture.** The current engine combines an async single-request HTTP orchestrator with a many-in-flight DNS load engine and optional process-local progress snapshots. This chapter defines the supervised runtime they should evolve toward.

## Process Model

```text
Desktop UI process                       wiresurge CLI process
       |                                             |
       | local IPC                                   | direct invocation
       v                                             v
  wiresurge engine --ipc  ------------------>  Engine Supervisor
                                                    |
                     +------------------------------+---------------------------+
                     |              |               |             |             |
                     v              v               v             v             v
                 Scheduler     Corpus Service   I/O Runtime   Metrics Task   Report Writer
                     |              |               |
                     +------- bounded work ---------+
                                                    |
                                           Connection Managers
                                                    |
                                      TCP / TLS / HTTP / DNS stages

SIGINT / SIGTERM / UI Stop ----------------> root cancellation token
UI hard kill ------------------------------> child process termination
```

HTTP/API workflows and DNS workflows are peers. Traffic is modeled as composable protocol stages. Runtime responsibilities are supervised actors and bounded task groups. Immutable corpora are shared once, connections have one explicit owner, and every long-running operation participates in a cancellation tree.

## Public Engine Contract

The concrete Rust API is still to be designed, but its behavioral contract is:

```text
EngineHandle {
  subscribe() -> Stream<EngineEvent>
  snapshot() -> RunnerSnapshot
  cancel(Graceful | Immediate)
  join() -> RunOutcome
}

IPC commands: StartRun, CancelRun, GetSnapshot, Shutdown
IPC events:   StateChanged, RunnerStats, LogRecord, Completed, Failed
```

The same state machine and event model must serve direct CLI calls and IPC calls. IPC is local, authenticated by process ownership or a per-launch capability, and never exposed as an ambient public daemon port.

## Responsibility Boundaries

| Component | Owns | Does not own |
|---|---|---|
| Supervisor | Run state, task lifecycle, IPC, and root cancellation. | Protocol-specific socket behavior. |
| Scheduler | Work admission, rate credits, ladder phase, and stop conditions. | Connections or persistent reports. |
| Corpus service | Immutable mapped inputs, indexes, and deterministic selection. | Per-request mutable buffers. |
| I/O runtime | Socket polling, timers, protocol futures, and bounded task queues. | Global experiment decisions. |
| Connection managers | TCP/TLS streams, HTTP pools, correlation, and idle expiry. | Cross-run workflow state. |
| Metrics task | Counter deltas, histogram merging, and live snapshots. | Report filesystem ownership. |
| Report writer | Atomic output, checkpoints, and final flush. | Live socket or scheduling control. |

## Workspace Evolution

The repository currently contains `core`, `engine`, `http`, `dns`, `corpus`, `transport`, `metrics`, `storage`, `plugins`, and `cli` crates. The target boundaries add a dedicated control crate when its behavior becomes substantial enough to justify the split.

```text
project-root/
  crates/
    core/              domain model, scenario schema, validation, redaction
    control/           supervisor, IPC, cancellation, lifecycle       (target)
    engine/            scheduler, work queues, rate control, run state
    corpus/            mapped datasets and deterministic selection
    http/              HTTP execution, pooling, redirects, assertions
    dns/               DNS messages, transports, and query generation
    transport/         TCP, TLS, UDP, PROXY protocol, connection actors
    metrics/           histograms, counters, exporters, report model
    plugins/           WASM host, capabilities, and plugin ABI
    storage/           workspace data, atomic reports, crash recovery
    cli/               wiresurge binary and internal engine mode
  apps/
    desktop/           Tauri shell and sidecar controller
    web/               shared React UI and optional browser-only mode
    site/              public marketing shell
  examples/
    scenarios/
    plugins/
  docs/                this mdBook source
```

Crates should be split by ownership and dependency direction, not merely because the architecture diagram gives a responsibility a name.
