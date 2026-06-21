# Execution and Shutdown

> **Mixed status.** HTTP and DNS now run on Tokio, use cancellation tokens, and share async signal handling. The HTTP engine remains single-request, and the supervisor, bounded queues, drain deadlines, and hierarchical task ownership below are target architecture.

## Tasks, Threads, and Ownership

Named responsibilities do not automatically receive dedicated operating-system threads. Nonblocking components run as supervised async tasks on a bounded Tokio runtime. Dedicated threads are reserved for blocking persistence or CPU-heavy generation after profiling demonstrates a need.

| Responsibility | Execution model | Owns |
|---|---|---|
| Supervisor | Main async task | Run state, child lifecycle, IPC, root cancellation. |
| Scheduler | One async task per run | Rate credits, ladder phase, work admission, stop conditions. |
| I/O runtime | Bounded set of work-stealing threads | Socket polling, timers, protocol futures, task queues. |
| Generators | Bounded CPU pool | Corpus index selection, payload mutation, packet encoding. |
| Connection managers | Async actors | Streams, pools, response correlation, idle expiry. |
| Metrics | One aggregator task | Counter deltas, histogram merging, runner snapshots. |
| Persistence | Dedicated blocking task | Atomic reports, logs, checkpoints, final flush. |

Runtime rules:

- All queues are bounded and expose saturation metrics.
- Workflow compilation, variable expansion, secret resolution, and corpus indexing finish before the hot path.
- Workers update local counters and histograms; aggregation avoids one shared hot lock.
- Work items carry indexes and immutable references rather than copied request or corpus objects.
- Random seeds and scheduler decisions are recorded for reproducibility.
- The supervisor owns and joins every spawned task.

## Backend Tiers

| Backend | Target | Use | Notes |
|---|---|---|---|
| Portable async sockets | macOS, Linux, Windows | Default desktop and CLI execution. | Prioritizes correctness and consistent cross-platform behavior. |
| Linux batch sockets | Linux runners | High-rate UDP/TCP workloads. | Optional batching, socket sharding, and per-core ownership behind the same engine contract. |
| Linux advanced I/O | Linux runners | Packet-rate experiments. | Evaluate `io_uring`, AF_XDP, netmap, or DPDK behind feature flags after the workflow model stabilizes. |

## Auto-Ladder

Auto-ladder is a configurable experiment, not a hardcoded algorithm. A workflow selects the climb dimension, interval, stabilization rules, stop rules, cool-down behavior, and retries.

Climb dimensions can include:

- QPS
- concurrency
- workers
- connections
- payload size
- protocol mix

Stop signals can include:

- p95 or p99 latency
- timeout or error rate
- dropped-response rate
- CPU saturation
- queue saturation

Each phase records inputs, scheduler decisions, observations, and the reason for advancing or stopping.

## Unified Shutdown

UI cancellation, Ctrl-C, Unix SIGINT/SIGTERM, Windows console events, and internal failures enter one lifecycle state machine. The first request is cooperative; a repeated request or expired deadline becomes immediate. SIGKILL cannot be handled, so persistent state cannot rely on cleanup code.

```text
Running
  -> StopRequested        stop scheduling new work
  -> Draining             wait for in-flight work within a grace period
  -> Flushing             merge metrics, close pools, write atomic report
  -> Stopped              join owned tasks and return

Second signal or deadline:
  StopRequested | Draining | Flushing -> ForcedStop
```

Shutdown order:

1. The supervisor cancels the root token; subsystem child tokens observe cancellation.
2. The scheduler stops issuing work and closes producer sides of bounded queues.
3. Connection actors reject new requests and drain or cancel in-flight operations.
4. Metrics publishes a final snapshot; persistence writes through a temporary file and atomic rename.
5. The supervisor joins owned tasks in dependency order and returns a cancelled or failed outcome.
6. The desktop escalates from IPC cancellation to process termination and then process kill when deadlines are missed.

`std::process::exit` is not the normal shutdown path because it skips destructors. Forced process termination is a fallback, not a cleanup mechanism.
