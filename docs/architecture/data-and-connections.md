# Data and Connections

> **Target architecture.** The current scaffold has a memory-mapped query-name corpus but no HTTP connection pool yet. Its DNS load engine already gives each connection actor its own socket — one connected UDP socket, or one TCP/TLS stream multiplexing many in-flight queries — which is consistent with the ownership model below.

## Corpus Memory and Randomization

Loading a million domains independently in every worker multiplies memory use. WireSurge stores each immutable corpus once and gives workers lightweight indexes into shared data.

```text
Memory-mapped corpus file
          |
          +-- shared offset table: u32/u64 per row
          |
          +-- Arc<DomainCorpus>
                    |
            +-------+-------+-------+
            |               |       |
         worker 0         worker 1  worker N
         seed+counter     seed+counter
         bounded buffers  bounded buffers
```

Design rules:

- Use a memory-mapped newline-delimited file or compact immutable blob with an offset table.
- One million `u32` offsets require roughly 4 MB; workers do not retain a million `String` objects.
- Sampling with replacement maps a counter-based random value to a corpus index.
- Visit-each-once mode uses a seeded permutation over indexes rather than allocating and shuffling a full index vector.
- Workers consume disjoint counters or scheduler-assigned ranges and build only bounded in-flight payloads.

```text
memory = corpus bytes
       + offset table
       + workers * bounded in-flight buffers

memory != workers * entire corpus
```

The run records its seed and selection mode for reproducibility.

## Connection Ownership

A TCP or TLS stream is ordered, stateful, and coupled to its protocol. One connection actor owns it. Workers submit requests through bounded channels or a pool API; they do not concurrently read and write one stream behind a shared mutex.

| Protocol | Reuse model | Concurrency rule |
|---|---|---|
| HTTP/1.1 | Per-origin keep-alive pool. | Lease one connection per in-flight request; avoid pipelining initially. |
| HTTP/2 | Shared client pool with multiplexed streams. | Multiple requests share a connection within peer stream limits. |
| Raw TCP/TLS | One actor per connection or a sharded pool. | The owner serializes writes and maps parsed responses to callers. |
| DNS/UDP | Socket per I/O worker or a receiver/demultiplexer task. | Correlate responses by transaction ID and destination metadata. |

Connection behavior is part of the experiment definition:

```yaml
connections:
  mode: pooled            # pooled | fresh | fixed
  max_per_origin: 32
  max_streams: 100        # HTTP/2
  idle_timeout: 30s
  tls_sessions: reuse     # reuse | fresh
```

A capacity test may reuse pools and TLS sessions. A handshake test intentionally requests fresh connections. Metrics report logical requests and physical connections separately.

## Backpressure and Bounded Memory

Schedulers, generators, connection owners, metrics, and persistence exchange bounded messages. When a consumer cannot keep up, the system records saturation and applies the experiment's policy: wait, shed work, or stop. It must not hide overload behind unbounded queues.
