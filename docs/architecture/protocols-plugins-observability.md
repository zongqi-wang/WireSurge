# Protocols, Plugins, and Observability

> **Mixed status.** A many-in-flight DNS load engine over Do53 UDP/TCP, DoT, and DoH, configurable EDNS0 options, PROXY v2 framing, live load snapshots, filesystem reports, basic redaction, and runner snapshots exist. The composable stage engine, broader protocol set, sandboxed plugins, and IPC observability pipeline are target features.

## Protocol Stages

Traffic is modeled as stages that compose into flows. HTTP/API remains first-class while the same execution model can grow toward custom network stacks.

| Phase | Protocol work | Reason |
|---|---|---|
| V1 | HTTP/1.1, HTTP/2, REST, JSON, GraphQL basics, DNS UDP/TCP/DoT, TLS SNI, EDNS0, and PROXY protocol v1/v2. | Delivers API and DNS workflows as peers. |
| V1.5 | DoH, WebSocket, SSE, gRPC unary, advanced HTTP auth, and imports from curl/OpenAPI/Postman. | Improves API-client usefulness and test realism. |
| V2 | Custom TLS extensions, packet templates, raw UDP, pcap replay, and Geneve/VXLAN research backends. | Expands into a protocol lab after V1 is stable. |

Best-in-class packet rate and arbitrary stack composition pull in different directions. V1 should prioritize correct composable stages. Specialized high-rate backends can later implement selected stage combinations behind the same engine contract.

### Current DNS boundary

`hickory-proto` owns DNS names, record types, complete message construction/parsing, and EDNS0 encoding. WireSurge owns Tokio socket choice, the per-connection actor and its many-in-flight multiplexer, pacing, deadlines, cancellation, and run metrics. The `load` engine runs over a protocol-agnostic `Transport`/`Connection` seam with Do53 UDP/TCP, DoT, and DoH implementations; replies are correlated by transaction id on Do53/DoT and by HTTP/2 stream on DoH, and a response is counted once its header validates (rcode, response bit, opcode). An EDNS option is a caller-selected `u16` code plus raw bytes; the `--token` credential rides EDNS option 65184 on DoT and the `?token=` URL query on DoH. PROXY v2 is a connection preamble for TCP/DoT/DoH and a per-datagram prefix for UDP. DNS-over-QUIC is reserved for a later transport phase.

## Plugin Model

Plugins are treated as untrusted third-party code. The target begins with WebAssembly plugins and WASI-style capabilities.

| Plugin type | Examples | Default permissions |
|---|---|---|
| Generator | IDs, payload mutations, DNS labels, refreshed values. | No filesystem or network; deterministic random source unless granted. |
| Mutator | HTTP signing, headers, EDNS0 payloads, TLS parameter selection. | Read only declared stage context and variables. |
| Assertion | Response, protocol, and latency checks. | Read response metadata and redacted body snippets. |
| Encoder | Binary frames and custom payload codecs. | No ambient host access; explicit bytes in and out. |

Target controls:

- Manifests declare network, filesystem, keychain, environment, subprocess, and UI capabilities.
- Installation shows requested capabilities before enablement.
- A plugin is disabled per workspace until explicitly trusted.
- Plugin output remains tainted until validation passes.
- A future native plugin runs out of process and requires an explicit trust prompt.

The current `plugins` crate only defines draft manifest and capability data. It does not load or execute plugins.

## Metrics and Logs

Metrics must be inexpensive in the hot path and useful after a run. The target uses per-worker counters and established histogram libraries with periodic aggregation.

| Surface | Target data |
|---|---|
| Live metrics | QPS/RPS, latency percentiles, errors, timeouts, connections, bytes, and queue/worker saturation. |
| Run report | Summary, capacity curve, thresholds, system information, scenario hash, Git commit, and redacted configuration. |
| Export | JSON, NDJSON, CSV, HTML, Prometheus text, and OpenTelemetry where appropriate. |

Logging rules:

- Configurable levels per component: engine, protocol, plugin, workflow, metrics, and UI.
- Structured logs for machine mode and runner output.
- Human-readable desktop log panel.
- Redaction before display or persistence.
- Sensitive debug capture only through an explicit warning and local-only storage.

The current runner writes JSON snapshots and optional JSON/HTML reports. DNS connection actors record bounded HDR histograms. Human TTY mode clones and merges those recorders for periodic aggregate/worker snapshots, while batch and JSON modes avoid that sampling path and merge once at the end. The stream is an in-process Tokio watch channel, not yet IPC, persistence, NDJSON, or a general runner aggregation service.

## Git and Reports

Git is the collaboration and history layer; WireSurge does not require proprietary cloud sync.

| Area | Target behavior |
|---|---|
| Workflows | Readable files with stable formatting and schema validation. |
| Reports | `reports/` with content-addressed assets and redacted workflow snapshots. |
| Desktop Git UI | Changed workflows, report diffs, branch, commit, and dirty-state warnings. |
| CLI Git support | `--record-git`, `--require-clean`, `--report-commit`, and ignore helpers. |

Current request files are readable YAML and current reports are local files, but stable full-workflow formatting, Git-aware commands, and content-addressed assets remain target work.
