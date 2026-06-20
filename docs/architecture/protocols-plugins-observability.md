# Protocols, Plugins, and Observability

> **Mixed status.** DNS UDP/TCP, configurable EDNS0 options, filesystem reports, basic redaction, and runner snapshots exist. The composable stage engine, broader protocol set, sandboxed plugins, and live observability pipeline are target features.

## Protocol Stages

Traffic is modeled as stages that compose into flows. HTTP/API remains first-class while the same execution model can grow toward custom network stacks.

| Phase | Protocol work | Reason |
|---|---|---|
| V1 | HTTP/1.1, HTTP/2, REST, JSON, GraphQL basics, DNS UDP/TCP/DoT, TLS SNI, EDNS0, and PROXY protocol v1/v2. | Delivers API and DNS workflows as peers. |
| V1.5 | DoH, WebSocket, SSE, gRPC unary, advanced HTTP auth, and imports from curl/OpenAPI/Postman. | Improves API-client usefulness and test realism. |
| V2 | Custom TLS extensions, packet templates, raw UDP, pcap replay, and Geneve/VXLAN research backends. | Expands into a protocol lab after V1 is stable. |

Best-in-class packet rate and arbitrary stack composition pull in different directions. V1 should prioritize correct composable stages. Specialized high-rate backends can later implement selected stage combinations behind the same engine contract.

### Current DNS boundary

NLnet Labs `domain` owns DNS names, record types, message construction/parsing, and EDNS0 encoding. WireSurge owns socket choice, one-owner connection reuse, pacing, cancellation, and run metrics. An EDNS option is represented by a caller-selected `u16` code plus raw bytes; code 65001 remains the CLI default for compatibility, while codes such as 65184 can be selected explicitly.

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
| Run report | Summary, capacity curve, thresholds, system information, workflow hash, Git commit, and redacted configuration. |
| Export | JSON, NDJSON, CSV, HTML, Prometheus text, and OpenTelemetry where appropriate. |

Logging rules:

- Configurable levels per component: engine, protocol, plugin, workflow, metrics, and UI.
- Structured logs for machine mode and runner output.
- Human-readable desktop log panel.
- Redaction before display or persistence.
- Sensitive debug capture only through an explicit warning and local-only storage.

The current runner writes JSON snapshots and optional JSON/HTML reports. DNS metrics use a custom fixed-memory histogram; replacing that implementation is tracked by the dependency policy.

## Git and Reports

Git is the collaboration and history layer; WireSurge does not require proprietary cloud sync.

| Area | Target behavior |
|---|---|
| Workflows | Readable files with stable formatting and schema validation. |
| Reports | `reports/` with content-addressed assets and redacted workflow snapshots. |
| Desktop Git UI | Changed workflows, report diffs, branch, commit, and dirty-state warnings. |
| CLI Git support | `--record-git`, `--require-clean`, `--report-commit`, and ignore helpers. |

Current request files are readable YAML and current reports are local files, but stable full-workflow formatting, Git-aware commands, and content-addressed assets remain target work.
