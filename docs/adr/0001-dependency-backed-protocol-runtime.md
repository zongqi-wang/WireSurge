# ADR 0001: Dependency-Backed Protocol Runtime

- Status: accepted
- Date: 2026-06-20

## Context

The initial CLI contained handwritten JSON/YAML parsing, HTTP/1.1 framing, direct signal FFI, a logarithmic latency histogram, and NLnet Labs `domain` DNS message handling. Most of that code implemented standards rather than WireSurge-specific behavior. HTTPS, HTTP/2, accurate quantiles, hierarchical cancellation, and stricter DNS response validation would make the custom surface substantially riskier.

The load engine must still own pacing, worker/socket affinity, deadlines, cancellation policy, and metrics. A dependency must not hide those controls merely because it offers a convenient high-level client.

## Decision

- Serde, `serde_json`, `yaml_serde`, and `serde_path_to_error` own typed serialization and field-aware parse errors.
- Tokio and `CancellationToken` own async tasks, sockets, timers, signals, and cooperative cancellation.
- Hyper, hyper-util, http-body-util, rustls, and URL own HTTP syntax, decoded bodies, pooling, TLS, and URL parsing.
- `hickory-proto` owns DNS message and EDNS0 semantics. WireSurge keeps UDP/TCP execution; `hickory-net` is reconsidered for encrypted DNS transports.
- `hdrhistogram` owns bounded percentile storage and merging.
- Rustls uses the `ring` provider. Its native assembly and build script are accepted because a supported cryptographic provider is required, it avoids a mandatory runtime OpenSSL installation, and it covers the selected release targets.

All direct versions are exact workspace pins. Features remain limited to the protocols and runtime facilities currently used.

## Consequences

HTTPS and HTTP/2 become available without maintaining a wire parser. DNS responses are fully decoded and validated. Async signal handling no longer requires unsafe platform bindings. Histogram precision and merge behavior are explicit.

The transitive graph and compile time increase. Hickory API upgrades and rustls provider changes require focused dependency reviews. Cross-target release CI must exercise the `ring` build, native root loading, and rustls handshakes.

## Revisit Conditions

- Replace `ring` if rustls removes support, a target cannot build it, or another audited provider materially improves portability without a system dependency.
- Adopt `hickory-net` when DoT, DoH, or DoQ is implemented and its transport lifecycle can satisfy WireSurge's pacing and cancellation contracts.
- Reconsider NLnet Labs `domain` only if binary size, no-std support, or a protocol capability becomes more important than Hickory ecosystem alignment.
